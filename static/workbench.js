/*
 * ReverseShield browser client.
 *
 * Structural section map:
 *   1. API client and request authorization
 *   2. Discovery and target selection
 *   3. Asynchronous job watcher and lifecycle
 *   4. Analysis and artifact rendering
 *   5. Before/after comparison
 *   6. Monitor and job history
 *
 * Safety rules: never use innerHTML. Render backend strings with textContent
 * and DOM builders. The browser only talks to the loopback API. No target is
 * executed by this file. See docs/AI_CONTEXT.md before extending the UI.
 */
(function (root) {
  'use strict';
  function createClient(fetcher = root.fetch.bind(root)) {
    let token = '';
    async function request(path, options = {}) {
      const response = await fetcher(path, {credentials: 'same-origin', cache: 'no-store', ...options});
      let data;
      try { data = await response.json(); }
      catch (_) { throw new Error(`Local API returned non-JSON data (HTTP ${response.status}).`); }
      if (!response.ok) {
        const detail = typeof data.error === 'string' ? data.error : data.error?.message;
        throw new Error(detail || data.message || `Local API request failed (HTTP ${response.status}).`);
      }
      return data;
    }
    function write(path, body, binary = false) {
      if (!token) return Promise.reject(new Error('Load a valid static-only API status and token first.'));
      return request(path, {method: 'POST', headers: {'X-ReverseShield-Token': token,
        'Content-Type': binary ? 'application/octet-stream' : 'application/json'},
      body: binary ? body : JSON.stringify(body)});
    }
    return {
      async loadStatus() {
        token = '';
        const status = await request('/api/status');
        if (status.dynamic_analysis?.enabled !== false) throw new Error('Static-only safety check failed: dynamic analysis must be disabled.');
        if (!status.token) throw new Error('Local API status did not provide an operation token.');
        token = status.token;
        return status;
      },
      apps: () => request('/api/apps'),
      samples: () => request('/api/samples'),
      async discover(source) {
        if (source.kind === 'path' && !source.path?.startsWith('/')) throw new Error('Enter an absolute local path beginning with /.');
        return write('/api/discover', source);
      },
      ingest: file => write(`/api/ingest?filename=${encodeURIComponent(file.name)}`, file.data ?? file, true),
      startJob: payload => write('/api/jobs', payload),
      jobs: () => request('/api/jobs'),
      job: (id, after = 0) => request(`/api/jobs/${encodeURIComponent(id)}?after=${after}`),
      cancelJob: id => write(`/api/jobs/${encodeURIComponent(id)}/cancel`, {})
    };
  }
  function defaultTargets(targets) {
    const available = (targets || []).filter(target => target.analyzable);
    const main = available.find(target => target.is_main || target.role === 'main') ||
      available.find(target => /(^|\/)s?bin\//.test(target.relative_path || '')) || available[0];
    return main ? [main.target_id] : [];
  }
  function selectedTools(tools, mode, manual) {
    return Object.entries(tools || {}).filter(([id, info]) => info.available && (mode === 'all' || manual.has(id))).map(([id]) => id);
  }
  function jobPayload({selection, targetIds, tools, authorized, operation, stripAvailable, binaryAvailable, profile}) {
    if (!authorized) throw new Error('Confirm authorization before starting static analysis.');
    if (!selection?.selection_id) throw new Error('Discover a source and select targets first.');
    const allowed = new Set((selection.targets || []).filter(target => target.analyzable).map(target => target.target_id));
    if (!targetIds.length || targetIds.some(id => !allowed.has(id))) throw new Error('Select at least one analyzable target.');
    if (!tools.length) throw new Error('Select at least one available analysis tool.');
    if (!['analyze', 'strip_compare', 'protect_compare', 'binary_compare'].includes(operation)) throw new Error('Unsupported operation.');
    if (operation === 'strip_compare' || operation === 'protect_compare') {
      if (selection.sourceKind !== 'sample') throw new Error('Source protection is limited to bundled sample copies.');
      if (targetIds.length !== 1) throw new Error('Select exactly one sample target for comparison.');
    }
    if (operation === 'binary_compare') {
      if (targetIds.length !== 1) throw new Error('Select exactly one ELF or PE target for binary hygiene.');
      if (!binaryAvailable) throw new Error('Binary hygiene tools are unavailable.');
    }
    if (profile === 'symbol_removal' || (operation === 'strip_compare' && !profile)) {
      if (!stripAvailable) throw new Error('GNU strip is unavailable.');
    }
    return {selection_id: selection.selection_id, target_ids: [...new Set(targetIds)], tools: [...new Set(tools)], operation,
      ...(profile ? {profile} : {}), authorized: true};
  }
  const isTerminal = status => ['completed', 'partial', 'failed', 'cancelled'].includes(status);
  const reportUrl = id => `/api/jobs/${encodeURIComponent(id)}/report`;
  const artifactUrl = id => `/api/jobs/${encodeURIComponent(id)}/artifact`;
  function createJobWatcher(client, {onUpdate, onError, schedule = setTimeout, clear = clearTimeout}) {
    let generation = 0;
    let timer;
    function stop() { generation += 1; clear(timer); }
    async function start(id) {
      stop();
      const active = generation;
      let after = 0;
      const events = new Map();
      async function poll() {
        try {
          const update = await client.job(id, after);
          if (active !== generation) return;
          for (const event of update.events || []) {
            if (!events.has(event.seq)) events.set(event.seq, event);
            after = Math.max(after, Number(event.seq) || 0);
          }
          after = Math.max(after, Number(update.next_seq) || 0);
          onUpdate({...update, events: [...events.values()].sort((a, b) => a.seq - b.seq)});
          if (!isTerminal(update.status)) timer = schedule(poll, 500);
        } catch (error) { if (active === generation) onError(error); }
      }
      return poll();
    }
    return {start, stop};
  }
  const GRAPH_NODE_CAP = 60;
  const GRAPH_EDGE_CAP = 180;
  function graphData(artifacts = {}, kind = 'calls', fn = {}) {
    const nodes = new Map();
    const aliases = new Map();
    const sourceNodes = kind === 'cfg' ? (fn.cfg_nodes || []) : (artifacts.functions || []);
    for (const item of sourceNodes) {
      const id = String(kind === 'cfg' ? item.id : (item.name ?? item.address ?? item.id));
      nodes.set(id, {id, label: String(item.label ?? item.name ?? item.address ?? id)});
      for (const alias of [item.name, item.address, item.id]) if (alias !== undefined) aliases.set(String(alias), id);
    }
    const rawEdges = kind === 'cfg' ? (fn.cfg_edges || []) : (artifacts.call_edges || []);
    const edges = rawEdges.filter(edge => edge.source !== undefined && edge.target !== undefined).map(edge => {
      const source = aliases.get(String(edge.source)) ?? String(edge.source);
      const target = aliases.get(String(edge.target)) ?? String(edge.target);
      for (const id of [source, target]) if (!nodes.has(id)) nodes.set(id, {id, label: id});
      return {source, target};
    });
    const displayed = [...nodes.values()].slice(0, GRAPH_NODE_CAP);
    const ids = new Set(displayed.map(node => node.id));
    const shownEdges = edges.filter(edge => ids.has(edge.source) && ids.has(edge.target)).slice(0, GRAPH_EDGE_CAP);
    return {nodes: displayed, edges: shownEdges, totalNodes: nodes.size, totalEdges: edges.length,
      capped: nodes.size > displayed.length || edges.length > shownEdges.length};
  }
  function display(value) {
    if (value === undefined || value === null || value === '') return 'Not collected';
    return typeof value === 'object' ? JSON.stringify(value) : String(value);
  }
  function analysisWarnings(analysis = {}) {
    const warnings = [...(analysis.limitations || [])].map(display);
    for (const tool of analysis.tools || []) {
      if (!['ok', 'success', 'completed'].includes(tool.status) || (tool.return_code != null && tool.return_code !== 0)) {
        warnings.push(`${tool.label || tool.tool}: ${tool.status || 'status not collected'}${tool.return_code == null ? '' : ` (exit ${tool.return_code})`}. Review raw output.`);
      }
      if (tool.truncated) warnings.push(`${tool.label || tool.tool}: output truncated by the backend.`);
    }
    for (const [name, value] of Object.entries(analysis.coverage || {})) {
      if (value === false || /unavailable|not.collected|partial|fail|missing|skip|truncat/i.test(display(value))) warnings.push(`Coverage — ${name}: ${display(value)}`);
    }
    return [...new Set(warnings)];
  }
  function element(tag, className = '', text) {
    const node = root.document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = display(text);
    return node;
  }
  function empty(parent, message = 'Unavailable / Not collected. Review tool output and coverage.') {
    parent.append(element('p', 'empty', message));
  }
  function warningList(parent, messages) {
    parent.replaceChildren();
    parent.hidden = !messages.length;
    if (messages.length) {
      const list = element('ul');
      messages.forEach(message => list.append(element('li', '', message)));
      parent.append(list);
    }
  }
  function table(parent, headings, rows, limit = 500) {
    if (!rows.length) { empty(parent); return; }
    const wrap = element('div', 'table-wrap');
    const grid = element('table');
    const head = element('thead');
    const headRow = element('tr');
    for (const heading of headings) { const th = element('th', '', heading); th.scope = 'col'; headRow.append(th); }
    head.append(headRow);
    const body = element('tbody');
    rows.slice(0, limit).forEach(values => {
      const row = element('tr');
      values.forEach(value => row.append(element('td', '', value)));
      body.append(row);
    });
    grid.append(head, body); wrap.append(grid); parent.append(wrap);
    if (rows.length > limit) parent.append(element('p', 'field-help', `Showing ${limit} of ${rows.length} returned rows. Download full JSON for all returned evidence.`));
  }
  function keyValues(parent, entries) {
    table(parent, ['Field', 'Observed value'], entries);
  }
  function humanSize(value) {
    if (typeof value !== 'number') return 'Not collected';
    if (value < 1024) return `${value} B`;
    if (value < 1048576) return `${(value / 1024).toFixed(1)} KiB`;
    return `${(value / 1048576).toFixed(2)} MiB`;
  }
  function option(select, value, text, disabled = false) {
    const item = element('option', '', text); item.value = value; item.disabled = disabled; select.append(item); return item;
  }
  function renderGraph(parent, data, label, prefix) {
    parent.append(element('h3', '', label));
    if (!data.nodes.length) { empty(parent, `${label}: unavailable / Not collected by the selected tools.`); return; }
    parent.append(element('p', 'field-help', `Showing ${data.nodes.length} of ${data.totalNodes} nodes; ${data.edges.length} of ${data.totalEdges} edges. Display cap: ${GRAPH_NODE_CAP} nodes / ${GRAPH_EDGE_CAP} edges.${data.capped ? ' Graph display is capped; download JSON for full returned evidence.' : ''}`));
    if (!data.totalEdges) parent.append(element('p', 'field-help', 'No edges were collected. Isolated nodes are not evidence that calls or branches are absent.'));
    const ns = 'http://www.w3.org/2000/svg';
    const svgNode = (name, attrs, text) => {
      const node = root.document.createElementNS(ns, name);
      Object.entries(attrs || {}).forEach(([key, value]) => node.setAttribute(key, value));
      if (text !== undefined) node.textContent = text;
      return node;
    };
    const columns = data.nodes.length > 1 ? 3 : 1;
    const height = Math.ceil(data.nodes.length / columns) * 84 + 30;
    const svg = svgNode('svg', {viewBox: `0 0 720 ${height}`, role: 'img', 'aria-labelledby': `${prefix}-title ${prefix}-description`});
    svg.append(svgNode('title', {id: `${prefix}-title`}, label));
    svg.append(svgNode('desc', {id: `${prefix}-description`}, `${data.nodes.length} displayed nodes and ${data.edges.length} directed edges from actual collected artifacts. A text edge list follows.`));
    const defs = svgNode('defs');
    const marker = svgNode('marker', {id: `${prefix}-arrow`, viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 5, markerHeight: 5, orient: 'auto-start-reverse'});
    marker.append(svgNode('path', {d: 'M 0 0 L 10 5 L 0 10 z', fill: 'var(--accent-dim)'})); defs.append(marker); svg.append(defs);
    const positions = new Map(data.nodes.map((node, index) => [node.id, {x: 20 + (index % columns) * 235, y: 20 + Math.floor(index / columns) * 84}]));
    data.edges.forEach(edge => {
      const from = positions.get(edge.source), to = positions.get(edge.target);
      if (!from || !to) return;
      const self = edge.source === edge.target;
      const d = self ? `M ${from.x + 180} ${from.y + 15} C ${from.x + 240} ${from.y - 25}, ${from.x + 240} ${from.y + 55}, ${from.x + 180} ${from.y + 30}` :
        `M ${from.x + 100} ${from.y + 42} C ${from.x + 100} ${from.y + 66}, ${to.x + 100} ${to.y - 20}, ${to.x + 100} ${to.y}`;
      svg.append(svgNode('path', {d, fill: 'none', stroke: 'var(--accent-dim)', 'stroke-width': 1.3, 'marker-end': `url(#${prefix}-arrow)`}));
    });
    data.nodes.forEach(node => {
      const {x, y} = positions.get(node.id);
      const group = svgNode('g');
      group.append(svgNode('title', {}, node.label));
      group.append(svgNode('rect', {x, y, width: 205, height: 42, rx: 3, fill: 'var(--inset)', stroke: 'var(--border-strong)'}));
      group.append(svgNode('text', {x: x + 10, y: y + 25, fill: 'var(--text)', 'font-size': 11}, node.label.length > 27 ? `${node.label.slice(0, 26)}…` : node.label));
      svg.append(group);
    });
    const viewport = element('div', 'graph-viewport'); viewport.append(svg); parent.append(viewport);
    const text = element('details', 'details'); text.append(element('summary', '', 'Accessible node & edge list (displayed graph)'));
    text.append(element('pre', '', [...data.nodes.map(node => `${node.id}: ${node.label}`), '', ...data.edges.map(edge => `${edge.source} → ${edge.target}`)].join('\n')));
    parent.append(text);
  }
  function renderAnalysis(parent, analysis = {}, {prefix = 'analysis', mode = 'all'} = {}) {
    parent.replaceChildren();
    const artifacts = analysis.artifacts || {};
    const functions = artifacts.functions || [];
    let functionIndex = 0;
    let activeView = mode === 'basic' || mode === 'all' ? 'metadata' : mode;
    let currentMode = mode;
    const summary = element('div', 'analysis-summary');
    summary.append(element('strong', '', analysis.filename || 'Analysis evidence'));
    summary.append(element('span', 'muted', `${humanSize(analysis.size_bytes)} · ${analysis.analysis_mode || 'static analysis'} · target not executed`));
    parent.append(summary);
    const warnings = element('div', 'notice warning'); warningList(warnings, analysisWarnings(analysis)); parent.append(warnings);
    const navigation = element('div', 'evidence-tabs'); navigation.setAttribute('aria-label', `${prefix} evidence views`);
    const body = element('div', 'evidence-body'); parent.append(navigation, body);
    const views = ['metadata', 'functions', 'symbols', 'strings', 'pseudocode', 'graphs', 'raw'];
    function selector() {
      const field = element('label', 'field function-field'); field.htmlFor = `${prefix}FunctionSelect`;
      field.append(element('span', '', 'Function (independent selection)'));
      const select = element('select'); select.id = `${prefix}FunctionSelect`;
      functions.forEach((fn, index) => option(select, String(index), `${fn.name || 'Unnamed'} · ${fn.address || 'address not collected'}`));
      if (!functions.length) { option(select, '', 'Functions unavailable / Not collected'); select.disabled = true; }
      else select.value = String(functionIndex);
      select.addEventListener('change', () => { functionIndex = Number(select.value); draw(); });
      field.append(select); body.append(field);
      return functions[functionIndex];
    }
    function draw() {
      navigation.replaceChildren(); body.replaceChildren();
      navigation.hidden = currentMode !== 'all';
      views.forEach(view => {
        const button = element('button', `evidence-tab${view === activeView ? ' active' : ''}`, view[0].toUpperCase() + view.slice(1));
        button.type = 'button'; button.dataset.evidenceView = view; button.setAttribute('aria-pressed', String(view === activeView));
        button.addEventListener('click', () => { activeView = view; draw(); navigation.querySelector(`[data-evidence-view="${view}"]`)?.focus(); }); navigation.append(button);
      });
      if (activeView === 'metadata') {
        keyValues(body, [['Filename', analysis.filename], ['Size', humanSize(analysis.size_bytes)], ['SHA-256', analysis.sha256], ['Analysis mode', analysis.analysis_mode], ...Object.entries(analysis.metadata || {})]);
        body.append(element('h3', '', 'Coverage as reported'));
        keyValues(body, Object.entries(analysis.coverage || {}));
        body.append(element('h3', '', 'ELF sections'));
        table(body, ['#', 'Name', 'Type', 'Address', 'Size'], (analysis.sections || []).map(item => [item.index, item.name, item.type, item.address, item.size ?? item.size_bytes]));
      } else if (activeView === 'functions') {
        body.append(element('p', 'field-help', `${functions.length} returned functions. Function recovery depends on the selected tools.`));
        table(body, ['Function', 'Address', 'Size', 'Pseudocode'], functions.map(fn => [fn.name, fn.address, fn.size, fn.pseudocode ? 'Collected' : 'Not collected']));
      } else if (activeView === 'symbols' || activeView === 'strings') {
        const items = artifacts[activeView] || [];
        const filter = element('input'); filter.type = 'search'; filter.placeholder = `Filter returned ${activeView}…`; filter.setAttribute('aria-label', `Filter ${prefix} ${activeView}`);
        const count = element('p', 'field-help'); const results = element('div'); body.append(filter, count, results);
        const list = () => {
          results.replaceChildren(); const needle = filter.value.toLocaleLowerCase();
          const matches = items.filter(item => display(item).toLocaleLowerCase().includes(needle));
          count.textContent = `${matches.length} matching / ${items.length} returned ${activeView}.`;
          if (activeView === 'symbols') table(results, ['Symbol', 'Address', 'Type', 'Size'], matches.map(item => [item.name, item.address, item.type, item.size]));
          else table(results, ['String'], matches.map(item => [item]));
        };
        filter.addEventListener('input', list); list();
      } else if (activeView === 'pseudocode') {
        const fn = selector();
        body.append(element('p', 'field-help', 'Decompiler output is an approximation, not recovered source or verified behavior.'));
        if (fn?.pseudocode) body.append(element('pre', 'pseudocode', fn.pseudocode));
        else empty(body, 'Pseudocode unavailable / Not collected for this function. Review decompiler availability, tool failures, and raw output.');
      } else if (activeView === 'graphs') {
        const fn = selector();
        renderGraph(body, graphData(artifacts, 'calls'), 'Collected call graph', `${prefix}-calls`);
        renderGraph(body, graphData(artifacts, 'cfg', fn), 'Selected function control-flow graph', `${prefix}-cfg`);
      } else if (activeView === 'raw') {
        if (!(analysis.tools || []).length) empty(body, 'No tool output collected.');
        (analysis.tools || []).forEach(tool => {
          const details = element('details', 'raw-output');
          const bad = !['ok', 'success', 'completed'].includes(tool.status) || (tool.return_code != null && tool.return_code !== 0);
          details.open = bad;
          details.append(element('summary', bad ? 'bad-text' : '', `${tool.label || tool.tool} · ${tool.status || 'unknown'} · exit ${tool.return_code ?? 'not collected'}${tool.truncated ? ' · TRUNCATED' : ''}`));
          details.append(element('p', 'tool-command', `$ ${Array.isArray(tool.command) ? tool.command.join(' ') : display(tool.command)}`));
          details.append(element('p', 'field-help', `Version: ${display(tool.version)} · duration: ${tool.duration_seconds == null ? 'Not collected' : `${tool.duration_seconds}s`}`));
          details.append(element('pre', '', tool.output || 'No output collected.')); body.append(details);
        });
      }
    }
    draw();
    return {setMode(next) { currentMode = next; activeView = next === 'basic' || next === 'all' ? 'metadata' : next; draw(); }};
  }
  function boot() {
    const document = root.document;
    const byId = id => document.getElementById(id);
    const client = createClient();
    const state = {status: null, samples: [], apps: [], selection: null, targetIds: new Set(), manualTools: new Set(),
      busy: false, job: null, result: null, renderedResult: null, eventsShown: new Set(), compareViews: [], pollingPaused: false};
    const text = (id, value) => { byId(id).textContent = value; };
    function message(value = '') { text('globalMessage', value); byId('globalMessage').hidden = !value; }
    function showPage(id) {
      if (!['operate', 'compare', 'monitor', 'readme'].includes(id)) return;
      document.querySelectorAll('.page').forEach(page => { page.hidden = page.id !== id; });
      document.querySelectorAll('.tab').forEach(tab => {
        const active = tab.dataset.page === id; tab.classList.toggle('active', active);
        if (active) tab.setAttribute('aria-current', 'page'); else tab.removeAttribute('aria-current');
      });
    }
    document.querySelectorAll('[data-page]').forEach(button => button.addEventListener('click', () => showPage(button.dataset.page)));
    function currentTools() { return selectedTools(state.status?.tools, byId('toolMode').value, state.manualTools); }
    function canRun(operation) {
      if (!state.status || state.busy || (state.job && !isTerminal(state.job.status))) return false;
      try { makePayload(operation); return true; } catch (_) { return false; }
    }
    function makePayload(operation) {
      const profile = operation === 'analyze' ? undefined : byId('protectionProfile').value;
      return jobPayload({selection: state.selection, targetIds: [...state.targetIds], tools: currentTools(),
        authorized: byId('authorization').checked, operation, profile,
        stripAvailable: !!state.status?.protection?.available,
        binaryAvailable: !!state.status?.protection?.binary_hygiene});
    }
    function controls() {
      const ready = !!state.status && !state.busy;
      byId('refreshAppsBtn').disabled = !ready;
      byId('discoverAppBtn').disabled = !ready || !byId('appSelect').value;
      byId('discoverPathBtn').disabled = !ready || !byId('localPath').value.trim();
      byId('discoverSampleBtn').disabled = !ready || !byId('sampleSelect').value;
      byId('ingestBtn').disabled = !ready || !byId('fileInput').files.length;
      byId('analyzeBtn').disabled = !canRun('analyze');
      const profile = byId('protectionProfile').value;
      const transformOperation = profile === 'symbol_removal' ? 'strip_compare' : profile === 'binary_hygiene' ? 'binary_compare' : 'protect_compare';
      byId('stripCompareBtn').disabled = !canRun(transformOperation);
      byId('cancelJobBtn').disabled = !state.status || !state.job || isTerminal(state.job.status);
      const targets = (state.selection?.targets || []).filter(target => target.analyzable);
      text('selectionCount', `${state.targetIds.size} SELECTED / ${targets.length} ANALYZABLE`);
      const all = byId('selectAllTargets'); all.disabled = !targets.length || state.busy;
      all.checked = targets.length > 0 && targets.length === state.targetIds.size;
      all.indeterminate = state.targetIds.size > 0 && state.targetIds.size < targets.length;
      let hint = 'Select targets and confirm authorization. Transformations operate on one copy at a time.';
      if (state.selection && profile === 'binary_hygiene' && state.targetIds.size !== 1) hint = 'Binary hygiene requires exactly one selected ELF or PE target.';
      else if (state.selection && ['symbol_removal', 'constant_blinding'].includes(profile) && state.selection.sourceKind !== 'sample') hint = 'Source protection is limited to bundled sample copies; binary hygiene can run on any selected ELF or PE copy.';
      else if (state.selection && profile === 'symbol_removal' && !state.status?.protection?.available) hint = 'GNU strip is unavailable. Demo constant blinding remains available for bundled samples.';
      else if (state.selection && profile === 'binary_hygiene' && !state.status?.protection?.binary_hygiene) hint = 'Binary hygiene requires GNU strip and objcopy; one is unavailable.';
      else if (state.job && !isTerminal(state.job.status)) hint = 'A selected job is active. Cancel it or wait for completion before starting another run.';
      else if (state.selection && !currentTools().length) hint = 'Select at least one available analysis tool.';
      text('runHint', hint);
    }
    function renderTools() {
      const list = byId('toolList'); list.replaceChildren();
      const tools = Object.entries(state.status?.tools || {});
      if (!tools.length) empty(list, 'No analysis tools reported by the local API.');
      tools.forEach(([id, info]) => {
        const row = element('label', 'tool-row');
        const checkbox = element('input'); checkbox.type = 'checkbox'; checkbox.dataset.toolId = id;
        checkbox.checked = !!info.available && (byId('toolMode').value === 'all' || state.manualTools.has(id));
        checkbox.disabled = !info.available || byId('toolMode').value === 'all';
        checkbox.setAttribute('aria-label', `Use ${info.label || id}`);
        checkbox.addEventListener('change', () => { if (checkbox.checked) state.manualTools.add(id); else state.manualTools.delete(id); controls(); });
        const copy = element('span', 'tool-copy'); copy.append(element('strong', '', info.label || id));
        copy.append(element('small', '', info.version || (info.available ? 'Version not reported' : 'Adapter unavailable')));
        if (info.path) { const path = element('small', '', info.path); path.title = info.path; copy.append(path); }
        row.append(checkbox, copy, element('span', `tool-state${info.available ? '' : ' missing'}`, info.available ? 'AVAILABLE' : 'MISSING')); list.append(row);
      });
    }
    async function refreshStatus() {
      byId('refreshStatusBtn').disabled = true;
      try {
        const status = await client.loadStatus();
        const first = !state.status;
        state.status = status;
        if (first) state.manualTools = new Set(selectedTools(status.tools, 'all', new Set()));
        text('connectionText', 'LOCAL API · STATIC ONLY'); byId('connectionText').className = 'badge good';
        text('versionText', `${status.version || 'Local'} · targets never executed`);
        renderTools(); message();
      } catch (error) {
        state.status = null; text('connectionText', 'LOCAL API UNAVAILABLE'); byId('connectionText').className = 'badge bad';
        message(`${error.message} Operations are disabled. Refresh status after checking the local server.`);
      } finally { byId('refreshStatusBtn').disabled = false; controls(); }
    }
    function sampleDescription() {
      const sample = state.samples.find(item => item.id === byId('sampleSelect').value);
      text('sampleDescription', sample ? `${sample.description || sample.name}${sample.topics?.length ? ` · ${sample.topics.join(', ')}` : ''}` : 'No compiled sample selected.');
      controls();
    }
    async function loadSamples() {
      try {
        const data = await client.samples(); state.samples = data.samples || [];
        const select = byId('sampleSelect'); select.replaceChildren();
        state.samples.forEach(sample => option(select, sample.id, `${sample.name}${sample.available ? '' : ' · build required'}`, !sample.available));
        const first = state.samples.find(sample => sample.available);
        if (first) select.value = first.id;
        else { option(select, '', 'No compiled samples available'); select.value = ''; }
        select.disabled = !first; sampleDescription();
      } catch (error) { text('sampleDescription', `Sample catalog unavailable: ${error.message}`); }
    }
    async function loadApps() {
      byId('refreshAppsBtn').disabled = true;
      text('appsMessage', 'Reading installed Flatpak applications…');
      try {
        const data = await client.apps(); state.apps = data.apps || [];
        const select = byId('appSelect'); const previous = select.value; select.replaceChildren();
        option(select, '', state.apps.length ? 'Select an installed application…' : 'No installed Flatpak applications found');
        state.apps.forEach(app => option(select, app.app_id, `${app.name || app.app_id}${app.version ? ` · ${app.version}` : ''} · ${app.app_id}`));
        if (state.apps.some(app => app.app_id === previous)) select.value = previous;
        select.disabled = !state.apps.length;
        const warnings = (data.warnings || []).map(display).join(' ');
        text('appsMessage', `${state.apps.length} applications listed. Runtime dependencies are not scanned.${warnings ? ` ${warnings}` : ''}`);
      } catch (error) { text('appsMessage', `Flatpak listing unavailable: ${error.message}`); }
      finally { controls(); }
    }
    function renderTargets() {
      const selection = state.selection; const rows = byId('targetRows'); rows.replaceChildren();
      if (!selection) {
        const row = element('tr'); const cell = element('td', 'empty', 'No discovery preview. Choose a source.'); cell.colSpan = 4; row.append(cell); rows.append(row);
        text('selectionName', 'No source selected'); text('selectionDetail', 'Discovery does not start analysis.');
        warningList(byId('discoveryWarnings'), []); text('runtimeSummary', 'not collected'); text('runtimeDetails', 'No runtime information collected.'); controls(); return;
      }
      text('selectionName', selection.app?.name || selection.app?.app_id || 'Selected input');
      text('selectionDetail', [selection.app?.version, selection.sourceKind, `${selection.targets?.length || 0} discovered entries`].filter(Boolean).join(' · '));
      warningList(byId('discoveryWarnings'), (selection.warnings || []).map(display));
      (selection.targets || []).forEach(target => {
        const row = element('tr', state.targetIds.has(target.target_id) ? 'selected' : '');
        const choose = element('td'); const checkbox = element('input'); checkbox.type = 'checkbox';
        checkbox.dataset.targetId = target.target_id; checkbox.disabled = !target.analyzable; checkbox.checked = state.targetIds.has(target.target_id);
        checkbox.setAttribute('aria-label', `Select ${target.relative_path || target.target_id}`);
        checkbox.addEventListener('change', () => {
          if (checkbox.checked) state.targetIds.add(target.target_id); else state.targetIds.delete(target.target_id);
          row.classList.toggle('selected', checkbox.checked); controls();
        });
        choose.append(checkbox); row.append(choose, element('td', 'path-cell', target.relative_path || target.target_id), element('td', '', humanSize(target.size_bytes)),
          element('td', target.analyzable ? 'good-text' : 'muted', target.analyzable ? `Available · ${target.format || 'ELF/PE'}` : target.reason || 'Not analyzable')); rows.append(row);
      });
      if (!selection.targets?.length) {
        const row = element('tr'); const cell = element('td', 'empty', 'No analyzable targets discovered. Review discovery warnings.'); cell.colSpan = 4; row.append(cell); rows.append(row);
      }
      const runtime = selection.runtime;
      text('runtimeSummary', runtime ? (runtime.scanned ? 'scanned (reported by backend)' : 'not scanned') : 'not collected');
      text('runtimeDetails', runtime ? JSON.stringify(runtime, null, 2) : 'No runtime information collected.'); controls();
    }
    async function discover(source, upload = null) {
      if (!state.status || state.busy) return;
      message(); state.busy = true; state.selection = null; state.targetIds.clear(); byId('authorization').checked = false;
      renderTargets(); controls(); text('discoveryState', upload ? 'Uploading file bytes and discovering targets…' : 'Discovering local targets…');
      try {
        const discovered = upload ? await client.ingest(upload) : await client.discover(source);
        if (!discovered.selection_id) throw new Error('Discovery did not return a selection identifier.');
        state.selection = {...discovered, sourceKind: upload ? 'upload' : source.kind};
        state.targetIds = new Set(defaultTargets(discovered.targets));
        renderTargets(); text('discoveryState', 'Discovery complete. Review targets, tools, and authorization before analysis.');
      } catch (error) { text('discoveryState', 'Discovery failed. No selection is active.'); message(error.message); }
      finally { state.busy = false; controls(); }
    }
    function downloadLink(id, url, show) { const link = byId(id); link.hidden = !show; if (show) link.href = url; else link.removeAttribute('href'); }
    function clearResults() {
      state.result = null; state.renderedResult = null; state.compareViews = [];
      byId('evidenceContent').replaceChildren(); empty(byId('evidenceContent'), 'Waiting for this job to return evidence.');
      byId('resultTargetSelect').replaceChildren(); option(byId('resultTargetSelect'), '', 'No results collected'); byId('resultTargetSelect').disabled = true;
      warningList(byId('evidenceWarnings'), []); byId('comparisonContent').hidden = true; byId('comparisonEmpty').hidden = false;
      for (const id of ['downloadReportBtn', 'comparisonReportLink', 'downloadArtifactBtn']) downloadLink(id, '', false);
    }
    function renderResultTarget() {
      const report = state.result?.reports?.[Number(byId('resultTargetSelect').value)];
      if (!report) return;
      renderAnalysis(byId('evidenceContent'), report.analysis || {}, {prefix: 'result'});
    }
    function renderComparison() {
      const result = state.result; const protection = result.protection || {};
      const comparison = result.comparison || {};
      byId('comparisonContent').hidden = false; byId('comparisonEmpty').hidden = true;
      const labels = {symbol_removal_applied: 'Symbol removal applied', demo_obfuscation_applied: 'Demo obfuscation applied', binary_metadata_hygiene_applied: 'Binary metadata hygiene applied'};
      text('transformationState', labels[protection.state] || `Transformation: ${protection.state || 'Not collected'}`);
      warningList(byId('comparisonWarnings'), [
        protection.state === 'binary_metadata_hygiene_applied'
          ? 'Binary hygiene removes metadata from a copy. It is not code obfuscation or a protection guarantee. The target was not executed; behavior is not verified.'
          : 'Demo transformations are not a protection certification or security score. Only a bundled sample copy is modified. Targets are never executed; behavior is not verified.',
        ...(result.limitations || []), ...(comparison.limitations || []),
        ...(state.job.status === 'partial' ? ['Partial job: one or more outputs are missing or failed. Review both tool records.'] : [])
      ].map(display));
      const details = byId('transformationDetails'); details.replaceChildren();
      keyValues(details, [
        ['Tool', protection.tool], ['Method', protection.method],
        ['Command', Array.isArray(protection.command) ? protection.command.join(' ') : protection.command],
        ['Strength', protection.strength],
        ['Original SHA-256', protection.original_sha256], ['Transformed SHA-256', protection.transformed_sha256],
        ['Original artifact', result.artifacts?.original], ['Transformed artifact', result.artifacts?.transformed],
        ['Behavior verified', 'No — target not executed']
      ].filter(([, value]) => value !== undefined && value !== null && value !== ''));
      const metrics = byId('comparisonMetrics'); metrics.replaceChildren(); metrics.append(element('h3', '', 'Observed differences — not a resistance score'));
      table(metrics, ['Metric', 'Before', 'After', 'Delta'], (comparison.metrics || []).map(item => [item.name, item.before, item.after, item.delta]));
      const diffs = byId('comparisonDiffs'); diffs.replaceChildren();
      for (const kind of ['symbols', 'strings']) {
        const detail = element('details', 'details'); detail.append(element('summary', '', `${kind[0].toUpperCase() + kind.slice(1)} · added / removed`));
        const data = comparison[kind];
        if (!data) empty(detail);
        else {
          const added = data.added || [], removed = data.removed || [];
          detail.append(element('p', 'field-help', `${added.length} added / ${removed.length} removed in returned comparison data.`));
          if (!added.length && !removed.length) empty(detail, 'No added or removed entries reported. Check collection coverage before interpreting this.');
          else table(detail, ['Change', 'Entry'], [...removed.map(item => ['Removed', display(item)]), ...added.map(item => ['Added', display(item)])]);
        }
        diffs.append(detail);
      }
      state.compareViews = [renderAnalysis(byId('compareBefore'), result.before || {}, {prefix: 'before', mode: byId('compareMode').value}),
        renderAnalysis(byId('compareAfter'), result.after || {}, {prefix: 'after', mode: byId('compareMode').value})];
      downloadLink('comparisonReportLink', reportUrl(state.job.job_id), true);
      const artifactLink = byId('downloadArtifactBtn');
      artifactLink.textContent = protection.state === 'demo_obfuscation_applied' ? 'Download protected copy' : protection.state === 'binary_metadata_hygiene_applied' ? 'Download hygiene copy' : 'Download stripped copy';
      downloadLink('downloadArtifactBtn', artifactUrl(state.job.job_id), ['symbol_removal_applied', 'demo_obfuscation_applied', 'binary_metadata_hygiene_applied'].includes(protection.state));
    }
    function renderResult(result) {
      state.result = result;
      const warnings = [...(result.limitations || [])].map(display);
      if (state.job.status !== 'completed') warnings.unshift(`Job ${state.job.status}: evidence may be partial. Tool errors and absent output are not a security result.`);
      warningList(byId('evidenceWarnings'), warnings);
      downloadLink('downloadReportBtn', reportUrl(state.job.job_id), true);
      if (['strip_compare', 'protect_compare', 'binary_compare'].includes(result.operation)) {
        renderComparison();
        byId('evidenceContent').replaceChildren(); empty(byId('evidenceContent'), `${result.operation === 'binary_compare' ? 'Binary hygiene' : 'Sample'} comparison collected. Open Compare for aligned before / after evidence.`);
        const button = element('button', 'btn', 'Open comparison'); button.type = 'button'; button.addEventListener('click', () => showPage('compare')); byId('evidenceContent').append(button);
        return;
      }
      const reports = result.reports || []; const select = byId('resultTargetSelect'); select.replaceChildren();
      reports.forEach((report, index) => option(select, String(index), report.label || report.analysis?.filename || report.target_id));
      select.disabled = !reports.length;
      if (reports.length) { select.value = '0'; renderResultTarget(); }
      else { option(select, '', 'No reports collected'); byId('evidenceContent').replaceChildren(); empty(byId('evidenceContent'), 'No analysis reports collected. Review job events and failures; download the returned report if available.'); }
    }
    async function loadJobs() {
      byId('refreshJobsBtn').disabled = true;
      try {
        const data = await client.jobs(); const list = byId('recentJobs'); list.replaceChildren();
        if (!data.jobs?.length) empty(list, 'No jobs recorded by this server yet.');
        (data.jobs || []).forEach(job => {
          const row = element('div', 'recent-job'); const copy = element('div', 'recent-copy');
          copy.append(element('strong', '', job.label || job.job_id), element('span', 'muted', `${job.operation || 'static analysis'} · ${job.status}`), element('small', 'muted', job.job_id));
          const button = element('button', 'btn compact', isTerminal(job.status) ? 'Open' : 'Resume'); button.type = 'button';
          button.addEventListener('click', () => openJob(job)); row.append(copy, button); list.append(row);
        });
      } catch (error) { const list = byId('recentJobs'); list.replaceChildren(); empty(list, `Recent jobs unavailable: ${error.message}`); }
      finally { byId('refreshJobsBtn').disabled = false; }
    }
    const watcher = createJobWatcher(client, {
      onUpdate(update) {
        const previous = state.job?.status;
        state.job = {...state.job, ...update}; state.pollingPaused = false;
        byId('resumeJobBtn').hidden = true; byId('monitorError').hidden = true;
        text('jobId', update.job_id); text('jobStatus', update.status);
        byId('jobStatus').className = `badge ${update.status === 'completed' ? 'good' : ['failed', 'cancelled'].includes(update.status) ? 'bad' : 'warning'}`;
        text('monitorJobLabel', `${state.job.label || update.job_id} · ${state.job.operation || 'static analysis'} · ${update.status}`);
        const stream = byId('jobEvents');
        const atBottom = stream.scrollHeight - stream.scrollTop - stream.clientHeight < 30;
        const fresh = (update.events || []).filter(event => !state.eventsShown.has(event.seq));
        if (fresh.length && !state.eventsShown.size) stream.replaceChildren();
        fresh.forEach(event => {
          const row = element('div', `event-row${/fail|error/i.test(event.type || '') ? ' event-error' : ''}`);
          row.append(element('span', 'event-time', `${event.seq} · ${event.time || 'time unavailable'}`));
          row.append(element('span', 'event-context', [event.phase, event.target, event.tool, event.type].filter(Boolean).join(' / ')));
          row.append(element('span', 'event-message', event.message)); stream.append(row); state.eventsShown.add(event.seq);
        });
        if (atBottom && fresh.length) stream.scrollTop = stream.scrollHeight;
        text('eventCount', `${state.eventsShown.size} RECORDED EVENTS`);
        const latest = update.events?.at(-1); text('jobLatest', latest?.message || `${update.status}. Waiting for recorded backend events.`);
        if (update.error) {
          const detail = typeof update.error === 'string' ? update.error : display(update.error);
          text('monitorError', detail); byId('monitorError').hidden = false;
          message(`Job ${update.status}: ${detail}`);
        }
        if (update.result && (isTerminal(update.status) || !state.renderedResult)) {
          const key = `${update.job_id}:${update.status}`;
          if (state.renderedResult !== key) { renderResult(update.result); state.renderedResult = key; }
        }
        if (isTerminal(update.status) && !update.result) {
          warningList(byId('evidenceWarnings'), [`Job ${update.status}. No evidence returned.${update.error ? ` ${display(update.error)}` : ''}`]);
        }
        if (isTerminal(update.status) && previous !== update.status) loadJobs();
        controls();
      },
      onError(error) {
        state.pollingPaused = true;
        byId('resumeJobBtn').hidden = false;
        text('jobLatest', 'Polling interrupted. Job state is unknown; the server may still be working.');
        text('monitorError', `${error.message} Resume polling to reconnect; no result is assumed.`); byId('monitorError').hidden = false;
        message(`Job polling interrupted: ${error.message}`); controls();
      }
    });
    function openJob(job) {
      watcher.stop(); state.job = job; state.eventsShown.clear(); state.pollingPaused = false; clearResults();
      byId('jobEvents').replaceChildren(); empty(byId('jobEvents'), 'Waiting for recorded backend events…'); text('eventCount', 'NO EVENTS');
      text('jobId', job.job_id); text('jobStatus', job.status || 'queued'); text('jobLatest', 'Loading recorded job state…');
      byId('resumeJobBtn').hidden = true; byId('monitorError').hidden = true; message(); showPage('monitor'); controls();
      watcher.start(job.job_id);
    }
    async function run(operation) {
      if (!canRun(operation)) return;
      message(); state.busy = true; controls();
      try {
        const payload = makePayload(operation); const job = await client.startJob(payload);
        if (!job.job_id) throw new Error('The backend did not return a job identifier.');
        openJob({...job, status: 'queued', operation, label: state.selection.app?.name || 'Selected input'}); loadJobs();
      } catch (error) { message(error.message); }
      finally { state.busy = false; controls(); }
    }
    byId('refreshStatusBtn').addEventListener('click', refreshStatus);
    byId('refreshAppsBtn').addEventListener('click', loadApps);
    byId('refreshJobsBtn').addEventListener('click', loadJobs);
    byId('appSelect').addEventListener('change', controls);
    byId('localPath').addEventListener('input', controls);
    byId('fileInput').addEventListener('change', controls);
    byId('sampleSelect').addEventListener('change', sampleDescription);
    byId('discoverAppBtn').addEventListener('click', () => discover({kind: 'flatpak', app_id: byId('appSelect').value}));
    byId('discoverPathBtn').addEventListener('click', () => discover({kind: 'path', path: byId('localPath').value.trim()}));
    byId('localPath').addEventListener('keydown', event => { if (event.key === 'Enter' && !byId('discoverPathBtn').disabled) byId('discoverPathBtn').click(); });
    byId('discoverSampleBtn').addEventListener('click', () => discover({kind: 'sample', sample_id: byId('sampleSelect').value}));
    byId('ingestBtn').addEventListener('click', () => { const file = byId('fileInput').files[0]; if (file) discover(null, file); });
    byId('selectAllTargets').addEventListener('change', event => {
      state.targetIds = new Set(event.target.checked ? (state.selection?.targets || []).filter(target => target.analyzable).map(target => target.target_id) : []); renderTargets();
    });
    byId('authorization').addEventListener('change', controls);
    byId('toolMode').addEventListener('change', () => { renderTools(); controls(); });
    byId('analyzeBtn').addEventListener('click', () => run('analyze'));
    byId('stripCompareBtn').addEventListener('click', () => {
      const profile = byId('protectionProfile').value;
      run(profile === 'symbol_removal' ? 'strip_compare' : profile === 'binary_hygiene' ? 'binary_compare' : 'protect_compare');
    });
    byId('protectionProfile').addEventListener('change', controls);
    byId('resultTargetSelect').addEventListener('change', renderResultTarget);
    byId('compareMode').addEventListener('change', event => { state.compareViews.forEach(view => view.setMode(event.target.value)); });
    byId('resumeJobBtn').addEventListener('click', () => { if (state.job) openJob(state.job); });
    byId('cancelJobBtn').addEventListener('click', async () => {
      if (!state.job || isTerminal(state.job.status)) return;
      byId('cancelJobBtn').disabled = true;
      try { await client.cancelJob(state.job.job_id); text('jobLatest', 'Cancellation requested; waiting for the backend to confirm its state.'); await watcher.start(state.job.job_id); }
      catch (error) { message(`Cancellation request failed: ${error.message}`); controls(); }
    });
    root.addEventListener('beforeunload', () => watcher.stop());
    const ready = Promise.all([refreshStatus(), loadSamples(), loadApps(), loadJobs()]);
    return {ready, state, showPage, stop: watcher.stop};
  }
  const api = {createClient, defaultTargets, selectedTools, jobPayload, isTerminal, reportUrl, artifactUrl, createJobWatcher, graphData, analysisWarnings, renderAnalysis, boot};
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.ReverseShield = api;

  if (typeof document !== 'undefined') {
    const start = () => {
      try {
        const instance = boot();
        instance.ready.catch(error => {
          const message = document.getElementById('globalMessage');
          if (message) { message.textContent = `Workbench initialization failed: ${error.message}`; message.hidden = false; }
        });
      } catch (error) {
        const message = document.getElementById('globalMessage');
        if (message) { message.textContent = `Workbench initialization failed: ${error.message}`; message.hidden = false; }
      }
    };
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, { once: true });
    else start();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this);
