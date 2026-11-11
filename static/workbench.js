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
      const response = await fetcher(path, {credentials: 'same-origin', cache: 'no-store', ...options, headers: {...options.headers, 'X-ReverseShield-Token': token}});
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
      async loadStatus(bootstrapToken = root.document?.querySelector('meta[name="reverseshield-token"]')?.content) {
        token = bootstrapToken || '';
        if (!token) throw new Error('Reload the workbench to obtain a session token.');
        const status = await request('/api/status');
        if (status.dynamic_analysis?.enabled !== false) { token = ''; throw new Error('Static-only safety check failed: dynamic analysis must be disabled.'); }
        return status;
      },
      async download(path) {
        const response = await fetcher(path, {credentials: 'same-origin', cache: 'no-store', headers: {'X-ReverseShield-Token': token}});
        if (!response.ok) throw new Error('Download failed. Reload the page if the server restarted.');
        return response.blob();
      },
      apps: () => request('/api/apps'),
      samples: () => request('/api/samples'),
      async discover(source) {
        if (source.kind === 'path' && /^(\\\\|\/\/)/.test(source.path || '')) throw new Error('Network (UNC) paths are not supported. Copy the files to a local folder first.');
        if (source.kind === 'path' && !isAbsolutePath(source.path)) throw new Error('Enter an absolute local path, for example /home/you/app or C:\\Apps\\Tool.');
        return write('/api/discover', source);
      },
      ingest: file => write(`/api/ingest?filename=${encodeURIComponent(file.name)}`, file.data ?? file, true),
      startJob: payload => write('/api/jobs', payload),
      jobs: () => request('/api/jobs'),
      job: (id, after = 0) => request(`/api/jobs/${encodeURIComponent(id)}?after=${after}`),
      cancelJob: id => write(`/api/jobs/${encodeURIComponent(id)}/cancel`, {})
    };
  }
  // POSIX (/home/…) and Windows drive (C:\… or C:/…) paths. Network (UNC)
  // paths are refused: Windows would send the user's credentials to that host.
  function isAbsolutePath(path) {
    return typeof path === 'string' && /^(\/(?!\/)|[A-Za-z]:[\\/])/.test(path);
  }
  // Turn transport and backend errors into an action the user can take.
  function friendlyError(error) {
    const raw = String(error?.message || error || 'Unknown error');
    if (/failed to fetch|networkerror|load failed|econnrefused|fetch failed/i.test(raw) || error?.name === 'TypeError' && /fetch/i.test(raw)) {
      return 'Cannot reach the local ReverseShield server. Check that run.bat (Windows) or python3 app.py (Linux) is still running, then press Refresh.';
    }
    if (/token/i.test(raw) && /invalid|missing/i.test(raw)) return 'The session token is no longer valid (the server was restarted). Reload this page.';
    if (/non-JSON/i.test(raw)) return 'The local server returned an unexpected response. Reload the page; if it persists, restart the server.';
    if (/Selection expired/i.test(raw)) return 'The selected source expired (the server was restarted). Choose the source again.';
    if (/Large target/i.test(raw)) return `${raw} Ghidra stays off unless you confirm.`;
    if (/Traceback|Errno|\[WinError/i.test(raw)) return `A local tool or file operation failed. Details: ${raw.replace(/\s+/g, ' ').slice(0, 300)}`;
    return raw;
  }
  function largeTargets(selection, targetIds, threshold) {
    const chosen = new Set(targetIds || []);
    return (selection?.targets || []).filter(target => chosen.has(target.target_id) && Number(target.size_bytes) > threshold);
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
  function jobPayload({selection, targetIds, tools, authorized, operation, stripAvailable, binaryAvailable, ollvmAvailable, profile, options}) {
    if (!authorized) throw new Error('Confirm authorization before starting static analysis.');
    if (!selection?.selection_id) throw new Error('Discover a source and select targets first.');
    const allowed = new Set((selection.targets || []).filter(target => target.analyzable).map(target => target.target_id));
    if (!targetIds.length || targetIds.some(id => !allowed.has(id))) throw new Error('Select at least one analyzable target.');
    if (!tools.length) throw new Error('Select at least one available analysis tool.');
    if (!['analyze', 'strip_compare', 'protect_compare', 'binary_compare', 'ollvm_compare'].includes(operation)) throw new Error('Unsupported operation.');
    if (operation === 'strip_compare' || operation === 'protect_compare' || operation === 'ollvm_compare') {
      if (selection.sourceKind !== 'sample') throw new Error('Source protection is limited to bundled sample copies.');
      if (['protect_compare', 'ollvm_compare'].includes(operation) && selection.source_transform_supported === false)
        throw new Error('This hardened fixture is analysis-only; choose the original Level 5 sample for source transforms.');
      if (targetIds.length !== 1) throw new Error('Select exactly one sample target for comparison.');
    }
    if (operation === 'ollvm_compare' && !ollvmAvailable) throw new Error('The project-local xollvm toolchain is unavailable.');
    if (operation === 'binary_compare') {
      if (targetIds.length !== 1) throw new Error('Select exactly one ELF or PE target for binary hygiene.');
      if (!binaryAvailable) throw new Error('Binary hygiene tools are unavailable.');
    }
    if (profile === 'symbol_removal' || (operation === 'strip_compare' && !profile)) {
      if (!stripAvailable) throw new Error('GNU strip is unavailable.');
    }
    // Ghidra options are only sent when Ghidra is part of the run.
    const ghidra = options && tools.includes('ghidra_headless') ? {options: {...options}} : {};
    return {selection_id: selection.selection_id, target_ids: [...new Set(targetIds)], tools: [...new Set(tools)], operation,
      ...(profile ? {profile} : {}), ...ghidra, authorized: true};
  }
  const isTerminal = status => ['completed', 'partial', 'failed', 'cancelled'].includes(status);
  const reportUrl = id => `/api/jobs/${encodeURIComponent(id)}/report-sanitized`;
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
    if (typeof value === 'boolean') return value ? 'Yes' : 'No';
    return typeof value === 'object' ? JSON.stringify(value) : String(value);
  }
  // Plain-language names for tools and statuses.
  const TOOL_NAMES = {file: 'file — file type', readelf: 'readelf — Linux file structure', objdump: 'objdump — disassembler',
    strings: 'strings — readable text', nm: 'nm — symbol names', ghidra_headless: 'Ghidra — decompiler', strip: 'strip', metrics: 'built-in metrics'};
  const STATUS_TEXT = {ok: 'Finished', skipped: 'Skipped', timeout: 'Stopped at time limit', cancelled: 'Cancelled',
    tool_error: 'Failed', unavailable: 'Not installed', queued: 'Queued', running: 'Running', completed: 'Done',
    partial: 'Done, with gaps', failed: 'Failed'};
  const OPERATION_TEXT = {analyze: 'Analysis', strip_compare: 'Remove symbol names + compare',
    protect_compare: 'Hide constants (demo) + compare', binary_compare: 'Remove debug info + compare',
    ollvm_compare: 'OLLVM obfuscation + QEMU behaviour check'};
  const toolName = id => TOOL_NAMES[id] || String(id || 'tool');
  const statusText = status => STATUS_TEXT[status] || String(status || 'Unknown');
  function fmt(value) {
    if (typeof value === 'number' && Number.isFinite(value)) {
      return Number.isInteger(value) ? value.toLocaleString('en-US') : value.toLocaleString('en-US', {maximumFractionDigits: 2});
    }
    return value;
  }
  function analysisWarnings(analysis = {}) {
    const warnings = [...(analysis.limitations || [])].map(display);
    for (const tool of analysis.tools || []) {
      // A deliberate skip (readelf on PE) is reported once, with its reason, from coverage.
      if (tool.status === 'skipped' && (analysis.coverage?.tools_skipped || []).some(item => item.tool === tool.tool)) continue;
      if (!['ok', 'success', 'completed'].includes(tool.status) || (tool.return_code != null && tool.return_code !== 0)) {
        warnings.push(`${tool.label || tool.tool}: ${tool.status || 'status not collected'}${tool.return_code == null ? '' : ` (exit ${tool.return_code})`}. See the Tool output tab.`);
      }
      // Prefer the coverage line (it has sizes); fall back for older reports.
      if (tool.truncated && !(analysis.coverage?.outputs_truncated || []).some(item => item.tool === tool.tool)) warnings.push(`${tool.label || tool.tool}: output was truncated because it was too long.`);
    }
    const coverage = analysis.coverage || {};
    for (const item of coverage.tools_skipped || []) warnings.push(`${item.tool} skipped: ${display(item.reason)}`);
    for (const item of coverage.tools_failed || []) warnings.push(`${item.tool} did not finish (${display(item.status)}): ${display(item.reason)}`);
    for (const item of coverage.tools_unavailable || []) warnings.push(`${item.tool} unavailable: ${display(item.reason)}`);
    for (const item of coverage.outputs_truncated || []) warnings.push(`${item.tool} output was long, so only the first ${humanSize(item.limit_bytes)} of ${humanSize(item.output_bytes)} is shown (counts may be partial).`);
    const structured = new Set(['tools_ran', 'tools_skipped', 'tools_failed', 'tools_unavailable', 'tools_not_selected', 'outputs_truncated', 'selected_tools']);
    for (const [name, value] of Object.entries(coverage)) {
      if (structured.has(name)) continue;
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        // Nested coverage (Ghidra): name only the caps that were actually hit.
        const hit = Object.entries(value).filter(([key, flag]) => flag === true && /truncat|timed_out|exhausted|fail/i.test(key)).map(([key]) => key);
        if (hit.length) warnings.push(`${name === 'ghidra' ? 'Ghidra' : name} reached its built-in limits, so not every function was exported or decompiled (${hit.join(', ')}). The JSON report has the full counts.`);
        continue;
      }
      if (value === false || /unavailable|not.collected|partial|fail|missing|skip|truncat/i.test(display(value))) warnings.push(`Coverage — ${name}: ${display(value)}`);
    }
    for (const error of analysis.content_metrics?.errors || []) warnings.push(`Content metrics: ${display(error)}`);
    return [...new Set(warnings)];
  }
  // Replace full folder paths inside free text with "…/file-name" (readability and privacy).
  function shortPaths(text) {
    return String(text ?? '')
      .replace(/(?:file:\/\/)?\/(?:[^\s'"()<>]+\/)+([^\s'"()<>\/]+)/g, '…/$1')
      .replace(/[A-Za-z]:\\(?:[^\s'"()<>]+\\)+([^\s'"()<>\\]+)/g, '…\\$1');
  }
  // Show tool commands without local folder names (they can contain user names).
  function shortCommand(command) {
    if (command === undefined || command === null) return undefined;
    const parts = Array.isArray(command) ? command.map(String) : String(command).split(' ');
    return parts.map(part => /^([A-Za-z]:[\\/]|\/|\\\\)/.test(part) ? `…/${part.split(/[\\/]/).pop()}` : part).join(' ');
  }
  // Missing values are N/A, never zero.
  function na(value) {
    if (value === undefined || value === null || value === '') return 'N/A';
    if (typeof value === 'boolean') return value ? 'present' : 'absent';
    if (typeof value === 'number') return String(fmt(value));
    return typeof value === 'object' ? JSON.stringify(value) : String(value);
  }
  function signed(value) {
    if (typeof value !== 'number') return 'N/A';
    return value > 0 ? `+${fmt(value)}` : String(fmt(value));
  }
  function yesNo(value) { return value === undefined || value === null ? 'N/A' : value ? 'Yes' : 'No'; }
  function formatName(format) { return format === 'PE' ? 'PE (Windows program)' : format === 'ELF' ? 'ELF (Linux program)' : na(format); }
  function entropyNote(value) {
    if (typeof value !== 'number') return 'Not measured.';
    if (value >= 7.2) return 'Very random: usually compressed, packed or encrypted data.';
    if (value >= 2) return 'Normal for a compiled program.';
    return 'Very low: mostly padding, zeros or repeated data.';
  }
  function symbolTableCount(metrics = {}) {
    const sym = metrics.symbols || {};
    if ('pe_coff_symbols' in sym) return sym.pe_coff_symbols;
    if (metrics.format === 'ELF' && !(metrics.errors || []).length) return sym.elf_symbols ?? 0;
    return sym.elf_symbols;
  }
  const HARDENING_STATES = {present: 'Present', absent: 'Absent', partial: 'Partial', unknown: 'Unknown', not_applicable: 'Not applicable'};
  function hardeningRows(hardening = {}) {
    return Object.values(hardening.checks || {}).map(item => [
      item.label || 'Protection',
      HARDENING_STATES[item.state] || String(item.state || 'Unknown'),
      item.evidence || 'No evidence collected.'
    ]);
  }

  // Grouped, explained metrics. Each row: [label, value, what it means].
  function metricGroups(metrics = {}) {
    const s = metrics.sections || {}, im = metrics.imports || {}, ex = metrics.exports || {};
    const st = metrics.strings || {}, cat = st.categories || {}, sym = metrics.symbols || {}, debug = metrics.debug || {}, g = metrics.ghidra;
    const groups = [
      {title: 'File structure', rows: [
        ['File type', formatName(metrics.format), 'Linux programs are ELF; Windows programs are PE.'],
        ['Sections', na(s.count), 'Parts of the file: code, data, names, debug info…'],
        ['Code sections', na(s.executable), 'Sections the processor can run.'],
        ['Writable data sections', na(s.writable), 'Sections the program can change while running.'],
        ['Randomness (entropy, 0–8)', na(metrics.file_entropy), entropyNote(metrics.file_entropy)]]},
      {title: 'Links to other software', rows: [
        ['Imported functions', na(im.count), 'Functions borrowed from system libraries. They hint at what the program does.'],
        ['Libraries used', na(im.libraries), 'Separate library files the program needs.'],
        ['Exported functions', na(ex.count), 'Functions this file offers to other programs.']]},
      {title: 'Readable text (strings)', rows: [
        ['Text strings found', na(st.total), `Runs of at least ${st.min_length || 4} readable characters.`],
        ['File and folder names', na(cat.paths), 'Source files, headers and folders from the build.'],
        ['· full folder paths', na(st.paths_absolute), 'Complete paths show how the build machine is laid out.'],
        ['· inside a user’s home folder', na(st.paths_in_user_home), 'Paths like /home/<name>/ or C:\\Users\\<name>\\ reveal a user name.'],
        ['Web addresses (URLs)', na(cat.urls), 'Servers or websites the program mentions.'],
        ['Compiler and build notes', na(cat.compiler_notes), 'Which compiler and library versions built it.'],
        ['Messages', na(cat.messages), 'Error and status text shown to users.'],
        ['Other text', na(cat.other), 'Short or unclassified text.']]},
      {title: 'Names and debug information', rows: [
        ['Symbol names in the file', na(symbolTableCount(metrics)), 'Function and variable names left in the file. Counted from the file bytes.'],
        ...('elf_dynamic_symbols' in sym ? [['Dynamic symbol names', na(sym.elf_dynamic_symbols), 'Names needed to link with libraries. They cannot be removed.']] : []),
        ['Names found by readelf', na(sym.readelf_symbols), 'Counted by the readelf tool (Linux files only).'],
        ['Names found by nm', na(sym.nm_symbols), 'Counted by the nm tool.'],
        ['Names found by Ghidra', na(sym.ghidra_symbols), 'Includes labels Ghidra invents, so it is usually higher.'],
        ['Debug information', yesNo(debug.debug_sections_present), 'Can reveal source file names, line numbers and variable types.'],
        ['Symbol table', yesNo(debug.symbol_table_present), 'The list of names inside the file.'],
        ...('build_id_present' in debug ? [['Build ID', yesNo(debug.build_id_present), 'A unique fingerprint of the build.']] : []),
        ...('compiler_comment_present' in debug ? [['Compiler comment', yesNo(debug.compiler_comment_present), 'Compiler name and version stored in the file.']] : []),
        ...('pdb_reference_present' in debug ? [['Link to a PDB debug file', yesNo(debug.pdb_reference_present), 'Windows debug file name, often with a build folder path.']] : []),
        ...('debug_directory_present' in debug ? [['Debug directory', yesNo(debug.debug_directory_present), 'Windows debug data table.']] : [])]},
      {title: 'Ghidra decompiler', rows: g ? [
        ['Result', statusText(g.status), 'Whether Ghidra finished.'],
        ['Time taken', g.duration_seconds == null ? 'N/A' : `${fmt(g.duration_seconds)} s`, `Stops automatically after ${fmt(g.timeout_seconds)} s.`],
        ['Functions found', na(g.functions_exported), 'Functions Ghidra identified (up to the export limit).'],
        ['Functions turned into readable code', na(g.functions_decompiled), 'C-like code an analyst can read, shown in the Recovered code tab.'],
        ['Function calls mapped', na(g.call_edges), 'Which function calls which, shown in the Graphs tab.']] :
        [['Ghidra', 'Not run for this report', 'Select Ghidra in Analysis tools to recover readable code.']]},
    ];
    return groups;
  }
  // Flat view of the grouped metrics (used by tests and the comparison panels).
  function metricRows(metrics = {}) {
    return metricGroups(metrics).flatMap(group => group.rows.map(([label, value]) => [label, value]));
  }
  // The short, plain-language answer to "what can someone learn from this file?".
  function exposureFindings(analysis = {}) {
    const m = analysis.content_metrics;
    if (!m) return [];
    const st = m.strings || {}, cat = st.categories || {}, debug = m.debug || {}, g = m.ghidra, im = m.imports || {};
    const plural = (n, one, many) => `${fmt(n)} ${n === 1 ? one : many}`;
    const names = symbolTableCount(m);
    const findings = [];
    findings.push(typeof names !== 'number' ? {title: 'Function and variable names', value: 'Not checked', why: 'The symbol table could not be read.', tone: 'info'}
      : names > 0 ? {title: 'Function and variable names', value: `${fmt(names)} names left in the file`, why: 'Names make the code much easier to understand.', tone: 'notice'}
      : {title: 'Function and variable names', value: 'Removed', why: 'No symbol table was found in the file.', tone: 'ok'});
    findings.push(debug.debug_sections_present === undefined ? {title: 'Debug information', value: 'Not checked', why: 'Section names could not be read.', tone: 'info'}
      : debug.debug_sections_present ? {title: 'Debug information', value: 'Included', why: 'Can reveal source file names, line numbers and variable types.', tone: 'notice'}
      : debug.pdb_reference_present ? {title: 'Debug information', value: 'Points to a PDB file', why: 'Not inside the file, but it names its separate debug file (.pdb), usually with the build folder.', tone: 'notice'}
      : {title: 'Debug information', value: 'Not included', why: 'No debug sections were found.', tone: 'ok'});
    const home = st.paths_in_user_home || 0;
    findings.push(typeof cat.paths !== 'number' ? {title: 'File and folder names', value: 'Not checked', why: '', tone: 'info'}
      : home > 0 ? {title: 'File and folder names', value: `${fmt(cat.paths)} found`, why: `${plural(home, 'path is', 'paths are')} inside a user’s home folder, so a user name is visible.`, tone: 'notice'}
      : cat.paths > 0 ? {title: 'File and folder names', value: `${fmt(cat.paths)} found`, why: (st.paths_absolute || 0) > 0 ? `Includes ${plural(st.paths_absolute, 'full folder path', 'full folder paths')} from the build machine.` : 'Source and build file names show how the program was made.', tone: 'notice'}
      : {title: 'File and folder names', value: 'None found', why: 'No file or folder names were found in the text.', tone: 'ok'});
    const notes = cat.compiler_notes || 0;
    const buildDetails = notes + (debug.build_id_present ? 1 : 0) + (debug.compiler_comment_present ? 1 : 0);
    findings.push(buildDetails > 0 ? {title: 'Build details', value: `${plural(notes, 'compiler note', 'compiler notes')}${debug.build_id_present ? ' + build ID' : ''}`, why: 'Shows which compiler and versions built the program.', tone: 'notice'}
      : {title: 'Build details', value: 'None found', why: 'No compiler notes, build ID or compiler comment.', tone: 'ok'});
    const limit = analysis.coverage?.ghidra?.decompile_limit;
    const capped = typeof limit === 'number' && typeof g?.functions_decompiled === 'number' && g.functions_decompiled >= limit && (g.functions_exported ?? 0) > limit;
    findings.push(g ? {title: 'Readable code recovered', value: g.functions_decompiled == null ? statusText(g.status) : `${fmt(g.functions_decompiled)} of ${fmt(g.functions_exported ?? 0)} functions`,
      why: capped ? `Ghidra stops after ${fmt(limit)} functions per run to stay fast; the rest could be recovered the same way. Removing names does not stop this.` : 'Ghidra rebuilt C-like code for these functions. Removing names does not stop this.',
      tone: g.functions_decompiled ? 'notice' : 'info'}
      : {title: 'Readable code recovered', value: 'Not checked', why: 'Ghidra was not run for this report.', tone: 'info'});
    findings.push({title: 'Borrowed functions (imports)', value: typeof im.count === 'number' ? `${fmt(im.count)} from ${fmt(im.libraries ?? 0)} ${im.libraries === 1 ? 'library' : 'libraries'}` : 'Not checked',
      why: 'Hints at what the program does: files, network, encryption…', tone: 'info'});
    return findings;
  }
  function element(tag, className = '', text) {
    const node = root.document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = display(text);
    return node;
  }
  function empty(parent, message = 'Not collected. See the Tool output tab for details.') {
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
  function table(parent, headings, rows, limit = 500, className = '') {
    if (!rows.length) { empty(parent); return; }
    const wrap = element('div', `table-wrap${className ? ` ${className}` : ''}`);
    const grid = element('table');
    const head = element('thead');
    const headRow = element('tr');
    for (const heading of headings) { const th = element('th', '', heading); th.scope = 'col'; headRow.append(th); }
    head.append(headRow);
    const body = element('tbody');
    rows.slice(0, limit).forEach(values => {
      const row = element('tr');
      values.forEach(value => row.append(element('td', '', typeof value === 'number' ? fmt(value) : value)));
      body.append(row);
    });
    grid.append(head, body); wrap.append(grid); parent.append(wrap);
    if (rows.length > limit) parent.append(element('p', 'field-help', `Showing ${fmt(limit)} of ${fmt(rows.length)} rows. Download the full report (JSON) for everything.`));
  }
  function keyValues(parent, entries, headings = ['Item', 'Value']) {
    table(parent, headings, entries);
  }
  function collapsible(parent, title, open = false) {
    const details = element('details', 'details'); details.open = open;
    details.append(element('summary', '', title)); parent.append(details);
    return details;
  }
  function humanSize(value) {
    if (typeof value !== 'number') return 'Not collected';
    if (value < 1024) return `${value} bytes`;
    if (value < 1048576) return `${(value / 1024).toFixed(1)} KB`;
    return `${(value / 1048576).toFixed(2)} MB`;
  }
  function option(select, value, text, disabled = false) {
    const item = element('option', '', text); item.value = value; item.disabled = disabled; select.append(item); return item;
  }
  const METADATA_LABELS = {file_type: 'Description (from the file tool)', format: 'Format', class: 'Class', endianness: 'Byte order',
    type: 'Kind of file', machine: 'Processor', entry_point: 'Start address (entry point)', os_abi: 'Operating system',
    image_base: 'Load address (image base)', timestamp: 'Build time stamp (from the header)', symbol_entries: 'Name rows listed (all tools combined)',
    debug_info_present: 'Debug information', symbol_table_present: 'Symbol table'};
  function metadataRows(analysis) {
    const meta = analysis.metadata || {};
    const rows = [['File name', analysis.filename], ['Size', humanSize(analysis.size_bytes)], ['Fingerprint (SHA-256)', analysis.sha256],
      ['How it was analyzed', analysis.analysis_mode === 'static_only' ? 'Read as data only (never executed)' : analysis.analysis_mode]];
    for (const [key, value] of Object.entries(meta)) {
      if (['sections_count', 'section_names'].includes(key)) continue;
      let shown = value;
      if (typeof value === 'boolean') shown = value ? 'Yes' : 'No';
      if (key === 'format') shown = formatName(value);
      if (key === 'timestamp' && typeof value === 'number' && value > 0) shown = `${new Date(value * 1000).toISOString().slice(0, 10)} (can be faked)`;
      rows.push([METADATA_LABELS[key] || key.replace(/_/g, ' '), shown]);
    }
    return rows.map(([label, value]) => [label, value === undefined || value === null || value === '' ? 'N/A' : value]);
  }
  const SYMBOL_KINDS = {FUNC: 'Function', OBJECT: 'Variable', NOTYPE: 'Label', SECTION: 'Section', FILE: 'Source file', TLS: 'Thread variable',
    T: 'Function (code)', t: 'Function (code, local)', D: 'Variable (data)', d: 'Variable (data, local)', B: 'Variable (empty at start)',
    b: 'Variable (empty at start, local)', R: 'Read-only data', r: 'Read-only data (local)', U: 'Imported from a library', W: 'Weak symbol', w: 'Weak symbol',
    V: 'Weak variable', v: 'Weak variable', A: 'Absolute value', N: 'Debug symbol'};
  function renderGraph(parent, data, label, prefix) {
    parent.append(element('h3', '', label));
    if (!data.nodes.length) { empty(parent, `${label}: not collected by the selected tools.`); return; }
    parent.append(element('p', 'field-help', `Showing ${data.nodes.length} of ${data.totalNodes} boxes and ${data.edges.length} of ${data.totalEdges} arrows.${data.capped ? ' The picture is shortened; the JSON report has everything.' : ''}`));
    if (!data.totalEdges) parent.append(element('p', 'field-help', 'No arrows were collected. That does not prove there are no calls or branches.'));
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
    svg.append(svgNode('desc', {id: `${prefix}-description`}, `${data.nodes.length} boxes and ${data.edges.length} arrows from the collected data. A text list follows.`));
    const defs = svgNode('defs');
    const marker = svgNode('marker', {id: `${prefix}-arrow`, viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 6, markerHeight: 6, orient: 'auto-start-reverse'});
    marker.append(svgNode('path', {d: 'M 0 0 L 10 5 L 0 10 z', fill: 'var(--muted)'})); defs.append(marker); svg.append(defs);
    const positions = new Map(data.nodes.map((node, index) => [node.id, {x: 20 + (index % columns) * 235, y: 20 + Math.floor(index / columns) * 84}]));
    data.edges.forEach(edge => {
      const from = positions.get(edge.source), to = positions.get(edge.target);
      if (!from || !to) return;
      const self = edge.source === edge.target;
      const d = self ? `M ${from.x + 180} ${from.y + 15} C ${from.x + 240} ${from.y - 25}, ${from.x + 240} ${from.y + 55}, ${from.x + 180} ${from.y + 30}` :
        `M ${from.x + 100} ${from.y + 42} C ${from.x + 100} ${from.y + 66}, ${to.x + 100} ${to.y - 20}, ${to.x + 100} ${to.y}`;
      svg.append(svgNode('path', {d, fill: 'none', stroke: 'var(--muted)', 'stroke-width': 1.4, 'marker-end': `url(#${prefix}-arrow)`}));
    });
    data.nodes.forEach(node => {
      const {x, y} = positions.get(node.id);
      const group = svgNode('g');
      group.append(svgNode('title', {}, node.label));
      group.append(svgNode('rect', {x, y, width: 205, height: 42, rx: 8, fill: 'var(--surface)', stroke: 'var(--border-strong)'}));
      group.append(svgNode('text', {x: x + 12, y: y + 26, fill: 'var(--text)', 'font-size': 13}, node.label.length > 25 ? `${node.label.slice(0, 24)}…` : node.label));
      svg.append(group);
    });
    const viewport = element('div', 'graph-viewport'); viewport.append(svg); parent.append(viewport);
    const text = collapsible(parent, 'Same graph as a text list');
    text.append(element('pre', '', [...data.nodes.map(node => `${node.id}: ${node.label}`), '', ...data.edges.map(edge => `${edge.source} → ${edge.target}`)].join('\n')));
  }
  function renderAnalysis(parent, analysis = {}, {prefix = 'analysis', mode = 'all'} = {}) {
    parent.replaceChildren();
    const artifacts = analysis.artifacts || {};
    const functions = artifacts.functions || [];
    const metrics = analysis.content_metrics;
    let functionIndex = 0;
    let activeView = mode === 'basic' || mode === 'all' ? 'metadata' : mode;
    let currentMode = mode;
    const summary = element('div', 'analysis-summary');
    summary.append(element('strong', '', analysis.filename || 'Report'));
    summary.append(element('span', 'muted', `${humanSize(analysis.size_bytes)} · ${formatName(metrics?.format || analysis.metadata?.format)} · read as data, never executed`));
    parent.append(summary);
    const findings = exposureFindings(analysis);
    if (findings.length) {
      parent.append(element('h3', '', 'What someone could learn from this file'));
      const grid = element('div', 'findings');
      for (const item of findings) {
        const card = element('div', `finding tone-${item.tone}`);
        card.append(element('div', 'finding-title', item.title), element('div', 'finding-value', item.value));
        if (item.why) card.append(element('p', 'finding-why', item.why));
        grid.append(card);
      }
      parent.append(grid);
    }
    // Problems worth acting on stay visible; standard disclaimers are folded away.
    const limitations = new Set((analysis.limitations || []).map(display));
    const issues = analysisWarnings(analysis).filter(item => !limitations.has(item));
    const warnings = element('div', 'notice warning'); warningList(warnings, issues); parent.append(warnings);
    if (limitations.size) {
      const about = collapsible(parent, `About this report (${limitations.size} limitations)`);
      const list = element('ul'); limitations.forEach(item => list.append(element('li', '', item))); about.append(list);
    }
    const navigation = element('div', 'evidence-tabs'); navigation.setAttribute('aria-label', `${prefix} report sections`);
    const body = element('div', 'evidence-body'); parent.append(navigation, body);
    const views = ['metadata', 'functions', 'symbols', 'strings', 'pseudocode', 'graphs', 'raw'];
    const viewLabels = {metadata: 'Overview', functions: 'Functions', symbols: 'Names (symbols)', strings: 'Text (strings)',
      pseudocode: 'Recovered code', graphs: 'Graphs', raw: 'Tool output'};
    function selector() {
      const field = element('label', 'field function-field'); field.htmlFor = `${prefix}FunctionSelect`;
      field.append(element('span', '', 'Function'));
      const select = element('select'); select.id = `${prefix}FunctionSelect`;
      functions.forEach((fn, index) => option(select, String(index), `${fn.name || 'Unnamed'} · ${fn.address || 'no address'}${fn.pseudocode ? ' · code recovered' : ''}`));
      if (!functions.length) { option(select, '', 'No functions collected'); select.disabled = true; }
      else select.value = String(functionIndex);
      select.addEventListener('change', () => { functionIndex = Number(select.value); draw(); });
      field.append(select); body.append(field);
      return functions[functionIndex];
    }
    function draw() {
      navigation.replaceChildren(); body.replaceChildren();
      navigation.hidden = currentMode !== 'all';
      views.forEach(view => {
        const button = element('button', `evidence-tab${view === activeView ? ' active' : ''}`, viewLabels[view]);
        button.type = 'button'; button.dataset.evidenceView = view; button.setAttribute('aria-pressed', String(view === activeView));
        button.addEventListener('click', () => { activeView = view; draw(); navigation.querySelector(`[data-evidence-view="${view}"]`)?.focus(); }); navigation.append(button);
      });
      if (activeView === 'metadata') {
        if (metrics) {
          for (const group of metricGroups(metrics)) {
            body.append(element('h3', '', group.title));
            table(body, ['Item', 'Value', 'What it means'], group.rows, 500, 'metric-table');
          }
          const hardening = analysis.hardening;
          if (hardening && Object.keys(hardening.checks || {}).length) {
            body.append(element('h3', '', 'Exploit-mitigation properties'));
            table(body, ['Protection', 'Result', 'Evidence'], hardeningRows(hardening), 500, 'metric-table');
            body.append(element('p', 'field-help', 'Present and absent are observed binary properties. They are not a security score; absence does not prove exploitability and presence is not a guarantee.'));
            for (const warning of hardening.errors || []) body.append(element('p', 'field-help', display(warning)));
          }
          body.append(element('p', 'field-help', 'N/A means the value was not collected (for example the tool was not installed). It never means zero.'));
        } else empty(body, 'Content metrics were not collected for this report.');
        const coverage = analysis.coverage || {};
        body.append(element('h3', '', 'Which tools ran'));
        const coverageRows = [
          ...(coverage.tools_ran || []).map(tool => { const record = (analysis.tools || []).find(t => t.tool === tool) || {};
            return [toolName(tool), statusText(record.status), record.duration_seconds == null ? '' : `${fmt(record.duration_seconds)} s`]; }),
          ...(coverage.tools_skipped || []).map(item => [toolName(item.tool), 'Skipped', item.reason]),
          ...(coverage.tools_unavailable || []).map(item => [toolName(item.tool), 'Not installed', 'Install it to collect this evidence.']),
          ...(coverage.tools_not_selected || []).map(tool => [toolName(tool), 'Not selected', 'Turned off for this run.'])];
        table(body, ['Tool', 'Result', 'Time / reason'], coverageRows);
        const fileDetails = collapsible(body, 'File details (header information)');
        keyValues(fileDetails, metadataRows(analysis));
        const items = metrics?.sections?.items || [];
        const sections = collapsible(body, `Sections (${items.length || (analysis.sections || []).length})`);
        if (items.length) {
          table(sections, ['#', 'Name', 'Size', 'Code?', 'Writable?', 'Randomness (0–8)'], items.map(item => [item.index, item.name, humanSize(item.size), item.executable ? 'Yes' : 'No', item.writable ? 'Yes' : 'No', na(item.entropy)]));
          if (metrics.sections.entropy_truncated) sections.append(element('p', 'field-help', 'Randomness was measured on the first part of very large sections.'));
        } else table(sections, ['#', 'Name', 'Type', 'Address', 'Size'], (analysis.sections || []).map(item => [item.index, item.name, item.type, item.address, item.size ?? item.size_bytes]));
        const limits = collapsible(body, 'Technical limits used for this run');
        keyValues(limits, Object.entries(coverage).filter(([key]) => !/^tools_|^outputs_truncated$/.test(key)).map(([key, value]) => [key.replace(/_/g, ' '), Array.isArray(value) ? value.join(', ') : value]), ['Setting', 'Value']);
      } else if (activeView === 'functions') {
        const recovered = functions.filter(fn => fn.pseudocode).length;
        body.append(element('p', 'field-help', `${fmt(functions.length)} functions found; readable code recovered for ${fmt(recovered)}. What is found depends on the tools that ran.`));
        table(body, ['Function', 'Address', 'Size (bytes)', 'Readable code?'], functions.map(fn => [fn.name, fn.address, fn.size ?? 'N/A', fn.pseudocode ? 'Yes' : 'No']));
      } else if (activeView === 'symbols' || activeView === 'strings') {
        const items = artifacts[activeView] || [];
        const noun = activeView === 'symbols' ? 'names' : 'text strings';
        const filter = element('input'); filter.type = 'search'; filter.placeholder = `Search ${noun}…`; filter.setAttribute('aria-label', `Search ${prefix} ${noun}`);
        const count = element('p', 'field-help'); const results = element('div'); body.append(filter, count, results);
        const list = () => {
          results.replaceChildren(); const needle = filter.value.toLocaleLowerCase();
          const matches = items.filter(item => display(item).toLocaleLowerCase().includes(needle));
          count.textContent = needle ? `${fmt(matches.length)} of ${fmt(items.length)} ${noun} match.` : `${fmt(items.length)} ${noun} found.`;
          if (activeView === 'symbols') table(results, ['Name', 'Address', 'Kind', 'Size (bytes)'], matches.map(item => [item.name, item.address ?? 'N/A', SYMBOL_KINDS[item.type] || item.type || 'N/A', item.size ?? 'N/A']));
          else table(results, ['Text'], matches.map(item => [item]));
        };
        filter.addEventListener('input', list); list();
      } else if (activeView === 'pseudocode') {
        const fn = selector();
        body.append(element('p', 'field-help', 'This is Ghidra’s reconstruction of the code. It is close to the original logic, but it is not the original source.'));
        if (fn?.pseudocode) body.append(element('pre', 'pseudocode', fn.pseudocode));
        else empty(body, 'No readable code for this function. Ghidra may not have run, or it skipped this function (see Tool output).');
      } else if (activeView === 'graphs') {
        const fn = selector();
        renderGraph(body, graphData(artifacts, 'calls'), 'Which function calls which', `${prefix}-calls`);
        renderGraph(body, graphData(artifacts, 'cfg', fn), 'Paths through the selected function', `${prefix}-cfg`);
      } else if (activeView === 'raw') {
        body.append(element('p', 'field-help', 'The exact output of each tool, for checking the numbers above. Problems are opened automatically.'));
        if (!(analysis.tools || []).length) empty(body, 'No tool output collected.');
        (analysis.tools || []).forEach(tool => {
          const details = element('details', 'raw-output');
          const bad = !['ok', 'success', 'completed', 'skipped'].includes(tool.status) || (tool.return_code != null && tool.return_code !== 0);
          details.open = bad;
          details.append(element('summary', bad ? 'bad-text' : '', `${toolName(tool.tool)} · ${statusText(tool.status)}${tool.duration_seconds == null ? '' : ` · ${fmt(tool.duration_seconds)} s`}${tool.truncated ? ' · output shortened' : ''}`));
          details.append(element('p', 'tool-command', `Command: ${shortCommand(tool.command) || 'Not collected'}`));
          details.append(element('p', 'field-help', `Version: ${display(tool.version)}${tool.return_code == null ? '' : ` · exit code ${tool.return_code}`}`));
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
      busy: false, job: null, result: null, renderedResult: null, eventsShown: new Set(), compareViews: [], pollingPaused: false,
      demoJobId: null};
    const text = (id, value) => { byId(id).textContent = value; };
    function message(value = '', tone = 'error') {
      text('globalMessage', value); byId('globalMessage').hidden = !value;
      byId('globalMessage').className = `notice${tone === 'info' ? ' info' : tone === 'warning' ? ' warning' : ''}`;
    }
    function showPage(id) {
      if (!['operate', 'compare', 'monitor', 'readme'].includes(id)) return;
      document.querySelectorAll('.page').forEach(page => { page.hidden = page.id !== id; });
      document.querySelectorAll('.tab').forEach(tab => {
        const active = tab.dataset.page === id; tab.classList.toggle('active', active);
        if (active) tab.setAttribute('aria-current', 'page'); else tab.removeAttribute('aria-current');
      });
    }
    document.querySelectorAll('[data-page]').forEach(button => button.addEventListener('click', () => showPage(button.dataset.page)));
    // Light/dark theme: follows the OS until the user picks one (remembered per browser).
    function applyTheme(theme) {
      const html = document.documentElement;
      if (theme) html.dataset.theme = theme; else delete html.dataset.theme;
      const dark = theme ? theme === 'dark' : !!root.matchMedia?.('(prefers-color-scheme: dark)').matches;
      const toggle = byId('themeToggle');
      if (toggle) { toggle.textContent = dark ? 'Light mode' : 'Dark mode'; toggle.setAttribute('aria-pressed', String(dark)); }
      return dark;
    }
    let savedTheme = null;
    try { savedTheme = root.localStorage?.getItem('reverseshield-theme'); } catch (_) { savedTheme = null; }
    let darkNow = applyTheme(savedTheme === 'dark' || savedTheme === 'light' ? savedTheme : null);
    byId('themeToggle')?.addEventListener('click', () => {
      const next = darkNow ? 'light' : 'dark'; darkNow = applyTheme(next);
      try { root.localStorage?.setItem('reverseshield-theme', next); } catch (_) { /* storage may be blocked */ }
    });
    function currentTools() { return selectedTools(state.status?.tools, byId('toolMode').value, state.manualTools); }
    function canRun(operation) {
      if (!state.status || state.busy || (state.job && !isTerminal(state.job.status))) return false;
      try { makePayload(operation); return true; } catch (_) { return false; }
    }
    function largeThreshold() { return Number(state.status?.ghidra?.large_target_bytes) || 8 * 1024 * 1024; }
    function ghidraOptions() {
      const timeout = Math.round(Number(byId('ghidraTimeout').value));
      const cpu = Math.round(Number(byId('ghidraCpu').value));
      const [low, high] = state.status?.ghidra?.timeout_range_seconds || [60, 1800];
      const maxCpu = Number(state.status?.ghidra?.max_cpu_limit) || 1;
      if (!Number.isFinite(timeout) || timeout < low || timeout > high) throw new Error(`Ghidra time limit must be between ${low} and ${high} seconds.`);
      if (!Number.isFinite(cpu) || cpu < 1 || cpu > maxCpu) throw new Error(`Ghidra CPU limit must be between 1 and ${maxCpu}.`);
      return {ghidra_timeout_seconds: timeout, ghidra_max_cpu: cpu, allow_large_ghidra: byId('allowLargeGhidra').checked};
    }
    function makePayload(operation) {
      const profile = operation === 'analyze' ? undefined : byId('protectionProfile').value;
      const tools = currentTools();
      const options = tools.includes('ghidra_headless') ? ghidraOptions() : undefined;
      if (options && !options.allow_large_ghidra && largeTargets(state.selection, [...state.targetIds], largeThreshold()).length) {
        throw new Error('A large file is selected with Ghidra. Press "Skip Ghidra" or tick "Run Ghidra anyway".');
      }
      return jobPayload({selection: state.selection, targetIds: [...state.targetIds], tools,
        authorized: byId('authorization').checked, operation, profile, options,
        stripAvailable: !!state.status?.protection?.available,
        binaryAvailable: !!state.status?.protection?.binary_hygiene,
        ollvmAvailable: !!state.status?.protection?.ollvm?.available});
    }
    function updateGhidraPanel() {
      const usesGhidra = currentTools().includes('ghidra_headless');
      byId('ghidraOptions').hidden = !usesGhidra;
      const large = usesGhidra ? largeTargets(state.selection, [...state.targetIds], largeThreshold()) : [];
      byId('largeTargetWarning').hidden = !large.length;
      if (large.length) {
        const biggest = Math.max(...large.map(target => Number(target.size_bytes) || 0));
        text('largeTargetText', `${large.length} selected file${large.length > 1 ? 's are' : ' is'} larger than ${humanSize(largeThreshold())} (largest: ${humanSize(biggest)}). Ghidra may take several minutes or hit its time limit. Skip Ghidra, or confirm below.`);
      }
    }
    function controls() {
      const ready = !!state.status && !state.busy;
      byId('refreshAppsBtn').disabled = !ready;
      byId('discoverAppBtn').disabled = !ready || !byId('appSelect').value;
      byId('discoverPathBtn').disabled = !ready || !byId('localPath').value.trim();
      byId('discoverSampleBtn').disabled = !ready || !byId('sampleSelect').value;
      byId('ingestBtn').disabled = !ready || !byId('fileInput').files.length;
      byId('analyzeBtn').disabled = !canRun('analyze');
      byId('runDemoBtn').disabled = !ready || !demoSample() || (state.job && !isTerminal(state.job.status));
      updateGhidraPanel();
      const profile = byId('protectionProfile').value;
      const transformOperation = profile === 'symbol_removal' ? 'strip_compare' : profile === 'binary_hygiene' ? 'binary_compare' : profile === 'ollvm_source' ? 'ollvm_compare' : 'protect_compare';
      byId('stripCompareBtn').disabled = !canRun(transformOperation);
      byId('cancelJobBtn').disabled = !state.status || !state.job || isTerminal(state.job.status);
      const targets = (state.selection?.targets || []).filter(target => target.analyzable);
      text('selectionCount', targets.length ? `${state.targetIds.size} of ${targets.length} selected` : 'Nothing selected');
      const all = byId('selectAllTargets'); all.disabled = !targets.length || state.busy;
      all.checked = targets.length > 0 && targets.length === state.targetIds.size;
      all.indeterminate = state.targetIds.size > 0 && state.targetIds.size < targets.length;
      // Blocking reasons for Analyze come first, then transform-profile notes.
      let hint = 'Ready. Analyze reads the selected files only; transformations operate on one copy at a time.';
      if (!state.status) hint = 'The local server is not connected. Start run.bat (or python3 app.py) and press Refresh in Analysis tools.';
      else if (state.job && !isTerminal(state.job.status)) hint = 'A selected job is active. Cancel it or wait for completion before starting another run.';
      else if (!state.selection) hint = 'No source selected yet. Choose a source in step 01, or press "Run demo · Level 5".';
      else if (!(state.selection.targets || []).some(target => target.analyzable)) hint = 'This source has no analyzable ELF or PE targets. Choose another folder, file or sample.';
      else if (!state.targetIds.size) hint = 'Select at least one target in the table above.';
      else if (!currentTools().length) hint = 'Select at least one available analysis tool.';
      else if (!byId('ghidraOptions').hidden && !byId('largeTargetWarning').hidden && !byId('allowLargeGhidra').checked) hint = 'A large file is selected with Ghidra. Press "Skip Ghidra" or tick "Run Ghidra anyway".';
      else if (!byId('authorization').checked) hint = 'Confirm the authorization checkbox to enable analysis.';
      else if (['constant_blinding', 'ollvm_source'].includes(profile) && state.selection.source_transform_supported === false) hint = 'Analyze is ready. The hardened Level 5 fixture is analysis-only; choose the original Level 5 for source transforms.';
      else if (profile === 'binary_hygiene' && state.targetIds.size !== 1) hint = 'Analyze is ready. Binary hygiene needs exactly one selected ELF or PE target.';
      else if (['symbol_removal', 'constant_blinding', 'ollvm_source'].includes(profile) && state.selection.sourceKind !== 'sample') hint = 'Analyze is ready. Source transforms are limited to bundled sample copies; binary hygiene can run on any one selected ELF or PE copy.';
      else if (profile === 'symbol_removal' && !state.status?.protection?.available) hint = 'Analyze is ready. GNU strip is unavailable; demo constant blinding remains available for bundled samples.';
      else if (profile === 'binary_hygiene' && !state.status?.protection?.binary_hygiene) hint = 'Analyze is ready. Binary hygiene requires GNU strip and objcopy; one is unavailable.';
      else if (profile === 'ollvm_source' && !state.status?.protection?.ollvm?.available) hint = state.status?.platform === 'windows'
        ? 'Analyze is ready. OLLVM source transforms and QEMU verification are unavailable on native Windows; use a supported Linux host.'
        : 'Analyze is ready. The project-local xollvm toolchain is unavailable.';
      else if (profile === 'ollvm_source' && state.selection.sourceKind === 'sample' && state.targetIds.size !== 1) hint = 'OLLVM protection needs exactly one selected sample target.';
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
        const copy = element('span', 'tool-copy'); copy.append(element('strong', '', toolName(id)));
        // The full install path stays in the tooltip only: it can contain the Windows user name.
        const version = element('small', '', info.version || (info.available ? 'Version not reported' : 'Not installed'));
        if (info.path) row.title = info.path;
        copy.append(version);
        if (id === 'ghidra_headless' && info.available) copy.append(element('small', 'warn-text', 'Ghidra may take several minutes on large targets.'));
        if (!info.available) copy.append(element('small', 'warn-text', id === 'readelf' ? 'Not installed — PE files do not need it.' : 'Not installed — run setup.bat (Windows) or install binutils (Linux).'));
        const badge = element('span', `tool-state${info.available ? '' : ' missing'}`, info.available ? 'Ready' : 'Not installed');
        badge.title = `Works on ${info.format || 'ELF/PE'} files`;
        row.append(checkbox, copy, badge); list.append(row);
      });
    }
    async function refreshStatus() {
      byId('refreshStatusBtn').disabled = true;
      try {
        const status = await client.loadStatus();
        const first = !state.status;
        state.status = status;
        if (first) state.manualTools = new Set(selectedTools(status.tools, 'all', new Set()));
        text('connectionText', 'Connected · static analysis only'); byId('connectionText').className = 'badge good';
        text('versionText', `Version ${status.version || 'local'} · host targets never executed`);
        const cpu = byId('ghidraCpu'); const timeout = byId('ghidraTimeout');
        cpu.max = String(status.ghidra?.max_cpu_limit || 1);
        if (first) {
          cpu.value = String(Math.min(status.ghidra?.default_max_cpu || 2, status.ghidra?.max_cpu_limit || 1));
          timeout.value = String(status.ghidra?.default_timeout_seconds || 240);
        }
        [timeout.min, timeout.max] = (status.ghidra?.timeout_range_seconds || [60, 1800]).map(String);
        renderTools(); message();
      } catch (error) {
        state.status = null; text('connectionText', 'Server not reachable'); byId('connectionText').className = 'badge bad';
        message(`${friendlyError(error)} Operations are disabled until the server answers.`);
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
        if (data.available === false) text('appsMessage', `Flatpak is not available on this machine (normal on Windows). Use Local path, Upload file or Bundled sample instead.${warnings ? ` Detail: ${warnings}` : ''}`);
        else text('appsMessage', `${state.apps.length} applications listed. Runtime dependencies are not scanned.${warnings ? ` ${warnings}` : ''}`);
      } catch (error) { text('appsMessage', `Flatpak listing unavailable: ${error.message}`); }
      finally { controls(); }
    }
    function renderTargets() {
      const selection = state.selection; const rows = byId('targetRows'); rows.replaceChildren();
      if (!selection) {
        const row = element('tr'); const cell = element('td', 'empty', 'Choose a source to list its programs.'); cell.colSpan = 4; row.append(cell); rows.append(row);
        text('selectionName', 'No source chosen yet'); text('selectionDetail', 'Choosing a source does not start any analysis.');
        warningList(byId('discoveryWarnings'), []); text('runtimeSummary', 'not collected'); text('runtimeDetails', 'No runtime information collected.'); controls(); return;
      }
      text('selectionName', selection.app?.name || selection.app?.app_id || 'Selected input');
      text('selectionDetail', [selection.app?.version, {sample: 'Bundled sample', upload: 'Uploaded file', path: 'File or folder on this computer', flatpak: 'Installed app'}[selection.sourceKind] || selection.sourceKind, `${fmt(selection.targets?.length || 0)} program${selection.targets?.length === 1 ? '' : 's'} found`].filter(Boolean).join(' · '));
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
        const status = element('td', target.analyzable ? 'good-text' : 'muted');
        const format = String(target.format || 'ELF/PE').toUpperCase();
        status.append(element('span', `fmt-badge ${format === 'PE' ? 'pe' : format === 'ELF' ? 'elf' : ''}`, format));
        status.append(document.createTextNode(` ${target.analyzable ? 'Available' : target.reason || 'Not analyzable'}`));
        if (target.analyzable && Number(target.size_bytes) > largeThreshold()) status.append(element('small', 'warn-text block', 'Large: Ghidra may take several minutes.'));
        choose.append(checkbox); row.append(choose, element('td', 'path-cell', target.relative_path || target.target_id), element('td', '', humanSize(target.size_bytes)), status); rows.append(row);
      });
      if (!selection.targets?.length) {
        const row = element('tr'); const cell = element('td', 'empty', 'No analyzable targets discovered. Review discovery warnings.'); cell.colSpan = 4; row.append(cell); rows.append(row);
      }
      const runtime = selection.runtime;
      text('runtimeSummary', runtime ? `${(runtime.dependencies || []).length} listed, not scanned` : 'not collected');
      text('runtimeDetails', runtime ? JSON.stringify(runtime, null, 2) : 'No runtime information collected.'); controls();
    }
    async function discover(source, upload = null) {
      if (!state.status || state.busy) return;
      message(); state.busy = true; state.selection = null; state.targetIds.clear(); byId('authorization').checked = false;
      renderTargets(); controls(); text('discoveryState', upload ? 'Uploading the file and looking for programs…' : 'Looking for programs…');
      try {
        const discovered = upload ? await client.ingest(upload) : await client.discover(source);
        if (!discovered.selection_id) throw new Error('Discovery did not return a selection identifier.');
        state.selection = {...discovered, sourceKind: upload ? 'upload' : source.kind};
        state.targetIds = new Set(defaultTargets(discovered.targets));
        renderTargets(); text('discoveryState', 'Done. Check the files in step 2, then confirm the checkbox and start.');
      } catch (error) { text('discoveryState', 'Could not read that source. See the message at the top of the page.'); message(friendlyError(error)); }
      finally { state.busy = false; controls(); }
    }
    function downloadLink(id, url, show) {
      const link = byId(id); link.hidden = !show; link.removeAttribute('href');
      if (!show) { link.onclick = null; return; }
      link.href = '#';
      link.onclick = async event => {
        event.preventDefault();
        try {
          const blob = await client.download(url);
          const objectUrl = URL.createObjectURL(blob);
          const save = document.createElement('a'); save.href = objectUrl;
          save.download = id === 'downloadArtifactBtn' ? 'reverseshield-changed-copy.bin' : 'reverseshield-sanitized.json';
          save.click(); setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
        } catch (error) { byId('globalMessage').textContent = friendlyError(error); }
      };
    }
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
      const labels = {symbol_removal_applied: 'Symbol removal applied — names were removed from a copy',
        demo_obfuscation_applied: 'Demo obfuscation applied — constants were hidden in a rebuilt copy',
        binary_metadata_hygiene_applied: 'Binary metadata hygiene applied — debug info and build notes were removed from a copy',
        ollvm_obfuscation_applied: 'OLLVM obfuscation applied — control flow and strings were transformed in a rebuilt copy'};
      text('transformationState', labels[protection.state] || `Change applied: ${protection.state || 'Not collected'}`);
      warningList(byId('comparisonWarnings'), [
        protection.state === 'binary_metadata_hygiene_applied'
          ? 'This removes metadata from a copy. It is not code obfuscation and not a protection guarantee. Nothing was executed, so behaviour is not verified.'
          : protection.state === 'ollvm_obfuscation_applied'
            ? (protection.driver_vectors_matched
              ? 'OLLVM rebuilt a sample copy. QEMU matched deterministic vectors from separate driver builds, not the downloadable protected ELF; its behavior is not verified. Generated code and Ghidra labels may increase counts; they are not a security score.'
              : 'OLLVM rebuilt a sample copy, but the separate QEMU driver check did not pass. The downloadable protected ELF was not executed or behaviorally verified.')
            : 'This is a demonstration on a copy of a bundled sample. It is not real protection or a security score. Nothing was executed, so behaviour is not verified.',
        ...(state.job.status === 'partial' ? ['Some tools did not finish, so a few numbers are missing (N/A). Check Tool output in both panels.'] : []),
        ...(state.job.status === 'failed' ? [`Analyzing the changed copy failed: ${display(state.job.error)}. The original report and the change details are kept below.`] : [])
      ].map(display));
      const details = byId('transformationDetails'); details.replaceChildren();
      const strength = {metadata_only: 'Metadata only (code unchanged)', demonstration_only: 'Demonstration only', source_obfuscation: 'Source obfuscation (control flow + strings)'}[protection.strength] || protection.strength;
      const detailsBox = collapsible(details, 'How the copy was made');
      keyValues(detailsBox, [
        ['Tool used', protection.tool], ['Method', protection.method],
        ['Command (folder names hidden)', shortCommand(protection.command)],
        ['Strength', strength],
        ['Original fingerprint (SHA-256)', protection.original_sha256], ['Changed copy fingerprint (SHA-256)', protection.transformed_sha256],
        ['Original file', result.artifacts?.original], ['Changed copy', result.artifacts?.transformed],
        ['Separate driver vectors', protection.state === 'ollvm_obfuscation_applied'
          ? (protection.driver_vectors_matched ? 'Matched in QEMU — separate driver builds only' : 'Not matched or unavailable')
          : 'Not tested'],
        ['Downloadable artifact behavior', 'Not verified — the downloadable copy was not executed']
      ].filter(([, value]) => value !== undefined && value !== null && value !== ''));
      if (protection.state === 'ollvm_obfuscation_applied' && result.behavior) {
        const behavior = result.behavior;
        const behaviorBox = collapsible(details, `QEMU behaviour check (${behavior.passed ? 'passed' : 'not passed'})`);
        keyValues(behaviorBox, [
          ['Result', behavior.passed ? 'Matched — original and protected separate-driver transcripts' : 'Not passed'],
          ['Scope', 'Separate deterministic driver builds, not the downloadable protected ELF'],
          ['Exit codes', behavior.exit_codes ? `original ${behavior.exit_codes.original}, protected ${behavior.exit_codes.protected}` : 'Not collected'],
          ['Isolation', 'QEMU micro-VM; no disk, no network'],
          ['Guest time', behavior.duration_seconds != null ? `${behavior.duration_seconds}s` : 'N/A'],
          ['Limitation', (behavior.limitations || []).join(' ') || 'Deterministic drivers only']
        ].filter(([, value]) => value !== undefined && value !== null && value !== ''));
        if (behavior.original_output || behavior.protected_output) {
          behaviorBox.append(element('h4', '', 'Original driver output'));
          behaviorBox.append(element('pre', '', behavior.original_output || 'Not collected'));
          behaviorBox.append(element('h4', '', 'Protected driver output'));
          behaviorBox.append(element('pre', '', behavior.protected_output || 'Not collected'));
        }
      }
      const afterTitles = {symbol_removal_applied: 'After · symbols-removed copy', demo_obfuscation_applied: 'After · demo-transformed copy',
        binary_metadata_hygiene_applied: 'After · metadata-hygiene copy', ollvm_obfuscation_applied: 'After · OLLVM-protected copy'};
      text('compareAfterTitle', afterTitles[protection.state] || 'After · transformed copy');
      text('compareBeforeTitle', protection.state === 'binary_metadata_hygiene_applied' ? 'Before · original copy' : 'Before · original sample');
      const summary = byId('comparisonSummary'); summary.replaceChildren();
      const groups = comparison.summary || {};
      const changeBox = element('div', 'summary-box changed'); changeBox.append(element('h3', '', `What changed (${(groups.changed || []).length})`));
      const sameBox = element('div', 'summary-box'); sameBox.append(element('h3', '', `What stayed the same (${(groups.unchanged || []).length})`));
      const naBox = element('div', 'summary-box muted-box'); naBox.append(element('h3', '', `Not measured — N/A (${(groups.not_collected || []).length})`));
      for (const [box, items, none] of [[changeBox, groups.changed, 'Nothing changed in the measured values.'], [sameBox, groups.unchanged, 'Every measured value changed.'], [naBox, groups.not_collected, 'Everything was measured on both sides.']]) {
        if (!items?.length) box.append(element('p', 'field-help', none));
        else { const list = element('ul'); items.forEach(item => list.append(element('li', '', item))); box.append(list); }
      }
      summary.append(changeBox, sameBox, naBox);
      const metrics = byId('comparisonMetrics'); metrics.replaceChildren(); metrics.append(element('h3', '', 'All measurements, before and after (not a security score)'));
      table(metrics, ['What was measured', 'Before', 'After', 'Change'], (comparison.metrics || []).map(item => [item.name, na(item.before), na(item.after), item.delta === 0 ? 'no change' : signed(item.delta)]));
      metrics.append(element('p', 'field-help', 'Counts from combined tools can increase after obfuscation because generated code, extra strings, and Ghidra analysis labels appear. This does not by itself mean weaker protection or a security regression. Compare file symbol tables, plaintext messages, recovered logic, and the limited QEMU check separately.'));
      metrics.append(element('p', 'field-help', 'N/A means the value was not measured on that side (for example the tool was not selected). It is never counted as zero.'));
      const functionsBox = byId('comparisonFunctions'); functionsBox.replaceChildren();
      functionsBox.append(element('h3', '', 'Which functions can still be matched'));
      const fm = comparison.functions;
      if (!fm || !fm.available) empty(functionsBox, `Function matching is not available: ${fm?.reason || 'functions were not collected on both sides'}.`);
      else {
        keyValues(functionsBox, [['Same start address in both', fm.matched_by_address], ['Same name in both (address moved)', fm.matched_by_name],
          ['Same address, but the name changed', (fm.renamed_at_same_address || []).length], ['Only in the original', fm.unmatched_before_count], ['Only in the copy', fm.unmatched_after_count]], ['Functions', 'Count']);
        const rows = [...(fm.renamed_at_same_address || []).map(item => ['Renamed', item]), ...(fm.unmatched_before || []).map(item => ['Only before', item]), ...(fm.unmatched_after || []).map(item => ['Only after', item])];
        if (rows.length) { const detail = collapsible(functionsBox, `List of renamed and unmatched functions (${rows.length}${fm.truncated ? ', shortened' : ''})`); table(detail, ['What happened', 'Function'], rows); }
        functionsBox.append(element('p', 'field-help', 'A match only means the same address or name was seen. It does not prove the code does the same thing.'));
      }
      const limits = byId('comparisonLimitations'); limits.replaceChildren(); limits.append(element('h3', '', 'Keep in mind'));
      const limitList = element('ul'); [...new Set([...(result.limitations || []), ...(comparison.limitations || [])])].forEach(item => limitList.append(element('li', '', item))); limits.append(limitList);
      const diffs = byId('comparisonDiffs'); diffs.replaceChildren();
      for (const kind of ['symbols', 'strings']) {
        const detail = element('details', 'details'); detail.append(element('summary', '', kind === 'symbols' ? 'Names added or removed' : 'Text strings added or removed'));
        const data = comparison[kind];
        if (!data) empty(detail);
        else {
          const added = data.added || [], removed = data.removed || [];
          detail.append(element('p', 'field-help', `${fmt(removed.length)} removed · ${fmt(added.length)} added.`));
          if (!added.length && !removed.length) empty(detail, 'Nothing was added or removed. Check that the same tools ran on both sides.');
          else table(detail, ['What happened', 'Entry'], [...removed.map(item => ['Removed', display(item)]), ...added.map(item => ['Added', display(item)])]);
        }
        diffs.append(detail);
      }
      state.compareViews = [renderAnalysis(byId('compareBefore'), result.before || {}, {prefix: 'before', mode: byId('compareMode').value}),
        renderAnalysis(byId('compareAfter'), result.after || {}, {prefix: 'after', mode: byId('compareMode').value})];
      downloadLink('comparisonReportLink', reportUrl(state.job.job_id), true);
      const artifactLink = byId('downloadArtifactBtn');
      artifactLink.textContent = protection.state === 'demo_obfuscation_applied' ? 'Download demo-transformed copy' : protection.state === 'binary_metadata_hygiene_applied' ? 'Download cleaned copy' : protection.state === 'ollvm_obfuscation_applied' ? 'Download OLLVM-protected copy' : 'Download copy without names';
      downloadLink('downloadArtifactBtn', artifactUrl(state.job.job_id), ['symbol_removal_applied', 'demo_obfuscation_applied', 'binary_metadata_hygiene_applied', 'ollvm_obfuscation_applied'].includes(protection.state));
    }
    function renderResult(result) {
      state.result = result;
      // Standard disclaimers live in each report's "About this report" section.
      const warnings = state.job.status === 'completed' ? [] :
        [`This analysis ended as “${statusText(state.job.status)}”, so some evidence may be missing. A missing result is not a sign the program is safe.`];
      warningList(byId('evidenceWarnings'), warnings);
      downloadLink('downloadReportBtn', reportUrl(state.job.job_id), true);
      if (['strip_compare', 'protect_compare', 'binary_compare', 'ollvm_compare'].includes(result.operation)) {
        renderComparison();
        byId('evidenceContent').replaceChildren(); empty(byId('evidenceContent'), 'The before/after comparison is ready on the Compare page.');
        const button = element('button', 'btn primary', 'Open the comparison'); button.type = 'button'; button.addEventListener('click', () => showPage('compare')); byId('evidenceContent').append(button);
        return;
      }
      const reports = result.reports || []; const select = byId('resultTargetSelect'); select.replaceChildren();
      reports.forEach((report, index) => option(select, String(index), report.label || report.analysis?.filename || report.target_id));
      select.disabled = !reports.length;
      if (reports.length) { select.value = '0'; renderResultTarget(); }
      else { option(select, '', 'No reports'); byId('evidenceContent').replaceChildren(); empty(byId('evidenceContent'), 'No report was produced. Check the Activity log for the reason; the JSON download may still contain partial data.'); }
    }
    async function loadJobs() {
      byId('refreshJobsBtn').disabled = true;
      try {
        const data = await client.jobs(); const list = byId('recentJobs'); list.replaceChildren();
        if (!data.jobs?.length) empty(list, 'No jobs recorded by this server yet.');
        (data.jobs || []).forEach(job => {
          const row = element('div', 'recent-job'); const copy = element('div', 'recent-copy');
          copy.append(element('strong', '', job.label || job.job_id), element('span', 'muted', `${OPERATION_TEXT[job.operation] || 'Analysis'} · ${statusText(job.status)}`), element('small', 'muted', `ID ${job.job_id}`));
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
        text('jobId', `ID ${update.job_id}`); text('jobStatus', statusText(update.status)); byId('jobStatus').dataset.status = update.status;
        byId('jobStatus').className = `badge ${update.status === 'completed' ? 'good' : ['failed', 'cancelled'].includes(update.status) ? 'bad' : 'warning'}`;
        text('monitorJobLabel', `${state.job.label || update.job_id} · ${OPERATION_TEXT[state.job.operation] || 'Analysis'} · ${statusText(update.status)}`);
        const stream = byId('jobEvents');
        const atBottom = stream.scrollHeight - stream.scrollTop - stream.clientHeight < 30;
        const fresh = (update.events || []).filter(event => !state.eventsShown.has(event.seq));
        if (fresh.length && !state.eventsShown.size) stream.replaceChildren();
        fresh.forEach(event => {
          const row = element('div', `event-row${/fail|error/i.test(event.type || '') ? ' event-error' : ''}`);
          const when = event.time ? new Date(event.time) : null;
          const time = element('span', 'event-time', when && !Number.isNaN(when.getTime()) ? when.toLocaleTimeString('en-GB', {hour12: false}) : `#${event.seq}`);
          time.title = `Message ${event.seq}${event.time ? ` · ${event.time}` : ''}`;
          row.append(time);
          const phase = {before: 'Original', after: 'Changed copy', analysis: 'Analysis', transform: 'Making copy'}[event.phase] || event.phase;
          row.append(element('span', 'event-context', [phase, event.target, event.tool ? toolName(event.tool) : null].filter(Boolean).join(' · ') || statusText(event.type)));
          let shown = shortPaths(event.message);
          if (event.type === 'tool_start' && event.tool) shown = `Started: ${shortPaths(shortCommand(event.command || event.message))}`;
          if (event.type === 'tool_end' && event.status) shown = `${statusText(event.status)}${event.duration_seconds == null ? '' : ` in ${fmt(event.duration_seconds)} s`}${event.truncated ? ' (output shortened)' : ''}`;
          const messageNode = element('span', 'event-message', shown); messageNode.title = String(event.message ?? '');
          row.append(messageNode); stream.append(row); state.eventsShown.add(event.seq);
        });
        if (atBottom && fresh.length) stream.scrollTop = stream.scrollHeight;
        text('eventCount', `${fmt(state.eventsShown.size)} messages`);
        const latest = update.events?.at(-1); text('jobLatest', latest?.message || `${update.status}. Waiting for recorded backend events.`);
        if (update.error) {
          const detail = typeof update.error === 'string' ? update.error : display(update.error);
          text('monitorError', detail); byId('monitorError').hidden = false;
          message(`Job ${update.status}: ${friendlyError({message: detail})}`);
        }
        if (update.result && (isTerminal(update.status) || !state.renderedResult)) {
          const key = `${update.job_id}:${update.status}`;
          if (state.renderedResult !== key) { renderResult(update.result); state.renderedResult = key; }
        }
        if (isTerminal(update.status) && !update.result) {
          warningList(byId('evidenceWarnings'), [`Job ${update.status}. No evidence returned.${update.error ? ` ${display(update.error)}` : ''}`]);
        }
        if (isTerminal(update.status) && previous !== update.status) loadJobs();
        if (update.status === 'cancelled' && previous !== 'cancelled') message('Run cancelled. Any evidence collected before the cancel is kept in the report; start a new run when ready.', 'warning');
        finishDemo(update);
        controls();
      },
      onError(error) {
        state.pollingPaused = true;
        byId('resumeJobBtn').hidden = false;
        text('jobLatest', 'Polling interrupted. Job state is unknown; the server may still be working.');
        text('monitorError', `${friendlyError(error)} Resume polling to reconnect; no result is assumed.`); byId('monitorError').hidden = false;
        message(`Job polling interrupted: ${friendlyError(error)}`); controls();
      }
    });
    function openJob(job) {
      watcher.stop(); state.job = job; state.eventsShown.clear(); state.pollingPaused = false; clearResults();
      byId('jobEvents').replaceChildren(); empty(byId('jobEvents'), 'Waiting for the first message…'); text('eventCount', 'No messages yet');
      text('jobId', `ID ${job.job_id}`); text('jobStatus', statusText(job.status || 'queued')); byId('jobStatus').dataset.status = job.status || 'queued'; text('jobLatest', 'Loading…');
      byId('resumeJobBtn').hidden = true; byId('monitorError').hidden = true; message(); showPage('monitor'); controls();
      watcher.start(job.job_id);
    }
    async function run(operation, {demo = false} = {}) {
      if (!canRun(operation)) return null;
      message(); state.busy = true; controls();
      try {
        const payload = makePayload(operation); const job = await client.startJob(payload);
        if (!job.job_id) throw new Error('The backend did not return a job identifier.');
        if (demo) state.demoJobId = job.job_id;
        openJob({...job, status: 'queued', operation, label: state.selection.app?.name || 'Selected input'}); loadJobs();
        return job.job_id;
      } catch (error) { message(friendlyError(error)); return null; }
      finally { state.busy = false; controls(); }
    }
    function demoSample() {
      const id = state.status?.demo?.sample_id || 'level-5';
      return state.samples.find(sample => sample.id === id && sample.available);
    }
    // One click: choose the Level 5 sample, select all its targets, run all
    // available tools and open the report. Nothing runs on page load.
    async function runDemo() {
      const sample = demoSample();
      if (!state.status || state.busy || !sample || (state.job && !isTerminal(state.job.status))) return;
      showPage('operate');
      text('demoState', `Step 1/3 · selecting ${sample.name}…`);
      byId('sampleSelect').value = sample.id; sampleDescription();
      await discover({kind: 'sample', sample_id: sample.id});
      if (!state.selection) { text('demoState', 'Demo stopped: the sample could not be selected. See the message above.'); return; }
      state.targetIds = new Set((state.selection.targets || []).filter(target => target.analyzable).map(target => target.target_id));
      byId('toolMode').value = 'all'; renderTools();
      byId('allowLargeGhidra').checked = false;
      // The bundled sample is self-authored; the demo action is the authorization.
      byId('authorization').checked = true;
      renderTargets();
      const tools = currentTools();
      text('demoState', `Step 2/3 · running ${tools.length} static tool${tools.length === 1 ? '' : 's'}${tools.includes('ghidra_headless') ? ' (Ghidra can take a minute)' : ''}…`);
      try { makePayload('analyze'); }
      catch (error) { message(friendlyError(error)); text('demoState', 'Demo stopped before analysis started. See the message above.'); return; }
      const jobId = await run('analyze', {demo: true});
      if (!jobId) text('demoState', 'Demo stopped before analysis started. See the message above.');
    }
    function finishDemo(update) {
      if (state.demoJobId !== update.job_id || !isTerminal(update.status)) return;
      state.demoJobId = null;
      const labels = {completed: 'Step 3/3 · done. The Level 5 report is open below.',
        partial: 'Step 3/3 · done with partial evidence; tool warnings are listed above the report.',
        failed: 'Demo run failed. The reason is shown above; the event log is on Monitor.',
        cancelled: 'Demo run cancelled. Start it again when ready.'};
      text('demoState', labels[update.status]);
      if (['completed', 'partial'].includes(update.status)) {
        showPage('operate');
        const panel = byId('evidencePanel'); panel.scrollIntoView({block: 'start'}); panel.focus({preventScroll: true});
      }
    }
    byId('runDemoBtn').addEventListener('click', runDemo);
    byId('lightweightBtn').addEventListener('click', () => {
      byId('toolMode').value = 'manual';
      state.manualTools = new Set(selectedTools(state.status?.tools, 'all', new Set()).filter(id => id !== 'ghidra_headless'));
      byId('allowLargeGhidra').checked = false; renderTools(); controls();
      message('Ghidra is turned off for this run. The faster tools (file, readelf, objdump, strings, nm) still run.', 'info');
    });
    for (const id of ['allowLargeGhidra', 'ghidraTimeout', 'ghidraCpu']) byId(id).addEventListener('input', controls);
    byId('refreshStatusBtn').addEventListener('click', refreshStatus);
    byId('refreshAppsBtn').addEventListener('click', loadApps);
    byId('refreshJobsBtn').addEventListener('click', loadJobs);
    byId('appSelect').addEventListener('change', controls);
    byId('localPath').addEventListener('input', controls);
    byId('fileInput').addEventListener('change', () => {
      const file = byId('fileInput').files[0];
      const label = byId('fileName'); if (label) label.textContent = file ? `${file.name} (${humanSize(file.size)})` : 'No file chosen';
      controls();
    });
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
      run(profile === 'symbol_removal' ? 'strip_compare' : profile === 'binary_hygiene' ? 'binary_compare' : profile === 'ollvm_source' ? 'ollvm_compare' : 'protect_compare');
    });
    byId('protectionProfile').addEventListener('change', controls);
    byId('resultTargetSelect').addEventListener('change', renderResultTarget);
    byId('compareMode').addEventListener('change', event => { state.compareViews.forEach(view => view.setMode(event.target.value)); });
    byId('resumeJobBtn').addEventListener('click', () => { if (state.job) openJob(state.job); });
    byId('cancelJobBtn').addEventListener('click', async () => {
      if (!state.job || isTerminal(state.job.status)) return;
      byId('cancelJobBtn').disabled = true;
      try { await client.cancelJob(state.job.job_id); text('jobLatest', 'Cancellation requested; waiting for the backend to confirm its state.'); await watcher.start(state.job.job_id); }
      catch (error) { message(`Cancellation request failed: ${friendlyError(error)}`); controls(); }
    });
    root.addEventListener('beforeunload', () => watcher.stop());
    const ready = refreshStatus().then(() => Promise.all([loadSamples(), loadApps(), loadJobs()]));
    return {ready, state, showPage, stop: watcher.stop};
  }
  const api = {createClient, defaultTargets, selectedTools, jobPayload, isTerminal, reportUrl, artifactUrl, createJobWatcher, graphData, analysisWarnings, renderAnalysis, boot,
    isAbsolutePath, friendlyError, largeTargets, metricRows, metricGroups, hardeningRows, exposureFindings, na, shortCommand, shortPaths, humanSize, fmt};
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
