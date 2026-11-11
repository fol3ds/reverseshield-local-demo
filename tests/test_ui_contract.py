"""Dependency-free browser contract tests using Node and static HTML/JS inputs.

Outputs are assertions over authorization, navigation and safe rendering. UI
code never executes selected targets or inserts backend strings as HTML.
Extend by checking the client contract and keeping tests independent of a live
browser session.
"""
from html.parser import HTMLParser
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "static"


class Document(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.elements = []
        self.feed(text)

    def handle_starttag(self, tag, attributes):
        self.elements.append((tag, dict(attributes)))

    def by_id(self, name):
        return next((attrs for _, attrs in self.elements if attrs.get("id") == name), None)


class WorkbenchUiContractTests(unittest.TestCase):
    def test_operate_shell_exposes_discovery_safety_and_local_assets(self):
        html = (STATIC / "index.html").read_text(encoding="utf-8")
        doc = Document(html)
        for name in ("operate", "compare", "monitor", "readme", "appSelect", "refreshAppsBtn",
                     "discoverAppBtn", "localPath", "discoverPathBtn", "fileInput", "ingestBtn",
                     "sampleSelect", "discoverSampleBtn", "targetRows", "toolMode", "toolList",
                     "authorization", "analyzeBtn", "stripCompareBtn", "globalMessage"):
            self.assertIsNotNone(doc.by_id(name), f"missing workbench control: {name}")
        self.assertNotIn("hidden", doc.by_id("operate"))
        self.assertIn("hidden", doc.by_id("compare"))
        self.assertIn("disabled", doc.by_id("analyzeBtn"))
        self.assertIn("disabled", doc.by_id("stripCompareBtn"))
        self.assertEqual(doc.by_id("authorization").get("type"), "checkbox")
        self.assertIn("never executed", html.lower())
        self.assertIn("not a malware sandbox", html.lower())
        self.assertNotIn("first milestone", html.lower())
        self.assertNotIn("fonts.googleapis", html)
        self.assertIn('src="/static/workbench.js"', html)
        self.assertIn('href="/static/workbench.css"', html)
        css = (STATIC / "workbench.css").read_text(encoding="utf-8")
        # Day 2 readable theme: calm light palette plus a matching dark palette.
        for token in ("--bg:", "--surface:", "--text:", "--muted:", "--accent:", "--good:", "--warn:", "--bad:",
                      "--font:", "--mono:", "prefers-color-scheme:dark", ':root[data-theme="dark"]'):
            self.assertIn(token, css)
        self.assertNotIn("fonts.googleapis", css)
        self.assertIn(":focus-visible", css)
        self.assertIn("@media", css)

    def test_discovery_client_uses_same_origin_token_and_byte_upload(self):
        self.node(r"""
(async () => {
  const http = require('node:http');
  const requests = [];
  const server = http.createServer(async (req, res) => {
    let body = ''; for await (const chunk of req) body += chunk;
    requests.push({url:req.url, method:req.method, headers:req.headers, body});
    res.setHeader('Content-Type', 'application/json');
    if (req.url === '/api/status') res.end(JSON.stringify({dynamic_analysis:{enabled:false}, tools:{}}));
    else if (req.url === '/api/apps') res.end('{"apps":[]}');
    else if (req.url === '/api/samples') res.end('{"samples":[]}');
    else res.end('{"selection_id":"s-1","targets":[]}');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const client = UI.createClient((url, options) => fetch(`http://127.0.0.1:${server.address().port}${url}`, options));
  try {
    await assert.rejects(client.discover({kind:'sample',sample_id:'level-1'}), /status|token/i);
    await client.loadStatus('test-token'); await client.apps(); await client.samples();
    await client.discover({kind:'flatpak',app_id:'com.example.App'});
    await client.discover({kind:'path',path:'/home/you/app'});
    await client.discover({kind:'sample',sample_id:'level-1'});
    await client.ingest({name:'a & b.rpm',data:new Uint8Array([65,66])});
    const writes = requests.filter(r => r.method === 'POST');
    for (const req of requests) assert.equal(req.headers['x-reverseshield-token'], 'test-token');
    const exported = await client.download('/api/jobs/example/report-sanitized');
    assert.ok(exported.size > 0);
    assert.equal(requests.at(-1).headers['x-reverseshield-token'], 'test-token');
    assert.equal(writes.length, 4);
    for (const req of writes) assert.equal(req.headers['x-reverseshield-token'], 'test-token');
    assert.deepEqual(JSON.parse(writes[0].body), {kind:'flatpak',app_id:'com.example.App'});
    assert.deepEqual(JSON.parse(writes[1].body), {kind:'path',path:'/home/you/app'});
    assert.deepEqual(JSON.parse(writes[2].body), {kind:'sample',sample_id:'level-1'});
    assert.equal(writes[3].url, '/api/ingest?filename=a%20%26%20b.rpm');
    assert.equal(writes[3].headers['content-type'], 'application/octet-stream');
    assert.equal(writes[3].body, 'AB');
    await assert.rejects(client.discover({kind:'path',path:'relative/path'}), /absolute/i);
  } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
  const unsafe = UI.createClient(async () => ({ok:true,json:async()=>({token:'x',dynamic_analysis:{enabled:true}})}));
  await assert.rejects(unsafe.loadStatus('test-token'), /dynamic|static/i);
  await assert.rejects(unsafe.discover({kind:'sample',sample_id:'x'}), /status|token/i);
})().catch(error => { console.error(error); process.exitCode = 1; });
""")

    def test_selection_uses_main_binary_and_authorized_sample_only_strip(self):
        self.node(r"""
const targets = [
  {target_id:'lib',relative_path:'lib/libapp.so',analyzable:true},
  {target_id:'main',relative_path:'bin/app',analyzable:true},
  {target_id:'text',relative_path:'README',analyzable:false,reason:'Not ELF'}];
assert.deepEqual(UI.defaultTargets(targets), ['main']);
assert.deepEqual(UI.defaultTargets([{target_id:'none',analyzable:false}]), []);
const tools = {readelf:{available:true},ghidra:{available:false},objdump:{available:true}};
assert.deepEqual(UI.selectedTools(tools, 'all', new Set()), ['readelf','objdump']);
assert.deepEqual(UI.selectedTools(tools, 'manual', new Set(['ghidra','readelf'])), ['readelf']);
const choice = {selection_id:'selection',targets,sourceKind:'sample'};
const options = {selection:choice,targetIds:['main'],tools:['readelf'],authorized:true,operation:'analyze',stripAvailable:true};
assert.deepEqual(UI.jobPayload(options), {selection_id:'selection',target_ids:['main'],tools:['readelf'],operation:'analyze',authorized:true});
assert.throws(() => UI.jobPayload({...options,authorized:false}), /authoriz/i);
assert.throws(() => UI.jobPayload({...options,targetIds:['text']}), /target/i);
assert.throws(() => UI.jobPayload({...options,tools:[]}), /tool/i);
assert.throws(() => UI.jobPayload({...options,operation:'execute'}), /operation/i);
assert.throws(() => UI.jobPayload({...options,operation:'strip_compare',selection:{...choice,sourceKind:'path'}}), /sample/i);
assert.throws(() => UI.jobPayload({...options,operation:'strip_compare',targetIds:['main','lib']}), /one|single/i);
assert.throws(() => UI.jobPayload({...options,operation:'strip_compare',stripAvailable:false}), /unavailable/i);
assert.equal(UI.jobPayload({...options,operation:'strip_compare'}).operation, 'strip_compare');
assert.equal(UI.jobPayload({...options,selection:{...choice,sourceKind:'path'},operation:'binary_compare',binaryAvailable:true,profile:'binary_hygiene'}).operation, 'binary_compare');
assert.throws(() => UI.jobPayload({...options,operation:'binary_compare',targetIds:['main','lib'],binaryAvailable:true}), /one|single/i);
assert.throws(() => UI.jobPayload({...options,operation:'binary_compare',binaryAvailable:false}), /unavailable/i);
assert.deepEqual(UI.hardeningRows({checks:{nx:{label:'NX / DEP',state:'present',evidence:'non-exec stack'}}}), [['NX / DEP','Present','non-exec stack']]);
const hardened = {...choice, sample_id:'level-5-hardened', source_transform_supported:false};
assert.equal(UI.jobPayload({...options,selection:hardened,operation:'analyze'}).operation, 'analyze');
assert.throws(() => UI.jobPayload({...options,selection:hardened,operation:'protect_compare'}), /analysis-only/i);
assert.throws(() => UI.jobPayload({...options,selection:hardened,operation:'ollvm_compare',ollvmAvailable:true}), /analysis-only/i);
""")

    def test_qemu_display_distinguishes_separate_drivers_from_download(self):
        script = (STATIC / 'workbench.js').read_text(encoding='utf-8')
        self.assertIn("['Separate driver vectors'", script)
        self.assertIn("['Downloadable artifact behavior', 'Not verified", script)
        self.assertNotIn('protection.behavior_verified ?', script)

    def test_windows_ollvm_limitation_is_visible_in_workbench(self):
        html = (STATIC / 'index.html').read_text(encoding='utf-8')
        js = (STATIC / 'workbench.js').read_text(encoding='utf-8')
        self.assertIn('OLLVM source transforms and QEMU verification require Linux', html)
        self.assertIn("state.status?.platform === 'windows'", js)

    def test_job_lifecycle_polls_real_sequences_and_stops_on_partial(self):
        self.node(r"""
(async () => {
  const requests = [];
  const payloads = [
    {job_id:'job/a',status:'running',events:[{seq:1,message:'tool started'}],next_seq:1,result:null},
    {job_id:'job/a',status:'partial',events:[{seq:1,message:'duplicate'},{seq:2,message:'tool failed'}],next_seq:2,result:{operation:'analyze',reports:[]}}
  ];
  const client = UI.createClient(async (url, options) => {
    requests.push({url,options});
    let data = {};
    if (url === '/api/status') data = {token:'token',dynamic_analysis:{enabled:false}};
    else if (url === '/api/jobs' && options.method === 'POST') data = {job_id:'job/a'};
    else if (url === '/api/jobs') data = {jobs:[{job_id:'job/a',status:'running'}]};
    else if (url.includes('?after=')) data = payloads.shift();
    return {ok:true,json:async()=>data};
  });
  await client.loadStatus('test-token');
  const job = await client.startJob({selection_id:'s',target_ids:['t'],tools:['readelf'],operation:'analyze',authorized:true});
  assert.equal(job.job_id, 'job/a');
  assert.equal((await client.jobs()).jobs.length, 1);
  const updates = [], queue = [];
  const watcher = UI.createJobWatcher(client, {
    onUpdate: update => updates.push(update),
    onError: error => { throw error; },
    schedule: (fn, delay) => { assert.equal(delay, 500); queue.push(fn); return 1; },
    clear: () => {}
  });
  await watcher.start(job.job_id);
  assert.equal(updates[0].status, 'running');
  assert.equal(queue.length, 1);
  await queue.shift()();
  assert.equal(updates[1].status, 'partial');
  assert.deepEqual(updates[1].events.map(event => event.seq), [1,2]);
  assert.equal(updates[1].events[0].message, 'tool started');
  assert.equal(queue.length, 0, 'terminal states must stop polling');
  assert.ok(requests.some(req => req.url === '/api/jobs/job%2Fa?after=1'));
  await client.cancelJob(job.job_id);
  const cancel = requests.find(req => req.url.endsWith('/cancel'));
  assert.equal(cancel.options.headers['X-ReverseShield-Token'], 'test-token');
  assert.equal(cancel.options.body, '{}');
  assert.equal(UI.reportUrl(job.job_id), '/api/jobs/job%2Fa/report-sanitized');
  assert.equal(UI.artifactUrl(job.job_id), '/api/jobs/job%2Fa/artifact');
  for (const status of ['completed','partial','failed','cancelled']) assert.equal(UI.isTerminal(status), true);
  assert.equal(UI.isTerminal('queued'), false);
  assert.equal(UI.isTerminal('running'), false);
  watcher.stop();
})().catch(error => { console.error(error); process.exitCode = 1; });
""")

    def test_connected_views_expose_monitor_comparison_and_safe_evidence(self):
        html = (STATIC / "index.html").read_text(encoding="utf-8")
        doc = Document(html)
        for name in ("jobStatus", "jobId", "cancelJobBtn", "resumeJobBtn", "jobEvents", "recentJobs",
                     "refreshJobsBtn", "downloadReportBtn", "downloadArtifactBtn", "resultTargetSelect",
                     "evidenceContent", "evidenceWarnings", "compareMode", "comparisonContent",
                     "comparisonWarnings", "compareBefore", "compareAfter"):
            self.assertIsNotNone(doc.by_id(name), f"missing result control: {name}")
        self.assertIn('role="log"', html)
        for mode in ("basic", "pseudocode", "graphs", "all"):
            self.assertTrue(any(tag == "option" and attrs.get("value") == mode for tag, attrs in doc.elements))
        self.assertTrue(any(tag == "option" and attrs.get("value") == "binary_hygiene" for tag, attrs in doc.elements))
        script = (STATIC / "workbench.js").read_text(encoding="utf-8")
        for unsafe in (".innerHTML", "insertAdjacentHTML", "eval(", "Math.random("):
            self.assertNotIn(unsafe, script)
        for phrase in ("Symbol removal applied", "Not collected", "textContent", "createElementNS", "boot()"):
            self.assertIn(phrase, script)
        for control in ("discoverAppBtn", "discoverPathBtn", "discoverSampleBtn", "ingestBtn", "analyzeBtn",
                        "stripCompareBtn", "cancelJobBtn", "resumeJobBtn", "refreshJobsBtn", "refreshAppsBtn",
                        "compareMode", "authorization", "resultTargetSelect", "toolMode"):
            self.assertIn(f"'{control}'", script)
        self.node("assert.equal(typeof UI.boot, 'function'); assert.equal(typeof UI.renderAnalysis, 'function');")

    def test_graphs_are_real_bounded_data_and_coverage_failures_stay_visible(self):
        self.node(r"""
const functions = Array.from({length:75}, (_, index) => ({name:`fn${index}`,address:`0x${index}`}));
const artifacts = {functions,call_edges:[{source:'fn0',target:'fn1'},{source:'fn1',target:'fn74'}]};
const graph = UI.graphData(artifacts, 'calls');
assert.equal(graph.nodes.length, 60);
assert.equal(graph.totalNodes, 75);
assert.deepEqual(graph.edges, [{source:'fn0',target:'fn1'}]);
assert.equal(graph.capped, true);
assert.deepEqual(UI.graphData({}, 'calls').nodes, []);
const fn = {cfg_nodes:[{id:'a',label:'entry <script>'},{id:'b',label:'return'}],cfg_edges:[{source:'a',target:'b'}]};
const cfg = UI.graphData({}, 'cfg', fn);
assert.equal(cfg.nodes[0].label, 'entry <script>');
assert.equal(cfg.edges.length, 1);
const warnings = UI.analysisWarnings({coverage:{functions:'not_collected'},limitations:['Static only'],tools:[
  {tool:'ghidra',status:'failed',return_code:1,output:'error'},
  {tool:'strings',status:'success',return_code:0,truncated:true}
]});
assert.ok(warnings.some(message => message.includes('ghidra') && message.includes('failed')));
assert.ok(warnings.some(message => message.includes('truncat')));
assert.ok(warnings.includes('Static only'));
assert.ok(warnings.some(message => message.includes('functions') && message.includes('not_collected')));
""")

    def node(self, script):
        self.assertTrue((STATIC / "workbench.js").exists(), "workbench.js not implemented")
        self.assertIsNotNone(shutil.which("node"), "node required for UI behavior contracts")
        result = subprocess.run(["node", "-e", "const assert = require('node:assert/strict');\n"
                                 "const UI = require('./static/workbench.js');\n" + script],
                                cwd=ROOT, text=True, encoding="utf-8", errors="replace", capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)


if __name__ == "__main__":
    unittest.main()
