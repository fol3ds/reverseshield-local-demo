"""Day 2 browser-contract tests: one-click demo, Ghidra options, N/A rendering.

Inputs are the static HTML/JS files evaluated in Node; outputs are assertions
about the client contract. No target is executed and no live server is used.
"""
from html.parser import HTMLParser
from pathlib import Path
import re
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


class DayTwoUiTests(unittest.TestCase):
    def test_demo_ghidra_and_comparison_controls_exist(self):
        html = (STATIC / "index.html").read_text(encoding="utf-8")
        doc = Document(html)
        for name in ("runDemoBtn", "demoState", "ghidraOptions", "ghidraTimeout", "ghidraCpu", "largeTargetWarning",
                     "lightweightBtn", "allowLargeGhidra", "comparisonSummary", "comparisonFunctions",
                     "comparisonLimitations", "compareAfterTitle", "compareBeforeTitle"):
            self.assertIsNotNone(doc.by_id(name), f"missing Day 2 control: {name}")
        self.assertIn("disabled", doc.by_id("runDemoBtn"), "demo must wait for status and samples")
        # Text + numeric keypad so digits always show as 0-9 (number inputs follow the OS locale).
        self.assertEqual(doc.by_id("ghidraTimeout").get("inputmode"), "numeric")
        self.assertIsNotNone(doc.by_id("themeToggle"), "readable light/dark toggle")
        self.assertIsNotNone(doc.by_id("fileName"), "English file picker label")
        self.assertIn("several minutes", html)
        self.assertNotIn("After · stripped copy", html)
        self.assertNotIn("protected copy", html.lower())

    def test_demo_never_runs_on_page_load(self):
        script = (STATIC / "workbench.js").read_text(encoding="utf-8")
        # runDemo is referenced only as a click handler, never invoked during boot.
        self.assertIn("byId('runDemoBtn').addEventListener('click', runDemo)", script)
        invocations = re.findall(r"(?<!function )\brunDemo\(", script)
        self.assertEqual(invocations, [], "runDemo must not be called directly")
        for unsafe in (".innerHTML", "insertAdjacentHTML", "eval(", "outerHTML"):
            self.assertNotIn(unsafe, script)

    def test_paths_errors_options_and_na_helpers(self):
        self.node(r"""
assert.equal(UI.isAbsolutePath('/home/you/app'), true);
assert.equal(UI.isAbsolutePath('C:\\Windows\\System32'), true);
assert.equal(UI.isAbsolutePath('D:/Apps/tool.exe'), true);
assert.equal(UI.isAbsolutePath('\\\\server\\share\\app'), false, 'UNC paths are refused');
assert.equal(UI.isAbsolutePath('//server/share'), false);
assert.equal(UI.isAbsolutePath('relative\\path'), false);
assert.equal(UI.isAbsolutePath('C:relative'), false);
assert.match(UI.friendlyError(new TypeError('Failed to fetch')), /Cannot reach the local ReverseShield server/);
assert.match(UI.friendlyError(new Error('Missing or invalid local request token. Reload the workbench.')), /Reload this page/);
assert.match(UI.friendlyError(new Error("[Errno 2] No such file or directory: 'x'")), /local tool or file operation failed/);
assert.equal(UI.friendlyError(new Error('Choose between 1 and 16 ELF/PE targets.')), 'Choose between 1 and 16 ELF/PE targets.');
const targets = [{target_id:'a',analyzable:true,size_bytes:100},{target_id:'b',analyzable:true,size_bytes:9*1024*1024}];
const selection = {selection_id:'s',targets,sourceKind:'path'};
assert.deepEqual(UI.largeTargets(selection, ['a','b'], 8*1024*1024).map(t => t.target_id), ['b']);
assert.deepEqual(UI.largeTargets(selection, ['a'], 8*1024*1024), []);
const base = {selection,targetIds:['a'],authorized:true,operation:'analyze',stripAvailable:true};
const options = {ghidra_timeout_seconds:300,ghidra_max_cpu:1,allow_large_ghidra:false};
assert.equal('options' in UI.jobPayload({...base,tools:['readelf'],options}), false, 'no Ghidra, no options');
assert.deepEqual(UI.jobPayload({...base,tools:['readelf','ghidra_headless'],options}).options, options);
assert.equal(UI.na(null), 'N/A');
assert.equal(UI.na(undefined), 'N/A');
assert.equal(UI.na(0), '0');
assert.equal(UI.na(false), 'absent');
const rows = UI.metricRows({format:'ELF',sections:{count:30,executable:3,writable:7},imports:{count:2},exports:{count:0},
  strings:{total:10,categories:{paths:1}},symbols:{elf_symbols:35,readelf_symbols:35,ghidra_symbols:null},debug:{debug_sections_present:true},ghidra:null});
const lookup = Object.fromEntries(rows);
assert.equal(lookup['File type'], 'ELF (Linux program)');
assert.equal(lookup['Sections'], '30');
assert.equal(lookup['Exported functions'], '0', 'an observed zero stays 0');
assert.equal(lookup['Names found by Ghidra'], 'N/A', 'not collected is N/A, never 0');
assert.equal(lookup['Symbol names in the file'], '35');
assert.equal(lookup['Debug information'], 'Yes');
assert.equal(lookup['Ghidra'], 'Not run for this report');
assert.equal(UI.humanSize(16088), '15.7 KB');
assert.equal(UI.fmt(1379), '1,379');
const findings = UI.exposureFindings({content_metrics:{format:'ELF',symbols:{elf_symbols:35},debug:{debug_sections_present:true,build_id_present:true},
  strings:{categories:{paths:15,compiler_notes:7}},imports:{count:2,libraries:1},
  ghidra:{status:'ok',functions_exported:13,functions_decompiled:10}}});
const byTitle = Object.fromEntries(findings.map(f => [f.title, f]));
assert.equal(byTitle['Function and variable names'].value, '35 names left in the file');
assert.equal(byTitle['Debug information'].value, 'Included');
assert.equal(byTitle['File and folder names'].value, '15 found');
assert.equal(byTitle['Build details'].value, '7 compiler notes + build ID');
const home = UI.exposureFindings({content_metrics:{format:'PE',symbols:{pe_coff_symbols:0},debug:{debug_sections_present:false,pdb_reference_present:true},
  strings:{categories:{paths:58,compiler_notes:1},paths_absolute:3,paths_in_user_home:2},imports:{count:315,libraries:50},
  ghidra:{status:'ok',functions_exported:519,functions_decompiled:40}}, coverage:{ghidra:{decompile_limit:40}}});
const h = Object.fromEntries(home.map(f => [f.title, f]));
assert.equal(h['Debug information'].value, 'Points to a PDB file');
assert.match(h['File and folder names'].why, /2 paths are inside a user’s home folder/);
assert.equal(h['Build details'].value, '1 compiler note');
assert.match(h['Readable code recovered'].why, /stops after 40 functions per run/);
assert.equal(byTitle['Readable code recovered'].value, '10 of 13 functions');
assert.equal(byTitle['Borrowed functions (imports)'].value, '2 from 1 library');
const stripped = UI.exposureFindings({content_metrics:{format:'ELF',symbols:{elf_symbols:null},debug:{debug_sections_present:false},strings:{categories:{paths:0}},imports:{count:2,libraries:1},ghidra:null}});
assert.equal(stripped[0].value, 'Removed');
assert.equal(stripped[0].tone, 'ok');
assert.equal(stripped.find(f => f.title === 'Readable code recovered').value, 'Not checked');
const warnings = UI.analysisWarnings({coverage:{tools_skipped:[{tool:'readelf',reason:'readelf does not parse PE/COFF files.'}],
  tools_unavailable:[{tool:'file',reason:'Not installed'}], tools_failed:[{tool:'ghidra_headless',status:'timeout',reason:'stopped at the 60 s time limit'}],
  outputs_truncated:[{tool:'strings',output_bytes:3000000,limit_bytes:1048576}], tools_ran:['strings']}});
assert.ok(warnings.some(w => w.includes('readelf skipped') && w.includes('PE/COFF')));
assert.ok(warnings.some(w => w.includes('file unavailable')));
assert.ok(warnings.some(w => w.includes('ghidra_headless did not finish') && w.includes('time limit')));
assert.ok(warnings.some(w => w.includes('strings output was long') && w.includes('1.00 MB of 2.86 MB')));
assert.ok(!warnings.some(w => w.startsWith('Coverage — tools_')), 'structured coverage is not dumped as JSON');
const peWarnings = UI.analysisWarnings({tools:[{tool:'readelf',label:'ELF headers, sections and symbols',status:'skipped'}],
  coverage:{tools_skipped:[{tool:'readelf',reason:'readelf does not parse PE/COFF files.'}]}});
assert.deepEqual(peWarnings, ['readelf skipped: readelf does not parse PE/COFF files.'], 'a skip is reported once');
const nested = UI.analysisWarnings({coverage:{ghidra:{functions_truncated:true,decompile_truncated:false,function_limit:1000}}});
assert.equal(nested.length, 1);
assert.match(nested[0], /^Ghidra reached its built-in limits.*functions_truncated/);
assert.equal(UI.shortPaths('INFO REPORT: file:///home/zayed/rs/runs/abc/symbols-removed.elf (HeadlessAnalyzer)'), 'INFO REPORT: …/symbols-removed.elf (HeadlessAnalyzer)');
assert.equal(UI.shortPaths('copy C:\\Users\\Zayed\\rs\\runs\\a\\input.exe done'), 'copy …\\input.exe done');
assert.equal(UI.shortCommand(['/usr/bin/strip','-o','/home/zayed/rs/runs/a/out.elf','C:\\Users\\Zayed\\rs\\in.elf']),
  '…/strip -o …/out.elf …/in.elf');
assert.equal(UI.shortCommand(undefined), undefined);
""")

    def node(self, script):
        self.assertIsNotNone(shutil.which("node"), "node required for UI behavior contracts")
        result = subprocess.run(["node", "-e", "const assert = require('node:assert/strict');\n"
                                 "const UI = require('./static/workbench.js');\n" + script],
                                cwd=ROOT, text=True, encoding="utf-8", errors="replace", capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)


if __name__ == "__main__":
    unittest.main()
