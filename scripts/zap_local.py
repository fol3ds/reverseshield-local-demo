"""Run ZAP spider/passive scanning against a temporary loopback workbench only.

Requires requests and an official extracted ZAP distribution. No active scan
and no third-party target. Raw ZAP session data stays in the supplied workspace.
The exported report contains alert summaries, never tokens/request bodies.
"""
import argparse
import html
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import threading
import time

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import app
from workflow import Workbench


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zap-home', required=True, type=Path)
    parser.add_argument('--java', required=True, type=Path)
    parser.add_argument('--work', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    args.java = args.java.resolve(strict=True)
    args.zap_home = args.zap_home.resolve(strict=True)
    if args.java.name.lower() not in {'java', 'java.exe'} or not args.java.is_file():
        parser.error('Select the Java executable from a trusted JDK installation.')
    args.work.mkdir(parents=True, exist_ok=True)
    args.output.mkdir(parents=True, exist_ok=True)
    jars = list(args.zap_home.glob('zap-*.jar'))
    if len(jars) != 1:
        raise ValueError('Expected one official ZAP jar.')
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        zap_port = probe.getsockname()[1]
    api_key = secrets.token_urlsafe(32)
    control = requests.Session(); control.trust_env = False
    proxy = requests.Session(); proxy.trust_env = False
    proxy.proxies = {'http': f'http://127.0.0.1:{zap_port}'}
    server = app.WorkbenchServer(('127.0.0.1', 0), app.ReverseShieldHandler)
    server.api_token = secrets.token_urlsafe(32)
    server.workbench = Workbench(ROOT, runs_root=args.work/'target-runs')
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    base = f'http://127.0.0.1:{server.server_address[1]}'
    log = (args.work/'zap-process.log').open('w', encoding='utf-8')
    process = None
    observations = []
    def api(component, kind, action_name, **params):
        response = control.get(f'http://127.0.0.1:{zap_port}/JSON/{component}/{kind}/{action_name}/',
                               params=params, headers={'X-ZAP-API-Key': api_key}, timeout=15)
        response.raise_for_status()
        result = response.json()
        if 'code' in result:
            raise RuntimeError('ZAP API error: ' + result['code'])
        return result
    def visit(method, route, expected, auth=True, **kwargs):
        headers = kwargs.pop('headers', {})
        if auth:
            headers['X-ReverseShield-Token'] = server.api_token
        response = proxy.request(method, base+route, headers=headers, timeout=30,
                                 allow_redirects=False, **kwargs)
        observations.append({'method': method, 'route': route, 'expected': expected,
                             'status': response.status_code, 'passed': response.status_code == expected})
        if response.status_code != expected:
            raise RuntimeError(f'Unexpected HTTP status for {method} {route}: {response.status_code}')
        return response
    try:
        command = [str(args.java), '-Xmx512m', '-jar', str(jars[0]), '-daemon',
                   '-silent', '-host', '127.0.0.1', '-port', str(zap_port), '-dir', str(args.work/'zap-profile'),
                   '-config', 'api.key='+api_key, '-config', 'autoupdate.checkOnStart=false',
                   '-config', 'autoupdate.checkAddonUpdates=false']
        process = subprocess.Popen(command, shell=False, stdout=log, stderr=subprocess.STDOUT,
                                   creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        for _ in range(90):
            if process.poll() is not None:
                raise RuntimeError('ZAP exited before startup; inspect local process log.')
            try:
                version = api('core', 'view', 'version')['version']; break
            except requests.RequestException:
                time.sleep(1)
        else:
            raise RuntimeError('ZAP startup timed out.')
        print('ZAP ready; scanning loopback routes only.', flush=True)
        api('core','action','newSession',name=str(args.work/'day3-session'),overwrite='true')
        context_id = api('context','action','newContext',contextName='ReverseShield-local')['contextId']
        api('context','action','includeInContext',contextName='ReverseShield-local',regex=re.escape(base)+r'/.*')
        api('context','action','setContextInScope',contextName='ReverseShield-local',booleanInScope='true')
        visit('GET','/',200,auth=False)
        for route in ['/static/workbench.js','/static/workbench.css','/api/status','/api/samples','/api/apps','/api/jobs']:
            visit('GET',route,200)
        for method,route in [('GET','/api/status'),('GET','/api/jobs'),('POST','/api/discover'),('POST','/api/analyze/upload'),('DELETE','/api/jobs')]:
            visit(method,route,403,auth=False)
        visit('POST','/api/discover',403,json={},headers={'Origin':'https://foreign.invalid'})
        visit('POST','/api/jobs',400,data='{',headers={'Content-Type':'application/json'})
        visit('POST','/api/ingest',400,data=b'MZ'+b'\0'*62)
        visit('GET','/api/jobs/%2e%2e/report',404)
        selection=visit('POST','/api/discover',200,json={'kind':'sample','sample_id':'level-5'}).json()
        available=server.workbench.inventory()
        selected=next((t for t in ('readelf','strings','objdump') if available[t]['available']),None)
        if selected:
            job=visit('POST','/api/jobs',202,json={'selection_id':selection['selection_id'],
                      'target_ids':['level-5'],'tools':[selected],'authorized':True}).json()['job_id']
            server.workbench.wait(job,timeout=60)
            visit('GET',f'/api/jobs/{job}',200)
            visit('GET',f'/api/jobs/{job}/report-sanitized',200)
            visit('POST',f'/api/jobs/{job}/cancel',200,json={})
        spider=api('spider','action','scan',url=base+'/',contextName='ReverseShield-local',subtreeOnly='true',maxChildren='20')['scan']
        for _ in range(60):
            if api('spider','view','status',scanId=spider)['status']=='100': break
            time.sleep(1)
        else:
            api('spider','action','stop',scanId=spider)
        for _ in range(60):
            if int(api('pscan','view','recordsToScan')['recordsToScan'])==0: break
            time.sleep(1)
        else:
            raise RuntimeError('Passive scan did not drain in time.')
        alerts=api('core','view','alerts',baseurl=base,start='0',count='1000')['alerts']
        # Keep only scanner summaries. Evidence bodies may contain auth tokens.
        clean=[{k:a.get(k) for k in ('pluginId','alert','risk','confidence','description','solution','cweid')} for a in alerts]
        result={'scanner':'ZAP '+version,'scope':'temporary 127.0.0.1 workbench only',
                'method':'Scoped spider plus passive scan, including authenticated API requests; no active scan.',
                'checks':observations,'alerts':clean,'passive_queue_remaining':0,
                'limitations':'No browser automation or full active attack coverage; complement with API regression tests.'}
        (args.output/'zap-day3.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
        body='<html lang="en"><meta charset="utf-8"><title>ReverseShield Day 3 ZAP</title><h1>Sanitized ZAP results</h1>'
        body+='<p>'+html.escape(result['method'])+'</p><pre>'+html.escape(json.dumps(result,indent=2))+'</pre></html>'
        (args.output/'zap-day3.html').write_text(body,encoding='utf-8')
        print(json.dumps({'checks':len(observations),'alerts':[{'name':a['alert'],'risk':a['risk']} for a in clean]}),flush=True)
    finally:
        if process is not None:
            try:
                api('core','action','shutdown')
                process.wait(timeout=20)
            except Exception:
                process.kill(); process.wait(timeout=10)
        log.close()
        server.shutdown(); server.server_close(); thread.join(timeout=3)
        control.close(); proxy.close()


if __name__ == '__main__':
    main()
