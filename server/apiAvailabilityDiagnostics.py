"""Report service availability and failure counts without collecting request payloads."""
import subprocess
import collections
import re

def run(*args):
    return subprocess.run(args, capture_output=True, text=True, timeout=25).stdout.strip()

unit = 'bdppt-site.service'
print(run('systemctl', 'show', unit, '-p', 'NRestarts,MemoryCurrent,MemoryPeak,ExecMainStartTimestamp,ActiveState'))
print(run('free', '-m'))
from pathlib import Path
import sqlite3
root=Path.home()/'thre4th-summary'/'server'
print('stores MiB', {p.name:round(p.stat().st_size/1048576,1) for p in root.glob('.*') if p.is_file() and p.stat().st_size>1048576})
print('largest processes',run('ps','-eo','comm,rss','--sort=-rss').splitlines()[:10])
log = run('journalctl','-u',unit,'--since','2 hours ago','-o','cat','--no-pager')
print('GC samples',re.findall(r'(?:Scavenge|Mark-Compact|Mark-sweep)[^\n]{0,115}',log)[-12:])
print('stack',re.findall(r'v8::internal::[a-zA-Z0-9_:]+',log)[-45:])
print('memory options',re.findall(r'--max[-_]old[-_]space[-_]size[= ]\d+',run('systemctl','cat',unit)))
try:
    with sqlite3.connect('file:'+str(root/'.ioc-intelligence.sqlite')+'?mode=ro',uri=True) as db:
        import json
        row=db.execute("select value from intelligence_state where id='news-current-cycle'").fetchone()
        if row:
            cycle=json.loads(row[0])
            print('cycle', {key:cycle.get(key) for key in ('startedAt','updatedAt','phase','stages','memory')})
except sqlite3.Error: pass
patterns = {'oom': r'out of memory|oom-kill|heap limit|killed process', 'restart': r'Scheduled restart job',
            'fatal': r'FATAL ERROR|uncaughtException', 'listening': r'Server running on port',
            'exit': r'Main process exited', 'tunnel': r'Unable to reach the origin service|context deadline exceeded',
            'feed': r'\[feed\] cycle '}
for source in (['-u',unit], ['-k'], ['-u','cloudflared']):
    counts = collections.Counter()
    lines = run('journalctl', *source, '--since', '3 hours ago', '--no-pager','-o','short-iso').splitlines()
    for line in lines:
        for name, pattern in patterns.items():
            if re.search(pattern, line, re.I):
                counts[(line[:16], name)] += 1
                if name in ('oom','fatal','exit','restart'):
                    signature=re.search(r'heap limit|out of memory|oom-kill|signal=[A-Z]+|status=[0-9A-Z/]+|restart counter is at [0-9]+',line,re.I)
                    if signature: print(line[:19], name, signature.group())
    print(source, dict(counts.most_common(45)))
for path in ('/api/vendors/status','/api/news/export'):
    print(path, run('curl','--max-time','10','-s','-o','/dev/null','-w','%{http_code} %{time_total}', 'http://127.0.0.1:3001'+path))
