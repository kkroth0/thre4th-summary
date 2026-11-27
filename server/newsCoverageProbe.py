"""Measure availability for the reported date interval, without printing articles."""
import json, sys, hashlib, sqlite3
from datetime import datetime
from pathlib import Path
root = Path(sys.argv[1]) / 'server'
start = datetime.fromisoformat('2026-11-20T03:00:00+00:00')
end = datetime.fromisoformat('2026-11-28T03:00:00+00:00')
def observe(rows):
    links = set()
    latest = ''
    for row in rows:
        try:
            timestamp = datetime.fromisoformat((row.get('pubDate') or row.get('firstCollectedAt') or '').replace('Z','+00:00'))
            latest = max(latest, timestamp.date().isoformat())
            if start <= timestamp < end and row.get('link'): links.add(row['link'])
        except (TypeError, ValueError): continue
    return links, latest
db=sqlite3.connect('file:'+str(root/'.ioc-intelligence.sqlite')+'?mode=ro',uri=True,timeout=1)
for kind in ['archive','stories']:
    cursor=db.execute('select payload from news_documents where kind=?',(kind,))
    def publications():
        for (raw,) in cursor:
            item=json.loads(raw)
            yield from ([item] if kind=='archive' else item.get('sources',[]))
    links,latest=observe(publications());print(kind,len(links),latest)
db.close()
cache=root/'.feed-cache'/'rss'
snapshot=hashlib.sha256(b'newsletter:snapshot').hexdigest()
sourceLinks=set(); newest=''
for p in cache.glob('*.json'):
    if p.stat().st_size > 100*1024**2: print('large cache skipped'); continue
    try:
        data=json.loads(p.read_bytes())
        links,latest=observe(data.get('items') or [])
        del data
    except (OSError,ValueError,AttributeError): continue
    if p.stem==snapshot: print('snapshot',len(links),latest)
    else: sourceLinks.update(links);newest=max(newest,latest)
print('source caches',len(sourceLinks),newest)
