"""Retry one recent failed bulletin using the existing, authenticated worker."""
import json
import hashlib
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

app = Path(sys.argv[1]).resolve()
engine = Path('/home/ubuntu/bd-ppt-generator')
sys.path.insert(0, str(engine))
from dotenv import load_dotenv
load_dotenv(engine / '.env')
from tools.job_worker import generate, job_urls, job_deck_type, job_template, job_subtype, post_result
from bdppt.netguard import assert_public_url

jobs_path = app / 'server/.feed-jobs.json'
jobs = json.loads(jobs_path.read_text())
cutoff = datetime.now(timezone.utc) - timedelta(days=1)
failed = [job for job in jobs.values() if job.get('status') == 'error' and datetime.fromisoformat(job['createdAt'].replace('Z', '+00:00')) >= cutoff]
if not failed:
    print('No recent failed bulletin to verify.'); sys.exit(0)
job = max(failed, key=lambda row: row.get('createdAt', ''))
urls = job_urls(job)
for url in urls:
    assert_public_url(url)
print(f"Verifying one existing failed bulletin: {job['id'][:8]}, {len(urls)} source(s)", flush=True)
def cached(key, directory):
    try:
        return json.loads((app / 'server/.feed-cache' / directory / (hashlib.sha256(key.encode()).hexdigest() + '.json')).read_text())
    except (OSError, ValueError):
        return {}

snapshot = cached('newsletter:snapshot', 'rss').get('items', [])
documents = []
for url in urls:
    row = next((item for item in snapshot if item.get('link') == url), {})
    body = cached(url, 'articles')
    original = next((item for item in cached(row.get('feedUrl', ''), 'rss').get('items', []) if item.get('link') == url), {})
    text = body.get('text') or original.get('text') or ''
    if len(text) >= 1500:
        iocs = row.get('iocs') or {}
        documents.append({'url': url, 'title': row.get('title'), 'text': text[:64000],
                          'iocText': '\n'.join(value for kind in ['ips', 'domains', 'hashes', 'urls'] for value in iocs.get(kind, []))})
print(f"Reusing {len(documents)} collected source document(s)", flush=True)

data, attachments = generate(urls, job_deck_type(job), True, 240,
                             model=os.getenv('FEED_WORKER_MODEL') or None,
                             template=job_template(job), subtype=job_subtype(job), documents=documents)
secret = os.environ['FEED_AGENT_SECRET']
for attempt in range(3):
    try:
        post_result('http://127.0.0.1:3001', secret, job['id'], data=data, attachments=attachments)
        break
    except Exception:
        if attempt == 2:
            raise
        time.sleep(4)
saved = json.loads(jobs_path.read_text()).get(job['id'], {})
print(json.dumps({'status': saved.get('status'), 'reportDelivered': bool(saved.get('json')), 'attachments': list((saved.get('deck') or {}).keys())}))
if saved.get('status') != 'done':
    sys.exit(1)
