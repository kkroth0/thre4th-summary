"""Read-only VPS diagnostics; report configuration presence, never credentials."""
import collections
import hashlib
import json
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

app = Path(sys.argv[1]).resolve()
engine = Path('/home/ubuntu/bd-ppt-generator')
secrets = []

def config(path):
    values = {}
    try:
        for line in path.read_text().splitlines():
            match = re.match(r'(?:export\s+)?([A-Z0-9_]+)\s*=\s*(.*)', line)
            if match:
                name, value = match.groups()
                values[name] = value.strip().strip('\"\'')
                if re.search(r'SECRET|KEY|TOKEN|PASSWORD', name) and len(values[name]) > 5:
                    secrets.append(values[name])
    except OSError:
        pass
    return values

site_config, engine_config = config(app / '.env'), config(engine / '.env')

def redact(value):
    text = str(value)
    for secret in sorted(secrets, key=len, reverse=True):
        text = text.replace(secret, '[redacted]')
    text = re.sub(r'(?:sk-[\w-]+|psk_[\w-]+|wis_live_[\w-]+)', '[redacted]', text)
    text = re.sub(r'(?i)(bearer\s+|(?:api[_-]?key|token|secret)=)[^\s&]+', r'\1[redacted]', text)
    return text[:500]

def command(*args):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return 'unavailable'

try:
    jobs = json.loads((app / 'server/.feed-jobs.json').read_text())
except (OSError, ValueError):
    jobs = {}
latest = sorted(jobs.values(), key=lambda row: row.get('updatedAt', ''), reverse=True)[:12]
worker_log = command('journalctl', '-u', 'bdppt-worker', '-n', '100', '--no-pager', '-o', 'cat')
quality = {}
try:
    with sqlite3.connect(f'file:{app / "server/.ioc-intelligence.sqlite"}?mode=ro', uri=True) as db:
        quality['reviews'] = {name: json.loads(value) for name, value in db.execute("SELECT id,value FROM intelligence_state WHERE id LIKE 'news-%'")}
        quality['collectors'] = []
        for name, value in db.execute("SELECT id,value FROM intelligence_state WHERE id LIKE 'source:%'"):
            state = json.loads(value)
            quality['collectors'].append({'provider': name.split(':')[-1], 'scope': 'platform' if name.count(':') == 1 else 'account',
                                         'status': state.get('status'), 'lastSuccessfulAt': state.get('lastSuccessfulAt'),
                                         'error': redact(state.get('error') or '')})
except (OSError, ValueError, sqlite3.Error):
    quality['database'] = 'unavailable'
try:
    archived = json.loads((app / 'server/.news-archive.json').read_text())
    paper = next(row for row in archived if '/four-ways-back-in-the-wordpress-xss' in row.get('link', ''))
    body_file = app / 'server/.feed-cache/articles' / (hashlib.sha256(paper['link'].encode()).hexdigest() + '.json')
    body = json.loads(body_file.read_text()) if body_file.exists() else {}
    texts = [('archive', paper.get('text') or paper.get('description') or ''), ('article cache', body.get('text') or '')]
    quality['tableArticle'] = {'storedIps': (paper.get('iocs') or {}).get('ips', []), 'textSources': []}
    for kind, text in texts:
        index = text.find('204.8.96.109')
        quality['tableArticle']['textSources'].append({'kind': kind, 'characters': len(text), 'containsMissingIp': index >= 0,
            'context': text[max(0, index - 80):index + 100] if index >= 0 else ''})
except (OSError, ValueError, StopIteration):
    quality['tableArticle'] = 'unavailable'
patterns = ['timeout', '401', '402', '403', '429', 'No module named', 'Traceback', 'OPENROUTER', 'poll erro', 'ERRO', ' OK']
repository_status = []
for url in ['https://github.com/paloaltonetworks/unit42-timely-threat-intel', 'https://github.com/rtkwlf/wolf-tools/tree/main/threat-intelligence']:
    try:
        cached = json.loads((app / 'server/.feed-cache/rss' / (hashlib.sha256(url.encode()).hexdigest() + '.json')).read_text())
        items = cached.get('items', [])
        c2 = next((item for item in items if 'C2Agent' in item.get('title', '')), {})
        repository_status.append({'url': url, 'reports': len(items), 'deferred': cached.get('deferredReports'),
                                  'lastSuccessfulAt': cached.get('lastSuccessfulAt'),
                                  'c2agentHashes': len((c2.get('iocs') or {}).get('hashes', []))})
    except (OSError, ValueError):
        repository_status.append({'url': url, 'status': 'not collected yet'})
print(json.dumps({
    'repositorySources': repository_status,
    'configuration': {
        'siteAgentSecret': bool(site_config.get('FEED_AGENT_SECRET')),
        'workerAgentSecret': bool(engine_config.get('FEED_AGENT_SECRET')),
        'secretsMatch': bool(site_config.get('FEED_AGENT_SECRET')) and site_config.get('FEED_AGENT_SECRET') == engine_config.get('FEED_AGENT_SECRET'),
        'workerOpenrouter': bool(engine_config.get('OPENROUTER_API_KEY')),
    },
    'newsQuality': quality,
    'workerService': command('systemctl', 'show', 'bdppt-worker', '--property=ActiveState,SubState,NRestarts,ExecMainStatus'),
    'siteService': command('systemctl', 'show', 'bdppt-site', '--property=ActiveState,SubState,NRestarts,ExecMainStatus'),
    'siteStartupSignals': [redact(line) for line in command('journalctl', '-u', 'bdppt-site', '-n', '100', '--no-pager', '-o', 'cat').splitlines() if re.search(r'Error|ReferenceError|TypeError|heap|Server running|news evidence review', line)][-15:],
    'memory': command('free', '-m'),
    'cpu': command('ps', '-C', 'node', '-o', 'pid,pcpu,pmem,etime,stat'),
    'siteLog': [redact(line) for line in command('journalctl', '-u', 'bdppt-site', '-n', '100', '--no-pager', '-o', 'cat').splitlines() if '[feed]' in line or '[catalog]' in line or 'background refresh newsletter' in line or 'unhandledRejection' in line][-12:],
    'storeBytes': {name: (app / 'server' / name).stat().st_size for name in ['.news-stories.json', '.news-archive.json', '.vulnerability-catalog.sqlite'] if (app / 'server' / name).exists()},
    'jobs': dict(collections.Counter(row.get('status') for row in jobs.values())),
    'recentJobs': [{'status': row.get('status'), 'createdAt': row.get('createdAt'), 'updatedAt': row.get('updatedAt'), 'sources': len(row.get('urls') or [row.get('url')]), 'error': redact(row.get('error') or '')} for row in latest],
    'workerLogSignals': {pattern: worker_log.count(pattern) for pattern in patterns},
    'workerErrors': [redact(line) for line in worker_log.splitlines() if any(pattern in line for pattern in ['ERRO:', 'poll erro:', 'Error:', 'ModuleNotFoundError'])][-12:],
    'workerPhases': [redact(line) for line in worker_log.splitlines() if any(pattern in line for pattern in ['Analyzing ', 'Source collected:', 'refinement', 'timed out', 'rate-limited', 'sem pdf', 'sem pptx', 'render excedeu', 'Scraped ', 'OpenRouter model chain'])][-16:],
}, indent=2))
