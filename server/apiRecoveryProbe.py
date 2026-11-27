"""Sample only process counters, feed stage and local readiness."""
import json, sqlite3, subprocess, sys, time
from pathlib import Path
from datetime import datetime, timezone

def cmd(*args):
    return subprocess.run(args, capture_output=True, text=True, timeout=10).stdout.strip()

db = sqlite3.connect('file:' + sys.argv[1] + '/server/.ioc-intelligence.sqlite?mode=ro', uri=True, timeout=1)
db.execute('PRAGMA query_only=ON')
for i in range(12):
    pid = cmd('systemctl','show','bdppt-site.service','--property=MainPID','--value')
    status = Path('/proc',pid,'status')
    try: memory = [l.strip() for l in status.read_text().splitlines() if l.startswith(('VmRSS:', 'VmSwap:'))]
    except OSError: memory=[]
    try:
        row = db.execute("select value from intelligence_state where id='news-current-cycle'").fetchone()
        cycle = json.loads(row[0]) if row else {}
    except sqlite3.Error: cycle={}
    print(datetime.now(timezone.utc).isoformat(),pid,memory,cycle.get('phase'),cycle.get('updatedAt'),
          cmd('curl','--max-time','8','-s','-o','/dev/null','-w','%{http_code} %{time_total}','http://127.0.0.1:3001/api/vendors/status'))
    if i!=11: time.sleep(45)
