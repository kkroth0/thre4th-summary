"""Report exception signatures and export response status without secrets."""
import subprocess, re
def command(*args):
    return subprocess.run(args,capture_output=True,text=True,timeout=20).stdout
lines=command('journalctl','-u','bdppt-site.service','--since','30 minutes ago','--no-pager','-o','cat').splitlines()
for i,line in enumerate(lines):
    if re.search(r'FATAL ERROR|heap limit|Main process exited|Scheduled restart|TypeError|ReferenceError|ERR_|Error:|Failed to background',line):
        safe=re.sub(r'https?://\S+','[url]',line)
        safe=re.sub(r'(?i)(token|key|secret|password)\s*[=:]\s*\S+',r'\1=[redacted]',safe)
        print(safe[:240])
        for stack in lines[i+1:i+5]:
            if re.match(r'\s+at ',stack): print(re.sub(r'https?://\S+','[url]',stack)[:180])
print(command('systemctl','show','bdppt-site.service','-p','User,MainPID,NRestarts,MemoryCurrent,ExecMainStartTimestamp'))
