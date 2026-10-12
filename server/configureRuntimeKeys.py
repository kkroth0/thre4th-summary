"""Update the explicitly supported deployment credentials from SSH stdin."""
import json
import os
from pathlib import Path
import re
import sys

target = Path(sys.argv[1])
values = json.load(sys.stdin)
allowed = {"ABUSE_CH_API_KEY", "PHISHSTATS_API_KEY", "WHOIS_API_KEY"}
if not isinstance(values, dict) or set(values) - allowed:
    raise ValueError("Unsupported credential names")
selected = {name: value.strip() for name, value in values.items() if isinstance(value, str) and value.strip()}
if any(not re.fullmatch(r"[a-zA-Z0-9_-]{8,400}", value) for value in selected.values()):
    raise ValueError("Invalid credential format")
if selected:
    target.touch(mode=0o600, exist_ok=True)
    text = target.read_text(encoding="utf-8")
    for name, value in selected.items():
        line = name + "=" + value
        pattern = rf"(?m)^{name}=.*$"
        text = re.sub(pattern, lambda _: line, text) if re.search(pattern, text) else text.rstrip() + "\n" + line + "\n"
    temp = target.with_name(target.name + ".deploy-tmp")
    try:
        temp.write_text(text, encoding="utf-8")
        temp.chmod(target.stat().st_mode & 0o777)
        os.replace(temp, target)
    finally:
        temp.unlink(missing_ok=True)
    print("Runtime credentials configured: " + ", ".join(sorted(selected)))
