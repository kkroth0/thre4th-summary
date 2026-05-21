import json

transcript_path = r"C:\Users\matheus.andrade\.gemini\antigravity\brain\df0d289f-fbdd-4b19-b19c-fb4ef6500ecc\.system_generated\logs\transcript.jsonl"

with open(transcript_path, "r", encoding="utf-8") as f:
    for line in f:
        try:
            data = json.loads(line)
            step_idx = data.get("step_index")
            tool_calls = data.get("tool_calls", [])
            for tc in tool_calls:
                name = tc.get("name")
                args = tc.get("args", {})
                if isinstance(args, str):
                    args = json.loads(args)
                
                target = args.get("TargetFile", "") or args.get("AbsolutePath", "")
                if "Index.tsx" in target and name == "view_file":
                    print(f"Step {step_idx}: view_file on {target} args={args}")
        except Exception as e:
            pass
