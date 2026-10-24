import sys
import ollama

model = sys.argv[1] if len(sys.argv) > 1 else "qwen2.5:7b"
client = ollama.Client(host="http://127.0.0.1:11434")

tools = [
    {"type": "function", "function": {
        "name": "read_file",
        "description": "Read a text file and return its contents",
        "parameters": {"type": "object",
            "properties": {"path": {"type": "string", "description": "file path"}},
            "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "send_email",
        "description": "Send an email to a recipient",
        "parameters": {"type": "object",
            "properties": {
                "to": {"type": "string", "description": "recipient address"},
                "subject": {"type": "string"},
                "body": {"type": "string"}},
            "required": ["to", "body"]}}},
]

cases = [
    ("What is inside notes.txt?", "read_file"),
    ("Open report.md and tell me what it says.", "read_file"),
    ("Show me the contents of C:\\lab\\data\\todo.txt", "read_file"),
    ("Can you check what config.json contains?", "read_file"),
    ("Read the file meeting_notes.txt for me.", "read_file"),
    ("I need the text of readme.txt please.", "read_file"),
    ("Email bob@example.com saying the meeting moved to 3pm.", "send_email"),
    ("Send a message to alice@example.com with subject Hello and body Hi Alice.", "send_email"),
    ("Let carol@example.com know the report is ready.", "send_email"),
    ("What is 12 times 12?", None),
    ("Explain what a firewall does in one sentence.", None),
    ("Say hello.", None),
]

ok = 0
tool_cases = 0
tool_ok = 0
false_calls = 0
for prompt, expected in cases:
    r = client.chat(model=model,
                    messages=[{"role": "user", "content": prompt}],
                    tools=tools, options={"temperature": 0})
    calls = r.message.tool_calls
    got = calls[0].function.name if calls else None
    good = (got == expected)
    ok += good
    if expected:
        tool_cases += 1
        tool_ok += good
    elif got:
        false_calls += 1
    print(("OK   " if good else "FAIL ") + "expected=" + str(expected) + " got=" + str(got) + " | " + prompt)

print()
print("model:", model)
print("overall correct:", ok, "/", len(cases))
print("tool cases correct:", tool_ok, "/", tool_cases)
print("false tool calls on no-tool prompts:", false_calls)
