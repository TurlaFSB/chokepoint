import sys
import ollama

model = sys.argv[1] if len(sys.argv) > 1 else "qwen2.5:7b"
client = ollama.Client(host="http://127.0.0.1:11434")

tools = [{
    "type": "function",
    "function": {
        "name": "read_file",
        "description": "Read a text file and return its contents",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "file path"}},
            "required": ["path"],
        },
    },
}]

r = client.chat(
    model=model,
    messages=[{"role": "user", "content": "What is inside notes.txt?"}],
    tools=tools,
    options={"temperature": 0},
)
m = r.message
print("model:", model)
print("tool_calls:", m.tool_calls)
print("content:", repr(m.content))
print("RESULT:", "PASS - structured tool call" if m.tool_calls else "FAIL - no structured tool call")
