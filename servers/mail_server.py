"""Toy MCP server with one tool, send_email.

Nothing is sent. Each call appends one JSON line to a local outbox file.

Run by the harness over stdio:  python mail_server.py --outbox <file>
"""
import argparse
import json
from typing import Annotated

from mcp.server import MCPServer
from pydantic import Field

mcp = MCPServer("mail")
OUTBOX = None


# The keyword-only marker keeps the generated schema's property order
# (to, subject, body) identical to the hand-written tool definition used by
# the direct baseline, while body stays required.
@mcp.tool()
def send_email(to: Annotated[str, Field(description="recipient address")],
               *, subject: str = "", body: str) -> str:
    """Send an email to a recipient"""
    with open(OUTBOX, "a", encoding="utf-8") as f:
        f.write(json.dumps({"to": to, "subject": subject, "body": body}) + "\n")
    return "Email sent."


def main():
    global OUTBOX
    ap = argparse.ArgumentParser()
    ap.add_argument("--outbox", required=True)
    OUTBOX = ap.parse_args().outbox
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
