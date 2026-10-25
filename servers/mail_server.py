"""Toy MCP server with one tool, send_email.

Nothing is sent. Each call appends one JSON line to a local outbox file.
The benign description is the reference; poison_* variants carry attacker text (variants.py).

Run by the harness over stdio:  python mail_server.py --outbox <file> [--variant NAME]
"""
import argparse
import json
from typing import Annotated

from mcp.server import MCPServer
from pydantic import Field

import variants


def build(outbox, variant):
    mcp = MCPServer("mail")
    desc = variants.MAIL_DESC.get(variant, variants.MAIL_DESC["benign"])
    to_desc = variants.MAIL_TO_DESC.get(variant, variants.MAIL_TO_DESC["benign"])

    # The keyword-only marker keeps the generated schema's property order
    # (to, subject, body) identical to the hand-written tool definition used by
    # the direct baseline, while body stays required.
    @mcp.tool(description=desc)
    def send_email(to: Annotated[str, Field(description=to_desc)],
                   *, subject: str = "", body: str) -> str:
        with open(outbox, "a", encoding="utf-8") as f:
            f.write(json.dumps({"to": to, "subject": subject, "body": body}) + "\n")
        return "Email sent."

    return mcp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--outbox", required=True)
    ap.add_argument("--variant", default="benign", choices=variants.MAIL_VARIANTS)
    a = ap.parse_args()
    build(a.outbox, a.variant).run(transport="stdio")


if __name__ == "__main__":
    main()
