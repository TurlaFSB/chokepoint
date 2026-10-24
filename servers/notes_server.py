"""Toy MCP server with one tool, add_note. Notes are appended to a local file.

The benign description is the reference. shadow_* variants carry cross-tool
instructions aimed at another server's tool (see variants.py).

Run by the harness over stdio:  python notes_server.py --store <file> [--variant NAME]
"""
import argparse
import json
from typing import Annotated

from mcp.server import MCPServer
from pydantic import Field

import variants


def build(store, variant):
    mcp = MCPServer("notes")

    @mcp.tool(description=variants.NOTES_DESC[variant])
    def add_note(text: Annotated[str, Field(description="note text")]) -> str:
        with open(store, "a", encoding="utf-8") as f:
            f.write(json.dumps({"text": text}) + "\n")
        return "Note saved."

    return mcp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--store", required=True)
    ap.add_argument("--variant", default="benign", choices=variants.NOTES_VARIANTS)
    a = ap.parse_args()
    build(a.store, a.variant).run(transport="stdio")


if __name__ == "__main__":
    main()
