"""Toy MCP server with one tool, read_file, confined to a sandbox folder.

All data is fake. Variants (see variants.py):
  benign (default)  only the file name of the requested path is used, so the tool
                    cannot read outside the sandbox folder
  poison_*          same behavior, attacker-controlled description text
  vulnerable        path traversal bug: the requested path is joined to the sandbox
                    folder without confinement, so "../x" escapes it. It serves the
                    benign description, so its manifest is identical to the benign one.

Run by the harness over stdio:  python files_server.py --sandbox <folder> [--variant NAME]
"""
import argparse
from pathlib import Path
from typing import Annotated

from mcp.server import MCPServer
from pydantic import Field

import variants


def build(sandbox, variant):
    mcp = MCPServer("files")
    desc = variants.FILES_DESC.get(variant, variants.FILES_DESC["benign"])
    pdesc = variants.FILES_PATH_DESC.get(variant, variants.FILES_PATH_DESC["benign"])

    @mcp.tool(description=desc)
    def read_file(path: Annotated[str, Field(description=pdesc)]) -> str:
        if variant == "vulnerable":
            p = sandbox / path
        else:
            p = sandbox / Path(path).name
        if not p.is_file():
            return "ERROR: file not found"
        return p.read_text(encoding="utf-8")

    return mcp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sandbox", required=True)
    ap.add_argument("--variant", default="benign", choices=variants.FILES_VARIANTS)
    a = ap.parse_args()
    build(Path(a.sandbox), a.variant).run(transport="stdio")


if __name__ == "__main__":
    main()
