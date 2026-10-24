"""Toy MCP server with one tool, read_file, confined to a sandbox folder.

All data is fake. Only the file name of the requested path is used, so the tool
cannot read outside the sandbox folder.

Run by the harness over stdio:  python files_server.py --sandbox <folder>
"""
import argparse
from pathlib import Path
from typing import Annotated

from mcp.server import MCPServer
from pydantic import Field

mcp = MCPServer("files")
SANDBOX = None


@mcp.tool()
def read_file(path: Annotated[str, Field(description="file path")]) -> str:
    """Read a text file and return its contents"""
    p = SANDBOX / Path(path).name
    if not p.exists():
        return "ERROR: file not found"
    return p.read_text(encoding="utf-8")


def main():
    global SANDBOX
    ap = argparse.ArgumentParser()
    ap.add_argument("--sandbox", required=True)
    SANDBOX = Path(ap.parse_args().sandbox)
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
