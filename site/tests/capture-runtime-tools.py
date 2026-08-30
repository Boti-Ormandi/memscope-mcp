from __future__ import annotations

import json
import os
import tempfile

import anyio


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="memscope-site-tools-") as data_root:
        os.environ["MEMSCOPE_HOME"] = data_root
        from memscope_mcp.server import mcp

        tools = anyio.run(mcp.list_tools)
        captured = []
        for tool in tools:
            value = tool.model_dump(by_alias=True, exclude_none=True)
            item = {
                "name": value["name"],
                "description": value["description"],
                "inputSchema": value["inputSchema"],
            }
            if "outputSchema" in value:
                item["outputSchema"] = value["outputSchema"]
            captured.append(item)

    print(json.dumps({"tools": captured}, ensure_ascii=False, separators=(",", ":")))


if __name__ == "__main__":
    main()
