"""Console-script entry point for memscope-mcp.

Bare invocation (`memscope-mcp` with no arguments) runs the MCP server over
stdio. This is the contract MCP clients depend on; do not change it.

Subcommands are exposed for inspection and bundled-plugin installation.
"""

from __future__ import annotations

import argparse
import sys
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
from importlib.resources import files

from . import paths


def _cmd_server(_args: argparse.Namespace) -> int:
    from .server import main as run_server

    run_server()
    return 0


def _cmd_version(_args: argparse.Namespace) -> int:
    try:
        print(_pkg_version("memscope-mcp"))
    except PackageNotFoundError:
        print("0.0.0+unknown")
    return 0


def _cmd_paths(_args: argparse.Namespace) -> int:
    print(f"MEMSCOPE_HOME={paths.MEMSCOPE_HOME}")
    print(f"LOGS_DIR={paths.LOGS_DIR}")
    print(f"SCRIPTS_DIR={paths.SCRIPTS_DIR}")
    print(f"PLUGINS_DIR={paths.PLUGINS_DIR}")
    return 0


def _first_docstring_line(text: str) -> str:
    for triple in ('"""', "'''"):
        idx = text.find(triple)
        if idx == -1:
            continue
        end = text.find(triple, idx + 3)
        if end == -1:
            continue
        body = text[idx + 3 : end].strip().splitlines()
        if body:
            return body[0].strip()
    return ""


def _bundled_plugins() -> list[tuple[str, str]]:
    pkg = files("memscope_mcp._contrib.plugins")
    items: list[tuple[str, str]] = []
    for entry in pkg.iterdir():
        name = entry.name
        if not name.endswith(".py") or name.startswith("_"):
            continue
        plugin_name = name[:-3]
        text = entry.read_text(encoding="utf-8")
        items.append((plugin_name, _first_docstring_line(text)))
    items.sort()
    return items


def _cmd_list_plugins(_args: argparse.Namespace) -> int:
    for name, summary in _bundled_plugins():
        if summary:
            print(f"{name}: {summary}")
        else:
            print(name)
    return 0


def _cmd_install_plugin(args: argparse.Namespace) -> int:
    src = files("memscope_mcp._contrib.plugins") / f"{args.name}.py"
    if not src.is_file():
        available = ", ".join(name for name, _ in _bundled_plugins())
        print(f"error: unknown plugin '{args.name}'; available: {available}", file=sys.stderr)
        return 1
    paths.PLUGINS_DIR.mkdir(parents=True, exist_ok=True)
    dest = paths.PLUGINS_DIR / f"{args.name}.py"
    if dest.exists() and not args.force:
        print(
            f"error: plugin already exists at {dest}; use --force to overwrite",
            file=sys.stderr,
        )
        return 1
    dest.write_bytes(src.read_bytes())
    print(f"installed {args.name} -> {dest}")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="memscope-mcp")
    sub = parser.add_subparsers(dest="cmd")

    p_server = sub.add_parser("server", help="run the MCP server (default)")
    p_server.set_defaults(func=_cmd_server)

    p_version = sub.add_parser("version", help="print the installed version")
    p_version.set_defaults(func=_cmd_version)

    p_paths = sub.add_parser("paths", help="print resolved data directories")
    p_paths.set_defaults(func=_cmd_paths)

    p_list = sub.add_parser("list-plugins", help="list bundled reference plugins")
    p_list.set_defaults(func=_cmd_list_plugins)

    p_install = sub.add_parser("install-plugin", help="install a bundled plugin")
    p_install.add_argument("name")
    p_install.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing plugin file",
    )
    p_install.set_defaults(func=_cmd_install_plugin)

    parser.set_defaults(func=_cmd_server)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
