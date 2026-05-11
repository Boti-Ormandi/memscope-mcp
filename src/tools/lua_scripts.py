"""Lua script management - file-based system.

Scripts are stored as .lua files in: <project>/scripts/<process>/<name>.lua
First line comment is the description: -- Description here

AI should use native file tools (Read/Write/Edit) to create and modify scripts.
This module provides list and run functionality only.
"""

from pathlib import Path
from typing import Optional

from ..session import SESSION

# Scripts directory - relative to project root (parent of src/)
SCRIPTS_DIR = Path(__file__).parent.parent.parent / "scripts"


def _get_process_name() -> Optional[str]:
    """Get current process name from session."""
    if not SESSION.target_process:
        return None
    return SESSION.target_process


def _extract_description(filepath: Path) -> str:
    """Extract description from first line comment of .lua file."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            first_line = f.readline().strip()
            if first_line.startswith("--"):
                return first_line[2:].strip()
    except Exception:
        pass
    return ""


def list_scripts(process: Optional[str] = None) -> dict:
    """List all available Lua scripts.

    Args:
        process: Optional process name filter. If None, uses current attached process.
                 Pass "*" to list all processes.

    Returns:
        {
            "scripts": [
                {
                    "name": "find_objects",
                    "process": "Target.exe",
                    "path": "/path/to/scripts/Target.exe/find_objects.lua",
                    "description": "Find key objects in memory..."
                },
                ...
            ],
            "count": int,
            "scripts_dir": str  # Base directory for creating new scripts
        }
    """
    scripts = []

    if process == "*":
        # List all processes
        if SCRIPTS_DIR.exists():
            process_dirs = [d for d in SCRIPTS_DIR.iterdir() if d.is_dir()]
        else:
            process_dirs = []
    else:
        # Single process
        process_name = process or _get_process_name()
        if not process_name:
            return {
                "scripts": [],
                "count": 0,
                "scripts_dir": str(SCRIPTS_DIR),
                "note": "Not attached. Pass process='*' for all, or process='ProcessName.exe' for specific.",
            }
        process_dir = SCRIPTS_DIR / process_name
        process_dirs = [process_dir] if process_dir.exists() else []

    for process_dir in process_dirs:
        for lua_file in process_dir.glob("*.lua"):
            scripts.append(
                {
                    "name": lua_file.stem,
                    "process": process_dir.name,
                    "path": str(lua_file),
                    "description": _extract_description(lua_file),
                }
            )

    # Sort by process, then name
    scripts.sort(key=lambda x: (x["process"], x["name"]))

    return {"scripts": scripts, "count": len(scripts), "scripts_dir": str(SCRIPTS_DIR)}


def run_script(name: str, process: Optional[str] = None, args: Optional[dict] = None) -> dict:
    """Run a saved Lua script by name.

    Args:
        name: Script name (without .lua extension)
        process: Optional process name. If None, uses current attached process.
        args: Optional dict of arguments passed to script as 'args' global

    Returns:
        Lua execution result with script metadata added.
    """
    from .lua_engine import execute_lua

    # Determine process
    process_name = process or _get_process_name()
    if not process_name:
        return {
            "success": False,
            "error": "NOT_ATTACHED",
            "detail": "Must be attached to determine process, or pass process='ProcessName.exe'",
        }

    # Find script file
    script_path = SCRIPTS_DIR / process_name / f"{name}.lua"
    if not script_path.exists():
        # Try case-insensitive search
        process_dir = SCRIPTS_DIR / process_name
        if process_dir.exists():
            for f in process_dir.glob("*.lua"):
                if f.stem.lower() == name.lower():
                    script_path = f
                    break

    if not script_path.exists():
        return {
            "success": False,
            "error": "SCRIPT_NOT_FOUND",
            "detail": f"Script '{name}' not found at {script_path}",
            "hint": f"Create it at: {script_path}",
        }

    # Read and execute
    try:
        with open(script_path, "r", encoding="utf-8") as f:
            script_content = f.read()
    except Exception as e:
        return {"success": False, "error": "READ_FAILED", "detail": str(e)}

    # Execute with args
    result = execute_lua(script_content, args)

    # Add metadata
    result["script_name"] = name
    result["script_path"] = str(script_path)
    result["script_description"] = _extract_description(script_path)

    return result


def get_script_count() -> int:
    """Get count of scripts for current process (for status display)."""
    process_name = _get_process_name()
    if not process_name:
        return 0
    process_dir = SCRIPTS_DIR / process_name
    if not process_dir.exists():
        return 0
    return len(list(process_dir.glob("*.lua")))
