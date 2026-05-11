"""Process introspection and session management: attach, detach, process list, threads, services."""

from typing import Callable

from ...extensions.base import ExtensionContext, LuaExtension
from ...tools.lua.process_info import (
    get_environment,
    get_memory_regions,
    get_modules_remote,
    get_process_info,
    get_process_list,
    get_region_info,
    get_services,
    get_threads,
    is_being_debugged,
)


class ProcessExtension(LuaExtension):
    """Process enumeration, threads, services, memory regions, session management."""

    name = "process"
    description = "Process introspection and session management"

    instructions = """
### Session Management

```lua
attach(target, pid?)        -- Full session attach with module cache + lifecycle
                            -- attach("Game.exe") or attach("chrome.exe", 1234) or attach(1234)
                            -- Returns {pid, name, module_count} or nil
detach()                    -- Clean detach with lifecycle callbacks. Returns bool
isAttached()                -- Check if currently attached to a process
getAttachedProcess()        -- Get {pid, name, module_count} or nil
openProcess(pid)            -- Attach by PID (legacy, prefer attach())
```

### Process Introspection (pre-attach)

```lua
getProcessList(filter?, limit?)  -- List processes: {pid, name, parent_pid}
getProcessInfo(pid?)             -- Details: {pid, name, path, threads, command_line,
                                 --   current_directory, being_debugged}
isBeingDebugged(pid?)            -- Quick debugger check (reads PEB)
getEnvironment(pid?)             -- Env vars as {KEY = "value", ...} table
getModulesRemote(pid?)           -- Modules without attaching: {name, base, size, path}
getServices(pid?)                -- Services: {name, display_name, pid, state}
getThreads(pid?)                 -- Threads: {tid, priority}
getMemoryRegions(filter?, limit?) -- Regions: {base, size, protection, type}
getRegionInfo(addr)              -- Region at address
```
""".strip()

    def register(self, ctx: ExtensionContext) -> dict[str, Callable]:
        self._session = ctx.session
        self._table = ctx.table_factory
        self._log_error = ctx.log_error

        return {
            # Session management
            "attach": lambda target, pid=None: self._attach(target, pid),
            "detach": lambda: self._detach(),
            "isAttached": lambda: self._is_attached(),
            "getAttachedProcess": lambda: self._get_attached_process(),
            # Process introspection
            "getProcessList": lambda filt=None, limit=500: get_process_list(self._table, filt, limit),
            "getProcessInfo": lambda pid=None: get_process_info(self._table, pid),
            "isBeingDebugged": lambda pid=None: is_being_debugged(pid),
            "getEnvironment": lambda pid=None: get_environment(self._table, pid),
            "getModulesRemote": lambda pid=None: get_modules_remote(self._table, pid),
            "getMemoryRegions": lambda filt=None, limit=1000: get_memory_regions(self._table, filt, limit),
            "getRegionInfo": lambda addr: get_region_info(self._table, addr),
            "getThreads": lambda pid=None: get_threads(self._table, pid),
            "getServices": lambda pid=None: get_services(self._table, pid),
            # Legacy
            "openProcess": lambda pid: self._attach(int(pid)),
        }

    def _attach(self, target, pid=None):
        """Attach to a process by name or PID with full session lifecycle.

        Args:
            target: Process name (str) or PID (int/float).
            pid: Optional PID for disambiguation when target is a name.

        Returns:
            Lua table with {pid, name, module_count} or None on failure.
        """
        import pymem.process

        from ...utils.logger import LOGGER

        try:
            process_name = None
            target_pid = 0

            if isinstance(target, (int, float)):
                # Target is a PID -- look up the name
                target_pid = int(target)
                for proc in pymem.process.list_processes():
                    if proc.th32ProcessID == target_pid:
                        process_name = proc.szExeFile.decode() if isinstance(proc.szExeFile, bytes) else proc.szExeFile
                        break
                if not process_name:
                    return None
            else:
                # Target is a process name
                process_name = str(target)
                if pid is not None:
                    target_pid = int(pid)

            # Canonical switch: detach old -> open new -> fire lifecycle
            if not self._session.switch_process(process_name, target_pid):
                return None

            LOGGER.set_process(process_name)

            result = self._table()
            result["pid"] = self._session.pid
            result["name"] = process_name
            result["module_count"] = len(self._session.modules)
            return result

        except Exception as e:
            self._log_error("attach", e)
            return None

    def _detach(self):
        """Detach from the current process with full lifecycle callbacks.

        Returns:
            True if detached, False if not attached.
        """
        try:
            if self._session.pm is None:
                return False
            self._session.detach()
            return True
        except Exception as e:
            self._log_error("detach", e)
            return False

    def _is_attached(self):
        """Check if currently attached to a process.

        Returns:
            True if attached, False otherwise.
        """
        return self._session.pm is not None

    def _get_attached_process(self):
        """Get info about the currently attached process.

        Returns:
            Lua table with {pid, name, module_count} or None if not attached.
        """
        if self._session.pm is None:
            return None
        result = self._table()
        result["pid"] = self._session.pid
        result["name"] = self._session.target_process or ""
        result["module_count"] = len(self._session.modules)
        return result
