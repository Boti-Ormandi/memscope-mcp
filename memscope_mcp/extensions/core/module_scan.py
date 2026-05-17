"""Module enumeration, address resolution, AOB scanning, pointer chains."""

from typing import Any, Callable, Optional

from ...extensions.base import ExtensionContext, LuaExtension
from ...tools.lua.modules import format_address as lua_format_address
from ...tools.lua.modules import get_module_from_address, get_modules, resolve_export_lua
from ...tools.lua.scanning_helpers import scan_pointer, scan_string
from ...tools.scanning import SCAN_TIMEOUT_SECONDS, scan_aob_addresses
from ...utils.memory_utils import is_valid_pointer, parse_address


class ModuleScanExtension(LuaExtension):
    """Module lookup, address resolution, AOB scanning, pointer chains."""

    name = "module_scan"
    description = "Modules, scanning, and pointer chains"

    instructions = """
### Modules & Scanning

```lua
getModuleBase("name.dll")      -- Module base address
getModuleSize("name.dll")      -- Module size
getAddress("mod.dll+0x123")    -- Resolve module+offset
getModules(filter?)             -- List modules: {name, base, size, path}
getModuleFromAddress(addr)      -- Reverse lookup: {name, base, offset} or nil
formatAddress(addr)             -- "module.dll+0xOFFSET" or "0xADDR"
AOBScan(pattern, start?, end?, limit?)  -- Modules by default; bounded scan when start/end given
AOBScanModule(mod, pattern)     -- Scan specific module
scanString(str, module?, wide?) -- Scan for string (ASCII or UTF-16)
scanPointer(target, module?)    -- Find all pointers to target address (xrefs)
resolveExport(module, name)     -- Resolve DLL export to address
```

AOBScan results carry a `metadata` table (mode, scanned_region_count, bytes_scanned, timeout_hit, result_count).

### Pointer Chains

```lua
readPointerChain(base, off1, off2, ...)  -- Follow chain, return final value
```
""".strip()

    def register(self, ctx: ExtensionContext) -> dict[str, Callable]:
        self._session = ctx.session
        self._table = ctx.table_factory
        self._log_error = ctx.log_error

        return {
            # Address/module
            "getAddress": self._get_address,
            "getModuleBase": self._get_module_base,
            "getModuleSize": self._get_module_size,
            "getModules": lambda filt=None: get_modules(self._table, filt),
            "getModuleFromAddress": lambda addr: get_module_from_address(self._table, addr, self._log_error),
            "formatAddress": lambda addr: lua_format_address(addr, self._log_error),
            # Scanning
            "AOBScan": self._aob_scan,
            "AOBScanModule": self._aob_scan_module,
            "scanString": lambda s, mod=None, wide=False, limit=100: scan_string(
                self._table, s, mod, wide, limit, self._log_error
            ),
            "scanPointer": lambda target, mod=None, align=8, limit=100: scan_pointer(
                self._table, target, mod, align, limit, self._log_error
            ),
            # PE export resolution
            "resolveExport": lambda mod, fn: resolve_export_lua(mod, fn, self._log_error),
            # Pointer chain
            "readPointerChain": self._read_pointer_chain,
        }

    def _get_address(self, expr: str) -> Optional[int]:
        """Parse address expression like 'module.dll+0x1A208D8'."""
        try:
            return parse_address(expr)
        except:
            return None

    def _get_module_base(self, name: str) -> Optional[int]:
        """Get module base address."""
        try:
            return self._session.get_module_base(name)
        except:
            return None

    def _get_module_size(self, name: str) -> Optional[int]:
        """Get module size."""
        try:
            return self._session.get_module_size(name)
        except:
            return None

    def _aob_scan(self, pattern: str, start_addr=None, end_addr=None, max_results=100, timeout_ms=None):
        """Scan modules or a bounded readable memory range for an AOB pattern."""
        try:
            start = self._optional_address(start_addr)
            end = self._optional_address(end_addr)
            timeout = int(timeout_ms) if timeout_ms is not None else SCAN_TIMEOUT_SECONDS * 1000

            result = scan_aob_addresses(
                pattern,
                start_addr=start,
                end_addr=end,
                max_results=int(max_results),
                timeout_ms=timeout,
            )
            if not result["success"]:
                return self._scan_table(
                    [], {"error": result.get("error_detail", result.get("error", "AOBScan failed"))}
                )

            return self._scan_table(result["matches"], result["metadata"])
        except Exception as e:
            self._log_error("AOBScan", e)
            return self._scan_table([], {"error": str(e)})

    def _aob_scan_module(self, module: str, pattern: str, max_results=100, timeout_ms=None):
        """Scan a single module for AOB pattern."""
        try:
            timeout = int(timeout_ms) if timeout_ms is not None else SCAN_TIMEOUT_SECONDS * 1000
            result = scan_aob_addresses(pattern, module=module, max_results=int(max_results), timeout_ms=timeout)
            if not result["success"]:
                return self._scan_table(
                    [], {"error": result.get("error_detail", result.get("error", "AOBScanModule failed"))}
                )

            return self._scan_table(result["matches"], result["metadata"])
        except Exception as e:
            self._log_error("AOBScanModule", e)
            return self._scan_table([], {"error": str(e)})

    def _optional_address(self, value) -> Optional[int]:
        if value is None:
            return None
        if isinstance(value, str):
            return parse_address(value)
        return int(value)

    def _scan_table(self, matches: list[int], metadata: dict[str, Any]):
        result = self._table(*matches)
        meta = self._table()
        for key, value in metadata.items():
            meta[key] = value
        result["metadata"] = meta
        return result

    def _read_pointer_chain(self, base, *offsets):
        """Follow pointer chain: [[base + off1] + off2] + off3..."""
        try:
            if isinstance(base, str):
                current = parse_address(base)
            else:
                current = int(base)

            for offset in offsets:
                ptr = self._session.read_ptr(current)
                if not is_valid_pointer(ptr):
                    return None
                current = ptr + int(offset)

            return current
        except:
            return None
