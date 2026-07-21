"""Module enumeration, address resolution, unified scanning, and pointer chains."""

from typing import Callable, Optional

from ...extensions.base import ExtensionContext, LuaExtension
from ...scanning.execution import ScanExecutor
from ...scanning.lua import LuaScanAdapter
from ...tools.lua.modules import format_address as lua_format_address
from ...tools.lua.modules import get_module_from_address, get_modules, resolve_export_lua
from ...utils.memory_utils import is_valid_pointer, parse_address, parse_offset


class ModuleScanExtension(LuaExtension):
    """Module lookup, address resolution, scanning, and pointer chains."""

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
AOBScan(pattern, options?)      -- Strict AOB pattern; ?? is the only wildcard
AOBScanMany(patterns, options?) -- One-pass keyed first/count batch (1-32 patterns)
scanString(text, options?)      -- encoding: "ascii" or "utf-16le"
scanPointer(target, options?)   -- alignment defaults to 8
resolveExport(module, name)     -- Resolve DLL export to address
```

Scan options use named fields only: `scope`, `mode`, `max_matches`, `timeout_ms`, and
`diagnostics`; `scanString` also accepts `encoding`, and `scanPointer` accepts `alignment`.
`AOBScanMany` accepts ordered `{key, pattern}` items and only `first` or `count` mode.
Scope kinds are `all_modules`, `modules`, and half-open `range`. Single-scan modes are
`addresses`, `first`, and `count`. Expected failures return `nil, error_table`; a valid no-match scan
returns a non-nil empty table with `metadata.status`.

### Pointer Chains

```lua
readPointerChain(base, off1, off2, ...)  -- Follow chain, return final address
```

Standard reverse-engineering semantics: add offset, dereference, repeat.
""".strip()

    def register(self, ctx: ExtensionContext) -> dict[str, Callable]:
        self._session = ctx.session
        self._table = ctx.table_factory
        self._log_error = ctx.log_error
        self._scan_adapter = LuaScanAdapter(
            ScanExecutor(ctx.session),
            engine=ctx.engine,
            table_factory=ctx.table_factory,
            log_error=ctx.log_error,
        )

        return {
            # Address/module
            "getAddress": self._get_address,
            "getModuleBase": self._get_module_base,
            "getModuleSize": self._get_module_size,
            "getModules": lambda filt=None: get_modules(self._table, filt),
            "getModuleFromAddress": lambda addr: get_module_from_address(self._table, addr, self._log_error),
            "formatAddress": lambda addr: lua_format_address(addr, self._log_error),
            # Scanning
            "AOBScan": self._scan_adapter.aob_scan,
            "AOBScanMany": self._scan_adapter.aob_scan_many,
            "scanString": self._scan_adapter.string_scan,
            "scanPointer": self._scan_adapter.pointer_scan,
            # PE export resolution
            "resolveExport": lambda mod, fn: resolve_export_lua(mod, fn, self._log_error),
            # Pointer chain
            "readPointerChain": self._read_pointer_chain,
        }

    def _get_address(self, expr: str) -> Optional[int]:
        """Parse address expression like 'module.dll+0x1A208D8'."""
        try:
            return parse_address(expr)
        except Exception:
            return None

    def _get_module_base(self, name: str) -> Optional[int]:
        """Get module base address."""
        try:
            return self._session.get_module_base(name)
        except Exception:
            return None

    def _get_module_size(self, name: str) -> Optional[int]:
        """Get module size."""
        try:
            return self._session.get_module_size(name)
        except Exception:
            return None

    def _read_pointer_chain(self, base, *offsets):
        """Follow pointer chain: [[base + off1] + off2] + off3..."""
        try:
            current = parse_address(base) if isinstance(base, str) else int(base)
            for offset in offsets:
                read_addr = current + parse_offset(offset)
                ptr = self._session.read_ptr(read_addr)
                if not is_valid_pointer(ptr):
                    return None
                current = ptr
            return current
        except Exception:
            return None
