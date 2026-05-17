"""PE export table parser for resolving DLL exports from process memory.

Reads the PE export directory from a loaded module in the target process.
Binary searches the sorted name table and handles forwarded exports.
"""

import logging
import struct

from ..session import SESSION

logger = logging.getLogger(__name__)


def resolve_export(module_name: str, function_name: str, _depth: int = 0) -> int | None:
    """Resolve a DLL export to its absolute address in the target process.

    Reads the PE export directory from the module's base address in process memory.
    Handles forwarded exports by recursively resolving the forwarder string.

    Args:
        module_name: DLL name (e.g. "ws2_32.dll").
        function_name: Export name (e.g. "send").
        _depth: Internal recursion depth for forwarded exports.

    Returns:
        Absolute address of the function, or None if not found.
    """
    if _depth > 5:
        logger.warning(f"Forwarded export chain exceeded depth limit: {module_name}!{function_name}")
        return None

    # Case-insensitive module lookup
    base = None
    for name, info in SESSION.modules.items():
        if name.lower() == module_name.lower():
            base = info["base"]
            break
    if base is None:
        return None

    try:
        return _resolve_from_base(base, module_name, function_name, _depth)
    except Exception:
        return None


def _resolve_from_base(base: int, module_name: str, function_name: str, depth: int) -> int | None:
    """Parse PE headers and resolve export from a known module base.

    Args:
        base: Module base address in target process.
        module_name: Module name (for forwarded export recursion).
        function_name: Export name to resolve.
        depth: Current forwarding recursion depth.

    Returns:
        Absolute address or None.
    """
    # Read DOS header - verify MZ signature, get PE offset
    dos_hdr = SESSION.read_bytes(base, 64)
    if dos_hdr[0:2] != b"MZ":
        logger.warning(f"Invalid MZ signature in {module_name}")
        return None

    pe_offset = struct.unpack_from("<I", dos_hdr, 0x3C)[0]

    # Read PE signature
    pe_sig = SESSION.read_bytes(base + pe_offset, 4)
    if pe_sig != b"PE\x00\x00":
        logger.warning(f"Invalid PE signature in {module_name}")
        return None

    # Skip COFF header (20 bytes after PE signature)
    # Read optional header magic
    opt_hdr_offset = pe_offset + 4 + 20
    opt_magic = struct.unpack_from("<H", SESSION.read_bytes(base + opt_hdr_offset, 2), 0)[0]
    if opt_magic != 0x020B:  # PE32+ (x64)
        return None

    # Export directory is data directory entry 0
    # PE32+ optional header: magic(2) + 110 bytes + data directories start at offset 112
    export_dir_entry_offset = opt_hdr_offset + 112
    export_dir_data = SESSION.read_bytes(base + export_dir_entry_offset, 8)
    export_dir_rva = struct.unpack_from("<I", export_dir_data, 0)[0]
    export_dir_size = struct.unpack_from("<I", export_dir_data, 4)[0]

    if export_dir_rva == 0:
        return None

    # Read export directory (40 bytes)
    export_dir = SESSION.read_bytes(base + export_dir_rva, 40)
    num_functions = struct.unpack_from("<I", export_dir, 0x14)[0]
    num_names = struct.unpack_from("<I", export_dir, 0x18)[0]
    addr_of_functions = struct.unpack_from("<I", export_dir, 0x1C)[0]
    addr_of_names = struct.unpack_from("<I", export_dir, 0x20)[0]
    addr_of_ordinals = struct.unpack_from("<I", export_dir, 0x24)[0]

    if num_names == 0:
        return None

    # Binary search the name table
    idx = _binary_search_exports(base, addr_of_names, num_names, function_name)
    if idx is None:
        return None

    # Read ordinal for the found name
    ordinal = struct.unpack_from("<H", SESSION.read_bytes(base + addr_of_ordinals + idx * 2, 2), 0)[0]

    if ordinal >= num_functions:
        return None

    # Read function RVA
    func_rva = struct.unpack_from("<I", SESSION.read_bytes(base + addr_of_functions + ordinal * 4, 4), 0)[0]

    # Check for forwarded export: RVA points inside export directory
    if export_dir_rva <= func_rva < export_dir_rva + export_dir_size:
        forwarder = SESSION.read_string(base + func_rva, max_length=256)
        if not forwarder or "." not in forwarder:
            return None
        dot_pos = forwarder.index(".")
        fwd_module = forwarder[:dot_pos]
        fwd_function = forwarder[dot_pos + 1 :]
        if not fwd_module.lower().endswith(".dll"):
            fwd_module += ".dll"
        return resolve_export(fwd_module, fwd_function, _depth=depth + 1)

    return base + func_rva


def _binary_search_exports(base: int, names_rva: int, num_names: int, target: str) -> int | None:
    """Binary search the PE export name table.

    Names are sorted alphabetically per PE spec.

    Args:
        base: Module base address.
        names_rva: RVA of the name pointer array.
        num_names: Number of entries in the name table.
        target: Function name to find.

    Returns:
        Index into the name/ordinal arrays, or None if not found.
    """
    lo, hi = 0, num_names - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        name_rva = struct.unpack_from("<I", SESSION.read_bytes(base + names_rva + mid * 4, 4), 0)[0]
        name = SESSION.read_string(base + name_rva, max_length=256)
        if name == target:
            return mid
        elif name < target:
            lo = mid + 1
        else:
            hi = mid - 1
    return None
