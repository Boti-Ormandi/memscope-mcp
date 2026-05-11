"""Tests for PE export table parser.

Builds minimal PE images in bytearrays and monkeypatches SESSION
to serve memory reads from them. No real process attachment needed.
"""

import struct

import pytest

from src.utils.pe import resolve_export

# ---------- PE Builder ----------


def _build_pe(base_addr, exports, export_dir_rva=0x1000, forwarded=None):
    """Build a minimal PE image with the given exports.

    Args:
        base_addr: Simulated module base address.
        exports: List of (name, func_rva) tuples, must be sorted by name.
        export_dir_rva: RVA where the export directory is placed.
        forwarded: Dict mapping export name -> forwarder string (e.g. "MSWSOCK.WSPSend").

    Returns:
        bytearray with the PE image.
    """
    forwarded = forwarded or {}
    buf = bytearray(0x4000)

    # --- DOS header ---
    buf[0:2] = b"MZ"
    pe_offset = 0x80
    struct.pack_into("<I", buf, 0x3C, pe_offset)

    # --- PE signature ---
    buf[pe_offset : pe_offset + 4] = b"PE\x00\x00"

    # --- COFF header (20 bytes) ---
    coff_offset = pe_offset + 4
    struct.pack_into("<H", buf, coff_offset + 16, 0xF0)  # SizeOfOptionalHeader

    # --- Optional header ---
    opt_offset = coff_offset + 20
    struct.pack_into("<H", buf, opt_offset, 0x020B)  # PE32+ magic

    # --- Data directory entry 0 (export) at opt_offset + 112 ---
    dd_offset = opt_offset + 112
    export_dir_size = 0x200  # generous size so forwarded RVAs fit inside
    struct.pack_into("<I", buf, dd_offset, export_dir_rva)
    struct.pack_into("<I", buf, dd_offset + 4, export_dir_size)

    if not exports:
        return buf

    num_funcs = len(exports)
    num_names = len(exports)

    # Layout within the export section (all relative to export_dir_rva):
    #   0x00..0x27  export directory (40 bytes)
    #   0x28..      name strings area
    # We place sub-tables after the directory.
    names_table_rva = export_dir_rva + 40
    ordinals_table_rva = names_table_rva + num_names * 4
    functions_table_rva = ordinals_table_rva + num_names * 2
    # Align to 4 bytes
    functions_table_rva = (functions_table_rva + 3) & ~3
    strings_area_rva = functions_table_rva + num_funcs * 4

    # --- Export directory (40 bytes at export_dir_rva) ---
    ed = export_dir_rva
    struct.pack_into("<I", buf, ed + 0x14, num_funcs)  # NumberOfFunctions
    struct.pack_into("<I", buf, ed + 0x18, num_names)  # NumberOfNames
    struct.pack_into("<I", buf, ed + 0x1C, functions_table_rva)  # AddressOfFunctions
    struct.pack_into("<I", buf, ed + 0x20, names_table_rva)  # AddressOfNames
    struct.pack_into("<I", buf, ed + 0x24, ordinals_table_rva)  # AddressOfNameOrdinals

    # --- Write name strings, name RVA array, ordinal array, function RVA array ---
    str_cursor = strings_area_rva
    for i, (name, func_rva) in enumerate(exports):
        # Name RVA pointer
        struct.pack_into("<I", buf, names_table_rva + i * 4, str_cursor)
        # Name string (null-terminated)
        name_bytes = name.encode("ascii") + b"\x00"
        buf[str_cursor : str_cursor + len(name_bytes)] = name_bytes
        str_cursor += len(name_bytes)

        # Ordinal (identity mapping: ordinal[i] = i)
        struct.pack_into("<H", buf, ordinals_table_rva + i * 2, i)

        # Function RVA
        if name in forwarded:
            # Place forwarder string inside the export directory range so the parser
            # detects it as a forwarded export.
            fwd_str = forwarded[name].encode("ascii") + b"\x00"
            fwd_rva = str_cursor
            buf[fwd_rva : fwd_rva + len(fwd_str)] = fwd_str
            str_cursor += len(fwd_str)
            # The forwarder RVA must be within [export_dir_rva, export_dir_rva + export_dir_size)
            assert export_dir_rva <= fwd_rva < export_dir_rva + export_dir_size, (
                f"Forwarder string at RVA {fwd_rva:#x} falls outside export dir range"
            )
            struct.pack_into("<I", buf, functions_table_rva + i * 4, fwd_rva)
        else:
            struct.pack_into("<I", buf, functions_table_rva + i * 4, func_rva)

    return buf


# ---------- Mock helpers ----------


class MockSession:
    """Minimal SESSION stand-in that reads from in-memory PE images."""

    def __init__(self):
        self.modules = {}
        self._images = {}  # base_addr -> bytearray

    def add_module(self, name, base, image):
        self.modules[name] = {"base": base, "size": len(image), "path": f"C:\\Windows\\System32\\{name}"}
        self._images[base] = image

    def read_bytes(self, address, size):
        for base, image in self._images.items():
            offset = address - base
            if 0 <= offset < len(image) and offset + size <= len(image):
                return bytes(image[offset : offset + size])
        return b"\x00" * size

    def read_string(self, address, max_length=256):
        for base, image in self._images.items():
            offset = address - base
            if 0 <= offset < len(image):
                end = image.index(0, offset) if 0 in image[offset : offset + max_length] else offset + max_length
                return image[offset:end].decode("ascii", errors="replace")
        return ""


# ---------- Fixtures ----------

BASE_ADDR = 0x7FF800000000


@pytest.fixture()
def mock_session(monkeypatch):
    """Provide a MockSession and patch it into the pe module."""
    session = MockSession()
    monkeypatch.setattr("src.utils.pe.SESSION", session)
    return session


@pytest.fixture()
def pe_with_exports(mock_session):
    """MockSession with a ws2_32.dll module exporting connect, recv, send."""
    exports = [
        ("connect", 0x2000),
        ("recv", 0x3000),
        ("send", 0x4000),
    ]
    image = _build_pe(BASE_ADDR, exports)
    mock_session.add_module("ws2_32.dll", BASE_ADDR, image)
    return mock_session


# ---------- Tests ----------


class TestResolveKnownExport:
    def test_resolve_send(self, pe_with_exports):
        addr = resolve_export("ws2_32.dll", "send")
        assert addr == BASE_ADDR + 0x4000

    def test_resolve_connect(self, pe_with_exports):
        addr = resolve_export("ws2_32.dll", "connect")
        assert addr == BASE_ADDR + 0x2000

    def test_resolve_recv(self, pe_with_exports):
        addr = resolve_export("ws2_32.dll", "recv")
        assert addr == BASE_ADDR + 0x3000


class TestBinarySearchBoundaries:
    """Binary search must handle first, last, and middle elements."""

    def test_first_name(self, pe_with_exports):
        # "connect" is first in sorted order
        assert resolve_export("ws2_32.dll", "connect") == BASE_ADDR + 0x2000

    def test_last_name(self, pe_with_exports):
        # "send" is last in sorted order
        assert resolve_export("ws2_32.dll", "send") == BASE_ADDR + 0x4000

    def test_middle_name(self, pe_with_exports):
        # "recv" is in the middle
        assert resolve_export("ws2_32.dll", "recv") == BASE_ADDR + 0x3000

    def test_single_export(self, mock_session):
        """Binary search on a table with exactly one entry."""
        exports = [("solo", 0x5000)]
        image = _build_pe(BASE_ADDR, exports)
        mock_session.add_module("single.dll", BASE_ADDR, image)
        assert resolve_export("single.dll", "solo") == BASE_ADDR + 0x5000

    def test_two_exports(self, mock_session):
        """Binary search on a table with exactly two entries."""
        exports = [("alpha", 0x5000), ("beta", 0x6000)]
        image = _build_pe(BASE_ADDR, exports)
        mock_session.add_module("pair.dll", BASE_ADDR, image)
        assert resolve_export("pair.dll", "alpha") == BASE_ADDR + 0x5000
        assert resolve_export("pair.dll", "beta") == BASE_ADDR + 0x6000


class TestExportNotFound:
    def test_nonexistent_function(self, pe_with_exports):
        assert resolve_export("ws2_32.dll", "nonexistent") is None

    def test_empty_function_name(self, pe_with_exports):
        assert resolve_export("ws2_32.dll", "") is None

    def test_case_sensitive_function_name(self, pe_with_exports):
        # PE export names are case-sensitive
        assert resolve_export("ws2_32.dll", "Send") is None


class TestModuleNotLoaded:
    def test_missing_module(self, mock_session):
        assert resolve_export("not_loaded.dll", "send") is None

    def test_empty_modules(self, mock_session):
        assert resolve_export("ws2_32.dll", "connect") is None


class TestNoExportDirectory:
    def test_export_dir_rva_zero(self, mock_session):
        """PE with export_dir_rva=0 should return None."""
        exports = [("send", 0x4000)]
        image = _build_pe(BASE_ADDR, exports, export_dir_rva=0x1000)
        # Overwrite the data directory entry to set export RVA to 0
        pe_offset = struct.unpack_from("<I", image, 0x3C)[0]
        dd_offset = pe_offset + 4 + 20 + 112
        struct.pack_into("<I", image, dd_offset, 0)  # export_dir_rva = 0
        struct.pack_into("<I", image, dd_offset + 4, 0)  # size = 0
        mock_session.add_module("noexport.dll", BASE_ADDR, image)
        assert resolve_export("noexport.dll", "send") is None


class TestForwardedExport:
    def test_forwarded_resolves_to_target(self, mock_session):
        """A forwarded export should recursively resolve to the real function."""
        target_base = 0x7FF900000000

        # Target module: MSWSOCK.dll with the real "SendReal" export
        target_exports = [("SendReal", 0x8000)]
        target_image = _build_pe(target_base, target_exports)
        mock_session.add_module("MSWSOCK.dll", target_base, target_image)

        # Source module: ws2_32.dll with "send" forwarded to MSWSOCK.SendReal
        source_exports = [("send", 0x9999)]  # func_rva is ignored for forwarded
        source_image = _build_pe(BASE_ADDR, source_exports, forwarded={"send": "MSWSOCK.SendReal"})
        mock_session.add_module("ws2_32.dll", BASE_ADDR, source_image)

        addr = resolve_export("ws2_32.dll", "send")
        assert addr == target_base + 0x8000

    def test_forwarded_without_dll_suffix(self, mock_session):
        """Forwarder string without .dll suffix should still resolve (parser appends .dll)."""
        target_base = 0x7FF900000000

        target_exports = [("DoStuff", 0x7000)]
        target_image = _build_pe(target_base, target_exports)
        mock_session.add_module("helper.dll", target_base, target_image)

        # Forwarder says "helper.DoStuff" (no .dll) -- parser should append .dll
        source_exports = [("DoStuff", 0x9999)]
        source_image = _build_pe(BASE_ADDR, source_exports, forwarded={"DoStuff": "helper.DoStuff"})
        mock_session.add_module("main.dll", BASE_ADDR, source_image)

        addr = resolve_export("main.dll", "DoStuff")
        assert addr == target_base + 0x7000

    def test_forwarded_target_not_loaded(self, mock_session):
        """Forwarded to a module that isn't loaded -> None."""
        source_exports = [("send", 0x9999)]
        source_image = _build_pe(BASE_ADDR, source_exports, forwarded={"send": "MISSING.SendFunc"})
        mock_session.add_module("ws2_32.dll", BASE_ADDR, source_image)

        assert resolve_export("ws2_32.dll", "send") is None


class TestForwardChainLimit:
    def test_chain_exceeds_depth_limit(self, mock_session):
        """Forwarder chain deeper than 5 levels should return None."""
        # Create 7 modules, each forwarding to the next.
        # Forwarder strings use "modN.func" format (no .dll) -- the parser appends .dll.
        # Depth limit is >5, so mod0(0)->mod1(1)->...->mod5(5)->mod6(6=blocked).
        num_modules = 7
        bases = [0x7FF800000000 + i * 0x100000 for i in range(num_modules)]

        # Last module has the real export
        last_exports = [("func", 0x5000)]
        last_image = _build_pe(bases[-1], last_exports)
        mock_session.add_module(f"mod{num_modules - 1}.dll", bases[-1], last_image)

        # Each earlier module forwards to the next
        for i in range(num_modules - 2, -1, -1):
            # Forwarder: "mod3.func" -> parser splits on first dot -> module="mod3", func="func"
            # Then appends .dll -> "mod3.dll"
            fwd_target = f"mod{i + 1}.func"
            exports = [("func", 0x9999)]
            image = _build_pe(bases[i], exports, forwarded={"func": fwd_target})
            mock_session.add_module(f"mod{i}.dll", bases[i], image)

        # mod0 -> mod1 -> mod2 -> mod3 -> mod4 -> mod5 -> mod6
        # Depths:  0       1       2       3       4       5      6 (blocked at >5)
        assert resolve_export("mod0.dll", "func") is None

    def test_chain_at_exact_depth_limit(self, mock_session):
        """A chain of exactly 6 forwards (depths 0..5) should succeed -- depth 5 is the last allowed."""
        # The limit check is `if _depth > 5`, so _depth=6 is the first blocked.
        # 6 modules: mod0 forwards to mod1 ... mod4 forwards to mod5 (real).
        # resolve_export is called with _depth=5 for mod5, and 5 > 5 is False, so it succeeds.
        num_modules = 6
        bases = [0x7FF800000000 + i * 0x100000 for i in range(num_modules)]

        last_exports = [("func", 0x5000)]
        last_image = _build_pe(bases[-1], last_exports)
        mock_session.add_module(f"mod{num_modules - 1}.dll", bases[-1], last_image)

        for i in range(num_modules - 2, -1, -1):
            fwd_target = f"mod{i + 1}.func"
            exports = [("func", 0x9999)]
            image = _build_pe(bases[i], exports, forwarded={"func": fwd_target})
            mock_session.add_module(f"mod{i}.dll", bases[i], image)

        # mod0(depth=0) -> mod1(1) -> mod2(2) -> mod3(3) -> mod4(4) -> mod5(5=real)
        assert resolve_export("mod0.dll", "func") == bases[-1] + 0x5000


class TestInvalidPESignature:
    def test_bad_mz_signature(self, mock_session):
        image = _build_pe(BASE_ADDR, [("send", 0x4000)])
        image[0:2] = b"\x00\x00"  # corrupt MZ
        mock_session.add_module("bad.dll", BASE_ADDR, image)
        assert resolve_export("bad.dll", "send") is None

    def test_bad_pe_signature(self, mock_session):
        image = _build_pe(BASE_ADDR, [("send", 0x4000)])
        pe_offset = struct.unpack_from("<I", image, 0x3C)[0]
        image[pe_offset : pe_offset + 4] = b"\x00\x00\x00\x00"  # corrupt PE\0\0
        mock_session.add_module("bad.dll", BASE_ADDR, image)
        assert resolve_export("bad.dll", "send") is None

    def test_bad_optional_header_magic(self, mock_session):
        image = _build_pe(BASE_ADDR, [("send", 0x4000)])
        pe_offset = struct.unpack_from("<I", image, 0x3C)[0]
        opt_offset = pe_offset + 4 + 20
        struct.pack_into("<H", image, opt_offset, 0x010B)  # PE32 instead of PE32+
        mock_session.add_module("bad.dll", BASE_ADDR, image)
        assert resolve_export("bad.dll", "send") is None


class TestCaseInsensitiveModuleLookup:
    def test_uppercase_query(self, pe_with_exports):
        assert resolve_export("WS2_32.DLL", "send") == BASE_ADDR + 0x4000

    def test_mixed_case_query(self, pe_with_exports):
        assert resolve_export("Ws2_32.Dll", "send") == BASE_ADDR + 0x4000

    def test_lowercase_query(self, pe_with_exports):
        assert resolve_export("ws2_32.dll", "send") == BASE_ADDR + 0x4000
