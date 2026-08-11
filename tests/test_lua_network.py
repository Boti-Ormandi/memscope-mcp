"""Tests for Lua network helpers without a live target process."""

from types import SimpleNamespace

from memscope_mcp.extensions.base import ExtensionContext
from memscope_mcp.extensions.core.network import NetworkExtension
from memscope_mcp.tools.lua import network


class _NetworkSession:
    def __init__(self, read_data=None):
        self.calls = []
        self.read_data = read_data or {}

    def allocate(self, size, executable=False):
        self.calls.append(("allocate", self, size, executable))
        return 0x3000

    def write_bytes(self, address, data):
        self.calls.append(("write_bytes", self, address, bytes(data)))

    def read_bytes(self, address, size):
        self.calls.append(("read_bytes", self, address, size))
        return self.read_data[address][:size]

    def free(self, address):
        self.calls.append(("free", self, address))
        return True


class _HostileGlobalSession:
    def __getattr__(self, name):
        raise AssertionError(f"global SESSION must not be consulted: {name}")


def _register_network_extension(session):
    errors = []

    def log_error(*args):
        errors.append(args)

    extension = NetworkExtension()
    functions = extension.register(
        ExtensionContext(
            engine=SimpleNamespace(_output=[]),
            session=session,
            table_factory=dict,
            log_error=log_error,
        )
    )
    return extension, functions, errors


def test_get_socket_info_preserves_none_when_exports_are_missing(monkeypatch):
    resolver_calls = []
    session_a = _NetworkSession()

    def fake_resolve(module_name, function_name, *, session):
        resolver_calls.append((module_name, function_name, session))
        return None

    def fail_live_process_access(*args, **kwargs):
        raise AssertionError("getSocketInfo must not touch the live-process path when PE resolution fails")

    monkeypatch.setattr("memscope_mcp.utils.pe.resolve_export", fake_resolve)
    monkeypatch.setattr("memscope_mcp.tools.execute.execute_code", fail_live_process_access)

    functions = network.build_network_functions(dict, lambda *_args: None, [], session=session_a)

    assert functions["getSocketInfo"](0x1234) is None
    assert [(module, function) for module, function, _session in resolver_calls] == [
        ("WS2_32.dll", "getpeername"),
        ("WS2_32.dll", "getsockname"),
    ]
    assert all(session is session_a for _module, _function, session in resolver_calls)
    assert session_a.calls == []


def test_network_extension_uses_registered_session_end_to_end(monkeypatch):
    import memscope_mcp.session as session_module

    peer_data = b"\x02\x00\x01\xbb\xcb\x00\x71\x09" + b"\x00" * 20
    local_data = b"\x02\x00\xc9\x3b\x0a\x00\x00\x05" + b"\x00" * 20
    session_a = _NetworkSession({0x3000: peer_data, 0x3020: local_data})
    session_b = _HostileGlobalSession()
    resolver_calls = []
    execute_calls = []
    addresses = iter((0x1000, 0x2000))

    def fake_resolve(module_name, function_name, *, session):
        resolver_calls.append((module_name, function_name, session))
        return next(addresses)

    def fake_execute_code(address, args, *, session):
        execute_calls.append((address, args, session))
        return {"success": True, "result": "0x0"}

    monkeypatch.setattr(session_module, "SESSION", session_b)
    monkeypatch.setattr("memscope_mcp.utils.pe.resolve_export", fake_resolve)
    monkeypatch.setattr("memscope_mcp.tools.execute.execute_code", fake_execute_code)

    extension, functions, errors = _register_network_extension(session_a)

    assert extension._session is session_a
    assert not hasattr(network, "SESSION")
    assert functions["getSocketInfo"](0x1234) == {
        "remote_addr": "203.0.113.9",
        "remote_port": 443,
        "local_addr": "10.0.0.5",
        "local_port": 51515,
        "family": "IPv4",
    }
    assert resolver_calls == [
        ("WS2_32.dll", "getpeername", session_a),
        ("WS2_32.dll", "getsockname", session_a),
    ]
    assert [(address, args) for address, args, _session in execute_calls] == [
        (0x1000, [0x1234, 0x3000, 0x3040]),
        (0x2000, [0x1234, 0x3020, 0x3044]),
    ]
    assert all(session is session_a for _address, _args, session in execute_calls)
    assert session_a.calls == [
        ("allocate", session_a, 72, False),
        ("write_bytes", session_a, 0x3040, b"\x1c\x00\x00\x00"),
        ("write_bytes", session_a, 0x3044, b"\x1c\x00\x00\x00"),
        ("read_bytes", session_a, 0x3000, 28),
        ("read_bytes", session_a, 0x3020, 28),
        ("free", session_a, 0x3000),
    ]
    assert all(call[1] is session_a for call in session_a.calls)
    assert errors == []
