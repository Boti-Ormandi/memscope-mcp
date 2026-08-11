import inspect
import struct
from types import SimpleNamespace

from memscope_mcp.extensions.base import ExtensionContext

READ_HELPERS = (
    "read_byte",
    "read_bytes",
    "read_bytes_hex",
    "read_int16",
    "read_int32",
    "read_int32_safe",
    "read_int64",
    "read_uint16",
    "read_uint32",
    "read_uint64",
    "read_pointer",
    "read_pointer_raw",
    "read_float",
    "read_double",
    "read_string",
    "read_bool",
    "read_wide_string",
    "read_pointer_array",
    "read_int_array",
    "read_float_array",
)

WRITE_HELPERS = (
    "write_byte",
    "write_bytes",
    "write_int16",
    "write_int32",
    "write_int64",
    "write_pointer",
    "write_float",
    "write_double",
    "write_string",
    "write_bool",
    "write_uint16",
    "write_uint32",
    "write_uint64",
)

STRUCT_HELPERS = (
    "read_vector3",
    "read_vector4",
    "read_matrix4x4",
    "read_struct",
)


def _register_memory_extension(session, table_factory=dict):
    from memscope_mcp.extensions.core.memory import MemoryExtension

    engine = SimpleNamespace(_log_error=lambda *_args: None, _output=[])
    extension = MemoryExtension()
    functions = extension.register(
        ExtensionContext(
            engine=engine,
            session=session,
            table_factory=table_factory,
            log_error=engine._log_error,
        )
    )
    return extension, functions


def test_memory_helpers_require_keyword_only_session():
    from memscope_mcp.tools.lua import memory_read, memory_write, struct_helpers

    for module, helper_names in (
        (memory_read, READ_HELPERS),
        (memory_write, WRITE_HELPERS),
        (struct_helpers, STRUCT_HELPERS),
    ):
        for helper_name in helper_names:
            parameter = inspect.signature(getattr(module, helper_name)).parameters["session"]
            assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
            assert parameter.default is inspect.Parameter.empty


def test_memory_extension_forwards_registered_session_to_every_helper(monkeypatch):
    import memscope_mcp.extensions.core.memory as memory_extension

    calls = {}

    def spy(helper_name):
        def capture(*args, **kwargs):
            calls.setdefault(helper_name, []).append((args, kwargs))
            return helper_name

        return capture

    for helper_name in (*READ_HELPERS, *WRITE_HELPERS, *STRUCT_HELPERS):
        monkeypatch.setattr(memory_extension, helper_name, spy(helper_name))

    session = object()
    _, functions = _register_memory_extension(session)
    invocations = (
        ("readByte", "read_byte", (0x20000,)),
        ("readBytes", "read_bytes", (0x20000, 4)),
        ("readBytesHex", "read_bytes_hex", (0x20000, 4)),
        ("readSmallInteger", "read_int16", (0x20000,)),
        ("readInteger", "read_int32", (0x20000,)),
        ("readIntegerSafe", "read_int32_safe", (0x20000,)),
        ("readQword", "read_int64", (0x20000,)),
        ("readPointer", "read_pointer", (0x20000,)),
        ("readPointerRaw", "read_pointer_raw", (0x20000,)),
        ("readFloat", "read_float", (0x20000,)),
        ("readDouble", "read_double", (0x20000,)),
        ("readString", "read_string", (0x20000,)),
        ("readWideString", "read_wide_string", (0x20000,)),
        ("readBool", "read_bool", (0x20000,)),
        ("readUInt16", "read_uint16", (0x20000,)),
        ("readUInt32", "read_uint32", (0x20000,)),
        ("readUInt64", "read_uint64", (0x20000,)),
        ("readPointerArray", "read_pointer_array", (0x20000, 2)),
        ("readIntArray", "read_int_array", (0x20000, 2)),
        ("readFloatArray", "read_float_array", (0x20000, 2)),
        ("writeByte", "write_byte", (0x20000, 1)),
        ("writeBytes", "write_bytes", (0x20000, {1: 0xAA})),
        ("writeSmallInteger", "write_int16", (0x20000, 2)),
        ("writeInteger", "write_int32", (0x20000, 3)),
        ("writeQword", "write_int64", (0x20000, 4)),
        ("writePointer", "write_pointer", (0x20000, 0x30000)),
        ("writeFloat", "write_float", (0x20000, 1.5)),
        ("writeDouble", "write_double", (0x20000, 2.5)),
        ("writeString", "write_string", (0x20000, "hello")),
        ("writeBool", "write_bool", (0x20000, True)),
        ("writeUInt16", "write_uint16", (0x20000, 5)),
        ("writeUInt32", "write_uint32", (0x20000, 6)),
        ("writeUInt64", "write_uint64", (0x20000, 7)),
        ("readVector3", "read_vector3", (0x20000,)),
        ("readVector4", "read_vector4", (0x20000,)),
        ("readQuaternion", "read_vector4", (0x20000,)),
        ("readMatrix4x4", "read_matrix4x4", (0x20000,)),
        ("readStruct", "read_struct", (0x20000, {"value": "int32@0"})),
    )

    for lua_name, helper_name, args in invocations:
        call_index = len(calls.get(helper_name, ()))
        assert functions[lua_name](*args) == helper_name
        _, kwargs = calls[helper_name][call_index]
        assert set(kwargs) == {"session"}
        assert kwargs["session"] is session


class _FakeMemorySession:
    def __init__(self):
        self.calls = []

    def read_int32(self, address):
        self.calls.append(("read_int32", address))
        values = {
            0x20000: 0x12345678,
            0x23004: 77,
        }
        return values[address]

    def read_bytes(self, address, size):
        self.calls.append(("read_bytes", address, size))
        values = {
            (0x22000, 12): struct.pack("<fff", 1.5, -2.0, 3.25),
            (0x23010, 12): struct.pack("<fff", 4.0, 5.0, 6.0),
        }
        return values[(address, size)]

    def is_memory_writable(self, address):
        self.calls.append(("is_memory_writable", address))
        return address == 0x21000

    def write_int32(self, address, value):
        self.calls.append(("write_int32", address, value))


def test_memory_extension_operations_stay_on_registered_session(monkeypatch):
    from memscope_mcp.session import SESSION

    def hostile_global(*_args, **_kwargs):
        raise AssertionError("global SESSION must not be consulted")

    for method_name in ("read_int32", "read_bytes", "is_memory_writable", "write_int32"):
        monkeypatch.setattr(SESSION, method_name, hostile_global)

    session = _FakeMemorySession()
    extension, functions = _register_memory_extension(session)

    assert extension._session is session
    assert functions["readInteger"](0x20000) == 0x12345678
    assert functions["writeInteger"](0x21000, -42) is True
    assert functions["readVector3"](0x22000) == {"x": 1.5, "y": -2.0, "z": 3.25}
    assert functions["readStruct"](
        0x23000,
        {
            "count": "int32@0x4",
            "position": "vector3@0x10",
        },
    ) == {
        "count": 77,
        "position": {"x": 4.0, "y": 5.0, "z": 6.0},
    }
    assert session.calls == [
        ("read_int32", 0x20000),
        ("is_memory_writable", 0x21000),
        ("write_int32", 0x21000, -42),
        ("read_bytes", 0x22000, 12),
        ("read_int32", 0x23004),
        ("read_bytes", 0x23010, 12),
    ]
