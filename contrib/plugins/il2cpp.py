"""IL2CPP runtime structure reader.

Reference plugin demonstrating runtime-structure helpers for Unity's IL2CPP
runtime. Useful for reverse engineering Unity-packaged binaries, malware
analysis of Unity-bundled payloads, and security research on IL2CPP apps.

Provides Lua functions for reading IL2CPP strings, arrays, lists, and dictionaries.
Activate by copying this file to the plugins/ directory.
"""

from typing import Optional

from src.plugins import PluginBase
from src.session import SESSION
from src.utils.memory_utils import is_valid_pointer


class IL2CppPlugin(PluginBase):
    """Unity IL2CPP runtime structure helpers."""

    name = "il2cpp"
    description = "Unity IL2CPP runtime structure helpers"

    instructions = """
## IL2CPP Helpers
Unity IL2CPP applications compile C# to C++. These helpers work with IL2CPP's runtime structures.

**Note:** The core `read` tool handles primitives and composite types only. Use the Lua
helpers below for IL2CPP-specific structures (strings, arrays, lists, dictionaries).

### IL2CPP String
```lua
readIL2CppString(addr)  -- UTF-16 string at object+0x14, length at +0x10
```

### IL2CPP Array
Layout: `+0x18` = length (uint64), `+0x20` = data start
```lua
local arr = readIL2CppArray(addr, "ptr", 50)  -- Read up to 50 pointer elements
-- Returns: {length=N, elements={...}}
```

### IL2CPP List<T>
Layout: `+0x10` = items array ptr, `+0x18` = count (int32)
```lua
local list = readIL2CppList(addr, 50)  -- Read up to 50 elements
-- Returns: {count=N, items={...}}
```

### IL2CPP Dictionary<K,V>
Layout: `+0x18` = entries array, `+0x20` = count
```lua
local dict = readIL2CppDict(addr, "int32", "ptr", 50)
-- Returns: {count=N, entries={{key=K, value=V}, ...}}
```

### Thread Attachment
IL2CPP API calls CRASH without thread attachment. The attachment is thread-local,
so you MUST use call_sequence to run attach + API calls in the same thread:

```lua
-- Resolve il2cpp_thread_attach and the appdomain pointer dynamically
-- (offsets vary by build; discover via pattern scan or exports).
local attach_func = getAddress("GameAssembly.dll+0x<thread_attach_offset>")
local domain = readPointer(getAddress("GameAssembly.dll+0x<domain_offset>"))

callSequence({
    {address=attach_func, args={domain}},   -- Attach this thread
    {address=api_func, args={...}}          -- Now safe to call
})
```

### Common IL2CPP Offsets
These are typical but may vary by Unity version:

| Structure | Field | Offset |
|-----------|-------|--------|
| Il2CppString | length | +0x10 |
| Il2CppString | chars | +0x14 |
| Il2CppArray | max_length | +0x18 |
| Il2CppArray | data | +0x20 |
| List<T> | _items | +0x10 |
| List<T> | _size | +0x18 |
| Dictionary | entries | +0x18 |
| Dictionary | count | +0x20 |

### Finding IL2CPP Structures
Use pattern scans to find IL2CPP runtime functions, then call them:
```lua
-- Example: Find class by name
local class_from_name = AOBScanModule("GameAssembly.dll", "48 89 5C 24 08 57 48 83 EC 20 ...")[1]
```

Scripts should discover offsets dynamically rather than hardcoding them,
as they change between Unity/IL2CPP versions.
""".strip()

    def register(self, engine) -> dict[str, callable]:
        self.table = engine.lua.table
        return {
            "readUnityString": self._read_string,
            "readIL2CppString": self._read_string,
            "readListCount": self._read_list_count,
            "readListElement": self._read_list_element,
            "readDictCount": self._read_dict_count,
            "readIL2CppArray": lambda addr, elem_type="ptr", limit=50: self._read_array(addr, elem_type, limit),
            "readIL2CppList": lambda addr, limit=50: self._read_list(addr, limit),
            "readIL2CppDict": lambda addr, key_type="int32", val_type="ptr", limit=50: self._read_dict(
                addr, key_type, val_type, limit
            ),
        }

    # =========================================================================
    # String
    # =========================================================================

    def _read_string(self, address) -> Optional[str]:
        """Read IL2CPP string (UTF-16 at addr+0x14, length at +0x10)."""
        try:
            addr = int(address)
            length = SESSION.read_int32(addr + 0x10)
            if length <= 0 or length > 4096:
                return ""
            raw = SESSION.read_bytes(addr + 0x14, length * 2)
            return raw.decode("utf-16-le", errors="replace")
        except:
            return None

    # =========================================================================
    # List
    # =========================================================================

    def _read_list_count(self, address) -> Optional[int]:
        """Read IL2CPP List<T> count (at +0x18)."""
        try:
            return SESSION.read_int32(int(address) + 0x18)
        except:
            return None

    def _read_list_element(self, address, index) -> Optional[int]:
        """Read pointer element from IL2CPP List<T>."""
        try:
            addr = int(address)
            items_ptr = SESSION.read_ptr(addr + 0x10)
            if not is_valid_pointer(items_ptr):
                return None
            elem_addr = items_ptr + 0x20 + (int(index) * 8)
            return SESSION.read_ptr(elem_addr)
        except:
            return None

    def _read_list(self, address, limit: int = 50):
        """Read IL2CPP List<T>. Layout: +0x10 = items ptr, +0x18 = count."""
        try:
            addr = int(address)
            items_ptr = SESSION.read_ptr(addr + 0x10)
            count = SESSION.read_int32(addr + 0x18)

            if not is_valid_pointer(items_ptr) or count is None or count < 0:
                return None

            data_start = items_ptr + 0x20
            items = []
            read_count = min(count, limit)

            for i in range(read_count):
                val = SESSION.read_ptr(data_start + (i * 8))
                items.append(val)

            result = self.table()
            result["count"] = count
            result["items"] = self.table(*items)
            return result
        except:
            return None

    # =========================================================================
    # Array
    # =========================================================================

    def _read_array(self, address, element_type: str = "ptr", limit: int = 50):
        """Read IL2CPP array. Layout: +0x18 = length, +0x20 = data start."""
        try:
            addr = int(address)
            length = SESSION.read_int32(addr + 0x18)
            if length is None or length < 0:
                return None

            data_start = addr + 0x20
            count = min(length, limit)

            elem_size = 8
            if element_type in ("int32", "float"):
                elem_size = 4
            elif element_type == "byte":
                elem_size = 1

            elements = []
            for i in range(count):
                elem_addr = data_start + (i * elem_size)
                if element_type in ("ptr", "pointer"):
                    val = SESSION.read_ptr(elem_addr)
                elif element_type == "int32":
                    val = SESSION.read_int32(elem_addr)
                elif element_type == "float":
                    val = SESSION.read_float(elem_addr)
                elif element_type == "byte":
                    data = SESSION.read_bytes(elem_addr, 1)
                    val = data[0] if data else None
                else:
                    val = SESSION.read_ptr(elem_addr)
                elements.append(val)

            result = self.table()
            result["length"] = length
            result["elements"] = self.table(*elements)
            return result
        except:
            return None

    # =========================================================================
    # Dictionary
    # =========================================================================

    def _read_dict_count(self, address) -> Optional[int]:
        """Read IL2CPP Dictionary count (at +0x20)."""
        try:
            return SESSION.read_int32(int(address) + 0x20)
        except:
            return None

    def _read_dict(self, address, key_type: str = "int32", value_type: str = "ptr", limit: int = 50):
        """Read IL2CPP Dictionary. Layout: +0x18 = entries, +0x20 = count."""
        try:
            addr = int(address)
            entries_ptr = SESSION.read_ptr(addr + 0x18)
            count = SESSION.read_int32(addr + 0x20)

            if not is_valid_pointer(entries_ptr) or count is None or count < 0:
                return None

            data_start = entries_ptr + 0x20
            entry_size = 24  # hashCode(4) + next(4) + key(8) + value(8)

            entries = []
            valid_count = 0

            for i in range(count + 100):
                if valid_count >= limit:
                    break

                entry_addr = data_start + (i * entry_size)
                hash_code = SESSION.read_int32(entry_addr)

                if hash_code is None or hash_code < 0:
                    continue

                key_addr = entry_addr + 8
                value_addr = entry_addr + 16

                key = self._read_typed_value(key_addr, key_type)
                value = self._read_typed_value(value_addr, value_type)

                entry = self.table()
                entry["key"] = key
                entry["value"] = value
                entries.append(entry)
                valid_count += 1

            result = self.table()
            result["count"] = count
            result["entries"] = self.table(*entries)
            return result
        except:
            return None

    def _read_typed_value(self, addr: int, type_name: str):
        """Read a value based on type name."""
        if type_name == "int32":
            return SESSION.read_int32(addr)
        elif type_name == "float":
            return SESSION.read_float(addr)
        elif type_name == "string":
            ptr = SESSION.read_ptr(addr)
            return self._read_string(ptr) if is_valid_pointer(ptr) else None
        else:
            return SESSION.read_ptr(addr)
