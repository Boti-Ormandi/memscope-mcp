---
title: "MCP tool reference"
description: "Installed-wheel reference for the exact 11-tool stdio surface."
---

## Configuration

See [Configure an MCP client](/get-started/configure-client/) for a VS Code example with an explicit `MEMSCOPE_HOME` data root. The server name is `memscope-mcp`. It communicates over stdio and advertises tools and instructions; it does not expose a second transport or plugin namespace.

## Tool list

| Tool | Request shape | Purpose |
| --- | --- | --- |
| `processes` | `filter?`, `pid?`, `parent?`, `service?`, `limit?`, `offset?` | Enumerate processes, with optional service and parent filtering. Entries can include path, command line, threads, and services. |
| `attach` | `process_name`, `pid?` | Open or switch the session to a selected process and publish a module snapshot. |
| `modules` | `filter?`, `limit?`, `refresh?` | List the current snapshot; `refresh=true` publishes a new snapshot generation. |
| `read` | `address`, `type_name`, `count?` | Read primitive, special, or composite values. |
| `write` | `address`, `value`, `type_name`, `verify?` | Write typed data or bytes. `verify=true` performs writable-range validation, pre-image capture, readback, and a restore attempt after a verification failure. |
| `dump` | `address`, `size?`, `pointers_only?`, `start_offset?`, `non_null_only?`, `max_entries?`, `annotation_level?` | Inspect a bounded 4096-byte window with pointer heuristics and pagination metadata. |
| `chain` | `base`, `offsets`, `read_final?` | Follow `[[base+offset0]+offset1]...` and format the final value. |
| `scan` | start request or cursor continuation | Run one strict AOB scan in `addresses`, `first`, or `count` mode. |
| `scan_many` | `patterns`, `scope?`, `mode?`, `max_matches?`, `timeout_ms?`, `diagnostics?` | Run 1–32 keyed AOB patterns in one shared traversal; mode is `first` or `count`. |
| `lua` | `script`, `timeout?` | Execute composed Lua with loops, dependent reads, native calls, and registered extension/plugin functions. |
| `scripts` | `action`, `name?`, `process?`, `args?`, `timeout?` | List or run saved Lua scripts. File tools create and edit scripts. |

The server does not add a separate MCP tool for plugins. A plugin registers Lua functions into the existing `lua` tool.

## Read-first examples

```text
processes(filter="target", limit=20)
attach(process_name="Target.exe", pid=1234)
modules(refresh=false, limit=50)
read(address="Target.exe+0x1000", type_name="bytes", count=2)
```

`read`, `dump`, `chain`, and `scan` require an attached process. `processes` and PEB-related Lua helpers can work before attachment.

## Scan boundary

`scan` rejects unknown fields, accepts either `pattern` or `cursor`, and uses strict request models. A start request can include a structured `scope`, `mode`, `limit`, `max_matches`, `timeout_ms`, and `diagnostics`. A continuation request contains a `cursor` plus only `limit`, `timeout_ms`, and `diagnostics`. See [Scanning reference](/reference/scanning/).

`scan_many` accepts 1–32 unique `{key, pattern}` entries, strict module/range scopes, `first` or `count`, and one shared traversal status. It intentionally has no address pagination.

## Result shape

Ordinary tools return dictionaries with `success=true` or `success=false`, an error code, and a bounded `detail` when an operation fails. The strict scan boundary returns a validated flat failure envelope:

```json
{
  "success": false,
  "error": "INVALID_ARGUMENT",
  "detail": "Unknown scan argument 'offset'",
  "field": "offset"
}
```

The `write` result distinguishes `MEMORY_NOT_WRITABLE`, `WRITE_ERROR`, `VERIFY_READ_FAILED`, and `VERIFY_MISMATCH` when verification is enabled. See [Errors and status](/reference/errors-and-status/).

## Lua and scripts

Use `lua` for composed operations:

```lua
local base = getModuleBase("Target.exe")
if base then
    addResult("signature", readBytesHex(base, 2))
end
```

Use `scripts(action="list")` to obtain absolute script paths. Use file tools to create or edit a `.lua` file, then run it with `scripts(action="run", name="finder")`. A `process` argument selects the saved-script namespace; it does not attach or switch targets.

The full function contract is in the [Lua reference](/reference/lua/).

Server: Memscope MCP

## processes

List running processes with smart filtering&#46; Returns array of &#123;pid&#44; name&#44; path&#44; parent&#95;pid&#44; threads&#44; command&#95;line&#44; services&#91;&#93;&#125;&#46; Services are auto&#45;included for svchost processes&#46; Filters &#40;combine as needed&#41;&#58; filter &#45; Substring match on process name pid &#45; Exact PID lookup &#40;returns single process&#41; parent &#45; Only processes with this parent PID service &#45; Only processes hosting this service &#40;e&#46;g&#46;&#44; &#34;EventLog&#34;&#41; Examples&#58; processes&#40;service&#61;&#34;EventLog&#34;&#41; &#45; Find which svchost hosts EventLog processes&#40;filter&#61;&#34;svchost&#34;&#41; &#45; All svchosts with their services processes&#40;pid&#61;1820&#41; &#45; Details for specific PID processes&#40;parent&#61;700&#41; &#45; Children of services&#46;exe

### Input JSON schema

```json
{
  "properties": {
    "filter": {
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "title": "Filter"
    },
    "pid": {
      "anyOf": [
        {
          "type": "integer"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "title": "Pid"
    },
    "parent": {
      "anyOf": [
        {
          "type": "integer"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "title": "Parent"
    },
    "service": {
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "title": "Service"
    },
    "limit": {
      "default": 100,
      "title": "Limit",
      "type": "integer"
    },
    "offset": {
      "default": 0,
      "title": "Offset",
      "type": "integer"
    }
  },
  "title": "processesArguments",
  "type": "object"
}
```

## attach

Attach to process and cache module bases&#46; Returns pid&#44; key&#95;modules &#40;base&#47;size&#41;&#44; saved&#95;scripts list&#44; scripts&#95;dir&#44; and log&#95;file path&#46; Use pid parameter when multiple processes share the same name &#40;e&#46;g&#46;&#44; svchost&#46;exe&#41;&#46; Use processes&#40;&#41; tool first to find the right PID&#46; Examples&#58; attach&#40;&#34;Game&#46;exe&#34;&#41; or attach&#40;&#34;svchost&#46;exe&#34;&#44; pid&#61;1820&#41;

### Input JSON schema

```json
{
  "properties": {
    "process_name": {
      "title": "Process Name",
      "type": "string"
    },
    "pid": {
      "anyOf": [
        {
          "type": "integer"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "title": "Pid"
    }
  },
  "required": [
    "process_name"
  ],
  "title": "attachArguments",
  "type": "object"
}
```

## modules

List loaded modules with base addresses&#44; sizes&#44; and paths&#46; Set refresh to rebuild the module snapshot and advance its generation&#46;

### Input JSON schema

```json
{
  "properties": {
    "filter": {
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "title": "Filter"
    },
    "limit": {
      "default": 30,
      "title": "Limit",
      "type": "integer"
    },
    "refresh": {
      "default": false,
      "title": "Refresh",
      "type": "boolean"
    }
  },
  "title": "modulesArguments",
  "type": "object"
}
```

## read

Read typed data from memory&#46; Primitive types&#58; int8&#47;sbyte&#44; uint8&#47;byte&#44; int16&#47;short&#44; uint16&#47;ushort&#44; char&#44; int32&#47;int&#44; uint32&#47;uint&#44; int64&#47;long&#44; uint64&#47;ulong&#44; float&#47;single&#44; double&#44; bool&#47;boolean&#44; ptr&#47;pointer&#47;intptr&#46; Special types&#58; cstring&#44; bytes&#44; bytes&#91;N&#93;&#46; Composite types&#58; vector2&#47;3&#47;4&#44; quaternion&#44; color&#44; color32&#44; rect&#44; bounds&#44; matrix4x4&#46; Use count &#62; 1 for consecutive values&#59; count controls length for bytes&#46; Returns value or values array&#46;

### Input JSON schema

```json
{
  "properties": {
    "address": {
      "title": "Address",
      "type": "string"
    },
    "type_name": {
      "title": "Type Name",
      "type": "string"
    },
    "count": {
      "default": 1,
      "title": "Count",
      "type": "integer"
    }
  },
  "required": [
    "address",
    "type_name"
  ],
  "title": "readArguments",
  "type": "object"
}
```

## write

Write typed data to memory&#46; Types&#58; primitives&#44; composite types &#40;vector3 as &#123;x&#44;y&#44;z&#125; dict&#41;&#44; bytes&#44; and bytes&#91;N&#93;&#46; Bytes values accept compact hex &#40;&#34;DEADBEEF&#34;&#41;&#44; spaced hex &#40;&#34;DE AD BE EF&#34;&#41;&#44; or &#91;222&#44; 173&#44; 190&#44; 239&#93;&#46; bytes&#91;N&#93; requires exactly N bytes&#46; Set verify&#61;True to require a writable range check&#44; pre&#45;image capture&#44; byte&#45;for&#45;byte readback&#44; and a pre&#45;image restore attempt on post&#45;write verification failure&#46;

### Input JSON schema

```json
{
  "properties": {
    "address": {
      "title": "Address",
      "type": "string"
    },
    "value": {
      "title": "value",
      "type": "string"
    },
    "type_name": {
      "title": "Type Name",
      "type": "string"
    },
    "verify": {
      "default": false,
      "title": "Verify",
      "type": "boolean"
    }
  },
  "required": [
    "address",
    "value",
    "type_name"
  ],
  "title": "writeArguments",
  "type": "object"
}
```

## dump

Smart memory dump with auto pointer detection&#46; For exploring unknown structures&#46; size is clamped to the remaining 4096&#45;byte window&#46; start&#95;offset selects a byte offset within that window&#46; annotation&#95;level&#58; minimal&#44; normal&#44; or full&#46; Returns annotated entries showing likely pointers and values&#46;

### Input JSON schema

```json
{
  "properties": {
    "address": {
      "title": "Address",
      "type": "string"
    },
    "size": {
      "default": 256,
      "title": "Size",
      "type": "integer"
    },
    "pointers_only": {
      "default": false,
      "title": "Pointers Only",
      "type": "boolean"
    },
    "start_offset": {
      "default": 0,
      "title": "Start Offset",
      "type": "integer"
    },
    "non_null_only": {
      "default": false,
      "title": "Non Null Only",
      "type": "boolean"
    },
    "max_entries": {
      "default": 100,
      "title": "Max Entries",
      "type": "integer"
    },
    "annotation_level": {
      "default": "normal",
      "title": "Annotation Level",
      "type": "string"
    }
  },
  "required": [
    "address"
  ],
  "title": "dumpArguments",
  "type": "object"
}
```

## chain

Follow pointer chain with standard RE semantics&#58; add offset&#44; then read&#46; &#91;&#91;base&#43;off0&#93;&#43;off1&#93;&#46;&#46;&#46; Offsets accept hex&#58; &#91;&#34;0x148&#34;&#44; &#34;0x10&#34;&#93;&#46; Returns chain steps&#44; final&#95;address&#44; and final&#95;value&#46;

### Input JSON schema

```json
{
  "properties": {
    "base": {
      "title": "Base",
      "type": "string"
    },
    "offsets": {
      "items": {
        "anyOf": [
          {
            "type": "integer"
          },
          {
            "type": "string"
          }
        ]
      },
      "title": "Offsets",
      "type": "array"
    },
    "read_final": {
      "default": "ptr",
      "title": "Read Final",
      "type": "string"
    }
  },
  "required": [
    "base",
    "offsets"
  ],
  "title": "chainArguments",
  "type": "object"
}
```

## scan

Scan target memory with strict AOB patterns&#46; Supports address pages with authenticated cursor continuation&#44; first&#45;hit mode&#44; count mode&#44; structured scopes&#44; planner filters&#44; and bounded diagnostics&#46;

### Input JSON schema

```json
{
  "$defs": {
    "AllModulesScopeInput": {
      "additionalProperties": false,
      "properties": {
        "kind": {
          "const": "all_modules",
          "title": "Kind",
          "type": "string"
        },
        "filters": {
          "$ref": "#/$defs/ScanFiltersInput"
        }
      },
      "required": [
        "kind"
      ],
      "title": "AllModulesScopeInput",
      "type": "object"
    },
    "ModulesScopeInput": {
      "additionalProperties": false,
      "properties": {
        "kind": {
          "const": "modules",
          "title": "Kind",
          "type": "string"
        },
        "names": {
          "items": {
            "minLength": 1,
            "type": "string"
          },
          "maxItems": 64,
          "minItems": 1,
          "title": "Names",
          "type": "array"
        },
        "filters": {
          "$ref": "#/$defs/ScanFiltersInput"
        }
      },
      "required": [
        "kind",
        "names"
      ],
      "title": "ModulesScopeInput",
      "type": "object"
    },
    "RangeScopeInput": {
      "additionalProperties": false,
      "properties": {
        "kind": {
          "const": "range",
          "title": "Kind",
          "type": "string"
        },
        "start": {
          "anyOf": [
            {
              "type": "integer"
            },
            {
              "type": "string"
            }
          ],
          "title": "Start"
        },
        "end_exclusive": {
          "anyOf": [
            {
              "type": "integer"
            },
            {
              "type": "string"
            }
          ],
          "title": "End Exclusive"
        },
        "filters": {
          "$ref": "#/$defs/ScanFiltersInput"
        }
      },
      "required": [
        "kind",
        "start",
        "end_exclusive"
      ],
      "title": "RangeScopeInput",
      "type": "object"
    },
    "ScanFiltersInput": {
      "additionalProperties": false,
      "properties": {
        "memory_types": {
          "anyOf": [
            {
              "items": {
                "enum": [
                  "image",
                  "mapped",
                  "private"
                ],
                "type": "string"
              },
              "maxItems": 3,
              "minItems": 1,
              "type": "array"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "title": "Memory Types"
        },
        "executable": {
          "default": "any",
          "enum": [
            "any",
            "required",
            "forbidden"
          ],
          "title": "Executable",
          "type": "string"
        },
        "writable": {
          "default": "any",
          "enum": [
            "any",
            "required",
            "forbidden"
          ],
          "title": "Writable",
          "type": "string"
        },
        "sections": {
          "anyOf": [
            {
              "items": {
                "minLength": 1,
                "type": "string"
              },
              "maxItems": 64,
              "minItems": 1,
              "type": "array"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "title": "Sections"
        }
      },
      "title": "ScanFiltersInput",
      "type": "object"
    }
  },
  "additionalProperties": false,
  "description": "Flat start-or-continuation request accepted by the strict MCP adapter.",
  "oneOf": [
    {
      "not": {
        "required": [
          "cursor"
        ]
      },
      "required": [
        "pattern"
      ]
    },
    {
      "not": {
        "anyOf": [
          {
            "required": [
              "pattern"
            ]
          },
          {
            "required": [
              "scope"
            ]
          },
          {
            "required": [
              "mode"
            ]
          },
          {
            "required": [
              "max_matches"
            ]
          }
        ]
      },
      "required": [
        "cursor"
      ]
    }
  ],
  "properties": {
    "pattern": {
      "anyOf": [
        {
          "maxLength": 4096,
          "minLength": 1,
          "type": "string"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "title": "Pattern"
    },
    "scope": {
      "anyOf": [
        {
          "discriminator": {
            "mapping": {
              "all_modules": "#/$defs/AllModulesScopeInput",
              "modules": "#/$defs/ModulesScopeInput",
              "range": "#/$defs/RangeScopeInput"
            },
            "propertyName": "kind"
          },
          "oneOf": [
            {
              "$ref": "#/$defs/AllModulesScopeInput"
            },
            {
              "$ref": "#/$defs/ModulesScopeInput"
            },
            {
              "$ref": "#/$defs/RangeScopeInput"
            }
          ]
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "title": "Scope"
    },
    "mode": {
      "default": "addresses",
      "enum": [
        "addresses",
        "first",
        "count"
      ],
      "title": "Mode",
      "type": "string"
    },
    "limit": {
      "anyOf": [
        {
          "maximum": 500,
          "minimum": 1,
          "type": "integer"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "title": "Limit"
    },
    "max_matches": {
      "anyOf": [
        {
          "maximum": 100000,
          "minimum": 1,
          "type": "integer"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "title": "Max Matches"
    },
    "timeout_ms": {
      "default": 30000,
      "maximum": 30000,
      "minimum": 100,
      "title": "Timeout Ms",
      "type": "integer"
    },
    "diagnostics": {
      "default": false,
      "title": "Diagnostics",
      "type": "boolean"
    },
    "cursor": {
      "anyOf": [
        {
          "minLength": 1,
          "type": "string"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "title": "Cursor"
    }
  },
  "title": "ScanInput",
  "type": "object"
}
```

### Output JSON schema

```json
{
  "$defs": {
    "AddressScanSuccess": {
      "additionalProperties": false,
      "properties": {
        "success": {
          "const": true,
          "title": "Success",
          "type": "boolean"
        },
        "mode": {
          "const": "addresses",
          "title": "Mode",
          "type": "string"
        },
        "matches": {
          "items": {
            "$ref": "#/$defs/ScanHit"
          },
          "maxItems": 500,
          "title": "Matches",
          "type": "array"
        },
        "returned_count": {
          "anyOf": [
            {
              "maximum": 500,
              "minimum": 1,
              "type": "integer"
            },
            {
              "const": 0,
              "type": "integer"
            }
          ],
          "title": "Returned Count"
        },
        "sequence_returned_count": {
          "maximum": 100000,
          "minimum": 0,
          "title": "Sequence Returned Count",
          "type": "integer"
        },
        "next_cursor": {
          "anyOf": [
            {
              "minLength": 1,
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "title": "Next Cursor"
        },
        "status": {
          "$ref": "#/$defs/ScanStatus"
        },
        "diagnostics": {
          "anyOf": [
            {
              "$ref": "#/$defs/ScanDiagnostics"
            },
            {
              "type": "null"
            }
          ],
          "default": null
        }
      },
      "required": [
        "success",
        "mode",
        "matches",
        "returned_count",
        "sequence_returned_count",
        "next_cursor",
        "status"
      ],
      "title": "AddressScanSuccess",
      "type": "object"
    },
    "CountScanSuccess": {
      "additionalProperties": false,
      "properties": {
        "success": {
          "const": true,
          "title": "Success",
          "type": "boolean"
        },
        "mode": {
          "const": "count",
          "title": "Mode",
          "type": "string"
        },
        "count": {
          "anyOf": [
            {
              "maximum": 100000,
              "minimum": 1,
              "type": "integer"
            },
            {
              "const": 0,
              "type": "integer"
            }
          ],
          "title": "Count"
        },
        "observation": {
          "enum": [
            "complete_traversal",
            "partial_traversal"
          ],
          "title": "Observation",
          "type": "string"
        },
        "status": {
          "$ref": "#/$defs/ScanStatus"
        },
        "diagnostics": {
          "anyOf": [
            {
              "$ref": "#/$defs/ScanDiagnostics"
            },
            {
              "type": "null"
            }
          ],
          "default": null
        }
      },
      "required": [
        "success",
        "mode",
        "count",
        "observation",
        "status"
      ],
      "title": "CountScanSuccess",
      "type": "object"
    },
    "FirstScanSuccess": {
      "additionalProperties": false,
      "properties": {
        "success": {
          "const": true,
          "title": "Success",
          "type": "boolean"
        },
        "mode": {
          "const": "first",
          "title": "Mode",
          "type": "string"
        },
        "match": {
          "anyOf": [
            {
              "$ref": "#/$defs/ScanHit"
            },
            {
              "type": "null"
            }
          ]
        },
        "status": {
          "$ref": "#/$defs/ScanStatus"
        },
        "diagnostics": {
          "anyOf": [
            {
              "$ref": "#/$defs/ScanDiagnostics"
            },
            {
              "type": "null"
            }
          ],
          "default": null
        }
      },
      "required": [
        "success",
        "mode",
        "match",
        "status"
      ],
      "title": "FirstScanSuccess",
      "type": "object"
    },
    "ScanDiagnostics": {
      "additionalProperties": false,
      "properties": {
        "duration_ms": {
          "minimum": 0,
          "title": "Duration Ms",
          "type": "number"
        },
        "scope_fingerprint": {
          "pattern": "^[0-9a-f]{64}$",
          "title": "Scope Fingerprint",
          "type": "string"
        },
        "sections": {
          "items": {
            "type": "string"
          },
          "maxItems": 64,
          "title": "Sections",
          "type": "array"
        },
        "strategy_counts": {
          "additionalProperties": {
            "minimum": 0,
            "type": "integer"
          },
          "maxProperties": 4,
          "propertyNames": {
            "enum": [
              "exact",
              "all_wildcard",
              "anchor",
              "regex"
            ]
          },
          "title": "Strategy Counts",
          "type": "object"
        },
        "unique_bytes_examined": {
          "minimum": 0,
          "title": "Unique Bytes Examined",
          "type": "integer"
        },
        "physical_read_calls": {
          "minimum": 0,
          "title": "Physical Read Calls",
          "type": "integer"
        },
        "physical_bytes_read": {
          "minimum": 0,
          "title": "Physical Bytes Read",
          "type": "integer"
        },
        "physical_cursor_prefix_bytes": {
          "minimum": 0,
          "title": "Physical Cursor Prefix Bytes",
          "type": "integer"
        },
        "region_count": {
          "minimum": 0,
          "title": "Region Count",
          "type": "integer"
        },
        "span_count": {
          "minimum": 0,
          "title": "Span Count",
          "type": "integer"
        },
        "candidate_count": {
          "minimum": 0,
          "title": "Candidate Count",
          "type": "integer"
        },
        "verification_count": {
          "minimum": 0,
          "title": "Verification Count",
          "type": "integer"
        },
        "control_polls": {
          "minimum": 0,
          "title": "Control Polls",
          "type": "integer"
        }
      },
      "required": [
        "duration_ms",
        "scope_fingerprint",
        "sections",
        "strategy_counts",
        "unique_bytes_examined",
        "physical_read_calls",
        "physical_bytes_read",
        "physical_cursor_prefix_bytes",
        "region_count",
        "span_count",
        "candidate_count",
        "verification_count",
        "control_polls"
      ],
      "title": "ScanDiagnostics",
      "type": "object"
    },
    "ScanFailure": {
      "additionalProperties": false,
      "properties": {
        "success": {
          "const": false,
          "default": false,
          "title": "Success",
          "type": "boolean"
        },
        "error": {
          "enum": [
            "INVALID_PATTERN",
            "INVALID_SCOPE",
            "INVALID_MODE",
            "INVALID_ARGUMENT",
            "MODULE_NOT_FOUND",
            "AMBIGUOUS_MODULE",
            "SECTION_NOT_FOUND",
            "PROCESS_NOT_ATTACHED",
            "INVALID_CURSOR",
            "CURSOR_STALE",
            "TARGET_CHANGED",
            "INTERNAL_SCAN_ERROR"
          ],
          "title": "Error",
          "type": "string"
        },
        "detail": {
          "maxLength": 1024,
          "minLength": 1,
          "title": "Detail",
          "type": "string"
        },
        "field": {
          "anyOf": [
            {
              "maxLength": 256,
              "minLength": 1,
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "title": "Field"
        },
        "hint": {
          "anyOf": [
            {
              "maxLength": 512,
              "minLength": 1,
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "title": "Hint"
        }
      },
      "required": [
        "error",
        "detail"
      ],
      "title": "ScanFailure",
      "type": "object"
    },
    "ScanHit": {
      "additionalProperties": false,
      "properties": {
        "address": {
          "pattern": "^0x(?:0|[1-9A-F][0-9A-F]*)$",
          "title": "Address",
          "type": "string"
        },
        "module": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "title": "Module"
        },
        "module_offset": {
          "anyOf": [
            {
              "pattern": "^0x(?:0|[1-9A-F][0-9A-F]*)$",
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "title": "Module Offset"
        }
      },
      "required": [
        "address",
        "module",
        "module_offset"
      ],
      "title": "ScanHit",
      "type": "object"
    },
    "ScanStatus": {
      "additionalProperties": false,
      "properties": {
        "termination": {
          "enum": [
            "scope_exhausted",
            "page_limit",
            "match_limit",
            "first_hit",
            "timeout",
            "cancelled",
            "target_changed",
            "reader_error"
          ],
          "title": "Termination",
          "type": "string"
        },
        "read_gaps_detected": {
          "title": "Read Gaps Detected",
          "type": "boolean"
        }
      },
      "required": [
        "termination",
        "read_gaps_detected"
      ],
      "title": "ScanStatus",
      "type": "object"
    }
  },
  "anyOf": [
    {
      "discriminator": {
        "mapping": {
          "addresses": "#/$defs/AddressScanSuccess",
          "count": "#/$defs/CountScanSuccess",
          "first": "#/$defs/FirstScanSuccess"
        },
        "propertyName": "mode"
      },
      "oneOf": [
        {
          "$ref": "#/$defs/AddressScanSuccess"
        },
        {
          "$ref": "#/$defs/FirstScanSuccess"
        },
        {
          "$ref": "#/$defs/CountScanSuccess"
        }
      ]
    },
    {
      "$ref": "#/$defs/ScanFailure"
    }
  ],
  "title": "ScanResponse",
  "type": "object"
}
```

## scan&#95;many

Scan 1&#45;32 keyed AOB patterns in one shared target&#45;memory traversal&#46; Supports only bounded first&#45;hit and count modes&#44; structured scopes&#44; PE&#45;section filters&#44; and shared diagnostics&#46;

### Input JSON schema

```json
{
  "$defs": {
    "AllModulesScopeInput": {
      "additionalProperties": false,
      "properties": {
        "kind": {
          "const": "all_modules",
          "title": "Kind",
          "type": "string"
        },
        "filters": {
          "$ref": "#/$defs/ScanFiltersInput"
        }
      },
      "required": [
        "kind"
      ],
      "title": "AllModulesScopeInput",
      "type": "object"
    },
    "ModulesScopeInput": {
      "additionalProperties": false,
      "properties": {
        "kind": {
          "const": "modules",
          "title": "Kind",
          "type": "string"
        },
        "names": {
          "items": {
            "minLength": 1,
            "type": "string"
          },
          "maxItems": 64,
          "minItems": 1,
          "title": "Names",
          "type": "array"
        },
        "filters": {
          "$ref": "#/$defs/ScanFiltersInput"
        }
      },
      "required": [
        "kind",
        "names"
      ],
      "title": "ModulesScopeInput",
      "type": "object"
    },
    "NamedPatternInput": {
      "additionalProperties": false,
      "description": "One caller-keyed AOB pattern in a bounded batch request.",
      "properties": {
        "key": {
          "minLength": 1,
          "title": "Key",
          "type": "string"
        },
        "pattern": {
          "maxLength": 4096,
          "minLength": 1,
          "title": "Pattern",
          "type": "string"
        }
      },
      "required": [
        "key",
        "pattern"
      ],
      "title": "NamedPatternInput",
      "type": "object"
    },
    "RangeScopeInput": {
      "additionalProperties": false,
      "properties": {
        "kind": {
          "const": "range",
          "title": "Kind",
          "type": "string"
        },
        "start": {
          "anyOf": [
            {
              "type": "integer"
            },
            {
              "type": "string"
            }
          ],
          "title": "Start"
        },
        "end_exclusive": {
          "anyOf": [
            {
              "type": "integer"
            },
            {
              "type": "string"
            }
          ],
          "title": "End Exclusive"
        },
        "filters": {
          "$ref": "#/$defs/ScanFiltersInput"
        }
      },
      "required": [
        "kind",
        "start",
        "end_exclusive"
      ],
      "title": "RangeScopeInput",
      "type": "object"
    },
    "ScanFiltersInput": {
      "additionalProperties": false,
      "properties": {
        "memory_types": {
          "anyOf": [
            {
              "items": {
                "enum": [
                  "image",
                  "mapped",
                  "private"
                ],
                "type": "string"
              },
              "maxItems": 3,
              "minItems": 1,
              "type": "array"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "title": "Memory Types"
        },
        "executable": {
          "default": "any",
          "enum": [
            "any",
            "required",
            "forbidden"
          ],
          "title": "Executable",
          "type": "string"
        },
        "writable": {
          "default": "any",
          "enum": [
            "any",
            "required",
            "forbidden"
          ],
          "title": "Writable",
          "type": "string"
        },
        "sections": {
          "anyOf": [
            {
              "items": {
                "minLength": 1,
                "type": "string"
              },
              "maxItems": 64,
              "minItems": 1,
              "type": "array"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "title": "Sections"
        }
      },
      "title": "ScanFiltersInput",
      "type": "object"
    }
  },
  "additionalProperties": false,
  "description": "Bounded first-hit or count batch over one shared scan traversal.",
  "properties": {
    "patterns": {
      "items": {
        "$ref": "#/$defs/NamedPatternInput"
      },
      "maxItems": 32,
      "minItems": 1,
      "title": "Patterns",
      "type": "array"
    },
    "scope": {
      "anyOf": [
        {
          "discriminator": {
            "mapping": {
              "all_modules": "#/$defs/AllModulesScopeInput",
              "modules": "#/$defs/ModulesScopeInput",
              "range": "#/$defs/RangeScopeInput"
            },
            "propertyName": "kind"
          },
          "oneOf": [
            {
              "$ref": "#/$defs/AllModulesScopeInput"
            },
            {
              "$ref": "#/$defs/ModulesScopeInput"
            },
            {
              "$ref": "#/$defs/RangeScopeInput"
            }
          ]
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "title": "Scope"
    },
    "mode": {
      "default": "first",
      "enum": [
        "first",
        "count"
      ],
      "title": "Mode",
      "type": "string"
    },
    "max_matches": {
      "anyOf": [
        {
          "maximum": 100000,
          "minimum": 1,
          "type": "integer"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "title": "Max Matches"
    },
    "timeout_ms": {
      "default": 30000,
      "maximum": 30000,
      "minimum": 100,
      "title": "Timeout Ms",
      "type": "integer"
    },
    "diagnostics": {
      "default": false,
      "title": "Diagnostics",
      "type": "boolean"
    }
  },
  "required": [
    "patterns"
  ],
  "title": "ScanManyInput",
  "type": "object"
}
```

### Output JSON schema

```json
{
  "$defs": {
    "CountScanManyItem": {
      "additionalProperties": false,
      "properties": {
        "key": {
          "minLength": 1,
          "title": "Key",
          "type": "string"
        },
        "count": {
          "anyOf": [
            {
              "maximum": 100000,
              "minimum": 1,
              "type": "integer"
            },
            {
              "const": 0,
              "type": "integer"
            }
          ],
          "title": "Count"
        },
        "observation": {
          "enum": [
            "complete_traversal",
            "partial_traversal"
          ],
          "title": "Observation",
          "type": "string"
        },
        "status": {
          "$ref": "#/$defs/ScanStatus"
        }
      },
      "required": [
        "key",
        "count",
        "observation",
        "status"
      ],
      "title": "CountScanManyItem",
      "type": "object"
    },
    "CountScanManySuccess": {
      "additionalProperties": false,
      "properties": {
        "success": {
          "const": true,
          "title": "Success",
          "type": "boolean"
        },
        "mode": {
          "const": "count",
          "title": "Mode",
          "type": "string"
        },
        "results": {
          "items": {
            "$ref": "#/$defs/CountScanManyItem"
          },
          "maxItems": 32,
          "minItems": 1,
          "title": "Results",
          "type": "array"
        },
        "shared": {
          "$ref": "#/$defs/ScanManyShared"
        }
      },
      "required": [
        "success",
        "mode",
        "results",
        "shared"
      ],
      "title": "CountScanManySuccess",
      "type": "object"
    },
    "FirstScanManyItem": {
      "additionalProperties": false,
      "properties": {
        "key": {
          "minLength": 1,
          "title": "Key",
          "type": "string"
        },
        "match": {
          "anyOf": [
            {
              "$ref": "#/$defs/ScanHit"
            },
            {
              "type": "null"
            }
          ]
        },
        "status": {
          "$ref": "#/$defs/ScanStatus"
        }
      },
      "required": [
        "key",
        "match",
        "status"
      ],
      "title": "FirstScanManyItem",
      "type": "object"
    },
    "FirstScanManySuccess": {
      "additionalProperties": false,
      "properties": {
        "success": {
          "const": true,
          "title": "Success",
          "type": "boolean"
        },
        "mode": {
          "const": "first",
          "title": "Mode",
          "type": "string"
        },
        "results": {
          "items": {
            "$ref": "#/$defs/FirstScanManyItem"
          },
          "maxItems": 32,
          "minItems": 1,
          "title": "Results",
          "type": "array"
        },
        "shared": {
          "$ref": "#/$defs/ScanManyShared"
        }
      },
      "required": [
        "success",
        "mode",
        "results",
        "shared"
      ],
      "title": "FirstScanManySuccess",
      "type": "object"
    },
    "ScanDiagnostics": {
      "additionalProperties": false,
      "properties": {
        "duration_ms": {
          "minimum": 0,
          "title": "Duration Ms",
          "type": "number"
        },
        "scope_fingerprint": {
          "pattern": "^[0-9a-f]{64}$",
          "title": "Scope Fingerprint",
          "type": "string"
        },
        "sections": {
          "items": {
            "type": "string"
          },
          "maxItems": 64,
          "title": "Sections",
          "type": "array"
        },
        "strategy_counts": {
          "additionalProperties": {
            "minimum": 0,
            "type": "integer"
          },
          "maxProperties": 4,
          "propertyNames": {
            "enum": [
              "exact",
              "all_wildcard",
              "anchor",
              "regex"
            ]
          },
          "title": "Strategy Counts",
          "type": "object"
        },
        "unique_bytes_examined": {
          "minimum": 0,
          "title": "Unique Bytes Examined",
          "type": "integer"
        },
        "physical_read_calls": {
          "minimum": 0,
          "title": "Physical Read Calls",
          "type": "integer"
        },
        "physical_bytes_read": {
          "minimum": 0,
          "title": "Physical Bytes Read",
          "type": "integer"
        },
        "physical_cursor_prefix_bytes": {
          "minimum": 0,
          "title": "Physical Cursor Prefix Bytes",
          "type": "integer"
        },
        "region_count": {
          "minimum": 0,
          "title": "Region Count",
          "type": "integer"
        },
        "span_count": {
          "minimum": 0,
          "title": "Span Count",
          "type": "integer"
        },
        "candidate_count": {
          "minimum": 0,
          "title": "Candidate Count",
          "type": "integer"
        },
        "verification_count": {
          "minimum": 0,
          "title": "Verification Count",
          "type": "integer"
        },
        "control_polls": {
          "minimum": 0,
          "title": "Control Polls",
          "type": "integer"
        }
      },
      "required": [
        "duration_ms",
        "scope_fingerprint",
        "sections",
        "strategy_counts",
        "unique_bytes_examined",
        "physical_read_calls",
        "physical_bytes_read",
        "physical_cursor_prefix_bytes",
        "region_count",
        "span_count",
        "candidate_count",
        "verification_count",
        "control_polls"
      ],
      "title": "ScanDiagnostics",
      "type": "object"
    },
    "ScanFailure": {
      "additionalProperties": false,
      "properties": {
        "success": {
          "const": false,
          "default": false,
          "title": "Success",
          "type": "boolean"
        },
        "error": {
          "enum": [
            "INVALID_PATTERN",
            "INVALID_SCOPE",
            "INVALID_MODE",
            "INVALID_ARGUMENT",
            "MODULE_NOT_FOUND",
            "AMBIGUOUS_MODULE",
            "SECTION_NOT_FOUND",
            "PROCESS_NOT_ATTACHED",
            "INVALID_CURSOR",
            "CURSOR_STALE",
            "TARGET_CHANGED",
            "INTERNAL_SCAN_ERROR"
          ],
          "title": "Error",
          "type": "string"
        },
        "detail": {
          "maxLength": 1024,
          "minLength": 1,
          "title": "Detail",
          "type": "string"
        },
        "field": {
          "anyOf": [
            {
              "maxLength": 256,
              "minLength": 1,
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "title": "Field"
        },
        "hint": {
          "anyOf": [
            {
              "maxLength": 512,
              "minLength": 1,
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "title": "Hint"
        }
      },
      "required": [
        "error",
        "detail"
      ],
      "title": "ScanFailure",
      "type": "object"
    },
    "ScanHit": {
      "additionalProperties": false,
      "properties": {
        "address": {
          "pattern": "^0x(?:0|[1-9A-F][0-9A-F]*)$",
          "title": "Address",
          "type": "string"
        },
        "module": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "title": "Module"
        },
        "module_offset": {
          "anyOf": [
            {
              "pattern": "^0x(?:0|[1-9A-F][0-9A-F]*)$",
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "title": "Module Offset"
        }
      },
      "required": [
        "address",
        "module",
        "module_offset"
      ],
      "title": "ScanHit",
      "type": "object"
    },
    "ScanManyShared": {
      "additionalProperties": false,
      "properties": {
        "termination": {
          "enum": [
            "scope_exhausted",
            "page_limit",
            "match_limit",
            "first_hit",
            "timeout",
            "cancelled",
            "target_changed",
            "reader_error"
          ],
          "title": "Termination",
          "type": "string"
        },
        "read_gaps_detected": {
          "title": "Read Gaps Detected",
          "type": "boolean"
        },
        "diagnostics": {
          "anyOf": [
            {
              "$ref": "#/$defs/ScanDiagnostics"
            },
            {
              "type": "null"
            }
          ],
          "default": null
        }
      },
      "required": [
        "termination",
        "read_gaps_detected"
      ],
      "title": "ScanManyShared",
      "type": "object"
    },
    "ScanStatus": {
      "additionalProperties": false,
      "properties": {
        "termination": {
          "enum": [
            "scope_exhausted",
            "page_limit",
            "match_limit",
            "first_hit",
            "timeout",
            "cancelled",
            "target_changed",
            "reader_error"
          ],
          "title": "Termination",
          "type": "string"
        },
        "read_gaps_detected": {
          "title": "Read Gaps Detected",
          "type": "boolean"
        }
      },
      "required": [
        "termination",
        "read_gaps_detected"
      ],
      "title": "ScanStatus",
      "type": "object"
    }
  },
  "anyOf": [
    {
      "discriminator": {
        "mapping": {
          "count": "#/$defs/CountScanManySuccess",
          "first": "#/$defs/FirstScanManySuccess"
        },
        "propertyName": "mode"
      },
      "oneOf": [
        {
          "$ref": "#/$defs/FirstScanManySuccess"
        },
        {
          "$ref": "#/$defs/CountScanManySuccess"
        }
      ]
    },
    {
      "$ref": "#/$defs/ScanFailure"
    }
  ],
  "title": "ScanManyResponse",
  "type": "object"
}
```

## lua

Execute Lua script for complex memory operations &#40;loops&#44; conditionals&#44; multi&#45;step&#41;&#46; See server instructions for full list of available Lua functions&#46; Args&#58; script &#45; Lua code&#46; timeout &#45; optional max seconds &#40;default&#58; 180 seconds&#41;&#46; Returns&#58; &#123;success&#44; results &#40;dict&#41;&#44; output &#40;array of prints&#41;&#125;

### Input JSON schema

```json
{
  "properties": {
    "script": {
      "title": "Script",
      "type": "string"
    },
    "timeout": {
      "anyOf": [
        {
          "type": "number"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "title": "Timeout"
    }
  },
  "required": [
    "script"
  ],
  "title": "luaArguments",
  "type": "object"
}
```

## scripts

Lua script management&#46; Scripts live under &#36;MEMSCOPE&#95;HOME&#47;scripts&#47;&#60;process&#62;&#47;&#60;name&#62;&#46;lua&#46; Actions&#58; list &#45; Returns scripts with absolute paths&#46; Use process&#61;&#39;&#42;&#39; for all processes&#46; run &#45; Execute by name&#46; Pass args&#61;&#123;&#125; for script arguments&#46; timeout&#61;seconds optional&#46; process&#61;&#39;ProcessName&#46;exe&#39; selects the saved&#45;script namespace only&#59; it does not attach or switch&#46; Without an attachment&#44; pass process for detached execution&#46; When attached&#44; process must match&#46; Responses include requested&#95;process&#44; attached&#95;process&#44; attached&#95;pid&#44; and detached&#95;execution&#46; CREATE&#47;EDIT&#58; Use file tools on paths from &#39;list&#39;&#46; First line comment &#61; description&#46; Example&#58; scripts&#40;action&#61;&#39;list&#39;&#41; &#45;&#62; get scripts&#95;dir&#44; then Write to &#123;scripts&#95;dir&#125;&#47;&#60;name&#62;&#46;lua

### Input JSON schema

```json
{
  "properties": {
    "action": {
      "title": "Action",
      "type": "string"
    },
    "name": {
      "default": "",
      "title": "Name",
      "type": "string"
    },
    "process": {
      "default": "",
      "title": "Process",
      "type": "string"
    },
    "args": {
      "anyOf": [
        {
          "additionalProperties": true,
          "type": "object"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "title": "Args"
    },
    "timeout": {
      "anyOf": [
        {
          "type": "number"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "title": "Timeout"
    }
  },
  "required": [
    "action"
  ],
  "title": "scriptsArguments",
  "type": "object"
}
```
