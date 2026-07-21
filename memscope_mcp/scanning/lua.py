"""Direct Lua adapters over the unified scanning engine."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pydantic import ValidationError

from memscope_mcp.scanning.contract import (
    AddressScanSuccess,
    CountScanManySuccess,
    CountScanSuccess,
    FirstScanManySuccess,
    FirstScanSuccess,
    LuaScanFailure,
    ScanFailure,
    ScanInput,
    ScanManyInput,
    scan_input_validation_failure,
    scan_many_input_validation_failure,
)
from memscope_mcp.scanning.execution import DirectScanError, ScanExecutor
from memscope_mcp.scanning.pattern import PatternCompileError, make_aob_query, make_exact_query, make_pointer_query
from memscope_mcp.scanning.scopes import USER_MODE_END_EXCLUSIVE, ScopeNormalizationError, resolve_address_expression

_COMMON_OPTIONS = frozenset({"scope", "mode", "max_matches", "timeout_ms", "diagnostics"})
_STRING_OPTIONS = _COMMON_OPTIONS | {"encoding"}
_POINTER_OPTIONS = _COMMON_OPTIONS | {"alignment"}
_BATCH_OPTIONS = frozenset({"scope", "mode", "max_matches", "timeout_ms", "diagnostics"})


class LuaScanAdapter:
    """Validate Lua tables and execute AOB, encoded-string, and pointer queries."""

    def __init__(
        self,
        executor: ScanExecutor,
        *,
        engine: Any,
        table_factory: Callable[..., Any],
        log_error: Callable[[str, Exception], None],
    ) -> None:
        if not isinstance(executor, ScanExecutor):
            raise TypeError("executor must be a ScanExecutor")
        if not callable(table_factory):
            raise TypeError("table_factory must be callable")
        if not callable(log_error):
            raise TypeError("log_error must be callable")
        self._executor = executor
        self._engine = engine
        self._table = table_factory
        self._log_error = log_error

    def aob_scan(self, pattern: Any, options: Any = None, *extra: Any):
        """Lua ``AOBScan(pattern, options?)`` implementation."""

        return self._invoke(
            "AOBScan",
            options,
            extra,
            allowed_options=_COMMON_OPTIONS,
            prepare_query=lambda _normalized: make_aob_query(pattern),
        )

    def aob_scan_many(self, patterns: Any, options: Any = None, *extra: Any):
        """Lua ``AOBScanMany(patterns, options?)`` implementation."""

        try:
            if extra:
                return self._failure(
                    "INVALID_ARGUMENT",
                    "Positional scan overloads were removed; pass one options table",
                    field="options",
                )
            normalized = _lua_options_to_python(options)
            unknown = sorted(set(normalized) - _BATCH_OPTIONS)
            if unknown:
                return self._failure(
                    "INVALID_ARGUMENT",
                    f"Unknown Lua scan option '{unknown[0]}'",
                    field=f"options.{unknown[0]}",
                )

            payload = dict(normalized)
            payload["patterns"] = _lua_value_to_python(patterns)
            try:
                request = ScanManyInput.model_validate(payload)
            except ValidationError as error:
                failure = scan_many_input_validation_failure(error)
                field = failure.field
                if field is not None and not field.startswith("patterns") and not field.startswith("options."):
                    failure = failure.model_copy(update={"field": f"options.{field}"})
                return self._failure_model(failure)

            outer_deadline = self._engine.execution_interrupt.deadline_ns
            local_deadline = self._executor.clock() + request.timeout_ms * 1_000_000
            effective_deadline = local_deadline if outer_deadline is None else min(local_deadline, outer_deadline)
            response = self._executor.execute_many(
                request,
                interrupt_check=self._engine.execution_interrupt.check,
                deadline_ns=effective_deadline,
            )
            return self._to_lua_many_result(response.root)
        except DirectScanError as error:
            return self._failure(error.error, error.detail, field=error.field, hint=error.hint)
        except Exception as error:
            self._log_error("AOBScanMany", error)
            raise

    def string_scan(self, text: Any, options: Any = None, *extra: Any):
        """Lua ``scanString(text, options?)`` implementation."""

        return self._invoke(
            "scanString",
            options,
            extra,
            allowed_options=_STRING_OPTIONS,
            prepare_query=lambda normalized: self._string_query(text, normalized.pop("encoding", "ascii")),
        )

    def pointer_scan(self, target: Any, options: Any = None, *extra: Any):
        """Lua ``scanPointer(target, options?)`` implementation."""

        return self._invoke(
            "scanPointer",
            options,
            extra,
            allowed_options=_POINTER_OPTIONS,
            prepare_query=lambda normalized: self._pointer_query_factory(
                target,
                normalized.pop("alignment", 8),
            ),
        )

    def _invoke(
        self,
        function_name: str,
        options: Any,
        extra: tuple[Any, ...],
        *,
        allowed_options: frozenset[str],
        query_factory=None,
        prepare_query=None,
    ):
        try:
            if extra:
                return self._failure(
                    "INVALID_ARGUMENT",
                    "Positional scan overloads were removed; pass one options table",
                    field="options",
                )

            normalized = _lua_options_to_python(options)
            unknown = sorted(set(normalized) - allowed_options)
            if unknown:
                field = f"options.{unknown[0]}"
                return self._failure(
                    "INVALID_ARGUMENT",
                    f"Unknown Lua scan option '{unknown[0]}'",
                    field=field,
                )

            active_query_factory = query_factory if prepare_query is None else prepare_query(normalized)
            request_or_failure = _validate_common_options(normalized)
            if isinstance(request_or_failure, ScanFailure):
                return self._failure_model(request_or_failure)
            request = request_or_failure

            max_matches = request.max_matches
            if request.mode == "addresses":
                max_matches = 100 if max_matches is None else max_matches
                if max_matches > 5000:
                    return self._failure(
                        "INVALID_ARGUMENT",
                        "Lua address mode max_matches must be between 1 and 5000",
                        field="options.max_matches",
                    )
            elif request.mode == "count":
                max_matches = 5000 if max_matches is None else max_matches

            outer_deadline = self._engine.execution_interrupt.deadline_ns
            local_deadline = self._executor.clock() + request.timeout_ms * 1_000_000
            effective_deadline = local_deadline if outer_deadline is None else min(local_deadline, outer_deadline)
            response = self._executor.execute_direct(
                active_query_factory,
                scope=request.scope,
                mode=request.mode,
                max_matches=max_matches,
                timeout_ms=request.timeout_ms,
                diagnostics=request.diagnostics,
                interrupt_check=self._engine.execution_interrupt.check,
                deadline_ns=effective_deadline,
            )
            return self._to_lua_result(response.root)
        except DirectScanError as error:
            return self._failure(error.error, error.detail, field=error.field, hint=error.hint)
        except PatternCompileError as error:
            return self._failure(error.code, error.detail, field=error.field)
        except Exception as error:
            self._log_error(function_name, error)
            raise

    def _string_query(self, text: Any, encoding: Any):
        if not isinstance(text, str) or not text:
            raise DirectScanError("INVALID_ARGUMENT", "text must be a non-empty string", field="text")
        if encoding not in {"ascii", "utf-16le"}:
            raise DirectScanError(
                "INVALID_ARGUMENT",
                "encoding must be 'ascii' or 'utf-16le'",
                field="options.encoding",
            )
        try:
            data = text.encode(encoding)
            return make_exact_query(data)
        except UnicodeEncodeError as error:
            raise DirectScanError(
                "INVALID_ARGUMENT",
                f"text cannot be encoded as {encoding}",
                field="text",
            ) from error
        except PatternCompileError as error:
            raise DirectScanError("INVALID_ARGUMENT", error.detail, field="text") from error

    def _pointer_query_factory(self, target: Any, alignment: Any):
        if isinstance(alignment, bool) or not isinstance(alignment, int) or not 1 <= alignment <= 4096:
            raise DirectScanError(
                "INVALID_ARGUMENT",
                "alignment must be an integer between 1 and 4096",
                field="options.alignment",
            )

        def build(lease):
            try:
                address = resolve_address_expression(target, lease.modules, field="target")
            except ScopeNormalizationError as error:
                raise DirectScanError(
                    "INVALID_ARGUMENT",
                    error.detail,
                    field="target",
                    hint=error.hint,
                ) from error
            if not 0 < address < USER_MODE_END_EXCLUSIVE:
                raise DirectScanError(
                    "INVALID_ARGUMENT",
                    "target must resolve to a non-zero user-mode address",
                    field="target",
                )
            return make_pointer_query(address, alignment=alignment)

        return build

    def _to_lua_result(self, result):
        if isinstance(result, ScanFailure):
            return self._failure_model(result)

        if isinstance(result, AddressScanSuccess):
            addresses = [int(hit.address, 16) for hit in result.matches]
            metadata = {
                "mode": "addresses",
                "returned_count": result.returned_count,
                "status": result.status.model_dump(mode="python"),
            }
        elif isinstance(result, FirstScanSuccess):
            addresses = [] if result.match is None else [int(result.match.address, 16)]
            metadata = {
                "mode": "first",
                "returned_count": len(addresses),
                "status": result.status.model_dump(mode="python"),
            }
        elif isinstance(result, CountScanSuccess):
            addresses = []
            metadata = {
                "mode": "count",
                "count": result.count,
                "observation": result.observation,
                "status": result.status.model_dump(mode="python"),
            }
        else:
            raise TypeError("unsupported direct scan response")

        if result.diagnostics is not None:
            metadata["diagnostics"] = result.diagnostics.model_dump(mode="python")
        table = self._table(*addresses)
        table["metadata"] = self._engine._python_to_lua(metadata)
        return table

    def _to_lua_many_result(self, result):
        if isinstance(result, ScanFailure):
            return self._failure_model(result)
        if not isinstance(result, (FirstScanManySuccess, CountScanManySuccess)):
            raise TypeError("unsupported direct scan_many response")

        rows = self._table()
        for index, item in enumerate(result.results, start=1):
            if isinstance(result, FirstScanManySuccess):
                row = {
                    "key": item.key,
                    "match": None if item.match is None else int(item.match.address, 16),
                    "status": item.status.model_dump(mode="python"),
                }
            else:
                row = {
                    "key": item.key,
                    "count": item.count,
                    "observation": item.observation,
                    "status": item.status.model_dump(mode="python"),
                }
            rows[index] = self._engine._python_to_lua(row)
        rows["metadata"] = self._engine._python_to_lua(
            {
                "mode": result.mode,
                "shared": result.shared.model_dump(mode="python", exclude_none=True),
            }
        )
        return rows

    def _failure(self, error: str, detail: str, *, field: str | None = None, hint: str | None = None):
        return self._failure_model(ScanFailure(error=error, detail=detail, field=field, hint=hint))

    def _failure_model(self, failure: ScanFailure):
        lua_failure = LuaScanFailure(
            error=failure.error,
            detail=failure.detail,
            field=failure.field,
            hint=failure.hint,
        )
        return None, self._engine._python_to_lua(lua_failure.model_dump(mode="python", exclude_none=True))


def _validate_common_options(options: dict[str, Any]) -> ScanInput | ScanFailure:
    mode = options.get("mode", "addresses")
    payload: dict[str, Any] = {
        "pattern": "00",
        "mode": mode,
        "timeout_ms": options.get("timeout_ms", 30_000),
        "diagnostics": options.get("diagnostics", False),
    }
    if "scope" in options:
        payload["scope"] = options["scope"]
    if "max_matches" in options:
        payload["max_matches"] = options["max_matches"]
    try:
        return ScanInput.model_validate(payload)
    except ValidationError as error:
        failure = scan_input_validation_failure(error)
        field = failure.field
        if field is not None and not field.startswith("options.") and field not in {"pattern", "text", "target"}:
            failure = failure.model_copy(update={"field": f"options.{field}"})
        return failure


def _lua_options_to_python(options: Any) -> dict[str, Any]:
    if options is None:
        return {}
    if not hasattr(options, "items") or isinstance(options, (str, bytes, bytearray, memoryview)):
        raise DirectScanError("INVALID_ARGUMENT", "options must be a Lua table", field="options")
    converted = _lua_value_to_python(options)
    if not isinstance(converted, dict):
        raise DirectScanError("INVALID_ARGUMENT", "options must be a Lua mapping table", field="options")
    for key in converted:
        if not isinstance(key, str):
            raise DirectScanError("INVALID_ARGUMENT", "option names must be strings", field="options")
    return converted


def _lua_value_to_python(value: Any) -> Any:
    if not hasattr(value, "items") or isinstance(value, (str, bytes, bytearray, memoryview)):
        return value
    items = list(value.items())
    if not items:
        return {}
    keys = [key for key, _item in items]
    if all(isinstance(key, int) and not isinstance(key, bool) and key >= 1 for key in keys):
        ordered = sorted(items, key=lambda item: item[0])
        expected = list(range(1, len(ordered) + 1))
        if [key for key, _item in ordered] != expected:
            raise DirectScanError("INVALID_ARGUMENT", "Lua array keys must be consecutive from 1")
        return [_lua_value_to_python(item) for _key, item in ordered]
    return {key: _lua_value_to_python(item) for key, item in items}
