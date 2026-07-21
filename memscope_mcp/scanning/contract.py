"""Strict MCP boundary models for scanning operations."""

from __future__ import annotations

from typing import Annotated, Any, Literal, Union

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    RootModel,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticCustomError

ScanMode = Literal["addresses", "first", "count"]
PermissionFilter = Literal["any", "required", "forbidden"]
MemoryType = Literal["image", "mapped", "private"]
Termination = Literal[
    "scope_exhausted",
    "page_limit",
    "match_limit",
    "first_hit",
    "timeout",
    "cancelled",
    "target_changed",
    "reader_error",
]
Observation = Literal["complete_traversal", "partial_traversal"]
MatcherStrategy = Literal["exact", "all_wildcard", "anchor", "regex"]
ScanErrorCode = Literal[
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
    "INTERNAL_SCAN_ERROR",
]

AddressPageLimit = Annotated[int, Field(strict=True, ge=1, le=500)]
MatchLimit = Annotated[int, Field(strict=True, ge=1, le=100_000)]
TimeoutMs = Annotated[int, Field(strict=True, ge=100, le=30_000)]
NonNegativeInt = Annotated[int, Field(strict=True, ge=0)]
SequenceCount = Annotated[int, Field(strict=True, ge=0, le=100_000)]
AddressExpression = Union[int, str]

_ASCII_WHITESPACE = frozenset(" \t\n\r\v\f")
_VALIDATION_BRANCH_NAMES = frozenset({"all_modules", "modules", "range", "int", "str"})


class StrictModel(BaseModel):
    """Common strict, immutable model policy for the public scan boundary."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class ScanFiltersInput(StrictModel):
    memory_types: Annotated[list[MemoryType], Field(min_length=1, max_length=3)] | None = None
    executable: PermissionFilter = "any"
    writable: PermissionFilter = "any"
    sections: Annotated[list[Annotated[str, Field(min_length=1)]], Field(min_length=1, max_length=64)] | None = None

    @field_validator("memory_types")
    @classmethod
    def _reject_duplicate_memory_types(cls, value: list[str] | None) -> list[str] | None:
        if value is not None and len(set(value)) != len(value):
            raise ValueError("duplicate memory types")
        return value

    @field_validator("sections")
    @classmethod
    def _validate_sections(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return value
        normalized: set[str] = set()
        for section in value:
            encoded_length = len(section.encode("utf-8"))
            if encoded_length > 64:
                raise ValueError("section name exceeds 64 UTF-8 bytes")
            folded = section.casefold()
            if folded in normalized:
                raise ValueError("duplicate section name")
            normalized.add(folded)
        return value


class AllModulesScopeInput(StrictModel):
    kind: Literal["all_modules"]
    filters: ScanFiltersInput = Field(default_factory=ScanFiltersInput)


class ModulesScopeInput(StrictModel):
    kind: Literal["modules"]
    names: Annotated[list[Annotated[str, Field(min_length=1)]], Field(min_length=1, max_length=64)]
    filters: ScanFiltersInput = Field(default_factory=ScanFiltersInput)

    @field_validator("names")
    @classmethod
    def _validate_names(cls, value: list[str]) -> list[str]:
        normalized: set[str] = set()
        for name in value:
            if len(name.encode("utf-8")) > 260:
                raise ValueError("module name exceeds 260 UTF-8 bytes")
            folded = name.casefold()
            if folded in normalized:
                raise ValueError("duplicate module name")
            normalized.add(folded)
        return value


class RangeScopeInput(StrictModel):
    kind: Literal["range"]
    start: AddressExpression
    end_exclusive: AddressExpression
    filters: ScanFiltersInput = Field(default_factory=ScanFiltersInput)

    @model_validator(mode="after")
    def _reject_sections(self):
        if self.filters.sections is not None:
            raise PydanticCustomError(
                "scan_scope_sections",
                "Sections are valid only for module-based scopes",
                {"field": "scope.filters.sections"},
            )
        return self


ScanScopeInput = Annotated[
    Union[AllModulesScopeInput, ModulesScopeInput, RangeScopeInput],
    Field(discriminator="kind"),
]


class ScanInput(StrictModel):
    """Flat start-or-continuation request accepted by the strict MCP adapter."""

    pattern: Annotated[str, Field(min_length=1, max_length=4096)] | None = None
    scope: ScanScopeInput | None = None
    mode: ScanMode = "addresses"
    limit: AddressPageLimit | None = None
    max_matches: MatchLimit | None = None
    timeout_ms: TimeoutMs = 30_000
    diagnostics: bool = False
    cursor: Annotated[str, Field(min_length=1)] | None = None

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        json_schema_extra={
            "oneOf": [
                {"required": ["pattern"], "not": {"required": ["cursor"]}},
                {
                    "required": ["cursor"],
                    "not": {
                        "anyOf": [
                            {"required": ["pattern"]},
                            {"required": ["scope"]},
                            {"required": ["mode"]},
                            {"required": ["max_matches"]},
                        ]
                    },
                },
            ]
        },
    )

    @field_validator("pattern")
    @classmethod
    def _reject_whitespace_only_pattern(cls, value: str | None) -> str | None:
        if value is not None and not value.strip("".join(_ASCII_WHITESPACE)):
            raise ValueError("pattern is empty")
        return value

    @field_validator("cursor")
    @classmethod
    def _bound_cursor_bytes(cls, value: str | None) -> str | None:
        if value is not None and len(value.encode("utf-8")) > 65_536:
            raise ValueError("cursor exceeds 65536 bytes")
        return value

    @model_validator(mode="after")
    def _validate_request_form(self):
        fields_set = self.model_fields_set
        has_pattern = self.pattern is not None
        has_cursor = self.cursor is not None

        if has_pattern == has_cursor:
            raise PydanticCustomError(
                "scan_request_form",
                "Provide exactly one of pattern or cursor",
            )

        if has_cursor:
            forbidden = [name for name in ("pattern", "scope", "mode", "max_matches") if name in fields_set]
            if forbidden:
                field = forbidden[0]
                raise PydanticCustomError(
                    "scan_continuation_field",
                    "Continuation requests cannot include this field",
                    {"field": field},
                )
            return self

        if "cursor" in fields_set:
            raise PydanticCustomError(
                "scan_start_cursor",
                "Start requests cannot include cursor",
                {"field": "cursor"},
            )

        if self.mode == "first":
            forbidden = [name for name in ("limit", "max_matches") if name in fields_set]
            if forbidden:
                field = forbidden[0]
                raise PydanticCustomError(
                    "scan_mode_field",
                    "The selected mode does not accept this field",
                    {"field": field, "mode": self.mode},
                )
        elif self.mode == "count" and "limit" in fields_set:
            raise PydanticCustomError(
                "scan_mode_field",
                "The selected mode does not accept this field",
                {"field": "limit", "mode": self.mode},
            )

        return self


class NamedPatternInput(StrictModel):
    """One caller-keyed AOB pattern in a bounded batch request."""

    key: Annotated[str, Field(min_length=1)]
    pattern: Annotated[str, Field(min_length=1, max_length=4096)]

    @field_validator("key")
    @classmethod
    def _bound_key_bytes(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 64:
            raise ValueError("key exceeds 64 UTF-8 bytes")
        return value

    @field_validator("pattern")
    @classmethod
    def _reject_whitespace_only_pattern(cls, value: str) -> str:
        if not value.strip("".join(_ASCII_WHITESPACE)):
            raise ValueError("pattern is empty")
        return value


class ScanManyInput(StrictModel):
    """Bounded first-hit or count batch over one shared scan traversal."""

    patterns: Annotated[list[NamedPatternInput], Field(min_length=1, max_length=32)]
    scope: ScanScopeInput | None = None
    mode: Literal["first", "count"] = "first"
    max_matches: MatchLimit | None = None
    timeout_ms: TimeoutMs = 30_000
    diagnostics: bool = False

    @model_validator(mode="after")
    def _validate_batch(self):
        seen: set[str] = set()
        for index, item in enumerate(self.patterns):
            if item.key in seen:
                raise PydanticCustomError(
                    "scan_many_duplicate_key",
                    "Batch pattern keys must be unique",
                    {"field": f"patterns[{index}].key"},
                )
            seen.add(item.key)
        if self.mode == "first" and "max_matches" in self.model_fields_set:
            raise PydanticCustomError(
                "scan_many_mode_field",
                "First-hit batches do not accept max_matches",
                {"field": "max_matches", "mode": self.mode},
            )
        return self


class ScanHit(StrictModel):
    address: Annotated[str, Field(pattern=r"^0x(?:0|[1-9A-F][0-9A-F]*)$")]
    module: str | None
    module_offset: Annotated[str, Field(pattern=r"^0x(?:0|[1-9A-F][0-9A-F]*)$")] | None

    @model_validator(mode="after")
    def _validate_module_pair(self):
        if (self.module is None) != (self.module_offset is None):
            raise ValueError("module and module_offset must both be present or both be null")
        return self


class ScanStatus(StrictModel):
    termination: Termination
    read_gaps_detected: bool


class ScanDiagnostics(StrictModel):
    duration_ms: Annotated[float, Field(strict=True, ge=0)]
    scope_fingerprint: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    sections: Annotated[list[str], Field(max_length=64)]
    strategy_counts: Annotated[dict[MatcherStrategy, NonNegativeInt], Field(max_length=4)]
    unique_bytes_examined: NonNegativeInt
    physical_read_calls: NonNegativeInt
    physical_bytes_read: NonNegativeInt
    physical_cursor_prefix_bytes: NonNegativeInt
    region_count: NonNegativeInt
    span_count: NonNegativeInt
    candidate_count: NonNegativeInt
    verification_count: NonNegativeInt
    control_polls: NonNegativeInt


class AddressScanSuccess(StrictModel):
    success: Literal[True]
    mode: Literal["addresses"]
    matches: Annotated[list[ScanHit], Field(max_length=500)]
    returned_count: AddressPageLimit | Literal[0]
    sequence_returned_count: SequenceCount
    next_cursor: Annotated[str, Field(min_length=1)] | None
    status: ScanStatus
    diagnostics: ScanDiagnostics | None = None

    @field_validator("next_cursor")
    @classmethod
    def _bound_cursor_bytes(cls, value: str | None) -> str | None:
        if value is not None and len(value.encode("utf-8")) > 65_536:
            raise ValueError("cursor exceeds 65536 bytes")
        return value

    @model_validator(mode="after")
    def _validate_address_result(self):
        if self.returned_count != len(self.matches):
            raise ValueError("returned_count must equal len(matches)")
        if self.sequence_returned_count < self.returned_count:
            raise ValueError("sequence_returned_count cannot be smaller than returned_count")
        numeric_addresses = [int(hit.address, 16) for hit in self.matches]
        if numeric_addresses != sorted(set(numeric_addresses)):
            raise ValueError("matches must be unique and address ordered")
        if self.status.termination == "first_hit":
            raise ValueError("first_hit is not valid for address mode")
        if self.status.termination == "page_limit" and self.next_cursor is None:
            raise ValueError("page_limit requires next_cursor")
        if self.status.termination != "page_limit" and self.next_cursor is not None:
            raise ValueError("next_cursor is valid only for page_limit")
        return self


class FirstScanSuccess(StrictModel):
    success: Literal[True]
    mode: Literal["first"]
    match: ScanHit | None
    status: ScanStatus
    diagnostics: ScanDiagnostics | None = None

    @model_validator(mode="after")
    def _validate_first_result(self):
        if self.status.termination in {"page_limit", "match_limit"}:
            raise ValueError("page_limit and match_limit are not valid for first mode")
        if self.match is None and self.status.termination == "first_hit":
            raise ValueError("first_hit requires a match")
        if self.match is not None and self.status.termination != "first_hit":
            raise ValueError("a first-mode match requires first_hit termination")
        return self


class CountScanSuccess(StrictModel):
    success: Literal[True]
    mode: Literal["count"]
    count: MatchLimit | Literal[0]
    observation: Observation
    status: ScanStatus
    diagnostics: ScanDiagnostics | None = None

    @model_validator(mode="after")
    def _validate_count_result(self):
        if self.status.termination in {"page_limit", "first_hit"}:
            raise ValueError("page_limit and first_hit are not valid for count mode")
        complete = self.status.termination == "scope_exhausted" and not self.status.read_gaps_detected
        expected = "complete_traversal" if complete else "partial_traversal"
        if self.observation != expected:
            raise ValueError(f"observation must be {expected} for this status")
        return self


class FirstScanManyItem(StrictModel):
    key: Annotated[str, Field(min_length=1)]
    match: ScanHit | None
    status: ScanStatus

    @model_validator(mode="after")
    def _validate_first_item(self):
        if self.status.termination in {"page_limit", "match_limit"}:
            raise ValueError("page_limit and match_limit are not valid for first batch items")
        if self.match is None and self.status.termination == "first_hit":
            raise ValueError("first_hit requires a match")
        if self.match is not None and self.status.termination != "first_hit":
            raise ValueError("a first-mode match requires first_hit termination")
        return self


class CountScanManyItem(StrictModel):
    key: Annotated[str, Field(min_length=1)]
    count: MatchLimit | Literal[0]
    observation: Observation
    status: ScanStatus

    @model_validator(mode="after")
    def _validate_count_item(self):
        if self.status.termination in {"page_limit", "first_hit"}:
            raise ValueError("page_limit and first_hit are not valid for count batch items")
        complete = self.status.termination == "scope_exhausted" and not self.status.read_gaps_detected
        expected = "complete_traversal" if complete else "partial_traversal"
        if self.observation != expected:
            raise ValueError(f"observation must be {expected} for this status")
        return self


class ScanManyShared(StrictModel):
    termination: Termination
    read_gaps_detected: bool
    diagnostics: ScanDiagnostics | None = None


class FirstScanManySuccess(StrictModel):
    success: Literal[True]
    mode: Literal["first"]
    results: Annotated[list[FirstScanManyItem], Field(min_length=1, max_length=32)]
    shared: ScanManyShared

    @model_validator(mode="after")
    def _validate_first_batch(self):
        keys = [item.key for item in self.results]
        if len(set(keys)) != len(keys):
            raise ValueError("batch result keys must be unique")
        if self.shared.termination in {"page_limit", "match_limit"}:
            raise ValueError("page_limit and match_limit are not valid for first batches")
        if self.shared.termination == "first_hit" and any(
            item.status.termination != "first_hit" for item in self.results
        ):
            raise ValueError("shared first_hit requires every item to complete with first_hit")
        return self


class CountScanManySuccess(StrictModel):
    success: Literal[True]
    mode: Literal["count"]
    results: Annotated[list[CountScanManyItem], Field(min_length=1, max_length=32)]
    shared: ScanManyShared

    @model_validator(mode="after")
    def _validate_count_batch(self):
        keys = [item.key for item in self.results]
        if len(set(keys)) != len(keys):
            raise ValueError("batch result keys must be unique")
        if self.shared.termination in {"page_limit", "first_hit"}:
            raise ValueError("page_limit and first_hit are not valid for count batches")
        if self.shared.termination == "match_limit" and any(
            item.status.termination != "match_limit" for item in self.results
        ):
            raise ValueError("shared match_limit requires every item to complete with match_limit")
        return self


class ScanFailure(StrictModel):
    success: Literal[False] = False
    error: ScanErrorCode
    detail: Annotated[str, Field(min_length=1, max_length=1024)]
    field: Annotated[str, Field(min_length=1, max_length=256)] | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    hint: Annotated[str, Field(min_length=1, max_length=512)] | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )


class LuaScanFailure(StrictModel):
    """Expected Lua request/domain failure returned as the second result value."""

    error: ScanErrorCode
    detail: Annotated[str, Field(min_length=1, max_length=1024)]
    field: Annotated[str, Field(min_length=1, max_length=256)] | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    hint: Annotated[str, Field(min_length=1, max_length=512)] | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )


ScanSuccess = Annotated[
    Union[AddressScanSuccess, FirstScanSuccess, CountScanSuccess],
    Field(discriminator="mode"),
]


class ScanResponse(RootModel[Union[ScanSuccess, ScanFailure]]):
    model_config = ConfigDict(strict=True, frozen=True)


ScanManySuccess = Annotated[
    Union[FirstScanManySuccess, CountScanManySuccess],
    Field(discriminator="mode"),
]


class ScanManyResponse(RootModel[Union[ScanManySuccess, ScanFailure]]):
    model_config = ConfigDict(strict=True, frozen=True)


def scan_input_validation_failure(error: ValidationError) -> ScanFailure:
    """Map strict input validation failures to stable scan application errors."""

    first = error.errors(include_url=False)[0]
    error_type = first["type"]
    context = first.get("ctx") or {}
    field = context.get("field") or _format_field_path(first.get("loc", ()))

    if error_type == "extra_forbidden":
        if field == "scope" or (field is not None and field.startswith("scope.")):
            return ScanFailure(
                error="INVALID_SCOPE",
                detail=f"Unknown scan scope field '{field}'",
                field=field,
            )
        detail = f"Unknown scan argument '{field}'"
        return ScanFailure(error="INVALID_ARGUMENT", detail=detail, field=field)

    if error_type == "scan_request_form":
        return ScanFailure(
            error="INVALID_ARGUMENT",
            detail="Provide either a start request with pattern or a continuation request with cursor",
        )

    if error_type == "scan_continuation_field":
        return ScanFailure(
            error="INVALID_ARGUMENT",
            detail=f"Continuation requests cannot include '{field}'",
            field=field,
        )

    if error_type == "scan_start_cursor":
        return ScanFailure(
            error="INVALID_ARGUMENT",
            detail="Start requests cannot include cursor",
            field="cursor",
        )

    if error_type == "scan_mode_field":
        mode = context.get("mode", "selected")
        return ScanFailure(
            error="INVALID_ARGUMENT",
            detail=f"Mode '{mode}' does not accept '{field}'",
            field=field,
        )

    if error_type == "scan_scope_sections":
        return ScanFailure(
            error="INVALID_SCOPE",
            detail="Sections are valid only for module-based scopes",
            field=field or "scope.filters.sections",
        )

    if field == "mode":
        return ScanFailure(
            error="INVALID_MODE",
            detail="Mode must be one of: addresses, first, count",
            field="mode",
        )

    if field == "pattern":
        return ScanFailure(
            error="INVALID_PATTERN",
            detail="Pattern must be a non-empty string of at most 4096 characters",
            field="pattern",
        )

    if field == "cursor":
        return ScanFailure(
            error="INVALID_CURSOR",
            detail="Cursor must be a non-empty string of at most 65536 bytes",
            field="cursor",
        )

    if field == "scope" or (field is not None and field.startswith("scope.")):
        return ScanFailure(
            error="INVALID_SCOPE",
            detail="Invalid scan scope",
            field=field or "scope",
        )

    if field:
        return ScanFailure(
            error="INVALID_ARGUMENT",
            detail=f"Invalid value for '{field}'",
            field=field,
        )

    return ScanFailure(error="INVALID_ARGUMENT", detail="Invalid scan request")


def scan_many_input_validation_failure(error: ValidationError) -> ScanFailure:
    """Map strict batch validation failures to stable scan application errors."""

    first = error.errors(include_url=False)[0]
    error_type = first["type"]
    context = first.get("ctx") or {}
    field = context.get("field") or _format_field_path(first.get("loc", ()))

    if error_type == "extra_forbidden":
        if field == "scope" or (field is not None and field.startswith("scope.")):
            return ScanFailure(
                error="INVALID_SCOPE",
                detail=f"Unknown scan scope field '{field}'",
                field=field,
            )
        return ScanFailure(
            error="INVALID_ARGUMENT",
            detail=f"Unknown scan_many argument '{field}'",
            field=field,
        )
    if error_type == "scan_many_duplicate_key":
        return ScanFailure(
            error="INVALID_ARGUMENT",
            detail="Batch pattern keys must be unique",
            field=field or "patterns",
        )
    if error_type == "scan_many_mode_field":
        return ScanFailure(
            error="INVALID_ARGUMENT",
            detail="Mode 'first' does not accept 'max_matches'",
            field=field or "max_matches",
        )
    if error_type == "scan_scope_sections":
        return ScanFailure(
            error="INVALID_SCOPE",
            detail="Sections are valid only for module-based scopes",
            field=field or "scope.filters.sections",
        )
    if field == "mode":
        return ScanFailure(
            error="INVALID_MODE",
            detail="Mode must be one of: first, count",
            field="mode",
        )
    if field is not None and field.endswith(".pattern"):
        return ScanFailure(
            error="INVALID_PATTERN",
            detail="Each pattern must be a non-empty string of at most 4096 characters",
            field=field,
        )
    if field == "scope" or (field is not None and field.startswith("scope.")):
        return ScanFailure(
            error="INVALID_SCOPE",
            detail="Invalid scan scope",
            field=field or "scope",
        )
    if field:
        return ScanFailure(
            error="INVALID_ARGUMENT",
            detail=f"Invalid value for '{field}'",
            field=field,
        )
    return ScanFailure(error="INVALID_ARGUMENT", detail="Invalid scan_many request")


def _format_field_path(location: tuple[Any, ...]) -> str | None:
    if not location:
        return None

    parts: list[str] = []
    for item in location:
        if isinstance(item, str) and (item in _VALIDATION_BRANCH_NAMES or item.endswith("ScopeInput")):
            continue
        if isinstance(item, int):
            if parts:
                parts[-1] = f"{parts[-1]}[{item}]"
            else:
                parts.append(f"[{item}]")
            continue
        parts.append(str(item))
    return ".".join(parts) or None
