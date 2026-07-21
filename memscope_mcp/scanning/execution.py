"""Lease-owning scan execution and cancellation-safe asynchronous adaptation."""

from __future__ import annotations

import hmac
import logging
import threading
import time
from collections.abc import Callable
from contextlib import AbstractContextManager
from functools import partial
from typing import Protocol

import anyio
import pymem.memory

from memscope_mcp.scanning.batch import BatchQuery, BatchScanResult, execute_scan_batch_plan
from memscope_mcp.scanning.collectors import (
    BoundedAddressCollector,
    CountCollector,
    FirstHitCollector,
    PageCollector,
    ScanCollector,
)
from memscope_mcp.scanning.contract import (
    AddressScanSuccess,
    CountScanManyItem,
    CountScanManySuccess,
    CountScanSuccess,
    FirstScanManyItem,
    FirstScanManySuccess,
    FirstScanSuccess,
    ScanDiagnostics,
    ScanFailure,
    ScanHit,
    ScanInput,
    ScanManyInput,
    ScanManyResponse,
    ScanManyShared,
    ScanResponse,
    ScanScopeInput,
    ScanStatus,
)
from memscope_mcp.scanning.cursor import (
    CURSOR_VERSION,
    SERVER_CURSOR_CODEC,
    CanonicalQueryState,
    CanonicalScopeState,
    ContinuationState,
    CursorCodec,
    CursorError,
)
from memscope_mcp.scanning.engine import execute_scan_plan
from memscope_mcp.scanning.lifecycle import ScanLease, ScanLeaseUnavailable
from memscope_mcp.scanning.model import (
    ScanControl,
    ScanQuery,
    ScanResult,
    ScanStats,
    TerminationReason,
)
from memscope_mcp.scanning.model import (
    ScanHit as InternalScanHit,
)
from memscope_mcp.scanning.pattern import PatternCompileError, make_aob_query
from memscope_mcp.scanning.planner import VirtualQuery, plan_scan_regions
from memscope_mcp.scanning.reader import (
    DEFAULT_PAGE_SIZE,
    PROVISIONAL_READ_CHUNK_SIZE,
    ReadMemory,
    TargetAlive,
)
from memscope_mcp.scanning.scopes import ScanScope, ScopeNormalizationError, normalize_scan_scope
from memscope_mcp.scanning.sections import SectionCache

ValidatedResponseLogger = Callable[[ScanResponse], None]
ValidatedManyResponseLogger = Callable[[ScanManyResponse], None]
DirectQueryFactory = Callable[[ScanLease], ScanQuery]


class DirectScanError(ValueError):
    """Expected domain failure raised while preparing a direct internal query."""

    def __init__(
        self,
        error: str,
        detail: str,
        *,
        field: str | None = None,
        hint: str | None = None,
    ) -> None:
        super().__init__(detail)
        self.error = error
        self.detail = detail
        self.field = field
        self.hint = hint


_MAX_ADDRESS_EXCLUSIVE = 1 << 64
_MAX_BATCH_COMPILED_BYTES = 32_768
_LOGGER = logging.getLogger(__name__)


class ScanSession(Protocol):
    """The stable-lease surface required from DebugSession."""

    def acquire_scan_lease(self) -> AbstractContextManager[ScanLease]: ...


class ScanExecutor:
    """Execute strict requests synchronously while owning exactly one scan lease."""

    def __init__(
        self,
        session: ScanSession,
        *,
        cursor_codec: CursorCodec | None = None,
        query_memory: VirtualQuery = pymem.memory.virtual_query,
        read_memory: ReadMemory = pymem.memory.read_bytes,
        target_alive: TargetAlive | None = None,
        section_cache: SectionCache | None = None,
        chunk_size: int = PROVISIONAL_READ_CHUNK_SIZE,
        page_size: int = DEFAULT_PAGE_SIZE,
        clock: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        if not hasattr(session, "acquire_scan_lease") or not callable(session.acquire_scan_lease):
            raise TypeError("session must provide acquire_scan_lease()")
        if not isinstance(cursor_codec, (CursorCodec, type(None))):
            raise TypeError("cursor_codec must be a CursorCodec or None")
        if not callable(query_memory):
            raise TypeError("query_memory must be callable")
        if not callable(read_memory):
            raise TypeError("read_memory must be callable")
        if target_alive is not None and not callable(target_alive):
            raise TypeError("target_alive must be callable or None")
        if section_cache is not None and not isinstance(section_cache, SectionCache):
            raise TypeError("section_cache must be a SectionCache or None")
        if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or chunk_size <= 0:
            raise ValueError("chunk_size must be a positive integer")
        if isinstance(page_size, bool) or not isinstance(page_size, int) or page_size <= 0:
            raise ValueError("page_size must be a positive integer")
        if not callable(clock):
            raise TypeError("clock must be callable")

        self.session = session
        self.cursor_codec = SERVER_CURSOR_CODEC if cursor_codec is None else cursor_codec
        self.query_memory = query_memory
        self.read_memory = read_memory
        self.target_alive = target_alive
        self.section_cache = SectionCache() if section_cache is None else section_cache
        self.chunk_size = chunk_size
        self.page_size = page_size
        self.clock = clock

    def execute(
        self,
        request: ScanInput,
        *,
        request_cancel: threading.Event | None = None,
        deadline_ns: int | None = None,
    ) -> ScanResponse:
        """Return one fully validated response without mutating registered routes."""

        if not isinstance(request, ScanInput):
            raise TypeError("request must be a validated ScanInput")
        if request_cancel is not None and not isinstance(request_cancel, threading.Event):
            raise TypeError("request_cancel must be a threading.Event or None")
        if deadline_ns is None:
            deadline_ns = self.clock() + request.timeout_ms * 1_000_000
        elif isinstance(deadline_ns, bool) or not isinstance(deadline_ns, int) or deadline_ns < 0:
            raise ValueError("deadline_ns must be a non-negative integer")

        cancellation = request_cancel or threading.Event()
        control = ScanControl(
            deadline_ns=deadline_ns,
            cancel_checks=(cancellation.is_set,),
            clock=self.clock,
        )

        try:
            if request.cursor is not None:
                response = self._execute_continuation(request, control)
            else:
                response = self._execute_start(request, control)
        except CursorError as error:
            response = _failure(error.error, error.detail, field="cursor", hint=error.hint)
        except PatternCompileError as error:
            response = _failure(error.code, error.detail, field=error.field)
        except ScopeNormalizationError as error:
            response = _failure(error.error, error.detail, field=error.field, hint=error.hint)
        except ScanLeaseUnavailable as error:
            response = _failure(error.error, error.detail)
        except Exception:
            _LOGGER.exception("Unexpected internal scan execution failure")
            response = _failure("INTERNAL_SCAN_ERROR", "The scan failed because of an internal error")

        return ScanResponse.model_validate(response)

    def execute_many(
        self,
        request: ScanManyInput,
        *,
        request_cancel: threading.Event | None = None,
        deadline_ns: int | None = None,
        interrupt_check: Callable[[], None] | None = None,
    ) -> ScanManyResponse:
        """Execute one bounded batch over a single planned target-memory traversal."""

        if not isinstance(request, ScanManyInput):
            raise TypeError("request must be a validated ScanManyInput")
        if request_cancel is not None and not isinstance(request_cancel, threading.Event):
            raise TypeError("request_cancel must be a threading.Event or None")
        if interrupt_check is not None and not callable(interrupt_check):
            raise TypeError("interrupt_check must be callable or None")
        if deadline_ns is None:
            deadline_ns = self.clock() + request.timeout_ms * 1_000_000
        elif isinstance(deadline_ns, bool) or not isinstance(deadline_ns, int) or deadline_ns < 0:
            raise ValueError("deadline_ns must be a non-negative integer")

        compiled: list[tuple[str, ScanQuery]] = []
        aggregate_bytes = 0
        for index, item in enumerate(request.patterns):
            try:
                query = make_aob_query(item.pattern)
            except PatternCompileError as error:
                return _many_failure(
                    error.code,
                    error.detail,
                    field=f"patterns[{index}].pattern",
                )
            aggregate_bytes += query.pattern.length
            if aggregate_bytes > _MAX_BATCH_COMPILED_BYTES:
                return _many_failure(
                    "INVALID_PATTERN",
                    f"Aggregate compiled pattern length exceeds {_MAX_BATCH_COMPILED_BYTES} bytes",
                    field="patterns",
                )
            compiled.append((item.key, query))

        cancel_checks = () if request_cancel is None else (request_cancel.is_set,)
        control = ScanControl(
            deadline_ns=deadline_ns,
            cancel_checks=cancel_checks,
            interrupt_check=interrupt_check,
            clock=self.clock,
        )

        try:
            with self.session.acquire_scan_lease() as lease:
                scope = normalize_scan_scope(request.scope, lease)
                max_matches = request.max_matches or 5_000
                entries = tuple(
                    BatchQuery(
                        key,
                        query,
                        FirstHitCollector() if request.mode == "first" else CountCollector(max_matches),
                    )
                    for key, query in compiled
                )
                plan = plan_scan_regions(
                    lease,
                    scope,
                    query_memory=self.query_memory,
                    read_memory=self.read_memory,
                    section_cache=self.section_cache,
                    control=control,
                )
                result = execute_scan_batch_plan(
                    entries,
                    lease,
                    plan,
                    control=control,
                    read_memory=self.read_memory,
                    target_alive=self.target_alive,
                    chunk_size=self.chunk_size,
                    page_size=self.page_size,
                )
                return self._format_many(request, result)
        except ScopeNormalizationError as error:
            return _many_failure(error.error, error.detail, field=error.field, hint=error.hint)
        except ScanLeaseUnavailable as error:
            return _many_failure(error.error, error.detail)
        except Exception:
            _LOGGER.exception("Unexpected internal scan_many execution failure")
            return _many_failure("INTERNAL_SCAN_ERROR", "The scan batch failed because of an internal error")

    def execute_direct(
        self,
        query: ScanQuery | DirectQueryFactory,
        *,
        scope: ScanScopeInput | None = None,
        mode: str = "addresses",
        max_matches: int | None = None,
        timeout_ms: int = 30_000,
        diagnostics: bool = False,
        interrupt_check: Callable[[], None] | None = None,
        deadline_ns: int | None = None,
    ) -> ScanResponse:
        """Execute a non-paginated internal query for a direct adapter such as Lua."""

        if not isinstance(query, ScanQuery) and not callable(query):
            raise TypeError("query must be a ScanQuery or lease-bound query factory")
        if mode not in {"addresses", "first", "count"}:
            return _failure("INVALID_MODE", "Mode must be one of: addresses, first, count", field="mode")
        if not isinstance(diagnostics, bool):
            return _failure("INVALID_ARGUMENT", "diagnostics must be a boolean", field="diagnostics")
        if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) or not 100 <= timeout_ms <= 30_000:
            return _failure(
                "INVALID_ARGUMENT",
                "timeout_ms must be an integer between 100 and 30000",
                field="timeout_ms",
            )
        if mode == "first":
            if max_matches is not None:
                return _failure("INVALID_ARGUMENT", "Mode 'first' does not accept max_matches", field="max_matches")
            effective_max_matches = 1
        else:
            effective_max_matches = 5_000 if max_matches is None else max_matches
            if (
                isinstance(effective_max_matches, bool)
                or not isinstance(effective_max_matches, int)
                or effective_max_matches < 1
                or effective_max_matches > 100_000
            ):
                return _failure(
                    "INVALID_ARGUMENT",
                    "max_matches must be an integer between 1 and 100000",
                    field="max_matches",
                )

        if interrupt_check is not None and not callable(interrupt_check):
            raise TypeError("interrupt_check must be callable or None")
        if deadline_ns is None:
            deadline_ns = self.clock() + timeout_ms * 1_000_000
        elif isinstance(deadline_ns, bool) or not isinstance(deadline_ns, int) or deadline_ns < 0:
            raise ValueError("deadline_ns must be a non-negative integer")

        control = ScanControl(
            deadline_ns=deadline_ns,
            interrupt_check=interrupt_check,
            clock=self.clock,
        )

        try:
            with self.session.acquire_scan_lease() as lease:
                prepared_query = query(lease) if callable(query) else query
                if not isinstance(prepared_query, ScanQuery):
                    raise TypeError("query factory must return ScanQuery")
                normalized_scope = normalize_scan_scope(scope, lease)
                if mode == "addresses":
                    collector: ScanCollector = BoundedAddressCollector(effective_max_matches)
                elif mode == "first":
                    collector = FirstHitCollector()
                else:
                    collector = CountCollector(effective_max_matches)
                plan = plan_scan_regions(
                    lease,
                    normalized_scope,
                    query_memory=self.query_memory,
                    read_memory=self.read_memory,
                    section_cache=self.section_cache,
                    control=control,
                )
                result = execute_scan_plan(
                    prepared_query,
                    lease,
                    plan,
                    collector,
                    control=control,
                    read_memory=self.read_memory,
                    target_alive=self.target_alive,
                    chunk_size=self.chunk_size,
                    page_size=self.page_size,
                )
                if mode == "addresses":
                    return self._format_addresses(
                        lease,
                        prepared_query,
                        normalized_scope,
                        result,
                        matches_returned_before=0,
                        max_matches=effective_max_matches,
                        diagnostics=diagnostics,
                    )
                if mode == "first":
                    early_failure = _fatal_result_without_progress(result)
                    if early_failure is not None:
                        return early_failure
                    match = _format_hit(result.hits[0]) if result.hits else None
                    return ScanResponse.model_validate(
                        FirstScanSuccess(
                            success=True,
                            mode="first",
                            match=match,
                            status=_status(result),
                            diagnostics=_diagnostics(result) if diagnostics else None,
                        )
                    )
                early_failure = _fatal_result_without_progress(result)
                if early_failure is not None:
                    return early_failure
                observation = (
                    "complete_traversal"
                    if result.termination_reason is TerminationReason.SCOPE_EXHAUSTED and not result.read_gaps_detected
                    else "partial_traversal"
                )
                return ScanResponse.model_validate(
                    CountScanSuccess(
                        success=True,
                        mode="count",
                        count=result.observed_count,
                        observation=observation,
                        status=_status(result),
                        diagnostics=_diagnostics(result) if diagnostics else None,
                    )
                )
        except DirectScanError as error:
            return _failure(error.error, error.detail, field=error.field, hint=error.hint)
        except PatternCompileError as error:
            return _failure(error.code, error.detail, field=error.field)
        except ScopeNormalizationError as error:
            return _failure(error.error, error.detail, field=error.field, hint=error.hint)
        except ScanLeaseUnavailable as error:
            return _failure(error.error, error.detail)

    def _format_many(self, request: ScanManyInput, result: BatchScanResult) -> ScanManyResponse:
        early_failure = _fatal_batch_without_progress(result)
        if early_failure is not None:
            return early_failure

        shared = ScanManyShared(
            termination=result.termination_reason.value,
            read_gaps_detected=result.read_gaps_detected,
            diagnostics=_diagnostics_from_stats(result.stats) if request.diagnostics else None,
        )
        if request.mode == "first":
            items = [
                FirstScanManyItem(
                    key=item.key,
                    match=_format_hit(item.hits[0]) if item.hits else None,
                    status=ScanStatus(
                        termination=item.termination_reason.value,
                        read_gaps_detected=item.read_gaps_detected,
                    ),
                )
                for item in result.items
            ]
            return ScanManyResponse.model_validate(
                FirstScanManySuccess(
                    success=True,
                    mode="first",
                    results=items,
                    shared=shared,
                )
            )

        items = [
            CountScanManyItem(
                key=item.key,
                count=item.observed_count,
                observation=(
                    "complete_traversal"
                    if item.termination_reason is TerminationReason.SCOPE_EXHAUSTED and not item.read_gaps_detected
                    else "partial_traversal"
                ),
                status=ScanStatus(
                    termination=item.termination_reason.value,
                    read_gaps_detected=item.read_gaps_detected,
                ),
            )
            for item in result.items
        ]
        return ScanManyResponse.model_validate(
            CountScanManySuccess(
                success=True,
                mode="count",
                results=items,
                shared=shared,
            )
        )

    def _execute_start(self, request: ScanInput, control: ScanControl) -> ScanResponse:
        if request.pattern is None:
            raise TypeError("start requests require pattern")
        query = make_aob_query(request.pattern)

        with self.session.acquire_scan_lease() as lease:
            scope = normalize_scan_scope(request.scope, lease)
            collector = _collector_for_start(request)
            plan = plan_scan_regions(
                lease,
                scope,
                query_memory=self.query_memory,
                read_memory=self.read_memory,
                section_cache=self.section_cache,
                control=control,
            )
            result = execute_scan_plan(
                query,
                lease,
                plan,
                collector,
                control=control,
                read_memory=self.read_memory,
                target_alive=self.target_alive,
                chunk_size=self.chunk_size,
                page_size=self.page_size,
            )
            return self._format_start(request, lease, query, scope, result)

    def _execute_continuation(self, request: ScanInput, control: ScanControl) -> ScanResponse:
        if request.cursor is None:
            raise TypeError("continuation requests require cursor")
        state = self.cursor_codec.decode(request.cursor)
        try:
            query = state.query.to_query()
        except PatternCompileError as error:
            raise CursorError("INVALID_CURSOR", "Cursor contains an invalid compiled query") from error

        with self.session.acquire_scan_lease() as lease:
            _validate_cursor_identity(state, lease)
            try:
                scope = normalize_scan_scope(state.scope.to_input(), lease)
            except ScopeNormalizationError as error:
                raise CursorError(
                    "CURSOR_STALE",
                    "Cursor scope no longer resolves against the current attachment",
                    hint="Restart the scan from its first page",
                ) from error
            if not hmac.compare_digest(scope.fingerprint, state.scope.fingerprint):
                raise CursorError("INVALID_CURSOR", "Cursor scope fingerprint does not match its canonical state")
            _validate_resume_address(state.resume_address, scope)

            remaining = state.max_matches - state.matches_returned_before
            if remaining <= 0:
                raise CursorError("INVALID_CURSOR", "Cursor has exhausted its cumulative match budget")
            collector = PageCollector(request.limit or 50, remaining_matches=remaining)
            plan = plan_scan_regions(
                lease,
                scope,
                query_memory=self.query_memory,
                read_memory=self.read_memory,
                section_cache=self.section_cache,
                control=control,
                resume_address=state.resume_address,
            )
            result = execute_scan_plan(
                query,
                lease,
                plan,
                collector,
                control=control,
                read_memory=self.read_memory,
                target_alive=self.target_alive,
                chunk_size=self.chunk_size,
                page_size=self.page_size,
                initial_read_gaps_detected=state.read_gaps_detected,
            )
            return self._format_addresses(
                lease,
                query,
                scope,
                result,
                matches_returned_before=state.matches_returned_before,
                max_matches=state.max_matches,
                diagnostics=request.diagnostics,
            )

    def _format_start(
        self,
        request: ScanInput,
        lease: ScanLease,
        query: ScanQuery,
        scope: ScanScope,
        result: ScanResult,
    ) -> ScanResponse:
        early_failure = _fatal_result_without_progress(result)
        if early_failure is not None:
            return early_failure

        if request.mode == "addresses":
            return self._format_addresses(
                lease,
                query,
                scope,
                result,
                matches_returned_before=0,
                max_matches=request.max_matches or 5000,
                diagnostics=request.diagnostics,
            )
        if request.mode == "first":
            match = _format_hit(result.hits[0]) if result.hits else None
            return ScanResponse.model_validate(
                FirstScanSuccess(
                    success=True,
                    mode="first",
                    match=match,
                    status=_status(result),
                    diagnostics=_diagnostics(result) if request.diagnostics else None,
                )
            )
        observation = (
            "complete_traversal"
            if result.termination_reason is TerminationReason.SCOPE_EXHAUSTED and not result.read_gaps_detected
            else "partial_traversal"
        )
        return ScanResponse.model_validate(
            CountScanSuccess(
                success=True,
                mode="count",
                count=result.observed_count,
                observation=observation,
                status=_status(result),
                diagnostics=_diagnostics(result) if request.diagnostics else None,
            )
        )

    def _format_addresses(
        self,
        lease: ScanLease,
        query: ScanQuery,
        scope: ScanScope,
        result: ScanResult,
        *,
        matches_returned_before: int,
        max_matches: int,
        diagnostics: bool,
    ) -> ScanResponse:
        early_failure = _fatal_result_without_progress(result)
        if early_failure is not None:
            return early_failure

        returned_count = len(result.hits)
        sequence_returned_count = matches_returned_before + returned_count
        next_cursor: str | None = None
        if result.termination_reason is TerminationReason.PAGE_LIMIT:
            if result.next_candidate_start is None:
                return _failure(
                    "INTERNAL_SCAN_ERROR",
                    "The scan stopped at a page boundary without an exact continuation address",
                )
            next_cursor = self.cursor_codec.encode(
                ContinuationState(
                    version=CURSOR_VERSION,
                    session_generation=lease.generation,
                    pid=lease.pid,
                    module_fingerprint=lease.modules.fingerprint,
                    query=CanonicalQueryState.from_query(query),
                    scope=CanonicalScopeState.from_scope(scope),
                    resume_address=result.next_candidate_start,
                    matches_returned_before=sequence_returned_count,
                    max_matches=max_matches,
                    read_gaps_detected=result.read_gaps_detected,
                )
            )

        return ScanResponse.model_validate(
            AddressScanSuccess(
                success=True,
                mode="addresses",
                matches=[_format_hit(hit) for hit in result.hits],
                returned_count=returned_count,
                sequence_returned_count=sequence_returned_count,
                next_cursor=next_cursor,
                status=_status(result),
                diagnostics=_diagnostics(result) if diagnostics else None,
            )
        )


async def execute_scan_async(
    executor: ScanExecutor,
    request: ScanInput,
    *,
    logger: ValidatedResponseLogger | None = None,
) -> ScanResponse:
    """Run a synchronous scan in a worker and never abandon its active lease."""

    if not isinstance(executor, ScanExecutor):
        raise TypeError("executor must be a ScanExecutor")
    if not isinstance(request, ScanInput):
        raise TypeError("request must be a validated ScanInput")
    if logger is not None and not callable(logger):
        raise TypeError("logger must be callable or None")

    deadline_ns = executor.clock() + request.timeout_ms * 1_000_000
    request_cancel = threading.Event()
    finished = anyio.Event()
    responses: list[ScanResponse] = []
    failures: list[BaseException] = []

    async def run_worker() -> None:
        try:
            with anyio.CancelScope(shield=True):
                response = await anyio.to_thread.run_sync(
                    partial(
                        executor.execute,
                        request,
                        request_cancel=request_cancel,
                        deadline_ns=deadline_ns,
                    ),
                    abandon_on_cancel=False,
                )
            responses.append(response)
        except BaseException as error:
            failures.append(error)
        finally:
            finished.set()

    async with anyio.create_task_group() as task_group:
        task_group.start_soon(run_worker)
        try:
            await finished.wait()
        except anyio.get_cancelled_exc_class():
            request_cancel.set()
            with anyio.CancelScope(shield=True):
                await finished.wait()
            raise

    if failures:
        raise failures[0]
    if len(responses) != 1:
        raise RuntimeError("scan worker completed without exactly one response")

    response = ScanResponse.model_validate(responses[0])
    if logger is not None:
        try:
            logger(response)
        except Exception:
            _LOGGER.exception("Validated scan response logger failed")
    return response


async def execute_scan_many_async(
    executor: ScanExecutor,
    request: ScanManyInput,
    *,
    logger: ValidatedManyResponseLogger | None = None,
) -> ScanManyResponse:
    """Run a synchronous batch in a worker and retain its lease until completion."""

    if not isinstance(executor, ScanExecutor):
        raise TypeError("executor must be a ScanExecutor")
    if not isinstance(request, ScanManyInput):
        raise TypeError("request must be a validated ScanManyInput")
    if logger is not None and not callable(logger):
        raise TypeError("logger must be callable or None")

    deadline_ns = executor.clock() + request.timeout_ms * 1_000_000
    request_cancel = threading.Event()
    finished = anyio.Event()
    responses: list[ScanManyResponse] = []
    failures: list[BaseException] = []

    async def run_worker() -> None:
        try:
            with anyio.CancelScope(shield=True):
                response = await anyio.to_thread.run_sync(
                    partial(
                        executor.execute_many,
                        request,
                        request_cancel=request_cancel,
                        deadline_ns=deadline_ns,
                    ),
                    abandon_on_cancel=False,
                )
            responses.append(response)
        except BaseException as error:
            failures.append(error)
        finally:
            finished.set()

    async with anyio.create_task_group() as task_group:
        task_group.start_soon(run_worker)
        try:
            await finished.wait()
        except anyio.get_cancelled_exc_class():
            request_cancel.set()
            with anyio.CancelScope(shield=True):
                await finished.wait()
            raise

    if failures:
        raise failures[0]
    if len(responses) != 1:
        raise RuntimeError("scan_many worker completed without exactly one response")

    response = ScanManyResponse.model_validate(responses[0])
    if logger is not None:
        try:
            logger(response)
        except Exception:
            _LOGGER.exception("Validated scan_many response logger failed")
    return response


def _collector_for_start(request: ScanInput) -> ScanCollector:
    if request.mode == "addresses":
        return PageCollector(request.limit or 50, remaining_matches=request.max_matches or 5000)
    if request.mode == "first":
        return FirstHitCollector()
    return CountCollector(request.max_matches or 5000)


def _validate_cursor_identity(state: ContinuationState, lease: ScanLease) -> None:
    if (
        state.session_generation != lease.generation
        or state.pid != lease.pid
        or not hmac.compare_digest(state.module_fingerprint, lease.modules.fingerprint)
    ):
        raise CursorError(
            "CURSOR_STALE",
            "Cursor attachment identity no longer matches the current process generation",
            hint="Restart the scan from its first page",
        )


def _validate_resume_address(resume_address: int, scope: ScanScope) -> None:
    if resume_address == _MAX_ADDRESS_EXCLUSIVE:
        if scope.ranges and scope.ranges[-1].end_exclusive == _MAX_ADDRESS_EXCLUSIVE:
            return
        raise CursorError("INVALID_CURSOR", "Cursor resume address is outside its normalized scope")
    if not any(item.start <= resume_address <= item.end_exclusive for item in scope.ranges):
        raise CursorError("INVALID_CURSOR", "Cursor resume address is outside its normalized scope")


def _fatal_result_without_progress(result: ScanResult) -> ScanResponse | None:
    progressed = result.stats.unique_bytes_examined > 0 or result.observed_count > 0
    if progressed:
        return None
    if result.termination_reason is TerminationReason.TARGET_CHANGED:
        return _failure("TARGET_CHANGED", "The attached process changed before scan results were available")
    if result.termination_reason is TerminationReason.READER_ERROR:
        return _failure("INTERNAL_SCAN_ERROR", "The target reader failed before scan results were available")
    return None


def _fatal_batch_without_progress(result: BatchScanResult) -> ScanManyResponse | None:
    progressed = result.stats.unique_bytes_examined > 0 or any(item.observed_count > 0 for item in result.items)
    if progressed:
        return None
    if result.termination_reason is TerminationReason.TARGET_CHANGED:
        return _many_failure("TARGET_CHANGED", "The attached process changed before scan results were available")
    if result.termination_reason is TerminationReason.READER_ERROR:
        return _many_failure("INTERNAL_SCAN_ERROR", "The target reader failed before scan results were available")
    return None


def _status(result: ScanResult) -> ScanStatus:
    return ScanStatus(
        termination=result.termination_reason.value,
        read_gaps_detected=result.read_gaps_detected,
    )


def _diagnostics(result: ScanResult) -> ScanDiagnostics:
    return _diagnostics_from_stats(result.stats)


def _diagnostics_from_stats(stats: ScanStats) -> ScanDiagnostics:
    return ScanDiagnostics(
        duration_ms=stats.duration_ns / 1_000_000,
        scope_fingerprint=stats.scope_fingerprint.hex(),
        sections=list(stats.section_names),
        strategy_counts={strategy.value: count for strategy, count in stats.strategy_counts.items()},
        unique_bytes_examined=stats.unique_bytes_examined,
        physical_read_calls=stats.physical_read_calls,
        physical_bytes_read=stats.physical_bytes_read,
        physical_cursor_prefix_bytes=stats.physical_cursor_prefix_bytes,
        region_count=stats.region_count,
        span_count=stats.span_count,
        candidate_count=stats.candidate_count,
        verification_count=stats.verification_count,
        control_polls=stats.control_polls,
    )


def _format_hit(hit: InternalScanHit) -> ScanHit:
    module_offset = None if hit.module_base is None else _format_hex(hit.address - hit.module_base)
    return ScanHit(
        address=_format_hex(hit.address),
        module=hit.module_name,
        module_offset=module_offset,
    )


def _format_hex(value: int) -> str:
    return f"0x{value:X}"


def _failure(
    error: str,
    detail: str,
    *,
    field: str | None = None,
    hint: str | None = None,
) -> ScanResponse:
    return ScanResponse.model_validate(
        ScanFailure(
            error=error,
            detail=detail,
            field=field,
            hint=hint,
        )
    )


def _many_failure(
    error: str,
    detail: str,
    *,
    field: str | None = None,
    hint: str | None = None,
) -> ScanManyResponse:
    return ScanManyResponse.model_validate(
        ScanFailure(
            error=error,
            detail=detail,
            field=field,
            hint=hint,
        )
    )
