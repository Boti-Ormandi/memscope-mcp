"""Cancellation-safe AnyIO worker adaptation for synchronous scan execution."""

from __future__ import annotations

import threading
from functools import partial

import anyio

from memscope_mcp.scanning.contract import (
    ScanInput,
    ScanManyInput,
    ScanManyResponse,
    ScanResponse,
)
from memscope_mcp.scanning.execution import (
    _LOGGER,
    ScanExecutor,
    ValidatedManyResponseLogger,
    ValidatedResponseLogger,
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
