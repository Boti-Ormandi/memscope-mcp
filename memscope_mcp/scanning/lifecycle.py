"""Scan-specific cancellation binding for stable attachment leases."""

from __future__ import annotations

from memscope_mcp.attachment import ScanLease

from .model import ScanControl


def bind_scan_control(control: ScanControl | None, lease: ScanLease) -> ScanControl:
    """Compose lifecycle cancellation into one request-local scan control."""

    if not isinstance(lease, ScanLease):
        raise TypeError("lease must be a ScanLease")
    base = control or ScanControl()
    if not isinstance(base, ScanControl):
        raise TypeError("control must be a ScanControl or None")
    return ScanControl(
        deadline_ns=base.deadline_ns,
        target_change_checks=(lease.lifecycle_cancel.is_set, *base.target_change_checks),
        cancel_checks=base.cancel_checks,
        interrupt_check=base.interrupt_check,
        clock=base.clock,
        poll_interval=base.poll_interval,
    )
