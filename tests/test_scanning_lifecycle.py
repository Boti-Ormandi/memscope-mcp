"""Deterministic tests for scanner attachment generations and read leases."""

from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

import memscope_mcp.session as session_module
from memscope_mcp.scanning.lifecycle import (
    AttachmentState,
    ModuleSnapshot,
    ModuleSnapshotError,
    ScanLeaseUnavailable,
    build_module_records,
)
from memscope_mcp.session import DebugSession


class FakePymem:
    def __init__(self, pid: int, handle: int, modules: list[SimpleNamespace]) -> None:
        self.process_id = pid
        self.process_handle = handle
        self._modules = modules
        self.fail_module_list = False
        self.closed = threading.Event()

    def list_modules(self):
        if self.fail_module_list:
            raise RuntimeError("module enumeration failed")
        return list(self._modules)

    def close_process(self) -> None:
        self.closed.set()


def module(name: str, base: int, size: int, path: str | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        name=name,
        lpBaseOfDll=base,
        SizeOfImage=size,
        filename=path if path is not None else rf"C:\Target\{name}",
    )


def attach_fake(monkeypatch, fake: FakePymem) -> DebugSession:
    monkeypatch.setattr(session_module.pymem, "Pymem", lambda _target: fake)
    session = DebugSession()
    assert session.switch_process("Target.exe") is True
    return session


class TestModuleSnapshot:
    def test_snapshot_sorts_indexes_duplicates_and_resolves_intervals(self):
        source = [
            module("FOO.dll", 0x3000, 0x100),
            module("target.exe", 0x1000, 0x400),
            module("foo.DLL", 0x2000, 0x200),
        ]

        snapshot = ModuleSnapshot.create(build_module_records(source), generation=7)

        assert [record.name for record in snapshot.ordered_by_base] == ["target.exe", "foo.DLL", "FOO.dll"]
        assert [record.base for record in snapshot.find_all(r"C:\Other\FoO.DlL")] == [0x2000, 0x3000]
        assert snapshot.find_by_address(0x11FF).name == "target.exe"
        assert snapshot.find_by_address(0x2200) is None
        assert snapshot.find_by_address(0x3000).name == "FOO.dll"

    def test_snapshot_is_immutable_after_source_mutation(self):
        source_module = module("target.exe", 0x1000, 0x400)
        snapshot = ModuleSnapshot.create(build_module_records([source_module]), generation=1)

        source_module.name = "changed.exe"
        source_module.lpBaseOfDll = 0x9000

        assert snapshot.ordered_by_base[0].name == "target.exe"
        assert snapshot.ordered_by_base[0].base == 0x1000
        with pytest.raises(TypeError):
            snapshot.by_normalized_name["other.dll"] = ()

    def test_snapshot_rejects_overlapping_module_ranges(self):
        records = build_module_records(
            [
                module("first.dll", 0x1000, 0x300),
                module("second.dll", 0x1200, 0x100),
            ]
        )

        with pytest.raises(ModuleSnapshotError, match="overlap"):
            ModuleSnapshot.create(records, generation=1)

    def test_fingerprint_binds_generation_and_layout(self):
        records = build_module_records([module("target.exe", 0x1000, 0x400)])
        first = ModuleSnapshot.create(records, generation=1)
        second = ModuleSnapshot.create(records, generation=2)
        moved = ModuleSnapshot.create(build_module_records([module("target.exe", 0x2000, 0x400)]), generation=1)

        assert first.fingerprint != second.fingerprint
        assert first.fingerprint != moved.fingerprint


class TestAttachmentGeneration:
    def test_successful_open_and_refresh_create_new_generations(self, monkeypatch):
        fake = FakePymem(111, 0xABC, [module("target.exe", 0x1000, 0x400)])
        session = attach_fake(monkeypatch, fake)

        assert session.attachment_state is AttachmentState.ATTACHED
        assert session.attachment_generation == 1
        first_snapshot = session.module_snapshot

        fake._modules.append(module("plugin.dll", 0x3000, 0x200))
        assert session.refresh_modules() is True

        assert session.attachment_generation == 2
        assert session.module_snapshot is not first_snapshot
        assert [record.name for record in session.module_snapshot.ordered_by_base] == ["target.exe", "plugin.dll"]
        assert fake.closed.is_set() is False

    def test_failed_open_does_not_consume_generation(self, monkeypatch):
        def fail_open(_target):
            raise RuntimeError("open failed")

        monkeypatch.setattr(session_module.pymem, "Pymem", fail_open)
        session = DebugSession()

        assert session.switch_process("Missing.exe") is False
        assert session.attachment_state is AttachmentState.DETACHED
        assert session.attachment_generation == 0
        assert session.module_snapshot is None

    def test_failed_refresh_preserves_generation_snapshot_and_live_lease(self, monkeypatch):
        fake = FakePymem(111, 0xABC, [module("target.exe", 0x1000, 0x400)])
        session = attach_fake(monkeypatch, fake)
        generation = session.attachment_generation
        snapshot = session.module_snapshot

        with session.acquire_scan_lease() as lease:
            fake.fail_module_list = True
            assert session.refresh_modules() is False
            assert lease.lifecycle_cancel.is_set() is False
            assert session.attachment_generation == generation
            assert session.module_snapshot is snapshot
            assert session.attachment_state is AttachmentState.ATTACHED

    def test_reconnect_retires_old_handle_and_advances_generation(self, monkeypatch):
        first = FakePymem(111, 0xAAA, [module("target.exe", 0x1000, 0x400)])
        second = FakePymem(222, 0xBBB, [module("target.exe", 0x2000, 0x500)])
        candidates = iter([first, second])
        monkeypatch.setattr(session_module.pymem, "Pymem", lambda _target: next(candidates))
        session = DebugSession()
        assert session.switch_process("Target.exe") is True
        monkeypatch.setattr(session, "_is_process_alive", lambda: False)

        assert session.ensure_attached() is True

        assert first.closed.is_set() is True
        assert session.pm is second
        assert session.pid == 222
        assert session.attachment_generation == 2


class TestScanLeaseRetirement:
    def test_detach_cancels_before_close_and_waits_for_release(self, monkeypatch):
        fake = FakePymem(111, 0xABC, [module("target.exe", 0x1000, 0x400)])
        session = attach_fake(monkeypatch, fake)
        monkeypatch.setattr(session, "_is_process_alive", lambda: False)
        errors: list[BaseException] = []

        with session.acquire_scan_lease() as lease:

            def detach_worker() -> None:
                try:
                    session.detach()
                except BaseException as exc:
                    errors.append(exc)

            worker = threading.Thread(target=detach_worker)
            worker.start()
            assert lease.lifecycle_cancel.wait(1.0)
            assert session.attachment_state is AttachmentState.RETIRING
            assert fake.closed.is_set() is False
            with pytest.raises(ScanLeaseUnavailable) as exc_info:
                with session.acquire_scan_lease():
                    pass
            assert exc_info.value.error == "TARGET_CHANGED"

        worker.join(1.0)
        assert worker.is_alive() is False
        assert errors == []
        assert fake.closed.is_set() is True
        assert session.attachment_state is AttachmentState.DETACHED
        assert session.active_scan_leases == 0

    def test_refresh_retires_leases_without_callbacks_or_handle_close(self, monkeypatch):
        fake = FakePymem(111, 0xABC, [module("target.exe", 0x1000, 0x400)])
        session = attach_fake(monkeypatch, fake)
        callback_calls: list[str] = []
        session.register_on_attach("test", lambda _session: callback_calls.append("attach"))
        session.register_on_detach("test", lambda _session, _alive: callback_calls.append("detach"))
        callback_calls.clear()
        fake._modules.append(module("plugin.dll", 0x3000, 0x200))
        results: list[bool] = []

        with session.acquire_scan_lease() as lease:
            worker = threading.Thread(target=lambda: results.append(session.refresh_modules()))
            worker.start()
            assert lease.lifecycle_cancel.wait(1.0)
            assert session.attachment_state is AttachmentState.RETIRING
            assert fake.closed.is_set() is False
            assert callback_calls == []

        worker.join(1.0)
        assert worker.is_alive() is False
        assert results == [True]
        assert callback_calls == []
        assert fake.closed.is_set() is False
        assert session.attachment_state is AttachmentState.ATTACHED
        assert session.attachment_generation == 2

    def test_exception_releases_lease(self, monkeypatch):
        fake = FakePymem(111, 0xABC, [module("target.exe", 0x1000, 0x400)])
        session = attach_fake(monkeypatch, fake)

        with pytest.raises(RuntimeError, match="scan failed"):
            with session.acquire_scan_lease():
                raise RuntimeError("scan failed")

        assert session.active_scan_leases == 0

    def test_detach_callbacks_run_without_condition_lock(self, monkeypatch):
        fake = FakePymem(111, 0xABC, [module("target.exe", 0x1000, 0x400)])
        session = attach_fake(monkeypatch, fake)
        monkeypatch.setattr(session, "_is_process_alive", lambda: False)
        condition_was_available = threading.Event()
        callback_finished = threading.Event()

        def callback(_session, _alive) -> None:
            def contend() -> None:
                acquired = session._lifecycle_condition.acquire(timeout=0.5)
                if acquired:
                    condition_was_available.set()
                    session._lifecycle_condition.release()

            contender = threading.Thread(target=contend)
            contender.start()
            contender.join(0.75)
            callback_finished.set()

        session.register_on_detach("lock-check", callback)
        session.detach()

        assert callback_finished.is_set()
        assert condition_was_available.is_set()
