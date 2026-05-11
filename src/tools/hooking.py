"""Hook manager: ring buffer allocation, reading, and hook state tracking.

The ring buffer lives in the target process's memory. All hooks share one buffer.
Entries contain a fixed 80-byte header (args, timestamp, return_addr, result)
plus optional captured data (buffer contents, stack args).
"""

import logging
import struct
from dataclasses import dataclass, field

from ..session import SESSION
from ..utils.disasm import RelocationOverflowError, decode_prologue_ex
from ..utils.shellcode import build_hook_trampoline

logger = logging.getLogger(__name__)

# ==================== Ring Buffer Layout ====================

# Control block (256 bytes at offset 0x000)
RB_WRITE_INDEX = 0x000  # uint64, atomically incremented by hooks
RB_READ_INDEX = 0x008  # uint64, updated by server
RB_ENTRY_COUNT = 0x010  # uint64, power of 2
RB_MAX_DATA_SIZE = 0x018  # uint64
RB_TOTAL_CAPTURED = 0x020  # uint64
RB_TOTAL_DROPPED = 0x028  # uint64
RB_FLAGS = 0x030  # uint64, bit 0 = active
RB_ENTRY_TOTAL_SIZE = 0x038  # uint64, pre-computed
RB_ENTRY_COUNT_MASK = 0x040  # uint64, entry_count - 1
RB_CONTROL_SIZE = 0x100  # 256 bytes total

# Entry header (80 bytes = 0x50)
ENTRY_SEQUENCE = 0x00  # uint64
ENTRY_STATUS = 0x08  # uint32 (0=empty, 1=writing, 2=complete, 3=marker)
ENTRY_HOOK_ID = 0x0C  # uint32
ENTRY_TIMESTAMP = 0x10  # uint64 (rdtsc)
ENTRY_RETURN_ADDR = 0x18  # uint64
ENTRY_ARG0 = 0x20  # uint64
ENTRY_ARG1 = 0x28  # uint64
ENTRY_ARG2 = 0x30  # uint64
ENTRY_ARG3 = 0x38  # uint64
ENTRY_RESULT = 0x40  # int32
ENTRY_DATA_LENGTH = 0x44  # uint32
ENTRY_CAPTURED_LENGTH = 0x48  # uint32
ENTRY_FLAGS = 0x4C  # uint32, bit 0 = has_data, bits 8-11 = extra_args_count
ENTRY_HEADER_SIZE = 0x50
ENTRY_DATA_OFFSET = 0x50

STATUS_EMPTY = 0
STATUS_WRITING = 1
STATUS_COMPLETE = 2
STATUS_MARKER = 3

# Hook installation constants
PAGE_EXECUTE_READWRITE = 0x40
TRAMPOLINE_MAX_SIZE = 4096  # One page


# ==================== Data Classes ====================


@dataclass
class RingBufferConfig:
    """Ring buffer metadata (Python-side)."""

    address: int  # base address in target process
    entry_count: int  # number of slots (power of 2)
    max_data_size: int  # max data bytes per entry
    entry_total_size: int  # ENTRY_HEADER_SIZE + max_data_size
    total_size: int  # RB_CONTROL_SIZE + entry_count * entry_total_size


@dataclass
class HookInfo:
    """Installed hook metadata."""

    hook_id: int
    target_addr: int
    saved_bytes: bytes
    saved_length: int
    trampoline_addr: int
    trampoline_size: int
    original_protection: int
    hook_type: str  # "pre" or "post"
    name: str
    buffer_arg: int  # 1-4 (Lua-indexed) or -1
    length_arg: int  # 1-4, 0 (return value), or -1 (fixed/none)
    max_capture: int
    stack_args: list[int] = field(default_factory=list)  # Lua-indexed positions (5+)
    deref_args: dict[int, int] = field(default_factory=dict)  # {Lua-indexed arg -> read_size}
    buffer_deref: dict | None = None  # {arg: int, offset: int} (Lua-indexed)
    length_deref: dict | None = None  # {arg: int, offset: int, size: int} (Lua-indexed)
    ring_buffer_addr: int = 0
    jmp_size: int = 5  # 5 (near rel32) or 14 (far abs64)
    stub_offset: int = 0  # byte offset of original-bytes stub in trampoline


class HookManager:
    """Manages hook installation, ring buffer, and lifecycle cleanup."""

    def __init__(self) -> None:
        self.hooks: dict[int, HookInfo] = {}  # target_addr -> HookInfo
        self._hooks_by_id: dict[int, HookInfo] = {}  # hook_id -> HookInfo
        self.next_hook_id: int = 1
        self.ring_buffer: RingBufferConfig | None = None
        self._deferred_trampolines: list[tuple[int, int]] = []  # (addr, size)

    # ==================== Ring Buffer ====================

    def create_ring_buffer(self, entry_count: int = 512, max_data_size: int = 4096) -> dict:
        """Allocate and initialize shared ring buffer in target process.

        Args:
            entry_count: Number of entry slots (must be power of 2, >= 4).
            max_data_size: Maximum data bytes per entry.

        Returns:
            Dict with address, entry_count, max_data_size, total_size.

        Raises:
            RuntimeError: If ring buffer already exists or entry_count is invalid.
        """
        if self.ring_buffer is not None:
            raise RuntimeError("Ring buffer already exists. Destroy it first.")

        if entry_count < 4 or (entry_count & (entry_count - 1)) != 0:
            raise ValueError(f"entry_count must be power of 2 and >= 4, got {entry_count}")

        entry_total_size = ENTRY_HEADER_SIZE + max_data_size
        total_size = RB_CONTROL_SIZE + entry_count * entry_total_size

        # Allocate RW memory (not executable). VirtualAllocEx zero-initializes.
        addr = SESSION.allocate(total_size, executable=False)

        # Write control block fields
        SESSION.write_uint64(addr + RB_ENTRY_COUNT, entry_count)
        SESSION.write_uint64(addr + RB_MAX_DATA_SIZE, max_data_size)
        SESSION.write_uint64(addr + RB_ENTRY_TOTAL_SIZE, entry_total_size)
        SESSION.write_uint64(addr + RB_ENTRY_COUNT_MASK, entry_count - 1)
        SESSION.write_uint64(addr + RB_FLAGS, 1)  # active

        self.ring_buffer = RingBufferConfig(
            address=addr,
            entry_count=entry_count,
            max_data_size=max_data_size,
            entry_total_size=entry_total_size,
            total_size=total_size,
        )

        logger.info(f"Ring buffer created at 0x{addr:X}, {entry_count} entries, {max_data_size} max data")
        return {
            "address": f"0x{addr:X}",
            "entry_count": entry_count,
            "max_data_size": max_data_size,
            "total_size": total_size,
        }

    def destroy_ring_buffer(self) -> None:
        """Free the ring buffer. All hooks must be removed first.

        Raises:
            RuntimeError: If hooks are still active or no ring buffer exists.
        """
        if self.ring_buffer is None:
            raise RuntimeError("No ring buffer to destroy")
        if self.hooks:
            raise RuntimeError(f"Cannot destroy ring buffer: {len(self.hooks)} hooks still active")

        SESSION.free(self.ring_buffer.address)
        self.ring_buffer = None
        logger.info("Ring buffer destroyed")

    def read_ring_buffer(self, limit: int = 100, min_result: int | None = None) -> list[dict]:
        """Read pending entries from the ring buffer.

        Advances the read pointer after reading. Stops at WRITING entries
        (in-flight) to preserve ordering.

        Args:
            limit: Maximum entries to read.
            min_result: If set, skip entries where result < min_result.

        Returns:
            List of entry dicts with sequence, hook_id, args, data, etc.

        Raises:
            RuntimeError: If no ring buffer exists.
        """
        if self.ring_buffer is None:
            raise RuntimeError("No ring buffer")

        rb = self.ring_buffer
        # Read control block header (first 0x48 bytes covers through entry_count_mask)
        hdr = SESSION.read_bytes(rb.address, 0x48)
        write_idx = struct.unpack_from("<Q", hdr, RB_WRITE_INDEX)[0]
        read_idx = struct.unpack_from("<Q", hdr, RB_READ_INDEX)[0]

        entries = []
        while read_idx < write_idx and len(entries) < limit:
            slot = read_idx & (rb.entry_count - 1)
            entry_addr = rb.address + RB_CONTROL_SIZE + slot * rb.entry_total_size

            ehdr = SESSION.read_bytes(entry_addr, ENTRY_HEADER_SIZE)
            status = struct.unpack_from("<I", ehdr, ENTRY_STATUS)[0]

            if status == STATUS_WRITING:
                break  # in-flight entry, stop here

            if status == STATUS_EMPTY:
                break  # shouldn't happen if read_idx < write_idx, but be safe

            # Parse header fields
            seq = struct.unpack_from("<Q", ehdr, ENTRY_SEQUENCE)[0]
            hook_id = struct.unpack_from("<I", ehdr, ENTRY_HOOK_ID)[0]
            timestamp = struct.unpack_from("<Q", ehdr, ENTRY_TIMESTAMP)[0]
            ret_addr = struct.unpack_from("<Q", ehdr, ENTRY_RETURN_ADDR)[0]
            arg0, arg1, arg2, arg3 = struct.unpack_from("<QQQQ", ehdr, ENTRY_ARG0)
            result, data_len, captured, flags = struct.unpack_from("<iIII", ehdr, ENTRY_RESULT)

            # Parse extra args from data section prefix (if any)
            extra_args_count = (flags >> 8) & 0xF
            if extra_args_count > 7:
                extra_args_count = 7  # clamp to max allowed
            extra_args = {}
            prefix_size = extra_args_count * 8

            # Clamp captured_length to prevent out-of-bounds reads
            max_data = rb.max_data_size
            if prefix_size + captured > max_data:
                captured = max(0, max_data - prefix_size)

            if extra_args_count > 0 and prefix_size <= max_data:
                prefix_data = SESSION.read_bytes(entry_addr + ENTRY_DATA_OFFSET, prefix_size)
                for i in range(extra_args_count):
                    arg_val = struct.unpack_from("<Q", prefix_data, i * 8)[0]
                    extra_args[f"arg{4 + i}"] = arg_val

            # Apply result filter (skip entries that don't meet threshold)
            if min_result is not None and status != STATUS_MARKER and result < min_result:
                read_idx += 1
                continue

            # Read buffer data (after the stack arg prefix)
            data = None
            data_hex = None
            if captured > 0:
                data = SESSION.read_bytes(entry_addr + ENTRY_DATA_OFFSET + prefix_size, captured)
                data_hex = " ".join(f"{b:02X}" for b in data)

            entry = {
                "sequence": seq,
                "hook_id": hook_id,
                "timestamp": timestamp,
                "return_addr": f"0x{ret_addr:X}",
                "arg0": arg0,
                "arg1": arg1,
                "arg2": arg2,
                "arg3": arg3,
                "result": result,
                "data_length": data_len,
                "captured_length": captured,
                "data": data,
                "data_hex": data_hex,
                "is_marker": status == STATUS_MARKER,
            }
            if extra_args:
                entry["extra_args"] = extra_args

            # Look up hook name if available
            hook = self._hooks_by_id.get(hook_id)
            if hook:
                entry["hook_name"] = hook.name

            entries.append(entry)
            read_idx += 1

        # Advance read pointer
        SESSION.write_uint64(rb.address + RB_READ_INDEX, read_idx)
        return entries

    def ring_buffer_stats(self) -> dict:
        """Read ring buffer statistics.

        Returns:
            Dict with total_captured, total_dropped, entries_pending, utilization_pct.

        Raises:
            RuntimeError: If no ring buffer exists.
        """
        if self.ring_buffer is None:
            raise RuntimeError("No ring buffer")

        rb = self.ring_buffer
        hdr = SESSION.read_bytes(rb.address, 0x48)
        write_idx = struct.unpack_from("<Q", hdr, RB_WRITE_INDEX)[0]
        read_idx = struct.unpack_from("<Q", hdr, RB_READ_INDEX)[0]
        total_captured = struct.unpack_from("<Q", hdr, RB_TOTAL_CAPTURED)[0]
        total_dropped = struct.unpack_from("<Q", hdr, RB_TOTAL_DROPPED)[0]

        pending = write_idx - read_idx
        return {
            "total_captured": total_captured,
            "total_dropped": total_dropped,
            "entries_pending": pending,
            "utilization_pct": round(pending / rb.entry_count * 100, 1) if rb.entry_count else 0,
        }

    def ring_buffer_marker(self, label: str) -> bool:
        """Write a marker entry to the ring buffer.

        Temporarily disables capture, writes the marker, re-enables.
        Timestamp is 0 for server-side markers. Ordering comes from sequence numbers.

        Args:
            label: Marker label text.

        Returns:
            True if marker was written.

        Raises:
            RuntimeError: If no ring buffer exists.
        """
        if self.ring_buffer is None:
            raise RuntimeError("No ring buffer")

        rb = self.ring_buffer

        # Disable capture
        SESSION.write_uint64(rb.address + RB_FLAGS, 0)

        try:
            # Read and increment write_index
            write_idx = struct.unpack_from("<Q", SESSION.read_bytes(rb.address, 8), 0)[0]
            slot = write_idx & (rb.entry_count - 1)
            entry_addr = rb.address + RB_CONTROL_SIZE + slot * rb.entry_total_size

            # Build marker entry header
            label_bytes = label.encode("utf-8")[: rb.max_data_size]
            header = bytearray(ENTRY_HEADER_SIZE)
            struct.pack_into("<Q", header, ENTRY_SEQUENCE, write_idx)
            struct.pack_into("<I", header, ENTRY_STATUS, STATUS_MARKER)
            struct.pack_into("<I", header, ENTRY_HOOK_ID, 0)
            # timestamp stays 0
            struct.pack_into("<I", header, ENTRY_DATA_LENGTH, len(label_bytes))
            struct.pack_into("<I", header, ENTRY_CAPTURED_LENGTH, len(label_bytes))
            struct.pack_into("<I", header, ENTRY_FLAGS, 1)  # has_data

            SESSION.write_bytes(entry_addr, bytes(header))
            if label_bytes:
                SESSION.write_bytes(entry_addr + ENTRY_DATA_OFFSET, label_bytes)

            # Advance write_index
            SESSION.write_uint64(rb.address + RB_WRITE_INDEX, write_idx + 1)
        finally:
            # Re-enable capture
            SESSION.write_uint64(rb.address + RB_FLAGS, 1)

        return True

    def list_hooks(self) -> list[dict]:
        """List all active hooks.

        Returns:
            List of dicts with hook_id, name, address, type, buffer_arg, length_arg.
        """
        return [
            {
                "hook_id": h.hook_id,
                "name": h.name,
                "address": f"0x{h.target_addr:X}",
                "type": h.hook_type,
                "buffer_arg": h.buffer_arg,
                "length_arg": h.length_arg,
                "stack_args": h.stack_args,
            }
            for h in self.hooks.values()
        ]

    def cleanup(self, process_alive: bool = True) -> None:
        """Clean up all hooks and ring buffer during process detach.

        Called by HookingExtension.on_process_detaching() and by the server
        shutdown handler. Idempotent -- safe to call multiple times.

        Uses BaseException (not Exception) so KeyboardInterrupt during one
        cleanup step doesn't skip the rest.

        Args:
            process_alive: True if the process is still running (remote cleanup possible).
                False if the process already exited (only clear local state).
        """
        if process_alive:
            # Remove all hooks (restore original bytes)
            for target_addr in list(self.hooks.keys()):
                try:
                    self.remove_hook(target_addr)
                except BaseException as e:
                    logger.warning(f"Failed to remove hook at 0x{target_addr:X}: {e}")

            # Free deferred trampolines
            for addr, _size in self._deferred_trampolines:
                try:
                    SESSION.free(addr)
                except BaseException as e:
                    logger.warning(f"Failed to free trampoline at 0x{addr:X}: {e}")

            # Destroy ring buffer
            if self.ring_buffer is not None:
                try:
                    SESSION.free(self.ring_buffer.address)
                except BaseException as e:
                    logger.warning(f"Failed to free ring buffer: {e}")

        # Clear all local state
        self.hooks.clear()
        self._hooks_by_id.clear()
        self._deferred_trampolines.clear()
        self.ring_buffer = None
        self.next_hook_id = 1

    # ==================== Safe Patching ====================

    def _safe_patch(
        self,
        target_addr: int,
        patch_bytes: bytes,
        patch_size: int,
        stub_addr: int,
    ) -> tuple[int, int]:
        """Write patch bytes with thread suspension and IP adjustment.

        Suspends all target threads, checks for threads with RIP in the
        danger zone [target_addr, target_addr + patch_size), redirects them
        to the equivalent offset in the trampoline stub, writes the patch,
        then resumes all threads.

        Args:
            target_addr: Start address of the region being patched.
            patch_bytes: Bytes to write at target_addr.
            patch_size: Size of the danger zone (>= len(patch_bytes)).
            stub_addr: Address of the original-bytes stub in the trampoline.

        Returns:
            Tuple of (adjusted_count, original_protection).
        """
        suspended = SESSION.suspend_process_threads()
        adjusted = 0
        old_prot = 0
        try:
            for thread in suspended:
                try:
                    rip = SESSION.get_thread_rip(thread.handle)
                except OSError:
                    continue  # Thread may have exited between suspend and context read

                if target_addr <= rip < target_addr + patch_size:
                    offset = rip - target_addr
                    new_rip = stub_addr + offset
                    try:
                        SESSION.set_thread_rip(thread.handle, new_rip)
                        adjusted += 1
                        logger.info(f"Thread {thread.tid}: adjusted RIP 0x{rip:X} -> 0x{new_rip:X}")
                    except OSError as e:
                        logger.warning(f"Thread {thread.tid}: failed to adjust RIP: {e}")

            # Write the patch
            old_prot = SESSION.virtual_protect(target_addr, patch_size, PAGE_EXECUTE_READWRITE)
            SESSION.write_bytes(target_addr, patch_bytes)
            SESSION.virtual_protect(target_addr, patch_size, old_prot)
        finally:
            # Always resume, even if write fails
            SESSION.resume_process_threads(suspended)

        return adjusted, old_prot

    # ==================== Hook Install/Remove ====================

    def install_hook(
        self,
        target_addr: int,
        name: str,
        hook_type: str = "pre",
        buffer_arg: int = -1,
        length_arg: int = -1,
        max_capture: int = 4096,
        stack_args: list[int] | None = None,
        deref_args: dict[int, int] | None = None,
        buffer_deref: dict | None = None,
        length_deref: dict | None = None,
    ) -> dict:
        """Install an inline hook at target_addr.

        Reads the function prologue, allocates a trampoline (preferring near allocation
        for 5-byte JMP), builds shellcode, and patches the target function.

        Args:
            target_addr: Address of the function to hook.
            name: Label for identification.
            hook_type: "pre" (capture before call) or "post" (capture after call).
            buffer_arg: Which arg (1-4 Lua-indexed) is buffer pointer, -1 = no buffer.
            length_arg: Which arg (1-4) is length, 0 = return value, -1 = fixed/none.
            max_capture: Max bytes to capture per entry.
            stack_args: Lua-indexed arg positions (5+) to capture from stack. Max 7.
            deref_args: Post-call output pointer dereference. {Lua-indexed arg (1-4) -> read_size (4 or 8)}.
                After the original function returns, dereferences the saved arg pointer and
                overwrites the entry's arg field. Only valid with hook_type="post".
            buffer_deref: Indirect buffer pointer. {arg: Lua-indexed (1-4), offset: int}.
                Dereferences arg to get a struct pointer, then reads buffer pointer at struct+offset.
                Mutually exclusive with buffer_arg.
            length_deref: Indirect length source. {arg: Lua-indexed (1-4), offset: int, size: 4|8}.
                Dereferences arg to get a pointer, then reads length at ptr+offset.
                Mutually exclusive with length_arg.

        Returns:
            Dict with hook_id, trampoline address, saved_bytes count, jmp_size.

        Raises:
            RuntimeError: If no ring buffer, target already hooked, or allocation fails.
            ValueError: If args are invalid or prologue can't be decoded.
        """
        # --- Validation ---
        if self.ring_buffer is None:
            raise RuntimeError("No ring buffer. Call createRingBuffer() first.")
        if target_addr in self.hooks:
            raise RuntimeError(f"Address 0x{target_addr:X} is already hooked")
        if hook_type not in ("pre", "post"):
            raise ValueError(f"hook_type must be 'pre' or 'post', got '{hook_type}'")
        if buffer_arg != -1 and not (1 <= buffer_arg <= 4):
            raise ValueError(f"buffer_arg must be 1-4 or -1, got {buffer_arg}")
        if length_arg not in (-1, 0, 1, 2, 3, 4):
            raise ValueError(f"length_arg must be -1, 0, or 1-4, got {length_arg}")
        if length_arg == 0 and hook_type == "pre":
            raise ValueError("length_arg=0 (return value) is invalid for pre-call hooks")

        # Validate buffer_deref / length_deref
        if buffer_deref is not None:
            if buffer_arg != -1:
                raise ValueError("buffer_deref and buffer_arg are mutually exclusive")
            bd_arg = buffer_deref.get("arg")
            if not bd_arg or not (1 <= bd_arg <= 4):
                raise ValueError(f"buffer_deref.arg must be 1-4, got {bd_arg}")
            if "offset" not in buffer_deref:
                raise ValueError("buffer_deref requires 'offset' key")
        if length_deref is not None:
            if length_arg != -1:
                raise ValueError("length_deref and length_arg are mutually exclusive")
            ld_arg = length_deref.get("arg")
            if not ld_arg or not (1 <= ld_arg <= 4):
                raise ValueError(f"length_deref.arg must be 1-4, got {ld_arg}")
            if "offset" not in length_deref:
                raise ValueError("length_deref requires 'offset' key")
            if length_deref.get("size", 4) not in (4, 8):
                raise ValueError(f"length_deref.size must be 4 or 8, got {length_deref.get('size')}")

        has_buffer_source = buffer_arg != -1 or buffer_deref is not None
        has_length_source = length_arg != -1 or length_deref is not None
        if not has_buffer_source and has_length_source:
            raise ValueError("length source requires a buffer source")

        stack_args = stack_args or []
        if len(stack_args) > 7:
            raise ValueError(f"Max 7 stack args, got {len(stack_args)}")
        for sa in stack_args:
            if sa < 5:
                raise ValueError(f"stack_args must be >= 5 (Lua-indexed), got {sa}")
        if len(stack_args) * 8 >= self.ring_buffer.max_data_size:
            raise ValueError("Stack arg prefix exceeds max_data_size")

        deref_args = deref_args or {}
        if deref_args:
            if hook_type != "post":
                raise ValueError("deref_args only valid with type='post'")
            for arg_idx, read_size in deref_args.items():
                if not (1 <= arg_idx <= 4):
                    raise ValueError(f"deref_args key must be 1-4, got {arg_idx}")
                if read_size not in (4, 8):
                    raise ValueError(f"deref_args read_size must be 4 or 8, got {read_size}")

        # --- Check for existing hooks (prologue starts with JMP) ---
        first_bytes = SESSION.read_bytes(target_addr, 32)
        if first_bytes[0] == 0xE9:
            raise RuntimeError(
                f"Address 0x{target_addr:X} appears already hooked (starts with E9 rel32 JMP). "
                "Unhook or use a different address."
            )
        if first_bytes[0:2] == b"\xff\x25":
            raise RuntimeError(
                f"Address 0x{target_addr:X} appears already hooked (starts with FF25 abs JMP). "
                "Unhook or use a different address."
            )

        # --- Read prologue ---

        # --- Allocate trampoline (prefer near for 5-byte JMP) ---
        trampoline_mem = SESSION.allocate_near(target_addr, TRAMPOLINE_MAX_SIZE, executable=True)
        if trampoline_mem:
            jmp_size = 5
        else:
            trampoline_mem = SESSION.allocate(TRAMPOLINE_MAX_SIZE, executable=True)
            jmp_size = 14

        # --- Decode prologue to find boundary >= jmp_size ---
        try:
            total_bytes, relocation_info = decode_prologue_ex(first_bytes, jmp_size)
        except ValueError:
            SESSION.free(trampoline_mem)
            raise

        # Early check: if prologue needs relocation but trampoline is far, fail fast
        needs_relocation = any(insn.fixup_offset >= 0 for insn in relocation_info)
        if needs_relocation and jmp_size == 14:
            SESSION.free(trampoline_mem)
            raise RuntimeError(
                f"Function at 0x{target_addr:X} has position-dependent instructions in its prologue "
                "and near allocation failed. Cannot hook: trampoline is too far for instruction relocation. "
                "Ensure sufficient free memory within 2GB of the target function."
            )

        saved_bytes = first_bytes[:total_bytes]
        target_continue_addr = target_addr + total_bytes

        # --- Convert Lua-indexed args to internal (0-indexed) ---
        internal_buffer_arg = buffer_arg - 1 if buffer_arg >= 1 else -1
        if length_arg >= 1:
            internal_length_arg = length_arg - 1
        elif length_arg == 0:
            internal_length_arg = -2  # return value
        else:
            internal_length_arg = -1  # fixed/none
        internal_stack_args = [a - 1 for a in stack_args]
        internal_deref_args = {k - 1: v for k, v in deref_args.items()} if deref_args else None
        internal_buffer_deref = (
            {"arg": buffer_deref["arg"] - 1, "offset": int(buffer_deref["offset"])} if buffer_deref else None
        )
        internal_length_deref = (
            {
                "arg": length_deref["arg"] - 1,
                "offset": int(length_deref["offset"]),
                "size": int(length_deref.get("size", 4)),
            }
            if length_deref
            else None
        )

        # --- Build trampoline shellcode ---
        try:
            shellcode, stub_offset = build_hook_trampoline(
                hook_id=self.next_hook_id,
                ring_buffer_addr=self.ring_buffer.address,
                hook_type=hook_type,
                buffer_arg=internal_buffer_arg,
                length_arg=internal_length_arg,
                max_capture=min(max_capture, self.ring_buffer.max_data_size),
                saved_bytes=saved_bytes,
                target_continue_addr=target_continue_addr,
                stack_args=internal_stack_args or None,
                deref_args=internal_deref_args,
                target_addr=target_addr,
                trampoline_addr=trampoline_mem,
                relocation_info=relocation_info if needs_relocation else None,
                buffer_deref=internal_buffer_deref,
                length_deref=internal_length_deref,
            )
        except RelocationOverflowError:
            SESSION.free(trampoline_mem)
            raise

        # --- Write trampoline to allocated memory ---
        SESSION.write_bytes(trampoline_mem, shellcode)

        # --- Build JMP instruction ---
        if jmp_size == 5:
            rel32 = trampoline_mem - (target_addr + 5)
            jmp_bytes = b"\xe9" + struct.pack("<i", rel32)
        else:
            jmp_bytes = b"\xff\x25\x00\x00\x00\x00" + struct.pack("<Q", trampoline_mem)
        # Pad with NOPs to saved_length
        jmp_bytes += b"\x90" * (total_bytes - len(jmp_bytes))

        # --- Patch target function ---
        if jmp_size == 14:
            # Non-atomic write: suspend threads, adjust IPs, patch, resume
            stub_addr = trampoline_mem + stub_offset
            adjusted, old_prot = self._safe_patch(target_addr, jmp_bytes, total_bytes, stub_addr)
            if adjusted > 0:
                logger.info(f"Adjusted {adjusted} thread(s) during hook install at 0x{target_addr:X}")
        else:
            # 5-byte JMP: effectively atomic at aligned function entries
            old_prot = SESSION.virtual_protect(target_addr, total_bytes, PAGE_EXECUTE_READWRITE)
            SESSION.write_bytes(target_addr, jmp_bytes)
            SESSION.virtual_protect(target_addr, total_bytes, old_prot)

        # --- Record hook info ---
        hook = HookInfo(
            hook_id=self.next_hook_id,
            target_addr=target_addr,
            saved_bytes=saved_bytes,
            saved_length=total_bytes,
            trampoline_addr=trampoline_mem,
            trampoline_size=TRAMPOLINE_MAX_SIZE,
            original_protection=old_prot,
            hook_type=hook_type,
            name=name,
            buffer_arg=buffer_arg,
            length_arg=length_arg,
            max_capture=max_capture,
            stack_args=stack_args,
            deref_args=deref_args,
            buffer_deref=buffer_deref,
            length_deref=length_deref,
            ring_buffer_addr=self.ring_buffer.address,
            jmp_size=jmp_size,
            stub_offset=stub_offset,
        )
        self.hooks[target_addr] = hook
        self._hooks_by_id[hook.hook_id] = hook
        self.next_hook_id += 1

        logger.info(f"Hook '{name}' (id={hook.hook_id}) installed at 0x{target_addr:X}, jmp_size={jmp_size}")
        return {
            "hook_id": hook.hook_id,
            "trampoline": f"0x{trampoline_mem:X}",
            "saved_bytes": total_bytes,
            "jmp_size": jmp_size,
        }

    def remove_hook(self, target_addr_or_id: int) -> bool:
        """Remove an installed hook, restoring original bytes.

        The trampoline is NOT freed immediately (a thread may still be inside it).
        It is deferred to cleanup() during detach.

        Args:
            target_addr_or_id: Target address or hook_id.

        Returns:
            True if the hook was removed.

        Raises:
            KeyError: If no hook found at the given address/id.
        """
        # Look up by target_addr first, then by hook_id
        hook = self.hooks.get(target_addr_or_id)
        if hook is None:
            hook = self._hooks_by_id.get(target_addr_or_id)
        if hook is None:
            raise KeyError(f"No hook found for 0x{target_addr_or_id:X}")

        # Restore original bytes
        if hook.jmp_size == 14:
            # Non-atomic restoration: use thread suspension
            stub_addr = hook.trampoline_addr + hook.stub_offset
            adjusted, _ = self._safe_patch(hook.target_addr, hook.saved_bytes, hook.saved_length, stub_addr)
            if adjusted > 0:
                logger.info(f"Adjusted {adjusted} thread(s) during hook removal at 0x{hook.target_addr:X}")
        else:
            # 5-byte: direct write
            old_prot = SESSION.virtual_protect(hook.target_addr, hook.saved_length, PAGE_EXECUTE_READWRITE)
            SESSION.write_bytes(hook.target_addr, hook.saved_bytes)
            SESSION.virtual_protect(hook.target_addr, hook.saved_length, old_prot)

        # Defer trampoline free (thread safety)
        self._deferred_trampolines.append((hook.trampoline_addr, hook.trampoline_size))

        # Remove from tracking
        del self.hooks[hook.target_addr]
        del self._hooks_by_id[hook.hook_id]

        logger.info(f"Hook '{hook.name}' (id={hook.hook_id}) removed from 0x{hook.target_addr:X}")
        return True


# Module-level singleton
HOOK_MANAGER = HookManager()
