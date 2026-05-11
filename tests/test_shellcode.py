"""Tests for x64 shellcode builder."""

import struct

from src.tools.execute import call_sequence
from src.utils.shellcode import build_call_x64, build_multi_call_x64, build_simple_ret


class TestBuildSimpleRet:
    def test_returns_zero(self):
        code = build_simple_ret(0)
        # mov rax, 0; ret
        assert code[:2] == b"\x48\xb8"
        assert struct.unpack("<Q", code[2:10])[0] == 0
        assert code[10:] == b"\xc3"

    def test_returns_value(self):
        code = build_simple_ret(0xDEADBEEF)
        assert struct.unpack("<Q", code[2:10])[0] == 0xDEADBEEF
        assert code[-1:] == b"\xc3"

    def test_returns_large_value(self):
        val = 0x7FFC8E7D0000
        code = build_simple_ret(val)
        assert struct.unpack("<Q", code[2:10])[0] == val


class TestBuildCallX64:
    def _find_call_rax(self, code: bytes) -> int:
        """Find the index of 'call rax' (ff d0) in shellcode."""
        idx = code.find(b"\xff\xd0")
        assert idx != -1, "call rax not found in shellcode"
        return idx

    def test_no_args(self):
        code = build_call_x64(func_addr=0x1000, args=[], result_addr=0x2000)
        # Should have prologue, call, store result, epilogue, ret
        assert b"\xff\xd0" in code  # call rax
        assert code[-1:] == b"\xc3"  # ret

    def test_one_arg_in_rcx(self):
        code = build_call_x64(func_addr=0x1000, args=[0x42], result_addr=0x2000)
        # mov rcx, 0x42
        idx = code.find(b"\x48\xb9")
        assert idx != -1
        val = struct.unpack("<Q", code[idx + 2 : idx + 10])[0]
        assert val == 0x42

    def test_two_args(self):
        code = build_call_x64(func_addr=0x1000, args=[0x11, 0x22], result_addr=0x2000)
        # mov rcx, 0x11
        rcx_idx = code.find(b"\x48\xb9")
        assert struct.unpack("<Q", code[rcx_idx + 2 : rcx_idx + 10])[0] == 0x11
        # mov rdx, 0x22
        rdx_idx = code.find(b"\x48\xba")
        assert struct.unpack("<Q", code[rdx_idx + 2 : rdx_idx + 10])[0] == 0x22

    def test_four_args(self):
        code = build_call_x64(func_addr=0x1000, args=[1, 2, 3, 4], result_addr=0x2000)
        # r8 = arg2: mov r8, imm64 = 49 B8
        assert b"\x49\xb8" in code
        # r9 = arg3: mov r9, imm64 = 49 B9
        assert b"\x49\xb9" in code

    def test_stack_args(self):
        # 5 args: first 4 in registers, 5th on stack at [rsp+0x20]
        code = build_call_x64(func_addr=0x1000, args=[1, 2, 3, 4, 0xAA], result_addr=0x2000)
        # The 5th arg should be loaded via mov rax, imm64 then mov [rsp+0x20], rax
        # mov rax, 0xAA
        rax_loads = []
        for i in range(len(code) - 9):
            if code[i : i + 2] == b"\x48\xb8":
                rax_loads.append(struct.unpack("<Q", code[i + 2 : i + 10])[0])
        assert 0xAA in rax_loads

    def test_func_addr_loaded(self):
        func = 0x7FFC8E7D1234
        code = build_call_x64(func_addr=func, args=[], result_addr=0x2000)
        # mov rax, func_addr should appear before call rax
        call_idx = self._find_call_rax(code)
        # The mov rax, func_addr is right before call rax (10 bytes: 48 B8 + 8 bytes)
        mov_rax = code[call_idx - 10 : call_idx]
        assert mov_rax[:2] == b"\x48\xb8"
        assert struct.unpack("<Q", mov_rax[2:])[0] == func

    def test_result_stored(self):
        result_addr = 0x2000
        code = build_call_x64(func_addr=0x1000, args=[], result_addr=result_addr)
        # mov rbx, result_addr (48 BB)
        idx = code.find(b"\x48\xbb")
        assert idx != -1
        assert struct.unpack("<Q", code[idx + 2 : idx + 10])[0] == result_addr
        # mov [rbx], rax (48 89 03)
        assert b"\x48\x89\x03" in code[idx:]

    def test_stack_alignment_4_args(self):
        code = build_call_x64(func_addr=0x1000, args=[1, 2, 3, 4], result_addr=0x2000)
        # Prologue: sub rsp, 0x28 (shadow space + alignment)
        assert code[:3] == b"\x48\x83\xec"
        stack_space = code[3]
        assert stack_space == 0x28

    def test_stack_alignment_5_args(self):
        code = build_call_x64(func_addr=0x1000, args=[1, 2, 3, 4, 5], result_addr=0x2000)
        # sub rsp, imm8
        assert code[:3] == b"\x48\x83\xec"
        stack_space = code[3]
        # Must be odd multiple of 8 for alignment after CALL pushes return address
        assert stack_space % 16 == 8, f"Stack space 0x{stack_space:X} not 16-byte aligned for CALL"

    def test_float_arg_xmm0(self):
        code = build_call_x64(func_addr=0x1000, args=[0x42], result_addr=0x2000, float_mask=1)
        # movq xmm0, rcx = 66 48 0F 6E C1
        assert b"\x66\x48\x0f\x6e\xc1" in code

    def test_float_arg_xmm1(self):
        code = build_call_x64(func_addr=0x1000, args=[0, 0x42], result_addr=0x2000, float_mask=2)
        # movq xmm1, rdx = 66 48 0F 6E CA
        assert b"\x66\x48\x0f\x6e\xca" in code

    def test_returns_float_stores_xmm0(self):
        code = build_call_x64(func_addr=0x1000, args=[], result_addr=0x2000, returns_float=True)
        # movq [rbx+8], xmm0 = 66 48 0F 7E 43 08
        assert b"\x66\x48\x0f\x7e\x43\x08" in code

    def test_no_float_no_xmm_store(self):
        code = build_call_x64(func_addr=0x1000, args=[], result_addr=0x2000, returns_float=False)
        # movq [rbx+8], xmm0 should NOT appear
        assert b"\x66\x48\x0f\x7e\x43\x08" not in code

    def test_epilogue_matches_prologue(self):
        code = build_call_x64(func_addr=0x1000, args=[1, 2], result_addr=0x2000)
        # Prologue: sub rsp, N
        assert code[:3] == b"\x48\x83\xec"
        prologue_space = code[3]
        # Epilogue: add rsp, N ... ret
        # Find add rsp near end
        epilogue_idx = code.rfind(b"\x48\x83\xc4")
        assert epilogue_idx != -1
        epilogue_space = code[epilogue_idx + 3]
        assert prologue_space == epilogue_space
        assert code[-1:] == b"\xc3"

    def test_boxed_return_copy(self):
        code = build_call_x64(
            func_addr=0x1000, args=[], result_addr=0x2000, result_copy_offset=0x10, result_copy_size=8
        )
        # rep movsb = F3 A4
        assert b"\xf3\xa4" in code


class TestBuildMultiCallX64:
    def test_single_call(self):
        code = build_multi_call_x64(calls=[(0x1000, [0x42])], result_addr=0x2000)
        assert b"\xff\xd0" in code  # call rax
        assert code[-1:] == b"\xc3"

    def test_two_calls(self):
        code = build_multi_call_x64(calls=[(0x1000, [1]), (0x2000, [2])], result_addr=0x3000)
        # Should have two call rax instructions
        count = 0
        idx = 0
        while True:
            idx = code.find(b"\xff\xd0", idx)
            if idx == -1:
                break
            count += 1
            idx += 2
        assert count == 2

    def test_stores_last_result(self):
        result_addr = 0x5000
        code = build_multi_call_x64(calls=[(0x1000, []), (0x2000, [])], result_addr=result_addr)
        # mov rbx, result_addr + 8 should appear after last call
        last_call = code.rfind(b"\xff\xd0")
        rbx_idx = code.find(b"\x48\xbb", last_call)
        assert rbx_idx != -1
        assert struct.unpack("<Q", code[rbx_idx + 2 : rbx_idx + 10])[0] == result_addr + 8

    def test_stores_each_result_and_loads_result_descriptors(self):
        result_addr = 0x5000
        code = build_multi_call_x64(
            calls=[
                (0x1000, []),
                (0x2000, [{"result": 1}]),
                (0x3000, [{"result": 2}]),
            ],
            result_addr=result_addr,
        )

        rbx_values = []
        idx = 0
        while True:
            idx = code.find(b"\x48\xbb", idx)
            if idx == -1:
                break
            rbx_values.append(struct.unpack("<Q", code[idx + 2 : idx + 10])[0])
            idx += 10

        assert result_addr in rbx_values
        assert result_addr + 8 in rbx_values
        assert result_addr + 16 in rbx_values

        assert b"\x48\xb8" + struct.pack("<Q", result_addr) + b"\x48\x8b\x08" in code
        assert b"\x48\xb8" + struct.pack("<Q", result_addr + 8) + b"\x48\x8b\x08" in code

    def test_stack_alignment(self):
        code = build_multi_call_x64(calls=[(0x1000, [1, 2, 3, 4, 5])], result_addr=0x2000)
        assert code[:3] == b"\x48\x83\xec"
        stack_space = code[3]
        assert stack_space % 16 == 8

    def test_empty_calls(self):
        code = build_multi_call_x64(calls=[], result_addr=0x2000)
        # Should still have prologue, result store, epilogue
        assert code[-1:] == b"\xc3"


class TestCallSequence:
    def test_returns_final_and_per_call_results(self, monkeypatch):
        class FakeSession:
            def __init__(self):
                self.pm = object()
                self.next_alloc = 0x100000
                self.result_addr = None
                self.memory = {}

            def is_valid_pointer(self, _addr):
                return True

            def allocate(self, size, executable=False):
                addr = self.next_alloc
                self.next_alloc += max(size, 1) + 0x100
                if not executable and self.result_addr is None:
                    self.result_addr = addr
                return addr

            def write_bytes(self, addr, data):
                self.memory[addr] = bytes(data)

            def create_remote_thread(self, _addr):
                self.memory[self.result_addr] = struct.pack("<QQ", 0x111, 0x222)
                return 0xABC

            def wait_for_thread(self, _handle, _timeout_ms):
                return True

            def read_bytes(self, addr, size):
                return self.memory[addr][:size]

            def free(self, _addr):
                return True

            def close_handle(self, _handle):
                return True

        monkeypatch.setattr("src.tools.execute.SESSION", FakeSession())

        result = call_sequence(
            [
                {"address": 0x1000, "args": []},
                {"address": 0x2000, "args": [{"result": 1}]},
            ]
        )

        assert result["success"] is True
        assert result["result"] == "0x222"
        assert result["call_results"] == ["0x111", "0x222"]
