"""Core extensions -- always loaded, ordered list."""

from .execution import ExecutionExtension
from .general import GeneralExtension
from .hooking import HookingExtension
from .memory import MemoryExtension
from .module_scan import ModuleScanExtension
from .network import NetworkExtension
from .process import ProcessExtension

# Registration order matters: earlier extensions get priority on name collisions.
# General must come first (provides addr, print, results helpers used by all).
# Hooking after execution (uses same memory primitives).
CORE_EXTENSIONS: list[type] = [
    GeneralExtension,
    MemoryExtension,
    ModuleScanExtension,
    ExecutionExtension,
    HookingExtension,
    ProcessExtension,
    NetworkExtension,
]

__all__ = ["CORE_EXTENSIONS"]
