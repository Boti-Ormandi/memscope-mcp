"""Core extensions -- always loaded, ordered list."""

from .execution import ExecutionExtension
from .general import GeneralExtension
from .memory import MemoryExtension
from .module_scan import ModuleScanExtension
from .process import ProcessExtension

# Registration order matters: earlier extensions get priority on name collisions.
# General must come first (provides addr, print, results helpers used by all).
CORE_EXTENSIONS: list[type] = [
    GeneralExtension,
    MemoryExtension,
    ModuleScanExtension,
    ExecutionExtension,
    ProcessExtension,
]

__all__ = ["CORE_EXTENSIONS"]
