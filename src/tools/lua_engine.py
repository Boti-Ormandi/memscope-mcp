"""Backward compatibility - use lua package directly."""

from .lua import LUA_ENGINE, MemscopeLuaEngine, execute_lua

__all__ = ["execute_lua", "LUA_ENGINE", "MemscopeLuaEngine"]
