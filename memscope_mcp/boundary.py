"""Public MCP SDK boundary for strict Pydantic-model tools."""

from __future__ import annotations

import inspect
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from functools import wraps
from typing import Any

from mcp import types as mcp_types
from mcp.server import MCPServer
from pydantic import BaseModel, ValidationError

ValidationFailureMapper = Callable[[ValidationError], BaseModel]
StrictToolHandler = Callable[[BaseModel, Any], Awaitable[Any]]


@dataclass(frozen=True, slots=True)
class StrictModelToolSpec:
    """Application-owned definition for a strict raw-model MCP tool."""

    name: str
    description: str
    input_model: type[BaseModel]
    output_model: type[BaseModel]
    handler: StrictToolHandler
    validation_failure_mapper: ValidationFailureMapper


class MemscopeMCPServer(MCPServer):
    """MCPServer with strict scan models and same-thread sync-tool dispatch."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._strict_model_tools: dict[str, StrictModelToolSpec] = {}
        self._ordinary_tool_names: set[str] = set()
        self._tool_registration_order: list[str] = []
        super().__init__(*args, **kwargs)

    def add_tool(
        self,
        fn: Callable[..., Any],
        name: str | None = None,
        title: str | None = None,
        description: str | None = None,
        annotations: mcp_types.ToolAnnotations | None = None,
        icons: list[mcp_types.Icon] | None = None,
        meta: dict[str, Any] | None = None,
        structured_output: bool | None = None,
    ) -> None:
        """Register sync tools through an async shim without changing the original function."""

        tool_name = name or fn.__name__
        if tool_name in self._strict_model_tools:
            raise ValueError(f"Tool already exists: {tool_name}")

        registered_fn = fn
        if not inspect.iscoroutinefunction(fn):

            @wraps(fn)
            async def same_thread_wrapper(*args: Any, **kwargs: Any) -> Any:
                return fn(*args, **kwargs)

            registered_fn = same_thread_wrapper

        super().add_tool(
            registered_fn,
            name=name,
            title=title,
            description=description,
            annotations=annotations,
            icons=icons,
            meta=meta,
            structured_output=structured_output,
        )
        if tool_name not in self._ordinary_tool_names:
            self._ordinary_tool_names.add(tool_name)
            self._tool_registration_order.append(tool_name)

    def add_strict_model_tool(self, spec: StrictModelToolSpec) -> None:
        """Register one strict raw-model tool without SDK-private manager access."""

        if not inspect.iscoroutinefunction(spec.handler):
            raise TypeError("Strict MCP handlers must be async")
        if spec.name in self._strict_model_tools or spec.name in self._ordinary_tool_names:
            raise ValueError(f"Tool already exists: {spec.name}")
        self._strict_model_tools[spec.name] = spec
        self._tool_registration_order.append(spec.name)

    async def list_tools(self) -> list[mcp_types.Tool]:
        """Advertise ordinary SDK-managed tools plus strict application-owned tools."""

        ordinary_tools = {tool.name: tool for tool in await super().list_tools()}
        strict_tools = {}
        for spec in self._strict_model_tools.values():
            output_schema = spec.output_model.model_json_schema(by_alias=True)
            # Handshake-era MCP protocols require an object marker on tool output schemas.
            # Every strict response union branch is already an object, so this is a semantic no-op.
            output_schema.setdefault("type", "object")
            strict_tools[spec.name] = mcp_types.Tool(
                name=spec.name,
                description=spec.description,
                input_schema=spec.input_model.model_json_schema(by_alias=True),
                output_schema=output_schema,
            )
        tools_by_name = {**ordinary_tools, **strict_tools}
        tools = [tools_by_name[name] for name in self._tool_registration_order if name in tools_by_name]
        registered_names = set(self._tool_registration_order)
        tools.extend(tool for name, tool in tools_by_name.items() if name not in registered_names)
        return tools

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        context: Any = None,
    ) -> mcp_types.CallToolResult | mcp_types.InputRequiredResult:
        """Dispatch strict raw-model tools directly and delegate ordinary tools to the SDK."""

        spec = self._strict_model_tools.get(name)
        if spec is None:
            return await super().call_tool(name, arguments, context)

        try:
            request = spec.input_model.model_validate(arguments)
        except ValidationError as error:
            result = spec.validation_failure_mapper(error)
        else:
            result = await spec.handler(request, context)

        validated_result = spec.output_model.model_validate(result)
        structured_content = validated_result.model_dump(mode="json", by_alias=True, exclude_none=False)
        text = json.dumps(structured_content, ensure_ascii=False, indent=2)
        return mcp_types.CallToolResult(
            content=[mcp_types.TextContent(type="text", text=text)],
            structured_content=structured_content,
        )
