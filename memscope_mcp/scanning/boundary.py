"""Isolated strict-model registration for FastMCP 1.27."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.fastmcp.tools.base import Tool
from mcp.server.fastmcp.utilities.func_metadata import ArgModelBase, FuncMetadata
from mcp.shared.exceptions import UrlElicitationRequiredError
from pydantic import BaseModel, Field, ValidationError

ValidationFailureMapper = Callable[[ValidationError], BaseModel]
StrictToolHandler = Callable[[BaseModel, Any], Awaitable[Any]]


class _EmptyArguments(ArgModelBase):
    pass


class _StrictModelTool(Tool):
    input_model: type[BaseModel] = Field(exclude=True)
    output_model: type[BaseModel] = Field(exclude=True)
    validation_failure_mapper: ValidationFailureMapper = Field(exclude=True)

    async def run(self, arguments: dict[str, Any], context: Any = None, convert_result: bool = False) -> Any:
        """Validate the raw top-level object before invoking the async handler."""

        try:
            try:
                request = self.input_model.model_validate(arguments)
            except ValidationError as error:
                result = self.validation_failure_mapper(error)
            else:
                result = await self.fn(request, context)

            validated_result = self.output_model.model_validate(result)
            if convert_result:
                return self.fn_metadata.convert_result(validated_result)
            return validated_result
        except UrlElicitationRequiredError:
            raise
        except Exception as error:
            raise ToolError(f"Error executing tool {self.name}: {error}") from error


def register_strict_model_tool(
    server: FastMCP,
    *,
    name: str,
    description: str,
    input_model: type[BaseModel],
    output_model: type[BaseModel],
    handler: StrictToolHandler,
    validation_failure_mapper: ValidationFailureMapper,
) -> Tool:
    """Register one flat strict-model tool through a contained FastMCP adapter."""

    if not inspect.iscoroutinefunction(handler):
        raise TypeError("Strict FastMCP handlers must be async")

    manager = getattr(server, "_tool_manager", None)
    tools = getattr(manager, "_tools", None)
    if manager is None or not isinstance(tools, dict):
        raise RuntimeError("Unsupported FastMCP tool-manager implementation")
    if name in tools:
        raise ValueError(f"Tool already exists: {name}")

    output_schema = output_model.model_json_schema(by_alias=True)
    metadata = FuncMetadata(
        arg_model=_EmptyArguments,
        output_schema=output_schema,
        output_model=output_model,
        wrap_output=False,
    )
    tool = _StrictModelTool(
        fn=handler,
        name=name,
        description=description,
        parameters=input_model.model_json_schema(by_alias=True),
        fn_metadata=metadata,
        is_async=True,
        context_kwarg=None,
        input_model=input_model,
        output_model=output_model,
        validation_failure_mapper=validation_failure_mapper,
    )
    tools[name] = tool
    return tool
