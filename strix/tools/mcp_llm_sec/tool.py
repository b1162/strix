"""``run_mcp_llm_sec`` — Client session interfaces for external MCP security servers."""

from __future__ import annotations

import json
import logging
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)


async def _run_mcp_stdio_flow(
    command: str,
    args: list[str],
    tool_name: str | None,
    tool_args: dict[str, Any] | None,
    list_only: bool,
) -> dict[str, Any]:
    """Connect to a local MCP server using stdio, negotiate handshake, and invoke operations."""
    try:
        from mcp import ClientSession, StdioServerParameters  # noqa: PLC0415
        from mcp.client.stdio import stdio_client  # noqa: PLC0415
    except ImportError:
        return {
            "success": False,
            "error": "The 'mcp' python library is not installed in the Strix runtime.",
        }

    server_params = StdioServerParameters(
        command=command,
        args=args,
        env=None,
    )

    try:
        async with stdio_client(server_params) as (read, write), ClientSession(
            read, write
        ) as session:
            await session.initialize()

            # List available tools
            tools_response = await session.list_tools()
            available_tools = [
                {
                    "name": getattr(t, "name", str(t)),
                    "description": getattr(t, "description", ""),
                    "input_schema": getattr(t, "inputSchema", {}),
                }
                for t in getattr(tools_response, "tools", [])
            ]

            if list_only or not tool_name:
                return {
                    "success": True,
                    "available_tools": available_tools,
                    "note": (
                        "Listed tools successfully. Specify 'mcp_tool_name' and "
                        "'mcp_tool_args' to execute."
                    ),
                }

            # Verify if requested tool is available
            matching_tools = [t for t in available_tools if t["name"] == tool_name]
            if not matching_tools:
                return {
                    "success": False,
                    "error": f"Tool '{tool_name}' not found on the MCP server.",
                    "available_tools": [t["name"] for t in available_tools],
                }

            # Call the requested tool
            logger.info("run_mcp_llm_sec: calling tool %s with args %s", tool_name, tool_args)
            result = await session.call_tool(tool_name, arguments=tool_args or {})

            return {
                "success": True,
                "tool_name": tool_name,
                "result": getattr(result, "content", str(result)),
                "available_tools": [t["name"] for t in available_tools],
            }

    except Exception as exc:
        logger.exception("MCP client connection flow failed")
        return {
            "success": False,
            "error": f"Failed to execute MCP stdio flow: {exc}",
        }


async def _run_mcp_sse_flow(
    url: str,
    tool_name: str | None,
    tool_args: dict[str, Any] | None,
    list_only: bool,
) -> dict[str, Any]:
    """Connect to a remote MCP server using SSE, negotiate handshake, and invoke operations."""
    try:
        from mcp import ClientSession  # noqa: PLC0415
        from mcp.client.sse import sse_client  # noqa: PLC0415
    except ImportError:
        return {
            "success": False,
            "error": "The 'mcp' python library is not installed in the Strix runtime.",
        }

    try:
        async with sse_client(url) as (read, write), ClientSession(read, write) as session:
            await session.initialize()

            # List available tools
            tools_response = await session.list_tools()
            available_tools = [
                {
                    "name": getattr(t, "name", str(t)),
                    "description": getattr(t, "description", ""),
                    "input_schema": getattr(t, "inputSchema", {}),
                }
                for t in getattr(tools_response, "tools", [])
            ]

            if list_only or not tool_name:
                return {
                    "success": True,
                    "available_tools": available_tools,
                    "note": (
                        "Listed tools successfully. Specify 'mcp_tool_name' and "
                        "'mcp_tool_args' to execute."
                    ),
                }

            # Call the requested tool
            logger.info(
                "run_mcp_llm_sec: calling SSE tool %s with args %s",
                tool_name,
                tool_args,
            )
            result = await session.call_tool(tool_name, arguments=tool_args or {})

            return {
                "success": True,
                "tool_name": tool_name,
                "result": getattr(result, "content", str(result)),
                "available_tools": [t["name"] for t in available_tools],
            }

    except Exception as exc:
        logger.exception("MCP client SSE flow failed")
        return {
            "success": False,
            "error": f"Failed to execute MCP SSE flow: {exc}",
        }


@function_tool(timeout=330, strict_mode=False)
async def run_mcp_llm_sec(
    ctx: RunContextWrapper,
    server_cmd: str | None = None,
    server_args: list[str] | None = None,
    sse_url: str | None = None,
    mcp_tool_name: str | None = None,
    mcp_tool_args: dict[str, Any] | None = None,
    list_only: bool = False,
) -> str:
    """Connect to a Model Context Protocol (MCP) server to run LLM audits or security scans.

    Use this tool to communicate with external LLM security/red-teaming servers (like garak-mcp,
    invariant-scan, etc.) using stdio command parameters or an SSE endpoint.

    Args:
        server_cmd: Launch command for the local stdio MCP server (e.g. "uv", "python3", "npx").
        server_args: Arguments passed to launch the stdio MCP server (e.g. ["run", "garak-mcp"]).
        sse_url: SSE connection endpoint for remote servers (e.g. "http://localhost:8000/sse").
        mcp_tool_name: Specific tool name to call from the MCP server.
        mcp_tool_args: Arguments passed to the target MCP tool.
        list_only: True to list tools on the server and terminate immediately. Default False.
    """
    del ctx

    if not server_cmd and not sse_url:
        return json.dumps(
            {
                "success": False,
                "error": "Either 'server_cmd' (for stdio) or 'sse_url' (for SSE) must be provided.",
            }
        )

    if server_cmd:
        cmd_args = list(server_args or [])
        res = await _run_mcp_stdio_flow(
            server_cmd, cmd_args, mcp_tool_name, mcp_tool_args, list_only
        )
    else:
        assert sse_url is not None
        res = await _run_mcp_sse_flow(sse_url, mcp_tool_name, mcp_tool_args, list_only)

    return json.dumps(res, ensure_ascii=False, indent=2)
