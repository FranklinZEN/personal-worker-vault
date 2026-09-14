"""Project-scoped local STDIO MCP bridge for CF2-A hostile-synthetic fixtures only.

The server deliberately implements a small JSON-RPC MCP tools surface without a third-party SDK.
It has no listener, network client, browser, connector, model client, persistence, or authority
integration.  Its sole outward interaction is the explicit macOS native picker for a known local
fixture chosen by the owner.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Sequence, TextIO

from vault_next.chat_ingress import ChatIngressError
from vault_next.content_profiles import ContentProfileError
from vault_next.host_ingress import (
    ADAPTER_ID,
    METHOD_PACKAGE,
    METHOD_VERSION,
    DisposableFixtureRoot,
    HostIngressCoordinator,
    HostIngressError,
    MacOSNativeFileSelector,
)
from vault_next.meeting_debrief import MeetingDebriefError
from vault_next.records import SchemaRegistry


_SERVER_NAME = "vault-next-chat-first-stdio"
_SERVER_VERSION = "0.1.0"
_MAX_REQUEST_BYTES = 1_200_000
_PROTOCOL_VERSION = "2025-06-18"


class McpProtocolError(RuntimeError):
    """A JSON-RPC request does not meet this deliberately small STDIO MCP surface."""


class CodexMcpApplication:
    """Expose only CF2-A U0 tools backed by one disposable fixture-root coordinator."""

    def __init__(self, coordinator: HostIngressCoordinator) -> None:
        self.coordinator = coordinator

    @classmethod
    def create(cls) -> CodexMcpApplication:
        """Build an application with a fresh process-owned fixture root and native picker only."""

        schema_root = Path(__file__).resolve().parents[2] / "schemas" / "v1"
        fixtures = DisposableFixtureRoot.create()
        return cls(
            HostIngressCoordinator(
                SchemaRegistry(schema_root),
                fixtures,
                MacOSNativeFileSelector(),
            )
        )

    def close(self) -> None:
        """Discard in-memory sessions and temporary fixture files."""

        self.coordinator.close()

    def initialize(self, params: object) -> dict[str, Any]:
        """Return the fixed tool capability; no resource, prompt, or remote capability exists."""

        if not isinstance(params, dict):
            raise McpProtocolError("initialize parameters are invalid")
        return {
            "protocolVersion": _PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": _SERVER_NAME, "version": _SERVER_VERSION},
            "instructions": (
                "CF2-A hostile-synthetic U0 proof only. No save, action, network, browser, "
                "connector, authority, or real-source operation is available."
            ),
        }

    def list_tools(self, params: object) -> dict[str, Any]:
        """List exactly the prepare/choose/validate U0 tools and no consequential capability."""

        if params not in ({}, None):
            raise McpProtocolError("tools/list parameters are invalid")
        return {"tools": _tool_definitions()}

    def call_tool(self, params: object) -> dict[str, Any]:
        """Invoke one bounded U0 operation and surface only a JSON text content result."""

        if not isinstance(params, dict) or set(params) != {"name", "arguments"}:
            raise McpProtocolError("tools/call parameters are invalid")
        name = params["name"]
        arguments = params["arguments"]
        if not isinstance(name, str) or not isinstance(arguments, dict):
            raise McpProtocolError("tools/call parameters are invalid")
        try:
            if name == "vault_next_prepare_meeting_debrief_paste":
                value = self._prepare_paste(arguments)
            elif name == "vault_next_choose_meeting_debrief_fixture":
                value = self._choose_fixture(arguments)
            elif name == "vault_next_validate_meeting_debrief":
                value = self._validate_debrief(arguments)
            else:
                raise McpProtocolError("requested tool is unavailable")
        except (ChatIngressError, ContentProfileError, HostIngressError, MeetingDebriefError) as exc:
            return _tool_error(str(exc))
        return _tool_result(value)

    def _prepare_paste(self, arguments: dict[str, Any]) -> dict[str, Any]:
        allowed = {"text", "safe_label", "declared_extension"}
        if not set(arguments).issubset(allowed) or "text" not in arguments:
            raise McpProtocolError("paste tool arguments are invalid")
        text = arguments["text"]
        safe_label = arguments.get("safe_label", "invented-paste.txt")
        extension = arguments.get("declared_extension", ".txt")
        if not isinstance(safe_label, str) or not isinstance(extension, str):
            raise McpProtocolError("paste tool arguments are invalid")
        session = self.coordinator.prepare_paste(
            text,
            safe_label=safe_label,
            declared_extension=extension,
        )
        return self.coordinator.host_packet(session)

    def _choose_fixture(self, arguments: dict[str, Any]) -> dict[str, Any]:
        if arguments:
            raise McpProtocolError("fixture-selection tool accepts no arguments")
        session = self.coordinator.choose_native_fixture()
        return self.coordinator.host_packet(session)

    def _validate_debrief(self, arguments: dict[str, Any]) -> dict[str, Any]:
        if set(arguments) != {"session_id", "analysis"}:
            raise McpProtocolError("debrief-validation tool arguments are invalid")
        return self.coordinator.validate_host_analysis(arguments["session_id"], arguments["analysis"])


class StdioMcpServer:
    """Line-delimited JSON-RPC loop: STDIO is the only transport and stdout carries only protocol."""

    def __init__(self, application: CodexMcpApplication, input_stream: TextIO, output_stream: TextIO) -> None:
        self.application = application
        self.input = input_stream
        self.output = output_stream

    def serve(self) -> int:
        """Serve requests until stdin closes, emitting no logs or non-protocol output on stdout."""

        try:
            for line in self.input:
                if len(line.encode("utf-8")) > _MAX_REQUEST_BYTES:
                    self._write(_error_response(None, -32600, "request exceeds fixed fixture budget"))
                    continue
                response = self._handle_line(line)
                if response is not None:
                    self._write(response)
        finally:
            self.application.close()
        return 0

    def _handle_line(self, line: str) -> dict[str, Any] | None:
        try:
            value = json.loads(line)
            if not isinstance(value, dict) or value.get("jsonrpc") != "2.0":
                raise McpProtocolError("invalid JSON-RPC request")
            request_id = value.get("id")
            notification = "id" not in value
            method = value.get("method")
            params = value.get("params", {})
            if not isinstance(method, str):
                raise McpProtocolError("invalid JSON-RPC request")
            if method == "initialize":
                result = self.application.initialize(params)
            elif method == "notifications/initialized":
                result = None
            elif method == "tools/list":
                result = self.application.list_tools(params)
            elif method == "tools/call":
                result = self.application.call_tool(params)
            else:
                return None if notification else _error_response(request_id, -32601, "method unavailable")
            return None if notification else _success_response(request_id, result)
        except json.JSONDecodeError:
            return _error_response(None, -32700, "invalid JSON")
        except McpProtocolError as exc:
            return _error_response(None, -32600, str(exc))
        except Exception:
            return _error_response(None, -32603, "local synthetic bridge failed safely")

    def _write(self, value: dict[str, Any]) -> None:
        self.output.write(json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n")
        self.output.flush()


def main(argv: Sequence[str] | None = None) -> int:
    """Launch the project-scoped local STDIO MCP server; command-line arguments are forbidden."""

    if argv is not None and list(argv):
        raise SystemExit("vault-next-chat-first-stdio accepts no command-line arguments")
    return StdioMcpServer(CodexMcpApplication.create(), sys.stdin, sys.stdout).serve()


def _tool_definitions() -> list[dict[str, Any]]:
    return [
        {
            "name": "vault_next_prepare_meeting_debrief_paste",
            "description": (
                "Prepare one explicitly supplied marked invented paste fixture for an ephemeral "
                "U0 Meeting Debrief evaluation. This does not save or take action."
            ),
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["text"],
                "properties": {
                    "text": {"type": "string", "minLength": 1, "maxLength": 1_000_000},
                    "safe_label": {"type": "string", "minLength": 1, "maxLength": 128},
                    "declared_extension": {"enum": [".txt", ".md"], "type": "string"},
                },
            },
        },
        {
            "name": "vault_next_choose_meeting_debrief_fixture",
            "description": (
                "Open a native macOS chooser for exactly one invented text, Markdown, or DOCX "
                "fixture in the server's disposable root. No real file is accepted."
            ),
            "inputSchema": {"type": "object", "additionalProperties": False, "properties": {}},
        },
        {
            "name": "vault_next_validate_meeting_debrief",
            "description": (
                "Validate a hosted structured Meeting Debrief against the prepared frozen evidence. "
                "Citations must be bound; no owner/due value or tool/effect request is allowed."
            ),
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["session_id", "analysis"],
                "properties": {
                    "session_id": {"type": "string", "minLength": 1},
                    "analysis": {"type": "object"},
                },
            },
        },
    ]


def _tool_result(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": json.dumps(value, sort_keys=True)}],
        "structuredContent": value,
        "isError": False,
    }


def _tool_error(message: str) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": json.dumps({"status": "rejected", "reason": message})}],
        "isError": True,
    }


def _success_response(request_id: object, result: object) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error_response(request_id: object, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


if __name__ == "__main__":
    raise SystemExit(main())
