"""Tools II: Calling, Errors, Annotations & Change Notifications — S25.

Delivers the runtime half of the MCP tools feature (§16.5–§16.9): how a client
invokes a named tool with ``tools/call``, the ``CallToolResult`` it gets back,
the two-layer error model that separates *tool-execution* failures (reported
inside a successful result with ``isError: true``) from *protocol* failures
(reported as a JSON-RPC error, e.g. ``-32602``), the optional, untrusted
``ToolAnnotations`` behavioural hints, the ``notifications/tools/list_changed``
change signal, and the non-normative stateful-tools handle pattern.

Discovery (the ``tools`` capability, ``tools/list``, the ``Tool`` type, and the
JSON-Schema rules for ``inputSchema``/``outputSchema``) is owned by S24 and is
*reused* here — in particular :class:`mcp_sdk_py.tools.Tool`,
:func:`mcp_sdk_py.tools.validate_arguments_against_input_schema`,
:func:`mcp_sdk_py.tools.structured_content_conforms`, and
``METHOD_TOOLS_CALL`` / ``NOTIFICATION_TOOLS_LIST_CHANGED``. The unstructured
``content`` blocks are S21's ``ContentBlock`` union; the multi-round-trip retry
fields (``inputResponses`` / ``requestState``) and ``input_required`` outcome are
S17's machinery, applied — not re-implemented — here.

Public surface:

Method / notification names (§16.5, §16.8):
  - METHOD_TOOLS_CALL, NOTIFICATION_TOOLS_LIST_CHANGED: re-exported from S24 for
    convenience so callers need only this module.
  - JSONRPC_INVALID_PARAMS: the ``-32602`` code used for both protocol-error
    cases (R-16.6-e/f).

Request & result (§16.5):
  - CallToolRequestParams: the ``tools/call`` params — ``name`` (required),
    ``arguments``, the S17 retry fields, and ``_meta`` (R-16.5-a…k).
  - CallToolResult: ``content``, ``structuredContent``, ``isError``,
    ``resultType``, ``_meta`` (R-16.5-l…s).
  - build_input_required_retry(): build the retry params after an
    ``input_required`` result, with a fresh id (R-16.5-f…j, R-16.5-t/u).

Error model (§16.6):
  - UnknownToolError, InvalidToolArgumentsError, ToolsNotSupportedError:
    protocol errors carrying a ``json_rpc_code`` (R-16.6-d/e/f).
  - dispatch_tool_call(): the two-layer dispatch gate — raises a protocol error
    or returns the tool's ``CallToolResult`` (R-16.6-a/d).
  - tool_execution_error_result(): build the successful result that *carries* a
    tool-execution error with ``isError: true`` (R-16.6-b).
  - provide_error_to_model(): the client-side rule that tool-execution errors
    SHOULD, and protocol errors MAY, be surfaced to the model (R-16.6-c/g).

Annotations (§16.7):
  - ToolAnnotations: the five untrusted behavioural hints with their defaults
    and "meaningful only when read-only is false" semantics (R-16.7-a…e).
  - client_may_use_annotations(): the untrusted-annotations client rule
    (R-16.7-f/g).

Change notification (§16.8):
  - ToolListChangedNotification: the no-payload server-to-client signal
    (R-16.8-a/b).
  - on_tools_list_changed(): the client reaction — invalidate cache, optionally
    re-list (R-16.8-c/d).

Stateful tools (§16.9, non-normative):
  - generate_state_handle(): a high-entropy UUIDv4 bearer handle (R-16.9-c).
  - StateHandle / StateHandleRegistry: opaque, bounded-lifetime handles with
    per-call authorization validation (R-16.9-a…f).

Spec: §16.5–§16.9
Depends on: S24 (Tool, tools/call gating, schema validation), S21 (ContentBlock),
            S17 (InputRequiredResult / inputResponses / requestState).
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from mcp_sdk_py.content_types import (
  ContentBlock,
  TextContent,
  UnsupportedContentBlock,
  parse_content_block,
)
from mcp_sdk_py.multi_round_trip import InputRequest, InputRequiredResult
from mcp_sdk_py.result_error import (
  RESULT_TYPE_COMPLETE,
  RESULT_TYPE_INPUT_REQUIRED,
  ResultType,
)
from mcp_sdk_py.tools import (
  METHOD_TOOLS_CALL,
  NOTIFICATION_TOOLS_LIST_CHANGED,
  Tool,
  structured_content_conforms,
  validate_arguments_against_input_schema,
)


# ---------------------------------------------------------------------------
# §16.5 / §16.6  Method name & the protocol-error code  [R-16.6-e, R-16.6-f]
# ---------------------------------------------------------------------------

#: The JSON-RPC "Invalid params" code used for BOTH protocol-error cases of a
#: ``tools/call``: an unknown tool name (R-16.6-e) and an arguments-validation
#: failure (R-16.6-f). The full error-code registry is owned by S34; this story
#: uses ``-32602`` locally (story §5, "Out of scope").
JSONRPC_INVALID_PARAMS: int = -32602


# ---------------------------------------------------------------------------
# Protocol-error exceptions  [R-16.6-d, R-16.6-e, R-16.6-f]
# ---------------------------------------------------------------------------

class ToolCallProtocolError(Exception):
  """Base for ``tools/call`` failures reported as a JSON-RPC error, not a result.

  A protocol error means the request could not be dispatched to a tool at all,
  so it MUST be reported as a JSON-RPC ``error`` and NOT as a ``CallToolResult``
  (R-16.6-d). The two error layers MUST never be conflated (R-16.6-a): a server
  builds a JSON-RPC error response from this exception, never a result with
  ``isError``.

  Attributes:
    json_rpc_code: the wire error code a caller places in the JSON-RPC error
      object. Subclasses set it to ``-32602`` for the two §16.6 cases.
  """

  json_rpc_code: int = JSONRPC_INVALID_PARAMS

  def to_error_object(self) -> dict[str, Any]:
    """Build the JSON-RPC ``error`` member for this protocol failure (R-16.6-d).

    Returns a ``{"code", "message"}`` dict suitable as the ``error`` of a
    ``JSONRPCErrorResponse`` (S03). It is never a ``CallToolResult`` — that is
    the whole point of the two-layer model (R-16.6-a, R-16.6-d).
    """
    return {"code": self.json_rpc_code, "message": str(self)}


class UnknownToolError(ToolCallProtocolError):
  """The requested ``name`` matches no tool the server currently exposes (R-16.5-b).

  An unknown tool name MUST be reported with error code ``-32602`` (Invalid
  params) (R-16.6-e), as a JSON-RPC error rather than a ``CallToolResult``
  (R-16.6-d).

  Attributes:
    tool_name: the unmatched name from the request params.
    json_rpc_code: always ``-32602`` (R-16.6-e).
  """

  json_rpc_code: int = JSONRPC_INVALID_PARAMS

  def __init__(self, tool_name: str) -> None:
    super().__init__(
      f"Unknown tool: {tool_name!r}. The supplied name MUST match a tool the "
      f"server currently exposes; reported as JSON-RPC {JSONRPC_INVALID_PARAMS} "
      f"(R-16.5-b, R-16.6-d, R-16.6-e)"
    )
    self.tool_name: str = tool_name


class InvalidToolArgumentsError(ToolCallProtocolError):
  """The ``arguments`` object failed validation against the tool's inputSchema (R-16.5-d).

  Argument-validation failure MUST be reported with error code ``-32602``
  (Invalid params) (R-16.6-f), as a JSON-RPC error and NOT a ``CallToolResult``
  (R-16.6-d). The tool MUST NOT be invoked when arguments are invalid (AC-25.4).

  Attributes:
    tool_name: the tool whose ``inputSchema`` rejected the arguments.
    json_rpc_code: always ``-32602`` (R-16.6-f).
  """

  json_rpc_code: int = JSONRPC_INVALID_PARAMS

  def __init__(self, tool_name: str, detail: str = "") -> None:
    msg = (
      f"Invalid arguments for tool {tool_name!r}: do not conform to its "
      f"inputSchema; reported as JSON-RPC {JSONRPC_INVALID_PARAMS} "
      f"(R-16.5-d, R-16.6-d, R-16.6-f)"
    )
    if detail:
      msg = f"{msg}: {detail}"
    super().__init__(msg)
    self.tool_name: str = tool_name


class ToolsNotSupportedError(ToolCallProtocolError):
  """A ``tools/call`` reached a server that does not support tools (R-16.6-d).

  A server that does not support tools cannot dispatch the request to any tool,
  so this is a protocol error reported as a JSON-RPC error rather than a
  ``CallToolResult`` (R-16.6-d).
  """

  def __init__(self) -> None:
    super().__init__(
      "This server does not support tools; a tools/call cannot be dispatched "
      "and is reported as a JSON-RPC error, not a CallToolResult (R-16.6-d)"
    )


class MalformedCallToolRequestError(ToolCallProtocolError):
  """A ``tools/call`` request was structurally malformed (e.g. missing ``name``).

  A missing or non-string ``name`` (R-16.5-a) means the request cannot be
  dispatched, so it is a protocol error reported as a JSON-RPC error rather than
  a ``CallToolResult`` (R-16.6-d). Carried with ``-32602`` like the other
  un-dispatchable cases.
  """


# ---------------------------------------------------------------------------
# §16.5  CallToolRequest params  [R-16.5-a … R-16.5-k]
# ---------------------------------------------------------------------------

@dataclass
class CallToolRequestParams:
  """Params of a ``tools/call`` request invoking a named tool (§16.5).

  Carries the tool ``name``, an OPTIONAL ``arguments`` object, the OPTIONAL
  multi-round-trip retry fields (``inputResponses`` / ``requestState``, S17), and
  an OPTIONAL ``_meta`` map. Field names map to the exact camelCase wire keys.

  Fields:
    name: REQUIRED tool name; MUST be a non-empty string (R-16.5-a) and MUST
      match a tool the server currently exposes (R-16.5-b — checked at dispatch).
    arguments: OPTIONAL arguments object; when present it MUST validate against
      the tool's ``inputSchema`` (R-16.5-c/d). When omitted (``None``) the server
      MUST treat it as the empty object ``{}`` — see :meth:`effective_arguments`
      (R-16.5-e). Wire key: ``arguments``.
    input_responses: OPTIONAL responses to a prior ``input_required`` result; for
      each key in that result's ``inputRequests`` the same key MUST appear here
      (R-16.5-f/g, S17). Wire key: ``inputResponses``.
    request_state: OPTIONAL opaque continuation token echoed back unchanged on
      retry; a client MUST treat it as an opaque blob and MUST NOT interpret or
      modify it (R-16.5-h/i/j, S17). Wire key: ``requestState``.
    meta: OPTIONAL reserved metadata map; MAY carry e.g. a ``progressToken``
      (R-16.5-k). Wire key: ``_meta``.
  """

  name: str
  arguments: dict[str, Any] | None = None              # JSON key: arguments
  input_responses: dict[str, Any] | None = None        # JSON key: inputResponses
  request_state: str | None = None                     # JSON key: requestState
  meta: dict[str, Any] | None = None                   # JSON key: _meta

  def __post_init__(self) -> None:
    # R-16.5-a: name is REQUIRED and MUST be a non-empty string. A missing or
    # non-string name is malformed (a protocol error), not a CallToolResult.
    if not isinstance(self.name, str) or not self.name:
      raise MalformedCallToolRequestError(
        "tools/call params.name is REQUIRED and MUST be a non-empty string; "
        "a missing or non-string name is malformed and reported as a JSON-RPC "
        f"error code {JSONRPC_INVALID_PARAMS} (R-16.5-a, R-16.6-d)"
      )
    if self.arguments is not None and not isinstance(self.arguments, dict):
      raise TypeError(
        "tools/call params.arguments must be a JSON object when present "
        "(R-16.5-c)"
      )
    if self.input_responses is not None and not isinstance(self.input_responses, dict):
      raise TypeError(
        "tools/call params.inputResponses must be a JSON object when present "
        "(R-16.5-f)"
      )
    # R-16.5-i/j: requestState is an opaque blob — only the string type is
    # checked; the value is never parsed, derived from, or mutated here.
    if self.request_state is not None and not isinstance(self.request_state, str):
      raise TypeError(
        "tools/call params.requestState must be an opaque string when present "
        "(R-16.5-h, R-16.5-i)"
      )
    if self.meta is not None and not isinstance(self.meta, dict):
      raise TypeError(
        "tools/call params._meta must be a JSON object when present (R-16.5-k)"
      )

  @property
  def effective_arguments(self) -> dict[str, Any]:
    """The arguments object, treating an omitted ``arguments`` as ``{}`` (R-16.5-e).

    When ``arguments`` is absent the server MUST treat it as the empty object
    ``{}``; this property is what dispatch validates and passes to the tool, so a
    no-argument call behaves identically to an explicit ``{}``.
    """
    return self.arguments if self.arguments is not None else {}

  @property
  def is_retry(self) -> bool:
    """True when this call is a retry of a prior ``input_required`` result (S17).

    A retry carries ``inputResponses`` and/or ``requestState`` (R-16.5-f/h). The
    retry MUST use a fresh JSON-RPC ``id`` (R-16.5-u) — enforced where the
    envelope is built, see :func:`build_input_required_retry`.
    """
    return self.input_responses is not None or self.request_state is not None

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> CallToolRequestParams:
    """Parse ``tools/call`` request params from a wire dict (§16.5).

    Validates that ``name`` is a present non-empty string (R-16.5-a); maps the
    camelCase wire keys ``arguments``/``inputResponses``/``requestState``/``_meta``
    onto the dataclass fields. Unknown top-level keys are ignored for forward
    compatibility.

    Raises:
      MalformedCallToolRequestError: ``name`` is absent, empty, or not a string
        (a protocol error, code ``-32602``; R-16.5-a, R-16.6-d).
      TypeError: ``data`` or a field has the wrong JSON type.
    """
    if not isinstance(data, dict):
      raise TypeError(
        f"tools/call params must be a JSON object; got {type(data).__name__}"
      )
    if "name" not in data:
      raise MalformedCallToolRequestError(
        "tools/call params.name is REQUIRED; it was absent — malformed request "
        f"reported as JSON-RPC error code {JSONRPC_INVALID_PARAMS} "
        "(R-16.5-a, R-16.6-d)"
      )
    return cls(
      name=data["name"],
      arguments=data.get("arguments"),
      input_responses=data.get("inputResponses"),
      request_state=data.get("requestState"),
      meta=data.get("_meta"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire-compatible dict; omits absent optional fields.

    ``name`` is always present (REQUIRED); ``arguments``, ``inputResponses``,
    ``requestState``, and ``_meta`` appear only when set. ``requestState`` is
    emitted byte-for-byte unchanged (R-16.5-i).
    """
    out: dict[str, Any] = {"name": self.name}
    if self.arguments is not None:
      out["arguments"] = self.arguments
    if self.input_responses is not None:
      out["inputResponses"] = self.input_responses
    if self.request_state is not None:
      out["requestState"] = self.request_state
    if self.meta is not None:
      out["_meta"] = self.meta
    return out


# ---------------------------------------------------------------------------
# §16.5  CallToolResult  [R-16.5-l … R-16.5-s]
# ---------------------------------------------------------------------------

#: Sentinel distinguishing "structuredContent absent" from "present and null"
#: (R-16.5-n permits an explicit ``null`` structured value).
_STRUCTURED_UNSET: object = object()


@dataclass
class CallToolResult:
  """Result of a successfully dispatched ``tools/call`` (a JSON-RPC result) (§16.5).

  Returned whether the tool succeeded, failed at execution (``isError: true``),
  or paused for input — it is always a JSON-RPC ``result``, never a JSON-RPC
  ``error`` (R-16.6-a/b/d). Field names map to the exact camelCase wire keys.

  Fields:
    content: REQUIRED array of ``ContentBlock``s (S21) carrying the unstructured
      result; MAY be empty and MAY mix block types (R-16.5-l/m).
    structured_content: OPTIONAL structured result; MAY be ANY JSON value —
      object, array, string, number, boolean, or ``null`` — and is explicitly NOT
      restricted to objects (R-16.5-n). Required and schema-conforming when the
      tool declares an ``outputSchema`` (R-16.5-o); pass it explicitly (even as
      ``None``) to emit it. Wire key: ``structuredContent``.
    is_error: OPTIONAL; whether the call ended in a tool-execution error. Absent
      ⇒ ``False`` (success) — see :attr:`ended_in_error` (R-16.5-q). Wire key:
      ``isError``.
    result_type: REQUIRED discriminator; ``"complete"`` for a finished call or
      ``"input_required"`` for a paused multi-round-trip call (R-16.5-r, §3).
      Wire key: ``resultType``.
    meta: OPTIONAL reserved metadata map (R-16.5-s). Wire key: ``_meta``.
  """

  content: list[ContentBlock]
  structured_content: Any = field(default=_STRUCTURED_UNSET)   # JSON: structuredContent
  is_error: bool | None = None                                 # JSON: isError
  result_type: ResultType = RESULT_TYPE_COMPLETE               # JSON: resultType
  meta: dict[str, Any] | None = None                           # JSON: _meta

  def __post_init__(self) -> None:
    # R-16.5-l: content is REQUIRED and is an array of ContentBlocks. R-16.5-m:
    # it MAY be empty and MAY mix block types — so only the array-of-blocks
    # shape is enforced, never a minimum length or single-type rule.
    if not isinstance(self.content, list):
      raise TypeError(
        "CallToolResult.content is REQUIRED and must be an array of "
        "ContentBlocks (R-16.5-l)"
      )
    for block in self.content:
      if not _is_content_block(block):
        raise TypeError(
          f"CallToolResult.content entries must be ContentBlock objects; got "
          f"{block!r} (R-16.5-l)"
        )
    # R-16.5-q: isError is OPTIONAL; only the boolean type is checked when set.
    if self.is_error is not None and not isinstance(self.is_error, bool):
      raise TypeError("CallToolResult.isError must be a boolean when present (R-16.5-q)")
    # R-16.5-r: resultType is REQUIRED and MUST be exactly "complete" or
    # "input_required"; any other value is rejected, not silently accepted.
    if self.result_type not in (RESULT_TYPE_COMPLETE, RESULT_TYPE_INPUT_REQUIRED):
      raise ValueError(
        f"CallToolResult.resultType is REQUIRED and MUST be "
        f"{RESULT_TYPE_COMPLETE!r} or {RESULT_TYPE_INPUT_REQUIRED!r}; got "
        f"{self.result_type!r} (R-16.5-r)"
      )
    if self.meta is not None and not isinstance(self.meta, dict):
      raise TypeError("CallToolResult._meta must be a JSON object when present (R-16.5-s)")

  @property
  def has_structured_content(self) -> bool:
    """True when ``structuredContent`` was provided (even as an explicit ``null``).

    Distinguishes an omitted ``structuredContent`` from one explicitly set to
    ``null`` — both are valid (R-16.5-n) but only a provided value is emitted.
    """
    return self.structured_content is not _STRUCTURED_UNSET

  @property
  def ended_in_error(self) -> bool:
    """Whether the call ended in a tool-execution error; absent ⇒ ``False`` (R-16.5-q).

    Implements the "absent ⇒ false (success)" rule: an absent or ``False``
    ``isError`` is success; only an explicit ``True`` is an execution error
    (R-16.5-q, AC-25.13).
    """
    return self.is_error is True

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> CallToolResult:
    """Parse a wire ``CallToolResult`` (§16.5).

    Validates that ``content`` is a present array (R-16.5-l), parses each block
    via :func:`mcp_sdk_py.content_types.parse_content_block` (an unknown block
    type becomes an ``UnsupportedContentBlock`` rather than failing the whole
    result, S21), preserves an explicit ``structuredContent: null`` distinctly
    from an absent one (R-16.5-n), and requires ``resultType`` (R-16.5-r).

    Raises:
      TypeError / ValueError: ``content`` or ``resultType`` is absent or has the
        wrong type/value.
    """
    if not isinstance(data, dict):
      raise TypeError(
        f"CallToolResult must be a JSON object; got {type(data).__name__}"
      )
    if "content" not in data:
      raise ValueError("CallToolResult.content is REQUIRED (R-16.5-l)")
    raw_content = data["content"]
    if not isinstance(raw_content, list):
      raise TypeError("CallToolResult.content must be an array (R-16.5-l)")
    content = [parse_content_block(block) for block in raw_content]

    if "resultType" not in data:
      raise ValueError("CallToolResult.resultType is REQUIRED (R-16.5-r)")

    structured = (
      data["structuredContent"]
      if "structuredContent" in data
      else _STRUCTURED_UNSET
    )
    return cls(
      content=content,
      structured_content=structured,
      is_error=data.get("isError"),
      result_type=data["resultType"],
      meta=data.get("_meta"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire-compatible dict; omits absent optional fields.

    ``resultType`` and ``content`` are always present (both REQUIRED).
    ``structuredContent`` is emitted only when provided (preserving an explicit
    ``null``, R-16.5-n); ``isError`` only when set; ``_meta`` only when present.
    """
    out: dict[str, Any] = {
      "resultType": self.result_type,
      "content": [_content_to_dict(block) for block in self.content],
    }
    if self.has_structured_content:
      out["structuredContent"] = self.structured_content
    if self.is_error is not None:
      out["isError"] = self.is_error
    if self.meta is not None:
      out["_meta"] = self.meta
    return out


def _is_content_block(block: Any) -> bool:
  """True if ``block`` is a recognised ContentBlock member or an unsupported one.

  Accepts the five S21 ``ContentBlock`` members and the
  ``UnsupportedContentBlock`` sentinel (so a parsed-but-unknown block does not
  fail the enclosing result, R-14.4-b) (R-16.5-l).
  """
  return isinstance(block, ContentBlock.__args__) or isinstance(
    block, UnsupportedContentBlock
  )


def _content_to_dict(block: Any) -> dict[str, Any]:
  """Serialise one content block; pass through an unsupported block's raw form."""
  if isinstance(block, UnsupportedContentBlock):
    return block.raw
  return block.to_dict()


# ---------------------------------------------------------------------------
# §16.5  Structured output with a declared outputSchema  [R-16.5-o, R-16.5-p]
# ---------------------------------------------------------------------------

def build_structured_tool_result(
  tool: Tool,
  structured_content: Any,
  *,
  is_error: bool | None = None,
  meta: dict[str, Any] | None = None,
) -> CallToolResult:
  """Build a ``CallToolResult`` for a tool that declares an ``outputSchema`` (R-16.5-o/p).

  When the tool declares an ``outputSchema`` the server MUST populate
  ``structuredContent`` with a value conforming to that schema (R-16.5-o) and
  SHOULD also provide a textual ``content`` fallback carrying the JSON
  serialization of the structured value, for clients that do not consume
  structured content (R-16.5-p). This helper enforces conformance (raising on a
  non-conforming value) and synthesises the SHOULD-level text fallback so the
  result satisfies both rules.

  Args:
    tool: the invoked tool; its ``outputSchema`` governs ``structuredContent``.
    structured_content: the structured result value to validate and embed.
    is_error: optional ``isError`` to set on the result.
    meta: optional ``_meta`` map.

  Returns:
    A ``complete`` ``CallToolResult`` carrying the structured value plus a single
    ``text`` fallback block (R-16.5-p).

  Raises:
    ValueError: the tool declares an ``outputSchema`` but ``structured_content``
      does not conform to it (R-16.5-o).
  """
  if tool.output_schema is not None and not structured_content_conforms(
    tool, structured_content
  ):
    raise ValueError(
      f"structuredContent does not conform to tool {tool.name!r}'s outputSchema; "
      f"a server MUST populate it with a conforming value (R-16.5-o)"
    )
  # R-16.5-p: provide a textual content fallback serialising the structured value.
  fallback = TextContent(text=json.dumps(structured_content, sort_keys=True))
  return CallToolResult(
    content=[fallback],
    structured_content=structured_content,
    is_error=is_error,
    result_type=RESULT_TYPE_COMPLETE,
    meta=meta,
  )


def structured_output_is_valid(tool: Tool, result: CallToolResult) -> bool:
  """Validate a result's ``structuredContent`` against a declared ``outputSchema`` (R-16.5-o).

  When the tool declares an ``outputSchema`` a conforming result MUST carry a
  ``structuredContent`` value that conforms to it (R-16.5-o); an absent or
  non-conforming structured value is invalid. When the tool declares no
  ``outputSchema`` there is nothing to enforce and this returns True
  (``structuredContent`` is then any-JSON-or-absent, R-16.5-n).

  Returns:
    True iff the result satisfies the outputSchema obligation for this tool.
  """
  if tool.output_schema is None:
    return True
  if not result.has_structured_content:
    return False  # R-16.5-o: structuredContent MUST be present when declared.
  return structured_content_conforms(tool, result.structured_content)


# ---------------------------------------------------------------------------
# §16.6  Two-layer error model: dispatch & tool-execution errors
#         [R-16.6-a, R-16.6-b, R-16.6-c, R-16.6-d, R-16.6-e, R-16.6-f, R-16.6-g]
# ---------------------------------------------------------------------------

def dispatch_tool_call(
  params: CallToolRequestParams,
  available_tools: dict[str, Tool],
  *,
  tools_supported: bool = True,
) -> Tool:
  """Resolve a ``tools/call`` to its target tool or raise a protocol error (R-16.6-a/d).

  Implements the dispatch gate of the two-layer error model: it decides whether
  the request can be dispatched to a tool at all. A failure here is a *protocol*
  error (raised, to be turned into a JSON-RPC ``error``), never a
  ``CallToolResult`` (R-16.6-a, R-16.6-d). On success the resolved :class:`Tool`
  is returned and the caller runs it — any failure *inside* the tool is the other
  layer and is reported via :func:`tool_execution_error_result` instead.

  Checks, in order:
    - the server supports tools, else :class:`ToolsNotSupportedError` (R-16.6-d);
    - ``name`` matches a currently-exposed tool, else :class:`UnknownToolError`
      with code ``-32602`` (R-16.5-b, R-16.6-e);
    - the effective arguments (omitted ⇒ ``{}``, R-16.5-e) validate against the
      tool's ``inputSchema``, else :class:`InvalidToolArgumentsError` with code
      ``-32602`` and the tool is NOT invoked (R-16.5-d, R-16.6-f, AC-25.4).

  Args:
    params: the parsed ``tools/call`` params.
    available_tools: the tools the server currently exposes, keyed by name.
    tools_supported: False models a server that does not support tools.

  Returns:
    The resolved :class:`Tool` the caller should execute.

  Raises:
    ToolsNotSupportedError / UnknownToolError / InvalidToolArgumentsError: the
      request cannot be dispatched (all carry ``json_rpc_code`` ``-32602`` except
      where noted) (R-16.6-d/e/f).
  """
  # R-16.6-d: a server that does not support tools cannot dispatch the call.
  if not tools_supported:
    raise ToolsNotSupportedError()

  # R-16.5-b, R-16.6-e: the name MUST match a currently-exposed tool.
  tool = available_tools.get(params.name)
  if tool is None:
    raise UnknownToolError(params.name)

  # R-16.5-d, R-16.6-f: arguments (omitted ⇒ {}, R-16.5-e) MUST validate against
  # the tool's inputSchema; on failure the tool MUST NOT be invoked.
  if not validate_arguments_against_input_schema(tool, params.effective_arguments):
    raise InvalidToolArgumentsError(params.name)
  return tool


def tool_execution_error_result(
  message: str,
  *,
  extra_content: list[ContentBlock] | None = None,
  structured_content: Any = _STRUCTURED_UNSET,
  meta: dict[str, Any] | None = None,
) -> CallToolResult:
  """Build the successful result that *carries* a tool-execution error (R-16.6-b).

  A tool-execution error (the call reached the tool but the tool itself failed —
  upstream failure, semantically-invalid-but-well-formed input, business-logic
  failure) MUST be reported inside a normal successful ``CallToolResult`` (a
  JSON-RPC result, NOT a JSON-RPC error) with ``isError: true`` and a human- and
  model-readable explanation in ``content`` (R-16.6-b). This is the opposite
  layer from :func:`dispatch_tool_call`'s protocol errors; the two MUST NOT be
  conflated (R-16.6-a).

  Args:
    message: the human- and model-readable explanation placed in a ``text``
      block (R-16.6-b).
    extra_content: optional additional content blocks appended after the message.
    structured_content: optional structured value (e.g. a machine-readable error
      payload); preserves an explicit ``null`` distinctly from absent.
    meta: optional ``_meta`` map.

  Returns:
    A ``complete`` ``CallToolResult`` with ``isError: True`` and the explanation
    in ``content``.
  """
  content: list[ContentBlock] = [TextContent(text=message)]
  if extra_content:
    content.extend(extra_content)
  return CallToolResult(
    content=content,
    structured_content=structured_content,
    is_error=True,
    result_type=RESULT_TYPE_COMPLETE,
    meta=meta,
  )


def provide_error_to_model(*, is_tool_execution_error: bool) -> bool:
  """Whether a client surfaces a tool error to the language model (R-16.6-c/g).

  Captures the two client-side rules: a client SHOULD provide *tool-execution*
  errors to the model to enable self-correction (R-16.6-c), and a client MAY
  surface *protocol* errors to the model though they are less likely to recover
  (R-16.6-g). A conforming client passes ``is_tool_execution_error=True`` for an
  ``isError: true`` result (returns True, the SHOULD) and may choose either for a
  protocol error (this returns True to model the permitted MAY).

  Args:
    is_tool_execution_error: True for an ``isError: true`` ``CallToolResult``;
      False for a JSON-RPC protocol error.

  Returns:
    True when the error is provided to the model. Always True for a tool-execution
    error (the SHOULD, R-16.6-c); True here for a protocol error to model the MAY
    permission (R-16.6-g) — a client MAY instead suppress it.
  """
  if is_tool_execution_error:
    return True  # R-16.6-c: SHOULD provide tool-execution errors to the model.
  return True    # R-16.6-g: MAY surface protocol errors; this models the choice.


# ---------------------------------------------------------------------------
# §16.5 / §16.6  Distinguishing the two layers  [R-16.6-a]
# ---------------------------------------------------------------------------

def is_tool_execution_error(result: CallToolResult) -> bool:
  """True iff a ``CallToolResult`` reports a tool-execution error (R-16.6-a/b).

  A tool-execution error is a JSON-RPC *result* with ``isError: true``; it is
  structurally distinct from a JSON-RPC *error* (a :class:`ToolCallProtocolError`
  turned into an error response). Keeping these on separate types is how the SDK
  guarantees the two layers are never conflated (R-16.6-a).
  """
  return result.ended_in_error


# ---------------------------------------------------------------------------
# §16.5 / §11  input_required retry construction  [R-16.5-f … R-16.5-j, R-16.5-t/u]
# ---------------------------------------------------------------------------

def build_input_required_retry(
  original: CallToolRequestParams,
  prior: InputRequiredResult,
  input_responses: dict[str, Any],
  *,
  meta: dict[str, Any] | None = None,
) -> CallToolRequestParams:
  """Build the retry params after an ``input_required`` result (R-16.5-f…j, R-16.5-t).

  After a ``tools/call`` returns ``resultType: "input_required"`` carrying
  ``inputRequests`` and/or ``requestState``, the client gathers the requested
  input and retries the same tool with ``inputResponses`` and ``requestState``
  set (R-16.5-t, S17). This builds those retry params and enforces the rules:

    - the same ``name`` as the original call is used;
    - for each key present in ``prior.inputRequests`` the same key MUST appear in
      ``input_responses`` with its response, else ``ValueError`` (R-16.5-g);
    - ``requestState`` from ``prior`` is echoed back byte-for-byte unchanged — it
      is never parsed, derived from, or mutated (R-16.5-h/i/j).

  The JSON-RPC ``id`` of the retry MUST differ from the initial request's id
  (R-16.5-u); the ``id`` lives on the envelope (S03), so this returns only the
  params — see :func:`retry_id_is_distinct` for that check.

  Args:
    original: the params of the initial ``tools/call``.
    prior: the server's ``input_required`` result.
    input_responses: the gathered responses keyed by the prior ``inputRequests``.
    meta: optional ``_meta`` for the retry (e.g. a fresh ``progressToken``).

  Returns:
    The retry :class:`CallToolRequestParams` with ``inputResponses`` and the
    echoed ``requestState`` set.

  Raises:
    ValueError: a key from ``prior.inputRequests`` is missing in
      ``input_responses`` (R-16.5-g).
  """
  requested: dict[str, InputRequest] = prior.input_requests or {}
  # R-16.5-g: every requested key MUST be answered in inputResponses.
  missing = [key for key in requested if key not in input_responses]
  if missing:
    raise ValueError(
      f"inputResponses is missing required keys from the prior inputRequests: "
      f"{sorted(missing)!r}; each requested key MUST be answered (R-16.5-g)"
    )
  return CallToolRequestParams(
    name=original.name,
    # R-16.5-h/i/j: echo requestState back unchanged — never parsed or mutated.
    request_state=prior.request_state,
    input_responses=dict(input_responses),
    meta=meta if meta is not None else original.meta,
  )


def retry_id_is_distinct(initial_id: Any, retry_id: Any) -> bool:
  """True iff a retry's JSON-RPC ``id`` differs from the initial request's (R-16.5-u).

  On retry after an ``input_required`` result the JSON-RPC ``id`` MUST differ
  from the ``id`` of the initial request (R-16.5-u, S17). This compares the two
  ids by JSON value: a retry that reused the original id (returns False) violates
  the rule.
  """
  return initial_id != retry_id


# ---------------------------------------------------------------------------
# §16.7  ToolAnnotations  [R-16.7-a … R-16.7-g]
# ---------------------------------------------------------------------------

#: Default for ``readOnlyHint`` when the field is absent (R-16.7-b).
DEFAULT_READ_ONLY_HINT: bool = False
#: Default for ``destructiveHint`` when the field is absent (R-16.7-c).
DEFAULT_DESTRUCTIVE_HINT: bool = True
#: Default for ``idempotentHint`` when the field is absent (R-16.7-d).
DEFAULT_IDEMPOTENT_HINT: bool = False
#: Default for ``openWorldHint`` when the field is absent (R-16.7-e).
DEFAULT_OPEN_WORLD_HINT: bool = True


@dataclass
class ToolAnnotations:
  """Optional, untrusted behavioural hints about a tool (§16.7).

  All properties are HINTS — not guaranteed faithful descriptions of behaviour,
  including ``title`` — so a client MUST treat them as untrusted and MUST NOT
  base tool-use or safety decisions on annotations from an untrusted server
  (R-16.7-f/g; see :func:`client_may_use_annotations`). Attached to a ``Tool``
  (S24) as its ``annotations`` object.

  Fields (each OPTIONAL with the documented default; absence is meaningful):
    title: human-readable display title; ranks after the tool's ``title`` and
      before ``name`` in display precedence (R-16.7-a, §16.3).
    read_only_hint: if ``True`` the tool does not modify its environment; default
      ``False`` when absent (R-16.7-b). Wire key: ``readOnlyHint``.
    destructive_hint: if ``True`` the tool MAY perform destructive updates, if
      ``False`` only additive; default ``True``; meaningful only when
      ``read_only_hint`` is ``False`` (R-16.7-c). Wire key: ``destructiveHint``.
    idempotent_hint: if ``True`` repeated same-argument calls have no additional
      effect beyond the first; default ``False``; meaningful only when
      ``read_only_hint`` is ``False`` (R-16.7-d). Wire key: ``idempotentHint``.
    open_world_hint: if ``True`` the tool MAY interact with an open world of
      external entities, if ``False`` its interaction domain is closed; default
      ``True`` (R-16.7-e). Wire key: ``openWorldHint``.

  The fields default to ``None`` (absent on the wire); the ``effective_*``
  properties apply the documented defaults so a reader gets the right value
  whether or not the hint was sent.
  """

  title: str | None = None
  read_only_hint: bool | None = None        # JSON key: readOnlyHint
  destructive_hint: bool | None = None      # JSON key: destructiveHint
  idempotent_hint: bool | None = None       # JSON key: idempotentHint
  open_world_hint: bool | None = None       # JSON key: openWorldHint

  def __post_init__(self) -> None:
    if self.title is not None and not isinstance(self.title, str):
      raise TypeError("ToolAnnotations.title must be a string when present (R-16.7-a)")
    for name, value in (
      ("readOnlyHint", self.read_only_hint),
      ("destructiveHint", self.destructive_hint),
      ("idempotentHint", self.idempotent_hint),
      ("openWorldHint", self.open_world_hint),
    ):
      if value is not None and not isinstance(value, bool):
        raise TypeError(
          f"ToolAnnotations.{name} must be a boolean when present (R-16.7-b…e)"
        )

  @property
  def effective_read_only_hint(self) -> bool:
    """``readOnlyHint`` with its default applied: absent ⇒ ``False`` (R-16.7-b)."""
    return self.read_only_hint if self.read_only_hint is not None else DEFAULT_READ_ONLY_HINT

  @property
  def effective_destructive_hint(self) -> bool:
    """``destructiveHint`` with its default applied: absent ⇒ ``True`` (R-16.7-c)."""
    return (
      self.destructive_hint
      if self.destructive_hint is not None
      else DEFAULT_DESTRUCTIVE_HINT
    )

  @property
  def effective_idempotent_hint(self) -> bool:
    """``idempotentHint`` with its default applied: absent ⇒ ``False`` (R-16.7-d)."""
    return (
      self.idempotent_hint
      if self.idempotent_hint is not None
      else DEFAULT_IDEMPOTENT_HINT
    )

  @property
  def effective_open_world_hint(self) -> bool:
    """``openWorldHint`` with its default applied: absent ⇒ ``True`` (R-16.7-e)."""
    return (
      self.open_world_hint
      if self.open_world_hint is not None
      else DEFAULT_OPEN_WORLD_HINT
    )

  @property
  def destructive_hint_is_meaningful(self) -> bool:
    """True only when ``destructiveHint`` is meaningful — i.e. not read-only (R-16.7-c)."""
    return not self.effective_read_only_hint

  @property
  def idempotent_hint_is_meaningful(self) -> bool:
    """True only when ``idempotentHint`` is meaningful — i.e. not read-only (R-16.7-d)."""
    return not self.effective_read_only_hint

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> ToolAnnotations:
    """Parse a wire ``ToolAnnotations`` object (§16.7).

    Maps the camelCase wire keys onto the dataclass fields; an absent hint stays
    ``None`` so the ``effective_*`` properties supply the documented default.
    Unknown keys are ignored for forward compatibility.

    Raises:
      TypeError: ``data`` is not an object, or a field has the wrong JSON type.
    """
    if not isinstance(data, dict):
      raise TypeError(
        f"ToolAnnotations must be a JSON object; got {type(data).__name__}"
      )
    return cls(
      title=data.get("title"),
      read_only_hint=data.get("readOnlyHint"),
      destructive_hint=data.get("destructiveHint"),
      idempotent_hint=data.get("idempotentHint"),
      open_world_hint=data.get("openWorldHint"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire-compatible dict; omits absent hints.

    Only hints that were explicitly set are emitted; an omitted hint relies on
    the reader applying the documented default (R-16.7-b…e).
    """
    out: dict[str, Any] = {}
    if self.title is not None:
      out["title"] = self.title
    if self.read_only_hint is not None:
      out["readOnlyHint"] = self.read_only_hint
    if self.destructive_hint is not None:
      out["destructiveHint"] = self.destructive_hint
    if self.idempotent_hint is not None:
      out["idempotentHint"] = self.idempotent_hint
    if self.open_world_hint is not None:
      out["openWorldHint"] = self.open_world_hint
    return out


def client_may_use_annotations(*, server_is_trusted: bool) -> bool:
  """Whether a client may base tool-use/safety decisions on annotations (R-16.7-f/g).

  A client MUST treat tool annotations as untrusted (R-16.7-f) and MUST NOT make
  tool-use or safety decisions based on annotations received from a server it
  does not trust (R-16.7-g). This returns ``True`` only when the server is
  trusted; for an untrusted server it returns ``False`` and a conforming client
  MUST ignore the annotations for any such decision (it MAY still use them for
  presentation, just like other untrusted hints).

  Args:
    server_is_trusted: whether the client trusts the originating server.

  Returns:
    True iff the client may rely on the annotations for tool-use/safety decisions.
  """
  return server_is_trusted


# ---------------------------------------------------------------------------
# §16.8  notifications/tools/list_changed  [R-16.8-a … R-16.8-d]
# ---------------------------------------------------------------------------

@dataclass
class ToolListChangedNotification:
  """The ``notifications/tools/list_changed`` server-to-client signal (§16.8).

  When the set of available tools changes, a server that declared
  ``tools.listChanged: true`` (S24/§16.1) SHOULD send this to subscribed clients
  receiving server-to-client messages (R-16.8-a). It carries no required payload
  and MAY be issued without any prior explicit subscription request (R-16.8-b).

  Fields:
    params: OPTIONAL params object; no required payload, MAY carry ``_meta`` and
      additional keys (R-16.8-b). ``None`` means the notification has no params.
  """

  #: The exact, case-sensitive notification method name (re-exported from S24).
  method: str = field(default=NOTIFICATION_TOOLS_LIST_CHANGED, init=False)
  params: dict[str, Any] | None = None

  def __post_init__(self) -> None:
    if self.params is not None and not isinstance(self.params, dict):
      raise TypeError(
        "ToolListChangedNotification.params must be a JSON object when present "
        "(R-16.8-b)"
      )

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> ToolListChangedNotification:
    """Parse a wire ``notifications/tools/list_changed`` message (§16.8).

    Validates the ``method`` is exactly ``notifications/tools/list_changed`` when
    present (case-sensitive); ``params`` is optional with no required payload
    (R-16.8-b).

    Raises:
      ValueError: ``method`` is present but not the expected notification name.
      TypeError: ``params`` is present but not an object.
    """
    if not isinstance(data, dict):
      raise TypeError(
        f"ToolListChangedNotification must be a JSON object; got "
        f"{type(data).__name__}"
      )
    method = data.get("method", NOTIFICATION_TOOLS_LIST_CHANGED)
    if method != NOTIFICATION_TOOLS_LIST_CHANGED:
      raise ValueError(
        f"method must be {NOTIFICATION_TOOLS_LIST_CHANGED!r}; got {method!r} "
        f"(R-16.8-a)"
      )
    return cls(params=data.get("params"))

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire-compatible notification body; omits absent ``params``.

    ``method`` is always present; ``params`` appears only when set (the
    notification carries no required payload, R-16.8-b).
    """
    out: dict[str, Any] = {"method": self.method}
    if self.params is not None:
      out["params"] = self.params
    return out


@dataclass
class ToolListCacheReaction:
  """The outcome of a client's reaction to ``notifications/tools/list_changed`` (R-16.8-c/d).

  Fields:
    cache_invalidated: True when the client invalidated its cached tool list — a
      client SHOULD do this on receiving the notification (R-16.8-c).
    should_relist: True when the client elects to issue a fresh ``tools/list`` to
      obtain the updated set — a client MAY do this (R-16.8-d).
  """

  cache_invalidated: bool
  should_relist: bool


def on_tools_list_changed(*, relist: bool = False) -> ToolListCacheReaction:
  """Compute a client's reaction to ``notifications/tools/list_changed`` (R-16.8-c/d).

  On receiving the notification a client SHOULD invalidate any cached tool list
  (R-16.8-c) and MAY issue a fresh ``tools/list`` request to obtain the updated
  set (R-16.8-d). This always reports the cache as invalidated (the SHOULD) and
  reflects the caller's MAY-level choice to re-list.

  Args:
    relist: whether the client elects to re-issue ``tools/list`` (R-16.8-d).

  Returns:
    A :class:`ToolListCacheReaction` recording the invalidation and re-list
    decision.
  """
  return ToolListCacheReaction(cache_invalidated=True, should_relist=relist)


# ---------------------------------------------------------------------------
# §16.9  Stateful tools (non-normative guidance)  [R-16.9-a … R-16.9-f]
# ---------------------------------------------------------------------------

def generate_state_handle() -> str:
  """Generate a high-entropy, opaque bearer state handle (R-16.9-c/d).

  For an unauthenticated server the handle is necessarily a bearer token, so it
  SHOULD be generated with sufficient entropy — a UUIDv4 is the spec's example
  (R-16.9-c) — and SHOULD be opaque so it does not invite parsing or guessing
  (R-16.9-d). Returns a fresh random UUIDv4 string.
  """
  return str(uuid.uuid4())


class StateHandleExpiredError(Exception):
  """A stateful-tool handle is expired or unknown (R-16.9-f).

  A call against an expired or unknown handle SHOULD be answered with a
  *tool-execution* error (§16.6) describing the condition so the model can
  recover by creating new state (R-16.9-f) — see
  :func:`expired_or_unknown_handle_result`. This exception is the internal
  signal a registry raises; it is reported on the wire as an ``isError: true``
  result, NOT a JSON-RPC error.
  """


class StateHandleAuthorizationError(Exception):
  """The caller is not authorised for a stateful-tool handle (R-16.9-b).

  For an authenticated server a handle is a name and not a capability, so the
  server SHOULD validate the caller's authorization against the handle on every
  call (R-16.9-b). This is raised when that check fails.
  """


@dataclass
class StateHandle:
  """An opaque, bounded-lifetime server-issued state handle (§16.9, non-normative).

  Models the recommended stateful-tool pattern: a creation tool returns an
  explicit handle that later tool calls pass as an ordinary argument, instead of
  relying on connection identity (R-16.9-a). The handle value is opaque
  (R-16.9-d) and, for an unauthenticated server, has a bounded lifetime
  (R-16.9-c).

  Fields:
    value: the opaque handle string (a UUIDv4 by default, R-16.9-c/d).
    owner: optional principal the handle belongs to; checked on every call for an
      authenticated server (R-16.9-b).
    expires_at: optional monotonic-clock deadline (seconds) after which the
      handle is expired; ``None`` means no bounded lifetime (R-16.9-c).
    payload: server-defined state associated with the handle.
  """

  value: str
  owner: str | None = None
  expires_at: float | None = None
  payload: Any = None

  def is_expired(self, *, now: float | None = None) -> bool:
    """True when the handle has passed its bounded-lifetime deadline (R-16.9-c).

    Uses a monotonic clock so wall-clock changes cannot extend a handle's life. A
    handle with no ``expires_at`` never expires by time alone.
    """
    if self.expires_at is None:
      return False
    current = now if now is not None else time.monotonic()
    return current >= self.expires_at


class StateHandleRegistry:
  """A registry of opaque, bounded-lifetime stateful-tool handles (§16.9, R-16.9-a…f).

  Implements the non-normative stateful-tools recommendations as a reusable
  primitive: a creation tool issues a handle (:meth:`issue`) and later calls
  resolve it (:meth:`resolve`), with per-call authorization validation
  (R-16.9-b), bounded lifetime (R-16.9-c), opaque high-entropy values
  (R-16.9-c/d), and an expired/unknown handle surfaced as a tool-execution error
  (R-16.9-f). The protocol defines no per-connection session, so a handle is just
  an ordinary string here, exactly as the spec describes (§16.9).
  """

  def __init__(self, *, default_ttl_seconds: float | None = None) -> None:
    """Create a registry.

    Args:
      default_ttl_seconds: optional bounded lifetime applied to issued handles
        when ``ttl_seconds`` is not given to :meth:`issue` (R-16.9-c). ``None``
        means issued handles do not expire by time unless a per-call TTL is given.
    """
    self._handles: dict[str, StateHandle] = {}
    self._default_ttl_seconds: float | None = default_ttl_seconds

  def issue(
    self,
    *,
    owner: str | None = None,
    payload: Any = None,
    ttl_seconds: float | None = None,
    now: float | None = None,
  ) -> StateHandle:
    """Issue a fresh opaque handle, optionally with an owner and bounded lifetime.

    The handle value is a high-entropy UUIDv4 (R-16.9-c) and opaque (R-16.9-d);
    when a TTL applies the handle expires after that many seconds (R-16.9-c). The
    handle is the value a creation tool returns and later calls pass back as an
    argument (R-16.9-a).

    Args:
      owner: principal the handle belongs to (for the R-16.9-b auth check).
      payload: server state to associate with the handle.
      ttl_seconds: per-handle bounded lifetime; falls back to the registry default.
      now: monotonic-clock override (for tests); defaults to ``time.monotonic()``.

    Returns:
      The newly issued :class:`StateHandle`.
    """
    ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl_seconds
    expires_at: float | None = None
    if ttl is not None:
      current = now if now is not None else time.monotonic()
      expires_at = current + ttl
    handle = StateHandle(
      value=generate_state_handle(),
      owner=owner,
      expires_at=expires_at,
      payload=payload,
    )
    self._handles[handle.value] = handle
    return handle

  def resolve(
    self,
    value: str,
    *,
    caller: str | None = None,
    now: float | None = None,
  ) -> StateHandle:
    """Resolve a handle for a call, enforcing expiry and authorization (R-16.9-b/c/f).

    A call against an expired or unknown handle raises
    :class:`StateHandleExpiredError` so the caller can report a tool-execution
    error (R-16.9-f). When the handle has an ``owner`` the ``caller`` MUST match
    it on every call, else :class:`StateHandleAuthorizationError` (R-16.9-b). An
    expired handle is also evicted so it cannot be guessed back into existence.

    Args:
      value: the opaque handle string presented on the call.
      caller: the calling principal, validated against ``handle.owner``.
      now: monotonic-clock override (for tests).

    Returns:
      The live :class:`StateHandle`.

    Raises:
      StateHandleExpiredError: the handle is unknown or expired (R-16.9-f).
      StateHandleAuthorizationError: the caller is not the handle's owner
        (R-16.9-b).
    """
    handle = self._handles.get(value)
    if handle is None:
      raise StateHandleExpiredError(
        "Unknown state handle; it may never have existed or was already evicted "
        "(R-16.9-f)"
      )
    if handle.is_expired(now=now):
      # Evict so a stale value cannot be resolved later (R-16.9-c).
      self._handles.pop(value, None)
      raise StateHandleExpiredError(
        "State handle has expired its bounded lifetime; create new state to "
        "continue (R-16.9-c, R-16.9-f)"
      )
    # R-16.9-b: validate the caller's authorization against the handle on every
    # call (a handle is a name, not a capability).
    if handle.owner is not None and caller != handle.owner:
      raise StateHandleAuthorizationError(
        "Caller is not authorised for this state handle; authorization is "
        "validated against the handle on every call (R-16.9-b)"
      )
    return handle


def expired_or_unknown_handle_result(detail: str = "") -> CallToolResult:
  """Build the tool-execution error result for an expired/unknown handle (R-16.9-f).

  A call against an expired or unknown handle SHOULD return a *tool-execution*
  error (§16.6) — i.e. a successful ``CallToolResult`` with ``isError: true`` —
  describing the condition so the model can recover by creating new state
  (R-16.9-f). This is deliberately the §16.6 tool-execution-error layer, not a
  JSON-RPC protocol error: the request *did* reach the tool.

  Args:
    detail: optional extra explanation appended to the standard message.

  Returns:
    A ``complete`` ``CallToolResult`` with ``isError: True`` describing the
    expired/unknown handle.
  """
  message = (
    "The provided state handle is expired or unknown. Create new state (call the "
    "creation tool again) and retry with the fresh handle."
  )
  if detail:
    message = f"{message} {detail}"
  return tool_execution_error_result(message)
