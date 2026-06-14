"""Sampling (Deprecated) — S33.

Delivers the Deprecated **Sampling** client capability: the means by which a
server obtains a language-model completion by delegating the model call to the
client. The client runs the model, keeps a human in the loop, and returns the
completion to the server — so a server can use model capabilities without
holding any model-provider credentials.

Sampling is **not** a server-initiated JSON-RPC request (§21.2.2). A server asks
for a completion by returning an input-required result (S17 / §11) that carries
a ``sampling/createMessage`` input request; the client runs the model and
answers by retrying the original request with a :class:`CreateMessageResult`
attached. If the user denies or an error occurs, the retry simply never happens
and the server is not left blocking (§21.2.2).

Because this capability is Deprecated, the central deliverable is *acceptance*:
an implementation MUST still understand ``sampling/createMessage`` and its data
shapes for interoperability, while new functionality SHOULD instead integrate
directly with a model provider (§21.2.1, R-21.2-a, R-21.2.1-a/b).

Public surface:

Capability:
  - ClientSamplingCapability: the value of the ``sampling`` capability, with the
    OPTIONAL ``tools`` and (Deprecated) ``context`` sub-capabilities (§21.2.3).
  - capability_supports_tools / capability_supports_context: presence gates that
    reuse the S10 sub-flag helpers.

Method name:
  - SAMPLING_CREATE_MESSAGE_METHOD: the exact ``sampling/createMessage`` string,
    re-exported from S17 for convenience.

Request / result data types (§21.2.4–§21.2.9):
  - CreateMessageRequestParams, ToolChoice, ToolChoiceMode,
    SamplingMessage, ToolUseContent, ToolResultContent,
    CreateMessageResult, ModelPreferences, ModelHint, IncludeContext.
  - SamplingMessageContentBlock union + parse_sampling_content_block dispatch.

Behaviors & gating (§21.2.3 / §21.2.10):
  - assert_tool_use_allowed / server_may_send_tool_request: tool-use gating on
    both the server side (MUST NOT send) and the client side (MUST error).
  - sanitize_include_context: the server-side ``includeContext`` discipline.
  - clamp_max_tokens: the ``maxTokens`` upper-bound guarantee (R-21.2.4-j).
  - select_model: model-preference evaluation (hints first, in order; numeric
    priorities only to break ties) (§21.2.9).
  - HumanInTheLoop: the consent / human-in-the-loop obligations (§21.2.10).

Spec: §21.2 (lines 5595–6013)
Depends on: S10 (capabilities), S21 (content blocks), S17 (multi-round-trip)
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Callable, Union

from mcp_sdk_py.capabilities import ClientCapabilities, subflag_object_present
from mcp_sdk_py.content_types import (
  AudioContent,
  ContentBlock,
  ImageContent,
  TextContent,
  parse_content_block,
)
from mcp_sdk_py.multi_round_trip import INPUT_REQUEST_SAMPLING
from mcp_sdk_py.result_error import RESULT_TYPE_COMPLETE


# ---------------------------------------------------------------------------
# Method name & deprecation posture  (§21.2.1, §21.2.2, §21.2.4)
# ---------------------------------------------------------------------------

#: The exact, case-sensitive input-request method string (§21.2.4).
#: Re-exported from S17 so callers of this module need not reach across.
SAMPLING_CREATE_MESSAGE_METHOD: str = INPUT_REQUEST_SAMPLING  # "sampling/createMessage"

#: Sampling is Deprecated (§21.2.1, R-21.2-a, R-21.2.1-a). New code SHOULD NOT
#: adopt it; it remains defined only for interoperability.
SAMPLING_IS_DEPRECATED: bool = True

#: The migration guidance the spec gives for new functionality
#: (§21.2.1, R-21.2.1-b): integrate directly with a model provider.
SAMPLING_MIGRATION_GUIDANCE: str = (
  "Integrate directly with a language-model provider interface rather than "
  "requesting model completions from the client through the sampling capability."
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class SamplingError(Exception):
  """Base class for sampling-protocol errors raised by this module."""


class SamplingToolsNotDeclaredError(SamplingError):
  """A tool-enabled sampling request reached a client lacking ``sampling.tools``.

  A client MUST return an error if a ``sampling/createMessage`` input request
  includes ``tools`` or ``toolChoice`` but the client did not declare
  ``sampling.tools`` (R-21.2.3-b, R-21.2.4-n, R-21.2.4-o). Servers MUST NOT
  send such a request in the first place (R-21.2.3-a); ``assert_tool_use_allowed``
  raises this on the client side, and ``server_may_send_tool_request`` lets the
  server avoid sending.

  Attributes:
    fields: the offending request field names (``"tools"`` / ``"toolChoice"``).
  """

  def __init__(self, fields: tuple[str, ...]) -> None:
    joined = " and ".join(repr(f) for f in fields)
    super().__init__(
      f"Sampling request supplied {joined} but the client did not declare "
      f"'sampling.tools'; the client MUST return an error "
      f"(R-21.2.3-a, R-21.2.3-b, R-21.2.4-n, R-21.2.4-o)"
    )
    self.fields: tuple[str, ...] = fields


class SamplingDeniedError(SamplingError):
  """The user denied a sampling request via the human-in-the-loop control.

  The client (or host) MUST give the user the ability to deny a sampling
  request (R-21.2.10-b). On denial the originating request is simply not
  retried with a completion attached; the server is not awaiting a response
  (§21.2.2), so no error travels on the wire.
  """


class MalformedSamplingRequestError(SamplingError):
  """A ``CreateMessageRequestParams`` object is structurally invalid.

  Raised when a REQUIRED field (``messages`` or ``maxTokens``) is missing or
  malformed (R-21.2.4-a, R-21.2.4-h, AC-33.5), or when a message / content
  ordering constraint is violated (§21.2.6, §21.2.7).
  """


class MalformedSamplingResultError(SamplingError):
  """A ``CreateMessageResult`` object is structurally invalid.

  Raised when a REQUIRED field (``role``, ``content``, ``model`` or
  ``resultType``) is missing or malformed (§21.2.8, AC-33.19).
  """


# ---------------------------------------------------------------------------
# §21.2.3  ClientSamplingCapability
# ---------------------------------------------------------------------------

@dataclass
class ClientSamplingCapability:
  """The value of the client's ``sampling`` capability (§21.2.3).

  An object with OPTIONAL sub-capability members. Their mere presence — even an
  empty object ``{}`` — declares support (presence-means-supported, S10/§6.1):

    tools: present ⇒ the client supports tool use during sampling (the ``tools``
      / ``toolChoice`` request fields). An empty object means "supported, no
      further settings" (R-21.2.3-a/b).
    context: present ⇒ the client supports context inclusion via
      ``includeContext``. **This sub-capability is Deprecated** (R-21.2.3-c).

  The sampling capability itself is Deprecated; it remains defined only for
  interoperability (§21.2.1, R-21.2-a, R-21.2.1-a).
  """

  tools: dict[str, Any] | None = None
  context: dict[str, Any] | None = None
  extra: dict[str, Any] = field(default_factory=dict)

  @property
  def supports_tools(self) -> bool:
    """True if the ``tools`` sub-capability is present (§21.2.3, R-21.2.3-a/b)."""
    return self.tools is not None

  @property
  def supports_context(self) -> bool:
    """True if the Deprecated ``context`` sub-capability is present (R-21.2.3-c)."""
    return self.context is not None

  def to_dict(self) -> dict[str, Any]:
    """Serialise to the wire object; omits absent sub-capabilities (§21.2.3)."""
    out: dict[str, Any] = {}
    if self.tools is not None:
      out["tools"] = self.tools
    if self.context is not None:
      out["context"] = self.context
    out.update(self.extra)
    return out

  @classmethod
  def from_dict(cls, raw: Any) -> ClientSamplingCapability:
    """Parse a wire ``sampling`` capability value (§21.2.3).

    An empty object ``{}`` is valid and declares sampling with no sub-flags.
    Unknown keys are preserved in ``extra`` for forward-compatible round-trip.

    Raises:
      TypeError: ``raw`` (or a sub-capability) is not a JSON object.
    """
    if not isinstance(raw, dict):
      raise TypeError(
        f"sampling capability must be a JSON object; got {type(raw).__name__}"
      )
    tools = raw.get("tools")
    if tools is not None and not isinstance(tools, dict):
      raise TypeError("sampling.tools must be a JSON object if present")
    context = raw.get("context")
    if context is not None and not isinstance(context, dict):
      raise TypeError("sampling.context must be a JSON object if present")
    extra = {k: v for k, v in raw.items() if k not in ("tools", "context")}
    return cls(tools=tools, context=context, extra=extra)


def capability_supports_tools(sampling_value: Any) -> bool:
  """True if a raw ``sampling`` capability value declares ``tools`` (R-21.2.3-a/b).

  Accepts the raw capability dict (e.g. ``ClientCapabilities.sampling``) and
  reuses the S10 sub-flag helper so this module never re-implements gating.
  """
  return subflag_object_present(sampling_value, "tools")


def capability_supports_context(sampling_value: Any) -> bool:
  """True if a raw ``sampling`` capability value declares ``context`` (R-21.2.3-c).

  The ``context`` sub-capability is itself Deprecated.
  """
  return subflag_object_present(sampling_value, "context")


def _client_supports_sampling_tools(
  client_caps: ClientCapabilities | dict[str, Any] | bool,
) -> bool:
  """Normalise the several ways a caller may express ``sampling.tools`` support.

  Accepts a :class:`ClientCapabilities`, a raw capabilities dict, or a bare
  boolean (already-resolved gate). Returns whether ``sampling.tools`` was
  declared (R-21.2.3-a/b).
  """
  if isinstance(client_caps, bool):
    return client_caps
  if isinstance(client_caps, ClientCapabilities):
    return client_caps.supports_sampling_tools
  sampling_value = client_caps.get("sampling") if isinstance(client_caps, dict) else None
  return capability_supports_tools(sampling_value)


# ---------------------------------------------------------------------------
# §21.2.4  includeContext enum
# ---------------------------------------------------------------------------

class IncludeContext(enum.Enum):
  """The ``includeContext`` request enum (§21.2.4).

  Exact, case-sensitive values:

    NONE ("none"): no additional context — the default when omitted.
    THIS_SERVER ("thisServer"): include context from the requesting server.
      **Deprecated** (R-21.2.4-e).
    ALL_SERVERS ("allServers"): include context from all connected servers.
      **Deprecated** (R-21.2.4-e).

  Servers SHOULD omit the field or use ``"none"`` and SHOULD use the Deprecated
  values only when the client declared ``sampling.context`` (R-21.2.3-c,
  R-21.2.4-e). The default when the field is omitted is ``"none"``.
  """

  NONE = "none"
  THIS_SERVER = "thisServer"
  ALL_SERVERS = "allServers"

  @property
  def is_deprecated(self) -> bool:
    """True for the Deprecated values ``"thisServer"`` / ``"allServers"``."""
    return self in (IncludeContext.THIS_SERVER, IncludeContext.ALL_SERVERS)


#: The two Deprecated includeContext values (R-21.2.4-e).
DEPRECATED_INCLUDE_CONTEXT_VALUES: frozenset[str] = frozenset(
  {IncludeContext.THIS_SERVER.value, IncludeContext.ALL_SERVERS.value}
)


def sanitize_include_context(
  value: IncludeContext | str | None,
  *,
  client_supports_context: bool,
) -> IncludeContext | None:
  """Apply the server-side ``includeContext`` discipline (R-21.2.3-c, R-21.2.4-e).

  Servers SHOULD omit the field or use ``"none"``, and SHOULD use the Deprecated
  values (``"thisServer"`` / ``"allServers"``) only when the client declared
  ``sampling.context``. This helper enforces that SHOULD on the building side:
  when the client did not declare ``sampling.context``, a requested Deprecated
  value is downgraded to ``IncludeContext.NONE`` (AC-33.4).

  Args:
    value: the desired includeContext, or None to omit the field.
    client_supports_context: whether the client declared ``sampling.context``.

  Returns:
    The value to send: None to omit, or an :class:`IncludeContext`. A Deprecated
    value is downgraded to ``NONE`` when context is not supported.

  Raises:
    ValueError: ``value`` is a string that is not a valid includeContext value.
  """
  if value is None:
    return None
  if isinstance(value, str):
    value = IncludeContext(value)
  if value.is_deprecated and not client_supports_context:
    # R-21.2.3-c / R-21.2.4-e: do not send a Deprecated value without the
    # context sub-capability — degrade to the safe default.
    return IncludeContext.NONE
  return value


# ---------------------------------------------------------------------------
# §21.2.5  ToolChoice
# ---------------------------------------------------------------------------

class ToolChoiceMode(enum.Enum):
  """The ``ToolChoice.mode`` enum controlling tool use during sampling (§21.2.5).

    AUTO ("auto"): the model decides whether to use tools — the default.
    REQUIRED ("required"): the model MUST use at least one tool before
      completing (R-21.2.5-a).
    NONE ("none"): the model MUST NOT use any tools (R-21.2.5-b).
  """

  AUTO = "auto"
  REQUIRED = "required"
  NONE = "none"


@dataclass
class ToolChoice:
  """Controls the model's tool-use behavior during sampling (§21.2.5).

  ``mode`` is OPTIONAL; the default when ``toolChoice`` is omitted entirely is
  ``{ "mode": "auto" }`` (R-21.2.4-p). :meth:`default` builds that default.
  """

  mode: ToolChoiceMode = ToolChoiceMode.AUTO

  @classmethod
  def default(cls) -> ToolChoice:
    """The default ``{ "mode": "auto" }`` used when ``toolChoice`` is omitted (R-21.2.4-p)."""
    return cls(mode=ToolChoiceMode.AUTO)

  @classmethod
  def from_dict(cls, raw: Any) -> ToolChoice:
    """Parse a wire ToolChoice object (§21.2.5).

    A missing ``mode`` defaults to ``"auto"``.

    Raises:
      TypeError: raw is not an object.
      ValueError: ``mode`` is not one of the enum values.
    """
    if not isinstance(raw, dict):
      raise TypeError(f"ToolChoice must be a JSON object; got {type(raw).__name__}")
    mode = raw.get("mode")
    if mode is None:
      return cls(mode=ToolChoiceMode.AUTO)
    return cls(mode=ToolChoiceMode(mode))

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire ToolChoice object."""
    return {"mode": self.mode.value}


# ---------------------------------------------------------------------------
# §21.2.6  Sampling-specific content blocks
# ---------------------------------------------------------------------------

@dataclass
class ToolUseContent:
  """A request from the assistant to call a tool (§21.2.6); type ``"tool_use"``.

  Fields:
    id: unique identifier for this tool use, matched by a later
      ``ToolResultContent.toolUseId`` (R-21.2.6-d).
    name: the name of the tool to call.
    input: the arguments to pass, conforming to the tool's input schema.
    meta: OPTIONAL reserved metadata (JSON ``_meta``). Clients SHOULD preserve
      it across subsequent sampling requests to enable caching (R-21.2.6-c).
  """

  id: str                                    # REQUIRED
  name: str                                  # REQUIRED
  input: dict[str, Any]                      # REQUIRED
  meta: dict[str, Any] | None = None         # OPTIONAL; JSON: _meta
  type: str = field(default="tool_use", init=False)

  def __post_init__(self) -> None:
    if not isinstance(self.id, str) or not self.id:
      raise ValueError("ToolUseContent.id is REQUIRED and must be a non-empty string")
    if not isinstance(self.name, str) or not self.name:
      raise ValueError("ToolUseContent.name is REQUIRED and must be a non-empty string")
    if not isinstance(self.input, dict):
      raise TypeError("ToolUseContent.input is REQUIRED and must be a JSON object")

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> ToolUseContent:
    """Deserialise from a JSON-decoded dict."""
    return cls(
      id=data["id"],
      name=data["name"],
      input=data["input"],
      meta=data.get("_meta"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a JSON-compatible dict; omits absent ``_meta``.

    ``_meta`` is preserved verbatim, satisfying the caching-preservation SHOULD
    (R-21.2.6-c).
    """
    result: dict[str, Any] = {
      "type": self.type,
      "id": self.id,
      "name": self.name,
      "input": self.input,
    }
    if self.meta is not None:
      result["_meta"] = self.meta
    return result


@dataclass
class ToolResultContent:
  """The result of a tool use, provided by the user (§21.2.6); type ``"tool_result"``.

  Fields:
    tool_use_id: MUST match the ``id`` of a previous ToolUseContent
      (R-21.2.6-d); JSON ``toolUseId``.
    content: unstructured result content (the tool-result array form from §16);
      MAY include text, images, audio, resource links, embedded resources
      (R-21.2.6-e).
    structured_content: OPTIONAL structured result; SHOULD conform to the tool's
      output schema when one is defined (R-21.2.6-f); JSON ``structuredContent``.
    is_error: OPTIONAL; default ``false`` when omitted (R-21.2.6-g); JSON
      ``isError``.
    meta: OPTIONAL reserved metadata (JSON ``_meta``). Clients SHOULD preserve
      it across subsequent sampling requests to enable caching (R-21.2.6-h).
  """

  tool_use_id: str                               # REQUIRED; JSON: toolUseId
  content: list[ContentBlock]                     # REQUIRED
  structured_content: Any = None                  # OPTIONAL; JSON: structuredContent
  is_error: bool = False                          # OPTIONAL; default false; JSON: isError
  meta: dict[str, Any] | None = None              # OPTIONAL; JSON: _meta
  type: str = field(default="tool_result", init=False)

  #: Sentinel distinguishing "structuredContent absent" from "present and null".
  _structured_present: bool = field(default=False, init=False, repr=False)

  def __post_init__(self) -> None:
    if not isinstance(self.tool_use_id, str) or not self.tool_use_id:
      raise ValueError(
        "ToolResultContent.toolUseId is REQUIRED and must be a non-empty string "
        "(R-21.2.6-d)"
      )
    if not isinstance(self.content, list):
      raise TypeError(
        "ToolResultContent.content is REQUIRED and must be an array (R-21.2.6-e)"
      )
    if not isinstance(self.is_error, bool):
      raise TypeError("ToolResultContent.isError must be a boolean (R-21.2.6-g)")

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> ToolResultContent:
    """Deserialise from a JSON-decoded dict.

    ``content`` blocks use the base ContentBlock union (S21); the sampling-only
    ``tool_use``/``tool_result`` types are not permitted inside a tool result.
    An omitted ``isError`` is treated as ``false`` (R-21.2.6-g).
    """
    raw_content = data.get("content")
    if not isinstance(raw_content, list):
      raise TypeError(
        "ToolResultContent.content is REQUIRED and must be an array (R-21.2.6-e)"
      )
    content = [parse_content_block(b) for b in raw_content]
    obj = cls(
      tool_use_id=data["toolUseId"],
      content=content,
      structured_content=data.get("structuredContent"),
      is_error=data.get("isError", False),
      meta=data.get("_meta"),
    )
    object.__setattr__(obj, "_structured_present", "structuredContent" in data)
    return obj

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a JSON-compatible dict; omits absent optional fields.

    ``_meta`` is preserved verbatim, satisfying the caching SHOULD (R-21.2.6-h).
    ``isError`` is emitted only when ``True`` (the default ``false`` is implied).
    """
    result: dict[str, Any] = {
      "type": self.type,
      "toolUseId": self.tool_use_id,
      "content": [_content_block_to_dict(b) for b in self.content],
    }
    if self._structured_present or self.structured_content is not None:
      result["structuredContent"] = self.structured_content
    if self.is_error:
      result["isError"] = self.is_error
    if self.meta is not None:
      result["_meta"] = self.meta
    return result


def _content_block_to_dict(block: Any) -> dict[str, Any]:
  """Serialise a ContentBlock-like object, tolerating plain dicts."""
  if isinstance(block, dict):
    return block
  to_dict = getattr(block, "to_dict", None)
  if callable(to_dict):
    return to_dict()
  raise TypeError(f"cannot serialise content block {block!r}")


# ---------------------------------------------------------------------------
# §21.2.6  SamplingMessageContentBlock union & dispatch
# ---------------------------------------------------------------------------

#: The sampling content union: the three shared S21 blocks plus the two
#: sampling-specific blocks (§21.2.6).
SamplingMessageContentBlock = Union[
  TextContent, ImageContent, AudioContent, ToolUseContent, ToolResultContent
]


def parse_sampling_content_block(data: dict[str, Any]) -> SamplingMessageContentBlock:
  """Dispatch a raw dict to the correct sampling content block by ``type`` (§21.2.6).

  Recognises the two sampling-only blocks (``tool_use`` / ``tool_result``) here,
  and delegates the shared ``text`` / ``image`` / ``audio`` blocks to the S21
  ContentBlock dispatcher so this module never re-implements them.

  Raises:
    ValueError: ``type`` is missing/non-string, or names a block type that is
      not valid in a sampling message.
  """
  type_val = data.get("type")
  if not isinstance(type_val, str):
    raise ValueError(
      f"sampling content block 'type' is REQUIRED and must be a string; "
      f"got {type(type_val).__name__}"
    )
  if type_val == "tool_use":
    return ToolUseContent.from_dict(data)
  if type_val == "tool_result":
    return ToolResultContent.from_dict(data)
  # Shared S21 blocks: text / image / audio (resource blocks are not part of the
  # sampling content union, but the dispatcher still parses them; callers only
  # ever build sampling messages from the union members).
  block = parse_content_block(data)
  return block  # type: ignore[return-value]


def _is_tool_result_block(block: Any) -> bool:
  """True if block is (or decodes to) a ``tool_result`` block."""
  if isinstance(block, ToolResultContent):
    return True
  if isinstance(block, dict):
    return block.get("type") == "tool_result"
  return getattr(block, "type", None) == "tool_result"


def _is_tool_use_block(block: Any) -> bool:
  """True if block is (or decodes to) a ``tool_use`` block."""
  if isinstance(block, ToolUseContent):
    return True
  if isinstance(block, dict):
    return block.get("type") == "tool_use"
  return getattr(block, "type", None) == "tool_use"


def _block_to_dict(block: Any) -> dict[str, Any]:
  """Serialise any sampling content block, tolerating plain dicts."""
  if isinstance(block, dict):
    return block
  to_dict = getattr(block, "to_dict", None)
  if callable(to_dict):
    return to_dict()
  raise TypeError(f"cannot serialise sampling content block {block!r}")


# ---------------------------------------------------------------------------
# §21.2.6  SamplingMessage
# ---------------------------------------------------------------------------

#: The two valid message roles (§21.2.6).
_SAMPLING_ROLES: frozenset[str] = frozenset({"user", "assistant"})


@dataclass
class SamplingMessage:
  """One message in the sampled conversation (§21.2.6).

  Fields:
    role: REQUIRED, ``"user"`` or ``"assistant"`` (R-21.2.6-a).
    content: REQUIRED, a single content block or an array of blocks
      (R-21.2.6-b). Always normalised to a list internally; ``content_is_single``
      records whether the wire form was a single block so it round-trips.
    meta: OPTIONAL reserved metadata (JSON ``_meta``).

  Message-content constraint (R-21.2.7-a): when a ``user`` message contains any
  ``tool_result`` block it MUST contain ONLY ``tool_result`` blocks; mixing a
  tool result with any other content type is rejected here.
  """

  role: str                                       # REQUIRED
  content: list[SamplingMessageContentBlock]       # REQUIRED (normalised to list)
  meta: dict[str, Any] | None = None              # OPTIONAL; JSON: _meta
  content_is_single: bool = False                 # wire form was a single block

  def __post_init__(self) -> None:
    if self.role not in _SAMPLING_ROLES:
      raise ValueError(
        f"SamplingMessage.role is REQUIRED and must be 'user' or 'assistant'; "
        f"got {self.role!r} (R-21.2.6-a)"
      )
    if not isinstance(self.content, list) or not self.content:
      raise ValueError(
        "SamplingMessage.content is REQUIRED and must be a non-empty block or "
        "array of blocks (R-21.2.6-b)"
      )
    self._validate_tool_result_exclusivity()

  def _validate_tool_result_exclusivity(self) -> None:
    """Enforce the tool-result exclusivity constraint (R-21.2.7-a).

    When a ``user`` message contains any ``tool_result`` block it MUST contain
    ONLY ``tool_result`` blocks; mixing with any other type is NOT allowed.
    """
    if self.role != "user":
      return
    has_tool_result = any(_is_tool_result_block(b) for b in self.content)
    if not has_tool_result:
      return
    for b in self.content:
      if not _is_tool_result_block(b):
        raise MalformedSamplingRequestError(
          "a 'user' message that contains a tool_result block MUST contain ONLY "
          "tool_result blocks; mixing tool_result with text/image/audio is NOT "
          "allowed (R-21.2.7-a)"
        )

  @property
  def tool_use_ids(self) -> list[str]:
    """The ids of every ToolUseContent block in this message (for §21.2.7-b matching)."""
    ids: list[str] = []
    for b in self.content:
      if isinstance(b, ToolUseContent):
        ids.append(b.id)
      elif isinstance(b, dict) and b.get("type") == "tool_use":
        ids.append(b.get("id"))  # type: ignore[arg-type]
    return ids

  @property
  def tool_result_ids(self) -> list[str]:
    """The toolUseIds of every ToolResultContent block in this message (§21.2.7-b)."""
    ids: list[str] = []
    for b in self.content:
      if isinstance(b, ToolResultContent):
        ids.append(b.tool_use_id)
      elif isinstance(b, dict) and b.get("type") == "tool_result":
        ids.append(b.get("toolUseId"))  # type: ignore[arg-type]
    return ids

  @property
  def has_tool_use(self) -> bool:
    """True if this message contains at least one ToolUseContent block."""
    return any(_is_tool_use_block(b) for b in self.content)

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> SamplingMessage:
    """Deserialise from a JSON-decoded dict (§21.2.6).

    ``content`` may be a single block object or an array; both are accepted and
    the single-vs-array form is preserved for round-trip (R-21.2.6-b).

    Raises:
      ValueError / MalformedSamplingRequestError: role/content missing or the
        tool-result exclusivity constraint is violated.
    """
    if "role" not in data:
      raise ValueError("SamplingMessage.role is REQUIRED (R-21.2.6-a)")
    if "content" not in data:
      raise ValueError("SamplingMessage.content is REQUIRED (R-21.2.6-b)")
    raw_content = data["content"]
    is_single = isinstance(raw_content, dict)
    raw_blocks = [raw_content] if is_single else raw_content
    if not isinstance(raw_blocks, list):
      raise ValueError(
        "SamplingMessage.content must be a single block or an array of blocks "
        "(R-21.2.6-b)"
      )
    content = [parse_sampling_content_block(b) for b in raw_blocks]
    return cls(
      role=data["role"],
      content=content,
      meta=data.get("_meta"),
      content_is_single=is_single and len(content) == 1,
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a JSON-compatible dict; preserves single-vs-array content form."""
    blocks = [_block_to_dict(b) for b in self.content]
    content: Any = blocks[0] if (self.content_is_single and len(blocks) == 1) else blocks
    result: dict[str, Any] = {"role": self.role, "content": content}
    if self.meta is not None:
      result["_meta"] = self.meta
    return result


def validate_tool_use_ordering(messages: list[SamplingMessage]) -> None:
  """Enforce the assistant-tool-use ⇒ user-tool-result ordering (R-21.2.7-b).

  Every ``assistant`` message that contains one or more ToolUseContent blocks
  MUST be followed immediately by a ``user`` message consisting entirely of
  ToolResultContent blocks, with each tool use (``id: $id``) matched by a
  corresponding tool result (``toolUseId: $id``), before any other message.
  Multiple parallel tool uses are permitted.

  Raises:
    MalformedSamplingRequestError: the ordering or matching is violated.
  """
  for i, msg in enumerate(messages):
    if msg.role != "assistant" or not msg.has_tool_use:
      continue
    use_ids = msg.tool_use_ids
    if i + 1 >= len(messages):
      raise MalformedSamplingRequestError(
        "an 'assistant' message containing tool_use blocks MUST be followed "
        "immediately by a 'user' message of tool_result blocks (R-21.2.7-b)"
      )
    nxt = messages[i + 1]
    if nxt.role != "user":
      raise MalformedSamplingRequestError(
        "an 'assistant' tool_use message MUST be followed immediately by a "
        "'user' message, before any other message (R-21.2.7-b)"
      )
    nxt_blocks = nxt.content
    if not all(_is_tool_result_block(b) for b in nxt_blocks):
      raise MalformedSamplingRequestError(
        "the 'user' message following an assistant tool_use MUST consist "
        "entirely of tool_result blocks (R-21.2.7-b)"
      )
    result_ids = set(nxt.tool_result_ids)
    if set(use_ids) != result_ids:
      raise MalformedSamplingRequestError(
        f"each tool_use id MUST be matched by exactly one tool_result toolUseId; "
        f"tool_use ids={sorted(use_ids)!r} tool_result ids={sorted(result_ids)!r} "
        f"(R-21.2.7-b)"
      )


def validate_tool_result_references(messages: list[SamplingMessage]) -> None:
  """Verify every ToolResultContent.toolUseId matches a prior ToolUseContent.id (R-21.2.6-d).

  Scans messages oldest-to-newest, accumulating seen tool-use ids; a
  ``toolUseId`` that does not match any *previous* tool use is invalid.

  Raises:
    MalformedSamplingRequestError: an unmatched ``toolUseId`` is found.
  """
  seen_use_ids: set[str] = set()
  for msg in messages:
    for b in msg.content:
      if _is_tool_result_block(b):
        ref = b.tool_use_id if isinstance(b, ToolResultContent) else b.get("toolUseId")  # type: ignore[union-attr]
        if ref not in seen_use_ids:
          raise MalformedSamplingRequestError(
            f"ToolResultContent.toolUseId {ref!r} does not match the id of any "
            f"previous ToolUseContent (R-21.2.6-d)"
          )
    for b in msg.content:
      if _is_tool_use_block(b):
        use_id = b.id if isinstance(b, ToolUseContent) else b.get("id")  # type: ignore[union-attr]
        seen_use_ids.add(use_id)


# ---------------------------------------------------------------------------
# §21.2.9  Model preferences
# ---------------------------------------------------------------------------

@dataclass
class ModelHint:
  """A single advisory hint toward a model (§21.2.9).

  ``name`` (OPTIONAL) is treated by the client as a *substring* of a model name
  (R-21.2.9-f). The client MAY map it to a different provider's model or a
  similar-niche family (R-21.2.9-g). Keys other than ``name`` are unspecified
  and preserved in ``extra``.
  """

  name: str | None = None
  extra: dict[str, Any] = field(default_factory=dict)

  @classmethod
  def from_dict(cls, raw: dict[str, Any]) -> ModelHint:
    """Deserialise from a JSON-decoded dict; unknown keys kept in ``extra``."""
    extra = {k: v for k, v in raw.items() if k != "name"}
    return cls(name=raw.get("name"), extra=extra)

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a JSON-compatible dict; omits absent ``name``."""
    out: dict[str, Any] = {}
    if self.name is not None:
      out["name"] = self.name
    out.update(self.extra)
    return out


@dataclass
class ModelPreferences:
  """The server's advisory model-selection priorities and hints (§21.2.9).

  All preferences are advisory; the client MAY ignore them, and final selection
  is the client's (or host's) responsibility (R-21.2.9-a).

  Fields:
    hints: OPTIONAL ordered hints; if multiple are given the client MUST
      evaluate them in order, taking the first match (R-21.2.9-b).
    cost_priority / speed_priority / intelligence_priority: OPTIONAL numbers in
      the inclusive range 0..1 (R-21.2.9-e); JSON ``costPriority`` etc.
  """

  hints: list[ModelHint] | None = None
  cost_priority: float | None = None          # JSON: costPriority
  speed_priority: float | None = None         # JSON: speedPriority
  intelligence_priority: float | None = None  # JSON: intelligencePriority

  @classmethod
  def from_dict(cls, raw: dict[str, Any]) -> ModelPreferences:
    """Deserialise from a JSON-decoded dict.

    Out-of-range priorities are accepted on parse: the spec sets no hard
    MUST-reject obligation; they MAY be ignored or clamped at selection time
    (R-21.2.9-e, AC-33.22).

    Raises:
      TypeError: ``hints`` is present but not an array.
    """
    raw_hints = raw.get("hints")
    hints: list[ModelHint] | None = None
    if raw_hints is not None:
      if not isinstance(raw_hints, list):
        raise TypeError("ModelPreferences.hints must be an array if present")
      hints = [ModelHint.from_dict(h) for h in raw_hints]
    return cls(
      hints=hints,
      cost_priority=raw.get("costPriority"),
      speed_priority=raw.get("speedPriority"),
      intelligence_priority=raw.get("intelligencePriority"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a JSON-compatible dict; omits absent optional fields."""
    out: dict[str, Any] = {}
    if self.hints is not None:
      out["hints"] = [h.to_dict() for h in self.hints]
    if self.cost_priority is not None:
      out["costPriority"] = self.cost_priority
    if self.speed_priority is not None:
      out["speedPriority"] = self.speed_priority
    if self.intelligence_priority is not None:
      out["intelligencePriority"] = self.intelligence_priority
    return out


def hint_matches(hint: ModelHint, model_name: str) -> bool:
  """True if ``hint.name`` is a substring of ``model_name`` (R-21.2.9-f).

  A hint with no ``name`` never matches. Matching is the substring rule the
  client SHOULD apply (e.g. ``"sonnet"`` matches ``"vendor-sonnet-..."``).
  """
  if hint.name is None:
    return False
  return hint.name in model_name


def select_model(
  preferences: ModelPreferences | None,
  available_models: list[str],
  *,
  priority_tiebreak: Callable[[str], float] | None = None,
) -> str | None:
  """Select a model from ``available_models`` honoring ``preferences`` (§21.2.9).

  Implements the advisory selection discipline:
    - If multiple ``hints`` are specified, evaluate them IN ORDER, taking the
      FIRST hint that matches any available model (R-21.2.9-b).
    - Hints are prioritised over the numeric priorities (R-21.2.9-c); the
      numeric priorities are used only to disambiguate among several models that
      match the same first-matching hint (R-21.2.9-d), via ``priority_tiebreak``.
    - All preferences are advisory; selection is ultimately the client/host's
      (R-21.2.9-a) — callers MAY override or ignore the return value.

  Args:
    preferences: the server's advisory ModelPreferences, or None.
    available_models: the model names the client can actually run.
    priority_tiebreak: OPTIONAL scorer used to break ties when several models
      match the first-matching hint; the highest score wins. Absent ⇒ the first
      matching model (in ``available_models`` order) is taken.

  Returns:
    The selected model name, or None when nothing is available / no hint matched
    and no fallback applies.
  """
  if not available_models:
    return None
  if preferences is not None and preferences.hints:
    # R-21.2.9-b: first matching hint, evaluated in order.
    for hint in preferences.hints:
      matches = [m for m in available_models if hint_matches(hint, m)]
      if matches:
        if priority_tiebreak is not None and len(matches) > 1:
          # R-21.2.9-d: use numeric priorities only to break ties.
          return max(matches, key=priority_tiebreak)
        return matches[0]
  # No hints (or none matched): fall back to a priority-scored choice if given,
  # else the first available model. All advisory (R-21.2.9-a).
  if priority_tiebreak is not None:
    return max(available_models, key=priority_tiebreak)
  return available_models[0]


# ---------------------------------------------------------------------------
# §21.2.4  CreateMessageRequestParams
# ---------------------------------------------------------------------------

@dataclass
class CreateMessageRequestParams:
  """Parameters of the ``sampling/createMessage`` input request (§21.2.4).

  Required fields: ``messages`` (R-21.2.4-a) and ``max_tokens`` (R-21.2.4-h). All
  other fields are OPTIONAL and advisory: the client MAY modify or ignore
  ``model_preferences`` / ``system_prompt`` / ``temperature`` / ``stop_sequences``
  / ``metadata`` / ``include_context`` without telling the server
  (R-21.2.4-c/d/f/g/k/l).

  Tool-use fields ``tools`` / ``tool_choice`` require the client to have declared
  ``sampling.tools``; a server MUST NOT send them otherwise (R-21.2.3-a) and a
  client MUST error on receipt (R-21.2.4-n/o) — see :func:`assert_tool_use_allowed`.
  An omitted ``tool_choice`` defaults to ``{ "mode": "auto" }`` (R-21.2.4-p).
  """

  messages: list[SamplingMessage]                          # REQUIRED
  max_tokens: int                                          # REQUIRED; JSON: maxTokens
  model_preferences: ModelPreferences | None = None        # JSON: modelPreferences
  system_prompt: str | None = None                         # JSON: systemPrompt
  include_context: IncludeContext | None = None            # JSON: includeContext
  temperature: float | None = None
  stop_sequences: list[str] | None = None                  # JSON: stopSequences
  metadata: dict[str, Any] | None = None
  tools: list[dict[str, Any]] | None = None
  tool_choice: ToolChoice | None = None                    # JSON: toolChoice

  def __post_init__(self) -> None:
    if not isinstance(self.messages, list) or not self.messages:
      raise MalformedSamplingRequestError(
        "CreateMessageRequestParams.messages is REQUIRED and must be a non-empty "
        "ordered array, oldest to newest (R-21.2.4-a)"
      )
    if isinstance(self.max_tokens, bool) or not isinstance(self.max_tokens, (int, float)):
      raise MalformedSamplingRequestError(
        "CreateMessageRequestParams.maxTokens is REQUIRED and must be a number "
        "(R-21.2.4-h)"
      )
    # Ordering & reference constraints (§21.2.6, §21.2.7).
    validate_tool_use_ordering(self.messages)
    validate_tool_result_references(self.messages)

  @property
  def effective_tool_choice(self) -> ToolChoice:
    """The tool choice applied, defaulting to ``{ "mode": "auto" }`` when omitted (R-21.2.4-p)."""
    return self.tool_choice if self.tool_choice is not None else ToolChoice.default()

  @property
  def has_tool_fields(self) -> bool:
    """True if the request carries ``tools`` or ``toolChoice`` (tool-use gating, §21.2.3)."""
    return self.tools is not None or self.tool_choice is not None

  @property
  def effective_include_context(self) -> IncludeContext:
    """The applied includeContext, defaulting to ``"none"`` when omitted (R-21.2.4 default)."""
    return self.include_context if self.include_context is not None else IncludeContext.NONE

  @classmethod
  def from_dict(cls, raw: dict[str, Any]) -> CreateMessageRequestParams:
    """Parse a wire ``CreateMessageRequestParams`` object (§21.2.4).

    A request missing ``messages`` or ``maxTokens`` is rejected as malformed
    (R-21.2.4-a, R-21.2.4-h, AC-33.5).

    Raises:
      MalformedSamplingRequestError: a REQUIRED field is missing or malformed.
      ValueError: ``includeContext`` is not a valid enum value.
    """
    if not isinstance(raw, dict):
      raise MalformedSamplingRequestError(
        f"CreateMessageRequestParams must be a JSON object; got {type(raw).__name__}"
      )
    if "messages" not in raw:
      raise MalformedSamplingRequestError(
        "CreateMessageRequestParams.messages is REQUIRED (R-21.2.4-a)"
      )
    if "maxTokens" not in raw:
      raise MalformedSamplingRequestError(
        "CreateMessageRequestParams.maxTokens is REQUIRED (R-21.2.4-h)"
      )
    raw_messages = raw["messages"]
    if not isinstance(raw_messages, list):
      raise MalformedSamplingRequestError(
        "CreateMessageRequestParams.messages must be an array (R-21.2.4-a)"
      )
    messages = [SamplingMessage.from_dict(m) for m in raw_messages]

    raw_prefs = raw.get("modelPreferences")
    model_preferences = (
      ModelPreferences.from_dict(raw_prefs) if raw_prefs is not None else None
    )

    raw_ic = raw.get("includeContext")
    include_context = IncludeContext(raw_ic) if raw_ic is not None else None

    raw_tc = raw.get("toolChoice")
    tool_choice = ToolChoice.from_dict(raw_tc) if raw_tc is not None else None

    return cls(
      messages=messages,
      max_tokens=raw["maxTokens"],
      model_preferences=model_preferences,
      system_prompt=raw.get("systemPrompt"),
      include_context=include_context,
      temperature=raw.get("temperature"),
      stop_sequences=raw.get("stopSequences"),
      metadata=raw.get("metadata"),
      tools=raw.get("tools"),
      tool_choice=tool_choice,
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire ``CreateMessageRequestParams`` object; omits absentees."""
    out: dict[str, Any] = {
      "messages": [m.to_dict() for m in self.messages],
      "maxTokens": self.max_tokens,
    }
    if self.model_preferences is not None:
      out["modelPreferences"] = self.model_preferences.to_dict()
    if self.system_prompt is not None:
      out["systemPrompt"] = self.system_prompt
    if self.include_context is not None:
      out["includeContext"] = self.include_context.value
    if self.temperature is not None:
      out["temperature"] = self.temperature
    if self.stop_sequences is not None:
      out["stopSequences"] = self.stop_sequences
    if self.metadata is not None:
      out["metadata"] = self.metadata
    if self.tools is not None:
      out["tools"] = self.tools
    if self.tool_choice is not None:
      out["toolChoice"] = self.tool_choice.to_dict()
    return out


# ---------------------------------------------------------------------------
# §21.2.3  Tool-use gating  (server-side & client-side)
# ---------------------------------------------------------------------------

def server_may_send_tool_request(
  client_caps: ClientCapabilities | dict[str, Any] | bool,
) -> bool:
  """True if a server MAY send a tool-enabled sampling request (R-21.2.3-a).

  A server MUST NOT send a request carrying ``tools`` or ``toolChoice`` to a
  client that has not declared ``sampling.tools``. Servers call this before
  attaching tool fields; when it returns False they MUST omit those fields.
  """
  return _client_supports_sampling_tools(client_caps)


def assert_tool_use_allowed(
  params: CreateMessageRequestParams,
  client_caps: ClientCapabilities | dict[str, Any] | bool,
) -> None:
  """Client-side gate: raise if a tool-enabled request lacks ``sampling.tools`` (R-21.2.3-b).

  A client MUST return an error if a sampling input request includes ``tools``
  or ``toolChoice`` but the client did not declare ``sampling.tools`` — restated
  per field as R-21.2.4-n (``tools``) and R-21.2.4-o (``toolChoice``). Call this
  on receipt before running the model.

  Raises:
    SamplingToolsNotDeclaredError: a tool field is present without the
      ``sampling.tools`` sub-capability.
  """
  if not params.has_tool_fields:
    return
  if _client_supports_sampling_tools(client_caps):
    return
  offending: list[str] = []
  if params.tools is not None:
    offending.append("tools")
  if params.tool_choice is not None:
    offending.append("toolChoice")
  raise SamplingToolsNotDeclaredError(tuple(offending))


# ---------------------------------------------------------------------------
# §21.2.4  maxTokens upper bound
# ---------------------------------------------------------------------------

def clamp_max_tokens(requested_max: int, sampled_count: int) -> int:
  """Enforce ``maxTokens`` as a hard upper bound on the sampled token count (R-21.2.4-j).

  The client MAY sample fewer tokens than ``requested_max`` (R-21.2.4-i) but MUST
  respect it as an upper bound (R-21.2.4-j). This returns the count actually
  permitted: ``min(requested_max, sampled_count)``, never exceeding the request.

  Args:
    requested_max: the ``maxTokens`` from the request (the hard ceiling).
    sampled_count: the number of tokens the model would otherwise produce.

  Returns:
    The number of tokens to keep — at most ``requested_max``.
  """
  if sampled_count < 0:
    raise ValueError("sampled_count must be non-negative")
  return min(requested_max, sampled_count)


# ---------------------------------------------------------------------------
# §21.2.8  CreateMessageResult
# ---------------------------------------------------------------------------

#: The standard (non-exhaustive) stopReason values (§21.2.8). The field is an
#: OPEN string — implementations MAY provide additional arbitrary values
#: (R-21.2.8-d).
STANDARD_STOP_REASONS: frozenset[str] = frozenset(
  {"endTurn", "stopSequence", "maxTokens", "toolUse"}
)


@dataclass
class CreateMessageResult:
  """The completion delivered back to the server on retry (§21.2.8).

  Required fields: ``role`` (R-21.2.8-a), ``content`` (R-21.2.8-b), ``model``
  (R-21.2.8-c) and ``result_type`` (R-21.2.8-e). ``stop_reason`` is an OPEN
  string — any value is accepted, standard or not (R-21.2.8-d). A completion is
  normally ``role: "assistant"``; tool-use requests are returned as
  ToolUseContent in the assistant role.

  ``result_type`` defaults to the §3.6 ``"complete"`` discriminator (reused from
  S04) since the completion is delivered as a final result on retry.
  """

  role: str                                                # REQUIRED
  content: list[SamplingMessageContentBlock]                # REQUIRED (normalised to list)
  model: str                                               # REQUIRED
  stop_reason: str | None = None                           # OPTIONAL open string; JSON: stopReason
  result_type: str = RESULT_TYPE_COMPLETE                  # REQUIRED; JSON: resultType
  meta: dict[str, Any] | None = None                       # OPTIONAL; JSON: _meta
  content_is_single: bool = False                          # wire form was a single block

  def __post_init__(self) -> None:
    if self.role not in _SAMPLING_ROLES:
      raise MalformedSamplingResultError(
        f"CreateMessageResult.role is REQUIRED and must be 'user' or 'assistant'; "
        f"got {self.role!r} (R-21.2.8-a)"
      )
    if not isinstance(self.content, list) or not self.content:
      raise MalformedSamplingResultError(
        "CreateMessageResult.content is REQUIRED and must be a block or array of "
        "blocks (R-21.2.8-b)"
      )
    if not isinstance(self.model, str) or not self.model:
      raise MalformedSamplingResultError(
        "CreateMessageResult.model is REQUIRED and must be a non-empty string "
        "(R-21.2.8-c)"
      )
    if not isinstance(self.result_type, str) or not self.result_type:
      raise MalformedSamplingResultError(
        "CreateMessageResult.resultType is REQUIRED and must be a string "
        "(R-21.2.8-e)"
      )

  @property
  def stop_reason_is_standard(self) -> bool:
    """True if ``stop_reason`` is one of the standard values (R-21.2.8-d).

    A False result does NOT mean the value is invalid — the field is an open
    string and any value is valid (R-21.2.8-d).
    """
    return self.stop_reason in STANDARD_STOP_REASONS

  @classmethod
  def from_dict(cls, raw: dict[str, Any]) -> CreateMessageResult:
    """Parse a wire ``CreateMessageResult`` object (§21.2.8).

    A result missing ``role``, ``content``, ``model`` or ``resultType`` is
    rejected (R-21.2.8-a/b/c/e, AC-33.19). ``content`` may be a single block or
    an array; both round-trip. A non-standard ``stopReason`` is accepted as an
    open-string value (R-21.2.8-d, AC-33.20).

    Raises:
      MalformedSamplingResultError: a REQUIRED field is missing or malformed.
    """
    if not isinstance(raw, dict):
      raise MalformedSamplingResultError(
        f"CreateMessageResult must be a JSON object; got {type(raw).__name__}"
      )
    for required in ("role", "content", "model", "resultType"):
      if required not in raw:
        raise MalformedSamplingResultError(
          f"CreateMessageResult.{required} is REQUIRED (R-21.2.8)"
        )
    raw_content = raw["content"]
    is_single = isinstance(raw_content, dict)
    raw_blocks = [raw_content] if is_single else raw_content
    if not isinstance(raw_blocks, list):
      raise MalformedSamplingResultError(
        "CreateMessageResult.content must be a single block or an array "
        "(R-21.2.8-b)"
      )
    content = [parse_sampling_content_block(b) for b in raw_blocks]
    return cls(
      role=raw["role"],
      content=content,
      model=raw["model"],
      stop_reason=raw.get("stopReason"),
      result_type=raw["resultType"],
      meta=raw.get("_meta"),
      content_is_single=is_single and len(content) == 1,
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire ``CreateMessageResult`` object; preserves content form."""
    blocks = [_block_to_dict(b) for b in self.content]
    content: Any = blocks[0] if (self.content_is_single and len(blocks) == 1) else blocks
    out: dict[str, Any] = {
      "role": self.role,
      "content": content,
      "model": self.model,
      "resultType": self.result_type,
    }
    if self.stop_reason is not None:
      out["stopReason"] = self.stop_reason
    if self.meta is not None:
      out["_meta"] = self.meta
    return out


# ---------------------------------------------------------------------------
# §21.2.10  Consent & human-in-the-loop
# ---------------------------------------------------------------------------

class ConsentDecision(enum.Enum):
  """A user's decision on a sampling prompt or result (§21.2.10).

    APPROVE: proceed with the (possibly edited) prompt / result.
    REJECT: do not proceed; the originating request is not retried (§21.2.2).
  """

  APPROVE = "approve"
  REJECT = "reject"


@dataclass
class HumanInTheLoop:
  """Encapsulates the §21.2.10 consent / human-in-the-loop obligations.

  The client (or its host) MUST keep a human in the loop and MUST give the user
  the ability to deny a sampling request (R-21.2.10-a, R-21.2.10-b). Before
  sampling, it SHOULD present the prompt for review/edit/reject (R-21.2.10-c);
  after sampling it SHOULD present the result for review/edit/reject before the
  server is allowed to see it (R-21.2.10-d). As part of this control the client
  MAY modify or omit ``systemPrompt`` / ``includeContext`` / ``temperature`` /
  ``stopSequences`` / ``metadata`` (R-21.2.10-e).

  This type drives that flow through caller-supplied reviewers; the reviewers
  embody the actual UI. With no reviewers a sampling request still requires
  explicit approval — there is no implicit auto-approval, so the human-in-the-
  loop and deny-ability guarantees hold by construction.

  Fields:
    prompt_reviewer: returns the (possibly edited) params and a decision for the
      pre-sampling review (R-21.2.10-c). None ⇒ the request is auto-denied.
    result_reviewer: returns the (possibly edited) result and a decision for the
      post-sampling review (R-21.2.10-d). None ⇒ the result is auto-denied.
  """

  prompt_reviewer: (
    Callable[[CreateMessageRequestParams], tuple[ConsentDecision, CreateMessageRequestParams]]
    | None
  ) = None
  result_reviewer: (
    Callable[[CreateMessageResult], tuple[ConsentDecision, CreateMessageResult]]
    | None
  ) = None

  def review_prompt(
    self, params: CreateMessageRequestParams
  ) -> CreateMessageRequestParams:
    """Present the prompt for review/edit/reject before sampling (R-21.2.10-c/e).

    Returns the (possibly edited) params when the user approves. The reviewer
    MAY modify or omit ``systemPrompt`` / ``includeContext`` / ``temperature`` /
    ``stopSequences`` / ``metadata`` as part of this control (R-21.2.10-e).

    Raises:
      SamplingDeniedError: the user denied the request, or no reviewer is
        configured (no implicit approval) (R-21.2.10-a/b).
    """
    if self.prompt_reviewer is None:
      raise SamplingDeniedError(
        "no prompt reviewer configured; a sampling request MUST be reviewable "
        "and deniable by a human (R-21.2.10-a, R-21.2.10-b)"
      )
    decision, reviewed = self.prompt_reviewer(params)
    if decision is not ConsentDecision.APPROVE:
      raise SamplingDeniedError(
        "the user rejected the sampling prompt (R-21.2.10-b/c)"
      )
    return reviewed

  def review_result(self, result: CreateMessageResult) -> CreateMessageResult:
    """Present the completion for review/edit/reject before the server sees it (R-21.2.10-d).

    Returns the (possibly edited) result when the user approves. The result is
    only surfaced to the server after approval.

    Raises:
      SamplingDeniedError: the user denied the result, or no reviewer is
        configured (R-21.2.10-b/d).
    """
    if self.result_reviewer is None:
      raise SamplingDeniedError(
        "no result reviewer configured; the completion MUST be reviewable and "
        "deniable by a human before the server sees it (R-21.2.10-b, R-21.2.10-d)"
      )
    decision, reviewed = self.result_reviewer(result)
    if decision is not ConsentDecision.APPROVE:
      raise SamplingDeniedError(
        "the user rejected the sampling result before the server could see it "
        "(R-21.2.10-b/d)"
      )
    return reviewed


# ---------------------------------------------------------------------------
# §21.2.10  Rate limiting, content validation & tool-loop iteration limits
# ---------------------------------------------------------------------------

class RateLimiter:
  """A simple fixed-window rate limiter for sampling operations (R-21.2.10-f).

  Clients SHOULD implement rate limiting. This counts permits issued within a
  rolling fixed window of ``window_seconds`` and refuses once ``max_requests``
  is reached, protecting the client/host from runaway sampling loops.
  """

  def __init__(self, max_requests: int, window_seconds: float) -> None:
    if max_requests <= 0:
      raise ValueError("max_requests must be positive")
    if window_seconds <= 0:
      raise ValueError("window_seconds must be positive")
    self.max_requests = max_requests
    self.window_seconds = window_seconds
    self._timestamps: list[float] = []

  def allow(self, now: float) -> bool:
    """Return True if a request at time ``now`` is within the rate limit (R-21.2.10-f).

    Records the request when allowed. ``now`` is a monotonic seconds value
    supplied by the caller (kept explicit so the limiter is deterministic and
    testable).
    """
    cutoff = now - self.window_seconds
    self._timestamps = [t for t in self._timestamps if t > cutoff]
    if len(self._timestamps) >= self.max_requests:
      return False
    self._timestamps.append(now)
    return True


def validate_message_content(messages: list[SamplingMessage]) -> None:
  """Validate sampling message content end-to-end (R-21.2.10-g).

  Both parties SHOULD validate message content. This composes the structural
  constraints already enforced per message (tool-result exclusivity, R-21.2.7-a)
  with the cross-message ordering and reference constraints (R-21.2.7-b,
  R-21.2.6-d), giving callers one entry point to validate a full conversation.

  Raises:
    MalformedSamplingRequestError: any content/ordering/reference constraint
      is violated.
  """
  validate_tool_use_ordering(messages)
  validate_tool_result_references(messages)


def within_iteration_limit(iteration: int, max_iterations: int) -> bool:
  """Return True while a tool-use loop is within its iteration limit (R-21.2.10-i).

  When tools are used in sampling, both parties SHOULD implement iteration
  limits for tool loops to bound runaway tool-call cycles. ``iteration`` is the
  zero-based count of tool-use rounds completed so far.
  """
  if max_iterations <= 0:
    raise ValueError("max_iterations must be positive")
  return iteration < max_iterations
