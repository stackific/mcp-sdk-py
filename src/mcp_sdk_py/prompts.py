"""Prompts: Capability, Listing, Retrieval & Types — S28.

Delivers the **prompts** server feature: a server-offered set of named,
optionally-argumented templates that render into structured conversation
messages a client can feed to a language model (§18). Prompts are
**user-controlled** — surfaced from servers so a user explicitly selects them
(for example, as slash commands) — and the protocol mandates no particular
user-interaction pattern (R-18-a).

This story owns:
  - ``PromptsCapability``: the value of the ``prompts`` key in a server's
    capabilities object, with its OPTIONAL ``listChanged`` sub-flag, plus the
    gating discipline that a client MUST NOT call prompt methods against a
    server that did not declare the capability (§18.1).
  - ``ListPromptsRequestParams`` / ``ListPromptsResult``: the paginated (§12),
    cacheable (§13), result-typed (§3) discovery exchange (§18.2).
  - ``Prompt`` and ``PromptArgument``: the descriptor data types (§18.3).
  - ``GetPromptRequestParams`` / ``GetPromptResult`` and the ``input_required``
    alternative: the retrieval request, its rendered result, and the
    multi-round-trip retry fields (§18.4).
  - ``PromptMessage``: a role paired with exactly one ``ContentBlock`` (§18.5).
  - ``PromptListChangedNotification``: the ``notifications/prompts/list_changed``
    change notification (§18.6).
  - The error model mapping unknown-name / missing-required-argument to
    ``-32602`` and internal failure to ``-32603`` (§18.4).
  - The argument-completion hook reference (§18.7).

It REUSES rather than re-implements earlier-wave types:
  - ``ServerCapabilities`` / ``capability_is_present`` (S10, capabilities) for
    capability-presence gating.
  - ``PaginatedRequestParams`` (S18, pagination) for the ``cursor``/``nextCursor``
    mechanics.
  - ``VALID_CACHE_SCOPES`` / ``is_valid_ttl_ms`` (S19, caching) for ``ttlMs`` and
    ``cacheScope``, and ``RESULT_TYPE_COMPLETE`` (S04) for ``resultType``.
  - ``BaseMetadata`` / ``Icon`` (S20, common_types) for ``name``/``title``/``icons``.
  - ``ContentBlock`` / ``ParticipantRole`` / ``parse_content_block`` (S21,
    content_types) for ``PromptMessage``.
  - ``InputRequiredResult`` / ``InputResponseRequestParams`` / the retry
    machinery (S17, multi_round_trip) for the ``input_required`` alternative.

Out of scope (owned elsewhere): the capability-negotiation machinery (S10), the
``Cursor`` and pagination base shapes (S18), the caching mechanics behind
``ttlMs``/``cacheScope`` (S19), the ``ContentBlock`` member shapes and the
``Role`` enumeration (S21), the ``Icon`` shape and its trust rules (S20), the
multi-round-trip algorithm and ``InputRequiredResult`` type (S17), the streaming
delivery of the notification (S16), and the completion wire shapes (S29).

Spec: §18.1–§18.7
Depends on: S10 (capability gating), S18 (pagination), S19 (caching),
            S20 (BaseMetadata/Icon), S21 (ContentBlock/Role), S17 (multi-round-trip)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mcp_sdk_py.caching import (
  CACHE_SCOPE_PRIVATE,
  CACHE_SCOPE_PUBLIC,
  VALID_CACHE_SCOPES,
  is_valid_ttl_ms,
)
from mcp_sdk_py.capabilities import ServerCapabilities, capability_is_present
from mcp_sdk_py.common_types import BaseMetadata, Icon
from mcp_sdk_py.content_types import (
  ContentBlock,
  ParticipantRole,
  UnsupportedContentBlock,
  parse_content_block,
)
from mcp_sdk_py.multi_round_trip import InputRequiredResult, validate_input_required_result
from mcp_sdk_py.pagination import PaginatedRequestParams
from mcp_sdk_py.result_error import (
  RESULT_TYPE_COMPLETE,
  RESULT_TYPE_INPUT_REQUIRED,
  ResultType,
)


# ---------------------------------------------------------------------------
# §18  Method names, the capability key & the list-changed notification
# ---------------------------------------------------------------------------

#: The paginated, cacheable discovery request (§18.2).
METHOD_PROMPTS_LIST: str = "prompts/list"

#: The retrieval request, which may participate in a multi-round-trip exchange
#: (§18.4). Both prompt methods are gated by the ``prompts`` capability.
METHOD_PROMPTS_GET: str = "prompts/get"

#: The two requests a client MUST NOT send, and a server MUST NOT be expected to
#: answer, unless the ``prompts`` capability is declared (R-18.1-a/b).
PROMPT_GATED_REQUESTS: frozenset[str] = frozenset({
  METHOD_PROMPTS_LIST,
  METHOD_PROMPTS_GET,
})

#: The change notification a server MAY emit when its prompt set changes; gated
#: on the ``listChanged`` sub-flag (R-18.1-d/e, R-18.6-a/g). The exact method
#: string is REQUIRED to be this value (R-18.6-b).
NOTIFICATION_PROMPTS_LIST_CHANGED: str = "notifications/prompts/list_changed"

#: The capability key under a server's capabilities object (§18.1).
PROMPTS_CAPABILITY_KEY: str = "prompts"

#: The completion method a client uses to autocomplete a prompt-argument value
#: (§18.7 / §19). Named here only for the argument-completion hook reference; the
#: completion wire shapes and gating are owned by S29 (R-18.7-a).
METHOD_COMPLETION_COMPLETE: str = "completion/complete"

#: JSON-RPC error code for Invalid params — an unknown prompt name or a missing
#: required argument on ``prompts/get`` (R-18.3-m, R-18.4-d/g/s).
JSONRPC_INVALID_PARAMS: int = -32602

#: JSON-RPC error code for Internal error — an internal failure rendering a
#: prompt (R-18.4-s).
JSONRPC_INTERNAL_ERROR: int = -32603


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class PromptsCapabilityNotDeclaredError(Exception):
  """A prompt request was attempted though the ``prompts`` capability was undeclared.

  Raised by the gating helpers (R-18.1-a, R-18.1-b): a client MUST NOT send
  ``prompts/list`` or ``prompts/get`` to a server that has not declared the
  ``prompts`` capability during version negotiation, and a server that has not
  declared it is not expected to answer. This is a local conformance guard,
  distinct from any on-the-wire JSON-RPC error.

  Attributes:
    method: the prompt method that was gated (``prompts/list`` or ``prompts/get``).
  """

  def __init__(self, method: str) -> None:
    super().__init__(
      f"Method {method!r} requires the 'prompts' capability, which the server "
      f"did not declare; a client MUST NOT send it and a server is not expected "
      f"to answer (R-18.1-a, R-18.1-b)"
    )
    self.method: str = method


class UnknownPromptError(Exception):
  """The ``prompts/get`` ``name`` does not match any prompt the server offers.

  The server SHOULD reject the request with JSON-RPC error code ``-32602``
  (Invalid params) (R-18.4-c/d, R-18.4-s, AC-28.29).

  Attributes:
    name: the unknown prompt name from the request.
    json_rpc_code: always ``-32602`` for callers building error responses.
  """

  json_rpc_code: int = JSONRPC_INVALID_PARAMS

  def __init__(self, name: str) -> None:
    super().__init__(
      f"No prompt named {name!r} is offered by this server; reject prompts/get "
      f"with JSON-RPC {JSONRPC_INVALID_PARAMS} (Invalid params) "
      f"(R-18.4-c, R-18.4-d, R-18.4-s)"
    )
    self.name: str = name


class MissingRequiredArgumentError(Exception):
  """A ``prompts/get`` request omitted an argument the prompt declares required.

  A client MUST supply a value for every argument declared with ``required:
  true`` (R-18.3-l, R-18.4-e); a server SHOULD reject a request missing one with
  JSON-RPC error code ``-32602`` (Invalid params) (R-18.3-m, R-18.4-g, R-18.4-s,
  AC-28.27, AC-28.30).

  Attributes:
    argument: the name of the missing required argument.
    json_rpc_code: always ``-32602`` for callers building error responses.
  """

  json_rpc_code: int = JSONRPC_INVALID_PARAMS

  def __init__(self, argument: str) -> None:
    super().__init__(
      f"Required prompt argument {argument!r} was not supplied; reject "
      f"prompts/get with JSON-RPC {JSONRPC_INVALID_PARAMS} (Invalid params) "
      f"(R-18.3-l, R-18.3-m, R-18.4-e, R-18.4-g, R-18.4-s)"
    )
    self.argument: str = argument


# ---------------------------------------------------------------------------
# §18.1  The `prompts` capability  [R-18.1-a, R-18.1-c, R-18.1-d, R-18.1-e]
# ---------------------------------------------------------------------------

@dataclass
class PromptsCapability:
  """The value of the ``prompts`` key in a server's capabilities object (§18.1).

  Its mere presence declares that the server offers prompts and so MUST appear
  during version negotiation for a prompts server (R-18.1-a, AC-28.2). The
  object carries one OPTIONAL boolean sub-flag (R-18.1-c, AC-28.4):

  Fields:
    list_changed: when ``True`` the server MAY emit
      ``notifications/prompts/list_changed`` whenever its prompt set changes
      (R-18.1-d, AC-28.5). When absent (``None``) or ``False`` the server MUST
      NOT be expected to emit it and a client MUST NOT rely on receiving it
      (R-18.1-e, R-18.1-f, AC-28.6). Wire key: ``listChanged``.
  """

  list_changed: bool | None = None  # JSON key: listChanged

  def __post_init__(self) -> None:
    if self.list_changed is not None and not isinstance(self.list_changed, bool):
      raise TypeError(
        "PromptsCapability.listChanged must be a boolean when present (R-18.1-c)"
      )

  @property
  def emits_list_changed(self) -> bool:
    """True only when ``listChanged`` is explicitly ``True`` (R-18.1-d/e, AC-28.6).

    A server emits ``notifications/prompts/list_changed`` only when this is True;
    a client MUST NOT rely on receiving it otherwise (R-18.1-f).
    """
    return self.list_changed is True

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> PromptsCapability:
    """Parse a wire ``PromptsCapability`` object; an empty object ``{}`` is valid.

    Both presence and absence of ``listChanged`` are accepted (R-18.1-c,
    AC-28.4). ``listChanged`` MUST be a boolean if present. Unknown keys are
    ignored for forward compatibility.

    Raises:
      TypeError: ``data`` is not an object, or ``listChanged`` is not a boolean.
    """
    if not isinstance(data, dict):
      raise TypeError(
        f"PromptsCapability must be a JSON object; got {type(data).__name__} "
        f"(R-18.1-a)"
      )
    raw = data.get("listChanged")
    if raw is not None and not isinstance(raw, bool):
      raise TypeError(
        "PromptsCapability.listChanged must be a boolean when present (R-18.1-c)"
      )
    return cls(list_changed=raw)

  def to_dict(self) -> dict[str, Any]:
    """Serialise to the wire object; omits ``listChanged`` when absent (None).

    A capability with no sub-flag serialises to an empty object ``{}``, which is
    still a valid declaration of the feature (R-18.1-a/c).
    """
    out: dict[str, Any] = {}
    if self.list_changed is not None:
      out["listChanged"] = self.list_changed
    return out


# ---------------------------------------------------------------------------
# §18.1  Capability gating  [R-18.1-a, R-18.1-b, R-18.1-d–g]
# ---------------------------------------------------------------------------

def prompts_capability_declared(server_caps: ServerCapabilities) -> bool:
  """Return True if the server declared the ``prompts`` capability (R-18.1-a, §6.1).

  Presence-means-supported (§6.1): the ``prompts`` field — even with an empty
  object value ``{}`` — declares the capability; absence declares it is not
  supported (AC-28.2). This is the single gate that opens both prompt requests
  and the list-changed notification.
  """
  return capability_is_present(server_caps.to_dict(), PROMPTS_CAPABILITY_KEY)


def client_may_send_prompt_request(
  server_caps: ServerCapabilities,
  method: str = METHOD_PROMPTS_LIST,
) -> bool:
  """Return True if a client may send ``method`` to this server (R-18.1-b).

  A client MUST NOT send ``prompts/list`` or ``prompts/get`` to a server that has
  not declared the ``prompts`` capability (AC-28.3). Only the two prompt methods
  are gated; any other method passed here is treated as ungated (returns True).
  """
  if method not in PROMPT_GATED_REQUESTS:
    return True
  return prompts_capability_declared(server_caps)


def assert_client_may_send_prompt_request(
  server_caps: ServerCapabilities,
  method: str = METHOD_PROMPTS_LIST,
) -> None:
  """Raise if a client may not send ``method`` to this server (R-18.1-b).

  Call this on the client before issuing ``prompts/list`` or ``prompts/get``.

  Raises:
    PromptsCapabilityNotDeclaredError: the server has not declared ``prompts``.
  """
  if not client_may_send_prompt_request(server_caps, method):
    raise PromptsCapabilityNotDeclaredError(method)


def server_may_emit_list_changed(server_caps: ServerCapabilities) -> bool:
  """Return True if the server may emit ``notifications/prompts/list_changed``.

  Requires BOTH that ``prompts`` is declared (R-18.1-a) and that the
  ``listChanged`` sub-flag is ``true`` (R-18.1-d, R-18.6-a/g, AC-28.39). When
  ``prompts`` is undeclared this is False even if a stray sub-flag value appears.
  """
  raw = server_caps.prompts
  if raw is None:
    return False
  return PromptsCapability.from_dict(raw).emits_list_changed


def client_may_rely_on_list_changed(server_caps: ServerCapabilities) -> bool:
  """Return True only if the server declared ``prompts.listChanged: true`` (R-18.1-f).

  A client MUST NOT rely on receiving ``notifications/prompts/list_changed``
  unless the server declared ``listChanged: true`` (R-18.1-e/f, AC-28.6). When
  ``prompts`` is absent, or ``listChanged`` is absent or ``false``, this returns
  False — the client may still re-fetch on its own schedule per ``ttlMs``.
  """
  return server_may_emit_list_changed(server_caps)


# ---------------------------------------------------------------------------
# §18.3  PromptArgument  [R-18.3-j, R-18.3-k, R-18.3-l]
# ---------------------------------------------------------------------------

@dataclass
class PromptArgument:
  """One argument a prompt accepts for templating; carries ``BaseMetadata`` (§18.3).

  Fields:
    name: REQUIRED programmatic identifier, from BaseMetadata; the key under
      which the client supplies a value in the ``arguments`` map of
      ``prompts/get`` (R-18.3-j, AC-28.26).
    title: OPTIONAL human-readable display name, from BaseMetadata; when absent,
      ``name`` SHOULD be used for display — see :meth:`display_name`
      (R-18.3-k, AC-28.26).
    description: OPTIONAL human-readable description of the argument.
    required: OPTIONAL; when ``True`` the argument MUST be provided in a
      ``prompts/get`` request (R-18.3-l, AC-28.27). When absent or ``False`` the
      argument is optional.
  """

  name: str
  title: str | None = None
  description: str | None = None
  required: bool | None = None

  def __post_init__(self) -> None:
    # Validate name/title via BaseMetadata so the identity contract (R-14.1) and
    # the REQUIRED-name rule (R-18.3-j) are enforced consistently.
    BaseMetadata(name=self.name, title=self.title)
    if self.description is not None and not isinstance(self.description, str):
      raise TypeError(
        "PromptArgument.description must be a string when present (§18.3)"
      )
    if self.required is not None and not isinstance(self.required, bool):
      raise TypeError(
        "PromptArgument.required must be a boolean when present (R-18.3-l)"
      )

  @property
  def is_required(self) -> bool:
    """True only when ``required`` is explicitly ``True`` (R-18.3-l).

    An absent or ``False`` ``required`` flag means the argument is optional.
    """
    return self.required is True

  def display_name(self) -> str:
    """Resolve the user-facing label: prefer ``title``, fall back to ``name`` (R-18.3-k)."""
    return self.title if self.title is not None else self.name

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> PromptArgument:
    """Deserialise a ``PromptArgument`` from a JSON-decoded dict (§18.3).

    Unknown keys are ignored for forward compatibility.

    Raises:
      TypeError: ``data`` is not a dict, or a field has the wrong type.
      ValueError/KeyError: ``name`` is missing or invalid.
    """
    if not isinstance(data, dict):
      raise TypeError(
        f"PromptArgument must be a JSON object; got {type(data).__name__}"
      )
    return cls(
      name=data["name"],
      title=data.get("title"),
      description=data.get("description"),
      required=data.get("required"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a JSON-compatible dict; omits absent optional fields (§18.3)."""
    out: dict[str, Any] = {"name": self.name}
    if self.title is not None:
      out["title"] = self.title
    if self.description is not None:
      out["description"] = self.description
    if self.required is not None:
      out["required"] = self.required
    return out


# ---------------------------------------------------------------------------
# §18.3  Prompt  [R-18.3-a, R-18.3-b, R-18.3-c, R-18.3-d]
# ---------------------------------------------------------------------------

@dataclass
class Prompt:
  """A single prompt or prompt template offered by the server (§18.3).

  Composes ``BaseMetadata`` (``name``/``title``, §14) and an optional icon set
  (§14). The ``Icon`` shape and its MIME-type/trust rules are owned and validated
  by S20 (§14.2); this type carries ``icons`` and references that shape but does
  not independently re-assert those rules (R-18.3-d/e–i are owned by S20).

  Fields:
    name: REQUIRED programmatic identifier; the value a client supplies in
      ``prompts/get`` and the fallback display name when ``title`` is absent
      (R-18.3-a, R-18.3-b, AC-28.21).
    title: OPTIONAL human-readable display name; when absent, ``name`` SHOULD be
      used for display — see :meth:`display_name` (R-18.3-b, AC-28.21).
    description: OPTIONAL human-readable description of what the prompt provides.
    arguments: OPTIONAL list of ``PromptArgument``; when absent or empty the
      prompt accepts no arguments (R-18.3-c, AC-28.22).
    icons: OPTIONAL list of ``Icon`` the client MAY display (R-18.3-d, AC-28.23).
    meta: OPTIONAL reserved metadata map; JSON key ``_meta``.
  """

  name: str
  title: str | None = None
  description: str | None = None
  arguments: list[PromptArgument] | None = None
  icons: list[Icon] | None = None
  meta: dict[str, Any] | None = None  # JSON key: _meta

  def __post_init__(self) -> None:
    # R-18.3-a: name is REQUIRED; validate name/title via BaseMetadata (R-14.1).
    BaseMetadata(name=self.name, title=self.title)
    if self.description is not None and not isinstance(self.description, str):
      raise TypeError("Prompt.description must be a string when present (§18.3)")
    if self.arguments is not None:
      if not isinstance(self.arguments, list):
        raise TypeError("Prompt.arguments must be a list when present (R-18.3-c)")
      for entry in self.arguments:
        if not isinstance(entry, PromptArgument):
          raise TypeError(
            f"Prompt.arguments entries must be PromptArgument objects; got "
            f"{entry!r} (R-18.3-c)"
          )
    if self.icons is not None:
      if not isinstance(self.icons, list):
        raise TypeError("Prompt.icons must be a list when present (R-18.3-d)")
      for entry in self.icons:
        if not isinstance(entry, Icon):
          raise TypeError(
            f"Prompt.icons entries must be Icon objects; got {entry!r} (R-18.3-d)"
          )
    if self.meta is not None and not isinstance(self.meta, dict):
      raise TypeError("Prompt._meta must be a JSON object when present (§18.3)")

  @property
  def accepts_no_arguments(self) -> bool:
    """True when ``arguments`` is absent or empty — the prompt takes none (R-18.3-c)."""
    return not self.arguments

  @property
  def required_argument_names(self) -> list[str]:
    """The names of the arguments declared ``required: true`` (R-18.3-l)."""
    if not self.arguments:
      return []
    return [a.name for a in self.arguments if a.is_required]

  def display_name(self) -> str:
    """Resolve the user-facing label: prefer ``title``, fall back to ``name`` (R-18.3-b)."""
    return self.title if self.title is not None else self.name

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> Prompt:
    """Deserialise a ``Prompt`` from a JSON-decoded dict (§18.3).

    Nested ``arguments`` and ``icons`` are converted to their typed objects;
    unknown keys are ignored for forward compatibility.

    Raises:
      TypeError: ``data`` is not a dict.
      ValueError/KeyError: a REQUIRED field is missing or invalid.
    """
    if not isinstance(data, dict):
      raise TypeError(f"Prompt must be a JSON object; got {type(data).__name__}")
    raw_args = data.get("arguments")
    raw_icons = data.get("icons")
    return cls(
      name=data["name"],
      title=data.get("title"),
      description=data.get("description"),
      arguments=(
        [PromptArgument.from_dict(a) for a in raw_args]
        if raw_args is not None
        else None
      ),
      icons=[Icon.from_dict(i) for i in raw_icons] if raw_icons is not None else None,
      meta=data.get("_meta"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a JSON-compatible dict; omits absent optional fields (§18.3)."""
    out: dict[str, Any] = {"name": self.name}
    if self.title is not None:
      out["title"] = self.title
    if self.description is not None:
      out["description"] = self.description
    if self.arguments is not None:
      out["arguments"] = [a.to_dict() for a in self.arguments]
    if self.icons is not None:
      out["icons"] = [i.to_dict() for i in self.icons]
    if self.meta is not None:
      out["_meta"] = self.meta
    return out


# ---------------------------------------------------------------------------
# §18.2  `prompts/list` request params  [R-18.2-a, R-18.2-b, R-18.2-c]
# ---------------------------------------------------------------------------

@dataclass
class ListPromptsRequestParams(PaginatedRequestParams):
  """The ``params`` of a ``prompts/list`` request (§18.2); a PaginatedRequestParams (§12).

  ``cursor`` is OPTIONAL (R-18.2-a) and ``_meta`` (``meta``) is OPTIONAL. No
  additional members are defined by this method. The client MUST treat any
  ``cursor`` as opaque and MUST NOT construct, parse, or modify it (R-18.2-b/c,
  AC-28.11); a client constructs one only by passing back a server-issued
  ``nextCursor`` verbatim.
  """

  @classmethod
  def from_dict(cls, raw: dict[str, Any] | None) -> ListPromptsRequestParams:
    """Parse ``prompts/list`` request params; ``None`` or ``{}`` means the first page.

    ``cursor`` MUST be a string if present (and is treated as opaque, R-18.2-b/c);
    the empty string ``""`` is a valid present cursor (§12). Unknown keys are
    kept in ``extra``.

    Raises:
      TypeError: ``raw`` is not an object, or a field has the wrong type.
    """
    if raw is None:
      return cls()
    if not isinstance(raw, dict):
      raise TypeError(
        f"prompts/list params must be a JSON object; got {type(raw).__name__}"
      )
    cursor = raw.get("cursor")
    if cursor is not None and not isinstance(cursor, str):
      raise TypeError(
        f"cursor must be an opaque string when present; got "
        f"{type(cursor).__name__} (R-18.2-a)"
      )
    meta = raw.get("_meta")
    if meta is not None and not isinstance(meta, dict):
      raise TypeError(
        f"_meta must be a JSON object when present; got {type(meta).__name__}"
      )
    extra = {k: v for k, v in raw.items() if k not in {"cursor", "_meta"}}
    return cls(cursor=cursor, meta=meta, extra=extra)


# ---------------------------------------------------------------------------
# §18.2  `ListPromptsResult`  [R-18.2-d … R-18.2-q]
# ---------------------------------------------------------------------------

@dataclass
class ListPromptsResult:
  """The result of ``prompts/list`` (§18.2).

  Simultaneously a paginated result (§12: ``nextCursor``), a cacheable result
  (§13: ``ttlMs``/``cacheScope``), and a result-typed result (§3: ``resultType``)
  wrapping a page of ``Prompt`` definitions.

  The ``prompts`` set is the set currently available to the requesting client; it
  MAY be empty and MAY change over time, but MUST NOT vary per-connection or as a
  side effect of other requests on the same connection — though it MAY vary by
  per-request authorization (R-18.1-g/h/i/j, AC-28.7–AC-28.10). Those properties
  are behavioural and are not enforced by this data type; the type carries the
  page exactly as the server produced it.

  Fields:
    prompts: REQUIRED page of ``Prompt`` definitions; MAY be empty (R-18.2-d,
      AC-28.12).
    ttl_ms: REQUIRED non-negative client-cache freshness hint in milliseconds;
      ``0`` ⇒ immediately stale, positive ⇒ fresh for that many ms after receipt
      (R-18.2-h/i/j/k, §13, AC-28.14–AC-28.16). Wire key: ``ttlMs``.
    cache_scope: REQUIRED enum ``"public"`` | ``"private"`` (R-18.2-l/m, §13,
      AC-28.17). Wire key: ``cacheScope``.
    next_cursor: OPTIONAL opaque token for the position after the last returned
      prompt; present ⇒ more MAY exist, absent ⇒ last page at response time
      (R-18.2-e/f/g, §12, AC-28.13). Wire key: ``nextCursor``.
    result_type: REQUIRED discriminator; for a completed list the value is
      ``"complete"`` (R-18.2-n/o/p, §3, AC-28.18). Wire key: ``resultType``.
    meta: OPTIONAL reserved metadata map (R-18.2-q, AC-28.19). Wire key: ``_meta``.
  """

  prompts: list[Prompt]
  ttl_ms: int
  cache_scope: str
  next_cursor: str | None = None                  # JSON key: nextCursor
  result_type: ResultType = RESULT_TYPE_COMPLETE  # JSON key: resultType
  meta: dict[str, Any] | None = None              # JSON key: _meta

  def __post_init__(self) -> None:
    # R-18.2-d: prompts is REQUIRED and is an array of Prompt definitions (MAY be empty).
    if not isinstance(self.prompts, list):
      raise TypeError("ListPromptsResult.prompts must be a list (R-18.2-d)")
    for entry in self.prompts:
      if not isinstance(entry, Prompt):
        raise TypeError(
          f"ListPromptsResult.prompts entries must be Prompt objects; got "
          f"{entry!r} (R-18.2-d)"
        )
    # R-18.2-h: ttlMs is REQUIRED, a non-negative integer (minimum 0).
    if not is_valid_ttl_ms(self.ttl_ms):
      raise ValueError(
        f"ttlMs is REQUIRED and must be a non-negative integer; got "
        f"{self.ttl_ms!r} (R-18.2-h)"
      )
    # R-18.2-l: cacheScope is REQUIRED, exactly "public" or "private".
    if self.cache_scope not in VALID_CACHE_SCOPES:
      raise ValueError(
        f"cacheScope is REQUIRED and must be exactly 'public' or 'private'; got "
        f"{self.cache_scope!r} (R-18.2-l)"
      )
    if self.next_cursor is not None and not isinstance(self.next_cursor, str):
      raise TypeError(
        f"nextCursor must be an opaque string when present; got "
        f"{type(self.next_cursor).__name__} (R-18.2-e)"
      )
    # R-18.2-n/o: resultType is REQUIRED; for a list response it is "complete".
    if not isinstance(self.result_type, str) or not self.result_type:
      raise ValueError("ListPromptsResult.resultType is REQUIRED (R-18.2-n)")
    if self.meta is not None and not isinstance(self.meta, dict):
      raise TypeError("ListPromptsResult._meta must be a JSON object when present (R-18.2-q)")

  @property
  def is_last_page(self) -> bool:
    """True when ``nextCursor`` is absent — this is the final page (R-18.2-e, §12)."""
    return self.next_cursor is None

  @property
  def is_immediately_stale(self) -> bool:
    """True when ``ttlMs`` is 0 — the result SHOULD be considered immediately stale (R-18.2-i)."""
    return self.ttl_ms == 0

  @property
  def is_public(self) -> bool:
    """True when ``cacheScope`` is ``"public"`` — any client/intermediary MAY cache it (§13)."""
    return self.cache_scope == CACHE_SCOPE_PUBLIC

  @property
  def is_private(self) -> bool:
    """True when ``cacheScope`` is ``"private"`` — shared caches MUST NOT serve it to others (R-18.2-m)."""
    return self.cache_scope == CACHE_SCOPE_PRIVATE

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> ListPromptsResult:
    """Parse a wire ``prompts/list`` result (§18.2).

    Validates that ``prompts`` is a present array (R-18.2-d), ``ttlMs`` is a
    present non-negative integer (R-18.2-h), ``cacheScope`` is present and
    exactly ``"public"``/``"private"`` (R-18.2-l), and ``nextCursor`` is opaque
    when present (R-18.2-e). A result lacking ``resultType`` is treated as
    ``"complete"`` (R-18.2-p, AC-28.18). Nested prompts are parsed via
    :meth:`Prompt.from_dict`.

    Raises:
      TypeError / ValueError: a required field is absent or has the wrong
        type/value.
    """
    if not isinstance(data, dict):
      raise TypeError(
        f"prompts/list result must be a JSON object; got {type(data).__name__}"
      )
    if "prompts" not in data:
      raise ValueError("ListPromptsResult.prompts is REQUIRED (R-18.2-d)")
    raw_prompts = data["prompts"]
    if not isinstance(raw_prompts, list):
      raise TypeError("ListPromptsResult.prompts must be an array (R-18.2-d)")
    if "ttlMs" not in data:
      raise ValueError("ttlMs is REQUIRED on a prompts/list result (R-18.2-h)")
    if "cacheScope" not in data:
      raise ValueError("cacheScope is REQUIRED on a prompts/list result (R-18.2-l)")
    # R-18.2-p: a client receiving a result lacking resultType treats it as "complete".
    return cls(
      prompts=[Prompt.from_dict(p) for p in raw_prompts],
      ttl_ms=data["ttlMs"],
      cache_scope=data["cacheScope"],
      next_cursor=data.get("nextCursor"),
      result_type=data.get("resultType", RESULT_TYPE_COMPLETE),
      meta=data.get("_meta"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire-compatible dict; omits absent optional fields (§18.2).

    ``resultType``, ``prompts``, ``ttlMs``, and ``cacheScope`` are always present
    (all REQUIRED); ``nextCursor`` and ``_meta`` appear only when present. A
    server MUST include ``resultType`` (R-18.2-o).
    """
    out: dict[str, Any] = {
      "resultType": self.result_type,
      "prompts": [p.to_dict() for p in self.prompts],
      "ttlMs": self.ttl_ms,
      "cacheScope": self.cache_scope,
    }
    if self.next_cursor is not None:
      out["nextCursor"] = self.next_cursor
    if self.meta is not None:
      out["_meta"] = self.meta
    return out


def next_prompts_list_request(
  result: ListPromptsResult,
) -> ListPromptsRequestParams | None:
  """Build the follow-up ``prompts/list`` params for the next page, or None (R-18.2-e/f/g).

  When ``result.next_cursor`` is present, more results MAY exist and the client
  MAY issue another ``prompts/list`` with ``params.cursor`` set to that value
  (R-18.2-e, AC-28.13). The value is passed through verbatim — never parsed or
  reconstructed (R-18.2-f, R-18.2-g). When ``next_cursor`` is absent this is the
  last page and None is returned.
  """
  if result.next_cursor is None:
    return None
  return ListPromptsRequestParams(cursor=result.next_cursor)


# ---------------------------------------------------------------------------
# §18.5  PromptMessage  [R-18.5-a, R-18.5-b, R-18.5-c]
# ---------------------------------------------------------------------------

#: The ``ContentBlock`` kinds valid inside a ``PromptMessage`` (§18.5). The full
#: field shapes are owned by S21 (§14.4); this set names which kinds a prompt
#: message admits.
VALID_PROMPT_CONTENT_TYPES: frozenset[str] = frozenset({
  "text",
  "image",
  "audio",
  "resource_link",
  "resource",
})


@dataclass
class PromptMessage:
  """One message within a prompt: a role paired with a single content block (§18.5).

  Fields:
    role: REQUIRED ``ParticipantRole`` — ``"user"`` or ``"assistant"`` (§14.7);
      the speaker of the message (R-18.5-a, AC-28.37).
    content: REQUIRED — exactly one ``ContentBlock`` (a single object, not an
      array). Valid kinds are text, image, audio, resource_link, and embedded
      resource (R-18.5-b/c, AC-28.37, AC-28.38). The member shapes are owned by
      S21 (§14.4).
  """

  role: ParticipantRole
  content: ContentBlock

  def __post_init__(self) -> None:
    # R-18.5-a: role is REQUIRED and is one of the Role values "user"/"assistant".
    if not isinstance(self.role, ParticipantRole):
      raise TypeError(
        f"PromptMessage.role must be a ParticipantRole ('user'/'assistant'); "
        f"got {self.role!r} (R-18.5-a)"
      )
    # R-18.5-b: content is REQUIRED and is exactly one content block, not an array.
    if isinstance(self.content, (list, tuple)):
      raise TypeError(
        "PromptMessage.content must be exactly one content block, not an array "
        "(R-18.5-b)"
      )
    if isinstance(self.content, UnsupportedContentBlock):
      raise TypeError(
        f"PromptMessage.content is an unsupported content block of type "
        f"{self.content.type!r}; a prompt message requires a recognized "
        f"ContentBlock (R-18.5-b)"
      )

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> PromptMessage:
    """Deserialise a ``PromptMessage`` from a JSON-decoded dict (§18.5).

    ``role`` MUST be ``"user"`` or ``"assistant"`` (R-18.5-a); ``content`` MUST be
    a single content-block object (not an array) dispatched via S21's
    :func:`parse_content_block` (R-18.5-b).

    Raises:
      TypeError: ``data`` is not a dict, ``role``/``content`` has the wrong type,
        or ``content`` is an array.
      ValueError: ``role`` is not a valid ``Role`` value, or ``content`` is a
        missing/forbidden content kind.
    """
    if not isinstance(data, dict):
      raise TypeError(
        f"PromptMessage must be a JSON object; got {type(data).__name__}"
      )
    if "role" not in data:
      raise ValueError("PromptMessage.role is REQUIRED (R-18.5-a)")
    # ParticipantRole is a CLOSED enum; an invalid value raises ValueError (R-18.5-a).
    role = ParticipantRole(data["role"])
    raw_content = data.get("content")
    if raw_content is None:
      raise ValueError("PromptMessage.content is REQUIRED (R-18.5-b)")
    if isinstance(raw_content, list):
      raise TypeError(
        "PromptMessage.content must be a single content block, not an array "
        "(R-18.5-b)"
      )
    if not isinstance(raw_content, dict):
      raise TypeError(
        f"PromptMessage.content must be a content-block object; got "
        f"{type(raw_content).__name__} (R-18.5-b)"
      )
    content = parse_content_block(raw_content)
    return cls(role=role, content=content)

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a JSON-compatible dict (§18.5).

    ``content`` is always a single object (never an array), per R-18.5-b.
    """
    return {"role": self.role.value, "content": self.content.to_dict()}


# ---------------------------------------------------------------------------
# §18.4  `prompts/get` request params  [R-18.4-a, R-18.4-b]
# ---------------------------------------------------------------------------

@dataclass
class GetPromptRequestParams:
  """The ``params`` of a ``prompts/get`` request (§18.4).

  May participate in a multi-round-trip exchange (§11): the ``inputResponses``
  and ``requestState`` fields carry the retry payload (R-18.4-a, AC-28.28). On a
  first attempt both are omitted.

  Fields:
    name: REQUIRED identifier of the prompt to retrieve; MUST match a
      ``Prompt.name`` the server offers (R-18.4-b/c, AC-28.29).
    arguments: OPTIONAL map of argument name → JSON-string value, keyed by
      ``PromptArgument.name``. MUST include every argument declared
      ``required: true`` (R-18.4-e, AC-28.27). Wire key: ``arguments``.
    input_responses: OPTIONAL multi-round-trip retry responses (§11). For each
      key in the server's prior ``inputRequests``, the same key MUST appear here
      with its response value (R-18.4-h, AC-28.31). Wire key: ``inputResponses``.
    request_state: OPTIONAL opaque multi-round-trip continuation token (§11);
      when the server supplied one, the client MUST echo it verbatim and MUST NOT
      interpret or modify it (R-18.4-i/j/k, AC-28.32). Wire key: ``requestState``.
    meta: OPTIONAL reserved ``_meta`` map (§14). Wire key: ``_meta``.
  """

  name: str
  arguments: dict[str, str] | None = None
  input_responses: dict[str, Any] | None = None  # JSON key: inputResponses
  request_state: str | None = None               # JSON key: requestState
  meta: dict[str, Any] | None = None             # JSON key: _meta

  def __post_init__(self) -> None:
    # R-18.4-b: name is REQUIRED.
    if not isinstance(self.name, str) or not self.name:
      raise ValueError(
        "GetPromptRequestParams.name is REQUIRED and must be a non-empty string "
        "(R-18.4-b)"
      )
    if self.arguments is not None:
      if not isinstance(self.arguments, dict):
        raise TypeError("GetPromptRequestParams.arguments must be a JSON object when present (§18.4)")
      for key, value in self.arguments.items():
        if not isinstance(value, str):
          raise TypeError(
            f"GetPromptRequestParams.arguments[{key!r}] must be a JSON string; "
            f"got {type(value).__name__} (§18.4)"
          )
    if self.input_responses is not None and not isinstance(self.input_responses, dict):
      raise TypeError(
        "GetPromptRequestParams.inputResponses must be a JSON object when present "
        "(R-18.4-h)"
      )
    if self.request_state is not None and not isinstance(self.request_state, str):
      raise TypeError(
        "GetPromptRequestParams.requestState must be an opaque string when "
        "present (R-18.4-i/j/k)"
      )
    if self.meta is not None and not isinstance(self.meta, dict):
      raise TypeError("GetPromptRequestParams._meta must be a JSON object when present (§18.4)")

  @property
  def is_retry(self) -> bool:
    """True when this carries multi-round-trip retry fields (§11, R-18.4-a).

    A retry supplies ``inputResponses`` and/or echoes ``requestState``; a first
    attempt carries neither.
    """
    return self.input_responses is not None or self.request_state is not None

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> GetPromptRequestParams:
    """Parse ``prompts/get`` request params from a wire dict (§18.4).

    ``name`` is REQUIRED (R-18.4-b). ``arguments`` values MUST be JSON strings.
    The multi-round-trip ``inputResponses``/``requestState`` fields are optional
    and omitted on a first attempt (R-18.4-a). Unknown keys are ignored.

    Raises:
      TypeError: ``data`` is not a dict, or a field has the wrong type.
      ValueError/KeyError: ``name`` is missing or invalid.
    """
    if not isinstance(data, dict):
      raise TypeError(
        f"prompts/get params must be a JSON object; got {type(data).__name__}"
      )
    if "name" not in data:
      raise ValueError("GetPromptRequestParams.name is REQUIRED (R-18.4-b)")
    return cls(
      name=data["name"],
      arguments=data.get("arguments"),
      input_responses=data.get("inputResponses"),
      request_state=data.get("requestState"),
      meta=data.get("_meta"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire-compatible dict; omits absent optional fields (§18.4).

    On a retry, ``inputResponses`` and ``requestState`` (echoed verbatim) appear;
    on a first attempt they are omitted (R-18.4-a/h/i).
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
# §18.4  Argument validation & error mapping  [R-18.3-l/m, R-18.4-c–g, R-18.4-s]
# ---------------------------------------------------------------------------

def validate_get_prompt_arguments(
  prompt: Prompt,
  arguments: dict[str, str] | None,
) -> None:
  """Validate ``prompts/get`` arguments against a prompt's declared arguments (§18.4).

  A server SHOULD validate supplied arguments before processing (R-18.4-f) and
  SHOULD reject a request missing a required argument with ``-32602`` (Invalid
  params) (R-18.3-m, R-18.4-g, R-18.4-s, AC-28.30). A client MUST supply a value
  for every argument the prompt declares ``required: true`` (R-18.3-l, R-18.4-e,
  AC-28.27).

  Args:
    prompt: the offered ``Prompt`` whose declared arguments are checked.
    arguments: the supplied ``arguments`` map, or None when none were supplied.

  Raises:
    MissingRequiredArgumentError: a required argument has no supplied value
      (json_rpc_code -32602).
  """
  supplied = arguments or {}
  for name in prompt.required_argument_names:
    if name not in supplied:
      raise MissingRequiredArgumentError(name)


def resolve_prompt_for_get(
  params: GetPromptRequestParams,
  offered: dict[str, Prompt] | list[Prompt],
) -> Prompt:
  """Resolve and validate a ``prompts/get`` request against the offered prompts (§18.4).

  Enforces the server-side checks this story maps onto JSON-RPC error codes
  (R-18.4-c/d/f/g, R-18.4-s, AC-28.29, AC-28.30, AC-28.36):
    - the request ``name`` MUST match a prompt the server offers, else
      ``-32602`` (Invalid params) via :class:`UnknownPromptError` (R-18.4-c/d);
    - every required argument MUST be supplied, else ``-32602`` via
      :class:`MissingRequiredArgumentError` (R-18.3-m, R-18.4-g).

  Args:
    params: the parsed ``prompts/get`` request params.
    offered: the prompts the server offers, as a name→Prompt map or a list.

  Returns:
    The matched ``Prompt``.

  Raises:
    UnknownPromptError: no offered prompt matches ``params.name`` (code -32602).
    MissingRequiredArgumentError: a required argument is missing (code -32602).
  """
  by_name: dict[str, Prompt]
  if isinstance(offered, dict):
    by_name = offered
  else:
    by_name = {p.name: p for p in offered}
  prompt = by_name.get(params.name)
  if prompt is None:
    raise UnknownPromptError(params.name)
  validate_get_prompt_arguments(prompt, params.arguments)
  return prompt


# ---------------------------------------------------------------------------
# §18.4  `GetPromptResult` and the `input_required` alternative
#        [R-18.4-l … R-18.4-r]
# ---------------------------------------------------------------------------

@dataclass
class GetPromptResult:
  """The result of a successful, completed ``prompts/get`` (§18.4).

  When the server needs more input it returns an ``InputRequiredResult`` instead
  (defined in §11 / S17), signalled by ``resultType: "input_required"`` — see
  :func:`parse_get_prompt_response` and :func:`is_input_required` (R-18.4-q).

  Fields:
    messages: REQUIRED ordered list of ``PromptMessage`` constituting the prompt;
      MAY contain a single message or several (R-18.4-l/m, AC-28.33).
    description: OPTIONAL human-readable description of the rendered prompt.
    result_type: REQUIRED discriminator; for a completed prompt the value is
      ``"complete"`` (R-18.4-n/o/p, §3, AC-28.34). Wire key: ``resultType``.
    meta: OPTIONAL reserved metadata map. Wire key: ``_meta``.
  """

  messages: list[PromptMessage]
  description: str | None = None
  result_type: ResultType = RESULT_TYPE_COMPLETE  # JSON key: resultType
  meta: dict[str, Any] | None = None              # JSON key: _meta

  def __post_init__(self) -> None:
    # R-18.4-l: messages is REQUIRED and is an ordered list of PromptMessage.
    if not isinstance(self.messages, list):
      raise TypeError("GetPromptResult.messages is REQUIRED and must be a list (R-18.4-l)")
    for entry in self.messages:
      if not isinstance(entry, PromptMessage):
        raise TypeError(
          f"GetPromptResult.messages entries must be PromptMessage objects; got "
          f"{entry!r} (R-18.4-l)"
        )
    if self.description is not None and not isinstance(self.description, str):
      raise TypeError("GetPromptResult.description must be a string when present (§18.4)")
    # R-18.4-n/o: resultType is REQUIRED; for a completed prompt it is "complete".
    if not isinstance(self.result_type, str) or not self.result_type:
      raise ValueError("GetPromptResult.resultType is REQUIRED (R-18.4-n)")
    if self.meta is not None and not isinstance(self.meta, dict):
      raise TypeError("GetPromptResult._meta must be a JSON object when present (§18.4)")

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> GetPromptResult:
    """Parse a wire completed ``prompts/get`` result (§18.4).

    Validates that ``messages`` is a present array (R-18.4-l); a result lacking
    ``resultType`` is treated as ``"complete"`` (R-18.4-p, AC-28.34). A caller
    that has not already discriminated on ``resultType`` SHOULD use
    :func:`parse_get_prompt_response` to branch on ``input_required`` first
    (R-18.4-r).

    Raises:
      TypeError / ValueError: a required field is absent or has the wrong type.
    """
    if not isinstance(data, dict):
      raise TypeError(
        f"GetPromptResult must be a JSON object; got {type(data).__name__}"
      )
    if "messages" not in data:
      raise ValueError("GetPromptResult.messages is REQUIRED (R-18.4-l)")
    raw_messages = data["messages"]
    if not isinstance(raw_messages, list):
      raise TypeError("GetPromptResult.messages must be an array (R-18.4-l)")
    # R-18.4-p: a result lacking resultType is treated as "complete".
    return cls(
      messages=[PromptMessage.from_dict(m) for m in raw_messages],
      description=data.get("description"),
      result_type=data.get("resultType", RESULT_TYPE_COMPLETE),
      meta=data.get("_meta"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire-compatible dict; omits absent optional fields (§18.4).

    A server MUST include ``resultType`` (R-18.4-o); ``messages`` is always
    present (REQUIRED).
    """
    out: dict[str, Any] = {
      "resultType": self.result_type,
      "messages": [m.to_dict() for m in self.messages],
    }
    if self.description is not None:
      out["description"] = self.description
    if self.meta is not None:
      out["_meta"] = self.meta
    return out


def is_input_required(data: dict[str, Any]) -> bool:
  """Return True if a ``prompts/get`` response is an ``InputRequiredResult`` (R-18.4-q/r).

  A client MUST inspect ``resultType`` to determine whether a response is a
  ``GetPromptResult`` (``"complete"``) or an ``InputRequiredResult``
  (``"input_required"``) BEFORE parsing the body (R-18.4-r, AC-28.35). This is
  the discriminator-only check; an absent ``resultType`` is treated as
  ``"complete"`` (R-18.4-p) and therefore returns False.
  """
  return data.get("resultType") == RESULT_TYPE_INPUT_REQUIRED


def parse_get_prompt_response(
  data: dict[str, Any],
) -> GetPromptResult | InputRequiredResult:
  """Branch a ``prompts/get`` response on ``resultType`` then parse it (R-18.4-q/r).

  A client MUST inspect ``resultType`` before parsing the body (R-18.4-r,
  AC-28.35):
    - ``"input_required"`` ⇒ parse as an ``InputRequiredResult`` (S17), and run
      the multi-round-trip retry of the same ``prompts/get`` (§11, R-18.4-q);
    - ``"complete"`` or absent ⇒ parse as a ``GetPromptResult`` (R-18.4-p).

  Args:
    data: the raw ``result`` object from the ``prompts/get`` response.

  Returns:
    An ``InputRequiredResult`` when ``resultType`` is ``"input_required"``,
    otherwise a ``GetPromptResult``.

  Raises:
    TypeError / ValueError: the body does not match the discriminated shape.
  """
  if not isinstance(data, dict):
    raise TypeError(
      f"prompts/get response must be a JSON object; got {type(data).__name__}"
    )
  if is_input_required(data):
    # R-18.4-q: parse the §11/S17 InputRequiredResult shape; drives the retry.
    return validate_input_required_result(data)
  # R-18.4-p/r: "complete" or absent → a completed GetPromptResult.
  return GetPromptResult.from_dict(data)


def build_get_prompt_retry(
  original: GetPromptRequestParams,
  input_responses: dict[str, Any],
  request_state: str | None,
) -> GetPromptRequestParams:
  """Build the retry ``prompts/get`` params after an ``input_required`` result (§11).

  The retry reuses the same ``name`` and ``arguments`` as the original request
  and adds the gathered ``inputResponses`` plus the echoed ``requestState``
  (R-18.4-h/i, AC-28.31, AC-28.32):
    - for each key in the server's prior ``inputRequests`` the same key MUST be
      present in ``input_responses`` (validated by the caller against the
      server's ``inputRequests``);
    - ``request_state`` MUST be the exact opaque value the server supplied — it
      is echoed verbatim and never interpreted or modified (R-18.4-i/j/k).

  Args:
    original: the first-attempt ``prompts/get`` params (name + arguments + meta).
    input_responses: the responses keyed identically to the server's
      ``inputRequests`` (R-18.4-h).
    request_state: the opaque ``requestState`` from the server's
      ``input_required`` result, echoed verbatim (R-18.4-i); None only when the
      server supplied none.

  Returns:
    A new ``GetPromptRequestParams`` carrying the retry fields.
  """
  return GetPromptRequestParams(
    name=original.name,
    arguments=original.arguments,
    input_responses=input_responses,
    request_state=request_state,
    meta=original.meta,
  )


# ---------------------------------------------------------------------------
# §18.6  The prompts-list-changed notification  [R-18.6-a … R-18.6-g]
# ---------------------------------------------------------------------------

@dataclass
class PromptListChangedNotification:
  """A one-way notification that the available-prompt set changed (§18.6).

  Has no ``id`` and no response. A server that declared ``listChanged: true``
  SHOULD send it when its prompt set changes, optionally without any prior
  explicit subscription (R-18.6-a/d, AC-28.39); a server that did not declare it
  MUST NOT be expected to emit it (R-18.6-g). On receipt a client SHOULD
  invalidate any cached prompt list and MAY re-issue ``prompts/list``
  (R-18.6-e/f, AC-28.41).

  Fields:
    meta: OPTIONAL reserved ``_meta`` map; when ``params`` is present it MAY
      carry only this map — the notification carries no prompt data itself
      (R-18.6-c, AC-28.40). Wire key: ``params._meta``.
  """

  meta: dict[str, Any] | None = None  # JSON key: params._meta

  #: The notification method; REQUIRED to be exactly this string (R-18.6-b).
  method: str = field(default=NOTIFICATION_PROMPTS_LIST_CHANGED, init=False)

  def __post_init__(self) -> None:
    if self.meta is not None and not isinstance(self.meta, dict):
      raise TypeError(
        "PromptListChangedNotification params._meta must be a JSON object when "
        "present (R-18.6-c)"
      )

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> PromptListChangedNotification:
    """Parse a wire ``notifications/prompts/list_changed`` notification (§18.6).

    Validates the ``method`` is exactly ``notifications/prompts/list_changed``
    (R-18.6-b) and that ``params``, when present, carries only ``_meta`` and no
    prompt data (R-18.6-c, AC-28.40).

    Raises:
      TypeError: ``data``/``params``/``_meta`` has the wrong type.
      ValueError: ``method`` is not the exact required string, or ``params``
        carries members other than ``_meta``.
    """
    if not isinstance(data, dict):
      raise TypeError(
        f"PromptListChangedNotification must be a JSON object; got "
        f"{type(data).__name__}"
      )
    method = data.get("method")
    if method != NOTIFICATION_PROMPTS_LIST_CHANGED:
      raise ValueError(
        f"method MUST be exactly {NOTIFICATION_PROMPTS_LIST_CHANGED!r}; got "
        f"{method!r} (R-18.6-b)"
      )
    params = data.get("params")
    if params is None:
      return cls()
    if not isinstance(params, dict):
      raise TypeError("PromptListChangedNotification.params must be an object when present (R-18.6-c)")
    # R-18.6-c: params MAY carry only a reserved _meta map; reject any other member.
    extra = {k for k in params if k != "_meta"}
    if extra:
      raise ValueError(
        f"PromptListChangedNotification.params may carry only '_meta'; "
        f"unexpected members {sorted(extra)!r} (R-18.6-c)"
      )
    meta = params.get("_meta")
    if meta is not None and not isinstance(meta, dict):
      raise TypeError("PromptListChangedNotification params._meta must be an object when present (R-18.6-c)")
    return cls(meta=meta)

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire-compatible JSON-RPC notification object (§18.6).

    Emits ``jsonrpc``/``method`` and includes ``params`` only when a ``_meta``
    map is present (R-18.6-c); a bare notification carries just the method, with
    no ``id`` (one-way).
    """
    out: dict[str, Any] = {"jsonrpc": "2.0", "method": self.method}
    if self.meta is not None:
      out["params"] = {"_meta": self.meta}
    return out


def should_invalidate_cached_prompts(notification_method: str) -> bool:
  """Return True if a notification SHOULD invalidate a cached prompt list (R-18.6-e).

  On receiving ``notifications/prompts/list_changed`` a client SHOULD invalidate
  any cached prompt list and MAY re-issue ``prompts/list`` to obtain the current
  set (R-18.6-e/f, AC-28.41). This is the predicate a cache layer consults.
  """
  return notification_method == NOTIFICATION_PROMPTS_LIST_CHANGED


# ---------------------------------------------------------------------------
# §18.7  Argument-completion hook  [R-18.7-a]
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PromptArgumentCompletionTarget:
  """Identifies a prompt argument whose value a client MAY autocomplete (§18.7).

  Prompt arguments are completable: a client MAY request auto-completion
  suggestions for the value of a prompt argument through the Completion utility
  (§19 / S29, R-18.7-a, AC-28.42). This story only *hooks into* completion — it
  names the prompt (by ``Prompt.name``) and the argument (by
  ``PromptArgument.name``) being completed and the partial value entered so far.
  The completion request/result wire shapes, the prompt-argument reference type,
  and the ``completions`` capability gating are defined and owned by S29; this
  type carries no completion wire shape and asserts none of those rules.

  Fields:
    prompt_name: the ``Prompt.name`` the completion references (R-18.3-a).
    argument_name: the ``PromptArgument.name`` being completed (R-18.3-j).
    partial_value: the partial argument value entered so far, if any.
  """

  prompt_name: str
  argument_name: str
  partial_value: str = ""

  def __post_init__(self) -> None:
    if not isinstance(self.prompt_name, str) or not self.prompt_name:
      raise ValueError(
        "PromptArgumentCompletionTarget.prompt_name is REQUIRED and must be a "
        "non-empty string (R-18.7-a)"
      )
    if not isinstance(self.argument_name, str) or not self.argument_name:
      raise ValueError(
        "PromptArgumentCompletionTarget.argument_name is REQUIRED and must be a "
        "non-empty string (R-18.7-a)"
      )
    if not isinstance(self.partial_value, str):
      raise TypeError(
        "PromptArgumentCompletionTarget.partial_value must be a string (R-18.7-a)"
      )

  @property
  def completion_method(self) -> str:
    """The method a client sends to request completions: ``completion/complete`` (§18.7/§19).

    The wire request/result shapes are owned by S29 (R-18.7-a); this only names
    the method a client MAY use to autocomplete the argument value.
    """
    return METHOD_COMPLETION_COMPLETE
