"""Capability Negotiation: Client & Server Capabilities — S10.

Delivers the capability layer of MCP: the two declaration objects
(``ClientCapabilities``, ``ServerCapabilities``) and the per-request, stateless
negotiation rules that gate every optional feature. A feature is usable on the
wire only when BOTH peers have declared the governing capability — effective
availability is the intersection of what both sides declared (§6.4).

Public surface:

Declaration objects (§6.2 / §6.3):
  - ClientCapabilities: experimental, elicitation (form/url), roots (D),
    sampling (D, context/tools), extensions — with presence-based gating.
  - ServerCapabilities: experimental, completions, prompts (listChanged),
    resources (subscribe/listChanged), tools (listChanged), logging (D),
    extensions.
  - Each has from_dict() (validating parse) and to_dict() (wire form). An
    entirely empty object {} is valid for either (R-6.2-s, R-6.3-s).

General semantics (§6.1):
  - capability_is_present(): presence-means-supported (R-6.1 bullet 1).
  - Sub-flag helpers refine without replacing the enclosing capability
    (R-6.1-b) and never infer one capability from another (R-6.1-c).

Per-request negotiation & gating (§6.4):
  - SERVER_METHOD_CAPABILITIES / CLIENT_METHOD-style maps.
  - read_client_capabilities(meta): the server's per-request read of
    io.modelcontextprotocol/clientCapabilities (R-6.4-b/c/d).
  - client_may_invoke_server_method(): client gate from discovery (R-6.4-f/g).
  - compute_missing_capabilities(): the requiredCapabilities for a -32003.
  - resolve_optional_behavior(): graceful degradation (R-6.4-l/m).

The -32003 (missing-required-client-capability) and -32602 (malformed _meta)
errors themselves are built in S09 (negotiation.py); this story owns only the
capability shapes and the gating discipline.

Spec: §6.1–§6.4
Depends on: S08 (discovery delivers ServerCapabilities), S05 (_meta), S06 (stateless)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mcp_sdk_py.meta_object import KEY_CLIENT_CAPABILITIES


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class CapabilityNotDeclaredError(Exception):
  """A peer attempted to use a behavior whose governing capability was not declared.

  Raised by the gating helpers when a sender would otherwise invoke a method,
  send a notification, or rely on a behavior the receiver never declared
  (R-6.1-a, R-6.4-a/g). This is a local programming guard — it prevents the
  sender from emitting a non-conformant message — and is distinct from the
  on-the-wire -32003 a server returns (built in negotiation.py).

  Attributes:
    capability: the capability/sub-flag name that was required but undeclared.
    detail: human-readable context (e.g. the method that needed it).
  """

  def __init__(self, capability: str, detail: str = "") -> None:
    msg = (
      f"Capability {capability!r} was not declared by the peer; a peer MUST NOT "
      f"rely on a behavior whose governing capability the other peer has not "
      f"declared (R-6.1-a, R-6.4-a)"
    )
    if detail:
      msg = f"{msg}. {detail}"
    super().__init__(msg)
    self.capability: str = capability
    self.detail: str = detail


# ---------------------------------------------------------------------------
# §6.1  Capability presence semantics
# ---------------------------------------------------------------------------

def capability_is_present(caps: dict[str, Any], name: str) -> bool:
  """Return True if the named capability field is present (R-6.1 — presence = supported).

  Presence of the field — even with an empty-object value ``{}`` — signifies
  the capability is supported; absence signifies it is not. This is the single
  rule that governs every gating decision and MUST NOT be derived from any
  related capability (R-6.1-c).
  """
  return name in caps


def subflag_object_present(capability_value: Any, subflag: str) -> bool:
  """Return True if an object-typed sub-flag is present within a capability (R-6.1-b).

  Object sub-flags (e.g. ``elicitation.url``, ``sampling.context``) declare
  support by their mere presence; an empty object ``{}`` means "supported, no
  further settings." Absence means not supported.
  """
  return isinstance(capability_value, dict) and subflag in capability_value


def subflag_boolean_true(capability_value: Any, subflag: str) -> bool:
  """Return True only if a boolean sub-flag is explicitly ``true`` (R-6.1-b).

  Boolean sub-flags (e.g. ``tools.listChanged``, ``resources.subscribe``)
  declare the optional behavior only when set to ``true``; absent or ``false``
  means not supported (R-6.3-h/l/o).
  """
  return isinstance(capability_value, dict) and capability_value.get(subflag) is True


def _validate_object(value: Any, label: str) -> dict[str, Any]:
  """Validate that value is a JSON object (dict); return it. Raise TypeError otherwise."""
  if not isinstance(value, dict):
    raise TypeError(f"{label} must be a JSON object; got {type(value).__name__}")
  return value


def _validate_optional_boolean(value: Any, label: str) -> None:
  """Validate that value (when present) is a JSON boolean. Raise TypeError otherwise."""
  if value is not None and not isinstance(value, bool):
    raise TypeError(f"{label} must be a boolean if present; got {type(value).__name__}")


# Known top-level fields, so from_dict can preserve unknown ones for round-trip
# forward-compatibility (receivers ignore unknown keys, R-6.2-b / R-6.3-b).
_CLIENT_KNOWN_FIELDS: frozenset[str] = frozenset(
  {"experimental", "elicitation", "roots", "sampling", "extensions"}
)
_SERVER_KNOWN_FIELDS: frozenset[str] = frozenset(
  {"experimental", "completions", "prompts", "resources", "tools", "logging", "extensions"}
)


# ---------------------------------------------------------------------------
# §6.2  ClientCapabilities
# ---------------------------------------------------------------------------

@dataclass
class ClientCapabilities:
  """The behaviors the client supports, carried on every request (§6.2).

  Each object-typed field is ``None`` when the capability is absent (not
  supported) and a dict when present (supported); the dict may carry sub-flags.
  An entirely empty object ``{}`` (all fields None) is a valid value declaring
  no optional client behaviors (R-6.2-s).

  Fields:
    experimental: map of non-standard capability id → arbitrary settings
      object; receivers ignore unknown keys (R-6.2-a/b/c).
    elicitation: present ⇒ client supports server-initiated elicitation
      (R-6.2-d). Sub-flags ``form`` / ``url`` (R-6.2-e/f).
    roots: Deprecated; present ⇒ client exposes filesystem roots (R-6.2-h).
    sampling: Deprecated; present ⇒ client supports sampling/createMessage
      (R-6.2-k). Sub-flags ``context`` / ``tools`` (R-6.2-n/p).
    extensions: map of MCP extensions (shape owned by S11) (R-6.2-r).
    extra: unknown top-level keys, preserved for forward-compatible round-trip.
  """

  experimental: dict[str, Any] | None = None
  elicitation: dict[str, Any] | None = None
  roots: dict[str, Any] | None = None
  sampling: dict[str, Any] | None = None
  extensions: dict[str, Any] | None = None
  extra: dict[str, Any] = field(default_factory=dict)

  # -- presence / sub-flag gates (§6.1, §6.2) --

  @property
  def supports_elicitation(self) -> bool:
    """True if server-initiated elicitation is supported (R-6.2-d)."""
    return self.elicitation is not None

  @property
  def supports_form_elicitation(self) -> bool:
    """True if form-mode elicitation is supported.

    When ``elicitation`` is present but ``form`` is absent, form mode is
    supported implicitly as the baseline behavior (R-6.2-e).
    """
    return self.elicitation is not None

  @property
  def supports_url_elicitation(self) -> bool:
    """True only if the ``elicitation.url`` sub-flag is present (R-6.2-f/g).

    A server MUST NOT use URL-mode elicitation unless this returns True.
    """
    return subflag_object_present(self.elicitation, "url")

  @property
  def supports_roots(self) -> bool:
    """True if the deprecated ``roots`` capability is present (R-6.2-h/i)."""
    return self.roots is not None

  @property
  def supports_sampling(self) -> bool:
    """True if the deprecated ``sampling`` capability is present (R-6.2-k/l)."""
    return self.sampling is not None

  @property
  def supports_sampling_context(self) -> bool:
    """True only if the ``sampling.context`` sub-flag is present (R-6.2-n/o)."""
    return subflag_object_present(self.sampling, "context")

  @property
  def supports_sampling_tools(self) -> bool:
    """True only if the ``sampling.tools`` sub-flag is present (R-6.2-p/q)."""
    return subflag_object_present(self.sampling, "tools")

  def to_dict(self) -> dict[str, Any]:
    """Serialise to the wire object; omits absent (None) capabilities (R-6.2-s)."""
    out: dict[str, Any] = {}
    if self.experimental is not None:
      out["experimental"] = self.experimental
    if self.elicitation is not None:
      out["elicitation"] = self.elicitation
    if self.roots is not None:
      out["roots"] = self.roots
    if self.sampling is not None:
      out["sampling"] = self.sampling
    if self.extensions is not None:
      out["extensions"] = self.extensions
    out.update(self.extra)
    return out

  @classmethod
  def from_dict(cls, raw: Any) -> ClientCapabilities:
    """Parse and validate a wire ClientCapabilities object (§6.2).

    An empty object ``{}`` is valid (R-6.2-s). Unknown top-level keys are kept
    in ``extra`` so receivers neither reject nor lose them (R-6.2-b).

    Raises:
      TypeError: raw or a known field has the wrong JSON type.
    """
    raw = _validate_object(raw, "ClientCapabilities")

    experimental = raw.get("experimental")
    if experimental is not None:
      _validate_object(experimental, "ClientCapabilities.experimental")

    elicitation = raw.get("elicitation")
    if elicitation is not None:
      _validate_object(elicitation, "ClientCapabilities.elicitation")
      for sub in ("form", "url"):
        if sub in elicitation:
          _validate_object(elicitation[sub], f"ClientCapabilities.elicitation.{sub}")

    roots = raw.get("roots")
    if roots is not None:
      _validate_object(roots, "ClientCapabilities.roots")

    sampling = raw.get("sampling")
    if sampling is not None:
      _validate_object(sampling, "ClientCapabilities.sampling")
      for sub in ("context", "tools"):
        if sub in sampling:
          _validate_object(sampling[sub], f"ClientCapabilities.sampling.{sub}")

    extensions = raw.get("extensions")
    if extensions is not None:
      _validate_object(extensions, "ClientCapabilities.extensions")

    extra = {k: v for k, v in raw.items() if k not in _CLIENT_KNOWN_FIELDS}
    return cls(
      experimental=experimental,
      elicitation=elicitation,
      roots=roots,
      sampling=sampling,
      extensions=extensions,
      extra=extra,
    )


# ---------------------------------------------------------------------------
# §6.3  ServerCapabilities
# ---------------------------------------------------------------------------

@dataclass
class ServerCapabilities:
  """The behaviors the server supports, learned from server/discover (§6.3).

  Each object-typed field is ``None`` when absent and a dict when present.
  Boolean sub-flags (``listChanged``, ``subscribe``) declare their behavior
  only when explicitly ``true`` (R-6.3-h/l/o). An entirely empty object is a
  valid value declaring no optional server behaviors (R-6.3-s).

  Fields:
    experimental: non-standard capability map (R-6.3-a/b/c).
    completions: present ⇒ completion/complete supported (R-6.3-d/e).
    prompts: present ⇒ prompts/list + prompts/get; ``listChanged`` (R-6.3-f/g/h).
    resources: present ⇒ resource methods; ``subscribe`` / ``listChanged``
      (R-6.3-i/j/k/l).
    tools: present ⇒ tools/list + tools/call; ``listChanged`` (R-6.3-m/n/o).
    logging: Deprecated; present ⇒ notifications/message (R-6.3-p/q).
    extensions: MCP extensions map (shape owned by S11) (R-6.3-r).
    extra: unknown top-level keys, preserved for round-trip.
  """

  experimental: dict[str, Any] | None = None
  completions: dict[str, Any] | None = None
  prompts: dict[str, Any] | None = None
  resources: dict[str, Any] | None = None
  tools: dict[str, Any] | None = None
  logging: dict[str, Any] | None = None
  extensions: dict[str, Any] | None = None
  extra: dict[str, Any] = field(default_factory=dict)

  # -- presence / sub-flag gates (§6.1, §6.3) --

  @property
  def supports_completions(self) -> bool:
    """True if completion/complete is supported (R-6.3-d/e)."""
    return self.completions is not None

  @property
  def supports_prompts(self) -> bool:
    """True if prompts/list and prompts/get are supported (R-6.3-f)."""
    return self.prompts is not None

  @property
  def prompts_list_changed(self) -> bool:
    """True only if ``prompts.listChanged`` is ``true`` (R-6.3-g/h)."""
    return subflag_boolean_true(self.prompts, "listChanged")

  @property
  def supports_resources(self) -> bool:
    """True if resource methods are supported (R-6.3-i)."""
    return self.resources is not None

  @property
  def resources_subscribe(self) -> bool:
    """True only if ``resources.subscribe`` is ``true`` (R-6.3-j)."""
    return subflag_boolean_true(self.resources, "subscribe")

  @property
  def resources_list_changed(self) -> bool:
    """True only if ``resources.listChanged`` is ``true`` (R-6.3-k/l)."""
    return subflag_boolean_true(self.resources, "listChanged")

  @property
  def supports_tools(self) -> bool:
    """True if tools/list and tools/call are supported (R-6.3-m)."""
    return self.tools is not None

  @property
  def tools_list_changed(self) -> bool:
    """True only if ``tools.listChanged`` is ``true`` (R-6.3-n/o)."""
    return subflag_boolean_true(self.tools, "listChanged")

  @property
  def supports_logging(self) -> bool:
    """True if the deprecated ``logging`` capability is present (R-6.3-p)."""
    return self.logging is not None

  def to_dict(self) -> dict[str, Any]:
    """Serialise to the wire object; omits absent (None) capabilities (R-6.3-s)."""
    out: dict[str, Any] = {}
    if self.experimental is not None:
      out["experimental"] = self.experimental
    if self.completions is not None:
      out["completions"] = self.completions
    if self.prompts is not None:
      out["prompts"] = self.prompts
    if self.resources is not None:
      out["resources"] = self.resources
    if self.tools is not None:
      out["tools"] = self.tools
    if self.logging is not None:
      out["logging"] = self.logging
    if self.extensions is not None:
      out["extensions"] = self.extensions
    out.update(self.extra)
    return out

  @classmethod
  def from_dict(cls, raw: Any) -> ServerCapabilities:
    """Parse and validate a wire ServerCapabilities object (§6.3).

    An empty object ``{}`` is valid (R-6.3-s). Unknown top-level keys are kept
    in ``extra`` (R-6.3-b). Sub-flags ``listChanged`` / ``subscribe`` must be
    booleans if present.

    Raises:
      TypeError: raw or a known field/sub-flag has the wrong JSON type.
    """
    raw = _validate_object(raw, "ServerCapabilities")

    experimental = raw.get("experimental")
    if experimental is not None:
      _validate_object(experimental, "ServerCapabilities.experimental")

    completions = raw.get("completions")
    if completions is not None:
      _validate_object(completions, "ServerCapabilities.completions")

    prompts = raw.get("prompts")
    if prompts is not None:
      _validate_object(prompts, "ServerCapabilities.prompts")
      _validate_optional_boolean(prompts.get("listChanged"), "ServerCapabilities.prompts.listChanged")

    resources = raw.get("resources")
    if resources is not None:
      _validate_object(resources, "ServerCapabilities.resources")
      _validate_optional_boolean(resources.get("subscribe"), "ServerCapabilities.resources.subscribe")
      _validate_optional_boolean(resources.get("listChanged"), "ServerCapabilities.resources.listChanged")

    tools = raw.get("tools")
    if tools is not None:
      _validate_object(tools, "ServerCapabilities.tools")
      _validate_optional_boolean(tools.get("listChanged"), "ServerCapabilities.tools.listChanged")

    logging = raw.get("logging")
    if logging is not None:
      _validate_object(logging, "ServerCapabilities.logging")

    extensions = raw.get("extensions")
    if extensions is not None:
      _validate_object(extensions, "ServerCapabilities.extensions")

    extra = {k: v for k, v in raw.items() if k not in _SERVER_KNOWN_FIELDS}
    return cls(
      experimental=experimental,
      completions=completions,
      prompts=prompts,
      resources=resources,
      tools=tools,
      logging=logging,
      extensions=extensions,
      extra=extra,
    )


# ---------------------------------------------------------------------------
# §6.4  Per-request negotiation & gating
# ---------------------------------------------------------------------------

#: Governing server capability for each server method named in §6.2/§6.3.
#: A client MUST consult ServerCapabilities before invoking any of these and
#: MUST NOT invoke one whose capability the server did not declare (R-6.4-f/g).
#: Feature stories (S24–S29) bind the per-feature specifics; this map covers the
#: methods explicitly enumerated by the capability field definitions.
SERVER_METHOD_CAPABILITIES: dict[str, str] = {
  "completion/complete": "completions",
  "prompts/list": "prompts",
  "prompts/get": "prompts",
  "resources/list": "resources",
  "resources/read": "resources",
  "tools/list": "tools",
  "tools/call": "tools",
}


def read_client_capabilities(meta: dict[str, Any]) -> ClientCapabilities:
  """Read the ClientCapabilities the current request declared (R-6.4-b/c/d).

  The server MUST consult the ``io.modelcontextprotocol/clientCapabilities``
  field of *this* request's ``_meta`` and MUST NOT infer capabilities from any
  prior request, connection, or process (R-6.4-c). Each call is self-contained:
  it reads only the supplied meta. An absent key yields an empty
  ClientCapabilities (no optional behaviors declared).

  Args:
    meta: the ``_meta`` object from the current client request.

  Returns:
    A ClientCapabilities parsed solely from this request.
  """
  raw = meta.get(KEY_CLIENT_CAPABILITIES, {})
  return ClientCapabilities.from_dict(raw)


def client_may_invoke_server_method(
  server_caps: ServerCapabilities,
  method: str,
) -> bool:
  """Return True if the server declared the capability governing ``method`` (R-6.4-f/g).

  Methods not in the gating map are treated as ungated here (core/un-enumerated
  methods); the client gate applies to the capability-governed methods named in
  §6.2/§6.3.
  """
  capability = SERVER_METHOD_CAPABILITIES.get(method)
  if capability is None:
    return True
  return capability_is_present(server_caps.to_dict(), capability)


def assert_client_may_invoke(server_caps: ServerCapabilities, method: str) -> None:
  """Raise CapabilityNotDeclaredError if the client may not invoke ``method`` (R-6.4-g).

  A client MUST NOT invoke a server method whose governing capability the
  server did not declare. Call this before issuing the request.
  """
  if not client_may_invoke_server_method(server_caps, method):
    capability = SERVER_METHOD_CAPABILITIES.get(method, method)
    raise CapabilityNotDeclaredError(
      capability,
      detail=f"the server did not declare {capability!r}; method {method!r} is unavailable (R-6.4-g)",
    )


def compute_missing_capabilities(
  declared: ClientCapabilities | dict[str, Any],
  required: dict[str, Any],
) -> dict[str, Any]:
  """Return the required-but-undeclared capabilities for a -32003 error (R-6.4-h).

  Operates solely on the capabilities declared on the current request; nothing
  is inferred from prior state (R-6.4-c). The returned object's keys are exactly
  the required capabilities absent from ``declared`` and its values are the
  settings objects from ``required`` — ready for ``data.requiredCapabilities``.

  Args:
    declared: the ClientCapabilities (or raw dict) declared on the request.
    required: capability-name → settings-object the server needs.

  Returns:
    The subset of ``required`` whose keys are absent from ``declared`` (empty
    when the request already declared everything required).
  """
  declared_dict = declared.to_dict() if isinstance(declared, ClientCapabilities) else dict(declared)
  return {name: value for name, value in required.items() if name not in declared_dict}


def resolve_optional_behavior(
  *,
  local_supports: bool,
  remote_declares: bool,
  mandatory: bool = False,
) -> bool:
  """Decide whether to use an optional behavior, applying graceful degradation (R-6.4-l/m).

  A feature is usable only when both sides support it. When the remote peer has
  not declared it, the local peer MUST fall back to mutually supported core
  behavior — it MUST NOT fail merely because the remote declared fewer
  capabilities (R-6.4-m). Only when the behavior is mandatory for the operation
  may the caller treat the absence as a hard error.

  Args:
    local_supports: whether this peer supports the optional behavior.
    remote_declares: whether the other peer declared the governing capability.
    mandatory: whether the operation cannot proceed without the behavior.

  Returns:
    True if the behavior may be used (both sides support it).

  Raises:
    CapabilityNotDeclaredError: the behavior is mandatory yet the remote peer
      did not declare it (R-6.4-l, reject-only-when-mandatory branch).
  """
  usable = local_supports and remote_declares
  if usable:
    return True
  if mandatory and not remote_declares:
    raise CapabilityNotDeclaredError(
      "required-behavior",
      detail="the operation requires a behavior the other peer did not declare (R-6.4-l)",
    )
  # R-6.4-m: degrade gracefully — do not fail for fewer declared capabilities.
  return False
