"""Elicitation I: Capability, Delivery & Modes — S30.

Elicitation lets a server request structured input from the user, gathered and
returned through the client (§20). It is one of the three kinds of
client-provided input a server may request while processing a client request,
and is an active (non-Deprecated) client capability (§20).

This story delivers the *front half* of elicitation:

  - The ``elicitation`` client capability value and its ``form`` / ``url``
    sub-flags, the must-declare-to-use and must-support-at-least-one-mode rules,
    the empty-object-equals-form-only equivalence, and the two server-side
    prohibitions (no unsupported ``mode``; no ``elicitation/create`` to an
    undeclared client) — §20.1.
  - The fact that an elicitation request is NOT a server-initiated JSON-RPC
    request: it is delivered as an ``elicitation/create`` input request embedded
    in a multi-round-trip ``input-required`` result (the §11 / S17 mechanism),
    and supplied back via retry — §20.2.
  - The two elicitation modes (``form`` / ``url``) and their parameter shapes
    (``ElicitRequest``, ``ElicitRequestParams`` discriminated over ``mode``,
    ``ElicitRequestFormParams``, ``ElicitRequestURLParams``) — §20.3.

Out of scope here (owned by S31/§20.4–§20.8): the ``PrimitiveSchemaDefinition``
value type and the full restricted-form-schema rules for
``requestedSchema.properties`` (this story references the type by name only);
``ElicitResult`` and the accept/decline/cancel actions; the §20.6
elicitation-complete notification ``elicitationId`` correlates with; and the
security/consent considerations. The general multi-round-trip machinery (the
``input-required`` result type, the ``InputRequest`` union over ``method``, the
``requestState`` token, the retry algorithm) is owned by S17 and consumed here;
the ``ClientCapabilities`` declaration surface and §6 gating are owned by
S05/S06/S09/S10 and merely specialized here for ``elicitation``.

Spec: §20.1–§20.3 (lines 4986–5108)
Depends on: S10 (capabilities.py), S17 (multi_round_trip.py)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Union
from urllib.parse import urlsplit

from mcp_sdk_py.capabilities import ClientCapabilities
from mcp_sdk_py.meta_object import KEY_CLIENT_CAPABILITIES
from mcp_sdk_py.multi_round_trip import INPUT_REQUEST_ELICITATION

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: The exact, case-sensitive method discriminator that identifies an elicitation
#: input request within the multi-round-trip ``InputRequest`` union (§20,
#: R-20.2-b). Re-exported from S17's recognized-kind registry so there is a
#: single source of truth for the literal.
ELICITATION_METHOD: str = INPUT_REQUEST_ELICITATION  # "elicitation/create"

#: The form-mode discriminator value (§20.3). OPTIONAL in form params; absent
#: ⇒ form mode (R-20.3-a/b/c).
MODE_FORM: str = "form"

#: The url-mode discriminator value (§20.3). REQUIRED in url params (R-20.3-i).
MODE_URL: str = "url"

#: The capability name carried under ``ClientCapabilities`` and the
#: ``io.modelcontextprotocol/clientCapabilities`` metadata envelope (§20.1).
CAPABILITY_NAME: str = "elicitation"

#: The two elicitation sub-flag / mode names (§20.1, §20.3).
SUBFLAG_FORM: str = "form"
SUBFLAG_URL: str = "url"

#: The literal the form-mode ``requestedSchema.type`` MUST equal (R-20.3-e).
SCHEMA_TYPE_OBJECT: str = "object"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ElicitationCapabilityError(Exception):
  """A server attempted to elicit in a way the client's declared capability forbids.

  Raised by the gating helpers when a server would (a) send an
  ``elicitation/create`` request to a client that did not declare the
  ``elicitation`` capability (R-20.1-e), or (b) send a ``mode`` the client's
  declared sub-flags do not support (R-20.1-d). This is a local guard that stops
  a server from emitting a non-conformant elicitation; it is distinct from any
  on-the-wire error (e.g. the -32003 built in S09).

  Attributes:
    mode: the offending elicitation mode, or ``None`` when the capability itself
      was absent.
    detail: human-readable context.
  """

  def __init__(self, detail: str, *, mode: str | None = None) -> None:
    super().__init__(detail)
    self.mode: str | None = mode
    self.detail: str = detail


class InvalidElicitRequestError(Exception):
  """Raised when an ``ElicitRequest`` or its ``params`` is structurally invalid (§20.2/§20.3).

  Covers a wrong/absent ``method`` (R-20.2-b), absent ``params`` (R-20.2-c), an
  unknown or wrongly-typed ``mode`` discriminator, and any per-mode field-rule
  violation (R-20.3-a–n). Callers receiving such a request MUST treat it as an
  error rather than acting on a malformed elicitation.
  """


# ---------------------------------------------------------------------------
# §20.1  Capability declaration & gating
# ---------------------------------------------------------------------------

def normalize_elicitation_capability(value: Any) -> dict[str, dict[str, Any]]:
  """Return the effective elicitation sub-flag map, applying the §20.1 equivalences.

  Implements the declaration rules and the backwards-compatibility equivalence
  of §20.1: an empty ``elicitation`` capability object ``{}`` is treated
  identically to ``{ "form": {} }`` — form mode only (R-20.1-c). The result is a
  map from supported mode name (``"form"`` / ``"url"``) to that sub-flag's
  settings object (``{}`` when no extra settings), with the equivalence applied.

  The whole ``elicitation`` value is itself OPTIONAL within
  ``ClientCapabilities``; this helper presumes the capability *is* present (the
  caller decides presence via :func:`client_supports_elicitation`).

  Args:
    value: the raw ``elicitation`` capability value (must be a JSON object).

  Returns:
    A map of supported-mode name → settings object, with at least one entry. An
    empty input maps to ``{"form": {}}`` (R-20.1-c).

  Raises:
    TypeError: ``value`` is not an object, or a present sub-flag is not an
      object (each sub-flag, when present, MUST be an object — R-20.1-f).
    ValueError: ``value`` is present but declares no supported mode — a client
      declaring ``elicitation`` MUST support at least one mode (R-20.1-b). This
      can only arise if non-mode keys are present without ``form``/``url``;
      ``{}`` itself is valid via the equivalence.
  """
  if not isinstance(value, dict):
    raise TypeError(
      f"elicitation capability must be a JSON object; got {type(value).__name__} "
      f"(R-20.1-f)"
    )

  modes: dict[str, dict[str, Any]] = {}
  for sub in (SUBFLAG_FORM, SUBFLAG_URL):
    if sub in value:
      sub_val = value[sub]
      if not isinstance(sub_val, dict):
        raise TypeError(
          f"elicitation.{sub} sub-flag, when present, MUST be an object; "
          f"got {type(sub_val).__name__} (R-20.1-f)"
        )
      modes[sub] = sub_val

  # R-20.1-c: an entirely empty value {} ≡ { "form": {} } — form mode only.
  if not value:
    return {SUBFLAG_FORM: {}}

  # R-20.1-b: a declared elicitation capability MUST support at least one mode.
  if not modes:
    raise ValueError(
      "a client that declares the elicitation capability MUST support at least "
      "one mode (form or url); the declared value names neither (R-20.1-b)"
    )
  return modes


def supported_elicitation_modes(value: Any) -> frozenset[str]:
  """Return the set of elicitation modes a declared ``elicitation`` value supports.

  Applies the empty-object-equals-form-only equivalence (R-20.1-c) via
  :func:`normalize_elicitation_capability`. A value of ``{}`` yields
  ``{"form"}``; ``{"form": {}, "url": {}}`` yields ``{"form", "url"}``
  (R-20.1-f). Used by servers to gate which ``mode`` they may send (R-20.1-d).
  """
  return frozenset(normalize_elicitation_capability(value))


def client_supports_elicitation(caps: ClientCapabilities | dict[str, Any]) -> bool:
  """Return True if the client declared the ``elicitation`` capability (R-20.1-a).

  A client that supports elicitation MUST declare the ``elicitation``
  capability; a client that does not declare it is treated as not supporting
  elicitation (R-20.1-a, AC-30.1). Presence — not value — is what counts (the
  §6.1 presence-means-supported rule, specialized here). Accepts either a parsed
  :class:`~mcp_sdk_py.capabilities.ClientCapabilities` or a raw capabilities
  dict.
  """
  if isinstance(caps, ClientCapabilities):
    return caps.elicitation is not None
  return CAPABILITY_NAME in caps


def client_supports_elicitation_mode(
  caps: ClientCapabilities | dict[str, Any],
  mode: str,
) -> bool:
  """Return True if the client supports the given elicitation ``mode`` (R-20.1-c/d).

  Determines support from the client's declared sub-flags, applying the
  empty-object-equals-form-only equivalence (R-20.1-c): a client declaring
  ``"elicitation": {}`` supports ``"form"`` but NOT ``"url"`` (AC-30.4). Returns
  False when the ``elicitation`` capability is absent entirely. A server MUST
  consult this before sending a request of that mode (R-20.1-d).

  Args:
    caps: the client's declared capabilities (parsed or raw dict).
    mode: the elicitation mode to check (``"form"`` or ``"url"``).
  """
  raw = _elicitation_value(caps)
  if raw is None:
    return False
  return mode in supported_elicitation_modes(raw)


def read_client_capabilities_from_meta(meta: dict[str, Any]) -> ClientCapabilities:
  """Parse the ClientCapabilities declared in this request's ``_meta`` envelope.

  Convenience over S10's per-request capability read: capabilities are carried
  per-request under the reserved ``io.modelcontextprotocol/clientCapabilities``
  key (§20.1, §4/§6). Each call is self-contained — nothing is inferred from
  prior requests or connections. An absent key yields an empty
  :class:`~mcp_sdk_py.capabilities.ClientCapabilities`.
  """
  raw = meta.get(KEY_CLIENT_CAPABILITIES, {})
  return ClientCapabilities.from_dict(raw)


def assert_server_may_elicit(
  caps: ClientCapabilities | dict[str, Any],
  mode: str,
) -> None:
  """Raise unless the server may send an elicitation of ``mode`` to this client.

  Enforces the two §20.1 server-side prohibitions before an
  ``elicitation/create`` request is emitted:

  - R-20.1-e: a server MUST NOT return an ``elicitation/create`` input-required
    result to a client that has not declared the ``elicitation`` capability
    (AC-30.6).
  - R-20.1-d: a server MUST NOT send a request whose ``mode`` is not supported
    by the client's declared sub-flags, with the empty-object-equals-form-only
    equivalence applied (AC-30.5).

  Args:
    caps: the client's declared capabilities (parsed or raw dict).
    mode: the elicitation mode the server intends to send.

  Raises:
    ElicitationCapabilityError: the capability is undeclared (R-20.1-e) or the
      mode is unsupported (R-20.1-d).
  """
  if not client_supports_elicitation(caps):
    raise ElicitationCapabilityError(
      "a server MUST NOT return an 'elicitation/create' input-required result to "
      "a client that has not declared the 'elicitation' capability (R-20.1-e)",
    )
  if not client_supports_elicitation_mode(caps, mode):
    supported = sorted(supported_elicitation_modes(_elicitation_value(caps) or {}))
    raise ElicitationCapabilityError(
      f"a server MUST NOT send an elicitation request whose mode {mode!r} is not "
      f"supported by the client; declared modes are {supported!r} (R-20.1-d)",
      mode=mode,
    )


def _elicitation_value(
  caps: ClientCapabilities | dict[str, Any],
) -> dict[str, Any] | None:
  """Return the raw ``elicitation`` capability value, or None when absent."""
  if isinstance(caps, ClientCapabilities):
    return caps.elicitation
  return caps.get(CAPABILITY_NAME)


# ---------------------------------------------------------------------------
# §20.3  URL validation  [R-20.3-n]
# ---------------------------------------------------------------------------

def validate_elicitation_url(value: Any) -> str:
  """Validate the url-mode ``url`` is a valid URI [RFC3986] containing a valid URL.

  The url-mode ``url`` is a REQUIRED string the user should navigate to
  (R-20.3-m); it MUST be a valid URI per RFC 3986 and MUST contain a valid URL
  (R-20.3-n, AC-30.17). A valid URL requires both a scheme and an authority
  (host) component — a bare scheme-only or relative reference is rejected.
  Fragments and queries are permitted (unlike a strict absolute-URI), since a
  navigable URL may legitimately carry them.

  Args:
    value: the candidate ``url`` string.

  Returns:
    value unchanged when valid.

  Raises:
    InvalidElicitRequestError: value is not a string, or is not a valid
      RFC3986 URI containing a valid URL (no scheme, or no host).
  """
  if not isinstance(value, str):
    raise InvalidElicitRequestError(
      f"url-mode 'url' must be a string; got {type(value).__name__} (R-20.3-m)"
    )
  if not value:
    raise InvalidElicitRequestError(
      "url-mode 'url' must be a non-empty valid URL (R-20.3-m, R-20.3-n)"
    )
  try:
    parts = urlsplit(value)
  except ValueError as exc:
    raise InvalidElicitRequestError(
      f"url-mode 'url' {value!r} is not a valid URI [RFC3986]: {exc} (R-20.3-n)"
    ) from exc
  # A valid URL [RFC3986] requires a scheme component.
  if not parts.scheme:
    raise InvalidElicitRequestError(
      f"url-mode 'url' {value!r} is not a valid URL: a scheme component is "
      f"REQUIRED [RFC3986] (R-20.3-n)"
    )
  # A navigable URL requires an authority (host); a scheme-only or path-only
  # reference does not "contain a valid URL".
  if not parts.netloc:
    raise InvalidElicitRequestError(
      f"url-mode 'url' {value!r} is not a valid URL: a host (authority) "
      f"component is REQUIRED (R-20.3-n)"
    )
  return value


# ---------------------------------------------------------------------------
# §20.3  Mode-specific parameter shapes
# ---------------------------------------------------------------------------

@dataclass
class ElicitRequestFormParams:
  """Form-mode elicitation parameters (§20.3): in-band structured collection.

  In-band structured data collection against an optional flat schema; the
  collected data IS exposed to the client (§20.3). Field rules:

  - ``mode`` is OPTIONAL; if present it MUST be the literal ``"form"``. A server
    MAY omit it, and a client receiving params with no ``mode`` treats them as
    form mode (R-20.3-a/b/c, AC-30.10).
  - ``message`` is a REQUIRED string describing to the user the information
    being requested (R-20.3-d, AC-30.11).
  - ``requested_schema`` is a REQUIRED object whose ``type`` MUST be the literal
    ``"object"`` (R-20.3-e, AC-30.12); its ``properties`` is a REQUIRED flat map
    of field name → ``PrimitiveSchemaDefinition`` (the primitive type itself is
    defined in S31/§20.4) (R-20.3-f, AC-30.13); ``required`` is an OPTIONAL array
    of property names (R-20.3-g) and ``$schema`` an OPTIONAL dialect string
    (R-20.3-h), both of which may be absent (AC-30.14).

  Fields:
    message: REQUIRED user-facing text (R-20.3-d).
    requested_schema: REQUIRED schema object (R-20.3-e/f). JSON key:
      ``requestedSchema``.
    mode: OPTIONAL; ``"form"`` when present, else None (R-20.3-a). Serialised
      only when set, preserving the backwards-compatible omit (R-20.3-b).
  """

  message: str
  requested_schema: dict[str, Any]
  mode: str | None = None

  def __post_init__(self) -> None:
    # R-20.3-a: if mode is present it MUST be the literal "form".
    if self.mode is not None and self.mode != MODE_FORM:
      raise InvalidElicitRequestError(
        f"form-mode 'mode', when present, MUST be the literal {MODE_FORM!r}; "
        f"got {self.mode!r} (R-20.3-a)"
      )
    # R-20.3-d: message is a REQUIRED string.
    if not isinstance(self.message, str):
      raise InvalidElicitRequestError(
        f"form-mode 'message' is REQUIRED and MUST be a string; "
        f"got {type(self.message).__name__} (R-20.3-d)"
      )
    _validate_requested_schema(self.requested_schema)

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> ElicitRequestFormParams:
    """Parse form-mode params from a wire dict (§20.3).

    A missing ``mode`` is preserved as None — the request is form mode by
    backwards compatibility (R-20.3-c). Validation is performed in
    ``__post_init__``.

    Raises:
      InvalidElicitRequestError: a required field is absent or a field violates
        its rule (R-20.3-a/d/e/f).
    """
    if not isinstance(data, dict):
      raise InvalidElicitRequestError(
        f"form-mode params must be a JSON object; got {type(data).__name__}"
      )
    if "message" not in data:
      raise InvalidElicitRequestError(
        "form-mode 'message' is REQUIRED (R-20.3-d)"
      )
    if "requestedSchema" not in data:
      raise InvalidElicitRequestError(
        "form-mode 'requestedSchema' is REQUIRED (R-20.3-e)"
      )
    return cls(
      message=data["message"],
      requested_schema=data["requestedSchema"],
      mode=data.get("mode"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire dict; omits ``mode`` when absent (R-20.3-b)."""
    out: dict[str, Any] = {
      "message": self.message,
      "requestedSchema": self.requested_schema,
    }
    if self.mode is not None:
      out["mode"] = self.mode
    return out


def _validate_requested_schema(schema: Any) -> None:
  """Validate the form-mode ``requestedSchema`` envelope (R-20.3-e/f/g/h).

  Checks the structural rules this story owns: ``type`` MUST be the literal
  ``"object"`` (R-20.3-e); ``properties`` is a REQUIRED flat (non-nested) map
  (R-20.3-f); ``required`` when present is an array of property-name strings
  (R-20.3-g); ``$schema`` when present is a string (R-20.3-h).

  The *value* schema of each property (a ``PrimitiveSchemaDefinition``) is NOT
  validated here — that type and its rules are owned by S31/§20.4. This helper
  only confirms ``properties`` is a flat object whose values are themselves
  objects (the primitive-schema container), without inspecting their contents.

  Raises:
    InvalidElicitRequestError: any structural rule is violated.
  """
  if not isinstance(schema, dict):
    raise InvalidElicitRequestError(
      f"form-mode 'requestedSchema' MUST be an object; "
      f"got {type(schema).__name__} (R-20.3-e)"
    )
  # R-20.3-e: type MUST be the literal "object".
  schema_type = schema.get("type")
  if schema_type != SCHEMA_TYPE_OBJECT:
    raise InvalidElicitRequestError(
      f"form-mode 'requestedSchema.type' MUST be the literal "
      f"{SCHEMA_TYPE_OBJECT!r}; got {schema_type!r} (R-20.3-e)"
    )
  # R-20.3-f: properties is a REQUIRED flat (non-nested) map.
  if "properties" not in schema:
    raise InvalidElicitRequestError(
      "form-mode 'requestedSchema.properties' is REQUIRED (R-20.3-f)"
    )
  properties = schema["properties"]
  if not isinstance(properties, dict):
    raise InvalidElicitRequestError(
      f"form-mode 'requestedSchema.properties' MUST be a map; "
      f"got {type(properties).__name__} (R-20.3-f)"
    )
  for prop_name, prop_schema in properties.items():
    if not isinstance(prop_name, str):
      raise InvalidElicitRequestError(
        f"form-mode 'requestedSchema.properties' keys MUST be strings; "
        f"got {type(prop_name).__name__} (R-20.3-f)"
      )
    # Flat, non-nested: each value is a PrimitiveSchemaDefinition object (its
    # full shape is owned by S31/§20.4). Confirm it is an object container only.
    if not isinstance(prop_schema, dict):
      raise InvalidElicitRequestError(
        f"form-mode 'requestedSchema.properties[{prop_name!r}]' MUST be a "
        f"primitive schema object; got {type(prop_schema).__name__} (R-20.3-f)"
      )
  # R-20.3-g: required, when present, is an array of property-name strings.
  if "required" in schema:
    required = schema["required"]
    if not isinstance(required, list) or not all(isinstance(r, str) for r in required):
      raise InvalidElicitRequestError(
        "form-mode 'requestedSchema.required', when present, MUST be an array of "
        "property-name strings (R-20.3-g)"
      )
  # R-20.3-h: $schema, when present, is a string.
  if "$schema" in schema:
    dialect = schema["$schema"]
    if not isinstance(dialect, str):
      raise InvalidElicitRequestError(
        f"form-mode 'requestedSchema.$schema', when present, MUST be a string; "
        f"got {type(dialect).__name__} (R-20.3-h)"
      )


@dataclass
class ElicitRequestURLParams:
  """URL-mode elicitation parameters (§20.3): out-of-band navigation.

  Out-of-band interaction by navigating the user to a URL; data other than the
  URL itself is NOT exposed to the client (suited to authorization / payment
  flows) (§20.3). Field rules:

  - ``mode`` is REQUIRED and MUST be the literal ``"url"`` (R-20.3-i, AC-30.15).
  - ``message`` is a REQUIRED string explaining why the interaction is needed
    (R-20.3-j, AC-30.15).
  - ``elicitation_id`` is a REQUIRED string uniquely identifying the elicitation
    within the server's context; the client MUST treat it as opaque — it does
    not parse, interpret, or modify it (R-20.3-k/l, AC-30.16). It correlates with
    the §20.6 elicitation-complete notification (defined in S31).
  - ``url`` is a REQUIRED string the user should navigate to; it MUST be a valid
    URI [RFC3986] containing a valid URL (R-20.3-m/n, AC-30.17).

  Fields:
    message: REQUIRED user-facing text (R-20.3-j).
    elicitation_id: REQUIRED opaque correlation id (R-20.3-k/l). JSON key:
      ``elicitationId``.
    url: REQUIRED navigable URL (R-20.3-m/n).
    mode: REQUIRED literal ``"url"`` (R-20.3-i).
  """

  message: str
  elicitation_id: str
  url: str
  mode: str = MODE_URL

  def __post_init__(self) -> None:
    # R-20.3-i: mode is REQUIRED and MUST be the literal "url".
    if self.mode != MODE_URL:
      raise InvalidElicitRequestError(
        f"url-mode 'mode' is REQUIRED and MUST be the literal {MODE_URL!r}; "
        f"got {self.mode!r} (R-20.3-i)"
      )
    # R-20.3-j: message is a REQUIRED string.
    if not isinstance(self.message, str):
      raise InvalidElicitRequestError(
        f"url-mode 'message' is REQUIRED and MUST be a string; "
        f"got {type(self.message).__name__} (R-20.3-j)"
      )
    # R-20.3-k: elicitationId is a REQUIRED string. Treated opaquely (R-20.3-l):
    # validated only as a non-empty string — never parsed or interpreted.
    if not isinstance(self.elicitation_id, str) or not self.elicitation_id:
      raise InvalidElicitRequestError(
        f"url-mode 'elicitationId' is REQUIRED and MUST be a non-empty string; "
        f"got {self.elicitation_id!r} (R-20.3-k)"
      )
    # R-20.3-m/n: url is a REQUIRED valid URL.
    validate_elicitation_url(self.url)

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> ElicitRequestURLParams:
    """Parse url-mode params from a wire dict (§20.3).

    The ``mode`` field is REQUIRED for url mode (R-20.3-i): unlike form mode it
    has no omit-equals-default shorthand, so an absent ``mode`` is rejected.

    Raises:
      InvalidElicitRequestError: a required field is absent or a field violates
        its rule (R-20.3-i/j/k/m/n).
    """
    if not isinstance(data, dict):
      raise InvalidElicitRequestError(
        f"url-mode params must be a JSON object; got {type(data).__name__}"
      )
    if "mode" not in data:
      raise InvalidElicitRequestError(
        f"url-mode 'mode' is REQUIRED and MUST be the literal {MODE_URL!r} "
        f"(R-20.3-i)"
      )
    for required_field in ("message", "elicitationId", "url"):
      if required_field not in data:
        raise InvalidElicitRequestError(
          f"url-mode {required_field!r} is REQUIRED (R-20.3-j/k/m)"
        )
    return cls(
      message=data["message"],
      elicitation_id=data["elicitationId"],
      url=data["url"],
      mode=data["mode"],
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire dict (§20.3); always includes the REQUIRED ``mode``."""
    return {
      "mode": self.mode,
      "message": self.message,
      "elicitationId": self.elicitation_id,
      "url": self.url,
    }


#: The ``ElicitRequestParams`` union: one of two mode-specific shapes,
#: discriminated by ``mode`` (§20.3, AC-30 §6.3). ``"form"`` (or absent) selects
#: form params; ``"url"`` selects URL params.
ElicitRequestParams = Union[ElicitRequestFormParams, ElicitRequestURLParams]


def parse_elicit_request_params(data: dict[str, Any]) -> ElicitRequestParams:
  """Dispatch raw ``params`` to the correct mode shape by the ``mode`` field (§20.3).

  Selection (R-20.3-a/c/i, AC-30.10/30.15):

  - ``mode`` absent or ``"form"`` → :class:`ElicitRequestFormParams`. A client
    MUST treat params with no ``mode`` field as form mode (R-20.3-c).
  - ``mode`` equals ``"url"`` → :class:`ElicitRequestURLParams`.
  - any other ``mode`` value → error (unknown discriminator).

  Args:
    data: the raw ``params`` object of an ``ElicitRequest``.

  Returns:
    The parsed, validated mode-specific params.

  Raises:
    InvalidElicitRequestError: ``params`` is not an object, ``mode`` is an
      unrecognized value, or a per-mode field rule is violated.
  """
  if not isinstance(data, dict):
    raise InvalidElicitRequestError(
      f"ElicitRequest 'params' must be a JSON object; got {type(data).__name__} "
      f"(R-20.2-c)"
    )
  mode = data.get("mode")
  # R-20.3-c: absent mode ⇒ form mode. R-20.3-a: explicit "form" ⇒ form mode.
  if mode is None or mode == MODE_FORM:
    return ElicitRequestFormParams.from_dict(data)
  if mode == MODE_URL:
    return ElicitRequestURLParams.from_dict(data)
  raise InvalidElicitRequestError(
    f"ElicitRequest 'params.mode' is an unrecognized elicitation mode {mode!r}; "
    f"recognized modes are {MODE_FORM!r} and {MODE_URL!r} (§20.3)"
  )


# ---------------------------------------------------------------------------
# §20.2  ElicitRequest — the embedded input request
# ---------------------------------------------------------------------------

@dataclass
class ElicitRequest:
  """The ``elicitation/create`` request embedded in a multi-round-trip input-required result.

  An elicitation request is NOT a server-initiated JSON-RPC request: it is the
  ``elicitation/create`` member of the §11 / S17 ``InputRequest`` union, embedded
  in an ``input-required`` result; the client gathers the input and supplies it
  by retrying the originating request (§20.2, R-20.2-a, AC-30.7).

  Fields:
    params: REQUIRED mode-specific parameters (an ``ElicitRequestParams``)
      (R-20.2-c, AC-30.9).
    method: the discriminator; always the exact, case-sensitive literal
      ``"elicitation/create"`` (R-20.2-b, AC-30.8). Not settable — fixed to the
      protocol literal.
  """

  params: ElicitRequestParams
  method: str = field(default=ELICITATION_METHOD, init=False)

  def __post_init__(self) -> None:
    # R-20.2-c: params is REQUIRED and is an ElicitRequestParams.
    if not isinstance(self.params, (ElicitRequestFormParams, ElicitRequestURLParams)):
      raise InvalidElicitRequestError(
        f"ElicitRequest 'params' is REQUIRED and MUST be an ElicitRequestParams; "
        f"got {type(self.params).__name__} (R-20.2-c)"
      )

  @property
  def mode(self) -> str:
    """The elicitation mode of this request (``"form"`` or ``"url"``).

    For form params with ``mode`` omitted, this reports ``"form"`` per the
    backwards-compatibility rule (R-20.3-c).
    """
    return MODE_URL if isinstance(self.params, ElicitRequestURLParams) else MODE_FORM

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> ElicitRequest:
    """Parse and validate an embedded ``ElicitRequest`` from a wire dict (§20.2).

    Enforces the embedded-request shape (R-20.2-b/c): ``method`` MUST be present
    and equal the exact, case-sensitive literal ``"elicitation/create"``
    (AC-30.8), and ``params`` MUST be present and a valid ``ElicitRequestParams``
    (AC-30.9). The mode-specific shape is dispatched and validated.

    Raises:
      InvalidElicitRequestError: ``method`` is absent or not the exact literal,
        ``params`` is absent, or the params violate a field rule.
    """
    if not isinstance(data, dict):
      raise InvalidElicitRequestError(
        f"ElicitRequest must be a JSON object; got {type(data).__name__}"
      )
    # R-20.2-b: method REQUIRED, exact case-sensitive "elicitation/create".
    if "method" not in data:
      raise InvalidElicitRequestError(
        f"ElicitRequest 'method' is REQUIRED and MUST be {ELICITATION_METHOD!r} "
        f"(R-20.2-b)"
      )
    method = data["method"]
    if method != ELICITATION_METHOD:
      raise InvalidElicitRequestError(
        f"ElicitRequest 'method' MUST be the exact, case-sensitive literal "
        f"{ELICITATION_METHOD!r}; got {method!r} (R-20.2-b)"
      )
    # R-20.2-c: params REQUIRED.
    if "params" not in data:
      raise InvalidElicitRequestError(
        "ElicitRequest 'params' is REQUIRED (R-20.2-c)"
      )
    return cls(params=parse_elicit_request_params(data["params"]))

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire dict for the ``InputRequest`` envelope (§20.2)."""
    return {"method": self.method, "params": self.params.to_dict()}
