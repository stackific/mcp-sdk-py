"""Roots (Deprecated) — S32.

Delivers the **Roots** client capability: a way for a client to expose
filesystem "roots" (directories and files it considers relevant) so a server
can focus its operations on them. Roots is **Deprecated** as a present
condition — implementations SHOULD NOT adopt it for new functionality — yet it
remains part of the specification, so a conforming receiver MUST still honor its
wire contract while the capability is published.

Roots is never delivered as a server-initiated JSON-RPC request. A server asks
for roots by returning an *input-required* result (the multi-round-trip
mechanism owned by S17 / §11) whose embedded input request has ``method``
``"roots/list"``; the client supplies the listing by retrying the original
request with a ``ListRootsResult`` keyed to that input request. This module owns
only the ``roots`` capability shape and the ``roots/list`` payloads — the
input-required envelope, request-state token, and input-response keying are
referenced from ``mcp_sdk_py.multi_round_trip`` and not re-implemented here.

Public surface:

Deprecation status & migration (§21.1.1):
  - ROOTS_FEATURE_NAME / ROOTS_MIGRATION_NOTE / ROOTS_EARLIEST_REMOVAL:
    the registry-aligned identity of the deprecated capability (R-21-a,
    R-21.1-a, R-21.1.1-a/-b).
  - ROOTS_IS_DEPRECATED: sentinel making the present condition explicit
    (R-21.1.1-c).
  - recommended_migration_mechanisms(): the non-roots mechanisms a builder
    SHOULD use instead (R-21.1.1-b).
  - warn_roots_deprecated(): emit an out-of-band DeprecationWarning.

Capability declaration & gating (§21.1.2):
  - ROOTS_CAPABILITY_NAME / canonical_roots_capability_value()
  - validate_roots_capability_value(): the ``{}`` shape rule (R-21.1.2-a/-b).
  - roots_capability_declared(): presence-means-declared (R-21.1.2-d/-e).
  - server_may_request_roots() / assert_server_may_request_roots(): the
    gating guard a server applies before requesting roots.
  - ROOTS_HAS_LIST_CHANGED: False — no listChanged sub-flag exists (R-21.1.2-c).

The roots/list input request (§21.1.4):
  - ROOTS_LIST_METHOD ("roots/list"), ListRootsRequest.

The result and Root type (§21.1.5):
  - ListRootsResult, Root, and their parse/validate/serialize methods.
  - validate_root_uri(): file-scheme + RFC 3986 + path-traversal guard.
  - server_should_tolerate_unavailable_root() / server-side non-enforcement
    helpers (R-21.1.5-j/-k/-l).

Spec: §21.1 (lines 5455–5594)
Depends on: S10 (capabilities), S21 (_meta on a Root), S17 (multi-round-trip)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from mcp_sdk_py.lifecycle import warn_deprecated_feature
from mcp_sdk_py.multi_round_trip import INPUT_REQUEST_ROOTS


# ---------------------------------------------------------------------------
# §21.1.1  Deprecation status and migration
# ---------------------------------------------------------------------------

#: The §27.3-registry name of this deprecated capability. Matches the entry in
#: ``lifecycle.DEPRECATED_FEATURES_REGISTRY`` so the two views stay aligned.
ROOTS_FEATURE_NAME: str = "Roots capability"

#: The migration guidance: instead of roots, convey relevant directories and
#: files through tool input parameters (§16 Tools), resource URIs (§17
#: Resources), or server configuration (R-21.1.1-b).
ROOTS_MIGRATION_NOTE: str = (
  "Convey relevant directories and files to a server through tool input "
  "parameters (see S24/S25 Tools), through resource URIs (see S26/S27 "
  "Resources), or through server configuration — not through the deprecated "
  "Roots capability."
)

#: Revision on or after which removal becomes eligible (mirrors the §27.3
#: registry entry for the Roots capability).
ROOTS_EARLIEST_REMOVAL: str = "2026-07-28"

#: The non-roots mechanisms a builder SHOULD choose for new functionality
#: instead of roots (R-21.1.1-b). Ordered as the spec lists them.
RECOMMENDED_MIGRATION_MECHANISMS: tuple[str, ...] = (
  "tool input parameters",
  "resource URIs",
  "server configuration",
)

#: Present-condition sentinel: the capability is Deprecated yet still published,
#: so a conforming receiver MUST keep honoring the wire contract defined here
#: (R-21-a, R-21.1-a, R-21.1.1-a, R-21.1.1-c). New code SHOULD NOT adopt roots.
ROOTS_IS_DEPRECATED: bool = True

#: There is no ``listChanged`` sub-flag for the ``roots`` capability in this
#: revision; a client MUST NOT rely on a ``listChanged``-style change
#: notification for roots (R-21.1.2-c).
ROOTS_HAS_LIST_CHANGED: bool = False


def recommended_migration_mechanisms() -> tuple[str, ...]:
  """Return the mechanisms a builder SHOULD use instead of roots (R-21.1.1-b).

  Roots (and Sampling) are Deprecated; implementations SHOULD NOT adopt them for
  new functionality (R-21-a, R-21.1-a, R-21.1.1-a). For new functionality a
  builder SHOULD instead convey relevant directories/files through one of these
  mechanisms; roots support exists only for interoperability with existing
  deployments.
  """
  return RECOMMENDED_MIGRATION_MECHANISMS


def warn_roots_deprecated() -> None:
  """Emit an out-of-band DeprecationWarning for the Roots capability (R-21.1.1-a/-b).

  Surfaces the deprecation as a native-language signal via Python's ``warnings``
  module; it never alters the wire contract or response semantics. The receiver
  MUST still honor the published wire contract regardless (R-21.1.1-c).
  """
  warn_deprecated_feature(
    ROOTS_FEATURE_NAME,
    ROOTS_MIGRATION_NOTE,
    earliest_removal=ROOTS_EARLIEST_REMOVAL,
  )


# ---------------------------------------------------------------------------
# §21.1.2  Capability declaration and gating
# ---------------------------------------------------------------------------

#: The client-capabilities key under which roots support is declared.
ROOTS_CAPABILITY_NAME: str = "roots"


class RootsCapabilityNotDeclaredError(Exception):
  """A server attempted to request roots from a client that did not declare them.

  Raised by ``assert_server_may_request_roots`` as a local guard: a server MUST
  NOT request a roots listing from a client that has not declared the ``roots``
  capability, and MUST instead proceed without roots (R-21.1.2-d, R-21.1.2-e).
  """

  def __init__(self, detail: str = "") -> None:
    msg = (
      "A server MUST NOT request a roots listing from a client that has not "
      "declared the 'roots' capability; it MUST proceed without roots "
      "(R-21.1.2-d, R-21.1.2-e)"
    )
    if detail:
      msg = f"{msg}. {detail}"
    super().__init__(msg)
    self.detail: str = detail


def canonical_roots_capability_value() -> dict[str, Any]:
  """Return the canonical ``roots`` capability value — the empty object ``{}``.

  The ``roots`` capability has no defined members; ``{}`` is the canonical value
  whose presence signals support for roots-listing (R-21.1.2-a, §6.1).
  """
  return {}


def validate_roots_capability_value(value: Any) -> dict[str, Any]:
  """Validate a ``roots`` capability value and return it (R-21.1.2-a, R-21.1.2-b).

  The value, when present, MUST be a JSON object; it has no defined members, and
  the empty object ``{}`` is the canonical value (R-21.1.2-a). A receiver MUST
  ignore any unrecognized members rather than rejecting the capability
  (R-21.1.2-b) — so any object value (even one carrying extra keys) is accepted
  and returned unchanged; the capability is still treated as declared.

  Raises:
    TypeError: ``value`` is not a JSON object (e.g. a list, string, number, or
      boolean) — such a value is invalid (R-21.1.2-a).
  """
  if isinstance(value, bool) or not isinstance(value, dict):
    raise TypeError(
      f"The 'roots' capability value MUST be a JSON object; got "
      f"{type(value).__name__} (R-21.1.2-a)"
    )
  return value


def roots_capability_declared(client_capabilities: dict[str, Any]) -> bool:
  """Return True if the client declared the ``roots`` capability (R-21.1.2-d/-e).

  Presence of the ``roots`` key (with any object value) signals support for
  roots-listing; absence signals no support (§6.1, §21.1.2). This is the single
  gate a server consults before requesting roots: a server MUST NOT request
  roots from a client that has not declared the capability (R-21.1.2-d).

  Args:
    client_capabilities: the client-capabilities object (e.g. as read from
      ``_meta.io.modelcontextprotocol/clientCapabilities``).
  """
  return (
    isinstance(client_capabilities, dict)
    and ROOTS_CAPABILITY_NAME in client_capabilities
  )


def server_may_request_roots(client_capabilities: dict[str, Any]) -> bool:
  """Return True if a server may request a roots listing from this client (R-21.1.2-d/-e).

  A server MUST NOT request a roots listing from a client that has not declared
  the ``roots`` capability (R-21.1.2-d); if it would otherwise need roots from
  such a client, it MUST proceed without roots (R-21.1.2-e). This helper returns
  the gating decision; ``server_proceed_without_roots`` expresses the fallback.
  """
  return roots_capability_declared(client_capabilities)


def assert_server_may_request_roots(client_capabilities: dict[str, Any]) -> None:
  """Raise if a server may not request roots from this client (R-21.1.2-d).

  Call this before embedding a ``roots/list`` input request. A server MUST NOT
  request a roots listing from a client that has not declared the ``roots``
  capability; instead it MUST proceed without roots (R-21.1.2-e) — see
  ``server_proceed_without_roots``.

  Raises:
    RootsCapabilityNotDeclaredError: the client did not declare ``roots``.
  """
  if not server_may_request_roots(client_capabilities):
    raise RootsCapabilityNotDeclaredError()


def server_proceed_without_roots(client_capabilities: dict[str, Any]) -> bool:
  """Return True when the server must proceed without requesting roots (R-21.1.2-e).

  If a server would otherwise request roots from a client that has not declared
  the capability, it MUST proceed without roots. This returns True exactly when
  the capability is undeclared, so a caller can branch into the no-roots path
  rather than emitting a (forbidden) roots request.
  """
  return not roots_capability_declared(client_capabilities)


# ---------------------------------------------------------------------------
# §21.1.4  The roots/list input request
# ---------------------------------------------------------------------------

#: The exact, case-sensitive method discriminator for the roots input request
#: (R-21.1.3-a, R-21.1.4-a). Reused from S17 so the recognized-kinds set in
#: ``multi_round_trip`` and this story share a single source of truth.
ROOTS_LIST_METHOD: str = INPUT_REQUEST_ROOTS  # "roots/list"


@dataclass
class ListRootsRequest:
  """The ``roots/list`` input request a server embeds to obtain roots (§21.1.4).

  Roots is NOT a server-initiated JSON-RPC request. A server requests a roots
  listing by returning an input-required result (S17 / §11) whose embedded input
  request is shaped as this type; the client supplies the listing by retrying
  the original request (R-21.1.3-a).

  Fields:
    method: REQUIRED. MUST be exactly ``"roots/list"`` (case-sensitive)
      (R-21.1.4-a). Defaults to the literal so callers cannot mis-set it.
    params: OPTIONAL. A request-parameters object carrying no roots-specific
      members; it MAY carry only the common ``_meta`` member. A receiver MUST
      tolerate its absence (R-21.1.4-b, R-21.1.4-c).
  """

  method: str = ROOTS_LIST_METHOD
  params: dict[str, Any] | None = None

  def __post_init__(self) -> None:
    # R-21.1.4-a: method is REQUIRED, a string, exactly "roots/list".
    if not isinstance(self.method, str):
      raise TypeError(
        f"ListRootsRequest.method must be a string; got "
        f"{type(self.method).__name__} (R-21.1.4-a)"
      )
    if self.method != ROOTS_LIST_METHOD:
      raise ValueError(
        f"ListRootsRequest.method MUST be exactly {ROOTS_LIST_METHOD!r} "
        f"(case-sensitive); got {self.method!r} (R-21.1.4-a)"
      )
    # R-21.1.4-b: params, when present, MUST be a JSON object.
    if self.params is not None and not isinstance(self.params, dict):
      raise TypeError(
        f"ListRootsRequest.params must be a JSON object if present; got "
        f"{type(self.params).__name__} (R-21.1.4-b)"
      )

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> ListRootsRequest:
    """Parse and validate a ``roots/list`` input request (§21.1.4).

    A receiver MUST tolerate the absence of ``params`` (R-21.1.4-c): an absent
    ``params`` parses to ``None`` and is accepted.

    Raises:
      TypeError: ``data`` is not a dict, or a field has the wrong type.
      ValueError: ``method`` is absent or not exactly ``"roots/list"``
        (R-21.1.4-a).
    """
    if not isinstance(data, dict):
      raise TypeError(
        f"ListRootsRequest must be a JSON object; got {type(data).__name__}"
      )
    if "method" not in data:
      raise ValueError("ListRootsRequest.method is REQUIRED (R-21.1.4-a)")
    return cls(method=data["method"], params=data.get("params"))

  def to_dict(self) -> dict[str, Any]:
    """Serialise to the wire object; omits ``params`` when absent (§21.1.4)."""
    out: dict[str, Any] = {"method": self.method}
    if self.params is not None:
      out["params"] = self.params
    return out


# ---------------------------------------------------------------------------
# §21.1.5  The ListRootsResult and the Root type
# ---------------------------------------------------------------------------

class InvalidRootURIError(ValueError):
  """A root ``uri`` failed client-side validation (R-21.1.5-b/-d/-i).

  Raised when a ``uri`` is missing, is not a string, does not use the ``file``
  scheme (does not begin with ``file://``), is not a syntactically valid URI per
  RFC 3986, or contains a path-traversal artifact a client SHOULD guard against
  before exposing the root (R-21.1.5-b, R-21.1.5-d, R-21.1.5-i).
  """

  def __init__(self, uri: Any, reason: str) -> None:
    super().__init__(
      f"Invalid root uri {uri!r}: {reason} (R-21.1.5-b, R-21.1.5-d, R-21.1.5-i)"
    )
    self.uri: Any = uri
    self.reason: str = reason


#: Substrings that signal a path-traversal artifact a client SHOULD guard
#: against before exposing a root (R-21.1.5-i). ``..`` as a path segment escapes
#: a parent directory; encoded forms (``%2e%2e``) and backslash variants are
#: included so the guard is not trivially bypassed.
_TRAVERSAL_MARKERS: tuple[str, ...] = (
  "/../",
  "/..",
  "\\..\\",
  "\\..",
  "%2e%2e",
  "%2E%2E",
)


def validate_root_uri(uri: Any, *, reject_traversal: bool = True) -> str:
  """Validate a root ``uri`` and return it, or raise (R-21.1.5-b/-d/-i).

  Enforces the client-side obligations on a root URI:
    - REQUIRED, and a string (R-21.1.5-b).
    - MUST use the ``file`` scheme — it MUST begin with ``file://`` (R-21.1.5-b).
    - MUST be a syntactically valid URI per RFC 3986 (R-21.1.5-d): it must have a
      scheme, and ``urlsplit`` must accept it without error.
    - SHOULD guard against path-traversal artifacts before exposing it
      (R-21.1.5-i). When ``reject_traversal`` is True (the default), a ``..``
      segment (or an encoded/backslash variant) in the path fails validation.

  Args:
    uri: the candidate root URI.
    reject_traversal: when True, reject path-traversal artifacts (R-21.1.5-i).

  Returns:
    The validated ``uri`` string unchanged.

  Raises:
    InvalidRootURIError: the URI is missing, non-string, non-``file``, malformed,
      or (when ``reject_traversal``) carries a traversal artifact.
  """
  if not isinstance(uri, str) or not uri:
    raise InvalidRootURIError(uri, "uri is REQUIRED and must be a non-empty string")
  # R-21.1.5-b: scheme MUST be 'file' — begin with "file://".
  if not uri.startswith("file://"):
    raise InvalidRootURIError(
      uri, "in this revision a root uri MUST use the 'file' scheme (begin with 'file://')"
    )
  # R-21.1.5-d: syntactically valid URI per RFC 3986. An RFC 3986 URI is a
  # sequence of allowed ASCII characters; a space, control character, or other
  # disallowed octet must be percent-encoded. Reject any raw disallowed octet.
  for ch in uri:
    if ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F:
      raise InvalidRootURIError(
        uri, "not a syntactically valid URI per RFC 3986: contains an unencoded "
        "space or control character"
      )
  # urlsplit raises ValueError for structurally invalid components (e.g. a
  # malformed IPv6 host). Accessing .port forces validation of the port subcomponent.
  try:
    parts = urlsplit(uri)
    _ = parts.port
  except ValueError as exc:
    raise InvalidRootURIError(uri, f"not a syntactically valid URI per RFC 3986: {exc}") from exc
  if parts.scheme != "file":
    raise InvalidRootURIError(
      uri, f"uri scheme MUST be 'file'; got {parts.scheme!r}"
    )
  # R-21.1.5-i: guard against path-traversal artifacts before exposing.
  if reject_traversal:
    lowered = uri.lower()
    for marker in _TRAVERSAL_MARKERS:
      if marker.lower() in lowered:
        raise InvalidRootURIError(
          uri, "contains a path-traversal artifact ('..'); guard against it before exposing"
        )
  return uri


def root_uri_is_file_scheme(uri: Any) -> bool:
  """Return True if ``uri`` is a string beginning with ``file://`` (R-21.1.5-c).

  A receiver MAY reject, or ignore, a root whose ``uri`` does not use the
  ``file`` scheme (R-21.1.5-c). This predicate lets a tolerant receiver decide
  to skip a non-``file`` root without raising; both rejecting and ignoring are
  conformant.
  """
  return isinstance(uri, str) and uri.startswith("file://")


@dataclass
class Root:
  """One exposed root: a ``file://`` URI plus an optional display name (§21.1.5).

  A Root is informational guidance, not an enforced access boundary
  (R-21.1.5-l). A client MUST only expose roots it intends a server to treat as
  in-scope (R-21.1.5-g) and SHOULD obtain user consent before exposing them
  (R-21.1.5-h); see ``assemble_listing`` for a consent-gated builder.

  Fields:
    uri: REQUIRED. The URI identifying the root; in this revision it MUST use the
      ``file`` scheme and MUST be a syntactically valid URI per RFC 3986
      (R-21.1.5-b, R-21.1.5-d). Validated unless ``validate=False`` is passed to
      the constructor.
    name: OPTIONAL. A human-readable name; when absent, no display name is
      implied (R-21.1.5-e).
    meta: OPTIONAL. Implementation-defined metadata (JSON: ``_meta``). A receiver
      MUST ignore members it does not recognize (R-21.1.5-f) — they are carried
      verbatim and never interpreted here.
  """

  uri: str
  name: str | None = None
  meta: dict[str, Any] | None = None
  #: When False, the constructor skips ``file``-scheme / RFC-3986 / traversal
  #: validation — used by a *receiver* that wishes to ignore (R-21.1.5-c) rather
  #: than reject a non-``file`` root. Clients assembling a listing leave this
  #: True to honor R-21.1.5-b/-d/-i.
  validate: bool = field(default=True)

  def __post_init__(self) -> None:
    if self.validate:
      validate_root_uri(self.uri)
    elif not isinstance(self.uri, str) or not self.uri:
      raise InvalidRootURIError(self.uri, "uri is REQUIRED and must be a non-empty string")
    if self.name is not None and not isinstance(self.name, str):
      raise TypeError(
        f"Root.name must be a string when present; got "
        f"{type(self.name).__name__} (R-21.1.5-e)"
      )
    if self.meta is not None and not isinstance(self.meta, dict):
      raise TypeError(
        f"Root._meta must be a JSON object when present; got "
        f"{type(self.meta).__name__} (R-21.1.5-f)"
      )

  @property
  def has_display_name(self) -> bool:
    """True only when a ``name`` is present; absent ``name`` implies none (R-21.1.5-e)."""
    return self.name is not None

  @classmethod
  def from_dict(cls, data: dict[str, Any], *, validate: bool = True) -> Root:
    """Parse and validate a ``Root`` from a wire dict (§21.1.5).

    Unrecognized ``_meta`` members are carried verbatim and never interpreted; a
    receiver MUST ignore those it does not recognize (R-21.1.5-f). Unknown
    top-level keys are tolerated for forward compatibility.

    Args:
      data: the wire ``Root`` object.
      validate: when True (default), enforce R-21.1.5-b/-d/-i on ``uri``; pass
        False to ignore (rather than reject) a non-``file`` root (R-21.1.5-c).

    Raises:
      TypeError: ``data`` is not a dict, or a field has the wrong type.
      ValueError / InvalidRootURIError: ``uri`` is absent or (when validating)
        fails URI validation.
    """
    if not isinstance(data, dict):
      raise TypeError(f"Root must be a JSON object; got {type(data).__name__}")
    if "uri" not in data:
      raise ValueError("Root.uri is REQUIRED (R-21.1.5-b)")
    return cls(
      uri=data["uri"],
      name=data.get("name"),
      meta=data.get("_meta"),
      validate=validate,
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to the wire object; omits absent optional fields (§21.1.5)."""
    out: dict[str, Any] = {"uri": self.uri}
    if self.name is not None:
      out["name"] = self.name
    if self.meta is not None:
      out["_meta"] = self.meta
    return out


@dataclass
class ListRootsResult:
  """The listing a client supplies on retry as the ``roots/list`` input response (§21.1.5).

  Fields:
    roots: REQUIRED. The exposed roots. MAY be empty (``[]``) to indicate no
      roots are exposed, but MUST be present even when empty (R-21.1.5-a).
  """

  roots: list[Root] = field(default_factory=list)

  def __post_init__(self) -> None:
    # R-21.1.5-a: roots is REQUIRED and MUST be a list (it MAY be empty).
    if not isinstance(self.roots, list):
      raise TypeError(
        f"ListRootsResult.roots is REQUIRED and must be an array; got "
        f"{type(self.roots).__name__} (R-21.1.5-a)"
      )
    for entry in self.roots:
      if not isinstance(entry, Root):
        raise TypeError(
          f"ListRootsResult.roots entries must be Root; got {type(entry).__name__}"
        )

  @property
  def is_empty(self) -> bool:
    """True when no roots are exposed — the conformant ``[]`` case (R-21.1.5-a)."""
    return not self.roots

  @classmethod
  def from_dict(cls, data: dict[str, Any], *, validate: bool = True) -> ListRootsResult:
    """Parse and validate a ``ListRootsResult`` from a wire dict (§21.1.5).

    The ``roots`` array is REQUIRED; a result missing ``roots`` is invalid, and
    ``roots: []`` is accepted as "no roots exposed" (R-21.1.5-a).

    Args:
      data: the wire ``ListRootsResult`` object.
      validate: forwarded to ``Root.from_dict`` — when False a receiver ignores
        (rather than rejects) non-``file`` roots (R-21.1.5-c).

    Raises:
      TypeError: ``data`` is not a dict, or ``roots`` is not an array.
      ValueError: ``roots`` is absent (R-21.1.5-a).
    """
    if not isinstance(data, dict):
      raise TypeError(
        f"ListRootsResult must be a JSON object; got {type(data).__name__}"
      )
    if "roots" not in data:
      raise ValueError(
        "ListRootsResult.roots is REQUIRED and must be present even when empty "
        "(R-21.1.5-a)"
      )
    raw_roots = data["roots"]
    if not isinstance(raw_roots, list):
      raise TypeError(
        f"ListRootsResult.roots must be an array; got {type(raw_roots).__name__} "
        f"(R-21.1.5-a)"
      )
    return cls(roots=[Root.from_dict(r, validate=validate) for r in raw_roots])

  def to_dict(self) -> dict[str, Any]:
    """Serialise to the wire object; always includes ``roots`` (R-21.1.5-a)."""
    return {"roots": [r.to_dict() for r in self.roots]}


# ---------------------------------------------------------------------------
# §21.1.5  Client-side consent & validation; server-side non-enforcement
# ---------------------------------------------------------------------------

class RootsConsentError(Exception):
  """A client assembled a listing without obtaining user consent (R-21.1.5-h).

  A client SHOULD obtain user consent before exposing roots to a server; this
  guard lets ``assemble_listing`` make that obligation explicit by raising when
  consent was not granted.
  """


def assemble_listing(
  candidate_roots: list[Root],
  *,
  user_consented: bool,
  validate_uris: bool = True,
) -> ListRootsResult:
  """Build a ``ListRootsResult`` from roots a client intends to expose (§21.1.5).

  Encodes the client-side obligations:
    - A client MUST only expose roots it intends a server to treat as in-scope
      (R-21.1.5-g) — the caller supplies exactly those ``candidate_roots``.
    - A client SHOULD obtain user consent before exposing roots (R-21.1.5-h):
      this raises ``RootsConsentError`` unless ``user_consented`` is True.
    - A client SHOULD validate every root ``uri`` to guard against
      path-traversal artifacts before exposing it (R-21.1.5-i): when
      ``validate_uris`` is True (default) each URI is re-validated.

  Passing an empty list yields the conformant "no roots exposed" result
  (``{"roots": []}``) (R-21.1.5-a).

  Raises:
    RootsConsentError: ``user_consented`` is False (R-21.1.5-h).
    InvalidRootURIError: a root URI fails validation (R-21.1.5-i).
  """
  if not user_consented:
    raise RootsConsentError(
      "A client SHOULD obtain user consent before exposing roots to a server "
      "(R-21.1.5-h); consent was not granted"
    )
  if validate_uris:
    for root in candidate_roots:
      validate_root_uri(root.uri)
  return ListRootsResult(roots=list(candidate_roots))


def server_should_tolerate_unavailable_root() -> bool:
  """Return True: a server SHOULD tolerate roots becoming unavailable (R-21.1.5-j).

  After a client reports roots, one MAY later become unavailable; a server
  SHOULD tolerate this rather than failing. This sentinel documents that a
  conforming server does not error merely because a reported root has vanished.
  """
  return True


def server_validates_derived_paths() -> bool:
  """Return True: a server SHOULD validate paths it derives against the roots (R-21.1.5-k).

  A server SHOULD validate any filesystem paths it derives from a request
  against the reported roots before acting on them; it cannot rely on the
  protocol to do so (see ``protocol_enforces_root_boundaries``).
  """
  return True


def protocol_enforces_root_boundaries() -> bool:
  """Return False: the protocol does NOT enforce root boundaries (R-21.1.5-l).

  Roots are informational guidance, not an access-control mechanism. A server
  MUST NOT assume the protocol confines its operations to the reported roots on
  its behalf (R-21.1.5-l); it must validate derived paths itself (R-21.1.5-k).
  """
  return False
