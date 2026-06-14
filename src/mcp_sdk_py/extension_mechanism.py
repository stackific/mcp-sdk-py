"""The Extension Mechanism — S38 (spec §24).

Delivers the framework by which functionality beyond the core protocol is
added, negotiated, and used: what an extension is, how an *active* extension may
contribute to the protocol surface, how extensions version and deprecate
independently of the core revision, and how peers gracefully degrade to core
behavior when an extension is not active.

This story is the surface-contribution and degradation layer that sits on top of
two lower stories and deliberately does NOT re-implement their surfaces:

  - S11 (``mcp_sdk_py.extensions``) owns the extension-identifier grammar
    (prefix/label/name rules, reserved prefixes, case-sensitivity), the
    ``extensions`` map parsing (``null``/non-object entries are malformed and
    dropped), and the active-set intersection. This module re-exports and reuses
    those primitives rather than duplicating them (§24.2/§24.3 ⇒ S11 §6.5).
  - S04 (``mcp_sdk_py.result_error``) owns the core ``resultType`` discriminator
    and its two protocol-defined values (``complete``, ``input_required``). This
    module forms the *accepted* ``resultType`` set as core ∪ active-extension
    contributions (§24.5 item 3).

What S38 adds on top (§24.5–§24.7):

  - :class:`ExtensionDefinition` — a self-describing extension: its identifier,
    classification (modular / specialized / experimental), the four-channel
    surface it contributes (methods, notifications, reserved ``_meta`` keys,
    ``resultType`` values, object fields), and its documented fallback behavior.
    Construction validates the identifier and every contributed surface element
    against §24.2/§24.5 — including the no-redefinition-of-core rule (§24.5-i)
    and the namespacing rule (§24.5-b/d). Implementations SHOULD derive the
    vendor prefix from reverse-DNS notation of a domain they control (e.g. the
    owner of ``example.com`` uses ``com.example/``) to avoid collisions
    (§24.2-c).
  - :class:`ExtensionRegistry` — the set of extensions a peer knows; computes the
    active set per request (§24.4), the accepted ``resultType`` set (§24.5-e/f),
    and gates outbound/inbound surface against the active set (§24.3-e/f).
  - Graceful-degradation helpers (§24.7): fall back to core behavior, ignore
    unrecognized identifiers, and — for a genuinely required extension — raise an
    *actionable* :class:`RequiredExtensionUnavailableError` that names the
    missing extension and carries a core error code per §22.
  - Versioning helpers (§24.6): read an extension's version from its negotiated
    settings object so it is discoverable through negotiation, never out of band.

Spec: §24 (lines 6999–7160)
Depends on: S11 (identifier grammar, active set), S10 (capability objects),
  S04 (core resultType values), S05 (_meta key grammar)
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from mcp_sdk_py.extensions import (
  ExtensionNotActiveError,
  InvalidExtensionIdentifierError,
  MandatoryExtensionUnavailableError,
  active_extensions,
  advertised_extension_ids,
  extension_setting,
  is_extension_active,
  split_extension_identifier,
  validate_extension_identifier,
)
from mcp_sdk_py.foundations import ConformanceError
from mcp_sdk_py.json_value import (
  BASE_METHOD_NAMES,
  RESERVED_SECOND_LABELS,
  is_base_method_name,
  is_valid_meta_name,
  is_valid_meta_prefix,
  parse_meta_key,
)
from mcp_sdk_py.result_error import (
  RESULT_TYPE_COMPLETE,
  RESULT_TYPE_INPUT_REQUIRED,
)


# ---------------------------------------------------------------------------
# Core surface this story protects against redefinition  [R-24.1-d, R-24.5-i]
# ---------------------------------------------------------------------------

#: The two ``resultType`` discriminator values defined by the core protocol
#: revision (§3.6, owned by S04). The accepted set a receiver forms is these
#: values UNION the values contributed by active extensions (§24.5 item 3,
#: R-24.5-e). Re-exposed here as a frozenset because S38 owns the
#: surface-composition rule that builds upon it.
CORE_RESULT_TYPES: frozenset[str] = frozenset({
  RESULT_TYPE_COMPLETE,
  RESULT_TYPE_INPUT_REQUIRED,
})

#: The core request-method and notification names an extension MUST NOT redefine
#: (R-24.5-i) and which extension method strings MUST NOT collide with
#: (R-24.5-b). Owned by S02 (``BASE_METHOD_NAMES``); re-exposed for the
#: namespacing/no-redefinition checks this story performs.
CORE_METHOD_NAMES: frozenset[str] = BASE_METHOD_NAMES

#: The default core JSON-RPC error code a receiver MAY use when it rejects
#: surface for a non-active extension or refuses a mandated-but-absent extension
#: (§24.3-f, §24.7-f ⇒ §22). ``-32601`` (method not found) is the natural code
#: when the rejected surface is an extension method; callers MAY substitute
#: another core code (e.g. ``-32600`` invalid request) as appropriate.
DEFAULT_REJECTION_ERROR_CODE: int = -32601


def assert_third_party_prefix_not_bare_reserved(identifier: str) -> None:
  """Reject a *single-label* vendor prefix that is a bare reserved token (R-24.2-f).

  R-24.2-e (owned by S11's :func:`validate_extension_identifier`) reserves any
  prefix whose *second* label is ``modelcontextprotocol`` or ``mcp``. R-24.2-f
  additionally forbids third parties from using the bare tokens themselves as the
  whole vendor prefix — e.g. ``mcp/x`` or ``modelcontextprotocol/x`` — which a
  second-label check cannot catch because a single-label prefix has no second
  label. This closes that gap so both rules are enforced for third-party
  identifiers.

  Args:
    identifier: a well-formed ``prefix/name`` extension identifier.

  Raises:
    InvalidExtensionIdentifierError: the vendor prefix is exactly a bare reserved
      token (R-24.2-f).
  """
  prefix, _ = split_extension_identifier(identifier)
  if prefix is not None and prefix in RESERVED_SECOND_LABELS:
    raise InvalidExtensionIdentifierError(
      identifier,
      f"vendor prefix {prefix!r} is a bare reserved token; third-party "
      f"extensions MUST NOT use {sorted(RESERVED_SECOND_LABELS)} as a vendor "
      f"prefix (R-24.2-f)",
    )


# ---------------------------------------------------------------------------
# §24.1  Extension classification  [R-24.1-a]
# ---------------------------------------------------------------------------

class ExtensionClassification(Enum):
  """How an extension relates to the core protocol (§24.1, R-24.1-a).

  Every extension is classifiable as exactly one of:

  MODULAR:
    A discrete, self-contained capability (e.g. an additional method family).
  SPECIALIZED:
    Domain- or industry-specific behavior.
  EXPERIMENTAL:
    Functionality being incubated for possible future inclusion in the core.

  The classification is descriptive only: an implementation that supports zero
  extensions of any classification is still fully conformant with the core
  protocol (R-24.1-a / AC-38.2). It carries no activation semantics — activation
  is governed solely by the active-set intersection of §24.3.
  """

  MODULAR = "modular"
  SPECIALIZED = "specialized"
  EXPERIMENTAL = "experimental"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class NonConformantExtensionError(ConformanceError):
  """An extension definition or surface element violates the §24 framework.

  Raised at definition time when an extension would add surface outside the
  sanctioned four channels, redefine core surface, fail the namespacing rule, or
  otherwise breach §24 (R-24-a, R-24.1-d, R-24.5-b/d/i). A conformance suite
  rejects such a definition rather than admitting non-conformant surface
  (AC-38.1, AC-38.5).

  Attributes:
    identifier: the extension identifier the violation concerns (or the offending
      surface element when no identifier applies).
    reason: a human-readable description citing the breached rule.
  """

  def __init__(self, identifier: str, reason: str) -> None:
    super().__init__(
      f"Extension {identifier!r} does not conform to the §24 framework: {reason}"
    )
    self.identifier: str = identifier
    self.reason: str = reason


class RequiredExtensionUnavailableError(ConformanceError):
  """A mandated extension is not in the active set, so the interaction is refused.

  An implementation that genuinely requires an extension the other side did not
  advertise SHOULD surface an *actionable* error rather than failing opaquely,
  and the error SHOULD identify the required extension (R-24.7-d/e). An
  implementation that mandates an extension MAY refuse the interaction outright
  (R-24.7-f). This exception is that actionable refusal: it names the extension
  and carries a core JSON-RPC error code per §22 so the rejection can be turned
  into a wire error.

  Attributes:
    identifier: the required extension identifier that was not active.
    error_code: the core JSON-RPC error code to emit (defaults to
      :data:`DEFAULT_REJECTION_ERROR_CODE`).
  """

  def __init__(
    self,
    identifier: str,
    *,
    error_code: int = DEFAULT_REJECTION_ERROR_CODE,
  ) -> None:
    super().__init__(
      f"This interaction requires extension {identifier!r}, which the other peer "
      f"did not advertise, so it is not in the active set; the implementation "
      f"mandates this extension and refuses the interaction rather than failing "
      f"opaquely (R-24.7-d/e/f). Advertise {identifier!r} on both peers to "
      f"proceed."
    )
    self.identifier: str = identifier
    self.error_code: int = error_code

  def to_error_object(self) -> dict[str, Any]:
    """Return a core error object naming the required extension (R-24.7-e ⇒ §22).

    The ``data.requiredExtension`` field carries the identifier so an operator or
    developer can act on it; the ``message`` is human-readable. The numeric code
    is the core JSON-RPC code chosen at construction.
    """
    return {
      "code": self.error_code,
      "message": str(self),
      "data": {"requiredExtension": self.identifier},
    }


# ---------------------------------------------------------------------------
# §24.5  Surface-element validation helpers  [R-24.5-b/d/i]
# ---------------------------------------------------------------------------

def derive_namespace(identifier: str) -> str:
  """Return the method/notification namespace token derived from ``identifier``.

  An extension's method strings are namespaced from its own identifier-derived
  namespace so they collide neither with core methods nor with other extensions
  (R-24.5-b). The namespace token is the extension *name* segment of the
  identifier — e.g. ``io.modelcontextprotocol/tasks`` yields ``tasks``, whose
  methods are ``tasks/get``, ``tasks/update``, ... (the §25 example). The vendor
  prefix guarantees the name segment is unique to that vendor's extension.

  Args:
    identifier: a well-formed extension identifier (``prefix/name``).

  Returns:
    The name segment used as the method namespace.

  Raises:
    InvalidExtensionIdentifierError: ``identifier`` has no prefix (a bare name is
      not a valid extension identifier, R-24.2-a).
  """
  prefix, name = split_extension_identifier(identifier)
  if prefix is None:
    raise InvalidExtensionIdentifierError(
      identifier,
      "a prefix is REQUIRED to derive a method namespace (R-24.2-a)",
    )
  return name


def is_namespaced_method(method: str, identifier: str) -> bool:
  """Return True if ``method`` lies in ``identifier``'s derived namespace (R-24.5-b).

  A method belongs to the extension when it equals the namespace token or begins
  with ``"<namespace>/"`` (e.g. ``tasks/get`` for the ``tasks`` namespace). This
  is the namespacing test that keeps extension methods from colliding with core
  methods or with other extensions' methods.
  """
  namespace = derive_namespace(identifier)
  return method == namespace or method.startswith(f"{namespace}/")


def validate_extension_method_string(method: str, identifier: str) -> None:
  """Validate an extension-defined method/notification name (R-24.5-b, R-24.5-i).

  Enforces, in order:
    1. The name does not collide with a core method/notification — an extension
       MUST NOT redefine core surface, only add (R-24.5-i, R-24.1-d).
    2. The name is namespaced from the extension's identifier-derived namespace,
       so it cannot collide with core or with another extension (R-24.5-b).

  Args:
    method: the proposed ``method`` string for an extension method/notification.
    identifier: the defining extension's identifier.

  Raises:
    NonConformantExtensionError: the name collides with core surface or is not
      namespaced from the extension's own namespace.
  """
  if is_base_method_name(method):
    raise NonConformantExtensionError(
      identifier,
      f"method {method!r} collides with a core method/notification; an extension "
      f"MUST NOT redefine core surface, only add (R-24.5-i, R-24.1-d)",
    )
  if not is_namespaced_method(method, identifier):
    raise NonConformantExtensionError(
      identifier,
      f"method {method!r} is not namespaced from this extension's identifier "
      f"namespace {derive_namespace(identifier)!r}; extension methods MUST be "
      f"namespaced so they collide with neither core nor other extensions "
      f"(R-24.5-b)",
    )


def validate_extension_meta_key(meta_key: str, identifier: str) -> None:
  """Validate an extension-reserved ``_meta`` key (R-24.5-d ⇒ §4 prefix rules).

  An additional reserved ``_meta`` key an extension defines MUST be named under a
  vendor prefix the extension controls, following the §4 prefix rules: a valid
  prefix and a valid name. Core-protocol extensions use a reserved prefix
  (``io.modelcontextprotocol/``); third-party extensions use their own vendor
  prefix. Bare keys are not permissible extension-reserved keys — the prefix is
  what scopes the key to the extension.

  Args:
    meta_key: the proposed ``_meta`` key.
    identifier: the defining extension's identifier (for error context).

  Raises:
    NonConformantExtensionError: the key has no prefix, a malformed prefix, or a
      malformed name (R-24.5-d).
  """
  prefix, name = parse_meta_key(meta_key)
  if prefix is None:
    raise NonConformantExtensionError(
      identifier,
      f"reserved _meta key {meta_key!r} must carry a vendor prefix the extension "
      f"controls; bare keys are not extension-reserved keys (R-24.5-d, §4)",
    )
  if not is_valid_meta_prefix(prefix):
    raise NonConformantExtensionError(
      identifier,
      f"reserved _meta key prefix {prefix!r} does not conform to the §4 label "
      f"grammar (R-24.5-d)",
    )
  if not is_valid_meta_name(name):
    raise NonConformantExtensionError(
      identifier,
      f"reserved _meta key name {name!r} does not conform to the §4 name grammar "
      f"(R-24.5-d)",
    )


def validate_extension_result_type(result_type: str, identifier: str) -> None:
  """Validate an extension-contributed ``resultType`` value (R-24.5-e/i).

  An extension MAY contribute additional ``resultType`` discriminator values
  (§24.5 item 3), but MUST NOT redefine a core value — it may only add new ones
  (R-24.5-i). A value equal to a core value (``complete`` / ``input_required``)
  is therefore rejected as a redefinition.

  Raises:
    NonConformantExtensionError: ``result_type`` is a core value (redefinition)
      or not a non-empty string.
  """
  if not isinstance(result_type, str) or not result_type:
    raise NonConformantExtensionError(
      identifier,
      f"resultType value {result_type!r} must be a non-empty string",
    )
  if result_type in CORE_RESULT_TYPES:
    raise NonConformantExtensionError(
      identifier,
      f"resultType value {result_type!r} is a core value; an extension MUST NOT "
      f"redefine an existing core resultType, only add new ones (R-24.5-i)",
    )


# ---------------------------------------------------------------------------
# §24.1 / §24.5  ExtensionDefinition
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ExtensionDefinition:
  """A self-describing extension conforming to the §24 framework (R-24-a).

  An extension declares its identifier, its classification, and — through the
  four-and-only-four sanctioned channels (§24.5) — the surface it contributes
  while active. Construction validates every part against §24.2/§24.5, so a
  non-conforming definition is rejected up front (AC-38.1, AC-38.5): the
  identifier grammar and reserved-prefix rule (R-24.2-a..g via S11), the
  method/notification namespacing and no-core-collision rule (R-24.5-b/i), the
  reserved ``_meta`` key prefix rule (R-24.5-d), and the no-redefinition rule for
  ``resultType`` values (R-24.5-i).

  Because only these four channels are populated, the definition itself embodies
  R-24.5-a: an active extension extends the surface ONLY via methods/
  notifications, reserved ``_meta`` keys, ``resultType`` values, or fields on
  existing objects. Adding surface outside this mechanism is non-conformant
  (R-24.1-d).

  Attributes:
    identifier: the globally unique extension identifier (``prefix/name``).
    classification: modular / specialized / experimental (R-24.1-a).
    methods: extension-defined request-method names, each namespaced from
      ``identifier`` (channel 1, R-24.5-b).
    notifications: extension-defined notification names, likewise namespaced
      (channel 1, R-24.5-b).
    meta_keys: reserved ``_meta`` keys the extension controls, each under a
      vendor prefix the extension controls (channel 2, R-24.5-d).
    result_types: ``resultType`` discriminator values the extension contributes
      (channel 3, R-24.5-e); none may be a core value (R-24.5-i).
    object_fields: names of fields the extension adds to existing core objects
      (channel 4, R-24.5-g/h). Recorded for documentation/ignoring purposes;
      peers without the extension MUST ignore them.
    fallback_doc: the documented core fallback behavior when the extension is not
      active (R-24.7-h). SHOULD be non-empty so implementers know what core
      behavior to provide.
    allow_reserved: when True, permits the reserved ``io.modelcontextprotocol/``
      family of prefixes — used only when defining the protocol's own official
      extensions, never by third parties (R-24.2-e/f).
  """

  identifier: str
  classification: ExtensionClassification = ExtensionClassification.MODULAR
  methods: frozenset[str] = field(default_factory=frozenset)
  notifications: frozenset[str] = field(default_factory=frozenset)
  meta_keys: frozenset[str] = field(default_factory=frozenset)
  result_types: frozenset[str] = field(default_factory=frozenset)
  object_fields: frozenset[str] = field(default_factory=frozenset)
  fallback_doc: str = ""
  allow_reserved: bool = False

  def __post_init__(self) -> None:
    """Validate the identifier and every contributed surface element (§24.2/§24.5).

    Raises:
      InvalidExtensionIdentifierError: the identifier is malformed or uses a
        reserved prefix without ``allow_reserved`` (R-24.2-a..g, via S11).
      NonConformantExtensionError: a contributed surface element breaches the
        namespacing, reserved-prefix, or no-redefinition rules (R-24.5-b/d/i).
    """
    # Normalize the collection fields to frozensets so callers may pass any
    # iterable; this also makes the frozen dataclass safely hashable.
    object.__setattr__(self, "methods", frozenset(self.methods))
    object.__setattr__(self, "notifications", frozenset(self.notifications))
    object.__setattr__(self, "meta_keys", frozenset(self.meta_keys))
    object.__setattr__(self, "result_types", frozenset(self.result_types))
    object.__setattr__(self, "object_fields", frozenset(self.object_fields))

    # §24.2 — the identifier grammar and second-label reserved-prefix rule
    # (R-24.2-a..e/g, owned by S11).
    validate_extension_identifier(
      self.identifier, allow_reserved=self.allow_reserved
    )
    # §24.2 — bare reserved tokens as the whole vendor prefix (R-24.2-f); S11's
    # second-label check cannot catch a single-label prefix. Skipped only for
    # the protocol's own official extensions (allow_reserved).
    if not self.allow_reserved:
      assert_third_party_prefix_not_bare_reserved(self.identifier)

    # §24.5 channel 1 — methods/notifications namespaced, no core collision.
    for method in self.methods | self.notifications:
      validate_extension_method_string(method, self.identifier)

    # §24.5 channel 2 — reserved _meta keys under a controlled vendor prefix.
    for meta_key in self.meta_keys:
      validate_extension_meta_key(meta_key, self.identifier)

    # §24.5 channel 3 — resultType values add only, never redefine core.
    for result_type in self.result_types:
      validate_extension_result_type(result_type, self.identifier)

  @property
  def namespace(self) -> str:
    """The method namespace token derived from the identifier (R-24.5-b)."""
    return derive_namespace(self.identifier)

  def declares_method(self, method: str) -> bool:
    """Return True if ``method`` is a method or notification this extension defines."""
    return method in self.methods or method in self.notifications

  def declares_result_type(self, result_type: str) -> bool:
    """Return True if ``result_type`` is a ``resultType`` value this extension contributes."""
    return result_type in self.result_types

  def declares_object_field(self, field_name: str) -> bool:
    """Return True if ``field_name`` is a field this extension adds to a core object."""
    return field_name in self.object_fields

  def all_surface(self) -> frozenset[str]:
    """Return every surface token (methods, notifications, _meta keys, resultTypes, fields).

    Useful for the conformance check that an extension contributes surface ONLY
    through the four sanctioned channels (R-24.5-a): the union here is exactly
    those four channels and nothing else.
    """
    return (
      self.methods
      | self.notifications
      | self.meta_keys
      | self.result_types
      | self.object_fields
    )


# ---------------------------------------------------------------------------
# §24.1-d  Sanctioned-surface conformance check  [R-24.1-d]
# ---------------------------------------------------------------------------

def is_sanctioned_surface_addition(
  *,
  declared_by_extension: bool,
) -> bool:
  """Return True only when new surface is added through the extension mechanism (R-24.1-d).

  The extension mechanism is the ONLY sanctioned way to add request methods,
  notifications, ``resultType`` values, reserved ``_meta`` keys, or fields not in
  the core protocol. New surface introduced outside an extension definition is
  non-conformant (R-24.1-d / AC-38.5). This predicate states that rule directly:
  surface is sanctioned iff an extension declares it.
  """
  return declared_by_extension


def assert_surface_is_sanctioned(
  surface_token: str,
  *,
  declared_by_extension: bool,
) -> None:
  """Raise when new surface is added outside the extension mechanism (R-24.1-d).

  A conformance check for AC-38.5: a method/notification/``resultType``/``_meta``
  key/field that is neither core nor declared by an extension is flagged
  non-conformant; only extension-declared surface (beyond core) is sanctioned.

  Raises:
    NonConformantExtensionError: ``surface_token`` is not declared by any
      extension (and is therefore unsanctioned non-core surface).
  """
  if not is_sanctioned_surface_addition(declared_by_extension=declared_by_extension):
    raise NonConformantExtensionError(
      surface_token,
      "surface added outside the extension mechanism is non-conformant; the "
      "extension mechanism is the only sanctioned way to add non-core methods, "
      "notifications, resultType values, reserved _meta keys, or fields "
      "(R-24.1-d)",
    )


# ---------------------------------------------------------------------------
# §24.3 / §24.4 / §24.5  ExtensionRegistry — the surface gate
# ---------------------------------------------------------------------------

class ExtensionRegistry:
  """A peer's known extensions, gating surface against the per-request active set.

  Holds the :class:`ExtensionDefinition` objects this peer understands. From the
  two peers' advertised ``extensions`` maps it computes the active set — the
  intersection of identifiers (§24.3, recomputed per request, §24.4) — and uses
  it to:

    - form the accepted ``resultType`` set as core ∪ active contributions, and
      reject any other value (R-24.5-e/f);
    - gate outbound surface so a peer never sends a non-active extension's
      method/notification/``_meta`` key/``resultType``/field (R-24.3-e, R-24.5-c);
    - decide inbound surface (reject with a core error or ignore), per
      forward-compatibility (R-24.3-f);
    - ignore identifiers it does not recognize (R-24.7-g).

  Each gating call takes both peers' raw ``extensions`` maps so activation is
  recomputed from the request being processed and never inferred from prior
  state (R-24.4-a/b).
  """

  def __init__(
    self,
    definitions: Iterable[ExtensionDefinition] = (),
  ) -> None:
    self._definitions: dict[str, ExtensionDefinition] = {}
    for definition in definitions:
      self.register(definition)

  # -- registration / recognition --

  def register(self, definition: ExtensionDefinition) -> None:
    """Register an extension this peer understands.

    Raises:
      NonConformantExtensionError: an extension with the same identifier is
        already registered (identifiers are globally unique, §24.2).
    """
    if definition.identifier in self._definitions:
      raise NonConformantExtensionError(
        definition.identifier,
        "an extension with this identifier is already registered; extension "
        "identifiers are globally unique (§24.2)",
      )
    self._definitions[definition.identifier] = definition

  @property
  def known_identifiers(self) -> frozenset[str]:
    """The identifiers this peer recognizes."""
    return frozenset(self._definitions)

  def get(self, identifier: str) -> ExtensionDefinition | None:
    """Return the registered definition for ``identifier``, or None if unknown."""
    return self._definitions.get(identifier)

  def recognizes(self, identifier: str) -> bool:
    """Return True if this peer recognizes ``identifier`` (R-24.7-g).

    An identifier this peer does not recognize is ignored and never enters the
    active set; its presence in the other side's map is not an error (R-24.7-g).
    """
    return identifier in self._definitions

  # -- §24.3 / §24.4  active set (per request) --

  def active_set(
    self,
    client_extensions: Any,
    server_extensions: Any,
  ) -> frozenset[str]:
    """Return the active set: identifiers advertised by BOTH peers (R-24.3 / R-24.4).

    The active set is the intersection of the client's and server's advertised
    ``extensions`` maps (R-24.3-d), recomputed from the maps supplied for *this*
    request so nothing is inferred from a prior request (R-24.4-a/b). Malformed
    ``null``/non-object entries on either side are excluded before intersecting
    (delegated to S11). Identifiers not recognized by this peer are not filtered
    out here — recognition is applied by :meth:`active_definitions`; an
    unrecognized identifier simply has no definition to act on (R-24.7-g).

    Args:
      client_extensions: the client's ``extensions`` field value (or ``None``).
      server_extensions: the server's ``extensions`` field value (or ``None``).
    """
    return active_extensions(client_extensions, server_extensions)

  def active_definitions(
    self,
    client_extensions: Any,
    server_extensions: Any,
  ) -> dict[str, ExtensionDefinition]:
    """Return the registered definitions that are active for this request (§24.3/§24.4).

    Only identifiers in BOTH the active set AND this peer's known set yield a
    definition; an active-but-unrecognized identifier contributes no surface here
    because this peer has no definition for it (R-24.7-g).
    """
    active = self.active_set(client_extensions, server_extensions)
    return {
      identifier: self._definitions[identifier]
      for identifier in active
      if identifier in self._definitions
    }

  def is_active(
    self,
    identifier: str,
    client_extensions: Any,
    server_extensions: Any,
  ) -> bool:
    """Return True if ``identifier`` is active for this request (R-24.3-d, R-24.4-a)."""
    return is_extension_active(identifier, client_extensions, server_extensions)

  # -- §24.5 item 3  accepted resultType set --

  def accepted_result_types(
    self,
    client_extensions: Any,
    server_extensions: Any,
  ) -> frozenset[str]:
    """Return the accepted ``resultType`` set: core ∪ active contributions (R-24.5-e).

    The set a receiver will accept MUST be the core-protocol values together with
    the values contributed by extensions in the active set (R-24.5-e). A value
    outside this set is invalid (R-24.5-f); see :meth:`result_type_is_accepted`.
    """
    accepted = set(CORE_RESULT_TYPES)
    for definition in self.active_definitions(
      client_extensions, server_extensions
    ).values():
      accepted |= definition.result_types
    return frozenset(accepted)

  def result_type_is_accepted(
    self,
    result_type: str,
    client_extensions: Any,
    server_extensions: Any,
  ) -> bool:
    """Return True if ``result_type`` is core or contributed by an active extension (R-24.5-e/f).

    A ``resultType`` neither core nor contributed by an active extension is
    invalid (R-24.5-f).
    """
    return result_type in self.accepted_result_types(
      client_extensions, server_extensions
    )

  # -- §24.3-e / §24.5-c  outbound surface gate --

  def may_send_method(
    self,
    method: str,
    client_extensions: Any,
    server_extensions: Any,
  ) -> bool:
    """Return True if ``method`` may be sent on this request (R-24.3-e, R-24.5-c).

    A core method is always sendable. An extension-defined method/notification is
    sendable only when its defining extension is in the active set; otherwise a
    peer MUST NOT send it (R-24.5-c). A method this peer does not recognize as
    either core or extension-declared is treated as non-sendable.
    """
    if is_base_method_name(method):
      return True
    owner = self._owning_definition_for_method(method)
    if owner is None:
      return False
    return self.is_active(owner.identifier, client_extensions, server_extensions)

  def assert_may_send_method(
    self,
    method: str,
    client_extensions: Any,
    server_extensions: Any,
  ) -> None:
    """Raise if ``method`` may not be sent because its extension is not active (R-24.5-c).

    Raises:
      ExtensionNotActiveError: ``method`` is an extension method whose extension
        is not in the active set (R-24.5-c). A method recognized as neither core
        nor extension surface also raises, since it is unsanctioned (R-24.1-d).
    """
    if is_base_method_name(method):
      return
    owner = self._owning_definition_for_method(method)
    if owner is None:
      raise NonConformantExtensionError(
        method,
        "method is neither core nor declared by a known extension; it may not be "
        "sent (R-24.1-d)",
      )
    if not self.is_active(owner.identifier, client_extensions, server_extensions):
      raise ExtensionNotActiveError(owner.identifier)

  def may_send_meta_key(
    self,
    meta_key: str,
    client_extensions: Any,
    server_extensions: Any,
  ) -> bool:
    """Return True if a reserved extension ``_meta`` key may be sent (R-24.3-e).

    An extension's reserved ``_meta`` key may be sent only while its extension is
    active. A key not owned by any known extension is treated as non-sendable
    through this gate (core/bare keys are handled by S05, not here).
    """
    owner = self._owning_definition_for_meta_key(meta_key)
    if owner is None:
      return False
    return self.is_active(owner.identifier, client_extensions, server_extensions)

  def may_send_result_type(
    self,
    result_type: str,
    client_extensions: Any,
    server_extensions: Any,
  ) -> bool:
    """Return True if ``result_type`` may be sent on this request (R-24.3-e, R-24.5-e).

    A core value is always sendable; an extension-contributed value only while
    its extension is active.
    """
    return self.result_type_is_accepted(
      result_type, client_extensions, server_extensions
    )

  def may_send_object_field(
    self,
    field_name: str,
    client_extensions: Any,
    server_extensions: Any,
  ) -> bool:
    """Return True if an extension-added object field may be sent (R-24.3-e, R-24.5-h).

    An extension-defined field may be emitted, and depended upon, only while its
    extension is active (R-24.5-h). A field not owned by any known extension is
    treated as non-sendable through this gate.
    """
    owner = self._owning_definition_for_field(field_name)
    if owner is None:
      return False
    return self.is_active(owner.identifier, client_extensions, server_extensions)

  # -- §24.3-f / §24.5-g  inbound surface handling --

  def handle_inbound_method(
    self,
    method: str,
    client_extensions: Any,
    server_extensions: Any,
    *,
    reject: bool = False,
  ) -> dict[str, Any] | None:
    """Decide what to do with an inbound method for a possibly-non-active extension.

    For surface belonging to a non-active extension a receiver MAY either reject
    with a core error or ignore it per forward-compatibility (R-24.3-f). This
    method returns ``None`` when the method is acceptable (core, or an active
    extension's method) or is to be ignored; it returns a core error object when
    ``reject`` is set and the method belongs to a non-active or unknown extension.

    Args:
      method: the inbound ``method`` string.
      client_extensions: the client's advertised ``extensions`` (or ``None``).
      server_extensions: the server's advertised ``extensions`` (or ``None``).
      reject: when True, return a core error object for non-active surface (the
        reject branch of R-24.3-f); when False, return ``None`` to ignore it (the
        ignore branch).

    Returns:
      ``None`` to accept/ignore, or a core JSON-RPC error object to reject.
    """
    if is_base_method_name(method):
      return None
    owner = self._owning_definition_for_method(method)
    if owner is not None and self.is_active(
      owner.identifier, client_extensions, server_extensions
    ):
      return None
    # Non-active extension surface, or surface for an unrecognized extension.
    if reject:
      return {
        "code": DEFAULT_REJECTION_ERROR_CODE,
        "message": (
          f"Method {method!r} belongs to an extension that is not in the active "
          f"set; it is rejected with a core error (R-24.3-f, §22)"
        ),
      }
    return None  # ignore (forward-compatibility branch, R-24.3-f / R-24.5-g)

  def ignore_inactive_object_fields(
    self,
    obj: Mapping[str, Any],
    client_extensions: Any,
    server_extensions: Any,
  ) -> dict[str, Any]:
    """Return ``obj`` with non-active extension fields removed (R-24.5-g).

    A peer for which an extension is not active MUST ignore that extension's
    fields on existing objects, per forward-compatibility (R-24.5-g), and MUST
    NOT depend on them (R-24.5-h). This drops every field a known extension
    declares whose extension is not active; fields not declared by any known
    extension are left untouched (they are simply unknown and ignored elsewhere),
    and active extensions' fields are retained.

    Args:
      obj: the inbound object (a mapping) to filter.
      client_extensions: the client's advertised ``extensions`` (or ``None``).
      server_extensions: the server's advertised ``extensions`` (or ``None``).

    Returns:
      A new dict in which non-active extension-declared fields are dropped.
    """
    inactive_fields: set[str] = set()
    for definition in self._definitions.values():
      if not self.is_active(
        definition.identifier, client_extensions, server_extensions
      ):
        inactive_fields |= definition.object_fields
    return {k: v for k, v in obj.items() if k not in inactive_fields}

  # -- §24.7  graceful degradation --

  def require_active(
    self,
    identifier: str,
    client_extensions: Any,
    server_extensions: Any,
    *,
    error_code: int = DEFAULT_REJECTION_ERROR_CODE,
  ) -> None:
    """Refuse the interaction with an actionable error if ``identifier`` is inactive (R-24.7-d/e/f).

    For an implementation that genuinely requires (mandates) an extension: when
    the extension is not in the active set, raise an actionable error that names
    the required extension rather than failing opaquely (R-24.7-d/e), exercising
    the implementation's right to refuse outright (R-24.7-f).

    Raises:
      RequiredExtensionUnavailableError: ``identifier`` is not active; the
        exception names it and carries ``error_code`` for a §22 wire error.
    """
    if not self.is_active(identifier, client_extensions, server_extensions):
      raise RequiredExtensionUnavailableError(identifier, error_code=error_code)

  def resolve_degradation(
    self,
    identifier: str,
    client_extensions: Any,
    server_extensions: Any,
    *,
    mandatory: bool = False,
    error_code: int = DEFAULT_REJECTION_ERROR_CODE,
  ) -> bool:
    """Decide whether to use an extension or gracefully degrade (R-24.7-a/b/d/f).

    When the extension is active the caller may emit its surface; otherwise both
    peers MUST fall back to core behavior for the affected interaction
    (R-24.7-a/b). Only when the extension is mandatory does the absence become an
    actionable refusal (R-24.7-d/f).

    Args:
      identifier: the extension under consideration.
      client_extensions: the client's advertised ``extensions`` (or ``None``).
      server_extensions: the server's advertised ``extensions`` (or ``None``).
      mandatory: whether the interaction cannot proceed without the extension.
      error_code: the core error code carried on the refusal when mandatory.

    Returns:
      True when the extension is active and may be used; False when the caller
      MUST fall back to core behavior (R-24.7-a/b).

    Raises:
      RequiredExtensionUnavailableError: the extension is mandatory yet not active
        (R-24.7-d/f).
    """
    if self.is_active(identifier, client_extensions, server_extensions):
      return True
    if mandatory:
      raise RequiredExtensionUnavailableError(identifier, error_code=error_code)
    return False  # R-24.7-a/b: degrade gracefully to core behavior

  def ignore_unrecognized_identifiers(self, raw_extensions: Any) -> frozenset[str]:
    """Return the advertised identifiers this peer recognizes, ignoring the rest (R-24.7-g).

    A peer that encounters an unrecognized identifier in the other side's
    ``extensions`` map MUST ignore that entry and MUST NOT treat its presence as
    an error; it simply never enters the active set (R-24.7-g). This returns the
    recognized, validly-advertised subset (malformed ``null``/non-object entries
    are already excluded by S11's parsing), never raising for unknown keys.
    """
    advertised = advertised_extension_ids(raw_extensions)
    return frozenset(i for i in advertised if i in self._definitions)

  # -- internal ownership lookups --

  def _owning_definition_for_method(
    self, method: str
  ) -> ExtensionDefinition | None:
    """Return the registered extension that declares ``method``, or None."""
    for definition in self._definitions.values():
      if definition.declares_method(method):
        return definition
    return None

  def _owning_definition_for_meta_key(
    self, meta_key: str
  ) -> ExtensionDefinition | None:
    """Return the registered extension that declares ``meta_key``, or None."""
    for definition in self._definitions.values():
      if meta_key in definition.meta_keys:
        return definition
    return None

  def _owning_definition_for_field(
    self, field_name: str
  ) -> ExtensionDefinition | None:
    """Return the registered extension that declares object field ``field_name``, or None."""
    for definition in self._definitions.values():
      if definition.declares_object_field(field_name):
        return definition
    return None


# ---------------------------------------------------------------------------
# §24.6  Versioning, stability, and deprecation
# ---------------------------------------------------------------------------

#: The conventional key under which an extension expresses its version inside its
#: settings object (§24.6 example). Extensions are free to choose another marker;
#: this is the recommended default for :func:`extension_version`.
DEFAULT_VERSION_SETTING_KEY: str = "version"


def extension_version(
  settings: Any,
  *,
  version_key: str = DEFAULT_VERSION_SETTING_KEY,
) -> Any:
  """Read an extension's version from its negotiated settings object (R-24.6-a/b).

  An extension that requires version discrimination SHOULD express its version
  inside its settings object (e.g. a ``version`` field) so the version is
  discoverable through negotiation (R-24.6-a). Where it has one, the version MUST
  be obtainable from the negotiation map and a peer MUST NOT be required to infer
  it from out-of-band information (R-24.6-b). This reads that marker from the
  settings object the peer advertised — purely from the negotiation map — using
  S11's settings accessor that ignores undefined keys.

  Args:
    settings: the extension's settings object (an ``extensions`` map value).
    version_key: the settings key carrying the version (default ``"version"``).

  Returns:
    The advertised version value, or ``None`` when absent or settings is not an
    object (the extension declares no version through negotiation).
  """
  return extension_setting(settings, version_key, None)


def is_backward_compatible_evolution(
  old_identifier: str,
  new_identifier: str,
) -> bool:
  """Return True if two versions share one identifier (backward-compatible) (R-24.6-c).

  For backward-compatible evolution within a single identifier, an extension
  SHOULD add capability flags or version markers inside its settings object
  rather than minting a new identifier (R-24.6-c). Sharing the identifier is the
  signal that the change is backward-compatible: the two are the same negotiation
  entry distinguished only by settings.
  """
  return old_identifier == new_identifier


def requires_new_identifier(
  old_identifier: str,
  new_identifier: str,
) -> bool:
  """Return True if an incompatible change has been published under a new identifier (R-24.6-d).

  Where an incompatible change cannot be avoided, the changed extension SHOULD be
  published under a NEW extension identifier so the two remain distinct in the
  negotiation map (e.g. ``com.example/my-extension`` and
  ``com.example/my-extension-2``) and are negotiated separately (R-24.6-d). A
  distinct identifier is exactly that separation.
  """
  return old_identifier != new_identifier


# ---------------------------------------------------------------------------
# Re-exports from S11 for callers operating at the §24 surface layer
# ---------------------------------------------------------------------------
# These primitives are owned by S11 (``mcp_sdk_py.extensions``); S38 builds on
# them and re-exposes the ones its §24 callers most need, so a caller working at
# the extension-mechanism layer has a single import surface. The grammar and
# active-set semantics are NOT re-implemented here.

__all__ = [
  # classification & definition (§24.1, §24.5)
  "ExtensionClassification",
  "ExtensionDefinition",
  "ExtensionRegistry",
  # surface composition constants (§24.5)
  "CORE_RESULT_TYPES",
  "CORE_METHOD_NAMES",
  "DEFAULT_REJECTION_ERROR_CODE",
  # identifier reservation (§24.2-f)
  "assert_third_party_prefix_not_bare_reserved",
  # surface-element validation (§24.5)
  "derive_namespace",
  "is_namespaced_method",
  "validate_extension_method_string",
  "validate_extension_meta_key",
  "validate_extension_result_type",
  # sanctioned-surface conformance (§24.1-d)
  "is_sanctioned_surface_addition",
  "assert_surface_is_sanctioned",
  # versioning (§24.6)
  "DEFAULT_VERSION_SETTING_KEY",
  "extension_version",
  "is_backward_compatible_evolution",
  "requires_new_identifier",
  # exceptions
  "NonConformantExtensionError",
  "RequiredExtensionUnavailableError",
  # re-exported S11 surface (active set, errors, helpers)
  "ExtensionNotActiveError",
  "InvalidExtensionIdentifierError",
  "MandatoryExtensionUnavailableError",
  "active_extensions",
  "advertised_extension_ids",
  "is_extension_active",
]
