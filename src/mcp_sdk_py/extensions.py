"""The Extensions Map & Forward Compatibility — S11.

Delivers the ``extensions`` map that lives inside both ``ClientCapabilities``
and ``ServerCapabilities`` (S10) and the forward-compatibility rules that govern
how peers handle capability fields, extension keys, and settings they do not
recognize.

This story owns three concerns (§6.5–§6.7):

Extension identifier grammar (§6.5):
  - An identifier is ``prefix/name``: a REQUIRED dot-separated prefix, a single
    slash, then a (possibly empty) name (R-6.5-a/e/f).
  - Each prefix label starts with a letter and ends with a letter or digit;
    interior characters may be letters, digits, or hyphens (R-6.5-b/c).
  - Reverse-DNS notation is RECOMMENDED (R-6.5-d).
  - A prefix whose *second label* is ``modelcontextprotocol`` or ``mcp`` is
    reserved for official MCP use; third parties MUST NOT use it (R-6.5-g).

Settings values & activation (§6.5):
  - ``{}`` means "enabled, no settings"; it is a valid enabling declaration,
    not absence (R-6.5-h).
  - A key MUST NOT map to ``null``; a receiver treats a ``null`` value as
    malformed and ignores the entry (R-6.5-i/j).
  - Settings keys an extension does not define are ignored (R-6.5-k).
  - An extension is active only in the intersection of both peers' advertised
    maps; a peer MUST NOT exercise behavior the other did not advertise
    (R-6.5-l). Extensions are disabled by default (R-6.5-m). One-sided support
    falls back to core behavior, or rejects only if mandatory (R-6.5-n).

Forward compatibility (§6.6):
  - Unknown capability fields, unknown extension/``experimental`` keys, and
    unknown settings keys are tolerated and ignored, never errors; absence of
    an un-understood field implies nothing about understood support
    (R-6.6-a..g).

The capability declaration objects (``ClientCapabilities`` /
``ServerCapabilities``) and the per-request gating algorithm are owned by S10
(``mcp_sdk_py.capabilities``); this module operates on the ``extensions`` field
of those objects and reuses ``RESERVED_SECOND_LABELS`` from S02
(``mcp_sdk_py.json_value``).

Spec: §6.5–§6.7
Depends on: S10 (capability objects), S02 (reserved-label grammar)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from mcp_sdk_py.foundations import ConformanceError
from mcp_sdk_py.json_value import RESERVED_SECOND_LABELS


# ---------------------------------------------------------------------------
# §6.5  Extension identifier grammar  [R-6.5-a..g]
# ---------------------------------------------------------------------------
#
# Grammar (per §6.5):
#   label   = letter (interior* (letter | digit))?      ; interior = letter|digit|hyphen
#   prefix  = label ('.' label)*                          ; REQUIRED, one or more labels
#   name    = '' | alnum (interior* alnum)?               ; interior = alnum | - | _ | .
#   id      = prefix '/' name
#
# A label starts with a letter and ends with a letter or digit; a single-char
# label (e.g. ``a``) is valid because its only character is both start and end
# (R-6.5-b). Interior characters may add hyphens (R-6.5-c).

#: One prefix label: starts with a letter, ends with a letter/digit, interior
#: may include hyphens. A lone letter is a valid label (R-6.5-b/c).
_LABEL_RE = re.compile(r"^[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?$")

#: The full prefix: one or more dot-separated labels (R-6.5-a/b/c).
_PREFIX_RE = re.compile(
  r"^[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
  r"(?:\.[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*$"
)

#: The name segment: empty, or begins/ends alphanumeric with interior
#: hyphens/underscores/dots/alphanumerics (R-6.5-e/f).
_NAME_RE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)?$")


class InvalidExtensionIdentifierError(ConformanceError):
  """An extension identifier does not conform to the §6.5 grammar.

  Raised by :func:`validate_extension_identifier` (a sender-side check) when an
  identifier lacks a prefix, has a malformed label or name, or uses a reserved
  prefix from a third party (R-6.5-a/b/e/g). Receivers MUST NOT raise this for
  identifiers they merely fail to recognize — those are ignored under the
  forward-compatibility rules (R-6.6-d).

  Attributes:
    identifier: the offending extension identifier string.
  """

  def __init__(self, identifier: str, reason: str) -> None:
    super().__init__(
      f"Invalid extension identifier {identifier!r}: {reason}"
    )
    self.identifier: str = identifier


def split_extension_identifier(identifier: str) -> tuple[str | None, str]:
  """Split an identifier into ``(prefix, name)`` at its first slash.

  Returns ``(None, identifier)`` when no slash is present, signalling a missing
  prefix (the prefix is REQUIRED, so a slash-less identifier is malformed,
  R-6.5-a). The split is on the FIRST ``/`` so that a name segment never
  contains a slash; the prefix grammar forbids slashes anyway.

  Args:
    identifier: the candidate extension identifier (the ``extensions`` map key).

  Returns:
    ``(prefix, name)`` where ``prefix`` is the text before the first slash (or
    ``None`` if there is no slash) and ``name`` is the remainder.
  """
  slash = identifier.find("/")
  if slash == -1:
    return None, identifier
  return identifier[:slash], identifier[slash + 1:]


def is_valid_extension_label(label: str) -> bool:
  """Return True if ``label`` is a well-formed prefix label (R-6.5-b/c).

  A label MUST start with a letter and end with a letter or digit; interior
  characters MAY be letters, digits, or hyphens. A single letter qualifies.
  """
  return bool(_LABEL_RE.match(label))


def is_valid_extension_prefix(prefix: str) -> bool:
  """Return True if ``prefix`` is one or more dot-separated valid labels (R-6.5-a/b/c).

  An empty string, a leading/trailing dot, or a malformed label all fail. The
  prefix is REQUIRED, so the empty string is never valid (R-6.5-a).
  """
  return bool(_PREFIX_RE.match(prefix))


def is_valid_extension_name(name: str) -> bool:
  """Return True if ``name`` conforms to the §6.5 name grammar (R-6.5-e/f).

  An empty name is permitted (R-6.5-e). A non-empty name MUST begin and end
  with an alphanumeric character and MAY contain hyphens, underscores, dots,
  and alphanumerics in between (R-6.5-f).
  """
  return bool(_NAME_RE.match(name))


def is_reserved_extension_prefix(prefix: str) -> bool:
  """Return True if ``prefix``'s *second label* is reserved for official MCP use (R-6.5-g).

  Any prefix whose second dot-separated label is ``modelcontextprotocol`` or
  ``mcp`` is reserved (e.g. ``io.modelcontextprotocol``, ``dev.mcp``,
  ``org.modelcontextprotocol.api``, ``com.mcp``). A prefix is NOT reserved
  merely because those tokens appear as some other label — ``com.example.mcp``
  is not reserved because its second label is ``example`` (R-6.5-g). A
  single-label prefix has no second label and is therefore never reserved.
  """
  labels = prefix.split(".")
  return len(labels) >= 2 and labels[1] in RESERVED_SECOND_LABELS


def is_well_formed_extension_identifier(identifier: str) -> bool:
  """Return True if ``identifier`` is syntactically well-formed (R-6.5-a/b/c/e/f).

  Checks the grammar only — a REQUIRED prefix of valid labels, a single slash,
  and a valid (possibly empty) name. Does NOT check the reserved-prefix
  prohibition (R-6.5-g): a reserved identifier such as
  ``io.modelcontextprotocol/tasks`` is well-formed for the protocol's own use,
  but third parties MUST NOT mint it — use
  :func:`validate_extension_identifier` for the sender-side prohibition.
  """
  prefix, name = split_extension_identifier(identifier)
  if prefix is None:
    return False
  return is_valid_extension_prefix(prefix) and is_valid_extension_name(name)


def validate_extension_identifier(
  identifier: str,
  *,
  allow_reserved: bool = False,
) -> None:
  """Validate an extension identifier a third party intends to mint (R-6.5-a/b/e/g).

  This is a SENDER-SIDE check. It enforces, in order:
    1. A prefix is present — a slash-less identifier (e.g. ``/tasks``) is
       malformed because the prefix is REQUIRED (R-6.5-a).
    2. The prefix is grammatically valid: dot-separated labels, each starting
       with a letter and ending with a letter or digit (R-6.5-b/c).
    3. Unless ``allow_reserved`` is set, the prefix is not reserved — a third
       party MUST NOT define an extension under a prefix whose second label is
       ``modelcontextprotocol`` or ``mcp`` (R-6.5-g).
    4. The name is grammatically valid: empty, or begins/ends alphanumeric with
       interior hyphens/underscores/dots/alphanumerics (R-6.5-e/f).

  Receivers MUST NOT use this to reject identifiers they fail to recognize;
  unrecognized identifiers are ignored under forward compatibility (R-6.6-d).

  Args:
    identifier: the candidate ``extensions`` map key.
    allow_reserved: when True, skip the reserved-prefix prohibition — for use by
      the protocol itself minting official ``io.modelcontextprotocol/*`` ids.

  Raises:
    InvalidExtensionIdentifierError: any grammar or reservation rule is violated.
  """
  prefix, name = split_extension_identifier(identifier)

  if prefix is None:
    raise InvalidExtensionIdentifierError(
      identifier,
      "a prefix is REQUIRED (e.g. 'com.example/name'); identifiers without a "
      "'/' separator are malformed (R-6.5-a)",
    )
  if not is_valid_extension_prefix(prefix):
    raise InvalidExtensionIdentifierError(
      identifier,
      f"prefix {prefix!r} is malformed; each dot-separated label must start with "
      f"a letter and end with a letter or digit, interior letters/digits/hyphens "
      f"(R-6.5-b, R-6.5-c)",
    )
  if not allow_reserved and is_reserved_extension_prefix(prefix):
    raise InvalidExtensionIdentifierError(
      identifier,
      f"prefix {prefix!r} is reserved for official MCP use; its second label is "
      f"one of {sorted(RESERVED_SECOND_LABELS)} and third parties MUST NOT define "
      f"extensions under it (R-6.5-g)",
    )
  if not is_valid_extension_name(name):
    raise InvalidExtensionIdentifierError(
      identifier,
      f"name {name!r} is malformed; unless empty it must begin and end with an "
      f"alphanumeric and may contain hyphens, underscores, dots, and "
      f"alphanumerics in between (R-6.5-e, R-6.5-f)",
    )


# ---------------------------------------------------------------------------
# §6.5  Settings values & advertised-set parsing  [R-6.5-h..k, R-6.6-d/e]
# ---------------------------------------------------------------------------

def is_valid_settings_value(value: Any) -> bool:
  """Return True if ``value`` is a valid extension settings object (R-6.5-h/i).

  A settings value MUST be a JSON object (``dict``). The empty object ``{}`` is
  valid and means "enabled, no settings" (R-6.5-h). ``null`` (Python ``None``)
  is NOT valid: a key MUST NOT map to ``null`` (R-6.5-i). Arrays, strings, and
  scalars are likewise not settings objects.
  """
  return isinstance(value, dict)


def parse_extensions_map(raw: Any) -> dict[str, dict[str, Any]]:
  """Parse a raw ``extensions`` map into the entries a receiver treats as advertised.

  Applies the receiver-side normalization rules of §6.5/§6.6:

  - A ``null``-valued entry is malformed and is dropped, so the extension is
    treated as not advertised by that peer (R-6.5-j).
  - Any entry whose value is not a JSON object (array/scalar) is likewise
    malformed and dropped — only object-valued settings are valid (R-6.5-i).
  - An empty object ``{}`` is retained: it is a valid enabling declaration, not
    absence (R-6.5-h).
  - Identifiers a receiver does not recognize are NOT filtered here; recognition
    is the caller's concern. Unrecognized keys are simply ignored when the
    caller computes the intersection (R-6.6-d), so they are returned as-is and
    naturally fall outside any recognized-identifier set.

  The result is a fresh mapping; the settings objects are the original objects
  (callers ignore undefined settings keys per R-6.5-k / R-6.6-e rather than
  stripping them, so older receivers keep working).

  Args:
    raw: the ``extensions`` field value from a capability object. ``None`` (the
      field absent) and a non-object value both yield an empty map.

  Returns:
    A mapping of identifier → settings object containing only the well-formed,
    object-valued entries.
  """
  if not isinstance(raw, dict):
    return {}
  return {
    identifier: value
    for identifier, value in raw.items()
    if is_valid_settings_value(value)
  }


def advertised_extension_ids(raw: Any) -> frozenset[str]:
  """Return the set of extension identifiers a peer has validly advertised.

  Equivalent to the keys of :func:`parse_extensions_map`: identifiers mapped to
  a ``null`` or non-object value are excluded because such entries are malformed
  and treated as not advertised (R-6.5-i/j). An entry mapped to ``{}`` IS
  included — it is a valid enabling declaration (R-6.5-h).
  """
  return frozenset(parse_extensions_map(raw))


# ---------------------------------------------------------------------------
# §6.5  Activation by intersection  [R-6.5-l/m]
# ---------------------------------------------------------------------------

def active_extensions(
  client_extensions: Any,
  server_extensions: Any,
) -> frozenset[str]:
  """Return the identifiers active for an interaction: the intersection of both peers.

  An extension is active only when it appears in BOTH peers' advertised
  ``extensions`` maps (R-6.5-l). Malformed entries (``null`` or non-object
  values) on either side are excluded before intersecting, so they never
  activate (R-6.5-i/j). Because extensions are disabled by default, a peer that
  has not advertised an identifier contributes nothing to the intersection
  (R-6.5-m).

  Args:
    client_extensions: the client's ``extensions`` field value (or ``None``).
    server_extensions: the server's ``extensions`` field value (or ``None``).

  Returns:
    The frozenset of identifiers present in both advertised sets.
  """
  return advertised_extension_ids(client_extensions) & advertised_extension_ids(
    server_extensions
  )


def is_extension_active(
  identifier: str,
  client_extensions: Any,
  server_extensions: Any,
) -> bool:
  """Return True if ``identifier`` is active (advertised by BOTH peers) (R-6.5-l).

  A peer MUST NOT exercise an extension's behavior unless this returns True for
  the relevant identifier; outside the intersection the extension is inactive
  and the peer falls back to core behavior (or rejects if mandatory, R-6.5-n).
  """
  return identifier in active_extensions(client_extensions, server_extensions)


def assert_extension_active(
  identifier: str,
  client_extensions: Any,
  server_extensions: Any,
) -> None:
  """Raise if ``identifier`` is not active, guarding against unilateral use (R-6.5-l).

  A peer MUST NOT exercise extension behavior with a peer that did not advertise
  the same identifier. Call this before invoking any extension-contributed
  method, notification, or behavior.

  Raises:
    ExtensionNotActiveError: ``identifier`` is not in the intersection of both
      peers' advertised maps.
  """
  if not is_extension_active(identifier, client_extensions, server_extensions):
    raise ExtensionNotActiveError(identifier)


class ExtensionNotActiveError(ConformanceError):
  """A peer attempted to exercise an extension not active in the intersection (R-6.5-l).

  An extension is active only when BOTH peers advertise the same identifier. A
  peer MUST NOT exercise extension behavior unilaterally; doing so is a
  conformance violation guarded by :func:`assert_extension_active`.

  Attributes:
    identifier: the extension identifier that was not active.
  """

  def __init__(self, identifier: str) -> None:
    super().__init__(
      f"Extension {identifier!r} is not active for this interaction: an "
      f"extension is active only when BOTH peers advertise it, and a peer MUST "
      f"NOT exercise extension behavior the other did not advertise (R-6.5-l)"
    )
    self.identifier: str = identifier


# ---------------------------------------------------------------------------
# §6.5 / §6.6  One-sided support: fallback or reject-if-mandatory  [R-6.5-n]
# ---------------------------------------------------------------------------

class MandatoryExtensionUnavailableError(ConformanceError):
  """A mandatory extension is not active, so the operation cannot proceed (R-6.5-n).

  When one peer advertises an extension the other does not, the supporting peer
  MUST either fall back to core behavior or — only if the extension is mandatory
  for the operation — reject the request with an appropriate error. This
  exception is that rejection for the mandatory branch.

  Attributes:
    identifier: the mandatory extension identifier that was not active.
  """

  def __init__(self, identifier: str) -> None:
    super().__init__(
      f"Operation requires extension {identifier!r}, which the other peer did "
      f"not advertise; the extension is mandatory here, so the request is "
      f"rejected rather than falling back to core behavior (R-6.5-n)"
    )
    self.identifier: str = identifier


def resolve_one_sided_extension(
  identifier: str,
  client_extensions: Any,
  server_extensions: Any,
  *,
  mandatory: bool = False,
) -> bool:
  """Decide how to handle an extension when only one peer may support it (R-6.5-n).

  Implements the one-sided-support rule: when the extension is active (both
  peers advertise it) the caller may use it; otherwise the caller MUST fall back
  to core behavior, unless the extension is mandatory for the operation, in
  which case the request is rejected.

  Args:
    identifier: the extension under consideration.
    client_extensions: the client's ``extensions`` field value (or ``None``).
    server_extensions: the server's ``extensions`` field value (or ``None``).
    mandatory: whether the operation cannot proceed without the extension.

  Returns:
    True if the extension is active and may be exercised; False if the caller
    MUST fall back to core protocol behavior (R-6.5-n, fallback branch).

  Raises:
    MandatoryExtensionUnavailableError: the extension is mandatory yet not
      active (R-6.5-n, reject branch).
  """
  if is_extension_active(identifier, client_extensions, server_extensions):
    return True
  if mandatory:
    raise MandatoryExtensionUnavailableError(identifier)
  # R-6.5-n: not mandatory → fall back to core behavior (no error).
  return False


# ---------------------------------------------------------------------------
# §6.5 / §6.6  Settings access ignoring unknown keys  [R-6.5-k, R-6.6-e]
# ---------------------------------------------------------------------------

def extension_setting(
  settings: Any,
  key: str,
  default: Any = None,
) -> Any:
  """Read one defined setting from an extension's settings object (R-6.5-k, R-6.6-e).

  Reads only the requested (defined) key; any other keys — including ones a
  newer extension version added that this receiver does not recognize — are
  simply not consulted, so they are ignored without error (R-6.5-k, R-6.6-e). A
  ``null``/non-object settings value yields the default (such a value is itself
  malformed under R-6.5-i and carries no settings).

  Args:
    settings: an extension's settings object (the ``extensions`` map value).
    key: the setting name the extension defines.
    default: value returned when the key is absent or settings is not an object.

  Returns:
    The setting's value, or ``default`` when absent.
  """
  if not isinstance(settings, dict):
    return default
  return settings.get(key, default)


def select_known_settings(
  settings: Any,
  known_keys: frozenset[str],
) -> dict[str, Any]:
  """Return only the settings keys an extension defines, ignoring the rest (R-6.5-k, R-6.6-e).

  Receivers of an extension MUST ignore settings keys the extension does not
  define; this allows extensions to add settings over time without breaking
  older receivers (R-6.5-k, R-6.6-e). Unknown keys are dropped from the result
  (not treated as errors). A non-object settings value yields an empty mapping.

  Args:
    settings: the extension's settings object.
    known_keys: the settings keys the extension version in use defines.

  Returns:
    A new mapping containing only the keys present in both ``settings`` and
    ``known_keys``.
  """
  if not isinstance(settings, dict):
    return {}
  return {k: v for k, v in settings.items() if k in known_keys}


# ---------------------------------------------------------------------------
# §6.6  Forward compatibility for capability objects  [R-6.6-a..g]
# ---------------------------------------------------------------------------

#: The capability fields a current receiver recognizes on a ``ClientCapabilities``
#: object (S10, §6.2). Any other field is tolerated and ignored (R-6.6-b/c).
KNOWN_CLIENT_CAPABILITY_FIELDS: frozenset[str] = frozenset({
  "experimental",
  "elicitation",
  "roots",
  "sampling",
  "extensions",
})

#: The capability fields a current receiver recognizes on a ``ServerCapabilities``
#: object (S10, §6.3). Any other field is tolerated and ignored (R-6.6-b/c).
KNOWN_SERVER_CAPABILITY_FIELDS: frozenset[str] = frozenset({
  "experimental",
  "completions",
  "prompts",
  "resources",
  "tools",
  "logging",
  "extensions",
})


def unknown_capability_fields(
  capabilities: Any,
  known_fields: frozenset[str],
) -> frozenset[str]:
  """Return the capability fields a receiver does not recognize (R-6.6-a/b).

  Used to demonstrate that a receiver tolerates and identifies unknown fields
  without failing; the receiver MUST ignore them rather than reject the object
  or the message carrying it (R-6.6-b/c). A non-object input yields the empty
  set (there are no fields to inspect).

  Args:
    capabilities: a raw ``ClientCapabilities``/``ServerCapabilities`` object.
    known_fields: the fields this receiver recognizes (e.g.
      :data:`KNOWN_CLIENT_CAPABILITY_FIELDS`).

  Returns:
    The set of keys present in ``capabilities`` but absent from ``known_fields``.
  """
  if not isinstance(capabilities, dict):
    return frozenset()
  return frozenset(k for k in capabilities if k not in known_fields)


def ignore_unknown_capability_fields(
  capabilities: Any,
  known_fields: frozenset[str],
) -> dict[str, Any]:
  """Return only the recognized capability fields, ignoring unknown ones (R-6.6-b/f).

  A receiver MUST ignore any capability field it does not recognize and MUST NOT
  reject the object because of it; unknown fields are not errors (R-6.6-b/c/f).
  This returns the recognized subset so a receiver can process known fields
  while the unknown ones are dropped (ignored).

  Note:
    This never raises for an unknown field — that absence of error is the whole
    point of R-6.6-c/f. A non-object input yields an empty mapping.
  """
  if not isinstance(capabilities, dict):
    return {}
  return {k: v for k, v in capabilities.items() if k in known_fields}


def recognized_extensions(
  raw: Any,
  recognized_ids: frozenset[str],
) -> dict[str, dict[str, Any]]:
  """Return only the recognized, well-formed entries of an ``extensions`` map (R-6.6-d).

  A receiver MUST ignore any key in the ``extensions`` map (and any key in the
  ``experimental`` map) whose identifier it does not recognize, treating such an
  entry as though the extension is simply not active in the intersection
  (R-6.6-d). Malformed ``null``/non-object entries are also excluded
  (R-6.5-i/j). The same helper applies to the ``experimental`` map, whose
  unknown keys are governed by the same ignore-unknown rule.

  Args:
    raw: the ``extensions`` (or ``experimental``) field value.
    recognized_ids: the identifiers this receiver recognizes.

  Returns:
    A mapping of identifier → settings for the recognized, well-formed entries
    only. Unrecognized identifiers are omitted (ignored), never raised.
  """
  parsed = parse_extensions_map(raw)
  return {
    identifier: settings
    for identifier, settings in parsed.items()
    if identifier in recognized_ids
  }


def is_forward_compatible_error(_exc: BaseException) -> bool:
  """Return False — unknown capabilities/extensions/settings are never errors (R-6.6-f).

  Provided as an explicit, self-documenting assertion of R-6.6-f: encountering
  an unknown capability, extension, or settings key MUST NOT be treated as an
  error. The forward-compatibility helpers in this module never raise for such
  inputs; this predicate exists so call sites and tests can state that invariant
  directly. It always returns False because there is no forward-compatibility
  condition that legitimately produces an error.
  """
  return False


@dataclass(frozen=True)
class CapabilityFieldSupport:
  """A receiver's reasoning about support, isolated from fields it cannot understand.

  Encapsulates R-6.6-g: a peer MUST NOT assume that the absence of a field it
  does not understand implies non-support of anything it *does* understand.
  Support for a recognized field is determined solely from that field's presence
  (S10 presence-means-supported), independent of any unknown field's absence.

  Attributes:
    field_name: the recognized capability field being reasoned about.
  """

  field_name: str

  def supported(self, capabilities: Any) -> bool:
    """Return whether ``field_name`` is supported, ignoring unknown fields (R-6.6-g).

    Support is decided purely by the presence of ``field_name`` in
    ``capabilities``. The presence or absence of any field this receiver does
    not understand is irrelevant and MUST NOT change the conclusion (R-6.6-g).
    """
    return isinstance(capabilities, dict) and self.field_name in capabilities
