"""Stateless Per-Request Model & Cross-Call Continuity — S06.

Every request is self-contained and processed independently. No state is
inferred from earlier requests or connection identity. Cross-request continuity
uses explicit, server-minted, opaque continuation identifiers that the client
echoes back verbatim.

Spec: §4.4–§4.7
Depends on: S05
"""

from __future__ import annotations

from typing import Any

from mcp_sdk_py.meta_object import REQUIRED_CLIENT_REQUEST_KEYS


# ---------------------------------------------------------------------------
# §4.6  Methods whose results MUST NOT vary by connection identity  [R-4.6-a]
# ---------------------------------------------------------------------------

#: Enumeration methods whose results are eligible to be identical for identical
#: parameters and _meta regardless of connection, process, or server instance
#: (R-4.6-a, R-4.6-b). Any variation MUST derive only from explicit request
#: inputs — parameters, pagination cursors, or per-request authenticated identity
#: (R-4.6-c).
LISTING_METHODS: frozenset[str] = frozenset({
  "tools/list",
  "prompts/list",
  "resources/list",
  "resources/templates/list",
})


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class StatelessnessViolationError(Exception):
  """Raised when logic would violate the per-request stateless processing model.

  Covers:
  - Inferring state from an earlier request (R-4.4-a)
  - Requiring a prior handshake/request before processing (R-4.4-b)
  - Inferring identity/capabilities/version from earlier requests (R-4.4-c)
  - Persisting per-connection conversational state (R-4.4-d)
  - Using connection/process identity as conversational continuity (R-4.4-f)
  """


class InvalidContinuationIdError(Exception):
  """Raised when a value cannot serve as a continuation identifier.

  A continuation identifier is any non-None JSON value minted by a server
  (R-4.5-b). None signals absence, not a valid id.
  """


# ---------------------------------------------------------------------------
# §4.5  Cross-call continuity via explicit identifiers  [R-4.5-a–d]
# ---------------------------------------------------------------------------

def is_valid_continuation_id(value: Any) -> bool:
  """Return True if value may serve as an opaque continuation identifier.

  Any non-None JSON scalar or structured value is valid. None signals
  absence of a continuation id, not the id itself (R-4.5-b).
  """
  return value is not None


def validate_continuation_id(value: Any) -> Any:
  """Validate value as a continuation identifier; raise if None.

  The client MUST treat continuation identifiers as opaque — MUST NOT parse,
  interpret, modify, or construct them — and MUST pass them back verbatim
  on later requests (R-4.5-c).

  Raises:
    InvalidContinuationIdError: value is None.
  """
  if value is None:
    raise InvalidContinuationIdError(
      "None is not a valid continuation identifier; identifiers are server-minted, "
      "non-null JSON values (R-4.5-b)"
    )
  return value


def continuation_ids_are_equal(a: Any, b: Any) -> bool:
  """Return True if two continuation identifiers are identical (opaque comparison).

  Clients MUST pass identifiers back verbatim (R-4.5-c). Identity is decided
  by exact Python equality; no semantic interpretation is applied.
  """
  return a == b


# ---------------------------------------------------------------------------
# §4.4  Self-describing request validation  [R-4.4-b, R-4.4-c]
# ---------------------------------------------------------------------------

def assert_request_is_self_describing(
  meta: dict[str, Any],
  *,
  required_keys: frozenset[str] | None = None,
) -> None:
  """Assert a request carries all identity/capability context in its own _meta.

  A server MUST NOT require prior requests (R-4.4-b) and MUST derive client
  identity, capabilities, and protocol version solely from the current
  request's _meta (R-4.4-c). Use this to verify a request is self-describing
  before processing it.

  Args:
    meta: The _meta dict from the current request's params.
    required_keys: Keys that must be present. Defaults to the three
      protocol-defined per-request keys (REQUIRED_CLIENT_REQUEST_KEYS, S05).

  Raises:
    StatelessnessViolationError: Any required key is absent from meta.
  """
  keys = required_keys if required_keys is not None else REQUIRED_CLIENT_REQUEST_KEYS
  missing = [k for k in sorted(keys) if k not in meta]
  if missing:
    raise StatelessnessViolationError(
      f"Request is not self-describing: missing required _meta keys {missing!r}. "
      f"A server MUST derive identity/capabilities from the current request only "
      f"(R-4.4-b, R-4.4-c)"
    )


# ---------------------------------------------------------------------------
# §4.4  Connection identity guard  [R-4.4-d, R-4.4-f]
# ---------------------------------------------------------------------------

def assert_not_connection_scoped(
  connection_id: Any,
  request_id: Any,
) -> None:
  """Always raise — call-site marker that connection identity must never reach here.

  A server MUST NOT treat connection/process identity as conversational
  continuity (R-4.4-f) and MUST NOT depend on per-connection state (R-4.4-d).
  Drop this call into any code path that mistakenly routes connection_id into
  request processing; it acts as a defensive assertion.

  Raises:
    StatelessnessViolationError: unconditionally — connection_id is never
      a legitimate argument to request processing.
  """
  raise StatelessnessViolationError(
    f"Request {request_id!r}: processing MUST NOT use connection identity "
    f"{connection_id!r} as conversational context. Use an explicit "
    f"continuation identifier instead (R-4.4-d, R-4.4-f, R-4.5-a)"
  )


# ---------------------------------------------------------------------------
# §4.6  List-result connection-independence helpers  [R-4.6-a–c]
# ---------------------------------------------------------------------------

def is_listing_method(method: str) -> bool:
  """Return True if method returns an enumeration that MUST NOT vary by connection.

  Results from listing methods are eligible to be identical for identical
  parameters and _meta regardless of which connection, process, or server
  instance handled the request (R-4.6-a, R-4.6-b). Any result variation
  MUST derive only from explicit request inputs (R-4.6-c).
  """
  return method in LISTING_METHODS
