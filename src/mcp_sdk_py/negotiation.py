"""Revision Selection & Negotiation Errors — S09.

The decision logic and error surface that let a client and server agree on a
single protocol revision — or fail loudly and cleanly when they cannot.

Public surface:

Revision selection (§5.4):
  - select_revision(): highest mutually supported revision by client preference
    order; returns None on empty intersection (no fabrication, R-5.4-c).
  - select_revision_or_raise(): same, raising IncompatibleRevisionsError on
    empty intersection so callers surface an actionable error (R-5.4-d).
  - IncompatibleRevisionsError: the actionable incompatibility surfaced when no
    mutually supported revision exists (R-5.4-d, R-5.5-j).

UnsupportedProtocolVersion -32004 (§5.5):
  - build_unsupported_protocol_version_error() / _response(): the -32004 error
    with mandatory data {supported (non-empty), requested}.
  - parse_unsupported_protocol_version_error(): client-side extraction.

MissingRequiredClientCapability -32003 (§5.6):
  - build_missing_required_client_capability_error() / _response(): the -32003
    error with mandatory data {requiredCapabilities}.
  - parse_missing_required_client_capability_error(): client-side extraction.
  - can_satisfy_required_capabilities() / retry_meta_with_capabilities():
    the client's optional retry-with-capabilities reaction (R-5.6-i).

HTTP mapping:
  - http_status_for_negotiation_error(): both -32004 and -32003 → 400 (R-5.5-b, R-5.6-d).

Client retry loop:
  - RevisionNegotiator: re-selects on -32004, never retries indefinitely
    (R-5.5-h/i), surfaces incompatibility when exhausted (R-5.5-j).

Backward-compatibility probe (§5.7):
  - build_probe_request(): server/discover as the opening request (R-5.7-b).
  - interpret_probe_response() / ProbeOutcome / ProbeResult: success vs.
    recognized -32004 vs. unrecognized → not-speaking-this-revision (R-5.7-c).
  - ProtocolSupportCache: per-endpoint determination, persistable, re-probed
    when a cached assumption proves wrong (R-5.7-e/f).
  - build_unspeakable_opening_error(): a server that only speaks this revision
    family names its supported revisions in the error (R-5.7-g).

Spec: §5.4–§5.7
Depends on: S08 (discovery), S07 (revision format/keys), S10 (ClientCapabilities)
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from mcp_sdk_py.capabilities import ClientCapabilities
from mcp_sdk_py.discovery import DISCOVER_METHOD_NAME, validate_discover_result
from mcp_sdk_py.jsonrpc import JSONRPCErrorResponse, JSONRPCRequest, RequestId
from mcp_sdk_py.meta_object import KEY_CLIENT_CAPABILITIES, KEY_PROTOCOL_VERSION
from mcp_sdk_py.result_error import ErrorObject


# ---------------------------------------------------------------------------
# Error codes & HTTP status (§5.5, §5.6)
# ---------------------------------------------------------------------------

#: The UnsupportedProtocolVersion error code (R-5.5-a/d).
UNSUPPORTED_PROTOCOL_VERSION_CODE: int = -32004

#: The MissingRequiredClientCapability error code (R-5.6-c/f).
MISSING_REQUIRED_CLIENT_CAPABILITY_CODE: int = -32003

#: HTTP status both negotiation errors ride on (R-5.5-b, R-5.6-d).
HTTP_BAD_REQUEST: int = 400

#: The negotiation error codes that map to HTTP 400 Bad Request.
_NEGOTIATION_ERROR_CODES: frozenset[int] = frozenset(
  {UNSUPPORTED_PROTOCOL_VERSION_CODE, MISSING_REQUIRED_CLIENT_CAPABILITY_CODE}
)


def http_status_for_negotiation_error(code: int) -> int:
  """Return the HTTP status for a negotiation error code (R-5.5-b, R-5.6-d).

  Both -32004 and -32003 are returned with HTTP 400 Bad Request on the HTTP
  transport.

  Raises:
    ValueError: code is not a negotiation error code owned by this story.
  """
  if code not in _NEGOTIATION_ERROR_CODES:
    raise ValueError(
      f"{code} is not a negotiation error code; this mapping covers only "
      f"-32004 and -32003 (R-5.5-b, R-5.6-d)"
    )
  return HTTP_BAD_REQUEST


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class IncompatibleRevisionsError(Exception):
  """No mutually supported protocol revision exists (R-5.4-c/d, R-5.5-i/j).

  Surfaced to the user or caller as an actionable incompatibility. The client
  MUST NOT fabricate a revision (R-5.4-c) and MUST NOT retry indefinitely
  (R-5.5-i); raising this terminates the negotiation loop cleanly.

  Attributes:
    client_revisions: the client's supported/preferred revisions.
    server_revisions: the server's advertised revisions.
  """

  def __init__(
    self,
    client_revisions: Sequence[str],
    server_revisions: Iterable[str],
  ) -> None:
    self.client_revisions: list[str] = list(client_revisions)
    self.server_revisions: list[str] = list(server_revisions)
    super().__init__(
      f"No mutually supported protocol revision: client supports "
      f"{self.client_revisions!r}, server supports {self.server_revisions!r}. "
      f"The client MUST NOT fabricate a revision (R-5.4-c) and surfaces this "
      f"incompatibility instead of retrying indefinitely (R-5.4-d, R-5.5-i/j)."
    )


# ---------------------------------------------------------------------------
# §5.4  Revision selection (client)
# ---------------------------------------------------------------------------

def select_revision(
  client_preferences: Sequence[str],
  server_supported: Iterable[str],
) -> str | None:
  """Select the highest mutually supported revision by client preference (R-5.4-b).

  "Highest" is the first revision in the client's own ordered preference list
  that also appears in the server's advertised set. Matching is exact (§5.1) —
  never lexical or chronological. On an empty intersection this returns None and
  does NOT fabricate a revision (R-5.4-c).

  Args:
    client_preferences: the client's supported revisions, most-preferred first.
    server_supported: the revisions the server advertises (order irrelevant).

  Returns:
    The selected revision string, or None when the intersection is empty.
  """
  server_set = set(server_supported)
  for revision in client_preferences:
    if revision in server_set:
      return revision
  return None


def select_revision_or_raise(
  client_preferences: Sequence[str],
  server_supported: Iterable[str],
) -> str:
  """Select the highest mutually supported revision, or raise (R-5.4-b/c/d).

  Like select_revision() but raises IncompatibleRevisionsError on an empty
  intersection so the caller can surface an actionable incompatibility error to
  the user (R-5.4-d) rather than silently failing or fabricating a revision.

  Raises:
    IncompatibleRevisionsError: no mutually supported revision exists.
  """
  server_supported = list(server_supported)
  selected = select_revision(client_preferences, server_supported)
  if selected is None:
    raise IncompatibleRevisionsError(client_preferences, server_supported)
  return selected


# ---------------------------------------------------------------------------
# §5.5  UnsupportedProtocolVersion error (-32004)
# ---------------------------------------------------------------------------

def build_unsupported_protocol_version_error(
  supported: Sequence[str],
  requested: str,
  *,
  message: str = "Unsupported protocol version",
) -> ErrorObject:
  """Build the -32004 UnsupportedProtocolVersion error object (§5.5).

  The ``data`` member is present and contains exactly ``supported`` and
  ``requested`` (R-5.5-c). ``supported`` MUST be a non-empty array of revision
  identifiers — the authoritative set the client re-selects from (R-5.5-f).

  Args:
    supported: the non-empty list of revisions the server supports.
    requested: the revision the rejected request declared.
    message: human-readable description (exact text not normative, R-5.5-e).

  Returns:
    An ErrorObject with code -32004 and data {supported, requested}.

  Raises:
    ValueError: supported is empty (R-5.5-f) or contains non-strings.
    TypeError: requested is not a string (R-5.5-g).
  """
  supported_list = list(supported)
  if not supported_list:
    raise ValueError(
      "data.supported MUST be a non-empty array of revision identifiers (R-5.5-f)"
    )
  for v in supported_list:
    if not isinstance(v, str):
      raise ValueError(
        f"data.supported entries MUST be revision strings; got {type(v).__name__} (R-5.5-f)"
      )
  if not isinstance(requested, str):
    raise TypeError(
      f"data.requested MUST be the requested revision string; got {type(requested).__name__} (R-5.5-g)"
    )
  return ErrorObject(
    code=UNSUPPORTED_PROTOCOL_VERSION_CODE,
    message=message,
    data={"supported": supported_list, "requested": requested},
  )


def build_unsupported_protocol_version_response(
  request_id: RequestId,
  supported: Sequence[str],
  requested: str,
  *,
  message: str = "Unsupported protocol version",
) -> JSONRPCErrorResponse:
  """Build the full -32004 JSON-RPC error response (§5.5; HTTP carries it as 400).

  See build_unsupported_protocol_version_error() for the error-object contract.
  On the HTTP transport this response MUST be returned with HTTP 400 Bad Request
  (R-5.5-b) — see http_status_for_negotiation_error().
  """
  error = build_unsupported_protocol_version_error(supported, requested, message=message)
  return JSONRPCErrorResponse(id=request_id, error=error.to_dict())


def parse_unsupported_protocol_version_error(
  error: ErrorObject | dict[str, Any],
) -> tuple[list[str], str]:
  """Extract (supported, requested) from a -32004 error (client side, §5.5).

  Validates the error carries code -32004 and a ``data`` object with a non-empty
  ``supported`` array and a ``requested`` string (R-5.5-c/f/g).

  Args:
    error: the ErrorObject or its wire dict from the response's ``error`` member.

  Returns:
    A tuple of (supported revisions, requested revision).

  Raises:
    ValueError: code is not -32004, or data is missing/malformed.
  """
  raw = error.to_dict() if isinstance(error, ErrorObject) else error
  if raw.get("code") != UNSUPPORTED_PROTOCOL_VERSION_CODE:
    raise ValueError(
      f"not an UnsupportedProtocolVersion error: code is {raw.get('code')!r}, "
      f"expected {UNSUPPORTED_PROTOCOL_VERSION_CODE} (R-5.5-d)"
    )
  data = raw.get("data")
  if not isinstance(data, dict):
    raise ValueError("UnsupportedProtocolVersion error MUST carry a data object (R-5.5-c)")
  supported = data.get("supported")
  if not isinstance(supported, list) or not supported:
    raise ValueError("data.supported MUST be a non-empty array (R-5.5-f)")
  requested = data.get("requested")
  if not isinstance(requested, str):
    raise ValueError("data.requested MUST be a string (R-5.5-g)")
  return [str(v) for v in supported], requested


# ---------------------------------------------------------------------------
# §5.6  MissingRequiredClientCapability error (-32003)
# ---------------------------------------------------------------------------

def build_missing_required_client_capability_error(
  required_capabilities: ClientCapabilities | dict[str, Any],
  *,
  message: str = "Required client capability not declared",
) -> ErrorObject:
  """Build the -32003 MissingRequiredClientCapability error object (§5.6).

  The ``data`` member is present and contains ``requiredCapabilities`` — a
  ClientCapabilities object (S10) enumerating the capabilities the server needs
  the client to declare (R-5.6-e/h).

  Args:
    required_capabilities: the capabilities required but undeclared, as a
      ClientCapabilities or its raw dict form.
    message: human-readable description (exact text not normative, R-5.6-g).

  Returns:
    An ErrorObject with code -32003 and data {requiredCapabilities}.
  """
  required_dict = (
    required_capabilities.to_dict()
    if isinstance(required_capabilities, ClientCapabilities)
    else dict(required_capabilities)
  )
  return ErrorObject(
    code=MISSING_REQUIRED_CLIENT_CAPABILITY_CODE,
    message=message,
    data={"requiredCapabilities": required_dict},
  )


def build_missing_required_client_capability_response(
  request_id: RequestId,
  required_capabilities: ClientCapabilities | dict[str, Any],
  *,
  message: str = "Required client capability not declared",
) -> JSONRPCErrorResponse:
  """Build the full -32003 JSON-RPC error response (§5.6; HTTP carries it as 400).

  On the HTTP transport this response MUST be returned with HTTP 400 Bad Request
  (R-5.6-d) — see http_status_for_negotiation_error().
  """
  error = build_missing_required_client_capability_error(required_capabilities, message=message)
  return JSONRPCErrorResponse(id=request_id, error=error.to_dict())


def parse_missing_required_client_capability_error(
  error: ErrorObject | dict[str, Any],
) -> dict[str, Any]:
  """Extract ``requiredCapabilities`` from a -32003 error (client side, §5.6).

  Args:
    error: the ErrorObject or its wire dict.

  Returns:
    The requiredCapabilities object (a ClientCapabilities dict).

  Raises:
    ValueError: code is not -32003, or data.requiredCapabilities is missing.
  """
  raw = error.to_dict() if isinstance(error, ErrorObject) else error
  if raw.get("code") != MISSING_REQUIRED_CLIENT_CAPABILITY_CODE:
    raise ValueError(
      f"not a MissingRequiredClientCapability error: code is {raw.get('code')!r}, "
      f"expected {MISSING_REQUIRED_CLIENT_CAPABILITY_CODE} (R-5.6-f)"
    )
  data = raw.get("data")
  if not isinstance(data, dict) or "requiredCapabilities" not in data:
    raise ValueError(
      "MissingRequiredClientCapability error MUST carry data.requiredCapabilities (R-5.6-e/h)"
    )
  required = data["requiredCapabilities"]
  if not isinstance(required, dict):
    raise ValueError("data.requiredCapabilities MUST be a ClientCapabilities object (R-5.6-h)")
  return required


def can_satisfy_required_capabilities(
  client_can_provide: ClientCapabilities | dict[str, Any],
  required_capabilities: dict[str, Any],
) -> bool:
  """Return True if the client can declare every required capability (R-5.6-i).

  The client decides, from a -32003 error's ``requiredCapabilities``, whether it
  is able to offer all of them. If so it SHOULD retry with them declared.

  Args:
    client_can_provide: the capabilities the client is actually able to offer.
    required_capabilities: the capabilities named in the -32003 error.
  """
  provide_dict = (
    client_can_provide.to_dict()
    if isinstance(client_can_provide, ClientCapabilities)
    else dict(client_can_provide)
  )
  return all(name in provide_dict for name in required_capabilities)


def retry_meta_with_capabilities(
  meta: dict[str, Any],
  required_capabilities: dict[str, Any],
) -> dict[str, Any]:
  """Return a copy of ``meta`` with required capabilities merged in (R-5.6-i).

  Adds the required capabilities to ``io.modelcontextprotocol/clientCapabilities``
  so the retried request declares them. The original meta is not mutated; the
  declaration is per-request (S06), so this builds the meta for the retry only.

  Args:
    meta: the original request ``_meta``.
    required_capabilities: the capabilities to declare on the retry.

  Returns:
    A new ``_meta`` dict with the merged clientCapabilities.
  """
  new_meta = dict(meta)
  existing = dict(new_meta.get(KEY_CLIENT_CAPABILITIES, {}))
  existing.update(required_capabilities)
  new_meta[KEY_CLIENT_CAPABILITIES] = existing
  return new_meta


# ---------------------------------------------------------------------------
# §5.4–§5.5  Client retry loop
# ---------------------------------------------------------------------------

class RevisionNegotiator:
  """Drives client-side revision selection and the -32004 retry loop (§5.4/§5.5).

  Construct with the client's ordered preference list. Call ``select`` once the
  server's supported set is known (from discovery or a prior error), then place
  the result in each request's ``io.modelcontextprotocol/protocolVersion``. On a
  -32004 error, call ``react_to_unsupported`` to re-select from the error's
  ``data.supported`` and retry the SAME request. The negotiator records every
  revision it has already tried so it never retries indefinitely (R-5.5-i):
  re-selection that yields an already-attempted (or no) revision raises
  IncompatibleRevisionsError (R-5.5-j).
  """

  def __init__(self, client_preferences: Sequence[str]) -> None:
    self.client_preferences: list[str] = list(client_preferences)
    self._attempted: set[str] = set()

  @property
  def attempted(self) -> frozenset[str]:
    """Snapshot of revisions already declared on an attempt."""
    return frozenset(self._attempted)

  def select(self, server_supported: Iterable[str]) -> str:
    """Select and record the initial revision (R-5.4-b); raise if none (R-5.4-d).

    Raises:
      IncompatibleRevisionsError: empty intersection.
    """
    chosen = select_revision_or_raise(self.client_preferences, server_supported)
    self._attempted.add(chosen)
    return chosen

  def react_to_unsupported(
    self,
    error: ErrorObject | dict[str, Any],
  ) -> str:
    """Re-select from a -32004 error's data.supported and record it (R-5.5-h/i/j).

    Applies the selection rule against the authoritative ``data.supported`` set.
    To avoid retrying indefinitely (R-5.5-i), a re-selection that resolves only
    to an already-attempted revision (or to no revision at all) raises
    IncompatibleRevisionsError so the caller surfaces incompatibility (R-5.5-j).

    Returns:
      The newly selected revision to declare on the retried request.

    Raises:
      IncompatibleRevisionsError: no new mutually supported revision remains.
    """
    supported, _requested = parse_unsupported_protocol_version_error(error)
    # Prefer a revision not yet attempted, in client preference order.
    for revision in self.client_preferences:
      if revision in supported and revision not in self._attempted:
        self._attempted.add(revision)
        return revision
    raise IncompatibleRevisionsError(self.client_preferences, supported)


# ---------------------------------------------------------------------------
# §5.7  Backward-compatibility probe
# ---------------------------------------------------------------------------

class ProbeOutcome(Enum):
  """Interpretation of a §5.7 probe response.

  SUPPORTED: a successful DiscoverResult — the server speaks this revision
    family; read ``supportedVersions`` and apply the selection rule (R-5.7-b).
  FAMILY_SUPPORTED_REVISION_UNSUPPORTED: a recognized -32004 carrying
    ``data.supported`` — the family is supported but not the requested revision;
    re-select from ``data.supported`` (R-5.7-b, §5.5).
  NOT_SUPPORTED: any error that is not a recognized error of this revision
    (unknown-method, malformed, or no response within the timeout) — the client
    MUST treat the server as not speaking this protocol revision (R-5.7-c).
  """

  SUPPORTED = "supported"
  FAMILY_SUPPORTED_REVISION_UNSUPPORTED = "family_supported_revision_unsupported"
  NOT_SUPPORTED = "not_supported"


@dataclass
class ProbeResult:
  """Outcome of interpreting a probe response (§5.7).

  Fields:
    outcome: the ProbeOutcome category.
    supported_versions: revisions the server advertised — populated for
      SUPPORTED (from DiscoverResult.supportedVersions) and for
      FAMILY_SUPPORTED_REVISION_UNSUPPORTED (from error data.supported).
    speaks_protocol: True iff the server speaks this protocol revision family
      (True for the first two outcomes, False for NOT_SUPPORTED).
  """

  outcome: ProbeOutcome
  supported_versions: list[str] = field(default_factory=list)

  @property
  def speaks_protocol(self) -> bool:
    """True iff the server speaks this protocol revision family (R-5.7-c)."""
    return self.outcome is not ProbeOutcome.NOT_SUPPORTED


def build_probe_request(request_id: RequestId = 0) -> JSONRPCRequest:
  """Build a server/discover probe to send as the opening request (R-5.7-b).

  Matches the §5.7 wire example (9.5): ``server/discover`` with empty params.
  A successful DiscoverResult confirms the protocol family; a recognized -32004
  confirms the family but not the revision; anything else is treated as
  not-speaking-this-revision (R-5.7-c).
  """
  return JSONRPCRequest(id=request_id, method=DISCOVER_METHOD_NAME, params={})


def interpret_probe_response(response: dict[str, Any] | None) -> ProbeResult:
  """Interpret a probe response into a ProbeResult (§5.7, R-5.7-b/c).

  Args:
    response: the decoded JSON response to the probe, or None to signal no
      response within the transport's timeout (treated as NOT_SUPPORTED).

  Returns:
    A ProbeResult. Any error that is not a recognized -32004 of this revision —
    including an unknown-method error, a malformed/unclassifiable response, or a
    None (timeout) — yields ProbeOutcome.NOT_SUPPORTED (R-5.7-c).
  """
  # No response within the timeout → not speaking this revision (R-5.7-c).
  if response is None or not isinstance(response, dict):
    return ProbeResult(ProbeOutcome.NOT_SUPPORTED)

  # Successful DiscoverResult → family supported (R-5.7-b, first bullet).
  if "result" in response and "error" not in response:
    try:
      discover = validate_discover_result(response["result"])
    except (TypeError, ValueError):
      # A result that does not validate as a DiscoverResult is not a recognized
      # success of this revision → treat as not speaking it (R-5.7-c).
      return ProbeResult(ProbeOutcome.NOT_SUPPORTED)
    return ProbeResult(
      ProbeOutcome.SUPPORTED,
      supported_versions=list(discover.supported_versions),
    )

  # A recognized UnsupportedProtocolVersion (-32004) → family supported, revision
  # not (R-5.7-b, second bullet). Any other error → not speaking this revision.
  error = response.get("error")
  if isinstance(error, dict):
    try:
      supported, _requested = parse_unsupported_protocol_version_error(error)
    except ValueError:
      return ProbeResult(ProbeOutcome.NOT_SUPPORTED)
    return ProbeResult(
      ProbeOutcome.FAMILY_SUPPORTED_REVISION_UNSUPPORTED,
      supported_versions=supported,
    )

  return ProbeResult(ProbeOutcome.NOT_SUPPORTED)


class ProtocolSupportCache:
  """Caches the per-endpoint protocol-support determination (§5.7, R-5.7-e/f).

  The determination is a property of the server *endpoint*, not of an individual
  request. A client SHOULD cache it for the lifetime of the connected server
  process (R-5.7-e) and MAY persist it across restarts of the same server
  configuration (R-5.7-f), re-probing if a cached assumption later proves wrong
  (e.g. a revision the server reported as supported begins returning -32004).

  Use ``record`` after a probe, ``get`` to consult the cache, and
  ``invalidate`` when an assumption proves wrong so the next consult re-probes.
  ``to_dict`` / ``from_dict`` support persistence across restarts.
  """

  def __init__(self) -> None:
    # endpoint → {"speaks": bool, "supported_versions": list[str]}
    self._by_endpoint: dict[str, dict[str, Any]] = {}

  def record(self, endpoint: str, result: ProbeResult) -> None:
    """Cache the determination for ``endpoint`` (R-5.7-e)."""
    self._by_endpoint[endpoint] = {
      "speaks": result.speaks_protocol,
      "supported_versions": list(result.supported_versions),
    }

  def get(self, endpoint: str) -> ProbeResult | None:
    """Return the cached determination for ``endpoint``, or None if absent."""
    entry = self._by_endpoint.get(endpoint)
    if entry is None:
      return None
    outcome = (
      ProbeOutcome.SUPPORTED if entry["speaks"] else ProbeOutcome.NOT_SUPPORTED
    )
    return ProbeResult(outcome, supported_versions=list(entry["supported_versions"]))

  def is_cached(self, endpoint: str) -> bool:
    """Return True if a determination is cached for ``endpoint``."""
    return endpoint in self._by_endpoint

  def invalidate(self, endpoint: str) -> None:
    """Drop the cached determination so the next consult re-probes (R-5.7-f)."""
    self._by_endpoint.pop(endpoint, None)

  def to_dict(self) -> dict[str, Any]:
    """Serialise the cache for persistence across restarts (R-5.7-f)."""
    return {ep: dict(entry) for ep, entry in self._by_endpoint.items()}

  @classmethod
  def from_dict(cls, raw: dict[str, Any]) -> ProtocolSupportCache:
    """Rehydrate a persisted cache (R-5.7-f)."""
    cache = cls()
    for ep, entry in raw.items():
      cache._by_endpoint[ep] = {
        "speaks": bool(entry.get("speaks", False)),
        "supported_versions": list(entry.get("supported_versions", [])),
      }
    return cache


def build_unspeakable_opening_error(
  request_id: RequestId | None,
  supported: Sequence[str],
  *,
  message: str = "Unsupported protocol version",
) -> JSONRPCErrorResponse:
  """Build an error that names the server's supported revisions (R-5.7-g).

  A server that implements only this protocol revision family, on receiving an
  opening request shaped for an out-of-band-negotiated transport it cannot
  interpret, SHOULD name the revisions it supports in any error it returns — on
  any transport — so a peer with no fall-forward mechanism can still surface a
  useful diagnostic. This reuses the -32004 shape, whose ``data.supported``
  carries the named revisions.

  Args:
    request_id: the id to echo, or None when it cannot be determined.
    supported: the non-empty list of revisions the server supports.
    message: human-readable description.
  """
  error = build_unsupported_protocol_version_error(supported, requested="(uninterpretable opening request)", message=message)
  return JSONRPCErrorResponse(id=request_id, error=error.to_dict())
