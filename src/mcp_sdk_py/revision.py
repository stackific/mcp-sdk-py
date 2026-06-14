"""Protocol Revision & Carrying the Revision — S07.

Defines the protocol revision identifier format (YYYY-MM-DD), the exact-match
support check, and the HTTP transport mirroring rules.

The current revision is '2026-07-28'. Revision identifiers are opaque,
exactly-matched strings; no lexical, chronological, or range comparison
is allowed for support decisions (R-5.1-a, R-5.1-b).

Spec: §5.1–§5.2
Depends on: S05
"""

from __future__ import annotations

import re
from typing import Any

from mcp_sdk_py.meta_object import CURRENT_PROTOCOL_VERSION, KEY_PROTOCOL_VERSION


# ---------------------------------------------------------------------------
# §5.1  Protocol revision identifier  [R-5.1-a, R-5.1-b]
# ---------------------------------------------------------------------------

#: The single revision defined by this specification.
#: Treat as an opaque, case-sensitive string; the date form is human-readable
#: only and MUST NOT be used for chronological ordering (R-5.1-b).
PROTOCOL_REVISION_CURRENT: str = CURRENT_PROTOCOL_VERSION

#: The set of revisions this SDK implementation supports.
SUPPORTED_REVISIONS: frozenset[str] = frozenset({PROTOCOL_REVISION_CURRENT})

#: YYYY-MM-DD format. Used only for format validation (R-5.2-b); the shape
#: does not imply ordering semantics for support decisions (R-5.1-b).
_REVISION_FORMAT: re.Pattern[str] = re.compile(r"^\d{4}-\d{2}-\d{2}$")

#: HTTP header name that mirrors the _meta protocolVersion on HTTP transport.
HTTP_PROTOCOL_VERSION_HEADER: str = "MCP-Protocol-Version"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class InvalidRevisionFormatError(ValueError):
  """Raised when a revision string does not conform to the YYYY-MM-DD format.

  R-5.2-b: The JSON type MUST be string and the value MUST be a protocol
  revision identifier (a YYYY-MM-DD string).
  """

  def __init__(self, value: Any) -> None:
    super().__init__(
      f"Protocol revision {value!r} is not a valid YYYY-MM-DD identifier; "
      f"expected a string matching 'YYYY-MM-DD' (R-5.1-a, R-5.2-b)"
    )
    self.value = value


class UnsupportedRevisionError(Exception):
  """Raised when a requested revision is not in the supported-revisions set.

  Support is decided by exact byte-for-byte equality only (R-5.1-a).
  No lexical or chronological comparison is performed (R-5.1-b).

  Attributes:
    requested: The revision string the client sent.
    supported: The set of revisions this server supports.
    json_rpc_code: -32004; used when building the JSON-RPC error response (S09).
  """

  json_rpc_code: int = -32004

  def __init__(self, requested: str, supported: frozenset[str]) -> None:
    super().__init__(
      f"Protocol revision {requested!r} is not supported; supported: "
      f"{sorted(supported)!r}. Support requires exact string equality — no "
      f"range or chronological comparison is performed (R-5.1-a, R-5.1-b)."
    )
    self.requested: str = requested
    self.supported: frozenset[str] = supported


class ProtocolVersionHeaderMismatchError(ValueError):
  """Raised when MCP-Protocol-Version HTTP header does not match _meta value.

  R-5.2-e: The server MUST respond with HTTP 400 Bad Request on mismatch.
  The http_status class attribute signals the expected response status code.
  """

  http_status: int = 400

  def __init__(self, meta_version: str, header_version: str) -> None:
    super().__init__(
      f"MCP-Protocol-Version header ({header_version!r}) does not match "
      f"_meta protocolVersion ({meta_version!r}); "
      f"server MUST respond HTTP 400 Bad Request (R-5.2-e)"
    )
    self.meta_version: str = meta_version
    self.header_version: str = header_version


# ---------------------------------------------------------------------------
# §5.1  Format validation  [R-5.2-b]
# ---------------------------------------------------------------------------

def is_valid_revision_format(revision: object) -> bool:
  """Return True if revision is a string conforming to YYYY-MM-DD format.

  The date shape is for human readability; it carries no ordering guarantee
  for support decisions (R-5.1-b). This only checks the string type and format.
  """
  if not isinstance(revision, str):
    return False
  return bool(_REVISION_FORMAT.match(revision))


def validate_revision_format(revision: object) -> str:
  """Validate revision is a YYYY-MM-DD string; return it or raise.

  Raises:
    InvalidRevisionFormatError: revision is not a valid YYYY-MM-DD string.
  """
  if not is_valid_revision_format(revision):
    raise InvalidRevisionFormatError(revision)
  return revision  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# §5.1  Exact-match support check  [R-5.1-a, R-5.1-b]
# ---------------------------------------------------------------------------

def revisions_are_equal(a: str, b: str) -> bool:
  """Return True if two revision strings are byte-for-byte identical.

  R-5.1-a: Support is decided by EXACT string equality only.
  R-5.1-b: MUST NOT use <, >, or any lexical/chronological operator.
  This is the only correct way to compare protocol revisions for support.
  """
  return a == b


def is_supported_revision(revision: str, supported: frozenset[str]) -> bool:
  """Return True if revision is byte-for-byte equal to one in supported.

  Uses exact string membership (R-5.1-a). Never applies ordering (R-5.1-b).
  """
  return revision in supported


def validate_supported_revision(
  revision: str,
  supported: frozenset[str],
) -> None:
  """Raise UnsupportedRevisionError if revision is not in supported.

  Uses exact string membership only (R-5.1-a, R-5.1-b).

  Raises:
    UnsupportedRevisionError: revision is not in the supported set.
  """
  if revision not in supported:
    raise UnsupportedRevisionError(revision, supported)


# ---------------------------------------------------------------------------
# §5.1  No-inference rule  [R-5.1-c]
# ---------------------------------------------------------------------------

def extract_request_revision(params_meta: dict) -> str:
  """Extract the protocol revision declared by this specific request's _meta.

  R-5.1-c: A receiver MUST NOT infer the revision of a request from any
  earlier request. Each request independently declares its revision; call
  this on each request's _meta in isolation, never caching or inheriting
  results from a prior call.

  Raises:
    ValueError: KEY_PROTOCOL_VERSION is absent from params_meta (R-5.2-a).
    TypeError: The value is present but not a string (R-5.2-b).
  """
  if KEY_PROTOCOL_VERSION not in params_meta:
    raise ValueError(
      f"Key {KEY_PROTOCOL_VERSION!r} is absent from _meta; it is REQUIRED "
      f"on every request (R-5.2-a)"
    )
  value = params_meta[KEY_PROTOCOL_VERSION]
  if not isinstance(value, str):
    raise TypeError(
      f"{KEY_PROTOCOL_VERSION!r} must be a string; got {type(value).__name__} "
      f"(R-5.2-b)"
    )
  return value


# ---------------------------------------------------------------------------
# §5.2  HTTP transport mirroring  [R-5.2-c, R-5.2-d, R-5.2-e]
# ---------------------------------------------------------------------------

def validate_http_revision_header(
  meta_version: str,
  header_version: str | None,
) -> None:
  """Validate that the MCP-Protocol-Version header matches the _meta value.

  On the HTTP transport:
  - The revision MUST be carried in the header (R-5.2-c).
  - The header value MUST equal the _meta value (R-5.2-d).
  - A mismatch or absent header MUST result in HTTP 400 Bad Request (R-5.2-e).

  The comparison uses exact string equality (R-5.1-a); no ordering is applied.

  Raises:
    ProtocolVersionHeaderMismatchError: header is absent or differs from
      meta_version. Callers map this to HTTP 400.
  """
  if header_version is None or meta_version != header_version:
    raise ProtocolVersionHeaderMismatchError(
      meta_version,
      header_version if header_version is not None else "(absent)",
    )
