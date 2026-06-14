"""The _meta Object & Metadata Naming Rules — S05.

Delivers:
  - MetaObject / RequestMetaObject type aliases
  - Per-request key constants and REQUIRED_CLIENT_REQUEST_KEYS registry
  - Reserved bare-key set (progressToken, trace-context keys)
  - LoggingLevel string constants and severity ordering
  - validate_meta_object(): type-check _meta as a JSON object
  - validate_third_party_meta_key(): sender-side grammar + reserved-prefix check
  - validate_request_meta_object(): receiver-side per-request key validation
  - is_log_notification_allowed(): log-level severity gate
  - require_client_capability(): -32003 capability gate
  - validate_protocol_version_header(): HTTP transport version-header check
  - Exceptions for -32602, -32003, -32004 outcomes

Spec: §4.1–§4.3
Depends on: S03, S04
"""

from __future__ import annotations

from typing import Any

from mcp_sdk_py.json_value import (
  W3C_TRACE_KEYS,
  is_reserved_meta_prefix,
  is_valid_meta_name,
  is_valid_meta_prefix,
  parse_meta_key,
)


# ---------------------------------------------------------------------------
# §4.1  MetaObject type aliases
# ---------------------------------------------------------------------------

#: A generic _meta value: string-keyed map; member values MAY be any JSON
#: value (R-4.1-b). MUST be a JSON object, not an array or scalar (R-4.1-j).
MetaObject = dict[str, Any]

#: The _meta shape for client requests, which extends MetaObject with the
#: three REQUIRED per-request keys (§4.3). See validate_request_meta_object().
RequestMetaObject = dict[str, Any]


# ---------------------------------------------------------------------------
# §4.2  Reserved bare keys  [R-4.2-j]
# ---------------------------------------------------------------------------

#: Bare keys (no prefix) that MAY appear in _meta by protocol exception.
#: Third parties MUST NOT mint these; they are owned by the protocol.
RESERVED_BARE_KEYS: frozenset[str] = W3C_TRACE_KEYS | frozenset({"progressToken"})


# ---------------------------------------------------------------------------
# §4.3  Canonical prefix and per-request key names  [R-4.3-a–c]
# ---------------------------------------------------------------------------

#: The only prefix the protocol uses for keys it defines (§4.2).
CANONICAL_PROTOCOL_PREFIX: str = "io.modelcontextprotocol/"

#: The current protocol revision string (sent in protocolVersion).
CURRENT_PROTOCOL_VERSION: str = "2026-07-28"

KEY_PROTOCOL_VERSION: str = "io.modelcontextprotocol/protocolVersion"
KEY_CLIENT_INFO: str = "io.modelcontextprotocol/clientInfo"
KEY_CLIENT_CAPABILITIES: str = "io.modelcontextprotocol/clientCapabilities"
KEY_LOG_LEVEL: str = "io.modelcontextprotocol/logLevel"

#: The three keys that MUST appear in _meta on every client request (§4.3).
REQUIRED_CLIENT_REQUEST_KEYS: frozenset[str] = frozenset({
  KEY_PROTOCOL_VERSION,
  KEY_CLIENT_INFO,
  KEY_CLIENT_CAPABILITIES,
})


# ---------------------------------------------------------------------------
# §4.3  LoggingLevel  [R-4.3-d, R-4.3-l, R-4.3-m]
# ---------------------------------------------------------------------------

#: All defined LoggingLevel values in ascending severity order (least → most).
LOGGING_LEVELS_ASCENDING: list[str] = [
  "debug",
  "info",
  "notice",
  "warning",
  "error",
  "critical",
  "alert",
  "emergency",
]

LOGGING_LEVEL_DEBUG: str = "debug"
LOGGING_LEVEL_INFO: str = "info"
LOGGING_LEVEL_NOTICE: str = "notice"
LOGGING_LEVEL_WARNING: str = "warning"
LOGGING_LEVEL_ERROR: str = "error"
LOGGING_LEVEL_CRITICAL: str = "critical"
LOGGING_LEVEL_ALERT: str = "alert"
LOGGING_LEVEL_EMERGENCY: str = "emergency"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class MissingRequiredMetaKeyError(Exception):
  """A client request is missing a required per-request _meta key.

  The server MUST reject the request with JSON-RPC error -32602 (Invalid
  params) and, on the HTTP transport, HTTP 400 Bad Request (R-4.3-n).

  Attributes:
    missing_key: The key name that was expected but absent.
    json_rpc_code: Always -32602; present for caller convenience.
  """

  json_rpc_code: int = -32602

  def __init__(self, missing_key: str) -> None:
    super().__init__(
      f"Missing required _meta key {missing_key!r} on client request (R-4.3-n); "
      f"reject with JSON-RPC -32602, HTTP 400"
    )
    self.missing_key: str = missing_key


class UnsupportedProtocolVersionError(Exception):
  """The request's protocolVersion is not supported by this server.

  The server MUST reject it with the unsupported-protocol-version error
  (R-4.3-f). The full error shape (code -32004) is defined in S09.

  Attributes:
    version: The unsupported version string the client sent.
    json_rpc_code: -32004 (placeholder; S09 defines the full shape).
  """

  json_rpc_code: int = -32004

  def __init__(self, version: str) -> None:
    super().__init__(
      f"Unsupported protocol version {version!r} (R-4.3-f); "
      f"reject with unsupported-protocol-version error (S09)"
    )
    self.version: str = version


class MissingRequiredClientCapabilityError(Exception):
  """Processing the request requires a client capability it did not declare.

  The server MUST reject with JSON-RPC -32003 and populate
  data.requiredCapabilities (R-4.3-k). On HTTP, status MUST be 400.

  Attributes:
    required_capabilities: Mapping of capability-name → capability-object
      for the capabilities the request was missing.
    json_rpc_code: Always -32003.
  """

  json_rpc_code: int = -32003

  def __init__(self, required_capabilities: dict[str, Any]) -> None:
    super().__init__(
      f"Missing required client capabilities (R-4.3-k): "
      f"{list(required_capabilities)!r}; reject with JSON-RPC -32003, HTTP 400"
    )
    self.required_capabilities: dict[str, Any] = required_capabilities


# ---------------------------------------------------------------------------
# §4.1  MetaObject validation  [R-4.1-i, R-4.1-j]
# ---------------------------------------------------------------------------

def validate_meta_object(meta: Any) -> MetaObject:
  """Validate that meta is a JSON object (dict), not an array or scalar.

  R-4.1-j: The _meta object MUST be a JSON object, not an array or scalar.
  R-4.1-i: Each member value MUST be a valid JSON value.
  (JSON-value validation is the caller's responsibility for specific keys.)

  Returns meta unchanged when valid.

  Raises:
    TypeError: meta is not a dict.
  """
  if not isinstance(meta, dict):
    raise TypeError(
      f"_meta MUST be a JSON object, not {type(meta).__name__} (R-4.1-j)"
    )
  return meta


# ---------------------------------------------------------------------------
# §4.2  Third-party meta key validation  [R-4.2-b–i]
# ---------------------------------------------------------------------------

def validate_third_party_meta_key(key: str) -> None:
  """Validate that a third-party _meta key conforms to all naming constraints.

  A key a third party (vendor / extension) mints MUST:
  1. Have a prefix — bare keys are reserved for the protocol (R-4.2-i).
  2. Have a grammatically valid prefix (R-4.2-b, R-4.2-c, R-4.2-d).
  3. Use a non-reserved prefix (second label MUST NOT be 'mcp' or
     'modelcontextprotocol') (R-4.2-f).
  4. Have a grammatically valid name segment (R-4.2-g, R-4.2-h).

  This is a SENDER-SIDE check: use it when minting a new key.
  Receivers MUST NOT reject messages for unknown keys (R-4.1-e).

  Raises:
    ValueError: any naming constraint is violated.
  """
  prefix, name = parse_meta_key(key)

  if prefix is None:
    raise ValueError(
      f"Third-party _meta key {key!r} must use a prefix (e.g. 'com.example/'); "
      f"bare keys are reserved for protocol use (R-4.2-i)"
    )
  if not is_valid_meta_prefix(prefix):
    raise ValueError(
      f"_meta key prefix {prefix!r} does not conform to the label grammar "
      f"(labels must start with a letter, end with letter or digit, "
      f"interior letters/digits/hyphens) (R-4.2-b, R-4.2-c, R-4.2-d)"
    )
  if is_reserved_meta_prefix(prefix):
    raise ValueError(
      f"_meta key {key!r} uses reserved prefix {prefix!r}; "
      f"the second label 'mcp'/'modelcontextprotocol' is reserved for protocol use "
      f"(R-4.2-f)"
    )
  if not is_valid_meta_name(name):
    raise ValueError(
      f"_meta key name {name!r} does not conform to the name grammar "
      f"(must begin and end with alphanumeric; interior: letters/digits/-/_ /.) "
      f"(R-4.2-g, R-4.2-h)"
    )


# ---------------------------------------------------------------------------
# §4.3  Request meta validation  [R-4.3-a–n]
# ---------------------------------------------------------------------------

def validate_request_meta_object(
  meta: dict[str, Any],
  *,
  supported_versions: frozenset[str] | None = None,
) -> None:
  """Validate the per-request _meta object on a client request (§4.3).

  Checks the three REQUIRED per-request keys (R-4.3-a/b/c):
    io.modelcontextprotocol/protocolVersion  — string
    io.modelcontextprotocol/clientInfo       — Implementation object
    io.modelcontextprotocol/clientCapabilities — object

  Optionally validates protocolVersion against supported_versions (R-4.3-f).

  Unknown keys are silently accepted and ignored after required-key
  validation (R-4.1-e, R-4.1-f).

  Args:
    meta: The _meta dict from a client request's params.
    supported_versions: When provided, the set of protocol versions this
      server supports. Raises UnsupportedProtocolVersionError if the
      request's version is not in the set (R-4.3-f).

  Raises:
    MissingRequiredMetaKeyError: A required key is absent (R-4.3-n).
    TypeError: A required key is present but has the wrong type.
    ValueError: clientInfo lacks required name/version (R-4.3-h).
    UnsupportedProtocolVersionError: Version not in supported_versions (R-4.3-f).
  """
  # --- io.modelcontextprotocol/protocolVersion (R-4.3-a) ---
  if KEY_PROTOCOL_VERSION not in meta:
    raise MissingRequiredMetaKeyError(KEY_PROTOCOL_VERSION)
  pv = meta[KEY_PROTOCOL_VERSION]
  if not isinstance(pv, str):
    raise TypeError(
      f"{KEY_PROTOCOL_VERSION!r} must be a string; got {type(pv).__name__}"
    )
  if supported_versions is not None and pv not in supported_versions:
    raise UnsupportedProtocolVersionError(pv)

  # --- io.modelcontextprotocol/clientInfo (R-4.3-b) ---
  if KEY_CLIENT_INFO not in meta:
    raise MissingRequiredMetaKeyError(KEY_CLIENT_INFO)
  ci = meta[KEY_CLIENT_INFO]
  if not isinstance(ci, dict):
    raise TypeError(
      f"{KEY_CLIENT_INFO!r} must be a JSON object; got {type(ci).__name__}"
    )
  # Validate name and version per R-4.3-h (mirrors Implementation requirements from S20).
  if not isinstance(ci.get("name"), str) or not ci.get("name"):
    raise ValueError(
      f"{KEY_CLIENT_INFO!r}.name is REQUIRED and must be a non-empty string (R-4.3-h)"
    )
  if not isinstance(ci.get("version"), str) or not ci.get("version"):
    raise ValueError(
      f"{KEY_CLIENT_INFO!r}.version is REQUIRED and must be a non-empty string (R-4.3-h)"
    )

  # --- io.modelcontextprotocol/clientCapabilities (R-4.3-c) ---
  if KEY_CLIENT_CAPABILITIES not in meta:
    raise MissingRequiredMetaKeyError(KEY_CLIENT_CAPABILITIES)
  cc = meta[KEY_CLIENT_CAPABILITIES]
  if not isinstance(cc, dict):
    raise TypeError(
      f"{KEY_CLIENT_CAPABILITIES!r} must be a JSON object; got {type(cc).__name__}"
    )

  # --- io.modelcontextprotocol/logLevel (R-4.3-d) — OPTIONAL, DEPRECATED ---
  if KEY_LOG_LEVEL in meta:
    ll = meta[KEY_LOG_LEVEL]
    if not isinstance(ll, str):
      raise TypeError(
        f"{KEY_LOG_LEVEL!r} must be a string if present; got {type(ll).__name__}"
      )

  # All other keys (including reserved bare keys, vendor keys, and any
  # unknown keys) are silently ignored (R-4.1-e, R-4.1-f).


# ---------------------------------------------------------------------------
# §4.3  LoggingLevel helpers  [R-4.3-l, R-4.3-m]
# ---------------------------------------------------------------------------

def validate_logging_level(value: Any) -> str:
  """Return value as a LoggingLevel string; raise TypeError if not a string.

  LoggingLevel is an open enum (future values may exist); only a string
  type constraint is enforced here. Full behavior is defined in S23.
  """
  if not isinstance(value, str):
    raise TypeError(
      f"logLevel must be a string; got {type(value).__name__}"
    )
  return value


def is_log_notification_allowed(
  meta: dict[str, Any],
  notification_level: str,
) -> bool:
  """Return True if the server may emit a log notification at notification_level.

  R-4.3-l: When logLevel is absent, the server MUST NOT emit log notifications.
  R-4.3-m: When logLevel is set, SHOULD emit only at or above that severity.

  Unknown level strings (open enum) are treated permissively (allowed).
  """
  if KEY_LOG_LEVEL not in meta:
    return False  # R-4.3-l: absent → no log notifications
  requested_min = meta[KEY_LOG_LEVEL]
  try:
    min_idx = LOGGING_LEVELS_ASCENDING.index(requested_min)
    notif_idx = LOGGING_LEVELS_ASCENDING.index(notification_level)
    return notif_idx >= min_idx
  except ValueError:
    return True  # Unknown levels are tolerated (open enum)


# ---------------------------------------------------------------------------
# §4.3  Client capability gate  [R-4.3-i, R-4.3-j, R-4.3-k]
# ---------------------------------------------------------------------------

def require_client_capability(
  meta: dict[str, Any],
  required_capabilities: dict[str, Any],
) -> None:
  """Raise if the current request lacks a required client capability.

  Each call operates solely on the current request's clientCapabilities.
  The server MUST NOT infer capabilities from prior requests (R-4.3-i) and
  MUST NOT rely on any capability not declared in this request (R-4.3-j).

  Args:
    meta: The _meta dict from the current client request.
    required_capabilities: Mapping of capability-name → expected value for
      each capability the server needs. Any capability not present in
      clientCapabilities is considered missing.

  Raises:
    MissingRequiredClientCapabilityError: One or more capabilities are absent
      from clientCapabilities; caller MUST respond with -32003, HTTP 400
      (R-4.3-k). The exception carries the mapping of missing capabilities
      in required_capabilities for use in data.requiredCapabilities.
  """
  client_caps: dict[str, Any] = meta.get(KEY_CLIENT_CAPABILITIES, {})
  missing = {
    cap: val
    for cap, val in required_capabilities.items()
    if cap not in client_caps
  }
  if missing:
    raise MissingRequiredClientCapabilityError(missing)


# ---------------------------------------------------------------------------
# §4.3  HTTP transport version-header check  [R-4.3-g]
# ---------------------------------------------------------------------------

def validate_protocol_version_header(
  meta_version: str,
  http_header_version: str | None,
) -> None:
  """Validate that the _meta protocolVersion equals the MCP-Protocol-Version header.

  On the HTTP transport the protocolVersion in _meta MUST equal the
  MCP-Protocol-Version header.  If they differ, or the header is absent when
  required, the server MUST respond with HTTP 400 Bad Request (R-4.3-g).

  Raises:
    ValueError: header is absent or differs from meta_version.
  """
  if http_header_version is None:
    raise ValueError(
      f"MCP-Protocol-Version HTTP header is absent; it is required and must "
      f"equal the _meta protocolVersion {meta_version!r} (R-4.3-g)"
    )
  if meta_version != http_header_version:
    raise ValueError(
      f"protocolVersion in _meta ({meta_version!r}) differs from "
      f"MCP-Protocol-Version header ({http_header_version!r}); "
      f"server MUST respond with HTTP 400 Bad Request (R-4.3-g)"
    )
