"""Utilities: Logging & Trace Context — S23.

Delivers two diagnostic utilities that ride on top of the message envelope:

1. **Logging (Deprecated [SEP-2577])**: the `notifications/message` log
   notification, the LoggingLevel severity scale (8 levels), and per-request
   opt-in via the `io.modelcontextprotocol/logLevel` reserved _meta key.

2. **Trace-context propagation (Active)**: the W3C `traceparent`, `tracestate`,
   and `baggage` bare keys carried in _meta. Receivers relay them opaquely.

Spec: §15.3–§15.4
Depends on: S05, S04
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mcp_sdk_py.json_value import (
  W3C_TRACE_KEYS,
  validate_w3c_baggage,
  validate_w3c_traceparent,
  validate_w3c_tracestate,
)
from mcp_sdk_py.meta_object import (
  KEY_LOG_LEVEL,
  LOGGING_LEVELS_ASCENDING,
  is_log_notification_allowed,
)


# ---------------------------------------------------------------------------
# §15.3  Deprecation marker
# ---------------------------------------------------------------------------

#: SEP number for the logging mechanism deprecation track.
LOGGING_DEPRECATED_SEP: str = "SEP-2577"

#: The logging mechanism is Deprecated. Implementations SHOULD NOT rely on it
#: (R-15.3-a). Use stderr (stdio transport) or out-of-band tracing instead
#: (R-15.3-b).
LOGGING_IS_DEPRECATED: bool = True


# ---------------------------------------------------------------------------
# §15.3  Notification method name & known log levels
# ---------------------------------------------------------------------------

#: Method name of the logging message notification.
LOGGING_MESSAGE_METHOD: str = "notifications/message"

#: Frozenset of the eight recognized LoggingLevel strings (§15.3.1).
LOGGING_LEVELS: frozenset[str] = frozenset(LOGGING_LEVELS_ASCENDING)


# ---------------------------------------------------------------------------
# §15.3  Data structures
# ---------------------------------------------------------------------------

@dataclass
class LoggingMessageNotificationParams:
  """Params of a notifications/message notification (§15.3.2).

  Fields:
    level: REQUIRED. Severity; must be one of the eight LoggingLevel strings
      (R-15.3.2-a). Wire key: "level".
    data: REQUIRED. Payload to be logged (R-15.3.2-c/d).
      MUST NOT carry credentials, secrets, PII, or attacker-aiding details
      (R-15.3.2-e). Wire key: "data".
    logger: OPTIONAL. Name identifying the emitting logger (R-15.3.2-b).
      Wire key: "logger".
    meta: OPTIONAL. Notification metadata. Wire key: "_meta".
  """

  level: str
  data: Any
  logger: str | None = None
  meta: dict[str, Any] | None = None

  def to_dict(self) -> dict[str, Any]:
    """Serialize to a wire-compatible dict."""
    out: dict[str, Any] = {"level": self.level, "data": self.data}
    if self.logger is not None:
      out["logger"] = self.logger
    if self.meta is not None:
      out["_meta"] = self.meta
    return out


# ---------------------------------------------------------------------------
# §15.3.1  Level validation  [R-15.3.1-a, R-15.3.2-a]
# ---------------------------------------------------------------------------

class InvalidLoggingLevelError(ValueError):
  """Raised when a level string is not one of the eight recognized LoggingLevel values.

  R-15.3.3-g: Server SHOULD reject the request with JSON-RPC -32602.
  json_rpc_code is provided for caller convenience.
  """

  json_rpc_code: int = -32602

  def __init__(self, value: Any) -> None:
    super().__init__(
      f"level {value!r} is not a recognized LoggingLevel; valid values: "
      f"{LOGGING_LEVELS_ASCENDING!r} (R-15.3.2-a)"
    )
    self.value = value


def validate_known_logging_level(level: Any) -> str:
  """Validate level is one of the eight recognized LoggingLevel strings.

  R-15.3.2-a: level MUST be one of the enumerated strings.
  R-15.3.3-g: SHOULD reject with -32602 if unrecognized.

  Unlike the open-enum validate_logging_level() in meta_object.py (which only
  checks the string type), this function enforces closed-set membership for
  notification payloads.

  Raises:
    InvalidLoggingLevelError: level is not in the known eight values.
  """
  if not isinstance(level, str) or level not in LOGGING_LEVELS:
    raise InvalidLoggingLevelError(level)
  return level


def compare_logging_levels(a: str, b: str) -> int:
  """Return negative/zero/positive as a < b, a == b, or a > b in severity order.

  Uses the fixed debug < info < notice < warning < error < critical < alert
  < emergency ordering (R-15.3.1-a). Both must be recognized level strings.

  Raises:
    InvalidLoggingLevelError: Either level is not recognized.
  """
  validate_known_logging_level(a)
  validate_known_logging_level(b)
  return LOGGING_LEVELS_ASCENDING.index(a) - LOGGING_LEVELS_ASCENDING.index(b)


def should_emit_log_notification(
  request_meta: dict[str, Any],
  notification_level: str,
) -> bool:
  """Return True if the server may emit a log notification at notification_level.

  R-15.3.3-a: MUST NOT emit if logLevel key is absent from request _meta.
  R-15.3.3-b/c/d: When present, emit only at or above the requested minimum level.

  Delegates to is_log_notification_allowed() from S05/meta_object.py.
  """
  return is_log_notification_allowed(request_meta, notification_level)


# ---------------------------------------------------------------------------
# §15.3  Notification parsing & validation
# ---------------------------------------------------------------------------

def validate_logging_message_notification_params(
  raw: dict[str, Any],
) -> LoggingMessageNotificationParams:
  """Parse and validate params of notifications/message (§15.3.2).

  Raises:
    TypeError: raw is not a dict, or a field has the wrong type.
    ValueError: level or data is absent.
    InvalidLoggingLevelError: level is not a recognized LoggingLevel string
      (R-15.3.2-a); caller SHOULD respond with -32602.
  """
  if not isinstance(raw, dict):
    raise TypeError(
      f"LoggingMessageNotificationParams must be a JSON object; "
      f"got {type(raw).__name__}"
    )
  if "level" not in raw:
    raise ValueError(
      "level is REQUIRED in notifications/message (R-15.3.2-a)"
    )
  level = validate_known_logging_level(raw["level"])

  if "data" not in raw:
    raise ValueError(
      "data is REQUIRED in notifications/message (R-15.3.2-c)"
    )
  data = raw["data"]

  logger = raw.get("logger")
  if logger is not None and not isinstance(logger, str):
    raise TypeError(
      f"logger must be a string if present; got {type(logger).__name__}"
    )

  meta = raw.get("_meta")
  if meta is not None and not isinstance(meta, dict):
    raise TypeError(
      f"_meta must be a JSON object if present; got {type(meta).__name__}"
    )

  return LoggingMessageNotificationParams(
    level=level,
    data=data,
    logger=logger,
    meta=meta,
  )


# ---------------------------------------------------------------------------
# §15.4  Trace-context propagation  [R-15.4.2-c–h]
# ---------------------------------------------------------------------------

def extract_trace_context(meta: dict[str, Any]) -> dict[str, str]:
  """Extract the W3C trace-context keys present in meta (§15.4).

  Returns a dict containing only the keys from W3C_TRACE_KEYS that are present
  in meta. Receivers MUST treat these values as opaque (R-15.4.2-c) and MUST
  NOT require their presence (R-15.4.2-d/e/f).
  """
  return {k: meta[k] for k in W3C_TRACE_KEYS if k in meta}


def propagate_trace_context(
  inbound_meta: dict[str, Any],
  outbound_meta: dict[str, Any],
) -> dict[str, Any]:
  """Copy W3C trace-context keys from inbound_meta onto outbound_meta verbatim.

  R-15.4.2-h: Intermediaries SHOULD propagate traceparent, tracestate, and
  baggage unchanged so a single logical operation remains correlatable end-to-end.

  Values are copied opaquely — never parsed or interpreted (R-15.4.2-c).

  Args:
    inbound_meta: The _meta dict from an inbound message.
    outbound_meta: The _meta dict to populate for the outbound message.
      Modified in-place.

  Returns:
    The updated outbound_meta.
  """
  for key in W3C_TRACE_KEYS:
    if key in inbound_meta:
      outbound_meta[key] = inbound_meta[key]
  return outbound_meta


def validate_trace_context_values(meta: dict[str, Any]) -> dict[str, str]:
  """Validate format of any trace-context keys present in meta (§15.4.1).

  R-15.4.1-a: traceparent follows W3C Trace Context format.
  R-15.4.1-b: tracestate follows W3C Trace Context format.
  R-15.4.1-c: baggage follows W3C Baggage format.

  All keys are OPTIONAL (R-15.4.2-b); this only validates keys that are present.
  Returns the subset of meta that contains valid trace-context entries.

  Raises:
    ValueError: A present trace-context key has an invalid format.
  """
  result: dict[str, str] = {}
  validators = {
    "traceparent": validate_w3c_traceparent,
    "tracestate": validate_w3c_tracestate,
    "baggage": validate_w3c_baggage,
  }
  for key, validator in validators.items():
    if key in meta:
      value = meta[key]
      validator(value)  # raises ValueError on invalid format
      result[key] = value
  return result


# ---------------------------------------------------------------------------
# §15.3  Log-data redaction safety net
# ---------------------------------------------------------------------------

#: Key names (lowercased) that commonly carry secrets.  Callers SHOULD pass
#: log data through :func:`redact_log_data` before sending it in a
#: ``notifications/message`` payload to prevent accidental secret leakage.
_DEFAULT_SENSITIVE_KEYS: frozenset[str] = frozenset({
  "password",
  "secret",
  "token",
  "api_key",
  "apikey",
  "auth",
  "authorization",
  "credential",
  "credentials",
  "key",
})


def redact_log_data(
  data: Any,
  *,
  sensitive_keys: frozenset[str] | None = None,
) -> Any:
  """Recursively replace sensitive key values with ``"[REDACTED]"`` (S23 Bucket B).

  A safety net against accidental secret leakage in log payloads.  Pass log
  ``data`` through this helper before including it in a ``notifications/message``
  notification.  Key matching is case-insensitive against the sensitive-keys set.

  Args:
    data: any JSON-compatible value (dict, list, scalar, None).
    sensitive_keys: override the built-in set of secret-bearing key names.
      When ``None``, :data:`_DEFAULT_SENSITIVE_KEYS` is used.

  Returns:
    A copy of ``data`` with matching key values replaced by ``"[REDACTED]"``.
    Non-dict/list values are returned unchanged.
  """
  if sensitive_keys is None:
    sensitive_keys = _DEFAULT_SENSITIVE_KEYS
  if isinstance(data, dict):
    return {
      k: "[REDACTED]" if k.lower() in sensitive_keys
      else redact_log_data(v, sensitive_keys=sensitive_keys)
      for k, v in data.items()
    }
  if isinstance(data, list):
    return [redact_log_data(item, sensitive_keys=sensitive_keys) for item in data]
  return data
