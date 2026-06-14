"""Consolidated Registries: Methods, Errors, _meta Keys, Capabilities & Types — S46.

This capstone module delivers the five document-wide reference registries of the
specification (Appendices A–E) as a single authoritative cross-reference catalog:

  - Appendix A — :data:`METHOD_NOTIFICATION_INDEX`: every JSON-RPC method and
    notification (and the three input-request kinds and UI-dialect names) with
    its Kind, Direction, and the section that defines it.
  - Appendix B — :data:`ERROR_CODE_REGISTRY_ENTRIES`: every ``error.code`` value
    this document defines, plus the reserved server-error range, with the
    collision-avoidance rule for additional codes.
  - Appendix C — :data:`META_KEY_REGISTRY`: every reserved ``_meta`` key, its
    Used-on location, its requirement level / optionality / deprecation, and the
    required shapes of the UI host value and the tool ``_meta.ui`` value.
  - Appendix D — :data:`CAPABILITY_REGISTRY`: every capability (client, server,
    and the two extension capabilities), its side(s), and its sub-flags.
  - Appendix E — :data:`TYPE_INDEX`: every wire type (interface or type alias),
    alphabetically sorted, with its defining section and a one-line purpose.

These appendices define **no new wire types**; they are reference tables. This
module is a *consolidation*: wherever a feature module already owns a method
name, error code, ``_meta`` key, capability constant, or extension identifier,
this module **imports and reuses it** rather than re-declaring the literal — so
the registry provably agrees with the feature modules. The cited section remains
the normative definition; this module only indexes and restates the handful of
cross-cutting rules listed in §7 of the story.

Naming note: the consolidated §22 error-code table is named
:data:`ERROR_CODE_REGISTRY_ENTRIES` here to avoid clashing with the
``ERROR_CODE_REGISTRY`` symbol already exported by :mod:`mcp_sdk_py.errors`
(S34); this module re-uses that module's codes and constants directly.

Spec: Appendix A–E (lines 8586–8862)
Depends on: S25 (Tools), S29 (Completion), S34 (Error Handling), S40 (Tasks),
  S42 (UI), and — for registry agreement — every feature module S01–S45.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

# --- Method / notification names (reused, never re-declared) ----------------
from mcp_sdk_py.completion import METHOD_COMPLETION_COMPLETE
from mcp_sdk_py.elicitation_form import ELICITATION_COMPLETE_METHOD
from mcp_sdk_py.multi_round_trip import (
  INPUT_REQUEST_ELICITATION,
  INPUT_REQUEST_ROOTS,
  INPUT_REQUEST_SAMPLING,
)
from mcp_sdk_py.progress import (
  CANCELLED_NOTIFICATION_METHOD,
  DISCOVER_METHOD,
  PROGRESS_NOTIFICATION_METHOD,
)
from mcp_sdk_py.prompts import (
  METHOD_PROMPTS_GET,
  METHOD_PROMPTS_LIST,
  NOTIFICATION_PROMPTS_LIST_CHANGED,
)
from mcp_sdk_py.resources import (
  METHOD_RESOURCES_LIST,
  METHOD_RESOURCES_READ,
  METHOD_RESOURCES_TEMPLATES_LIST,
  NOTIFICATION_RESOURCES_LIST_CHANGED,
  NOTIFICATION_RESOURCES_UPDATED,
)
from mcp_sdk_py.subscriptions import (
  ACKNOWLEDGED_NOTIFICATION_METHOD,
  SUBSCRIPTIONS_LISTEN_METHOD,
)
from mcp_sdk_py.tasks_ops import (
  TASKS_CANCEL_METHOD,
  TASKS_GET_METHOD,
  TASKS_NOTIFICATION_METHOD,
  TASKS_UPDATE_METHOD,
)
from mcp_sdk_py.tools import (
  METHOD_TOOLS_CALL,
  METHOD_TOOLS_LIST,
  NOTIFICATION_TOOLS_LIST_CHANGED,
)
from mcp_sdk_py.logging_utils import LOGGING_MESSAGE_METHOD
from mcp_sdk_py.ui_host import (
  METHOD_PING as UI_METHOD_PING,
  METHOD_RESOURCES_READ as UI_METHOD_RESOURCES_READ,
  METHOD_TOOLS_CALL as UI_METHOD_TOOLS_CALL,
  METHOD_UI_INITIALIZE,
  METHOD_UI_MESSAGE,
  METHOD_UI_OPEN_LINK,
  METHOD_UI_REQUEST_DISPLAY_MODE,
  METHOD_UI_RESOURCE_TEARDOWN,
  METHOD_UI_UPDATE_MODEL_CONTEXT,
  NOTIFICATION_HOST_CONTEXT_CHANGED,
  NOTIFICATION_MESSAGE as UI_NOTIFICATION_MESSAGE,
  NOTIFICATION_SANDBOX_PROXY_READY,
  NOTIFICATION_SANDBOX_RESOURCE_READY,
  NOTIFICATION_SIZE_CHANGED,
  NOTIFICATION_TOOL_CANCELLED,
  NOTIFICATION_TOOL_INPUT,
  NOTIFICATION_TOOL_INPUT_PARTIAL,
  NOTIFICATION_TOOL_RESULT,
  NOTIFICATION_UI_INITIALIZED,
)

# --- Error codes (reused from the S34 consolidated registry) ----------------
from mcp_sdk_py.errors import (
  HEADER_MISMATCH_CODE,
  INTERNAL_ERROR_CODE,
  INVALID_PARAMS_CODE,
  INVALID_REQUEST_CODE,
  METHOD_NOT_FOUND_CODE,
  MISSING_REQUIRED_CLIENT_CAPABILITY_CODE,
  PARSE_ERROR_CODE,
  RESERVED_ERROR_CODES,
  SERVER_ERROR_RANGE_MAX,
  SERVER_ERROR_RANGE_MIN,
  UNSUPPORTED_PROTOCOL_VERSION_CODE,
)

# --- Reserved _meta keys & bare-key exceptions (reused) ---------------------
from mcp_sdk_py.meta_object import (
  CANONICAL_PROTOCOL_PREFIX,
  KEY_CLIENT_CAPABILITIES,
  KEY_CLIENT_INFO,
  KEY_LOG_LEVEL,
  KEY_PROTOCOL_VERSION,
  RESERVED_BARE_KEYS,
)
from mcp_sdk_py.json_value import W3C_TRACE_KEYS, is_reserved_meta_prefix, parse_meta_key
from mcp_sdk_py.subscriptions import SUBSCRIPTION_ID_META_KEY

# --- Extension identifiers, UI shapes (reused) ------------------------------
from mcp_sdk_py.tasks import TASKS_EXTENSION_IDENTIFIER
from mcp_sdk_py.ui import (
  TOOL_UI_META_KEY,
  UI_EXTENSION_IDENTIFIER,
  UI_MIME_TYPE,
)


# ===========================================================================
# Shared enums for the index columns
# ===========================================================================

class Kind(str, Enum):
  """Appendix A **Kind** column: how a message name behaves on the wire.

  A ``REQUEST`` expects a response; a ``NOTIFICATION`` has none; an
  ``INPUT_REQUEST_KIND`` is delivered embedded inside an input-required result
  and resolved by client retry (§11) — it is NOT a standalone server-initiated
  request. (Appendix A header, footnote †.)
  """

  REQUEST = "request"
  NOTIFICATION = "notification"
  INPUT_REQUEST_KIND = "input-request kind"


class Side(str, Enum):
  """Appendix D **Side** column: which side(s) advertise a capability.

  ``HOST_CLIENT_AND_SERVER`` and ``CLIENT_AND_SERVER`` model the extension
  capabilities negotiated through the ``extensions`` map (Appendix D rows for
  ``io.modelcontextprotocol/tasks`` and ``io.modelcontextprotocol/ui``).
  """

  CLIENT = "client"
  SERVER = "server"
  HOST = "host"
  CLIENT_AND_SERVER = "client and server"
  HOST_CLIENT_AND_SERVER = "host/client and server"


class Requirement(str, Enum):
  """RFC 2119 requirement level a registry row restates for a reserved key/value."""

  REQUIRED = "REQUIRED"
  OPTIONAL = "OPTIONAL"


# ===========================================================================
# Appendix A — Method and Notification Index
# ===========================================================================

@dataclass(frozen=True)
class MethodNotificationIndexEntry:
  """One row of Appendix A (the Method and Notification Index).

  Fields (mirroring the Appendix A columns):
    name: the JSON-RPC method or notification name (for example ``tools/list``).
    kind: a :class:`Kind` — request, notification, or input-request kind.
    direction: the normal sender→receiver pairing (for example
      ``client→server``, ``server→client``, ``UI↔host``).
    defined_in: the section that normatively defines the message.
    ui_dialect: True only for the additional UI-dialect names that are in scope
      only when the user-interface extension is active (Appendix A note).
  """

  name: str
  kind: Kind
  direction: str
  defined_in: str
  ui_dialect: bool = False


# Direction string constants (Appendix A **Direction** column).
DIRECTION_CLIENT_TO_SERVER: str = "client→server"
DIRECTION_SERVER_TO_CLIENT: str = "server→client"
DIRECTION_EITHER: str = "client→server or server→client"
DIRECTION_VIA_INPUT_REQUIRED: str = "server→client (via input-required result, §11)"
DIRECTION_UI_HOST: str = "UI↔host"


#: The core Method and Notification Index (Appendix A), excluding the additional
#: UI-dialect names. Reuses every method/notification literal from its owning
#: feature module so the index provably agrees with the rest of the SDK.
METHOD_NOTIFICATION_INDEX_CORE: tuple[MethodNotificationIndexEntry, ...] = (
  MethodNotificationIndexEntry(
    DISCOVER_METHOD, Kind.REQUEST, DIRECTION_CLIENT_TO_SERVER,
    "§5 Protocol Revision, Version Negotiation, and Discovery"),
  MethodNotificationIndexEntry(
    METHOD_TOOLS_LIST, Kind.REQUEST, DIRECTION_CLIENT_TO_SERVER, "§16 Tools"),
  MethodNotificationIndexEntry(
    METHOD_TOOLS_CALL, Kind.REQUEST, DIRECTION_CLIENT_TO_SERVER, "§16 Tools"),
  MethodNotificationIndexEntry(
    METHOD_RESOURCES_LIST, Kind.REQUEST, DIRECTION_CLIENT_TO_SERVER,
    "§17 Resources"),
  MethodNotificationIndexEntry(
    METHOD_RESOURCES_READ, Kind.REQUEST, DIRECTION_CLIENT_TO_SERVER,
    "§17 Resources"),
  MethodNotificationIndexEntry(
    METHOD_RESOURCES_TEMPLATES_LIST, Kind.REQUEST, DIRECTION_CLIENT_TO_SERVER,
    "§17 Resources"),
  MethodNotificationIndexEntry(
    METHOD_PROMPTS_LIST, Kind.REQUEST, DIRECTION_CLIENT_TO_SERVER,
    "§18 Prompts"),
  MethodNotificationIndexEntry(
    METHOD_PROMPTS_GET, Kind.REQUEST, DIRECTION_CLIENT_TO_SERVER, "§18 Prompts"),
  MethodNotificationIndexEntry(
    METHOD_COMPLETION_COMPLETE, Kind.REQUEST, DIRECTION_CLIENT_TO_SERVER,
    "§19 Completion"),
  MethodNotificationIndexEntry(
    SUBSCRIPTIONS_LISTEN_METHOD, Kind.REQUEST, DIRECTION_CLIENT_TO_SERVER,
    "§10 Server-to-Client Streaming and Subscriptions"),
  MethodNotificationIndexEntry(
    INPUT_REQUEST_ELICITATION, Kind.INPUT_REQUEST_KIND,
    DIRECTION_VIA_INPUT_REQUIRED, "§20 Elicitation"),
  MethodNotificationIndexEntry(
    INPUT_REQUEST_SAMPLING, Kind.INPUT_REQUEST_KIND,
    DIRECTION_VIA_INPUT_REQUIRED, "§21 Deprecated Client-Provided Capabilities"),
  MethodNotificationIndexEntry(
    INPUT_REQUEST_ROOTS, Kind.INPUT_REQUEST_KIND,
    DIRECTION_VIA_INPUT_REQUIRED, "§21 Deprecated Client-Provided Capabilities"),
  MethodNotificationIndexEntry(
    TASKS_GET_METHOD, Kind.REQUEST, DIRECTION_CLIENT_TO_SERVER,
    "§25 The Tasks Extension"),
  MethodNotificationIndexEntry(
    TASKS_UPDATE_METHOD, Kind.REQUEST, DIRECTION_CLIENT_TO_SERVER,
    "§25 The Tasks Extension"),
  MethodNotificationIndexEntry(
    TASKS_CANCEL_METHOD, Kind.REQUEST, DIRECTION_CLIENT_TO_SERVER,
    "§25 The Tasks Extension"),
  MethodNotificationIndexEntry(
    METHOD_UI_INITIALIZE, Kind.REQUEST, "UI↔host (UI→host)",
    "§26 The Interactive User-Interface Extension"),
  MethodNotificationIndexEntry(
    NOTIFICATION_UI_INITIALIZED, Kind.NOTIFICATION, "UI↔host (UI→host)",
    "§26 The Interactive User-Interface Extension"),
  MethodNotificationIndexEntry(
    PROGRESS_NOTIFICATION_METHOD, Kind.NOTIFICATION, DIRECTION_EITHER,
    "§15 Utilities: Progress, Cancellation, Logging, and Trace Context"),
  MethodNotificationIndexEntry(
    CANCELLED_NOTIFICATION_METHOD, Kind.NOTIFICATION, DIRECTION_EITHER,
    "§15 Utilities: Progress, Cancellation, Logging, and Trace Context"),
  MethodNotificationIndexEntry(
    LOGGING_MESSAGE_METHOD, Kind.NOTIFICATION, DIRECTION_SERVER_TO_CLIENT,
    "§15 Utilities: Progress, Cancellation, Logging, and Trace Context"),
  MethodNotificationIndexEntry(
    NOTIFICATION_TOOLS_LIST_CHANGED, Kind.NOTIFICATION,
    DIRECTION_SERVER_TO_CLIENT, "§16 Tools"),
  MethodNotificationIndexEntry(
    NOTIFICATION_PROMPTS_LIST_CHANGED, Kind.NOTIFICATION,
    DIRECTION_SERVER_TO_CLIENT, "§18 Prompts"),
  MethodNotificationIndexEntry(
    NOTIFICATION_RESOURCES_LIST_CHANGED, Kind.NOTIFICATION,
    DIRECTION_SERVER_TO_CLIENT, "§17 Resources"),
  MethodNotificationIndexEntry(
    NOTIFICATION_RESOURCES_UPDATED, Kind.NOTIFICATION,
    DIRECTION_SERVER_TO_CLIENT, "§17 Resources"),
  MethodNotificationIndexEntry(
    ACKNOWLEDGED_NOTIFICATION_METHOD, Kind.NOTIFICATION,
    DIRECTION_SERVER_TO_CLIENT,
    "§10 Server-to-Client Streaming and Subscriptions"),
  MethodNotificationIndexEntry(
    ELICITATION_COMPLETE_METHOD, Kind.NOTIFICATION, DIRECTION_SERVER_TO_CLIENT,
    "§20 Elicitation"),
  MethodNotificationIndexEntry(
    TASKS_NOTIFICATION_METHOD, Kind.NOTIFICATION, DIRECTION_SERVER_TO_CLIENT,
    "§25 The Tasks Extension"),
)


_UI_DIALECT_SECTION: str = "§26 The Interactive User-Interface Extension"

#: The additional UI-dialect message names (Appendix A note): in scope only when
#: the user-interface extension is active. The host-to-UI tool-data
#: notifications, the UI-to-host requests, the bidirectional ``ping``, the
#: host-to-UI notifications and request, and the sandbox-bridging notifications.
METHOD_NOTIFICATION_INDEX_UI_DIALECT: tuple[MethodNotificationIndexEntry, ...] = (
  # Host → UI tool-data notifications.
  MethodNotificationIndexEntry(
    NOTIFICATION_TOOL_INPUT, Kind.NOTIFICATION, "UI↔host (host→UI)",
    _UI_DIALECT_SECTION, ui_dialect=True),
  MethodNotificationIndexEntry(
    NOTIFICATION_TOOL_INPUT_PARTIAL, Kind.NOTIFICATION, "UI↔host (host→UI)",
    _UI_DIALECT_SECTION, ui_dialect=True),
  MethodNotificationIndexEntry(
    NOTIFICATION_TOOL_RESULT, Kind.NOTIFICATION, "UI↔host (host→UI)",
    _UI_DIALECT_SECTION, ui_dialect=True),
  MethodNotificationIndexEntry(
    NOTIFICATION_TOOL_CANCELLED, Kind.NOTIFICATION, "UI↔host (host→UI)",
    _UI_DIALECT_SECTION, ui_dialect=True),
  # UI → host requests.
  MethodNotificationIndexEntry(
    UI_METHOD_TOOLS_CALL, Kind.REQUEST, "UI↔host (UI→host)",
    _UI_DIALECT_SECTION, ui_dialect=True),
  MethodNotificationIndexEntry(
    UI_METHOD_RESOURCES_READ, Kind.REQUEST, "UI↔host (UI→host)",
    _UI_DIALECT_SECTION, ui_dialect=True),
  MethodNotificationIndexEntry(
    METHOD_UI_OPEN_LINK, Kind.REQUEST, "UI↔host (UI→host)",
    _UI_DIALECT_SECTION, ui_dialect=True),
  MethodNotificationIndexEntry(
    METHOD_UI_MESSAGE, Kind.REQUEST, "UI↔host (UI→host)",
    _UI_DIALECT_SECTION, ui_dialect=True),
  MethodNotificationIndexEntry(
    METHOD_UI_REQUEST_DISPLAY_MODE, Kind.REQUEST, "UI↔host (UI→host)",
    _UI_DIALECT_SECTION, ui_dialect=True),
  MethodNotificationIndexEntry(
    METHOD_UI_UPDATE_MODEL_CONTEXT, Kind.REQUEST, "UI↔host (UI→host)",
    _UI_DIALECT_SECTION, ui_dialect=True),
  # UI → host notification.
  MethodNotificationIndexEntry(
    UI_NOTIFICATION_MESSAGE, Kind.NOTIFICATION, "UI↔host (UI→host)",
    _UI_DIALECT_SECTION, ui_dialect=True),
  # Bidirectional request.
  MethodNotificationIndexEntry(
    UI_METHOD_PING, Kind.REQUEST, DIRECTION_UI_HOST,
    _UI_DIALECT_SECTION, ui_dialect=True),
  # Host → UI notifications.
  MethodNotificationIndexEntry(
    NOTIFICATION_SIZE_CHANGED, Kind.NOTIFICATION, "UI↔host (host→UI)",
    _UI_DIALECT_SECTION, ui_dialect=True),
  MethodNotificationIndexEntry(
    NOTIFICATION_HOST_CONTEXT_CHANGED, Kind.NOTIFICATION, "UI↔host (host→UI)",
    _UI_DIALECT_SECTION, ui_dialect=True),
  # Host → UI request.
  MethodNotificationIndexEntry(
    METHOD_UI_RESOURCE_TEARDOWN, Kind.REQUEST, "UI↔host (host→UI)",
    _UI_DIALECT_SECTION, ui_dialect=True),
  # Sandbox-bridging notifications.
  MethodNotificationIndexEntry(
    NOTIFICATION_SANDBOX_PROXY_READY, Kind.NOTIFICATION, "UI↔host (sandbox→host)",
    _UI_DIALECT_SECTION, ui_dialect=True),
  MethodNotificationIndexEntry(
    NOTIFICATION_SANDBOX_RESOURCE_READY, Kind.NOTIFICATION,
    "UI↔host (host→sandbox)", _UI_DIALECT_SECTION, ui_dialect=True),
)

#: The full Appendix A index: the core table followed by the UI-dialect names.
METHOD_NOTIFICATION_INDEX: tuple[MethodNotificationIndexEntry, ...] = (
  METHOD_NOTIFICATION_INDEX_CORE + METHOD_NOTIFICATION_INDEX_UI_DIALECT
)

#: The footnote restated for the three input-request kinds (Appendix A †).
INPUT_REQUEST_KIND_NOTE: str = (
  "Delivered as an input request embedded inside an input-required result and "
  "resolved by client retry (§11 Multi-Round-Trip Requests); NOT a standalone "
  "server-initiated JSON-RPC request."
)


def method_notification_entry(
  name: str, *, include_ui_dialect: bool = True
) -> MethodNotificationIndexEntry | None:
  """Return the Appendix A row for ``name``, or None when it is not indexed.

  When ``include_ui_dialect`` is False, only the core table (the names always in
  scope) is consulted; the additional UI-dialect names — in scope only when the
  user-interface extension is active (Appendix A note) — are excluded.
  """
  table = METHOD_NOTIFICATION_INDEX if include_ui_dialect else METHOD_NOTIFICATION_INDEX_CORE
  for entry in table:
    if entry.name == name:
      return entry
  return None


# ===========================================================================
# Appendix B — Error Code Registry
# ===========================================================================

@dataclass(frozen=True)
class ErrorCodeRegistryEntry:
  """One row of Appendix B (the Error Code Registry).

  Fields (mirroring the Appendix B columns):
    code: the ``error.code`` value, or None for the reserved-range row.
    name: the symbolic name (for example ``Invalid params``, ``HeaderMismatch``).
    meaning: a human-readable description of the condition the code reports.
    defined_in: the section that normatively specifies the code's shape.
    range_min / range_max: for the reserved-range row, the inclusive bounds of
      ``-32000`` to ``-32099``; both None for single-code rows.
  """

  code: int | None
  name: str
  meaning: str
  defined_in: str
  range_min: int | None = None
  range_max: int | None = None


_SEC_ERROR_HANDLING: str = "§22 Error Handling and Error Codes"
_SEC_NEGOTIATION: str = "§5 Protocol Revision, Version Negotiation, and Discovery"
_SEC_STREAMABLE_HTTP: str = "§9 The Streamable HTTP Transport"


#: The consolidated Error Code Registry (Appendix B). Named
#: ``ERROR_CODE_REGISTRY_ENTRIES`` to avoid clashing with the ``ERROR_CODE_REGISTRY``
#: dict already exported by :mod:`mcp_sdk_py.errors`. Each numeric code is reused
#: from S34 so the table provably agrees with the SDK's error codes.
ERROR_CODE_REGISTRY_ENTRIES: tuple[ErrorCodeRegistryEntry, ...] = (
  ErrorCodeRegistryEntry(
    PARSE_ERROR_CODE, "Parse error",
    "Invalid JSON was received; the receiver could not parse the byte stream "
    "of the message as JSON text.",
    _SEC_ERROR_HANDLING),
  ErrorCodeRegistryEntry(
    INVALID_REQUEST_CODE, "Invalid Request",
    "The payload is valid JSON but is not a valid JSON-RPC request object (for "
    "example, a missing or wrongly typed jsonrpc or method member).",
    _SEC_ERROR_HANDLING),
  ErrorCodeRegistryEntry(
    METHOD_NOT_FOUND_CODE, "Method not found",
    "The requested method is not implemented or not available (for example, a "
    "feature method whose gating capability was not advertised).",
    _SEC_ERROR_HANDLING),
  ErrorCodeRegistryEntry(
    INVALID_PARAMS_CODE, "Invalid params",
    "The method parameters are invalid: a required _meta field or method "
    "parameter is missing or wrongly typed, an unknown target name was "
    "supplied, or required arguments are absent.",
    _SEC_ERROR_HANDLING),
  ErrorCodeRegistryEntry(
    INTERNAL_ERROR_CODE, "Internal error",
    "An internal error occurred in the receiver while processing an otherwise "
    "valid request.",
    _SEC_ERROR_HANDLING),
  ErrorCodeRegistryEntry(
    MISSING_REQUIRED_CLIENT_CAPABILITY_CODE, "MissingRequiredClientCapability",
    "Fulfilling the request would require a client-provided capability that the "
    "request did not declare in io.modelcontextprotocol/clientCapabilities; "
    "error.data.requiredCapabilities lists the missing capabilities. On HTTP "
    "transports, returned with status 400 Bad Request.",
    _SEC_NEGOTIATION),
  ErrorCodeRegistryEntry(
    UNSUPPORTED_PROTOCOL_VERSION_CODE, "UnsupportedProtocolVersion",
    "The request declared a protocol revision in "
    "io.modelcontextprotocol/protocolVersion that the server does not "
    "implement; error.data.supported lists the server's supported revisions. "
    "On HTTP transports, returned with status 400 Bad Request.",
    _SEC_NEGOTIATION),
  ErrorCodeRegistryEntry(
    HEADER_MISMATCH_CODE, "HeaderMismatch",
    "A Streamable HTTP request was rejected because a routing-header value does "
    "not match the corresponding request-body value, or a required routing "
    "header is missing or malformed. Returned with HTTP status 400 Bad "
    "Request. Lies within the reserved server-error range -32000 to -32099.",
    _SEC_STREAMABLE_HTTP),
  ErrorCodeRegistryEntry(
    None, "(reserved server-error range)",
    "Implementation-defined server-error range reserved by JSON-RPC. The -32001 "
    "(HeaderMismatch) code occupies one value of this range; implementations "
    "MAY define additional codes within it provided they do not collide with "
    "codes defined by this document.",
    _SEC_ERROR_HANDLING,
    range_min=SERVER_ERROR_RANGE_MIN, range_max=SERVER_ERROR_RANGE_MAX),
)

#: Every concrete (non-range) error code listed in Appendix B. Re-uses S34's
#: ``RESERVED_ERROR_CODES`` so the two registries agree by construction
#: (R-AppB-a names exactly these as the codes a custom code MUST NOT equal).
REGISTERED_ERROR_CODES: frozenset[int] = RESERVED_ERROR_CODES


class ReservedErrorCodeCollisionError(ValueError):
  """A proposed additional error code collides with a registry code (Appendix B).

  Raised by :func:`validate_additional_error_code` when the candidate equals any
  code listed in the Error Code Registry — including ``-32001`` (HeaderMismatch),
  which occupies one value of the reserved range (R-AppB-a, R-AppB-b).
  """


def is_in_reserved_server_error_range(code: int) -> bool:
  """Return True iff ``code`` is within the reserved server-error range (Appendix B).

  The range ``-32000`` to ``-32099`` (inclusive) is the implementation-defined
  server-error range reserved by JSON-RPC, in which additions are explicitly
  permitted (R-AppB-b). ``SERVER_ERROR_RANGE_MIN`` is ``-32099`` and
  ``SERVER_ERROR_RANGE_MAX`` is ``-32000``.
  """
  return SERVER_ERROR_RANGE_MIN <= code <= SERVER_ERROR_RANGE_MAX


def validate_additional_error_code(code: int) -> int:
  """Validate that ``code`` may be defined as an additional error code (Appendix B).

  An implementation defining additional error codes MUST NOT use a value that
  collides with any code already listed in the Error Code Registry (R-AppB-a).
  Implementations MAY define additional codes within the reserved server-error
  range ``-32000`` to ``-32099``, provided those codes do not collide with the
  document's codes — notably ``-32001`` (HeaderMismatch), which already occupies
  one value of that range (R-AppB-b).

  Returns ``code`` unchanged when it does not collide.

  Raises:
    ReservedErrorCodeCollisionError: ``code`` equals a registry code (R-AppB-a).
  """
  if code in REGISTERED_ERROR_CODES:
    entry = next(
      (e for e in ERROR_CODE_REGISTRY_ENTRIES if e.code == code), None
    )
    name = entry.name if entry is not None else "a registry code"
    raise ReservedErrorCodeCollisionError(
      f"Additional error code {code} collides with {name} ({code}) in the "
      f"Error Code Registry; an implementation MUST NOT reuse a listed code "
      f"(R-AppB-a)."
    )
  return code


# ===========================================================================
# Appendix C — Reserved _meta Key Registry
# ===========================================================================

@dataclass(frozen=True)
class MetaKeyRegistryEntry:
  """One row of Appendix C (the Reserved _meta Key Registry).

  Fields (mirroring the Appendix C columns plus the restated rules of §7):
    key: the reserved ``_meta`` key (a ``io.modelcontextprotocol/…`` key or a
      bare reserved-by-exception key).
    used_on: where the key normally appears.
    meaning: purpose of the key, including requirement level and deprecation.
    defined_in: the section that normatively specifies the key.
    requirement: REQUIRED or OPTIONAL on the location it is used on, or None when
      the key carries no single per-location requirement level.
    deprecated: True iff the registry marks the key Deprecated.
  """

  key: str
  used_on: str
  meaning: str
  defined_in: str
  requirement: Requirement | None = None
  deprecated: bool = False


_SEC_META: str = "§4 Request Metadata and the Stateless Model"
_SEC_UTILITIES: str = (
  "§15 Utilities: Progress, Cancellation, Logging, and Trace Context"
)
_SEC_SUBSCRIPTIONS: str = "§10 Server-to-Client Streaming and Subscriptions"
_SEC_TASKS: str = "§25 The Tasks Extension"
_SEC_UI: str = "§26 The Interactive User-Interface Extension"

# The protocol-version key value example, kept vendor-neutral and matching the
# wire revision string used across the SDK.
KEY_PROTOCOL_VERSION_EXAMPLE: str = "2026-07-28"

#: The progress-correlation reserved bare key (reused from S05 RESERVED_BARE_KEYS).
KEY_PROGRESS_TOKEN: str = "progressToken"


#: The Reserved _meta Key Registry (Appendix C). Each key literal is reused from
#: its owning module (meta_object / subscriptions / tasks / ui) so the registry
#: agrees with the SDK. Order follows the Appendix C table.
META_KEY_REGISTRY: tuple[MetaKeyRegistryEntry, ...] = (
  MetaKeyRegistryEntry(
    KEY_PROTOCOL_VERSION, "every client request (_meta)",
    "The protocol revision the request uses (the wire value, for example "
    f'"{KEY_PROTOCOL_VERSION_EXAMPLE}"). REQUIRED on client requests.',
    _SEC_META, requirement=Requirement.REQUIRED),
  MetaKeyRegistryEntry(
    KEY_CLIENT_INFO, "every client request (_meta)",
    "An Implementation object identifying the client software issuing the "
    "request. REQUIRED on client requests.",
    _SEC_META, requirement=Requirement.REQUIRED),
  MetaKeyRegistryEntry(
    KEY_CLIENT_CAPABILITIES, "every client request (_meta)",
    "A ClientCapabilities object declaring, for this specific request, the "
    "optional capabilities the client supports. REQUIRED on client requests.",
    _SEC_META, requirement=Requirement.REQUIRED),
  MetaKeyRegistryEntry(
    KEY_LOG_LEVEL, "client request _meta (OPTIONAL)",
    "The minimum log severity the server may emit while processing this "
    "request, as a LoggingLevel string. Status: Deprecated.",
    _SEC_META, requirement=Requirement.OPTIONAL, deprecated=True),
  MetaKeyRegistryEntry(
    KEY_PROGRESS_TOKEN, "request _meta (OPTIONAL)",
    "Out-of-band progress correlation token; the value (a string or number) is "
    "echoed in notifications/progress to correlate updates with the "
    "originating request.",
    _SEC_UTILITIES, requirement=Requirement.OPTIONAL),
  MetaKeyRegistryEntry(
    SUBSCRIPTION_ID_META_KEY, "notification _meta on a subscription stream",
    "Correlates a notification delivered on a subscriptions/listen stream with "
    "the subscription it belongs to; value is the subscription identifier as a "
    "string.",
    _SEC_SUBSCRIPTIONS),
  MetaKeyRegistryEntry(
    "traceparent", "request and notification _meta (OPTIONAL)",
    "W3C Trace Context traceparent value, carried unchanged for "
    "distributed-trace propagation.",
    _SEC_UTILITIES, requirement=Requirement.OPTIONAL),
  MetaKeyRegistryEntry(
    "tracestate", "request and notification _meta (OPTIONAL)",
    "W3C Trace Context tracestate value, carried unchanged for "
    "distributed-trace propagation.",
    _SEC_UTILITIES, requirement=Requirement.OPTIONAL),
  MetaKeyRegistryEntry(
    "baggage", "request and notification _meta (OPTIONAL)",
    "W3C Baggage value, carried unchanged for distributed-trace propagation.",
    _SEC_UTILITIES, requirement=Requirement.OPTIONAL),
  MetaKeyRegistryEntry(
    TASKS_EXTENSION_IDENTIFIER,
    "extensions map within client clientCapabilities and within server "
    "capabilities",
    "Extension identifier declaring support for the Tasks extension; its value "
    "is an OPTIONAL settings object (empty {} defined).",
    _SEC_TASKS),
  MetaKeyRegistryEntry(
    UI_EXTENSION_IDENTIFIER, "extensions map within host/server capabilities",
    "Extension identifier declaring support for the Interactive "
    "User-Interface extension; the host's value carries the REQUIRED mimeTypes "
    "array.",
    _SEC_UI, requirement=Requirement.REQUIRED),
  MetaKeyRegistryEntry(
    TOOL_UI_META_KEY, "a Tool object's _meta (§16 Tools)",
    "Declares the user interface associated with a tool: an object with "
    "REQUIRED resourceUri (a ui:// URI) and OPTIONAL visibility. In scope only "
    "when the user-interface extension is active.",
    _SEC_UI, requirement=Requirement.REQUIRED),
)

#: The three reserved client keys REQUIRED on every client request (Appendix C
#: rows; reused from S05). R-AppC-b/c/d.
REQUIRED_CLIENT_REQUEST_META_KEYS: frozenset[str] = frozenset({
  KEY_PROTOCOL_VERSION,
  KEY_CLIENT_INFO,
  KEY_CLIENT_CAPABILITIES,
})

#: Every reserved key the registry lists by its literal value (R-AppC-a). The
#: ``io.modelcontextprotocol/…`` keys plus the bare keys reserved by exception.
RESERVED_META_KEYS: frozenset[str] = frozenset(
  e.key for e in META_KEY_REGISTRY
)


def meta_key_entry(key: str) -> MetaKeyRegistryEntry | None:
  """Return the Appendix C row for ``key``, or None when it is not registry-reserved."""
  for entry in META_KEY_REGISTRY:
    if entry.key == key:
      return entry
  return None


def is_reserved_meta_key(key: str) -> bool:
  """Return True iff ``key`` is a registry-reserved ``_meta`` key (R-AppC-a, R-AppC-j).

  A key is reserved when it either (a) is explicitly listed in the Reserved
  _meta Key Registry, or (b) begins with the ``io.modelcontextprotocol/`` prefix
  — reserved by this document for keys it (and its extensions) define — or (c)
  is one of the bare keys reserved by exception (``progressToken``,
  ``traceparent``, ``tracestate``, ``baggage``). Extension-defined identifiers
  under the canonical prefix that are not individually listed are still reserved
  (R-AppC-j); the namespacing rules are owned by §24 and §4.

  This is the converse of "unknown/custom key": a True result means the key's
  presence in ``_meta`` is permitted and not treated as an unknown key.
  """
  if key in RESERVED_META_KEYS:
    return True
  if key in RESERVED_BARE_KEYS:
    return True
  if key.startswith(CANONICAL_PROTOCOL_PREFIX):
    return True
  return False


def is_extension_meta_key(key: str) -> bool:
  """Return True iff ``key`` is a permitted extension-defined ``_meta`` key (R-AppC-j).

  Extension-defined identifiers and keys beyond those listed in the registry MAY
  appear in ``_meta`` and in the ``extensions`` capability map. A prefixed key
  qualifies when its prefix is grammatically a namespaced prefix and is not one
  the protocol reserves for its own keys (the ``mcp`` / ``modelcontextprotocol``
  second-label reservation of §4); the full namespacing rules are owned by §24
  (the Extension Mechanism) and §4.

  Keys already listed in the registry (or under the canonical protocol prefix)
  are protocol-reserved, not extension-defined, so this returns False for them.
  """
  if key in RESERVED_META_KEYS or key in RESERVED_BARE_KEYS:
    return False
  prefix, _name = parse_meta_key(key)
  if prefix is None:
    return False  # bare non-reserved keys are not valid extension keys (§4)
  if is_reserved_meta_prefix(prefix):
    return False  # io.modelcontextprotocol/… is protocol-reserved, not extension
  return True


class MissingRequiredClientMetaKeyError(ValueError):
  """A client request omits a key REQUIRED on every client request (Appendix C).

  Raised by :func:`validate_client_request_reserved_keys` when any of
  ``io.modelcontextprotocol/protocolVersion`` (R-AppC-b),
  ``io.modelcontextprotocol/clientInfo`` (R-AppC-c), or
  ``io.modelcontextprotocol/clientCapabilities`` (R-AppC-d) is absent.

  Attributes:
    missing_key: the REQUIRED key that was absent.
  """

  def __init__(self, missing_key: str) -> None:
    super().__init__(
      f"Client request _meta is missing REQUIRED reserved key {missing_key!r} "
      f"(Appendix C; R-AppC-b/c/d)."
    )
    self.missing_key: str = missing_key


def validate_client_request_reserved_keys(meta: dict[str, Any]) -> None:
  """Validate the three REQUIRED reserved client keys are present (Appendix C).

  Every client request's ``_meta`` MUST carry
  ``io.modelcontextprotocol/protocolVersion`` (R-AppC-b),
  ``io.modelcontextprotocol/clientInfo`` (R-AppC-c), and
  ``io.modelcontextprotocol/clientCapabilities`` (R-AppC-d). Absence of any one
  is non-conformant. ``io.modelcontextprotocol/logLevel`` is OPTIONAL, so its
  absence is conformant (R-AppC-e); this function does not require it.

  Raises:
    MissingRequiredClientMetaKeyError: a REQUIRED reserved client key is absent.
  """
  for key in (KEY_PROTOCOL_VERSION, KEY_CLIENT_INFO, KEY_CLIENT_CAPABILITIES):
    if key not in meta:
      raise MissingRequiredClientMetaKeyError(key)


class InvalidUiHostValueError(ValueError):
  """A host's ``io.modelcontextprotocol/ui`` value is malformed (Appendix C/D).

  Raised by :func:`validate_ui_host_value` when the host value lacks the REQUIRED
  ``mimeTypes`` array (R-AppC-h, R-AppD-f) or when that array does not include
  the verbatim UI MIME type ``text/html;profile=mcp-app`` (R-AppD-f).
  """


def validate_ui_host_value(value: Any) -> None:
  """Validate a host's ``io.modelcontextprotocol/ui`` extension value (Appendix C/D).

  The host's value under the ``io.modelcontextprotocol/ui`` extension identifier
  carries the REQUIRED ``mimeTypes`` array (R-AppC-h, R-AppD-f), which MUST be a
  string array that includes the verbatim ``text/html;profile=mcp-app``
  (R-AppD-f, reused as :data:`mcp_sdk_py.ui.UI_MIME_TYPE`). Absence of
  ``mimeTypes`` is non-conformant.

  Raises:
    InvalidUiHostValueError: ``value`` is not an object, ``mimeTypes`` is absent
      or not a string array, or it omits the verbatim UI MIME type.
  """
  if not isinstance(value, dict):
    raise InvalidUiHostValueError(
      "io.modelcontextprotocol/ui host value MUST be an object carrying "
      "mimeTypes (R-AppC-h, R-AppD-f)."
    )
  if "mimeTypes" not in value:
    raise InvalidUiHostValueError(
      "io.modelcontextprotocol/ui host value is missing the REQUIRED mimeTypes "
      "array (R-AppC-h, R-AppD-f)."
    )
  mime_types = value["mimeTypes"]
  if not isinstance(mime_types, list) or not all(
    isinstance(m, str) for m in mime_types
  ):
    raise InvalidUiHostValueError(
      "io.modelcontextprotocol/ui host value mimeTypes MUST be a string array "
      "(R-AppD-f)."
    )
  if UI_MIME_TYPE not in mime_types:
    raise InvalidUiHostValueError(
      f"io.modelcontextprotocol/ui host value mimeTypes MUST include the "
      f"verbatim {UI_MIME_TYPE!r} (R-AppD-f)."
    )


def is_empty_ui_server_acknowledgement(value: Any) -> bool:
  """Return True iff ``value`` is a conformant empty server acknowledgement (R-AppD-f).

  Under the ``io.modelcontextprotocol/ui`` extension the *server's*
  acknowledgement value MAY be empty (R-AppD-f) — unlike the host value, it
  carries no REQUIRED ``mimeTypes``. An empty object ``{}`` is the conformant
  empty acknowledgement.
  """
  return isinstance(value, dict) and len(value) == 0


class InvalidToolUiMetaError(ValueError):
  """A tool's ``_meta.ui`` value is malformed (Appendix C row for the ``ui`` key).

  Raised by :func:`validate_tool_ui_meta` when ``resourceUri`` is absent or is
  not a ``ui://`` URI (R-AppC-i). ``visibility`` is OPTIONAL.
  """


#: The URI scheme a tool ``_meta.ui`` ``resourceUri`` MUST use (R-AppC-i).
TOOL_UI_RESOURCE_URI_SCHEME: str = "ui://"


def validate_tool_ui_meta(ui_value: Any) -> None:
  """Validate the value of a tool's ``_meta.ui`` key (Appendix C row, R-AppC-i).

  The ``_meta.ui`` key on a ``Tool`` object declares an object with a REQUIRED
  ``resourceUri`` (a ``ui://`` URI) and an OPTIONAL ``visibility`` (R-AppC-i).
  Absence of ``resourceUri`` is non-conformant. The key is meaningful only when
  the user-interface extension is active; callers gate it accordingly (the
  registry only states its required shape).

  Raises:
    InvalidToolUiMetaError: ``ui_value`` is not an object, ``resourceUri`` is
      absent, or ``resourceUri`` is not a ``ui://`` URI.
  """
  if not isinstance(ui_value, dict):
    raise InvalidToolUiMetaError(
      "A tool's _meta.ui value MUST be an object with a REQUIRED resourceUri "
      "(R-AppC-i)."
    )
  if "resourceUri" not in ui_value:
    raise InvalidToolUiMetaError(
      "A tool's _meta.ui value is missing the REQUIRED resourceUri (R-AppC-i)."
    )
  resource_uri = ui_value["resourceUri"]
  if not isinstance(resource_uri, str) or not resource_uri.startswith(
    TOOL_UI_RESOURCE_URI_SCHEME
  ):
    raise InvalidToolUiMetaError(
      f"A tool's _meta.ui resourceUri MUST be a "
      f"{TOOL_UI_RESOURCE_URI_SCHEME!r} URI (R-AppC-i)."
    )


# ===========================================================================
# Appendix D — Capability Registry
# ===========================================================================

@dataclass(frozen=True)
class SubFlag:
  """A nested capability sub-flag (one entry of an Appendix D Sub-flags cell).

  Fields:
    name: the sub-flag's wire member name (for example ``listChanged``).
    requirement: REQUIRED or OPTIONAL.
    deprecated: True iff the sub-flag carries Deprecated status.
    note: an optional human-readable note (for example what it enables).
  """

  name: str
  requirement: Requirement
  deprecated: bool = False
  note: str = ""


@dataclass(frozen=True)
class CapabilityRegistryEntry:
  """One row of Appendix D (the Capability Registry).

  Fields (mirroring the Appendix D columns plus the restated rules of §7):
    capability: the capability name (for example ``tools``,
      ``io.modelcontextprotocol/ui``).
    side: which side(s) advertise the capability (:class:`Side`).
    sub_flags: the nested members defined for the capability (possibly empty).
    defined_in: the section that normatively specifies the capability.
    deprecated: True iff the capability as a whole carries Deprecated status.
    note: an optional human-readable note (for example required value shapes).
  """

  capability: str
  side: Side
  sub_flags: tuple[SubFlag, ...]
  defined_in: str
  deprecated: bool = False
  note: str = ""

  def sub_flag(self, name: str) -> SubFlag | None:
    """Return the named sub-flag, or None when this capability has no such flag."""
    for flag in self.sub_flags:
      if flag.name == name:
        return flag
    return None


_SEC_CAPABILITIES: str = "§6 Capabilities and Extensions"

#: The other defined elicitation mode besides the ``form`` sub-flag (R-AppD-a).
ELICITATION_URL_MODE: str = "url"


#: The Capability Registry (Appendix D). Extension-capability identifiers are
#: reused from their owning modules (tasks / ui) so the table agrees with the SDK.
CAPABILITY_REGISTRY: tuple[CapabilityRegistryEntry, ...] = (
  CapabilityRegistryEntry(
    "elicitation", Side.CLIENT,
    (SubFlag(
      "form", Requirement.OPTIONAL,
      note="the url mode is the other defined elicitation mode (see §20)."),),
    _SEC_CAPABILITIES),
  CapabilityRegistryEntry(
    "roots", Side.CLIENT, (), _SEC_CAPABILITIES, deprecated=True,
    note="none (value is {}); Status: Deprecated."),
  CapabilityRegistryEntry(
    "sampling", Side.CLIENT,
    (
      SubFlag(
        "tools", Requirement.OPTIONAL,
        note="enables sampling tools/toolChoice parameters."),
      SubFlag(
        "context", Requirement.OPTIONAL, deprecated=True,
        note="enables includeContext non-none values."),
    ),
    _SEC_CAPABILITIES, deprecated=True, note="Status: Deprecated."),
  CapabilityRegistryEntry(
    "extensions", Side.CLIENT, (), _SEC_CAPABILITIES,
    note="(object map keyed by extension identifier)."),
  CapabilityRegistryEntry(
    "tools", Side.SERVER,
    (SubFlag("listChanged", Requirement.OPTIONAL, note="boolean."),),
    _SEC_CAPABILITIES),
  CapabilityRegistryEntry(
    "resources", Side.SERVER,
    (
      SubFlag("listChanged", Requirement.OPTIONAL, note="boolean."),
      SubFlag("subscribe", Requirement.OPTIONAL, note="boolean."),
    ),
    _SEC_CAPABILITIES),
  CapabilityRegistryEntry(
    "prompts", Side.SERVER,
    (SubFlag("listChanged", Requirement.OPTIONAL, note="boolean."),),
    _SEC_CAPABILITIES),
  CapabilityRegistryEntry(
    "completions", Side.SERVER, (), _SEC_CAPABILITIES,
    note="none (value is {})."),
  CapabilityRegistryEntry(
    "logging", Side.SERVER, (), _SEC_CAPABILITIES, deprecated=True,
    note="none (value is {}); Status: Deprecated."),
  CapabilityRegistryEntry(
    "extensions", Side.SERVER, (), _SEC_CAPABILITIES,
    note="(object map keyed by extension identifier)."),
  CapabilityRegistryEntry(
    TASKS_EXTENSION_IDENTIFIER, Side.CLIENT_AND_SERVER, (), _SEC_TASKS,
    note="via extensions; none (settings value is {})."),
  CapabilityRegistryEntry(
    UI_EXTENSION_IDENTIFIER, Side.HOST_CLIENT_AND_SERVER,
    (SubFlag(
      "mimeTypes", Requirement.REQUIRED,
      note=(
        'host value: string array, MUST include "text/html;profile=mcp-app"; '
        "server acknowledgement value MAY be empty.")),),
    _SEC_UI,
    note=(
      'host value mimeTypes is REQUIRED and MUST include '
      '"text/html;profile=mcp-app"; server acknowledgement value MAY be empty.')),
)


def capability_entry(
  capability: str, *, side: Side | None = None
) -> CapabilityRegistryEntry | None:
  """Return the Appendix D row for ``capability`` (optionally disambiguated by side).

  ``extensions`` is defined for both the client and the server side, so when the
  capability name is ``extensions`` the caller SHOULD pass ``side`` to select the
  intended row; without it the first matching row is returned.
  """
  for entry in CAPABILITY_REGISTRY:
    if entry.capability == capability and (side is None or entry.side == side):
      return entry
  return None


# ===========================================================================
# Appendix E — Consolidated Type Index
# ===========================================================================

@dataclass(frozen=True)
class TypeIndexEntry:
  """One row of Appendix E (the Consolidated Type Index).

  Fields (mirroring the Appendix E columns):
    type_name: the wire type (interface or type alias) name.
    defined_in: the section containing the type's full canonical declaration.
    purpose: a one-line statement of the type's purpose.
  """

  type_name: str
  defined_in: str
  purpose: str


#: The Consolidated Type Index (Appendix E), sorted alphabetically
#: (case-insensitive, ASCII) by type name, exactly as the specification lists it.
TYPE_INDEX: tuple[TypeIndexEntry, ...] = (
  TypeIndexEntry("Annotations", "§14.6 Annotations", "Optional client-facing hints (audience, priority, timestamps) attachable to content and resources."),
  TypeIndexEntry("AudioContent", "§14.4.3 AudioContent", "Content block carrying base64-encoded audio data with a MIME type."),
  TypeIndexEntry("AuthorizationServerMetadata", "§23.3 Authorization Server Metadata Discovery", "OAuth authorization-server metadata document advertising endpoints and supported capabilities."),
  TypeIndexEntry("BaseMetadata", "§14.1 BaseMetadata: name and title", "Common base carrying the programmatic name and human-facing title."),
  TypeIndexEntry("BlobResourceContents", "§14.5 ResourceContents and variants", "Resource contents variant carrying base64-encoded binary data."),
  TypeIndexEntry("BooleanSchema", "§20.4 The restricted form schema", "Primitive form-field schema describing a boolean input."),
  TypeIndexEntry("CacheableResult", "§13.1 The CacheableResult Structure", "Result mixin carrying caching hints (ttlMs, cacheScope)."),
  TypeIndexEntry("CallToolRequest", "§16.5 Calling tools: tools/call", "Request to invoke a tool by name with arguments."),
  TypeIndexEntry("CallToolResult", "§16.5 Calling tools: tools/call", "Successful tool-invocation result carrying content blocks and optional structured output."),
  TypeIndexEntry("CancelledNotification", "§15.2.1 The notifications/cancelled notification", "Notification that the sender is cancelling a request the sender issued earlier."),
  TypeIndexEntry("CancelledNotificationParams", "§15.2.1 The notifications/cancelled notification", "Parameters of the cancellation notification (target request id and optional reason)."),
  TypeIndexEntry("CancelledTask", "§25.4 Task and DetailedTask Object Types", "DetailedTask variant for a task in the cancelled terminal state."),
  TypeIndexEntry("CancelTaskRequest", "§25.9 Cancelling a Task: tasks/cancel", "Request to cancel an in-progress task by taskId."),
  TypeIndexEntry("CancelTaskResult", "§25.9 Cancelling a Task: tasks/cancel", "Empty acknowledgement returned for a task cancellation."),
  TypeIndexEntry("ClientCapabilities", "§6.2 ClientCapabilities", "Capability set a client advertises to the server."),
  TypeIndexEntry("ClientIdMetadataDocument", "§23.12 Client ID Metadata Documents", "Client-published metadata document identified by a client-id URL."),
  TypeIndexEntry("ClientRegistrationRequest", "§23.14 Dynamic Client Registration", "Dynamic client registration request body."),
  TypeIndexEntry("ClientRegistrationResponse", "§23.14 Dynamic Client Registration", "Dynamic client registration response carrying issued client credentials."),
  TypeIndexEntry("ClientSamplingCapability", "§21.2.3 Client Capability", "Client capability declaring support for the deprecated sampling input-request kind."),
  TypeIndexEntry("CompletedTask", "§25.4 Task and DetailedTask Object Types", "DetailedTask variant for a task in the completed terminal state."),
  TypeIndexEntry("CompleteRequest", "§19.2 completion/complete request", "Request for completion suggestions for a prompt or resource-template argument."),
  TypeIndexEntry("CompleteRequestParams", "§19.2 completion/complete request", "Parameters of a completion request (reference, argument, context)."),
  TypeIndexEntry("CompleteResult", "§19.4 CompleteResult", "Completion result carrying candidate values and totals."),
  TypeIndexEntry("CompletionsCapability", "§19.1 The completions capability", "Server capability declaring support for argument completion."),
  TypeIndexEntry("ContentBlock", "§14.4 ContentBlock", "Discriminated union of content block kinds exchanged in messages and results."),
  TypeIndexEntry("CreateMessageRequest", "§21.2.4 Request Parameters", "Deprecated sampling request asking the client to produce a model message."),
  TypeIndexEntry("CreateMessageRequestParams", "§21.2.4 Request Parameters", "Parameters of the deprecated sampling request (messages, model preferences, tools)."),
  TypeIndexEntry("CreateMessageResult", "§21.2.8 Result", "Result of the deprecated sampling request carrying the generated message."),
  TypeIndexEntry("CreateTaskResult", "§25.3 Task Augmentation of Existing Requests", "Task-handle result (resultType: task) returned in place of an ordinary result."),
  TypeIndexEntry("Cursor", "§3.7 Base Request and Notification Params", "Opaque pagination cursor string."),
  TypeIndexEntry("DetailedTask", "§25.4 Task and DetailedTask Object Types", "Discriminated union of task objects with status-specific fields."),
  TypeIndexEntry("DiscoverRequest", "§5.3.1 Request", "Request for server discovery and protocol-revision negotiation."),
  TypeIndexEntry("DiscoverResult", "§5.3.2 Result", "Result of server/discover carrying the negotiated revision and capabilities."),
  TypeIndexEntry("DiscoverResultResponse", "§5.3.2 Result", "Success-response envelope wrapping a DiscoverResult."),
  TypeIndexEntry("ElicitRequest", "§20.2 Delivery via input-required result", "Input-request asking the client to collect user input via form or URL."),
  TypeIndexEntry("ElicitRequestFormParams", "§20.3 Elicitation modes and parameter shapes", "Form-mode elicitation parameters carrying the requested schema."),
  TypeIndexEntry("ElicitRequestParams", "§20.2 Delivery via input-required result", "Union of form-mode and URL-mode elicitation parameter shapes."),
  TypeIndexEntry("ElicitRequestURLParams", "§20.3 Elicitation modes and parameter shapes", "URL-mode elicitation parameters carrying the out-of-band URL and id."),
  TypeIndexEntry("ElicitResult", "§20.5 ElicitResult and response actions", "Elicitation response carrying the user action and any collected content."),
  TypeIndexEntry("EmbeddedResource", "§14.4.5 EmbeddedResource", "Content block embedding resource contents inline."),
  TypeIndexEntry("EmptyResult", "§3.9 Empty Result", "Result type with no fields beyond the base, used for bare acknowledgements."),
  TypeIndexEntry("EnumSchema", "§20.4 The restricted form schema", "Union of enumerated (single/multi-select) primitive form-field schemas."),
  TypeIndexEntry("Error", "§3.8 Error Object", "JSON-RPC error object (code, message, optional data)."),
  TypeIndexEntry("ExtensionSettings", "§24.3 Negotiation", "Per-extension settings map carried during extension negotiation."),
  TypeIndexEntry("FailedTask", "§25.4 Task and DetailedTask Object Types", "DetailedTask variant for a task in the failed terminal state."),
  TypeIndexEntry("GetPromptRequest", "§18.4 Getting a prompt: prompts/get", "Request to resolve a prompt by name with arguments."),
  TypeIndexEntry("GetPromptResult", "§18.4 Getting a prompt: prompts/get", "Resolved prompt result carrying the message list."),
  TypeIndexEntry("GetTaskRequest", "§25.7 Retrieving a Task: tasks/get", "Request to retrieve a task's current detailed state by taskId."),
  TypeIndexEntry("GetTaskResult", "§25.7 Retrieving a Task: tasks/get", "Result carrying a DetailedTask for the requested task."),
  TypeIndexEntry("Icon", "§14.2 Icon and Icons", "Single icon descriptor (source, optional MIME type and size)."),
  TypeIndexEntry("Icons", "§14.2 Icon and Icons", "Collection of icon descriptors."),
  TypeIndexEntry("ImageContent", "§14.4.2 ImageContent", "Content block carrying base64-encoded image data with a MIME type."),
  TypeIndexEntry("Implementation", "§14.3 Implementation", "Descriptor identifying an implementation (name, title, version)."),
  TypeIndexEntry("InputRequest", "§11.2 InputRequiredResult and the Input Requests", "Discriminated union of input-request kinds a server may ask a client to fulfill."),
  TypeIndexEntry("InputRequests", "§11.2 InputRequiredResult and the Input Requests", "Map from server-chosen key to a single InputRequest."),
  TypeIndexEntry("InputRequiredResult", "§11.2 InputRequiredResult and the Input Requests", "Result (resultType: input_required) requesting further client input."),
  TypeIndexEntry("InputRequiredTask", "§25.4 Task and DetailedTask Object Types", "DetailedTask variant for a task awaiting client input."),
  TypeIndexEntry("InputResponse", "§11.4 The Retry Request: InputResponseRequestParams", "Discriminated union of input-response kinds answering an InputRequest."),
  TypeIndexEntry("InputResponseRequestParams", "§11.4 The Retry Request: InputResponseRequestParams", "Retry parameters carrying inputResponses and the echoed requestState."),
  TypeIndexEntry("InputResponses", "§11.4 The Retry Request: InputResponseRequestParams", "Map from key to InputResponse, answering the corresponding inputRequests."),
  TypeIndexEntry("JSONArray", "§2.3 JSON Value Model", "Ordered list of JSON values."),
  TypeIndexEntry("JSONObject", "§2.3 JSON Value Model", "Unordered, string-keyed map of JSON values."),
  TypeIndexEntry("JSONRPCErrorResponse", "§3.5.2 Error Response", "JSON-RPC error response envelope."),
  TypeIndexEntry("JSONRPCMessage", "§3.1 JSON-RPC Framing", "Union of all framed JSON-RPC message kinds."),
  TypeIndexEntry("JSONRPCNotification", "§3.4 Notifications", "JSON-RPC notification envelope (no id)."),
  TypeIndexEntry("JSONRPCRequest", "§3.3 Requests", "JSON-RPC request envelope (with id)."),
  TypeIndexEntry("JSONRPCResponse", "§3.5 Responses", "Union of success and error response envelopes."),
  TypeIndexEntry("JSONRPCResultResponse", "§3.5.1 Success Response", "JSON-RPC success response envelope carrying a result."),
  TypeIndexEntry("JSONValue", "§2.3 JSON Value Model", "Any JSON value (null, boolean, number, string, array, object)."),
  TypeIndexEntry("LegacyTitledEnumSchema", "§20.4 The restricted form schema", "Deprecated enum form-field schema using a parallel enumNames array."),
  TypeIndexEntry("ListPromptsRequest", "§18.2 Listing prompts: prompts/list", "Paginated request to list available prompts."),
  TypeIndexEntry("ListPromptsResult", "§18.2 Listing prompts: prompts/list", "Paginated result listing prompts."),
  TypeIndexEntry("ListResourcesRequest", "§17.2 Listing resources: resources/list", "Paginated request to list available resources."),
  TypeIndexEntry("ListResourcesResult", "§17.2 Listing resources: resources/list", "Paginated, cacheable result listing resources."),
  TypeIndexEntry("ListResourceTemplatesRequest", "§17.3 Listing resource templates: resources/templates/list", "Paginated request to list resource templates."),
  TypeIndexEntry("ListResourceTemplatesResult", "§17.3 Listing resource templates: resources/templates/list", "Paginated, cacheable result listing resource templates."),
  TypeIndexEntry("ListRootsRequest", "§21.1.4 The roots/list Input Request", "Deprecated input-request asking the client for its root list."),
  TypeIndexEntry("ListRootsResult", "§21.1.5 The ListRootsResult and the Root Type", "Result of the deprecated roots listing."),
  TypeIndexEntry("ListToolsRequest", "§16.2 Listing tools: tools/list", "Paginated request to list available tools."),
  TypeIndexEntry("ListToolsResult", "§16.2 Listing tools: tools/list", "Paginated result listing tools."),
  TypeIndexEntry("LoggingLevel", "§15.3.1 The LoggingLevel enumeration", "Enumeration of syslog-style log severity levels."),
  TypeIndexEntry("LoggingMessageNotification", "§15.3.2 The notifications/message notification", "Notification carrying a log message from server to client."),
  TypeIndexEntry("LoggingMessageNotificationParams", "§15.3.2 The notifications/message notification", "Parameters of a logging notification (level, logger, data)."),
  TypeIndexEntry("MetaObject", "§4.1 The _meta Object", "Open string-keyed metadata map carried in _meta."),
  TypeIndexEntry("MissingRequiredClientCapabilityError", "§22.3.1 -32003 MissingRequiredClientCapability", "Error payload reporting a required client capability that was not declared."),
  TypeIndexEntry("ModelHint", "§21.2.9 Model Preferences", "Hint guiding model selection during deprecated sampling."),
  TypeIndexEntry("ModelPreferences", "§21.2.9 Model Preferences", "Model-selection preferences for deprecated sampling."),
  TypeIndexEntry("Notification", "§3.4 Notifications", "Base shape of a notification (method and optional params)."),
  TypeIndexEntry("NotificationParams", "§3.7 Base Request and Notification Params", "Base parameters shape common to notifications."),
  TypeIndexEntry("NumberSchema", "§20.4 The restricted form schema", "Primitive form-field schema describing a numeric input."),
  TypeIndexEntry("OpenLinkParams", "§26.5.3 Tool-invocation and other requests (UI → Host)", "UI-to-host request parameters to open an external link."),
  TypeIndexEntry("PaginatedRequestParams", "§12.2 Request and Result Shapes", "Base request parameters carrying an optional cursor."),
  TypeIndexEntry("PaginatedResult", "§12.2 Request and Result Shapes", "Base result carrying an optional nextCursor."),
  TypeIndexEntry("PrimitiveSchemaDefinition", "§20.4 The restricted form schema", "Union of primitive form-field schema kinds (string, number, boolean, enum)."),
  TypeIndexEntry("ProgressNotification", "§15.1.3 The notifications/progress notification", "Notification reporting progress on a long-running request."),
  TypeIndexEntry("ProgressNotificationParams", "§15.1.3 The notifications/progress notification", "Parameters of a progress notification (token, progress, total, message)."),
  TypeIndexEntry("ProgressToken", "§3.7 Base Request and Notification Params", "Token correlating progress notifications with a request."),
  TypeIndexEntry("Prompt", "§18.3 The Prompt and PromptArgument types", "Descriptor of an available prompt and its arguments."),
  TypeIndexEntry("PromptArgument", "§18.3 The Prompt and PromptArgument types", "Descriptor of a single prompt argument."),
  TypeIndexEntry("PromptListChangedNotification", "§18.6 The prompts-list-changed notification", "Notification that the prompt list has changed."),
  TypeIndexEntry("PromptMessage", "§18.5 The PromptMessage type and valid content", "Single message within a resolved prompt."),
  TypeIndexEntry("PromptReference", "§19.3 Reference types: PromptReference and ResourceTemplateReference", "Completion reference identifying a prompt."),
  TypeIndexEntry("PromptsCapability", "§18.1 The prompts capability", "Server capability declaring support for prompts."),
  TypeIndexEntry("ProtectedResourceMetadata", "§23.2 Protected Resource Metadata Discovery", "Metadata document advertising the resource server's authorization servers."),
  TypeIndexEntry("ReadResourceRequest", "§17.5 Reading a resource: resources/read", "Request to read a resource by URI."),
  TypeIndexEntry("ReadResourceRequestParams", "§17.5 Reading a resource: resources/read", "Parameters of a resource-read request (URI plus input responses)."),
  TypeIndexEntry("ReadResourceResult", "§17.5 Reading a resource: resources/read", "Cacheable result carrying the read resource's contents."),
  TypeIndexEntry("Request", "§3.3 Requests", "Base shape of a request (method and optional params)."),
  TypeIndexEntry("RequestId", "§3.2 Request Identifier", "Request-correlation identifier (string or number)."),
  TypeIndexEntry("RequestMetaObject", "§4.3 Protocol-Defined Per-Request _meta Keys", "_meta shape for protocol-defined per-request metadata keys."),
  TypeIndexEntry("RequestParams", "§3.7 Base Request and Notification Params", "Base parameters shape common to requests, carrying _meta."),
  TypeIndexEntry("RequestProtocolVersionMeta", "§5.2 Carrying the Protocol Revision on a Request", "_meta shape carrying the protocol revision on a request."),
  TypeIndexEntry("Resource", "§17.4 The Resource and ResourceTemplate types", "Descriptor of a concrete resource."),
  TypeIndexEntry("ResourceContents", "§14.5 ResourceContents and variants", "Base of the resource-contents variants (text/blob)."),
  TypeIndexEntry("ResourceLink", "§14.4.4 ResourceLink", "Content block referencing a resource by URI."),
  TypeIndexEntry("ResourceListChangedNotification", "§17.7 Change notifications and subscriptions", "Notification that the resource list has changed."),
  TypeIndexEntry("ResourceNotFoundError", "§17.6 Resource-not-found error", "Error payload reporting that a requested resource URI was not found."),
  TypeIndexEntry("ResourcesServerCapability", "§17.1 The resources capability", "Server capability declaring support for resources (and subscription flags)."),
  TypeIndexEntry("ResourceTeardownParams", "§26.5.4 Lifecycle and context-change messages (Host → UI)", "Host-to-UI parameters signalling that the UI resource is being torn down."),
  TypeIndexEntry("ResourceTemplate", "§17.4 The Resource and ResourceTemplate types", "Descriptor of a parameterized resource URI template."),
  TypeIndexEntry("ResourceTemplateReference", "§19.3 Reference types: PromptReference and ResourceTemplateReference", "Completion reference identifying a resource template."),
  TypeIndexEntry("ResourceUiMeta", "§26.4 The UI Resource", "UI metadata (CSP, permissions) attached to a UI resource."),
  TypeIndexEntry("ResourceUpdatedNotification", "§17.7 Change notifications and subscriptions", "Notification that a subscribed resource has been updated."),
  TypeIndexEntry("ResourceUpdatedNotificationParams", "§17.7 Change notifications and subscriptions", "Parameters of a resource-updated notification (URI)."),
  TypeIndexEntry("Result", "§3.6 Result Base Type", "Base of all result types, carrying resultType and _meta."),
  TypeIndexEntry("ResultType", "§3.6 Result Base Type", "Open discriminator selecting the concrete result shape."),
  TypeIndexEntry("Role", "§14.7 Role", "Message-author role (user or assistant)."),
  TypeIndexEntry("Root", "§21.1.5 The ListRootsResult and the Root Type", "Deprecated descriptor of a client-exposed filesystem root."),
  TypeIndexEntry("SamplingMessage", "§21.2.6 Messages and Content Blocks", "Single message in a deprecated sampling conversation."),
  TypeIndexEntry("SamplingMessageContentBlock", "§21.2.6 Messages and Content Blocks", "Content-block union for sampling messages (text/image/audio plus the sampling-only tool_use/tool_result blocks; excludes resource_link and resource)."),
  TypeIndexEntry("SandboxResourceReadyParams", "§26.5.5 Host-internal sandbox-proxy messages", "Host-internal sandbox-proxy parameters signalling the UI resource is ready."),
  TypeIndexEntry("ServerCapabilities", "§6.3 ServerCapabilities", "Capability set a server advertises to the client."),
  TypeIndexEntry("SingleSelectEnumSchema", "§20.4 The restricted form schema", "Union of single-select enum form-field schema variants."),
  TypeIndexEntry("SizeChangedParams", "§26.5.4 Lifecycle and context-change messages (Host → UI)", "Host-to-UI parameters reporting a UI size change."),
  TypeIndexEntry("StringSchema", "§20.4 The restricted form schema", "Primitive form-field schema describing a string input."),
  TypeIndexEntry("SubscriptionFilter", "§10.2 The subscriptions/listen Request and the Notification Filter", "Filter selecting which notification kinds a subscription delivers."),
  TypeIndexEntry("SubscriptionsAcknowledgedNotification", "§10.3 Acknowledgement", "Notification acknowledging an established subscription."),
  TypeIndexEntry("SubscriptionsAcknowledgedNotificationParams", "§10.3 Acknowledgement", "Parameters of the subscription-acknowledgement notification."),
  TypeIndexEntry("SubscriptionsListenRequest", "§10.2 The subscriptions/listen Request and the Notification Filter", "Request to open a server-to-client notification stream."),
  TypeIndexEntry("SubscriptionsListenRequestParams", "§10.2 The subscriptions/listen Request and the Notification Filter", "Parameters of the subscription-listen request (filter)."),
  TypeIndexEntry("Task", "§25.4 Task and DetailedTask Object Types", "Core task object (id, status, timestamps) shared by all task variants."),
  TypeIndexEntry("TaskStatus", "§25.5 Task Status Lifecycle", "Enumeration of task lifecycle states."),
  TypeIndexEntry("TaskStatusNotification", "§25.10 Task Status Notifications: notifications/tasks", "Notification reporting a task's status change."),
  TypeIndexEntry("TaskStatusNotificationParams", "§25.10 Task Status Notifications: notifications/tasks", "Parameters of a task-status notification (a DetailedTask)."),
  TypeIndexEntry("TasksExtensionCapability", "§25.2 Capability Declaration and Negotiation", "Capability declaring support for the Tasks extension."),
  TypeIndexEntry("TextContent", "§14.4.1 TextContent", "Content block carrying plain text."),
  TypeIndexEntry("TextResourceContents", "§14.5 ResourceContents and variants", "Resource contents variant carrying text."),
  TypeIndexEntry("TitledMultiSelectEnumSchema", "§20.4 The restricted form schema", "Multi-select enum form-field schema with per-option titles."),
  TypeIndexEntry("TitledSingleSelectEnumSchema", "§20.4 The restricted form schema", "Single-select enum form-field schema with per-option titles."),
  TypeIndexEntry("Tool", "§16.3 The Tool type", "Descriptor of an available tool (name, schemas, annotations)."),
  TypeIndexEntry("ToolAnnotations", "§16.7 Tool annotations", "Behavioral hints about a tool (read-only, destructive, idempotent, etc.)."),
  TypeIndexEntry("ToolCancelledParams", "§26.5.2 Tool input and result delivery (Host → UI)", "Host-to-UI parameters signalling a tool invocation was cancelled."),
  TypeIndexEntry("ToolChoice", "§21.2.5 Tool Choice", "Deprecated sampling control selecting how tools may be used."),
  TypeIndexEntry("ToolInputParams", "§26.5.2 Tool input and result delivery (Host → UI)", "Host-to-UI parameters delivering tool input arguments."),
  TypeIndexEntry("ToolListChangedNotification", "§16.8 The notifications/tools/list_changed notification", "Notification that the tool list has changed."),
  TypeIndexEntry("ToolResultContent", "§21.2.6 Messages and Content Blocks", "Sampling content block carrying a tool result."),
  TypeIndexEntry("ToolResultParams", "§26.5.2 Tool input and result delivery (Host → UI)", "Host-to-UI parameters delivering a tool result."),
  TypeIndexEntry("ToolsCallParams", "§26.5.3 Tool-invocation and other requests (UI → Host)", "UI-to-host parameters requesting a tool invocation."),
  TypeIndexEntry("ToolsCapability", "§16.1 The tools server capability", "Server capability declaring support for tools."),
  TypeIndexEntry("ToolUiMeta", "§26.3 Declaring a UI on a Tool", "UI metadata declaring an interactive UI on a tool."),
  TypeIndexEntry("ToolUseContent", "§21.2.6 Messages and Content Blocks", "Sampling content block carrying a tool-use request."),
  TypeIndexEntry("TraceContextMeta", "§15.4.1 Reserved trace-context metadata keys", "_meta shape carrying W3C trace-context fields."),
  TypeIndexEntry("UiContentSecurityPolicy", "§26.4 The UI Resource", "Content-security-policy descriptor for a UI resource."),
  TypeIndexEntry("UiHostContext", "§26.5.1 Initialization handshake", "Host rendering context (theme, display mode, styles) supplied to a UI."),
  TypeIndexEntry("UiHostExtensionCapability", "§26.2 Extension Identifier and Capability Negotiation", "Capability declaring support for the interactive user-interface extension."),
  TypeIndexEntry("UiInitializeParams", "§26.5.1 Initialization handshake", "UI-to-host initialization request parameters."),
  TypeIndexEntry("UiInitializeResult", "§26.5.1 Initialization handshake", "Host-to-UI initialization result (granted permissions, CSP, host context)."),
  TypeIndexEntry("UiMessageParams", "§26.5.3 Tool-invocation and other requests (UI → Host)", "UI-to-host parameters carrying a user-facing message."),
  TypeIndexEntry("UiPermissions", "§26.4 The UI Resource", "Sandbox permission set requested or granted for a UI resource."),
  TypeIndexEntry("UnsupportedProtocolVersionError", "§22.3.2 -32004 UnsupportedProtocolVersion", "Error payload reporting that no mutually supported protocol revision exists."),
  TypeIndexEntry("UntitledMultiSelectEnumSchema", "§20.4 The restricted form schema", "Multi-select enum form-field schema without per-option titles."),
  TypeIndexEntry("UntitledSingleSelectEnumSchema", "§20.4 The restricted form schema", "Single-select enum form-field schema without per-option titles."),
  TypeIndexEntry("UpdateModelContextParams", "§26.5.3 Tool-invocation and other requests (UI → Host)", "UI-to-host parameters updating the model-visible context."),
  TypeIndexEntry("UpdateTaskRequest", "§25.8 Supplying Input to a Task: tasks/update", "Request supplying input responses to an in-progress task."),
  TypeIndexEntry("UpdateTaskResult", "§25.8 Supplying Input to a Task: tasks/update", "Empty acknowledgement returned for a task update."),
  TypeIndexEntry("WorkingTask", "§25.4 Task and DetailedTask Object Types", "DetailedTask variant for a task in the working state."),
)


def type_index_entry(type_name: str) -> TypeIndexEntry | None:
  """Return the Appendix E row for ``type_name``, or None when it is not indexed."""
  for entry in TYPE_INDEX:
    if entry.type_name == type_name:
      return entry
  return None


def _type_index_sort_key(name: str) -> tuple[tuple[str, str], ...]:
  """Build the Appendix E ordering key for a type name.

  Appendix E lists types "sorted alphabetically (case-insensitive, ASCII)". The
  published table compares names character-by-character with the letter case
  folded for the primary comparison and, where two characters fold to the same
  letter, breaks the tie by raw ASCII (so an uppercase letter precedes the
  lowercase form). This reproduces the table's ordering exactly — including the
  ``TaskStatus`` group preceding ``TasksExtensionCapability`` (where uppercase
  ``S`` sorts before lowercase ``s``).
  """
  return tuple((ch.lower(), ch) for ch in name)


def type_index_is_alphabetical() -> bool:
  """Return True iff :data:`TYPE_INDEX` preserves the Appendix E ordering.

  Confirms the catalog is in the case-insensitive ASCII order Appendix E
  declares (see :func:`_type_index_sort_key` for the exact comparison rule the
  published table follows).
  """
  names = [e.type_name for e in TYPE_INDEX]
  return names == sorted(names, key=_type_index_sort_key)
