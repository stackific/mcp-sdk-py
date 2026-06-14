"""Interactive UI Extension II: UI-to-Host Dialect, Registry & Security — S42.

Delivers the *runtime* half of the OPTIONAL Interactive User-Interface ("apps")
extension (spec §26.5–§26.9): the ``ui/``-prefixed JSON-RPC message dialect a
rendered UI and its host speak over the host-provided channel once a UI resource
(S41) has been rendered. S41 established *what* a UI is and how it is declared
and served; this module defines *how* it talks to the host and how that channel
is kept safe. It models:

  1. The dialect *framing and versioning* rule (§26.5): every message is a
     JSON-RPC request/response/notification with the §3 wire shape, and every
     method/notification name is matched verbatim and case-sensitively; the
     dialect-revision string is the exact value ``"2026-01-26"`` and is
     independent of the core revision negotiated at ``server/discover``
     (R-26.5-a/b).
  2. The *initialization handshake* (§26.5.1): the :class:`UiInitializeParams`
     request the UI sends, the :class:`UiInitializeResult` the host replies with
     (carrying ``hostCapabilities.sandbox`` and the initial
     :class:`UiHostContext`), and the strict ordering rule that no other dialect
     message precedes the ``ui/initialize`` response (R-26.5.1-a/b).
  3. The *Host → UI delivery* notifications (§26.5.2): tool input (complete and
     partial), tool result, and tool cancellation — :class:`ToolInputParams`,
     :class:`ToolResultParams`, :class:`ToolCancelledParams`.
  4. The *UI → Host mediated requests* (§26.5.3): ``tools/call``,
     ``resources/read``, ``ui/open-link``, ``ui/message``,
     ``ui/request-display-mode``, ``ui/update-model-context``, the
     ``notifications/message`` notification, and ``ping`` (either direction),
     with the mediation/consent/visibility rules a host enforces (R-26.5.3-a…g).
  5. The *Host → UI lifecycle/context* messages (§26.5.4) and the *host-internal
     sandbox-proxy* notifications (§26.5.5).
  6. The verbatim *method/notification name registry* of all 19 dialect names
     with their kind and sender (§26.6).
  7. The normative *security and consent* rules a host enforces (§26.7) restated
     as auditable predicates, and the *error-handling* contract (§26.8): failed
     dialect requests answered with §22 JSON-RPC errors, declined UI requests
     never silently dropped, and method-not-found for unknown dialect methods.
  8. The *SDK scope summary* (§26.9): which obligations are a server SDK's and
     which are host/client concerns.

Per §26.9 (R-26.9-d) the dialect runtime — rendering, sandboxing, CSP/permission
enforcement, mediation, and consent — is a *host/client* concern, NOT a server
SDK obligation. This module therefore has no rendering, browser, or UI-toolkit
dependency: it provides the abstract data structures, the name registry, and the
host-side conformance predicates a host implementation (or a conformance suite)
consumes, while a server SDK only needs the §26.9-a/b/c surface re-exported from
S41.

This module REUSES the lower waves rather than re-implementing them:

  - S41 (``mcp_sdk_py.ui``) owns the UI extension identifier, the ``_meta.ui``
    tool declaration (:class:`ToolUiMeta`, ``visibility`` semantics), and the
    ``ui://`` UI resource hint shapes (:class:`UiContentSecurityPolicy`,
    :class:`UiPermissions`). The handshake's sandbox report reuses those hint
    shapes; the visibility gate delegates to :func:`host_should_reject_ui_call`.
  - S03 (``mcp_sdk_py.jsonrpc``) owns the JSON-RPC request/notification/response
    framing; the dialect messages serialise via its dataclasses and the host's
    message validation delegates to :func:`classify_message`.
  - S34 (``mcp_sdk_py.errors``) / S04 (``mcp_sdk_py.result_error``) own the
    error-code registry and :class:`ErrorObject`; the §26.8 error contract reuses
    ``METHOD_NOT_FOUND_CODE`` / ``INVALID_PARAMS_CODE`` / ``INTERNAL_ERROR_CODE``.
  - S21 (``mcp_sdk_py.content_types``) owns the ``ContentBlock`` shape carried in
    tool-result and model-context ``content`` fields.

Spec: §26.5–§26.9 (lines 7958–8278)
Depends on: S41 (UI declaration / resource / hint shapes), S03 (JSON-RPC
  framing), S34/S04 (error codes, ErrorObject), S21 (ContentBlock)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from mcp_sdk_py.errors import (
  INTERNAL_ERROR_CODE,
  INVALID_PARAMS_CODE,
  METHOD_NOT_FOUND_CODE,
)
from mcp_sdk_py.jsonrpc import (
  JSONRPCErrorResponse,
  JSONRPCNotification,
  JSONRPCRequest,
  JSONRPCResultResponse,
  RequestId,
  classify_message,
)
from mcp_sdk_py.result_error import ErrorObject
from mcp_sdk_py.ui import (
  UiContentSecurityPolicy,
  UiPermissions,
  host_should_reject_ui_call,
)
from mcp_sdk_py.ui import ToolUiMeta as _ToolUiMeta


# ---------------------------------------------------------------------------
# §26.5  Dialect framing and versioning  [R-26.5-a, R-26.5-b]
# ---------------------------------------------------------------------------

#: The exact dialect-revision string carried in this dialect's initialization
#: handshake (§26.5, R-26.5-b). It identifies the *message-dialect* revision and
#: is independent of the core protocol revision negotiated at ``server/discover``
#: (which is ``"2026-07-28"``, §5/§27.1). Matched verbatim and case-sensitively.
UI_DIALECT_PROTOCOL_VERSION: str = "2026-01-26"


# -- §26.6  Method/notification name registry (verbatim, case-sensitive) --

#: The 19 dialect method/notification names, reproduced verbatim and matched
#: case-sensitively (§26.6, R-26.5-a). Defined as constants so callers never
#: spell a name inline; :data:`DIALECT_REGISTRY` records each name's kind and
#: sender. ``ping``, ``tools/call``, ``resources/read``, and
#: ``notifications/message`` are core names reused by the dialect verbatim.
METHOD_UI_INITIALIZE: str = "ui/initialize"
NOTIFICATION_UI_INITIALIZED: str = "ui/notifications/initialized"
NOTIFICATION_TOOL_INPUT: str = "ui/notifications/tool-input"
NOTIFICATION_TOOL_INPUT_PARTIAL: str = "ui/notifications/tool-input-partial"
NOTIFICATION_TOOL_RESULT: str = "ui/notifications/tool-result"
NOTIFICATION_TOOL_CANCELLED: str = "ui/notifications/tool-cancelled"
METHOD_TOOLS_CALL: str = "tools/call"
METHOD_RESOURCES_READ: str = "resources/read"
METHOD_UI_OPEN_LINK: str = "ui/open-link"
METHOD_UI_MESSAGE: str = "ui/message"
METHOD_UI_REQUEST_DISPLAY_MODE: str = "ui/request-display-mode"
METHOD_UI_UPDATE_MODEL_CONTEXT: str = "ui/update-model-context"
NOTIFICATION_MESSAGE: str = "notifications/message"
METHOD_PING: str = "ping"
NOTIFICATION_SIZE_CHANGED: str = "ui/notifications/size-changed"
NOTIFICATION_HOST_CONTEXT_CHANGED: str = "ui/notifications/host-context-changed"
METHOD_UI_RESOURCE_TEARDOWN: str = "ui/resource-teardown"
NOTIFICATION_SANDBOX_PROXY_READY: str = "ui/notifications/sandbox-proxy-ready"
NOTIFICATION_SANDBOX_RESOURCE_READY: str = "ui/notifications/sandbox-resource-ready"


class DialectKind(Enum):
  """Whether a dialect name is a JSON-RPC request or a notification (§26.6).

  A ``request`` expects exactly one response (success or §22 error); a
  ``notification`` is one-way and never answered (§3 / R-26.5-a). The registry's
  ``kind`` drives whether a receiver must produce a response.
  """

  REQUEST = "request"
  NOTIFICATION = "notification"


class DialectSender(Enum):
  """The fixed originator of a dialect message (§26.6).

  Every dialect name has a fixed direction (§26.5, §26.6): ``UI_TO_HOST``,
  ``HOST_TO_UI``, ``EITHER`` (only ``ping``, UI ↔ Host), ``SANDBOX_TO_HOST`` and
  ``HOST_TO_SANDBOX`` (the host-internal sandbox-proxy notifications of §26.5.5).
  """

  UI_TO_HOST = "ui->host"
  HOST_TO_UI = "host->ui"
  EITHER = "ui<->host"
  SANDBOX_TO_HOST = "sandbox->host"
  HOST_TO_SANDBOX = "host->sandbox"


@dataclass(frozen=True)
class DialectName:
  """One row of the §26.6 method/notification name registry.

  Fields:
    name: the verbatim, case-sensitive dialect name (§26.6, R-26.5-a).
    kind: whether it is a :class:`DialectKind.REQUEST` or
      :class:`DialectKind.NOTIFICATION`.
    sender: the fixed :class:`DialectSender` direction of the message.
  """

  name: str
  kind: DialectKind
  sender: DialectSender


#: The complete §26.6 registry of all 19 dialect names, in spec table order,
#: keyed by the verbatim name (R-26.5-a). A host/conformance suite consults this
#: to confirm an observed name matches a registered one byte-for-byte and to look
#: up its kind (must a response be produced?) and sender (who may originate it).
DIALECT_REGISTRY: dict[str, DialectName] = {
  entry.name: entry
  for entry in (
    DialectName(METHOD_UI_INITIALIZE, DialectKind.REQUEST, DialectSender.UI_TO_HOST),
    DialectName(NOTIFICATION_UI_INITIALIZED, DialectKind.NOTIFICATION, DialectSender.UI_TO_HOST),
    DialectName(NOTIFICATION_TOOL_INPUT, DialectKind.NOTIFICATION, DialectSender.HOST_TO_UI),
    DialectName(NOTIFICATION_TOOL_INPUT_PARTIAL, DialectKind.NOTIFICATION, DialectSender.HOST_TO_UI),
    DialectName(NOTIFICATION_TOOL_RESULT, DialectKind.NOTIFICATION, DialectSender.HOST_TO_UI),
    DialectName(NOTIFICATION_TOOL_CANCELLED, DialectKind.NOTIFICATION, DialectSender.HOST_TO_UI),
    DialectName(METHOD_TOOLS_CALL, DialectKind.REQUEST, DialectSender.UI_TO_HOST),
    DialectName(METHOD_RESOURCES_READ, DialectKind.REQUEST, DialectSender.UI_TO_HOST),
    DialectName(METHOD_UI_OPEN_LINK, DialectKind.REQUEST, DialectSender.UI_TO_HOST),
    DialectName(METHOD_UI_MESSAGE, DialectKind.REQUEST, DialectSender.UI_TO_HOST),
    DialectName(METHOD_UI_REQUEST_DISPLAY_MODE, DialectKind.REQUEST, DialectSender.UI_TO_HOST),
    DialectName(METHOD_UI_UPDATE_MODEL_CONTEXT, DialectKind.REQUEST, DialectSender.UI_TO_HOST),
    DialectName(NOTIFICATION_MESSAGE, DialectKind.NOTIFICATION, DialectSender.UI_TO_HOST),
    DialectName(METHOD_PING, DialectKind.REQUEST, DialectSender.EITHER),
    DialectName(NOTIFICATION_SIZE_CHANGED, DialectKind.NOTIFICATION, DialectSender.HOST_TO_UI),
    DialectName(NOTIFICATION_HOST_CONTEXT_CHANGED, DialectKind.NOTIFICATION, DialectSender.HOST_TO_UI),
    DialectName(METHOD_UI_RESOURCE_TEARDOWN, DialectKind.REQUEST, DialectSender.HOST_TO_UI),
    DialectName(NOTIFICATION_SANDBOX_PROXY_READY, DialectKind.NOTIFICATION, DialectSender.SANDBOX_TO_HOST),
    DialectName(NOTIFICATION_SANDBOX_RESOURCE_READY, DialectKind.NOTIFICATION, DialectSender.HOST_TO_SANDBOX),
  )
}

#: The frozen set of every verbatim dialect name (§26.6, R-26.5-a). Membership is
#: an exact, case-sensitive match: ``"UI/Initialize"`` is NOT in this set.
DIALECT_NAMES: frozenset[str] = frozenset(DIALECT_REGISTRY)

#: The UI-initiated request names a host MUST answer with a §22 error when it
#: declines them — never silently drop (§26.8, R-26.8-b). Used by
#: :func:`requires_error_on_decline`.
DECLINABLE_UI_REQUESTS: frozenset[str] = frozenset({
  METHOD_TOOLS_CALL,
  METHOD_RESOURCES_READ,
  METHOD_UI_OPEN_LINK,
  METHOD_UI_MESSAGE,
  METHOD_UI_UPDATE_MODEL_CONTEXT,
})

#: The display-mode enum shared by ``appCapabilities.availableDisplayModes``,
#: ``hostContext.displayMode``, and ``ui/request-display-mode`` (§26.5). A CLOSED
#: set matched verbatim.
DISPLAY_MODE_INLINE: str = "inline"
DISPLAY_MODE_FULLSCREEN: str = "fullscreen"
DISPLAY_MODE_PIP: str = "pip"
VALID_DISPLAY_MODES: frozenset[str] = frozenset({
  DISPLAY_MODE_INLINE,
  DISPLAY_MODE_FULLSCREEN,
  DISPLAY_MODE_PIP,
})


def is_dialect_name(name: Any) -> bool:
  """Return True iff ``name`` is a verbatim §26.6 dialect name (R-26.5-a).

  The match is exact and case-sensitive against :data:`DIALECT_NAMES`: a name
  differing only in case (``"UI/Initialize"``) or whitespace does NOT match, so a
  conformance check can flag any non-registry name (R-26.5-a / AC-42.1).
  """
  return isinstance(name, str) and name in DIALECT_NAMES


def dialect_entry(name: str) -> DialectName | None:
  """Return the §26.6 registry row for ``name``, or None when it is not a dialect name.

  A None result means ``name`` is not one of the 19 verbatim dialect names; a
  receiver that gets such a method as a request MUST answer method-not-found
  (§26.8, R-26.8-c) — see :func:`method_not_found_response`.
  """
  return DIALECT_REGISTRY.get(name)


def dialect_protocol_version_matches(version: Any) -> bool:
  """Return True iff ``version`` is exactly :data:`UI_DIALECT_PROTOCOL_VERSION` (R-26.5-b).

  The dialect-revision string is the exact value ``"2026-01-26"`` (§26.5); the
  comparison is verbatim and case-sensitive and is observably independent of the
  core revision ``"2026-07-28"`` negotiated at ``server/discover`` (R-26.5-b /
  AC-42.2): a value equal to the core revision does NOT match.
  """
  return version == UI_DIALECT_PROTOCOL_VERSION


# ---------------------------------------------------------------------------
# §26.5.1  Initialization handshake data structures  [R-26.5.1-a, R-26.5.1-b]
# ---------------------------------------------------------------------------

@dataclass
class UiInitializeParams:
  """Params of the ``ui/initialize`` request the UI sends to open the channel (§26.5.1).

  All members are OPTIONAL. The UI MUST NOT issue any other dialect message
  before it has received the response to ``ui/initialize`` (R-26.5.1-a) — see
  :class:`HandshakeState`.

  Fields:
    protocol_version: OPTIONAL dialect revision the UI implements, e.g.
      :data:`UI_DIALECT_PROTOCOL_VERSION`. Wire key: ``protocolVersion``.
    client_info: OPTIONAL UI identity ``{name, version}``. Wire key:
      ``clientInfo``.
    app_capabilities: OPTIONAL capabilities the UI offers — ``experimental``,
      ``tools`` (``{listChanged?}``), and ``availableDisplayModes`` (an array of
      the :data:`VALID_DISPLAY_MODES` enum). Wire key: ``appCapabilities``.
  """

  protocol_version: str | None = None         # JSON: protocolVersion
  client_info: dict[str, Any] | None = None   # JSON: clientInfo
  app_capabilities: dict[str, Any] | None = None  # JSON: appCapabilities

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> UiInitializeParams:
    """Parse a wire ``ui/initialize`` params object (§26.5.1). Unknown keys ignored."""
    if not isinstance(data, dict):
      raise TypeError(
        f"UiInitializeParams must be a JSON object; got {type(data).__name__} "
        f"(§26.5.1)"
      )
    return cls(
      protocol_version=data.get("protocolVersion"),
      client_info=data.get("clientInfo"),
      app_capabilities=data.get("appCapabilities"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire params object; omits absent (None) members."""
    out: dict[str, Any] = {}
    if self.protocol_version is not None:
      out["protocolVersion"] = self.protocol_version
    if self.client_info is not None:
      out["clientInfo"] = self.client_info
    if self.app_capabilities is not None:
      out["appCapabilities"] = self.app_capabilities
    return out


@dataclass
class UiHostContext:
  """The rendering environment the host delivers to the UI (§26.5.1).

  Carried as ``hostContext`` in :class:`UiInitializeResult` and, as a *partial*
  (only the changed members), as the params of
  ``ui/notifications/host-context-changed`` (§26.5.4). Every member is OPTIONAL;
  only the tool input/result the UI was rendered for and host context explicitly
  delivered here are made available to the UI (R-26.7-m).

  Fields mirror the §26.5.1 ``UiHostContext`` shape; wire keys differ from the
  snake_case attribute names where noted.
  """

  tool_info: dict[str, Any] | None = None            # JSON: toolInfo
  theme: str | None = None
  styles: dict[str, Any] | None = None
  display_mode: str | None = None                    # JSON: displayMode
  available_display_modes: list[str] | None = None   # JSON: availableDisplayModes
  container_dimensions: dict[str, Any] | None = None  # JSON: containerDimensions
  locale: str | None = None
  time_zone: str | None = None                       # JSON: timeZone
  user_agent: str | None = None                      # JSON: userAgent
  platform: str | None = None
  device_capabilities: dict[str, Any] | None = None  # JSON: deviceCapabilities
  safe_area_insets: dict[str, Any] | None = None     # JSON: safeAreaInsets

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> UiHostContext:
    """Parse a wire ``UiHostContext`` object (§26.5.1). Unknown keys ignored.

    The same parser handles the full initial context and the partial used in
    ``ui/notifications/host-context-changed`` (only the changed members present).
    """
    if not isinstance(data, dict):
      raise TypeError(
        f"UiHostContext must be a JSON object; got {type(data).__name__} "
        f"(§26.5.1)"
      )
    return cls(
      tool_info=data.get("toolInfo"),
      theme=data.get("theme"),
      styles=data.get("styles"),
      display_mode=data.get("displayMode"),
      available_display_modes=data.get("availableDisplayModes"),
      container_dimensions=data.get("containerDimensions"),
      locale=data.get("locale"),
      time_zone=data.get("timeZone"),
      user_agent=data.get("userAgent"),
      platform=data.get("platform"),
      device_capabilities=data.get("deviceCapabilities"),
      safe_area_insets=data.get("safeAreaInsets"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire object; omits absent (None) members."""
    out: dict[str, Any] = {}
    for wire_key, value in (
      ("toolInfo", self.tool_info),
      ("theme", self.theme),
      ("styles", self.styles),
      ("displayMode", self.display_mode),
      ("availableDisplayModes", self.available_display_modes),
      ("containerDimensions", self.container_dimensions),
      ("locale", self.locale),
      ("timeZone", self.time_zone),
      ("userAgent", self.user_agent),
      ("platform", self.platform),
      ("deviceCapabilities", self.device_capabilities),
      ("safeAreaInsets", self.safe_area_insets),
    ):
      if value is not None:
        out[wire_key] = value
    return out


@dataclass
class UiSandboxReport:
  """The ``hostCapabilities.sandbox`` report in the initialize result (§26.5.1, §26.7).

  Reports back to the UI the *effective* sandbox policy the host applied: the
  permissions actually granted and the content-security policy in force. The
  granted ``permissions`` MUST NOT include any capability the resource did not
  request (R-26.7-h), and ``csp`` reports the effective policy the host applied
  (R-26.7-g).

  Fields:
    permissions: a S41 :class:`UiPermissions` reporting the granted set, or None.
    csp: a S41 :class:`UiContentSecurityPolicy` reporting the effective policy,
      or None.
  """

  permissions: UiPermissions | None = None
  csp: UiContentSecurityPolicy | None = None

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> UiSandboxReport:
    """Parse a wire ``sandbox`` object (§26.5.1). Reuses S41 hint shapes."""
    if not isinstance(data, dict):
      raise TypeError(
        f"sandbox must be a JSON object; got {type(data).__name__} (§26.5.1)"
      )
    raw_perms = data.get("permissions")
    raw_csp = data.get("csp")
    return cls(
      permissions=UiPermissions.from_dict(raw_perms) if raw_perms is not None else None,
      csp=UiContentSecurityPolicy.from_dict(raw_csp) if raw_csp is not None else None,
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire ``sandbox`` object; omits absent members."""
    out: dict[str, Any] = {}
    if self.permissions is not None:
      out["permissions"] = self.permissions.to_dict()
    if self.csp is not None:
      out["csp"] = self.csp.to_dict()
    return out


class InvalidUiInitializeResultError(ValueError):
  """A ``ui/initialize`` result is malformed: ``protocolVersion`` is missing (§26.5.1).

  ``UiInitializeResult.protocolVersion`` is REQUIRED (R-26.5.1-b); its absence is
  a conformance failure (AC-42.4). Raised by :meth:`UiInitializeResult.from_dict`
  and the :class:`UiInitializeResult` constructor.
  """


@dataclass
class UiInitializeResult:
  """The host's reply to ``ui/initialize`` (§26.5.1).

  Carries the host identity, capabilities, and the initial rendering context.

  Fields:
    protocol_version: REQUIRED dialect revision, e.g.
      :data:`UI_DIALECT_PROTOCOL_VERSION` (R-26.5.1-b). A non-string/absent value
      is rejected. Wire key: ``protocolVersion``.
    host_info: OPTIONAL host identity ``{name, version}``. Wire key: ``hostInfo``.
    host_capabilities: OPTIONAL host capabilities — ``experimental``,
      ``openLinks`` (present iff the host honors ``ui/open-link``),
      ``serverTools``, ``serverResources``, ``logging``, and ``sandbox``
      (a :class:`UiSandboxReport`). Wire key: ``hostCapabilities``.
    host_context: OPTIONAL initial :class:`UiHostContext`. Wire key:
      ``hostContext``.
  """

  protocol_version: str
  host_info: dict[str, Any] | None = None            # JSON: hostInfo
  host_capabilities: dict[str, Any] | None = None    # JSON: hostCapabilities
  host_context: UiHostContext | None = None          # JSON: hostContext

  def __post_init__(self) -> None:
    # R-26.5.1-b: protocolVersion is REQUIRED and is a string.
    if not isinstance(self.protocol_version, str) or not self.protocol_version:
      raise InvalidUiInitializeResultError(
        "UiInitializeResult.protocolVersion is REQUIRED and must be a non-empty "
        "string carrying the dialect revision (R-26.5.1-b)"
      )

  @property
  def sandbox(self) -> UiSandboxReport | None:
    """The parsed ``hostCapabilities.sandbox`` report, or None when absent (§26.7).

    Surfaces the effective sandbox policy reported to the UI: ``csp`` is the
    effective policy the host applied (R-26.7-g) and ``permissions`` is exactly
    the granted set (R-26.7-h).
    """
    if not isinstance(self.host_capabilities, dict):
      return None
    raw = self.host_capabilities.get("sandbox")
    if not isinstance(raw, dict):
      return None
    return UiSandboxReport.from_dict(raw)

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> UiInitializeResult:
    """Parse a wire ``ui/initialize`` result object (§26.5.1).

    Validates that ``protocolVersion`` is present (R-26.5.1-b); its absence is a
    conformance failure (AC-42.4). Unknown keys are ignored.

    Raises:
      InvalidUiInitializeResultError: ``protocolVersion`` is absent or not a
        string.
    """
    if not isinstance(data, dict):
      raise InvalidUiInitializeResultError(
        f"UiInitializeResult must be a JSON object; got {type(data).__name__} "
        f"(R-26.5.1-b)"
      )
    if "protocolVersion" not in data:
      raise InvalidUiInitializeResultError(
        "UiInitializeResult.protocolVersion is REQUIRED; its absence is a "
        "conformance failure (R-26.5.1-b / AC-42.4)"
      )
    raw_context = data.get("hostContext")
    return cls(
      protocol_version=data["protocolVersion"],
      host_info=data.get("hostInfo"),
      host_capabilities=data.get("hostCapabilities"),
      host_context=UiHostContext.from_dict(raw_context) if raw_context is not None else None,
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire result object; omits absent (None) members."""
    out: dict[str, Any] = {"protocolVersion": self.protocol_version}
    if self.host_info is not None:
      out["hostInfo"] = self.host_info
    if self.host_capabilities is not None:
      out["hostCapabilities"] = self.host_capabilities
    if self.host_context is not None:
      out["hostContext"] = self.host_context.to_dict()
    return out


# -- §26.5.1  Handshake-ordering guard  [R-26.5.1-a] --

class HandshakeOrderError(RuntimeError):
  """The UI emitted a dialect message before the ``ui/initialize`` response (§26.5.1).

  Raised by :meth:`HandshakeState.before_send` when the UI attempts to send any
  dialect message other than ``ui/initialize`` itself before it has received the
  initialize response, or attempts ``ui/notifications/initialized`` before the
  response arrives (R-26.5.1-a / AC-42.3).
  """


class HandshakeState:
  """Tracks the §26.5.1 handshake ordering on the UI side (R-26.5.1-a).

  Enforces the strict order: the UI sends ``ui/initialize``; the host replies
  with the initialize result; the UI then sends ``ui/notifications/initialized``.
  The UI MUST NOT issue any other dialect message before it has received the
  response to ``ui/initialize`` (R-26.5.1-a). This is a host/conformance-side
  guard a UI runtime (or a conformance suite verifying a UI) uses to detect a
  premature message (AC-42.3).
  """

  def __init__(self) -> None:
    self._initialize_sent: bool = False
    self._response_received: bool = False

  @property
  def response_received(self) -> bool:
    """True once the host's ``ui/initialize`` response has been observed."""
    return self._response_received

  def before_send(self, method: str) -> None:
    """Assert the UI may send ``method`` now, given handshake progress (R-26.5.1-a).

    The first message the UI may send is ``ui/initialize``. Until the response is
    received, the ONLY further permitted message is — once the response arrives —
    ``ui/notifications/initialized``. Any other dialect message sent before the
    response is a violation (AC-42.3).

    Raises:
      HandshakeOrderError: a non-``ui/initialize`` message is sent before the
        response, or ``ui/notifications/initialized`` is sent before it.
    """
    if not self._response_received:
      if method == METHOD_UI_INITIALIZE and not self._initialize_sent:
        self._initialize_sent = True
        return
      raise HandshakeOrderError(
        f"the UI MUST NOT issue any dialect message ({method!r}) before it has "
        f"received the response to {METHOD_UI_INITIALIZE!r} (R-26.5.1-a)"
      )

  def on_response(self) -> None:
    """Record that the host's ``ui/initialize`` response has been received.

    Raises:
      HandshakeOrderError: a response arrived before ``ui/initialize`` was sent.
    """
    if not self._initialize_sent:
      raise HandshakeOrderError(
        f"received a {METHOD_UI_INITIALIZE!r} response before the request was "
        f"sent (R-26.5.1-a)"
      )
    self._response_received = True

  def may_send_initialized(self) -> bool:
    """True iff ``ui/notifications/initialized`` may be sent now (after the response).

    ``ui/notifications/initialized`` is sent only after the initialize response
    arrives (R-26.5.1-a / AC-42.3).
    """
    return self._response_received


# ---------------------------------------------------------------------------
# §26.5.2  Host → UI delivery params  [ToolInput / ToolResult / ToolCancelled]
# ---------------------------------------------------------------------------

@dataclass
class ToolInputParams:
  """Params of ``ui/notifications/tool-input`` and ``-tool-input-partial`` (§26.5.2).

  The complete tool arguments (or, for the ``-partial`` variant, a streaming
  snapshot delivered before the complete input). Identical shape for both names.

  Fields:
    arguments: REQUIRED map of tool arguments.
  """

  arguments: dict[str, Any]

  def __post_init__(self) -> None:
    if not isinstance(self.arguments, dict):
      raise TypeError(
        "ToolInputParams.arguments is REQUIRED and must be an object/map "
        "(§26.5.2)"
      )

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> ToolInputParams:
    """Parse a wire tool-input params object (§26.5.2)."""
    if not isinstance(data, dict) or "arguments" not in data:
      raise TypeError(
        "tool-input params must be an object carrying `arguments` (§26.5.2)"
      )
    return cls(arguments=data["arguments"])

  def to_dict(self) -> dict[str, Any]:
    """Serialise to ``{"arguments": ...}`` (§26.5.2)."""
    return {"arguments": self.arguments}


@dataclass
class ToolResultParams:
  """Params of ``ui/notifications/tool-result`` — the §16 tool-result shape (§26.5.2).

  Carries the result of the tool the UI was rendered for. All members OPTIONAL;
  ``content`` blocks follow §14 (S21) and ``structuredContent`` follows §16.

  Fields:
    content: OPTIONAL array of content blocks (§14). Wire key: ``content``.
    structured_content: OPTIONAL structured tool result (any JSON value, §16).
      Wire key: ``structuredContent``.
    is_error: OPTIONAL flag marking a tool error. Wire key: ``isError``.
    meta: OPTIONAL result metadata. Wire key: ``_meta``.
  """

  content: list[dict[str, Any]] | None = None
  structured_content: Any = field(default=None)     # JSON: structuredContent
  is_error: bool | None = None                      # JSON: isError
  meta: dict[str, Any] | None = None                # JSON: _meta
  _has_structured: bool = field(default=False, init=False, repr=False, compare=False)

  def __post_init__(self) -> None:
    # structuredContent MAY legitimately be any JSON value including null, so we
    # cannot use None as "absent". Callers set it explicitly via from_dict.
    self._has_structured = self.structured_content is not None

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> ToolResultParams:
    """Parse a wire ``tool-result`` params object (§26.5.2). Unknown keys ignored."""
    if not isinstance(data, dict):
      raise TypeError(
        f"ToolResultParams must be a JSON object; got {type(data).__name__} "
        f"(§26.5.2)"
      )
    obj = cls(
      content=data.get("content"),
      structured_content=data.get("structuredContent"),
      is_error=data.get("isError"),
      meta=data.get("_meta"),
    )
    obj._has_structured = "structuredContent" in data
    return obj

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire params object; omits absent members.

    ``structuredContent`` is emitted iff it was explicitly provided (it MAY be
    any JSON value, including ``null``), tracked separately from None-as-absent.
    """
    out: dict[str, Any] = {}
    if self.content is not None:
      out["content"] = self.content
    if self._has_structured:
      out["structuredContent"] = self.structured_content
    if self.is_error is not None:
      out["isError"] = self.is_error
    if self.meta is not None:
      out["_meta"] = self.meta
    return out


@dataclass
class ToolCancelledParams:
  """Params of ``ui/notifications/tool-cancelled`` (§26.5.2).

  Fields:
    reason: REQUIRED human-readable reason the associated tool call was cancelled.
  """

  reason: str

  def __post_init__(self) -> None:
    if not isinstance(self.reason, str):
      raise TypeError(
        "ToolCancelledParams.reason is REQUIRED and must be a string (§26.5.2)"
      )

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> ToolCancelledParams:
    """Parse a wire ``tool-cancelled`` params object (§26.5.2)."""
    if not isinstance(data, dict) or "reason" not in data:
      raise TypeError(
        "tool-cancelled params must be an object carrying `reason` (§26.5.2)"
      )
    return cls(reason=data["reason"])

  def to_dict(self) -> dict[str, Any]:
    """Serialise to ``{"reason": ...}`` (§26.5.2)."""
    return {"reason": self.reason}


# ---------------------------------------------------------------------------
# §26.5.3  UI → Host request params  [tools/call, open-link, message, etc.]
# ---------------------------------------------------------------------------

@dataclass
class ToolsCallParams:
  """Params of the UI-initiated ``tools/call`` request — the §16 shape (§26.5.3).

  Asks the host to invoke a server tool on the UI's behalf. The host MUST mediate
  the request and obtain consent before routing it (R-26.5.3-a) and SHOULD reject
  it when the tool's effective ``visibility`` excludes ``"app"`` (R-26.5.3-b);
  see :func:`host_should_reject_app_call`.

  Fields:
    name: REQUIRED server tool name to invoke.
    arguments: OPTIONAL arguments map.
  """

  name: str
  arguments: dict[str, Any] | None = None

  def __post_init__(self) -> None:
    if not isinstance(self.name, str) or not self.name:
      raise TypeError(
        "ToolsCallParams.name is REQUIRED and must be a non-empty string "
        "(§26.5.3)"
      )

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> ToolsCallParams:
    """Parse a wire ``tools/call`` params object (§26.5.3)."""
    if not isinstance(data, dict) or "name" not in data:
      raise TypeError(
        "tools/call params must be an object carrying `name` (§26.5.3)"
      )
    return cls(name=data["name"], arguments=data.get("arguments"))

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire params object; omits absent ``arguments``."""
    out: dict[str, Any] = {"name": self.name}
    if self.arguments is not None:
      out["arguments"] = self.arguments
    return out


@dataclass
class OpenLinkParams:
  """Params of ``ui/open-link`` (§26.5.3). Result is an empty object ``{}``.

  Asks the host to open an external link. The host MAY decline and SHOULD confirm
  with the user before honoring it (R-26.5.3-d, R-26.7-l) — see
  :func:`host_should_confirm_open_link`.

  Fields:
    url: REQUIRED external link to open.
  """

  url: str

  def __post_init__(self) -> None:
    if not isinstance(self.url, str) or not self.url:
      raise TypeError(
        "OpenLinkParams.url is REQUIRED and must be a non-empty string (§26.5.3)"
      )

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> OpenLinkParams:
    """Parse a wire ``ui/open-link`` params object (§26.5.3)."""
    if not isinstance(data, dict) or "url" not in data:
      raise TypeError(
        "ui/open-link params must be an object carrying `url` (§26.5.3)"
      )
    return cls(url=data["url"])

  def to_dict(self) -> dict[str, Any]:
    """Serialise to ``{"url": ...}`` (§26.5.3)."""
    return {"url": self.url}


@dataclass
class UiMessageParams:
  """Params of ``ui/message`` — insert a user message (§26.5.3). Result is ``{}``.

  Asks the host to insert a message into the conversation on the user's behalf.
  The host SHOULD confirm with the user before inserting it (R-26.7-l) — see
  :func:`host_should_confirm_ui_message`.

  Fields:
    role: REQUIRED, always the exact string ``"user"``.
    content: REQUIRED ``{type: "text", text: string}`` content object.
  """

  role: str
  content: dict[str, Any]

  def __post_init__(self) -> None:
    if self.role != "user":
      raise ValueError(
        f"UiMessageParams.role MUST be the exact string 'user'; got "
        f"{self.role!r} (§26.5.3)"
      )
    if (
      not isinstance(self.content, dict)
      or self.content.get("type") != "text"
      or not isinstance(self.content.get("text"), str)
    ):
      raise ValueError(
        "UiMessageParams.content MUST be {type: 'text', text: <string>} "
        "(§26.5.3)"
      )

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> UiMessageParams:
    """Parse a wire ``ui/message`` params object (§26.5.3)."""
    if not isinstance(data, dict) or "role" not in data or "content" not in data:
      raise ValueError(
        "ui/message params must carry `role` and `content` (§26.5.3)"
      )
    return cls(role=data["role"], content=data["content"])

  def to_dict(self) -> dict[str, Any]:
    """Serialise to ``{"role": "user", "content": {...}}`` (§26.5.3)."""
    return {"role": self.role, "content": self.content}


@dataclass
class RequestDisplayModeParams:
  """Params of ``ui/request-display-mode`` (§26.5.3).

  Fields:
    mode: REQUIRED display mode the UI requests, one of :data:`VALID_DISPLAY_MODES`.
  """

  mode: str

  def __post_init__(self) -> None:
    if self.mode not in VALID_DISPLAY_MODES:
      raise ValueError(
        f"RequestDisplayModeParams.mode must be one of "
        f"{sorted(VALID_DISPLAY_MODES)}; got {self.mode!r} (§26.5.3)"
      )

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> RequestDisplayModeParams:
    """Parse a wire ``ui/request-display-mode`` params object (§26.5.3)."""
    if not isinstance(data, dict) or "mode" not in data:
      raise ValueError(
        "ui/request-display-mode params must carry `mode` (§26.5.3)"
      )
    return cls(mode=data["mode"])

  def to_dict(self) -> dict[str, Any]:
    """Serialise to ``{"mode": ...}`` (§26.5.3)."""
    return {"mode": self.mode}


@dataclass
class RequestDisplayModeResult:
  """Result of ``ui/request-display-mode`` (§26.5.3).

  The host MAY grant a different mode than requested; this result reports the
  mode actually applied (R-26.5.3-e / AC-42.9).

  Fields:
    mode: REQUIRED display mode the host actually applied, one of
      :data:`VALID_DISPLAY_MODES`.
  """

  mode: str

  def __post_init__(self) -> None:
    if self.mode not in VALID_DISPLAY_MODES:
      raise ValueError(
        f"RequestDisplayModeResult.mode must be one of "
        f"{sorted(VALID_DISPLAY_MODES)}; got {self.mode!r} (§26.5.3)"
      )

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> RequestDisplayModeResult:
    """Parse a wire ``ui/request-display-mode`` result object (§26.5.3)."""
    if not isinstance(data, dict) or "mode" not in data:
      raise ValueError(
        "ui/request-display-mode result must carry `mode` (§26.5.3)"
      )
    return cls(mode=data["mode"])

  def to_dict(self) -> dict[str, Any]:
    """Serialise to ``{"mode": ...}`` (§26.5.3)."""
    return {"mode": self.mode}


@dataclass
class UpdateModelContextParams:
  """Params of ``ui/update-model-context`` (§26.5.3). Result is ``{}``.

  Supplies content from the UI to be incorporated into the model's context for
  the conversation. All members OPTIONAL.

  Fields:
    content: OPTIONAL array of content blocks (§14). Wire key: ``content``.
    structured_content: OPTIONAL structured content (any JSON value, §16). Wire
      key: ``structuredContent``.
  """

  content: list[dict[str, Any]] | None = None
  structured_content: Any = field(default=None)     # JSON: structuredContent
  _has_structured: bool = field(default=False, init=False, repr=False, compare=False)

  def __post_init__(self) -> None:
    self._has_structured = self.structured_content is not None

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> UpdateModelContextParams:
    """Parse a wire ``ui/update-model-context`` params object (§26.5.3)."""
    if not isinstance(data, dict):
      raise TypeError(
        f"UpdateModelContextParams must be a JSON object; got "
        f"{type(data).__name__} (§26.5.3)"
      )
    obj = cls(
      content=data.get("content"),
      structured_content=data.get("structuredContent"),
    )
    obj._has_structured = "structuredContent" in data
    return obj

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire params object; omits absent members."""
    out: dict[str, Any] = {}
    if self.content is not None:
      out["content"] = self.content
    if self._has_structured:
      out["structuredContent"] = self.structured_content
    return out


@dataclass
class PingParams:
  """Params of ``ping`` (either direction) (§26.5.3). Carries no parameters.

  ``ping`` MAY be sent UI ↔ Host; it carries no parameters and yields an empty
  result; the receiver MUST respond promptly with a success response
  (R-26.5.3-f/g) — see :func:`ping_response`.
  """

  @classmethod
  def from_dict(cls, data: dict[str, Any] | None) -> PingParams:
    """Parse a wire ``ping`` params object (empty or absent) (§26.5.3)."""
    return cls()

  def to_dict(self) -> dict[str, Any]:
    """Serialise to an empty object ``{}`` (§26.5.3)."""
    return {}


# ---------------------------------------------------------------------------
# §26.5.4  Lifecycle / context-change params  [size-changed / teardown]
# ---------------------------------------------------------------------------

@dataclass
class SizeChangedParams:
  """Params of ``ui/notifications/size-changed`` (§26.5.4).

  Fields:
    width: REQUIRED new container width.
    height: REQUIRED new container height.
  """

  width: float
  height: float

  def __post_init__(self) -> None:
    for label, value in (("width", self.width), ("height", self.height)):
      if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(
          f"SizeChangedParams.{label} is REQUIRED and must be a number "
          f"(§26.5.4)"
        )

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> SizeChangedParams:
    """Parse a wire ``size-changed`` params object (§26.5.4)."""
    if not isinstance(data, dict) or "width" not in data or "height" not in data:
      raise TypeError(
        "size-changed params must carry `width` and `height` (§26.5.4)"
      )
    return cls(width=data["width"], height=data["height"])

  def to_dict(self) -> dict[str, Any]:
    """Serialise to ``{"width": ..., "height": ...}`` (§26.5.4)."""
    return {"width": self.width, "height": self.height}


@dataclass
class ResourceTeardownParams:
  """Params of the ``ui/resource-teardown`` request, Host → UI (§26.5.4).

  Asks the UI to tear down before the host removes it. On receiving it the UI
  SHOULD release resources and respond with an empty object ``{}`` (R-26.5.4-a) —
  see :func:`teardown_response`.

  Fields:
    reason: REQUIRED reason the UI is being torn down.
  """

  reason: str

  def __post_init__(self) -> None:
    if not isinstance(self.reason, str):
      raise TypeError(
        "ResourceTeardownParams.reason is REQUIRED and must be a string "
        "(§26.5.4)"
      )

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> ResourceTeardownParams:
    """Parse a wire ``ui/resource-teardown`` params object (§26.5.4)."""
    if not isinstance(data, dict) or "reason" not in data:
      raise TypeError(
        "ui/resource-teardown params must carry `reason` (§26.5.4)"
      )
    return cls(reason=data["reason"])

  def to_dict(self) -> dict[str, Any]:
    """Serialise to ``{"reason": ...}`` (§26.5.4)."""
    return {"reason": self.reason}


# ---------------------------------------------------------------------------
# §26.5.5  Host-internal sandbox-proxy params  [sandbox-resource-ready]
# ---------------------------------------------------------------------------

@dataclass
class SandboxResourceReadyParams:
  """Params of ``ui/notifications/sandbox-resource-ready``, Host → Sandbox (§26.5.5).

  Host-internal: delivers the resource HTML and the policy to apply into the
  sandbox proxy. Not exchanged with a server.

  Fields:
    html: REQUIRED UI document to render.
    sandbox: OPTIONAL sandbox token string to apply, if any.
    csp: OPTIONAL effective :class:`UiContentSecurityPolicy` (S41 shape).
    permissions: OPTIONAL granted :class:`UiPermissions` (S41 shape).
  """

  html: str
  sandbox: str | None = None
  csp: UiContentSecurityPolicy | None = None
  permissions: UiPermissions | None = None

  def __post_init__(self) -> None:
    if not isinstance(self.html, str):
      raise TypeError(
        "SandboxResourceReadyParams.html is REQUIRED and must be a string "
        "(§26.5.5)"
      )

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> SandboxResourceReadyParams:
    """Parse a wire ``sandbox-resource-ready`` params object (§26.5.5)."""
    if not isinstance(data, dict) or "html" not in data:
      raise TypeError(
        "sandbox-resource-ready params must carry `html` (§26.5.5)"
      )
    raw_csp = data.get("csp")
    raw_perms = data.get("permissions")
    return cls(
      html=data["html"],
      sandbox=data.get("sandbox"),
      csp=UiContentSecurityPolicy.from_dict(raw_csp) if raw_csp is not None else None,
      permissions=UiPermissions.from_dict(raw_perms) if raw_perms is not None else None,
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire params object; omits absent members."""
    out: dict[str, Any] = {"html": self.html}
    if self.sandbox is not None:
      out["sandbox"] = self.sandbox
    if self.csp is not None:
      out["csp"] = self.csp.to_dict()
    if self.permissions is not None:
      out["permissions"] = self.permissions.to_dict()
    return out


# ---------------------------------------------------------------------------
# §26.5.3 / §26.7  Mediation, consent, and visibility predicates
# ---------------------------------------------------------------------------

def host_must_mediate(method: str) -> bool:
  """Return True: the host MUST mediate every action the UI requests (R-26.7-i).

  The host stands between the UI and the rest of the system; every UI-initiated
  request is routed, policy-checked, and consent-gated by the host (R-26.5.3-a,
  R-26.7-i / AC-42.5). Mediation is unconditional for every UI → Host request, so
  this returns True for any such name; the argument documents that the conclusion
  does not depend on the specific method.
  """
  return True


def host_may_route_tools_call(*, consent_obtained: bool, policy_applied: bool) -> bool:
  """Return True iff the host may route a UI ``tools/call`` to the server (R-26.5.3-a, R-26.7-j).

  For a UI-initiated ``tools/call`` the host MUST obtain user consent and apply
  its policy *before* routing the call to the server (R-26.5.3-a, R-26.7-i/j). A
  path that reaches the server without prior consent and policy is a failure
  (AC-42.5): this returns True only when BOTH ``consent_obtained`` and
  ``policy_applied`` are True.

  Args:
    consent_obtained: True iff the host obtained user consent for the invocation.
    policy_applied: True iff the host applied its tool-execution policy.
  """
  return bool(consent_obtained) and bool(policy_applied)


def host_should_reject_app_call(ui_meta: _ToolUiMeta) -> bool:
  """Return True iff the host SHOULD reject a UI ``tools/call`` for non-app visibility (R-26.5.3-b, R-26.7-k).

  A host SHOULD reject a UI-initiated ``tools/call`` when the named tool's
  effective ``visibility`` (S41 §26.3) does not include ``"app"`` (R-26.5.3-b,
  R-26.7-k / AC-42.6). Delegates to S41's :func:`host_should_reject_ui_call`,
  which returns True exactly when the tool is NOT app-callable.

  Args:
    ui_meta: the tool's S41 :class:`ToolUiMeta` declaration.
  """
  return host_should_reject_ui_call(ui_meta)


def host_may_decline_resources_read() -> bool:
  """Return True: the host mediates a UI ``resources/read`` and MAY decline (R-26.5.3-c).

  For a UI-initiated ``resources/read`` the host mediates the request and MAY
  decline (R-26.5.3-c / AC-42.7). A decline is permitted, so this returns True;
  a declined request MUST be answered with a §22 error response rather than
  silently dropped (R-26.8-b) — see :func:`decline_response`.
  """
  return True


def host_may_decline_open_link() -> bool:
  """Return True: the host MAY decline a ``ui/open-link`` request (R-26.5.3-d).

  For ``ui/open-link`` the host MAY decline (R-26.5.3-d / AC-42.8). A decline is
  permitted; before honoring it the host SHOULD confirm with the user — see
  :func:`host_should_confirm_open_link`.
  """
  return True


def host_should_confirm_open_link() -> bool:
  """Return True: the host SHOULD confirm with the user before honoring ``ui/open-link`` (R-26.5.3-d, R-26.7-l).

  Before opening an external link the host SHOULD confirm with the user; a
  non-confirming auto-open is flagged (R-26.5.3-d, R-26.7-l / AC-42.8). This
  returns True to assert the confirmation obligation.
  """
  return True


def host_should_confirm_ui_message() -> bool:
  """Return True: the host SHOULD confirm before inserting a ``ui/message`` (R-26.7-l).

  Before inserting a ``ui/message`` into the conversation the host SHOULD confirm
  with the user (R-26.7-l). This returns True to assert the confirmation
  obligation.
  """
  return True


def host_applied_display_mode(
  requested: RequestDisplayModeParams,
  applied: str,
) -> RequestDisplayModeResult:
  """Return the ``ui/request-display-mode`` result reporting the applied mode (R-26.5.3-e).

  The host MAY grant a different mode than the UI requested; the result reports
  the mode actually applied, which may differ from ``requested.mode``
  (R-26.5.3-e / AC-42.9). ``applied`` MUST be one of :data:`VALID_DISPLAY_MODES`.

  Args:
    requested: the UI's :class:`RequestDisplayModeParams` (the requested mode).
    applied: the display mode the host actually applied.

  Returns:
    A :class:`RequestDisplayModeResult` carrying ``applied``.

  Raises:
    ValueError: ``applied`` is not a valid display mode.
  """
  return RequestDisplayModeResult(mode=applied)


# ---------------------------------------------------------------------------
# §26.5.3  ping  [R-26.5.3-f, R-26.5.3-g]
# ---------------------------------------------------------------------------

def ping_response(request_id: RequestId) -> JSONRPCResultResponse:
  """Build the empty success response a ``ping`` receiver MUST return promptly (R-26.5.3-g).

  ``ping`` MAY be sent in either direction (R-26.5.3-f); on receiving one the
  receiver MUST respond promptly with a success response carrying an empty result
  ``{}`` so the sender can confirm the peer is still live (R-26.5.3-g / AC-42.10).

  Args:
    request_id: the id of the ``ping`` request being answered (echoed, §3.5.1).
  """
  return JSONRPCResultResponse(id=request_id, result={})


# ---------------------------------------------------------------------------
# §26.5.4  teardown  [R-26.5.4-a]
# ---------------------------------------------------------------------------

def teardown_response(request_id: RequestId) -> JSONRPCResultResponse:
  """Build the empty success response to a ``ui/resource-teardown`` request (R-26.5.4-a).

  On a teardown request the UI SHOULD release its resources and respond with an
  empty object ``{}`` (R-26.5.4-a / AC-42.11). This builds that response; the
  actual resource release is the UI runtime's job.

  Args:
    request_id: the id of the teardown request being answered (echoed, §3.5.1).
  """
  return JSONRPCResultResponse(id=request_id, result={})


# ---------------------------------------------------------------------------
# §26.7  Security and consent (host) — auditable predicates
# ---------------------------------------------------------------------------

#: The access a host's sandboxed, isolated browsing context MUST deny the
#: rendered UI (§26.7 Sandboxing, R-26.7-a): the embedding document's DOM, its
#: cookies, its storage, and its navigation. Provided as an auditable set so a
#: conformance suite can assert each is denied (AC-42.12).
SANDBOX_DENIED_ACCESS: frozenset[str] = frozenset({
  "dom",
  "cookies",
  "storage",
  "navigation",
})

#: The categories of data a host MUST NOT expose to the rendered UI (§26.7 No
#: credential or context leakage, R-26.7-m): credentials, authorization tokens
#: (§23), and conversation/context data unrelated to the rendered UI. A
#: conformance suite asserts none of these reach the UI (AC-42.17).
FORBIDDEN_UI_DATA: frozenset[str] = frozenset({
  "credentials",
  "authorization_tokens",
  "unrelated_conversation_context",
})

#: The ONLY data legitimately made available to the rendered UI (§26.7,
#: R-26.7-m): the tool input and result the UI was rendered for, and host context
#: explicitly delivered through the dialect. Anything outside this set is a leak.
ALLOWED_UI_DATA: frozenset[str] = frozenset({
  "tool_input",
  "tool_result",
  "host_context",
})


def host_must_sandbox_rendered_ui() -> bool:
  """Return True: every UI resource MUST run in a sandboxed, isolated context (R-26.7-a).

  The host MUST render every UI resource in a sandboxed, isolated browsing
  context that denies the content access to the embedding document's DOM,
  cookies, storage, and navigation (R-26.7-a / AC-42.12) — the set
  :data:`SANDBOX_DENIED_ACCESS`. Unconditional host obligation; always True.
  """
  return True


def sandbox_denies_access(access: str) -> bool:
  """Return True iff a conforming sandbox denies ``access`` to the rendered UI (R-26.7-a).

  Membership test against :data:`SANDBOX_DENIED_ACCESS`: the sandbox denies the
  embedding document's DOM, cookies, storage, and navigation (R-26.7-a /
  AC-42.12). Any other token is not among the enumerated denied accesses.
  """
  return access in SANDBOX_DENIED_ACCESS


def rendered_content_can_escape_sandbox() -> bool:
  """Return False: rendered content MUST NOT escape the sandbox (R-26.7-b).

  The rendered content MUST NOT be able to escape the sandbox to reach host or
  user state (R-26.7-b / AC-42.12). A conforming host permits no escape, so this
  invariant always returns False.
  """
  return False


def only_channel_is_dialect() -> bool:
  """Return True: the §26.5 dialect is the ONLY UI ↔ host path (R-26.7-c).

  The only path between the rendered UI and the host is the §26.5 message-channel
  dialect; the host MUST NOT grant the UI ambient access to host or user data
  through any other path (R-26.7-c / AC-42.13). This returns True to assert that
  the dialect channel is the sole interaction surface.
  """
  return True


def host_grants_ambient_access() -> bool:
  """Return False: the host grants the UI NO ambient access to host/user data (R-26.7-c).

  The host MUST NOT grant the UI ambient access to host or user data through any
  path other than the §26.5 dialect (R-26.7-c / AC-42.13). A conforming host
  grants no such ambient access, so this always returns False.
  """
  return False


def host_must_apply_csp() -> bool:
  """Return True: the host MUST apply a content-security policy (R-26.7-d).

  The host MUST apply a content-security policy to the rendered content
  (R-26.7-d / AC-42.14). Unconditional host obligation; always True. The concrete
  origin allow/deny test is :func:`host_blocks_origin`.
  """
  return True


def host_blocks_origin(
  origin: str,
  member: str,
  csp: UiContentSecurityPolicy | None,
) -> bool:
  """Return True iff the host MUST block ``origin`` for CSP ``member`` (R-26.7-e/f).

  When the resource declares a ``csp`` descriptor (S41 §26.4), the host MUST
  constrain the UI to exactly the declared origins: any origin not present in the
  applicable ``csp`` member MUST be blocked (R-26.7-e). When no ``csp`` is
  declared (``None``), the host applies a restrictive deny-by-default policy that
  blocks all external origins, so EVERY origin is blocked here (R-26.7-f /
  AC-42.14). Thus this returns True unless ``csp`` is present and ``origin`` is
  listed in ``member``.

  Args:
    origin: the origin the UI is attempting to use.
    member: the CSP member governing the attempt (e.g. ``"connectDomains"``).
    csp: the resource's declared S41 CSP, or ``None`` when omitted.
  """
  if csp is None:
    return True  # deny-by-default when csp omitted (R-26.7-f)
  return not csp.origin_allowed(member, origin)


def host_default_policy_is_deny(csp: UiContentSecurityPolicy | None) -> bool:
  """Return True iff the host applies deny-by-default — i.e. ``csp`` omitted (R-26.7-f).

  When no ``csp`` is declared the host MUST apply a restrictive deny-by-default
  policy that blocks all external origins except those it explicitly permits
  (R-26.7-f / AC-42.14). The policy is deny-by-default exactly when no CSP
  descriptor is present.
  """
  return csp is None


def effective_csp_reported(result: UiInitializeResult) -> UiContentSecurityPolicy | None:
  """Return the effective CSP the host reported in the initialize result (R-26.7-g).

  The effective policy the host applied is reported back to the UI in the
  ``hostCapabilities.sandbox.csp`` field of the initialize result (R-26.7-g /
  AC-42.15). Returns the reported :class:`UiContentSecurityPolicy`, or None when
  no sandbox/csp was reported.

  Args:
    result: the host's :class:`UiInitializeResult`.
  """
  report = result.sandbox
  return report.csp if report is not None else None


def granted_permissions_reported(result: UiInitializeResult) -> UiPermissions | None:
  """Return the granted permissions reported in the initialize result (R-26.7-g/h).

  The set of permissions actually granted is reported in
  ``hostCapabilities.sandbox.permissions`` (R-26.7-h / AC-42.15). Returns the
  reported :class:`UiPermissions`, or None when none was reported.

  Args:
    result: the host's :class:`UiInitializeResult`.
  """
  report = result.sandbox
  return report.permissions if report is not None else None


def host_grant_respects_request(
  granted: UiPermissions | None,
  requested: UiPermissions | None,
) -> bool:
  """Return True iff every granted permission was requested (R-26.7-h).

  The host MUST NOT grant any sandbox permission that the resource did not
  request (R-26.7-h / AC-42.15, AC-42.16): the granted set MUST be a subset of
  the requested set. The host MAY decline a requested permission (so a proper
  subset is fine). An empty/absent grant always satisfies the rule.

  Args:
    granted: the permissions the host actually granted (or None for none).
    requested: the permissions the resource requested (or None for none).
  """
  granted_set = granted.requested() if granted is not None else frozenset()
  requested_set = requested.requested() if requested is not None else frozenset()
  return granted_set <= requested_set


def host_may_grant_permission(
  capability: str,
  requested: UiPermissions | None,
) -> bool:
  """Return True iff the host MAY grant ``capability`` — i.e. it was requested (R-26.7-h).

  The host MUST NOT grant a sandbox permission that the resource did not request
  (R-26.7-h / AC-42.16): when ``requested`` is omitted, or does not request
  ``capability``, this returns False. When the capability IS requested the host
  MAY grant it — but MAY also decline (a host policy decision this predicate does
  not force). A True result means "grant is permitted", never "grant is required".

  Args:
    capability: the wire member name (e.g. ``"camera"``).
    requested: the resource's requested S41 :class:`UiPermissions`, or None.
  """
  if requested is None:
    return False
  return requested.is_requested(capability)


def ui_data_is_permitted(category: str) -> bool:
  """Return True iff ``category`` of data may be exposed to the rendered UI (R-26.7-m).

  Only the tool input and result the UI was rendered for, and host context
  explicitly delivered through the dialect, are made available to the UI — the
  set :data:`ALLOWED_UI_DATA`. Credentials, authorization tokens (§23), and
  unrelated conversation/context data MUST NOT be exposed (R-26.7-m / AC-42.17).
  Returns True only for a member of :data:`ALLOWED_UI_DATA`.
  """
  return category in ALLOWED_UI_DATA


def ui_data_is_forbidden(category: str) -> bool:
  """Return True iff ``category`` MUST NOT be exposed to the rendered UI (R-26.7-m).

  Membership test against :data:`FORBIDDEN_UI_DATA`: credentials, authorization
  tokens (§23), and conversation/context data unrelated to the rendered UI MUST
  NOT be exposed to the UI (R-26.7-m / AC-42.17).
  """
  return category in FORBIDDEN_UI_DATA


def host_treats_rendered_content_as_untrusted() -> bool:
  """Return True: the host MUST treat the rendered content as untrusted (R-26.7-o).

  The host MUST treat the rendered content as untrusted (R-26.7-o / AC-42.18).
  Unconditional host obligation; always True. The companion validation obligation
  is :func:`host_validate_incoming_message`.
  """
  return True


def host_validate_incoming_message(raw: Any) -> Any:
  """Validate an incoming dialect message against §3 framing before acting (R-26.7-n).

  The host MUST validate every incoming dialect message against the §3 JSON-RPC
  framing before acting on it, treating the rendered content as untrusted
  (R-26.7-n/o / AC-42.18). This delegates the framing validation to S03's
  :func:`classify_message`, returning the typed message on success and raising
  S03's ``FramingError`` on any framing violation — so a host never acts on an
  unvalidated message.

  Args:
    raw: a JSON-decoded incoming message.

  Returns:
    The typed S03 message (request / notification / response).

  Raises:
    FramingError: the message violates §3 JSON-RPC framing (from S03).
  """
  return classify_message(raw)


# ---------------------------------------------------------------------------
# §26.8  Error-handling contract  [R-26.8-a, R-26.8-b, R-26.8-c]
# ---------------------------------------------------------------------------

class DeclineReason(Enum):
  """Why a host declines a UI-initiated request (§26.8).

  A host that declines a UI-initiated ``tools/call``, ``resources/read``,
  ``ui/open-link``, ``ui/message``, or ``ui/update-model-context`` — whether for
  lack of consent, policy, or an unknown method — MUST return an error response
  with an appropriate §22 code rather than silently dropping the request
  (R-26.8-b / AC-42.20). The reason selects the §22 code.
  """

  NO_CONSENT = "no_consent"
  POLICY = "policy"
  UNKNOWN_METHOD = "unknown_method"


#: Maps a §26.8 decline reason to the §22 error code used (R-26.8-b). An unknown
#: method maps to method-not-found (-32601, R-26.8-c); lack of consent or policy
#: rejection is reported with invalid-params (-32602, §22.4) — a well-formed
#: request the host refuses to act on. The codes are owned by S34; never
#: re-defined here.
_DECLINE_REASON_CODE: dict[DeclineReason, int] = {
  DeclineReason.NO_CONSENT: INVALID_PARAMS_CODE,
  DeclineReason.POLICY: INVALID_PARAMS_CODE,
  DeclineReason.UNKNOWN_METHOD: METHOD_NOT_FOUND_CODE,
}


def requires_error_on_decline(method: str) -> bool:
  """Return True iff declining a UI ``method`` MUST be answered with an error (R-26.8-b).

  A host that declines a UI-initiated ``tools/call``, ``resources/read``,
  ``ui/open-link``, ``ui/message``, or ``ui/update-model-context`` MUST return an
  error response rather than silently dropping it (R-26.8-b / AC-42.20). Returns
  True for any member of :data:`DECLINABLE_UI_REQUESTS`.
  """
  return method in DECLINABLE_UI_REQUESTS


def build_dialect_error(
  reason: DeclineReason,
  message: str,
  *,
  data: Any = None,
) -> ErrorObject:
  """Build the §22 :class:`ErrorObject` for a declined dialect request (R-26.8-a/b/c).

  Maps the :class:`DeclineReason` to the appropriate §22 code via S34's registry:
  an unknown method ⇒ method-not-found (-32601, R-26.8-c); lack of consent or a
  policy refusal ⇒ invalid-params (-32602, §22.4). The ``message`` is
  informational (never parsed, §22.1-j) and ``data`` is OPTIONAL.

  Args:
    reason: why the request was declined.
    message: a concise human-readable description.
    data: OPTIONAL sender-defined structured data.

  Returns:
    An :class:`ErrorObject` with the §22 code for ``reason``.
  """
  code = _DECLINE_REASON_CODE[reason]
  if data is None:
    return ErrorObject(code=code, message=message)
  return ErrorObject(code=code, message=message, data=data)


def decline_response(
  request_id: RequestId,
  reason: DeclineReason,
  message: str,
  *,
  data: Any = None,
) -> JSONRPCErrorResponse:
  """Build the §22 error *response* a host returns when it declines a UI request (R-26.8-a/b).

  A declined UI-initiated request (for consent, policy, or unknown method) MUST
  be answered with a JSON-RPC error response per §3 and §22 — never silently
  dropped (R-26.8-a/b / AC-42.19, AC-42.20). The response echoes the request id
  (§3.5.2) and carries the §22 error for ``reason``.

  Args:
    request_id: the id of the declined request (echoed, §3.5.2).
    reason: why the request was declined.
    message: a concise human-readable description.
    data: OPTIONAL sender-defined structured data.
  """
  error = build_dialect_error(reason, message, data=data)
  return JSONRPCErrorResponse(id=request_id, error=error.to_dict())


def method_not_found_response(
  request_id: RequestId,
  method: str,
) -> JSONRPCErrorResponse:
  """Build the §22 method-not-found error for an unimplemented dialect method (R-26.8-c).

  A receiver that gets a dialect request whose method it does not implement MUST
  respond with the method-not-found error (-32601) defined in §22 (R-26.8-c /
  AC-42.21). The response echoes the request id (§3.5.2).

  Args:
    request_id: the id of the unimplemented request (echoed, §3.5.2).
    method: the unrecognised method name (surfaced in the message, never parsed).
  """
  error = ErrorObject(
    code=METHOD_NOT_FOUND_CODE,
    message=f"Method not found: {method!r}",
  )
  return JSONRPCErrorResponse(id=request_id, error=error.to_dict())


def is_silent_drop_conformant(*, request_declined: bool, error_sent: bool) -> bool:
  """Return True iff a declined request was handled conformantly (not dropped) (R-26.8-b).

  A declined UI-initiated request MUST be answered with an error response and
  MUST NOT be silently dropped (R-26.8-b / AC-42.20). A handling is conformant
  when the request was not declined, OR it was declined and an error was sent;
  it is NON-conformant exactly when the request was declined but no error was
  sent (the silent-drop failure).

  Args:
    request_declined: True iff the host declined the request.
    error_sent: True iff the host sent an error response for it.
  """
  if not request_declined:
    return True
  return error_sent


def is_dialect_error_response(response: Any) -> bool:
  """Return True iff ``response`` is a JSON-RPC error response per §3/§22 (R-26.8-a).

  A failed dialect request is answered with a JSON-RPC error response carrying an
  ``error`` member and no ``result`` (R-26.8-a / AC-42.19). Accepts either a S03
  :class:`JSONRPCErrorResponse` or a raw response dict.
  """
  if isinstance(response, JSONRPCErrorResponse):
    return True
  if isinstance(response, dict):
    return "error" in response and "result" not in response
  return False


# ---------------------------------------------------------------------------
# §26.9  SDK scope summary  [R-26.9-a…d]
# ---------------------------------------------------------------------------

class SdkScopeRole(Enum):
  """Which side an §26.9 obligation belongs to (server SDK vs host/client).

  §26.9 splits the extension's obligations: acknowledging the extension,
  declaring ``_meta.ui``, and serving the ``ui://`` resource are SERVER-SDK
  obligations (R-26.9-a/b/c); rendering/sandboxing, running the dialect runtime,
  and obtaining consent are HOST/client concerns and NOT server-SDK obligations
  (R-26.9-d / AC-42.25).
  """

  SERVER_SDK = "server-sdk"
  HOST_CLIENT = "host-client"


#: The §26.9 obligation split, keyed by a short obligation token (R-26.9-a…d).
#: Provided as an auditable map so a conformance suite can assert each obligation
#: is attributed to the correct side (AC-42.22…AC-42.25).
SDK_SCOPE_ASSIGNMENT: dict[str, SdkScopeRole] = {
  # Server-SDK obligations (R-26.9-a/b/c).
  "acknowledge_extension": SdkScopeRole.SERVER_SDK,   # R-26.9-a (AC-42.22)
  "declare_meta_ui": SdkScopeRole.SERVER_SDK,         # R-26.9-b (AC-42.23)
  "serve_ui_resource": SdkScopeRole.SERVER_SDK,       # R-26.9-c (AC-42.24)
  # Host/client concerns — NOT server-SDK obligations (R-26.9-d).
  "render_sandbox": SdkScopeRole.HOST_CLIENT,         # R-26.9-d (AC-42.25)
  "enforce_csp_permissions": SdkScopeRole.HOST_CLIENT,  # R-26.9-d (AC-42.25)
  "run_dialect_runtime": SdkScopeRole.HOST_CLIENT,    # R-26.9-d (AC-42.25)
  "obtain_user_consent": SdkScopeRole.HOST_CLIENT,    # R-26.9-d (AC-42.25)
}

#: The obligations a server SDK explicitly does NOT carry (R-26.9-d): rendering,
#: sandboxing, CSP/permission enforcement, running the dialect runtime, and
#: obtaining consent. These are host/client concerns (AC-42.25).
SERVER_SDK_NON_OBLIGATIONS: frozenset[str] = frozenset({
  "render_sandbox",
  "enforce_csp_permissions",
  "run_dialect_runtime",
  "obtain_user_consent",
})


def sdk_scope_of(obligation: str) -> SdkScopeRole:
  """Return the side that owns ``obligation`` under §26.9 (R-26.9-a…d).

  Looks the obligation up in :data:`SDK_SCOPE_ASSIGNMENT`, making the obligation
  split auditable: acknowledging/declaring/serving is the SERVER SDK's
  (R-26.9-a/b/c), while rendering, CSP/permission enforcement, running the
  dialect runtime, and consent are host/client concerns (R-26.9-d).

  Raises:
    KeyError: ``obligation`` is not one of the §26.9 obligations.
  """
  return SDK_SCOPE_ASSIGNMENT[obligation]


def is_server_sdk_obligation(obligation: str) -> bool:
  """Return True iff ``obligation`` is a server-SDK obligation (R-26.9-a/b/c/d).

  Acknowledging the extension, declaring ``_meta.ui``, and serving the ``ui://``
  resource are server-SDK obligations (R-26.9-a/b/c). Rendering, CSP/permission
  enforcement, running the dialect runtime, and consent are NOT (R-26.9-d /
  AC-42.25) — they are host/client concerns — so this returns False for those. An
  unknown obligation token is treated as not a server-SDK obligation.
  """
  return SDK_SCOPE_ASSIGNMENT.get(obligation) is SdkScopeRole.SERVER_SDK


def server_sdk_runs_dialect_runtime() -> bool:
  """Return False: running the dialect runtime is NOT a server-SDK obligation (R-26.9-d).

  Rendering the UI in a sandbox, enforcing CSP/permissions, running the
  message-channel dialect runtime (handshake, tool input/result delivery,
  mediation, lifecycle, teardown), and obtaining consent are host/client concerns
  and are NOT obligations of a server SDK (R-26.9-d / AC-42.25). A conforming
  server SDK does not run the runtime, so this always returns False — which is
  why this module has no rendering/browser/UI-toolkit dependency.
  """
  return False


__all__ = [
  # §26.5 / §26.6  framing, versioning, and the name registry
  "UI_DIALECT_PROTOCOL_VERSION",
  "METHOD_UI_INITIALIZE",
  "NOTIFICATION_UI_INITIALIZED",
  "NOTIFICATION_TOOL_INPUT",
  "NOTIFICATION_TOOL_INPUT_PARTIAL",
  "NOTIFICATION_TOOL_RESULT",
  "NOTIFICATION_TOOL_CANCELLED",
  "METHOD_TOOLS_CALL",
  "METHOD_RESOURCES_READ",
  "METHOD_UI_OPEN_LINK",
  "METHOD_UI_MESSAGE",
  "METHOD_UI_REQUEST_DISPLAY_MODE",
  "METHOD_UI_UPDATE_MODEL_CONTEXT",
  "NOTIFICATION_MESSAGE",
  "METHOD_PING",
  "NOTIFICATION_SIZE_CHANGED",
  "NOTIFICATION_HOST_CONTEXT_CHANGED",
  "METHOD_UI_RESOURCE_TEARDOWN",
  "NOTIFICATION_SANDBOX_PROXY_READY",
  "NOTIFICATION_SANDBOX_RESOURCE_READY",
  "DialectKind",
  "DialectSender",
  "DialectName",
  "DIALECT_REGISTRY",
  "DIALECT_NAMES",
  "DECLINABLE_UI_REQUESTS",
  "DISPLAY_MODE_INLINE",
  "DISPLAY_MODE_FULLSCREEN",
  "DISPLAY_MODE_PIP",
  "VALID_DISPLAY_MODES",
  "is_dialect_name",
  "dialect_entry",
  "dialect_protocol_version_matches",
  # §26.5.1  handshake
  "UiInitializeParams",
  "UiHostContext",
  "UiSandboxReport",
  "UiInitializeResult",
  "InvalidUiInitializeResultError",
  "HandshakeOrderError",
  "HandshakeState",
  # §26.5.2  Host → UI delivery
  "ToolInputParams",
  "ToolResultParams",
  "ToolCancelledParams",
  # §26.5.3  UI → Host requests
  "ToolsCallParams",
  "OpenLinkParams",
  "UiMessageParams",
  "RequestDisplayModeParams",
  "RequestDisplayModeResult",
  "UpdateModelContextParams",
  "PingParams",
  # §26.5.4  lifecycle / context
  "SizeChangedParams",
  "ResourceTeardownParams",
  # §26.5.5  sandbox-proxy
  "SandboxResourceReadyParams",
  # §26.5.3 / §26.7  mediation, consent, visibility
  "host_must_mediate",
  "host_may_route_tools_call",
  "host_should_reject_app_call",
  "host_may_decline_resources_read",
  "host_may_decline_open_link",
  "host_should_confirm_open_link",
  "host_should_confirm_ui_message",
  "host_applied_display_mode",
  "ping_response",
  "teardown_response",
  # §26.7  security and consent
  "SANDBOX_DENIED_ACCESS",
  "FORBIDDEN_UI_DATA",
  "ALLOWED_UI_DATA",
  "host_must_sandbox_rendered_ui",
  "sandbox_denies_access",
  "rendered_content_can_escape_sandbox",
  "only_channel_is_dialect",
  "host_grants_ambient_access",
  "host_must_apply_csp",
  "host_blocks_origin",
  "host_default_policy_is_deny",
  "effective_csp_reported",
  "granted_permissions_reported",
  "host_grant_respects_request",
  "host_may_grant_permission",
  "ui_data_is_permitted",
  "ui_data_is_forbidden",
  "host_treats_rendered_content_as_untrusted",
  "host_validate_incoming_message",
  # §26.8  error handling
  "DeclineReason",
  "requires_error_on_decline",
  "build_dialect_error",
  "decline_response",
  "method_not_found_response",
  "is_silent_drop_conformant",
  "is_dialect_error_response",
  # §26.9  SDK scope summary
  "SdkScopeRole",
  "SDK_SCOPE_ASSIGNMENT",
  "SERVER_SDK_NON_OBLIGATIONS",
  "sdk_scope_of",
  "is_server_sdk_obligation",
  "server_sdk_runs_dialect_runtime",
]
