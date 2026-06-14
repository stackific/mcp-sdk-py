"""Tests for S42 — Interactive UI Extension II (spec §26.5–§26.9).

Covers the runtime UI-to-host message dialect: the framing/versioning rule, the
initialization handshake, Host→UI delivery, UI→Host mediated requests, the
lifecycle/teardown and sandbox-proxy messages, the verbatim method/notification
name registry, the host security & consent predicates, the §26.8 error-handling
contract, and the §26.9 SDK-scope split. The static S41 half (UI declaration /
resource / hint shapes) is reused, not re-tested here.

AC → test coverage map (each AC has at least one dedicated test):

  AC-42.1  every dialect message is §3-framed; names match the registry
             byte-for-byte, case-sensitive
             → test_ac_42_1_framing_and_registry_names
             → test_ac_42_1_registry_names_case_sensitive
  AC-42.2  dialect protocol version is exactly "2026-01-26", independent of core
             → test_ac_42_2_dialect_version_value
             → test_ac_42_2_independent_of_core_revision
  AC-42.3  no dialect message before the ui/initialize response;
             initialized only after
             → test_ac_42_3_no_message_before_response
             → test_ac_42_3_initialized_only_after_response
  AC-42.4  initialize result MUST carry protocolVersion (absence is failure)
             → test_ac_42_4_protocol_version_required
  AC-42.5  UI tools/call routed only after consent + policy; mediation mandatory
             → test_ac_42_5_route_requires_consent_and_policy
             → test_ac_42_5_mediation_mandatory
  AC-42.6  UI tools/call for non-"app" visibility SHOULD be rejected
             → test_ac_42_6_reject_non_app_visibility
  AC-42.7  UI resources/read mediated; MAY decline (error, not silent drop)
             → test_ac_42_7_resources_read_may_decline
  AC-42.8  ui/open-link MAY decline; SHOULD confirm before opening
             → test_ac_42_8_open_link_decline_and_confirm
  AC-42.9  request-display-mode result reports the mode actually applied
             → test_ac_42_9_display_mode_reports_applied
  AC-42.10 ping carries no params; receiver returns empty success promptly
             → test_ac_42_10_ping_empty_success
  AC-42.11 resource-teardown: UI releases and responds with {}
             → test_ac_42_11_teardown_empty_result
  AC-42.12 rendered UI is sandboxed; DOM/cookies/storage/navigation denied;
             no escape
             → test_ac_42_12_sandbox_denies_access
             → test_ac_42_12_no_escape
  AC-42.13 dialect is the only channel; no ambient host/user access
             → test_ac_42_13_only_channel_no_ambient
  AC-42.14 CSP applied; declared csp constrains to listed origins;
             absent ⇒ deny-by-default
             → test_ac_42_14_csp_applied
             → test_ac_42_14_declared_csp_constrains_origins
             → test_ac_42_14_deny_by_default_when_absent
  AC-42.15 initialize sandbox reports effective csp and exact granted permissions
             → test_ac_42_15_sandbox_reports_effective_csp_and_permissions
  AC-42.16 granted permissions ⊆ requested; none beyond request granted
             → test_ac_42_16_granted_subset_of_requested
  AC-42.17 only tool input/result + host context exposed; no creds/tokens/context
             → test_ac_42_17_allowed_and_forbidden_data
  AC-42.18 host validates incoming message vs §3 before acting; content untrusted
             → test_ac_42_18_validate_before_acting
             → test_ac_42_18_content_untrusted
  AC-42.19 failed dialect request answered with a §3/§22 error response
             → test_ac_42_19_failed_request_error_response
  AC-42.20 declined UI request answered with §22 error; never silently dropped
             → test_ac_42_20_decline_returns_error
             → test_ac_42_20_silent_drop_non_conformant
  AC-42.21 unimplemented dialect method ⇒ §22 method-not-found
             → test_ac_42_21_method_not_found
  AC-42.22 server acknowledges io.modelcontextprotocol/ui in server/discover
             → test_ac_42_22_server_acknowledges_extension
  AC-42.23 server can emit _meta.ui with resourceUri and OPTIONAL visibility
             → test_ac_42_23_server_emits_meta_ui
  AC-42.24 ui:// resource served with text/html;profile=mcp-app + optional hints
             → test_ac_42_24_resource_mime_and_hints
  AC-42.25 sandboxing/CSP/runtime/consent are NOT server-SDK obligations
             → test_ac_42_25_not_server_sdk_obligations
             → test_ac_42_25_server_sdk_does_not_run_runtime
"""

from __future__ import annotations

import pytest

from mcp_sdk_py.errors import (
  INVALID_PARAMS_CODE,
  METHOD_NOT_FOUND_CODE,
)
from mcp_sdk_py.jsonrpc import (
  FramingError,
  JSONRPCErrorResponse,
  JSONRPCNotification,
  JSONRPCRequest,
  JSONRPCResultResponse,
  classify_message,
)
from mcp_sdk_py.ui import (
  UI_EXTENSION_IDENTIFIER,
  UI_MIME_TYPE,
  UiContentSecurityPolicy,
  UiPermissions,
  ToolUiMeta,
  UiResource,
  server_acknowledges_ui,
  server_ui_acknowledgement,
  tool_ui_meta_from_tool_meta,
)
from mcp_sdk_py.content_types import TextResourceContents
from mcp_sdk_py import ui_host
from mcp_sdk_py.ui_host import (
  ALLOWED_UI_DATA,
  DECLINABLE_UI_REQUESTS,
  DIALECT_NAMES,
  DIALECT_REGISTRY,
  FORBIDDEN_UI_DATA,
  METHOD_PING,
  METHOD_RESOURCES_READ,
  METHOD_TOOLS_CALL,
  METHOD_UI_INITIALIZE,
  METHOD_UI_MESSAGE,
  METHOD_UI_OPEN_LINK,
  METHOD_UI_RESOURCE_TEARDOWN,
  METHOD_UI_UPDATE_MODEL_CONTEXT,
  NOTIFICATION_SANDBOX_PROXY_READY,
  NOTIFICATION_SANDBOX_RESOURCE_READY,
  NOTIFICATION_TOOL_INPUT,
  NOTIFICATION_TOOL_RESULT,
  NOTIFICATION_UI_INITIALIZED,
  SANDBOX_DENIED_ACCESS,
  SERVER_SDK_NON_OBLIGATIONS,
  UI_DIALECT_PROTOCOL_VERSION,
  DialectKind,
  DialectSender,
  DeclineReason,
  HandshakeOrderError,
  HandshakeState,
  InvalidUiInitializeResultError,
  OpenLinkParams,
  PingParams,
  RequestDisplayModeParams,
  RequestDisplayModeResult,
  ResourceTeardownParams,
  SandboxResourceReadyParams,
  SdkScopeRole,
  SizeChangedParams,
  ToolCancelledParams,
  ToolInputParams,
  ToolResultParams,
  ToolsCallParams,
  UiHostContext,
  UiInitializeParams,
  UiInitializeResult,
  UiMessageParams,
  UiSandboxReport,
  UpdateModelContextParams,
  build_dialect_error,
  decline_response,
  dialect_entry,
  dialect_protocol_version_matches,
  effective_csp_reported,
  granted_permissions_reported,
  host_applied_display_mode,
  host_blocks_origin,
  host_default_policy_is_deny,
  host_grant_respects_request,
  host_grants_ambient_access,
  host_may_decline_open_link,
  host_may_decline_resources_read,
  host_may_grant_permission,
  host_may_route_tools_call,
  host_must_apply_csp,
  host_must_mediate,
  host_must_sandbox_rendered_ui,
  host_should_confirm_open_link,
  host_should_confirm_ui_message,
  host_should_reject_app_call,
  host_treats_rendered_content_as_untrusted,
  host_validate_incoming_message,
  is_dialect_error_response,
  is_dialect_name,
  is_server_sdk_obligation,
  is_silent_drop_conformant,
  method_not_found_response,
  only_channel_is_dialect,
  ping_response,
  rendered_content_can_escape_sandbox,
  requires_error_on_decline,
  sandbox_denies_access,
  sdk_scope_of,
  server_sdk_runs_dialect_runtime,
  teardown_response,
  ui_data_is_forbidden,
  ui_data_is_permitted,
)

# Vendor-neutral placeholder identities used throughout (no real AI vendor/model
# names appear anywhere in this suite).
UI_CLIENT_INFO = {"name": "Example UI App", "version": "1.0.0"}
HOST_INFO = {"name": "ExampleHost", "version": "1.0.0"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _completed_handshake() -> HandshakeState:
  """Return a HandshakeState whose initialize request/response have both occurred."""
  state = HandshakeState()
  state.before_send(METHOD_UI_INITIALIZE)
  state.on_response()
  return state


def _initialize_result_wire(*, with_sandbox: bool = True) -> dict:
  """Build the §26.5.1 wire initialize result example (Host → UI)."""
  caps: dict = {
    "openLinks": {},
    "serverTools": {"listChanged": True},
    "logging": {},
  }
  if with_sandbox:
    caps["sandbox"] = {
      "permissions": {"clipboardWrite": {}},
      "csp": {"connectDomains": ["https://api.example.com"]},
    }
  return {
    "protocolVersion": UI_DIALECT_PROTOCOL_VERSION,
    "hostInfo": HOST_INFO,
    "hostCapabilities": caps,
    "hostContext": {
      "theme": "dark",
      "displayMode": "inline",
      "locale": "en-US",
      "platform": "web",
      "containerDimensions": {"width": 640, "maxHeight": 480},
    },
  }


# ---------------------------------------------------------------------------
# AC-42.1  Framing + registry names (R-26.5-a)
# ---------------------------------------------------------------------------

def test_ac_42_1_framing_and_registry_names() -> None:
  # Every dialect message round-trips through §3 framing and classifies as a
  # request, notification, or response — and registry names match byte-for-byte.
  assert len(DIALECT_REGISTRY) == 19
  assert DIALECT_NAMES == frozenset(DIALECT_REGISTRY)

  # A request: ui/initialize.
  req = JSONRPCRequest(
    id=1, method=METHOD_UI_INITIALIZE,
    params=UiInitializeParams(protocol_version=UI_DIALECT_PROTOCOL_VERSION).to_dict(),
  )
  classified = classify_message(req.to_dict())
  assert isinstance(classified, JSONRPCRequest)
  assert is_dialect_name(classified.method)

  # A notification: ui/notifications/tool-result.
  note = JSONRPCNotification(
    method=NOTIFICATION_TOOL_RESULT,
    params=ToolResultParams(content=[{"type": "text", "text": "x"}]).to_dict(),
  )
  classified_note = classify_message(note.to_dict())
  assert isinstance(classified_note, JSONRPCNotification)
  assert is_dialect_name(classified_note.method)

  # A response: ping result.
  resp = ping_response(4)
  classified_resp = classify_message(resp.to_dict())
  assert isinstance(classified_resp, JSONRPCResultResponse)

  # Each registry name is in DIALECT_NAMES exactly once and classifiable.
  for name in DIALECT_NAMES:
    assert dialect_entry(name) is not None
    assert dialect_entry(name).name == name


def test_ac_42_1_registry_names_case_sensitive() -> None:
  # Case-sensitive, byte-for-byte match: a case-folded variant does NOT match.
  assert is_dialect_name("ui/initialize")
  assert not is_dialect_name("UI/Initialize")
  assert not is_dialect_name("ui/Initialize")
  assert not is_dialect_name("ui/initialize ")  # trailing space
  assert not is_dialect_name("PING")
  assert not is_dialect_name(123)  # non-string
  assert dialect_entry("UI/Initialize") is None

  # The 19 names verbatim, with the spec's kind + sender.
  assert DIALECT_REGISTRY[METHOD_UI_INITIALIZE].kind is DialectKind.REQUEST
  assert DIALECT_REGISTRY[METHOD_UI_INITIALIZE].sender is DialectSender.UI_TO_HOST
  assert DIALECT_REGISTRY[NOTIFICATION_TOOL_INPUT].kind is DialectKind.NOTIFICATION
  assert DIALECT_REGISTRY[NOTIFICATION_TOOL_INPUT].sender is DialectSender.HOST_TO_UI
  assert DIALECT_REGISTRY[METHOD_PING].sender is DialectSender.EITHER
  assert DIALECT_REGISTRY[NOTIFICATION_SANDBOX_PROXY_READY].sender is DialectSender.SANDBOX_TO_HOST
  assert DIALECT_REGISTRY[NOTIFICATION_SANDBOX_RESOURCE_READY].sender is DialectSender.HOST_TO_SANDBOX


# ---------------------------------------------------------------------------
# AC-42.2  Dialect protocol version (R-26.5-b)
# ---------------------------------------------------------------------------

def test_ac_42_2_dialect_version_value() -> None:
  assert UI_DIALECT_PROTOCOL_VERSION == "2026-01-26"
  assert dialect_protocol_version_matches("2026-01-26")
  assert not dialect_protocol_version_matches("2026-1-26")
  assert not dialect_protocol_version_matches(None)
  # Carried in the handshake.
  params = UiInitializeParams(protocol_version=UI_DIALECT_PROTOCOL_VERSION)
  assert params.to_dict()["protocolVersion"] == "2026-01-26"
  result = UiInitializeResult(protocol_version=UI_DIALECT_PROTOCOL_VERSION)
  assert result.to_dict()["protocolVersion"] == "2026-01-26"


def test_ac_42_2_independent_of_core_revision() -> None:
  # The core protocol revision is "2026-07-28" (§5/§27.1); the dialect revision is
  # observably different and a value equal to the core revision does NOT match.
  core_revision = "2026-07-28"
  assert UI_DIALECT_PROTOCOL_VERSION != core_revision
  assert not dialect_protocol_version_matches(core_revision)


# ---------------------------------------------------------------------------
# AC-42.3  Handshake ordering (R-26.5.1-a)
# ---------------------------------------------------------------------------

def test_ac_42_3_no_message_before_response() -> None:
  state = HandshakeState()
  # The very first permitted send is ui/initialize.
  state.before_send(METHOD_UI_INITIALIZE)
  # Any other dialect message before the response is flagged.
  for method in (METHOD_TOOLS_CALL, METHOD_PING, NOTIFICATION_UI_INITIALIZED):
    with pytest.raises(HandshakeOrderError):
      state.before_send(method)
  assert not state.response_received
  assert not state.may_send_initialized()


def test_ac_42_3_initialized_only_after_response() -> None:
  state = HandshakeState()
  state.before_send(METHOD_UI_INITIALIZE)
  assert not state.may_send_initialized()
  state.on_response()
  assert state.response_received
  assert state.may_send_initialized()
  # After the response, ui/notifications/initialized and other messages are fine.
  state.before_send(NOTIFICATION_UI_INITIALIZED)
  state.before_send(METHOD_TOOLS_CALL)
  # A response arriving before the request was sent is itself a violation.
  with pytest.raises(HandshakeOrderError):
    HandshakeState().on_response()


# ---------------------------------------------------------------------------
# AC-42.4  protocolVersion REQUIRED in result (R-26.5.1-b)
# ---------------------------------------------------------------------------

def test_ac_42_4_protocol_version_required() -> None:
  result = UiInitializeResult.from_dict(_initialize_result_wire())
  assert result.protocol_version == UI_DIALECT_PROTOCOL_VERSION
  # Absence is a conformance failure.
  bad = _initialize_result_wire()
  del bad["protocolVersion"]
  with pytest.raises(InvalidUiInitializeResultError):
    UiInitializeResult.from_dict(bad)
  # An empty / non-string version is rejected at construction too.
  with pytest.raises(InvalidUiInitializeResultError):
    UiInitializeResult(protocol_version="")


# ---------------------------------------------------------------------------
# AC-42.5  UI tools/call mediation + consent + policy (R-26.5.3-a, R-26.7-i/j)
# ---------------------------------------------------------------------------

def test_ac_42_5_route_requires_consent_and_policy() -> None:
  # The host may route to the server only after BOTH consent and policy.
  assert host_may_route_tools_call(consent_obtained=True, policy_applied=True)
  assert not host_may_route_tools_call(consent_obtained=False, policy_applied=True)
  assert not host_may_route_tools_call(consent_obtained=True, policy_applied=False)
  assert not host_may_route_tools_call(consent_obtained=False, policy_applied=False)


def test_ac_42_5_mediation_mandatory() -> None:
  # Mediation is mandatory for every UI-initiated request.
  for method in DECLINABLE_UI_REQUESTS:
    assert host_must_mediate(method)
  assert host_must_mediate(METHOD_TOOLS_CALL)


# ---------------------------------------------------------------------------
# AC-42.6  Reject non-"app" visibility (R-26.5.3-b, R-26.7-k)
# ---------------------------------------------------------------------------

def test_ac_42_6_reject_non_app_visibility() -> None:
  model_only = ToolUiMeta(resource_uri="ui://app/get-time", visibility=["model"])
  assert host_should_reject_app_call(model_only)
  app_visible = ToolUiMeta(resource_uri="ui://app/get-time", visibility=["model", "app"])
  assert not host_should_reject_app_call(app_visible)
  # The omitted-default visibility includes "app", so a default tool is allowed.
  default = ToolUiMeta(resource_uri="ui://app/get-time")
  assert not host_should_reject_app_call(default)


# ---------------------------------------------------------------------------
# AC-42.7  resources/read mediated, MAY decline (R-26.5.3-c)
# ---------------------------------------------------------------------------

def test_ac_42_7_resources_read_may_decline() -> None:
  assert host_may_decline_resources_read()
  assert host_must_mediate(METHOD_RESOURCES_READ)
  # A decline is answered with an error response, never a silent drop.
  resp = decline_response(7, DeclineReason.POLICY, "resource read declined")
  assert is_dialect_error_response(resp)
  assert resp.error["code"] == INVALID_PARAMS_CODE
  assert resp.id == 7


# ---------------------------------------------------------------------------
# AC-42.8  open-link MAY decline; SHOULD confirm (R-26.5.3-d, R-26.7-l)
# ---------------------------------------------------------------------------

def test_ac_42_8_open_link_decline_and_confirm() -> None:
  assert host_may_decline_open_link()
  assert host_should_confirm_open_link()
  # A non-confirming auto-open is non-conformant: the obligation to confirm holds.
  params = OpenLinkParams(url="https://example.com/docs")
  assert params.to_dict() == {"url": "https://example.com/docs"}
  with pytest.raises(TypeError):
    OpenLinkParams.from_dict({})  # url is REQUIRED


# ---------------------------------------------------------------------------
# AC-42.9  display-mode reports applied mode (R-26.5.3-e)
# ---------------------------------------------------------------------------

def test_ac_42_9_display_mode_reports_applied() -> None:
  requested = RequestDisplayModeParams(mode="fullscreen")
  # The host applies a DIFFERENT mode; the result reports what was applied.
  result = host_applied_display_mode(requested, "pip")
  assert isinstance(result, RequestDisplayModeResult)
  assert result.mode == "pip"
  assert result.to_dict() == {"mode": "pip"}
  # When the host honors the request, the applied mode equals the requested.
  same = host_applied_display_mode(requested, "fullscreen")
  assert same.mode == "fullscreen"
  # Invalid modes are rejected.
  with pytest.raises(ValueError):
    RequestDisplayModeParams(mode="floating")
  with pytest.raises(ValueError):
    host_applied_display_mode(requested, "floating")


# ---------------------------------------------------------------------------
# AC-42.10  ping (R-26.5.3-f, R-26.5.3-g)
# ---------------------------------------------------------------------------

def test_ac_42_10_ping_empty_success() -> None:
  # ping carries no params.
  assert PingParams().to_dict() == {}
  assert PingParams.from_dict(None).to_dict() == {}
  assert PingParams.from_dict({}).to_dict() == {}
  # The receiver returns an empty success response echoing the id.
  resp = ping_response(4)
  assert isinstance(resp, JSONRPCResultResponse)
  assert resp.id == 4
  assert resp.result == {}
  assert resp.to_dict() == {"jsonrpc": "2.0", "id": 4, "result": {}}


# ---------------------------------------------------------------------------
# AC-42.11  teardown (R-26.5.4-a)
# ---------------------------------------------------------------------------

def test_ac_42_11_teardown_empty_result() -> None:
  params = ResourceTeardownParams.from_dict({"reason": "conversation-closed"})
  assert params.reason == "conversation-closed"
  resp = teardown_response(9)
  assert isinstance(resp, JSONRPCResultResponse)
  assert resp.id == 9
  assert resp.result == {}
  with pytest.raises(TypeError):
    ResourceTeardownParams.from_dict({})  # reason REQUIRED


# ---------------------------------------------------------------------------
# AC-42.12  Sandboxing (R-26.7-a, R-26.7-b)
# ---------------------------------------------------------------------------

def test_ac_42_12_sandbox_denies_access() -> None:
  assert host_must_sandbox_rendered_ui()
  assert SANDBOX_DENIED_ACCESS == frozenset({"dom", "cookies", "storage", "navigation"})
  for denied in ("dom", "cookies", "storage", "navigation"):
    assert sandbox_denies_access(denied)
  assert not sandbox_denies_access("network")


def test_ac_42_12_no_escape() -> None:
  # The rendered content MUST NOT escape the sandbox to reach host/user state.
  assert not rendered_content_can_escape_sandbox()


# ---------------------------------------------------------------------------
# AC-42.13  Single channel, no ambient access (R-26.7-c)
# ---------------------------------------------------------------------------

def test_ac_42_13_only_channel_no_ambient() -> None:
  assert only_channel_is_dialect()
  assert not host_grants_ambient_access()


# ---------------------------------------------------------------------------
# AC-42.14  CSP enforcement (R-26.7-d/e/f)
# ---------------------------------------------------------------------------

def test_ac_42_14_csp_applied() -> None:
  assert host_must_apply_csp()


def test_ac_42_14_declared_csp_constrains_origins() -> None:
  csp = UiContentSecurityPolicy(connect_domains=["https://api.example.com"])
  # The listed origin is allowed; an unlisted origin is blocked.
  assert not host_blocks_origin("https://api.example.com", "connectDomains", csp)
  assert host_blocks_origin("https://evil.example.net", "connectDomains", csp)
  # A member with no declared origins blocks everything for that member.
  assert host_blocks_origin("https://api.example.com", "frameDomains", csp)
  assert not host_default_policy_is_deny(csp)


def test_ac_42_14_deny_by_default_when_absent() -> None:
  # No declared csp ⇒ deny-by-default: every external origin is blocked.
  assert host_default_policy_is_deny(None)
  assert host_blocks_origin("https://api.example.com", "connectDomains", None)
  assert host_blocks_origin("https://anything.example", "resourceDomains", None)


# ---------------------------------------------------------------------------
# AC-42.15  Sandbox report (R-26.7-g, R-26.7-h)
# ---------------------------------------------------------------------------

def test_ac_42_15_sandbox_reports_effective_csp_and_permissions() -> None:
  result = UiInitializeResult.from_dict(_initialize_result_wire())
  report = result.sandbox
  assert isinstance(report, UiSandboxReport)
  # csp reports the EFFECTIVE policy the host applied.
  csp = effective_csp_reported(result)
  assert isinstance(csp, UiContentSecurityPolicy)
  assert csp.connect_domains == ["https://api.example.com"]
  # permissions reports exactly the granted set.
  perms = granted_permissions_reported(result)
  assert isinstance(perms, UiPermissions)
  assert perms.requested() == frozenset({"clipboardWrite"})
  # No sandbox reported ⇒ no csp / permissions surfaced.
  no_sandbox = UiInitializeResult.from_dict(_initialize_result_wire(with_sandbox=False))
  assert effective_csp_reported(no_sandbox) is None
  assert granted_permissions_reported(no_sandbox) is None


# ---------------------------------------------------------------------------
# AC-42.16  Granted ⊆ requested (R-26.7-h)
# ---------------------------------------------------------------------------

def test_ac_42_16_granted_subset_of_requested() -> None:
  requested = UiPermissions(clipboard_write=True, camera=True)
  # Granting a subset of the requested set is conformant.
  granted_subset = UiPermissions(clipboard_write=True)
  assert host_grant_respects_request(granted_subset, requested)
  # Granting exactly the requested set is conformant (host MAY grant all).
  assert host_grant_respects_request(requested, requested)
  # Granting something NOT requested is a violation.
  over_grant = UiPermissions(clipboard_write=True, microphone=True)
  assert not host_grant_respects_request(over_grant, requested)
  # No permission absent from the request is grantable.
  assert host_may_grant_permission("camera", requested)
  assert not host_may_grant_permission("microphone", requested)
  assert not host_may_grant_permission("camera", None)
  # Empty/absent grant always satisfies the rule.
  assert host_grant_respects_request(None, requested)
  assert host_grant_respects_request(None, None)


# ---------------------------------------------------------------------------
# AC-42.17  No credential/context leakage (R-26.7-m)
# ---------------------------------------------------------------------------

def test_ac_42_17_allowed_and_forbidden_data() -> None:
  assert ALLOWED_UI_DATA == frozenset({"tool_input", "tool_result", "host_context"})
  for allowed in ALLOWED_UI_DATA:
    assert ui_data_is_permitted(allowed)
    assert not ui_data_is_forbidden(allowed)
  for forbidden in FORBIDDEN_UI_DATA:
    assert ui_data_is_forbidden(forbidden)
    assert not ui_data_is_permitted(forbidden)
  # Credentials, authorization tokens, and unrelated context are forbidden.
  assert ui_data_is_forbidden("credentials")
  assert ui_data_is_forbidden("authorization_tokens")
  assert ui_data_is_forbidden("unrelated_conversation_context")


# ---------------------------------------------------------------------------
# AC-42.18  Message validation + untrusted content (R-26.7-n, R-26.7-o)
# ---------------------------------------------------------------------------

def test_ac_42_18_validate_before_acting() -> None:
  # A well-framed message validates and returns the typed message.
  good = JSONRPCRequest(id=2, method=METHOD_TOOLS_CALL,
                        params={"name": "get-time"}).to_dict()
  typed = host_validate_incoming_message(good)
  assert isinstance(typed, JSONRPCRequest)
  assert typed.method == METHOD_TOOLS_CALL
  # A malformed (batch / wrong jsonrpc) message is rejected before acting.
  with pytest.raises(FramingError):
    host_validate_incoming_message([{"jsonrpc": "2.0", "id": 1, "method": "ping"}])
  with pytest.raises(FramingError):
    host_validate_incoming_message({"jsonrpc": "1.0", "id": 1, "method": "ping"})


def test_ac_42_18_content_untrusted() -> None:
  assert host_treats_rendered_content_as_untrusted()


# ---------------------------------------------------------------------------
# AC-42.19  Failed request ⇒ §3/§22 error response (R-26.8-a)
# ---------------------------------------------------------------------------

def test_ac_42_19_failed_request_error_response() -> None:
  resp = decline_response(2, DeclineReason.POLICY, "blocked by policy")
  assert isinstance(resp, JSONRPCErrorResponse)
  assert is_dialect_error_response(resp)
  wire = resp.to_dict()
  assert wire["jsonrpc"] == "2.0"
  assert wire["id"] == 2
  assert "error" in wire and "result" not in wire
  assert wire["error"]["code"] == INVALID_PARAMS_CODE
  # The raw-dict form is also recognised; a success response is not an error.
  assert is_dialect_error_response({"jsonrpc": "2.0", "id": 2, "error": {"code": -32602, "message": "x"}})
  assert not is_dialect_error_response({"jsonrpc": "2.0", "id": 2, "result": {}})


# ---------------------------------------------------------------------------
# AC-42.20  Decline ⇒ error, never silent drop (R-26.8-b)
# ---------------------------------------------------------------------------

def test_ac_42_20_decline_returns_error() -> None:
  # Every declinable UI request requires an error on decline.
  assert DECLINABLE_UI_REQUESTS == frozenset({
    METHOD_TOOLS_CALL,
    METHOD_RESOURCES_READ,
    METHOD_UI_OPEN_LINK,
    METHOD_UI_MESSAGE,
    METHOD_UI_UPDATE_MODEL_CONTEXT,
  })
  for method in DECLINABLE_UI_REQUESTS:
    assert requires_error_on_decline(method)
  # A non-declinable name (e.g. ping) is not in the set.
  assert not requires_error_on_decline(METHOD_PING)
  # Each decline reason maps to an appropriate §22 code.
  no_consent = build_dialect_error(DeclineReason.NO_CONSENT, "no consent")
  assert no_consent.code == INVALID_PARAMS_CODE
  policy = build_dialect_error(DeclineReason.POLICY, "policy")
  assert policy.code == INVALID_PARAMS_CODE
  unknown = build_dialect_error(DeclineReason.UNKNOWN_METHOD, "unknown")
  assert unknown.code == METHOD_NOT_FOUND_CODE


def test_ac_42_20_silent_drop_non_conformant() -> None:
  # Declined but no error sent ⇒ silent drop ⇒ NON-conformant.
  assert not is_silent_drop_conformant(request_declined=True, error_sent=False)
  # Declined with an error sent ⇒ conformant.
  assert is_silent_drop_conformant(request_declined=True, error_sent=True)
  # Not declined ⇒ conformant regardless.
  assert is_silent_drop_conformant(request_declined=False, error_sent=False)


# ---------------------------------------------------------------------------
# AC-42.21  Unknown method ⇒ method-not-found (R-26.8-c)
# ---------------------------------------------------------------------------

def test_ac_42_21_method_not_found() -> None:
  resp = method_not_found_response(2, "ui/does-not-exist")
  assert isinstance(resp, JSONRPCErrorResponse)
  assert resp.id == 2
  assert resp.error["code"] == METHOD_NOT_FOUND_CODE
  assert is_dialect_error_response(resp)
  # An unimplemented method is not in the registry.
  assert dialect_entry("ui/does-not-exist") is None
  assert not is_dialect_name("ui/does-not-exist")


# ---------------------------------------------------------------------------
# AC-42.22  Server acknowledges extension in server/discover (R-26.9-a)
# ---------------------------------------------------------------------------

def test_ac_42_22_server_acknowledges_extension() -> None:
  # Reuses the S41 server acknowledgement surface (§26.2-j).
  ack = server_ui_acknowledgement()
  assert ack == {UI_EXTENSION_IDENTIFIER: {}}
  assert server_acknowledges_ui(ack)
  # The §26.9 obligation is attributed to the server SDK.
  assert is_server_sdk_obligation("acknowledge_extension")
  assert sdk_scope_of("acknowledge_extension") is SdkScopeRole.SERVER_SDK


# ---------------------------------------------------------------------------
# AC-42.23  Server emits _meta.ui with resourceUri + OPTIONAL visibility (R-26.9-b)
# ---------------------------------------------------------------------------

def test_ac_42_23_server_emits_meta_ui() -> None:
  meta = ToolUiMeta(resource_uri="ui://app/get-time", visibility=["app"])
  tool_meta = meta.to_tool_meta()
  assert tool_meta["ui"]["resourceUri"] == "ui://app/get-time"
  assert tool_meta["ui"]["visibility"] == ["app"]
  # OPTIONAL visibility: omitting it is valid and round-trips back.
  meta2 = ToolUiMeta(resource_uri="ui://app/get-time")
  round_tripped = tool_ui_meta_from_tool_meta(meta2.to_tool_meta())
  assert round_tripped is not None
  assert round_tripped.resource_uri == "ui://app/get-time"
  assert round_tripped.visibility is None
  assert is_server_sdk_obligation("declare_meta_ui")


# ---------------------------------------------------------------------------
# AC-42.24  ui:// resource served with the UI MIME type + hints (R-26.9-c)
# ---------------------------------------------------------------------------

def test_ac_42_24_resource_mime_and_hints() -> None:
  contents = TextResourceContents(
    uri="ui://app/get-time",
    text="<html><body>time</body></html>",
    mime_type=UI_MIME_TYPE,
  )
  resource = UiResource(contents=contents)
  wire = resource.to_content_dict()
  assert wire["mimeType"] == "text/html;profile=mcp-app"
  assert wire["uri"] == "ui://app/get-time"
  assert is_server_sdk_obligation("serve_ui_resource")
  assert sdk_scope_of("serve_ui_resource") is SdkScopeRole.SERVER_SDK


# ---------------------------------------------------------------------------
# AC-42.25  Host concerns are NOT server-SDK obligations (R-26.9-d)
# ---------------------------------------------------------------------------

def test_ac_42_25_not_server_sdk_obligations() -> None:
  assert SERVER_SDK_NON_OBLIGATIONS == frozenset({
    "render_sandbox",
    "enforce_csp_permissions",
    "run_dialect_runtime",
    "obtain_user_consent",
  })
  for obligation in SERVER_SDK_NON_OBLIGATIONS:
    assert not is_server_sdk_obligation(obligation)
    assert sdk_scope_of(obligation) is SdkScopeRole.HOST_CLIENT


def test_ac_42_25_server_sdk_does_not_run_runtime() -> None:
  # Running the dialect runtime is a host/client concern; the server SDK does not.
  assert not server_sdk_runs_dialect_runtime()
  # An unknown obligation token is treated as not a server-SDK obligation.
  assert not is_server_sdk_obligation("unknown-obligation")


# ---------------------------------------------------------------------------
# Round-trip coverage for the remaining abstract data structures
# ---------------------------------------------------------------------------

def test_data_structures_round_trip() -> None:
  # UiInitializeParams.
  ip = UiInitializeParams.from_dict({
    "protocolVersion": UI_DIALECT_PROTOCOL_VERSION,
    "clientInfo": UI_CLIENT_INFO,
    "appCapabilities": {"availableDisplayModes": ["inline", "fullscreen", "pip"]},
  })
  assert ip.to_dict()["clientInfo"] == UI_CLIENT_INFO

  # UiHostContext as full and partial.
  ctx = UiHostContext.from_dict({"theme": "dark", "displayMode": "inline"})
  assert ctx.to_dict() == {"theme": "dark", "displayMode": "inline"}
  partial = UiHostContext.from_dict({"theme": "light"})
  assert partial.to_dict() == {"theme": "light"}

  # ToolInputParams (complete and partial share a shape).
  ti = ToolInputParams.from_dict({"arguments": {"city": "anywhere"}})
  assert ti.to_dict() == {"arguments": {"city": "anywhere"}}
  with pytest.raises(TypeError):
    ToolInputParams.from_dict({})

  # ToolResultParams preserves explicit structuredContent (incl. null).
  tr = ToolResultParams.from_dict({"structuredContent": None, "isError": False})
  assert tr.to_dict() == {"structuredContent": None, "isError": False}
  tr2 = ToolResultParams(content=[{"type": "text", "text": "x"}])
  assert tr2.to_dict() == {"content": [{"type": "text", "text": "x"}]}

  # ToolCancelledParams.
  tc = ToolCancelledParams.from_dict({"reason": "superseded"})
  assert tc.to_dict() == {"reason": "superseded"}

  # ToolsCallParams.
  call = ToolsCallParams.from_dict({"name": "get-time", "arguments": {}})
  assert call.to_dict() == {"name": "get-time", "arguments": {}}
  with pytest.raises(TypeError):
    ToolsCallParams.from_dict({})

  # UiMessageParams enforces role == "user" and text content.
  msg = UiMessageParams.from_dict({"role": "user", "content": {"type": "text", "text": "hi"}})
  assert msg.to_dict()["role"] == "user"
  with pytest.raises(ValueError):
    UiMessageParams(role="assistant", content={"type": "text", "text": "no"})
  with pytest.raises(ValueError):
    UiMessageParams(role="user", content={"type": "image"})

  # UpdateModelContextParams.
  umc = UpdateModelContextParams.from_dict({"content": [{"type": "text", "text": "ctx"}]})
  assert umc.to_dict() == {"content": [{"type": "text", "text": "ctx"}]}

  # SizeChangedParams.
  sc = SizeChangedParams.from_dict({"width": 640, "height": 480})
  assert sc.to_dict() == {"width": 640, "height": 480}
  with pytest.raises(TypeError):
    SizeChangedParams.from_dict({"width": 640})

  # SandboxResourceReadyParams (host-internal §26.5.5).
  srr = SandboxResourceReadyParams.from_dict({
    "html": "<html></html>",
    "sandbox": "allow-scripts",
    "csp": {"connectDomains": ["https://api.example.com"]},
    "permissions": {"clipboardWrite": {}},
  })
  out = srr.to_dict()
  assert out["html"] == "<html></html>"
  assert out["sandbox"] == "allow-scripts"
  assert out["csp"] == {"connectDomains": ["https://api.example.com"]}
  assert out["permissions"] == {"clipboardWrite": {}}
  with pytest.raises(TypeError):
    SandboxResourceReadyParams.from_dict({})  # html REQUIRED


def test_public_surface_is_complete() -> None:
  # Every name in __all__ resolves on the module.
  for name in ui_host.__all__:
    assert hasattr(ui_host, name), name
  # No accidental private leakage.
  assert "RequestDisplayModeResult" in ui_host.__all__
  assert "UiSandboxReport" in ui_host.__all__
