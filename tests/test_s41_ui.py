"""Tests for S41 — Interactive UI Extension I (spec §26.1–§26.4).

Covers the server-facing, static half of the OPTIONAL Interactive UI ("apps")
extension: the responsibility split, identifier/capability negotiation, the
``_meta.ui`` tool declaration, and the UI resource model with its hints. The
dynamic UI-to-host message channel (S42) is out of scope and not exercised here.

AC → test coverage map (each AC has at least one dedicated test):

  AC-41.1  extension is OPTIONAL; omitting it stays conformant
             → test_ac_41_1_extension_is_optional
  AC-41.2  server MAY (need not) declare a tool UI
             → test_ac_41_2_server_may_declare_ui
  AC-41.3  declaring _meta.ui is a SERVER/SDK responsibility
             → test_ac_41_3_declare_is_server_responsibility
  AC-41.4  serving the ui:// resource is a SERVER/SDK responsibility
             → test_ac_41_4_serve_is_server_responsibility
  AC-41.5  render/sandbox/channel are NOT server-SDK responsibilities
             → test_ac_41_5_not_server_sdk_responsibilities
  AC-41.6  rendering/sandboxing attributed to the HOST
             → test_ac_41_6_render_sandbox_is_host
  AC-41.7  CSP/permission enforcement attributed to the HOST
             → test_ac_41_7_enforce_is_host
  AC-41.8  running the channel attributed to the HOST
             → test_ac_41_8_channel_is_host
  AC-41.9  obtaining consent attributed to the HOST
             → test_ac_41_9_consent_is_host
  AC-41.10 server SDK implementable with no rendering dependency
             → test_ac_41_10_no_rendering_dependency
  AC-41.11 absent identifier ⇒ extension inactive
             → test_ac_41_11_absent_identifier_inactive
  AC-41.12 identifier matched opaque, case-sensitive
             → test_ac_41_12_identifier_case_sensitive
  AC-41.13 host advertises identifier in clientCapabilities._meta path
             → test_ac_41_13_host_advertises_in_meta
  AC-41.14 UiHostExtensionCapability requires mimeTypes
             → test_ac_41_14_mime_types_required
  AC-41.15 mimeTypes includes verbatim UI MIME type only
             → test_ac_41_15_mime_type_verbatim
  AC-41.16 no advertised MIME ⇒ server MUST NOT declare UI
             → test_ac_41_16_must_not_declare_without_mime
  AC-41.17 no advertised MIME ⇒ server MUST NOT expect rendering
             → test_ac_41_17_must_not_expect_render
  AC-41.18 not negotiated ⇒ server MAY expose plain tool
             → test_ac_41_18_may_expose_plain_tool
  AC-41.19 not negotiated ⇒ receiver ignores _meta.ui (normal tool)
             → test_ac_41_19_receiver_ignores_meta_ui
  AC-41.20 server MAY acknowledge with empty object under capabilities.extensions
             → test_ac_41_20_server_acknowledgement
  AC-41.21 resourceUri required and present
             → test_ac_41_21_resource_uri_required
  AC-41.22 resourceUri must be a ui:// URI; non-ui:// rejected
             → test_ac_41_22_resource_uri_scheme
  AC-41.23 host fetches the EXACT resourceUri via resources/read
             → test_ac_41_23_exact_resource_uri_read
  AC-41.24 visibility default ["model","app"]; only model/app elements
             → test_ac_41_24_visibility_default_and_enum
  AC-41.25 UI-originated call rejected when visibility excludes "app"
             → test_ac_41_25_reject_non_app_ui_call
  AC-41.26 visibility ["app"] ⇒ hidden from model list
             → test_ac_41_26_app_only_hidden_from_model
  AC-41.27 non-negotiating receiver ignores _meta.ui
             → test_ac_41_27_non_negotiating_ignores
  AC-41.28 ordinary tools/call unchanged by _meta.ui presence
             → test_ac_41_28_ordinary_call_unchanged
  AC-41.29 host MAY preload the UI resource
             → test_ac_41_29_may_preload
  AC-41.30 ui:// URI treated as opaque identifier
             → test_ac_41_30_uri_opaque
  AC-41.31 host derives no network origin from ui:// URI
             → test_ac_41_31_no_network_origin
  AC-41.32 UI content MIME is verbatim text/html;profile=mcp-app
             → test_ac_41_32_content_mime_verbatim
  AC-41.33 content MAY carry _meta.ui hints that take effect
             → test_ac_41_33_content_hints
  AC-41.34 csp members enumerate connect/resource/frame/baseUri origins
             → test_ac_41_34_csp_members
  AC-41.35 origin not listed in applicable csp member is blocked
             → test_ac_41_35_unlisted_origin_blocked
  AC-41.36 csp omitted ⇒ deny-by-default
             → test_ac_41_36_csp_omitted_deny_default
  AC-41.37 permissions members are exact-name + {} ⇒ requested
             → test_ac_41_37_permissions_shape
  AC-41.38 capability not requested ⇒ host does not grant
             → test_ac_41_38_unrequested_not_granted
  AC-41.39 requested capability MAY be declined by host
             → test_ac_41_39_requested_may_be_declined
  AC-41.40 domain ⇒ host SHOULD render under dedicated origin
             → test_ac_41_40_domain_hint
  AC-41.41 prefersBorder ⇒ host MAY honor or ignore
             → test_ac_41_41_prefers_border
  AC-41.42 sandboxed/isolated context denies doc/cookies/storage/nav
             → test_ac_41_42_sandbox_denies_access
  AC-41.43 host applies restrictive CSP constrained by csp
             → test_ac_41_43_restrictive_csp
  AC-41.44 rendered content has no ambient access; only channel is S42
             → test_ac_41_44_no_ambient_access

Plus round-trip/parse and registry-integration tests.
"""

from __future__ import annotations

import pytest

from mcp_sdk_py.content_types import BlobResourceContents, TextResourceContents
from mcp_sdk_py.extension_mechanism import ExtensionClassification, ExtensionRegistry
from mcp_sdk_py.meta_object import KEY_CLIENT_CAPABILITIES
from mcp_sdk_py.ui import (
  DEFAULT_VISIBILITY,
  RESPONSIBILITY_ASSIGNMENT,
  SANDBOX_DENIED_ACCESS,
  SERVER_SDK_NON_RESPONSIBILITIES,
  TOOL_UI_META_KEY,
  UI_EXTENSION_DEFINITION,
  UI_EXTENSION_IDENTIFIER,
  UI_MIME_TYPE,
  UI_URI_SCHEME,
  VALID_PERMISSIONS,
  VALID_VISIBILITY,
  VISIBILITY_APP,
  VISIBILITY_MODEL,
  InvalidToolUiMetaError,
  InvalidUiHostCapabilityError,
  ResourceUiMeta,
  ResponsibilityRole,
  ToolUiMeta,
  UiContentSecurityPolicy,
  UiExtensionNotNegotiatedError,
  UiHostExtensionCapability,
  UiPermissions,
  UiResource,
  assert_may_declare_ui,
  assert_ui_mime_type,
  host_advertises_ui_extension,
  host_blocks_origin,
  host_capabilities_from_request_meta,
  host_default_policy_is_deny,
  host_derives_network_origin_from_ui_uri,
  host_may_grant_permission,
  host_may_preload_ui_resource,
  host_must_apply_restrictive_csp,
  host_must_sandbox_rendered_ui,
  host_should_reject_ui_call,
  is_server_sdk_responsibility,
  is_ui_extension_identifier,
  is_ui_resource_content,
  is_ui_uri,
  ordinary_call_behavior_unchanged_by_ui_meta,
  receiver_ignores_ui_meta,
  rendered_ui_has_ambient_host_access,
  resource_ui_meta_from_content_meta,
  responsibility_of,
  sandbox_denies_access,
  server_acknowledges_ui,
  server_may_declare_ui,
  server_may_expose_plain_tool,
  server_sdk_requires_rendering_dependency,
  server_ui_acknowledgement,
  tool_ui_meta_from_tool_meta,
  ui_capability_from_extensions,
  ui_extension_active,
  ui_extension_advertisement,
  ui_uri_is_opaque_identifier,
)


# Vendor-neutral placeholder values used throughout (no real vendor/model names).
EXAMPLE_UI_URI = "ui://get-time/mcp-app.html"
EXAMPLE_HTML = "<!DOCTYPE html><html><body><p>placeholder</p></body></html>"


def _host_extensions_with_ui() -> dict:
  """A host extensions map that correctly advertises the UI extension."""
  return ui_extension_advertisement()


def _server_extensions_with_ui() -> dict:
  """A server extensions map that acknowledges the UI extension."""
  return server_ui_acknowledgement()


# ---------------------------------------------------------------------------
# §26.1  Roles & responsibilities  (AC-41.1 … AC-41.10)
# ---------------------------------------------------------------------------

def test_ac_41_1_extension_is_optional() -> None:
  """AC-41.1 — the extension is OPTIONAL; an implementation omitting it conforms."""
  # The extension is modelled as an ExtensionDefinition (classified, registrable);
  # nothing forces it active, and the inactive path is the core fallback.
  assert UI_EXTENSION_DEFINITION.classification is ExtensionClassification.MODULAR
  # Omitting it (no advertisement on either side) leaves it simply inactive.
  assert ui_extension_active(None, None) is False
  assert UI_EXTENSION_DEFINITION.fallback_doc  # documented core fallback exists


def test_ac_41_2_server_may_declare_ui() -> None:
  """AC-41.2 — a server MAY (but need not) declare a tool UI."""
  host = _host_extensions_with_ui()
  # MAY declare when the host advertised it...
  assert server_may_declare_ui(host) is True
  # ...and need not: a server can equally expose a plain tool.
  assert server_may_expose_plain_tool(host) is True


def test_ac_41_3_declare_is_server_responsibility() -> None:
  """AC-41.3 — declaring _meta.ui is a SERVER/SDK responsibility (R-26.1-b)."""
  assert responsibility_of("declare_ui_meta") is ResponsibilityRole.SERVER
  assert is_server_sdk_responsibility("declare_ui_meta") is True


def test_ac_41_4_serve_is_server_responsibility() -> None:
  """AC-41.4 — serving the ui:// resource is a SERVER/SDK responsibility (R-26.1-c)."""
  assert responsibility_of("serve_ui_resource") is ResponsibilityRole.SERVER
  assert is_server_sdk_responsibility("serve_ui_resource") is True


def test_ac_41_5_not_server_sdk_responsibilities() -> None:
  """AC-41.5 — render/sandbox/channel are NOT server-SDK responsibilities (R-26.1-d)."""
  for obligation in ("render", "sandbox", "run_message_channel"):
    assert obligation in SERVER_SDK_NON_RESPONSIBILITIES
    assert is_server_sdk_responsibility(obligation) is False


def test_ac_41_6_render_sandbox_is_host() -> None:
  """AC-41.6 — rendering & sandboxing are attributed to the HOST (R-26.1-e)."""
  assert responsibility_of("render") is ResponsibilityRole.HOST
  assert responsibility_of("sandbox") is ResponsibilityRole.HOST


def test_ac_41_7_enforce_is_host() -> None:
  """AC-41.7 — enforcing CSP & permissions is attributed to the HOST (R-26.1-f)."""
  assert responsibility_of("enforce_csp_permissions") is ResponsibilityRole.HOST


def test_ac_41_8_channel_is_host() -> None:
  """AC-41.8 — running the message channel is attributed to the HOST (R-26.1-g)."""
  assert responsibility_of("run_message_channel") is ResponsibilityRole.HOST


def test_ac_41_9_consent_is_host() -> None:
  """AC-41.9 — obtaining user consent is attributed to the HOST (R-26.1-h)."""
  assert responsibility_of("obtain_user_consent") is ResponsibilityRole.HOST


def test_ac_41_10_no_rendering_dependency() -> None:
  """AC-41.10 — server SDK implementable with no rendering dependency (R-26.1-i)."""
  assert server_sdk_requires_rendering_dependency() is False
  # And every host obligation is consistently attributed (sanity over the map).
  host_obligations = {
    k for k, v in RESPONSIBILITY_ASSIGNMENT.items() if v is ResponsibilityRole.HOST
  }
  assert {"render", "sandbox", "run_message_channel"} <= host_obligations


def test_unknown_obligation_lookups() -> None:
  """Unknown obligation tokens: responsibility_of raises; is_server_* is False."""
  with pytest.raises(KeyError):
    responsibility_of("not-a-real-obligation")
  assert is_server_sdk_responsibility("not-a-real-obligation") is False


# ---------------------------------------------------------------------------
# §26.2  Identifier & capability negotiation  (AC-41.11 … AC-41.20)
# ---------------------------------------------------------------------------

def test_ac_41_11_absent_identifier_inactive() -> None:
  """AC-41.11 — absent identifier in the negotiated map ⇒ extension inactive."""
  # Host advertises, server does not → not in the intersection → inactive.
  assert ui_extension_active(_host_extensions_with_ui(), {}) is False
  assert ui_extension_active({}, _server_extensions_with_ui()) is False
  # Neither side → inactive.
  assert ui_extension_active(None, None) is False


def test_ac_41_12_identifier_case_sensitive() -> None:
  """AC-41.12 — identifier matched opaque & case-sensitive (R-26.2-b)."""
  assert is_ui_extension_identifier("io.modelcontextprotocol/ui") is True
  assert is_ui_extension_identifier("IO.ModelContextProtocol/UI") is False
  assert is_ui_extension_identifier("io.modelcontextprotocol/UI") is False
  assert is_ui_extension_identifier(" io.modelcontextprotocol/ui ") is False


def test_ac_41_13_host_advertises_in_meta() -> None:
  """AC-41.13 — host advertises the key under clientCapabilities in _meta (R-26.2-c)."""
  request_meta = {
    KEY_CLIENT_CAPABILITIES: {
      "extensions": _host_extensions_with_ui(),
    }
  }
  extensions = host_capabilities_from_request_meta(request_meta)
  assert extensions is not None
  assert UI_EXTENSION_IDENTIFIER in extensions
  assert host_advertises_ui_extension(extensions) is True


def test_host_capabilities_from_request_meta_missing_paths() -> None:
  """Missing _meta / clientCapabilities / extensions all yield None gracefully."""
  assert host_capabilities_from_request_meta(None) is None
  assert host_capabilities_from_request_meta({}) is None
  assert host_capabilities_from_request_meta({KEY_CLIENT_CAPABILITIES: 5}) is None
  assert host_capabilities_from_request_meta({KEY_CLIENT_CAPABILITIES: {}}) is None


def test_ac_41_14_mime_types_required() -> None:
  """AC-41.14 — UiHostExtensionCapability requires mimeTypes (R-26.2-d)."""
  with pytest.raises(InvalidUiHostCapabilityError):
    UiHostExtensionCapability.from_dict({})  # missing mimeTypes
  with pytest.raises(InvalidUiHostCapabilityError):
    UiHostExtensionCapability(mime_types="not-a-list")  # type: ignore[arg-type]
  with pytest.raises(InvalidUiHostCapabilityError):
    UiHostExtensionCapability(mime_types=[123])  # type: ignore[list-item]
  cap = UiHostExtensionCapability.from_dict({"mimeTypes": [UI_MIME_TYPE]})
  assert cap.mime_types == [UI_MIME_TYPE]


def test_ac_41_15_mime_type_verbatim() -> None:
  """AC-41.15 — mimeTypes must include the verbatim, case-sensitive UI MIME (R-26.2-e)."""
  assert UI_MIME_TYPE == "text/html;profile=mcp-app"
  ok = UiHostExtensionCapability(mime_types=[UI_MIME_TYPE])
  assert ok.renders_ui_mime_type is True
  # Extra whitespace does NOT satisfy.
  bad_space = UiHostExtensionCapability(mime_types=["text/html; profile=mcp-app"])
  assert bad_space.renders_ui_mime_type is False
  # Wrong case does NOT satisfy.
  bad_case = UiHostExtensionCapability(mime_types=["TEXT/HTML;PROFILE=MCP-APP"])
  assert bad_case.renders_ui_mime_type is False
  assert host_advertises_ui_extension(
    {UI_EXTENSION_IDENTIFIER: bad_space.to_dict()}
  ) is False


def test_ac_41_16_must_not_declare_without_mime() -> None:
  """AC-41.16 — no advertised MIME ⇒ server MUST NOT declare UI associations (R-26.2-f)."""
  no_mime = {UI_EXTENSION_IDENTIFIER: {"mimeTypes": []}}
  assert server_may_declare_ui(no_mime) is False
  with pytest.raises(UiExtensionNotNegotiatedError):
    assert_may_declare_ui(no_mime)
  # Key entirely absent.
  assert server_may_declare_ui({}) is False
  with pytest.raises(UiExtensionNotNegotiatedError):
    assert_may_declare_ui(None)


def test_ac_41_17_must_not_expect_render() -> None:
  """AC-41.17 — no advertised MIME ⇒ server MUST NOT expect rendering (R-26.2-g)."""
  # The same gate governs "may declare" and "may expect rendering" (R-26.2-f/g).
  assert host_advertises_ui_extension({}) is False
  assert server_may_declare_ui({}) is False
  # With the required MIME present, both become permitted.
  assert host_advertises_ui_extension(_host_extensions_with_ui()) is True
  assert server_may_declare_ui(_host_extensions_with_ui()) is True


def test_ac_41_18_may_expose_plain_tool() -> None:
  """AC-41.18 — not negotiated ⇒ server MAY still expose a plain tool (R-26.2-h)."""
  assert server_may_expose_plain_tool({}) is True
  assert server_may_expose_plain_tool(None) is True
  assert server_may_expose_plain_tool(_host_extensions_with_ui()) is True


def test_ac_41_19_receiver_ignores_meta_ui() -> None:
  """AC-41.19 — host not negotiating ⇒ treats tool as normal, ignores _meta.ui (R-26.2-i)."""
  # Extension inactive (host advertises but server does not) ⇒ ignore _meta.ui.
  assert receiver_ignores_ui_meta(_host_extensions_with_ui(), {}) is True
  # Active on both sides ⇒ not ignored.
  assert receiver_ignores_ui_meta(
    _host_extensions_with_ui(), _server_extensions_with_ui()
  ) is False


def test_ac_41_20_server_acknowledgement() -> None:
  """AC-41.20 — server MAY acknowledge with an (empty) object value (R-26.2-j)."""
  ack = server_ui_acknowledgement()
  assert ack == {UI_EXTENSION_IDENTIFIER: {}}
  assert server_acknowledges_ui(ack) is True
  # Empty value still counts (presence is the signal).
  assert server_acknowledges_ui({UI_EXTENSION_IDENTIFIER: {}}) is True
  # Absent / malformed (null) value does not.
  assert server_acknowledges_ui({}) is False
  assert server_acknowledges_ui({UI_EXTENSION_IDENTIFIER: None}) is False


def test_ui_capability_from_extensions_malformed_is_none() -> None:
  """A malformed advertised value yields None rather than raising (graceful)."""
  assert ui_capability_from_extensions(None) is None
  assert ui_capability_from_extensions({UI_EXTENSION_IDENTIFIER: None}) is None
  assert ui_capability_from_extensions({UI_EXTENSION_IDENTIFIER: {}}) is None  # no mimeTypes


def test_ui_extension_advertisement_includes_extras() -> None:
  """The advertisement helper always leads with the verbatim MIME, then extras."""
  adv = ui_extension_advertisement(extra_mime_types=["text/html;profile=other", UI_MIME_TYPE])
  mimes = adv[UI_EXTENSION_IDENTIFIER]["mimeTypes"]
  assert mimes[0] == UI_MIME_TYPE
  assert "text/html;profile=other" in mimes
  # No duplicate of the mandatory entry.
  assert mimes.count(UI_MIME_TYPE) == 1


# ---------------------------------------------------------------------------
# §26.3  ToolUiMeta declaration  (AC-41.21 … AC-41.28)
# ---------------------------------------------------------------------------

def test_ac_41_21_resource_uri_required() -> None:
  """AC-41.21 — resourceUri is required and present (R-26.3-a)."""
  with pytest.raises(InvalidToolUiMetaError):
    ToolUiMeta.from_dict({})  # missing resourceUri
  with pytest.raises(InvalidToolUiMetaError):
    ToolUiMeta(resource_uri="")  # empty
  meta = ToolUiMeta(resource_uri=EXAMPLE_UI_URI)
  assert meta.resource_uri == EXAMPLE_UI_URI


def test_ac_41_22_resource_uri_scheme() -> None:
  """AC-41.22 — resourceUri must use ui://; a non-ui:// URI is rejected (R-26.3-b)."""
  assert is_ui_uri(EXAMPLE_UI_URI) is True
  assert is_ui_uri("https://example.com/app.html") is False
  assert is_ui_uri(42) is False
  with pytest.raises(InvalidToolUiMetaError):
    ToolUiMeta(resource_uri="https://example.com/app.html")


def test_ac_41_23_exact_resource_uri_read() -> None:
  """AC-41.23 — host fetches the EXACT resourceUri via resources/read (R-26.3-c)."""
  meta = ToolUiMeta(resource_uri=EXAMPLE_UI_URI)
  # The URI a host would read is the exact declared string (no transformation).
  assert meta.resource_uri == EXAMPLE_UI_URI
  # Round-trip through tool _meta preserves the exact string.
  tool_meta = meta.to_tool_meta()
  parsed = tool_ui_meta_from_tool_meta(tool_meta)
  assert parsed is not None
  assert parsed.resource_uri == EXAMPLE_UI_URI


def test_ac_41_24_visibility_default_and_enum() -> None:
  """AC-41.24 — visibility default ["model","app"]; only model/app elements (R-26.3-d)."""
  # Omitted ⇒ effective ["model","app"].
  omitted = ToolUiMeta(resource_uri=EXAMPLE_UI_URI)
  assert omitted.visibility is None
  assert omitted.effective_visibility() == DEFAULT_VISIBILITY
  assert DEFAULT_VISIBILITY == (VISIBILITY_MODEL, VISIBILITY_APP)
  # Present ⇒ only model/app allowed.
  ok = ToolUiMeta(resource_uri=EXAMPLE_UI_URI, visibility=["app"])
  assert ok.effective_visibility() == ("app",)
  with pytest.raises(InvalidToolUiMetaError):
    ToolUiMeta(resource_uri=EXAMPLE_UI_URI, visibility=["model", "human"])
  with pytest.raises(InvalidToolUiMetaError):
    ToolUiMeta(resource_uri=EXAMPLE_UI_URI, visibility="model")  # type: ignore[arg-type]
  assert VALID_VISIBILITY == {"model", "app"}


def test_ac_41_25_reject_non_app_ui_call() -> None:
  """AC-41.25 — UI-originated call rejected when visibility excludes "app" (R-26.3-e)."""
  model_only = ToolUiMeta(resource_uri=EXAMPLE_UI_URI, visibility=["model"])
  assert model_only.is_app_callable() is False
  assert host_should_reject_ui_call(model_only) is True
  # Default (model+app) is app-callable → not rejected.
  both = ToolUiMeta(resource_uri=EXAMPLE_UI_URI)
  assert both.is_app_callable() is True
  assert host_should_reject_ui_call(both) is False


def test_ac_41_26_app_only_hidden_from_model() -> None:
  """AC-41.26 — visibility ["app"] ⇒ callable only by UI, hidden from model (R-26.3-f)."""
  app_only = ToolUiMeta(resource_uri=EXAMPLE_UI_URI, visibility=["app"])
  assert app_only.is_model_visible() is False
  assert app_only.is_app_callable() is True
  # A model-visible tool is not hidden.
  assert ToolUiMeta(resource_uri=EXAMPLE_UI_URI).is_model_visible() is True


def test_ac_41_27_non_negotiating_ignores() -> None:
  """AC-41.27 — a non-negotiating receiver ignores _meta.ui (R-26.3-g)."""
  # Same predicate as R-26.2-i: inactive ⇒ ignore.
  assert receiver_ignores_ui_meta(None, None) is True
  assert receiver_ignores_ui_meta({}, _server_extensions_with_ui()) is True


def test_ac_41_28_ordinary_call_unchanged() -> None:
  """AC-41.28 — ordinary tools/call behavior unchanged by _meta.ui presence (R-26.3-h)."""
  with_ui = ToolUiMeta(resource_uri=EXAMPLE_UI_URI).to_tool_meta({"other": 1})
  without_ui = {"other": 1}
  assert ordinary_call_behavior_unchanged_by_ui_meta(with_ui) is True
  assert ordinary_call_behavior_unchanged_by_ui_meta(without_ui) is True


def test_tool_ui_meta_roundtrip_and_helpers() -> None:
  """ToolUiMeta serialises/parses; absent visibility is omitted; base meta preserved."""
  meta = ToolUiMeta(resource_uri=EXAMPLE_UI_URI, visibility=["model", "app"])
  d = meta.to_dict()
  assert d == {"resourceUri": EXAMPLE_UI_URI, "visibility": ["model", "app"]}
  # Omitted visibility is dropped (means default).
  assert "visibility" not in ToolUiMeta(resource_uri=EXAMPLE_UI_URI).to_dict()
  # to_tool_meta merges under the reserved "ui" key, preserving base keys.
  tool_meta = meta.to_tool_meta({"keep": True})
  assert tool_meta["keep"] is True
  assert tool_meta[TOOL_UI_META_KEY] == d
  # Round trip.
  assert tool_ui_meta_from_tool_meta(tool_meta).to_dict() == d
  # No ui key → None.
  assert tool_ui_meta_from_tool_meta({"keep": True}) is None
  assert tool_ui_meta_from_tool_meta(None) is None


# ---------------------------------------------------------------------------
# §26.4  UI resource, ui:// scheme, hints  (AC-41.29 … AC-41.41)
# ---------------------------------------------------------------------------

def test_ac_41_29_may_preload() -> None:
  """AC-41.29 — the host MAY preload the UI resource before the tool is called (R-26.4-a)."""
  assert host_may_preload_ui_resource() is True


def test_ac_41_30_uri_opaque() -> None:
  """AC-41.30 — the whole ui:// URI is treated as an opaque identifier (R-26.4-b)."""
  assert ui_uri_is_opaque_identifier(EXAMPLE_UI_URI) is True
  # Server-defined authority/path: any ui:// content is still opaque.
  assert ui_uri_is_opaque_identifier("ui://anything/here?x=1#frag") is True
  assert ui_uri_is_opaque_identifier("https://example.com") is False
  assert UI_URI_SCHEME == "ui://"


def test_ac_41_31_no_network_origin() -> None:
  """AC-41.31 — the host derives no network origin from a ui:// URI (R-26.4-c)."""
  assert host_derives_network_origin_from_ui_uri("ui://example.com/app.html") is False


def test_ac_41_32_content_mime_verbatim() -> None:
  """AC-41.32 — UI content MIME is verbatim text/html;profile=mcp-app (R-26.4-d)."""
  assert_ui_mime_type(UI_MIME_TYPE)  # no raise
  for bad in ("text/html", "text/html; profile=mcp-app", "TEXT/HTML;PROFILE=MCP-APP"):
    with pytest.raises(ValueError):
      assert_ui_mime_type(bad)
  text = TextResourceContents(uri=EXAMPLE_UI_URI, text=EXAMPLE_HTML, mime_type=UI_MIME_TYPE)
  assert is_ui_resource_content(text) is True
  plain = TextResourceContents(uri=EXAMPLE_UI_URI, text=EXAMPLE_HTML, mime_type="text/html")
  assert is_ui_resource_content(plain) is False


def test_ac_41_33_content_hints() -> None:
  """AC-41.33 — a content entry MAY carry _meta.ui hints that take effect (R-26.4-e)."""
  content = {
    "uri": EXAMPLE_UI_URI,
    "mimeType": UI_MIME_TYPE,
    "text": EXAMPLE_HTML,
    "_meta": {
      "ui": {
        "csp": {"connectDomains": ["https://api.example.com"]},
        "permissions": {"clipboardWrite": {}},
        "prefersBorder": True,
      }
    },
  }
  resource = UiResource.from_content_dict(content)
  assert resource.ui_meta is not None
  assert resource.ui_meta.prefers_border is True
  assert resource.ui_meta.permissions is not None
  assert resource.ui_meta.permissions.clipboard_write is True
  # resource_ui_meta_from_content_meta also reads hints directly.
  hints = resource_ui_meta_from_content_meta(content["_meta"])
  assert hints is not None
  assert hints.csp is not None
  # No _meta.ui → None.
  assert resource_ui_meta_from_content_meta({}) is None
  assert resource_ui_meta_from_content_meta(None) is None


def test_ac_41_34_csp_members() -> None:
  """AC-41.34 — csp members enumerate connect/resource/frame/baseUri origins (R-26.4-f)."""
  csp = UiContentSecurityPolicy(
    connect_domains=["https://c.example.com"],
    resource_domains=["https://r.example.com"],
    frame_domains=["https://f.example.com"],
    base_uri_domains=["https://b.example.com"],
  )
  assert csp.allowed_origins("connectDomains") == ("https://c.example.com",)
  assert csp.allowed_origins("resourceDomains") == ("https://r.example.com",)
  assert csp.allowed_origins("frameDomains") == ("https://f.example.com",)
  assert csp.allowed_origins("baseUriDomains") == ("https://b.example.com",)
  # Round-trip preserves member names.
  assert UiContentSecurityPolicy.from_dict(csp.to_dict()).to_dict() == csp.to_dict()


def test_ac_41_35_unlisted_origin_blocked() -> None:
  """AC-41.35 — an origin not in the applicable csp member is blocked (R-26.4-g)."""
  csp = UiContentSecurityPolicy(connect_domains=["https://allowed.example.com"])
  assert csp.origin_allowed("connectDomains", "https://allowed.example.com") is True
  assert csp.origin_allowed("connectDomains", "https://evil.example.com") is False
  assert host_blocks_origin("https://evil.example.com", "connectDomains", csp) is True
  assert host_blocks_origin("https://allowed.example.com", "connectDomains", csp) is False
  # An omitted member within a present csp blocks everything for that member.
  assert host_blocks_origin("https://x.example.com", "frameDomains", csp) is True


def test_ac_41_36_csp_omitted_deny_default() -> None:
  """AC-41.36 — csp omitted ⇒ host applies restrictive deny-by-default (R-26.4-h)."""
  assert host_default_policy_is_deny(None) is True
  # With csp omitted, every origin is blocked for every member.
  assert host_blocks_origin("https://anything.example.com", "connectDomains", None) is True
  csp = UiContentSecurityPolicy(connect_domains=["https://x.example.com"])
  assert host_default_policy_is_deny(csp) is False


def test_ac_41_37_permissions_shape() -> None:
  """AC-41.37 — permissions members are exact-name + {}; presence ⇒ requested (R-26.4-i)."""
  perms = UiPermissions.from_dict({"camera": {}, "clipboardWrite": {}})
  assert perms.is_requested("camera") is True
  assert perms.is_requested("clipboardWrite") is True
  assert perms.is_requested("microphone") is False
  assert perms.requested() == {"camera", "clipboardWrite"}
  assert VALID_PERMISSIONS == {"camera", "microphone", "geolocation", "clipboardWrite"}
  # Unknown member name rejected.
  with pytest.raises(ValueError):
    UiPermissions.from_dict({"bluetooth": {}})
  # Non-{} value rejected.
  with pytest.raises(ValueError):
    UiPermissions.from_dict({"camera": {"x": 1}})
  # Round-trip: each requested capability maps to {}.
  assert perms.to_dict() == {"camera": {}, "clipboardWrite": {}}


def test_ac_41_38_unrequested_not_granted() -> None:
  """AC-41.38 — a capability not present in permissions is not granted (R-26.4-j)."""
  perms = UiPermissions(camera=True)
  assert host_may_grant_permission("camera", perms) is True
  assert host_may_grant_permission("microphone", perms) is False
  # Omitted permissions entirely → nothing grantable.
  assert host_may_grant_permission("camera", None) is False


def test_ac_41_39_requested_may_be_declined() -> None:
  """AC-41.39 — a requested capability MAY be declined by the host (R-26.4-k)."""
  perms = UiPermissions(geolocation=True)
  # "may grant" means permitted, never required — the host is free to decline.
  assert host_may_grant_permission("geolocation", perms) is True
  # Declining is a host policy choice; the model does not force a grant.
  # (Represented by the host simply not acting on the True permission.)


def test_ac_41_40_domain_hint() -> None:
  """AC-41.40 — domain ⇒ host SHOULD render under that dedicated origin (R-26.4-l)."""
  hints = ResourceUiMeta(domain="https://ui.example.com")
  assert hints.domain == "https://ui.example.com"
  assert ResourceUiMeta.from_dict({"domain": "https://ui.example.com"}).domain == (
    "https://ui.example.com"
  )
  with pytest.raises(TypeError):
    ResourceUiMeta(domain=123)  # type: ignore[arg-type]


def test_ac_41_41_prefers_border() -> None:
  """AC-41.41 — prefersBorder ⇒ host MAY honor or ignore the preference (R-26.4-m)."""
  assert ResourceUiMeta(prefers_border=True).prefers_border is True
  assert ResourceUiMeta(prefers_border=False).prefers_border is False
  # Absent ⇒ None (no preference expressed).
  assert ResourceUiMeta().prefers_border is None
  with pytest.raises(TypeError):
    ResourceUiMeta(prefers_border="yes")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# §26.4  Host rendering isolation  (AC-41.42 … AC-41.44)
# ---------------------------------------------------------------------------

def test_ac_41_42_sandbox_denies_access() -> None:
  """AC-41.42 — sandboxed/isolated context denies doc/cookies/storage/nav (R-26.4-n)."""
  assert host_must_sandbox_rendered_ui() is True
  assert SANDBOX_DENIED_ACCESS == {"embedding_document", "cookies", "storage", "navigation"}
  for denied in ("embedding_document", "cookies", "storage", "navigation"):
    assert sandbox_denies_access(denied) is True
  assert sandbox_denies_access("microphone") is False


def test_ac_41_43_restrictive_csp() -> None:
  """AC-41.43 — host applies a restrictive CSP constrained by csp (R-26.4-o)."""
  assert host_must_apply_restrictive_csp() is True
  # Constrained-by-csp behavior is exercised by host_blocks_origin (AC-41.35/36).
  csp = UiContentSecurityPolicy(resource_domains=["https://cdn.example.com"])
  assert host_blocks_origin("https://cdn.example.com", "resourceDomains", csp) is False
  assert host_blocks_origin("https://other.example.com", "resourceDomains", csp) is True


def test_ac_41_44_no_ambient_access() -> None:
  """AC-41.44 — rendered content has no ambient host access (only S42 channel) (R-26.4-p)."""
  assert rendered_ui_has_ambient_host_access() is False


# ---------------------------------------------------------------------------
# UiResource construction & serialization
# ---------------------------------------------------------------------------

def test_ui_resource_validates_mime_and_scheme() -> None:
  """UiResource enforces verbatim MIME and ui:// scheme on its contents."""
  good = TextResourceContents(uri=EXAMPLE_UI_URI, text=EXAMPLE_HTML, mime_type=UI_MIME_TYPE)
  res = UiResource(contents=good)
  assert res.uri == EXAMPLE_UI_URI
  # Wrong MIME rejected.
  with pytest.raises(ValueError):
    UiResource(
      contents=TextResourceContents(uri=EXAMPLE_UI_URI, text=EXAMPLE_HTML, mime_type="text/html")
    )
  # Non-ui:// scheme rejected.
  with pytest.raises(ValueError):
    UiResource(
      contents=TextResourceContents(
        uri="https://example.com/x", text=EXAMPLE_HTML, mime_type=UI_MIME_TYPE
      )
    )


def test_ui_resource_blob_variant_and_content_dict_roundtrip() -> None:
  """UiResource supports a blob payload and round-trips its content dict with hints."""
  # Base64 of EXAMPLE_HTML bytes via a known-valid placeholder string.
  import base64

  blob = base64.b64encode(EXAMPLE_HTML.encode()).decode()
  contents = BlobResourceContents(uri=EXAMPLE_UI_URI, blob=blob, mime_type=UI_MIME_TYPE)
  hints = ResourceUiMeta(
    csp=UiContentSecurityPolicy(connect_domains=["https://api.example.com"]),
    permissions=UiPermissions(clipboard_write=True),
    prefers_border=True,
  )
  res = UiResource(contents=contents, ui_meta=hints)
  out = res.to_content_dict()
  assert out["uri"] == EXAMPLE_UI_URI
  assert out["mimeType"] == UI_MIME_TYPE
  assert out["blob"] == blob
  assert out["_meta"]["ui"]["prefersBorder"] is True
  # Re-parse the produced content dict.
  reparsed = UiResource.from_content_dict(out)
  assert reparsed.ui_meta is not None
  assert reparsed.ui_meta.permissions is not None
  assert reparsed.ui_meta.permissions.clipboard_write is True


def test_ui_resource_preserves_existing_content_meta() -> None:
  """Serializing UI hints preserves other _meta keys already on the content."""
  contents = TextResourceContents(
    uri=EXAMPLE_UI_URI,
    text=EXAMPLE_HTML,
    mime_type=UI_MIME_TYPE,
    meta={"vendor.example/note": "keep-me"},
  )
  res = UiResource(contents=contents, ui_meta=ResourceUiMeta(prefers_border=True))
  out = res.to_content_dict()
  assert out["_meta"]["vendor.example/note"] == "keep-me"
  assert out["_meta"]["ui"]["prefersBorder"] is True


# ---------------------------------------------------------------------------
# Registry integration (S38) — the extension negotiates via the standard machinery
# ---------------------------------------------------------------------------

def test_definition_registers_and_negotiates() -> None:
  """UI_EXTENSION_DEFINITION registers in an ExtensionRegistry and goes active on intersection."""
  registry = ExtensionRegistry([UI_EXTENSION_DEFINITION])
  assert registry.recognizes(UI_EXTENSION_IDENTIFIER) is True
  client = _host_extensions_with_ui()
  server = _server_extensions_with_ui()
  # Active only in the intersection.
  assert registry.is_active(UI_EXTENSION_IDENTIFIER, client, server) is True
  assert registry.is_active(UI_EXTENSION_IDENTIFIER, client, {}) is False
  # The module-level predicate agrees with the registry.
  assert ui_extension_active(client, server) is True


def test_definition_identifier_and_classification() -> None:
  """The definition carries the exact identifier and MODULAR classification."""
  assert UI_EXTENSION_DEFINITION.identifier == UI_EXTENSION_IDENTIFIER
  assert UI_EXTENSION_DEFINITION.classification is ExtensionClassification.MODULAR


# ---------------------------------------------------------------------------
# Full wire example from the spec (§26 examples 9.1–9.4)
# ---------------------------------------------------------------------------

def test_spec_wire_examples_roundtrip() -> None:
  """The §26 host advertisement, tool declaration, and resource read parse correctly."""
  # 9.1 host advertisement inside a request _meta.
  request_meta = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    KEY_CLIENT_CAPABILITIES: {
      "extensions": {
        UI_EXTENSION_IDENTIFIER: {"mimeTypes": [UI_MIME_TYPE]},
      }
    },
  }
  host_ext = host_capabilities_from_request_meta(request_meta)
  assert host_advertises_ui_extension(host_ext) is True

  # 9.3 tool _meta.ui.
  tool = {
    "name": "get-time",
    "_meta": {"ui": {"resourceUri": EXAMPLE_UI_URI, "visibility": ["model", "app"]}},
  }
  ui_meta = tool_ui_meta_from_tool_meta(tool["_meta"])
  assert ui_meta is not None
  assert ui_meta.resource_uri == EXAMPLE_UI_URI
  assert ui_meta.effective_visibility() == ("model", "app")

  # 9.4 resources/read content entry.
  content = {
    "uri": EXAMPLE_UI_URI,
    "mimeType": UI_MIME_TYPE,
    "text": EXAMPLE_HTML,
    "_meta": {
      "ui": {
        "csp": {
          "connectDomains": ["https://api.example.com"],
          "resourceDomains": ["https://cdn.example.com"],
        },
        "permissions": {"clipboardWrite": {}},
        "prefersBorder": True,
      }
    },
  }
  res = UiResource.from_content_dict(content)
  assert is_ui_resource_content(res.contents) is True
  assert res.ui_meta is not None
  assert res.ui_meta.csp is not None
  assert res.ui_meta.csp.origin_allowed("connectDomains", "https://api.example.com") is True
  assert host_blocks_origin("https://evil.example.com", "connectDomains", res.ui_meta.csp) is True
