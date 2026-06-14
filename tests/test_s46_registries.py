"""Tests for S46 — Consolidated Registries (Appendices A–E).

Validates the five consolidated reference registries and the cross-cutting rules
they restate, and asserts each registry agrees with the feature modules that own
the underlying methods, error codes, _meta keys, capabilities, and extension
identifiers.

AC → test coverage map
----------------------
AC-46.1  (R-AppB-a)  -> test_ac_46_1_custom_code_must_not_collide_with_registry
                        test_ac_46_1_registered_codes_match_spec_set
AC-46.2  (R-AppB-b)  -> test_ac_46_2_range_additions_accepted_when_no_collision
                        test_ac_46_2_range_collision_with_header_mismatch_rejected
                        test_ac_46_2_reserved_range_is_minus32000_to_minus32099
AC-46.3  (R-AppC-a)  -> test_ac_46_3_registry_reserved_keys_are_permitted
                        test_ac_46_3_bare_reserved_keys_recognized
AC-46.4  (R-AppC-b)  -> test_ac_46_4_missing_protocol_version_non_conformant
                        test_ac_46_4_protocol_version_required_row
AC-46.5  (R-AppC-c)  -> test_ac_46_5_missing_client_info_non_conformant
AC-46.6  (R-AppC-d)  -> test_ac_46_6_missing_client_capabilities_non_conformant
AC-46.7  (R-AppC-e)  -> test_ac_46_7_log_level_optional_and_deprecated
AC-46.8  (R-AppC-f)  -> test_ac_46_8_progress_token_optional
AC-46.9  (R-AppC-g)  -> test_ac_46_9_trace_context_keys_optional_on_both
AC-46.10 (R-AppC-h,  -> test_ac_46_10_ui_host_value_requires_mimetypes
          R-AppD-f)     test_ac_46_10_ui_host_value_missing_mimetypes_non_conformant
AC-46.11 (R-AppC-i)  -> test_ac_46_11_tool_ui_meta_requires_resource_uri
                        test_ac_46_11_tool_ui_meta_missing_resource_uri_non_conformant
                        test_ac_46_11_tool_ui_meta_non_ui_scheme_rejected
AC-46.12 (R-AppC-j)  -> test_ac_46_12_extension_key_permitted
                        test_ac_46_12_protocol_prefix_key_reserved_not_extension
AC-46.13 (R-AppD-a)  -> test_ac_46_13_elicitation_form_optional_url_mode
AC-46.14 (R-AppD-b)  -> test_ac_46_14_sampling_subflags_and_capability_deprecated
AC-46.15 (R-AppD-c)  -> test_ac_46_15_tools_list_changed_optional_boolean
AC-46.16 (R-AppD-d)  -> test_ac_46_16_resources_list_changed_and_subscribe
AC-46.17 (R-AppD-e)  -> test_ac_46_17_prompts_list_changed_optional_boolean
AC-46.18 (R-AppD-f)  -> test_ac_46_18_ui_host_mimetypes_includes_mcp_app
                        test_ac_46_18_empty_server_acknowledgement_conformant

Registry-agreement and completeness tests strengthen correctness by importing
the feature modules and asserting the registry rows reproduce their constants.
"""

from __future__ import annotations

import pytest

from mcp_sdk_py import registries as reg
from mcp_sdk_py.registries import (
  CAPABILITY_REGISTRY,
  ERROR_CODE_REGISTRY_ENTRIES,
  INPUT_REQUEST_KIND_NOTE,
  InvalidToolUiMetaError,
  InvalidUiHostValueError,
  Kind,
  META_KEY_REGISTRY,
  METHOD_NOTIFICATION_INDEX,
  METHOD_NOTIFICATION_INDEX_CORE,
  METHOD_NOTIFICATION_INDEX_UI_DIALECT,
  MissingRequiredClientMetaKeyError,
  REGISTERED_ERROR_CODES,
  REQUIRED_CLIENT_REQUEST_META_KEYS,
  RESERVED_META_KEYS,
  Requirement,
  ReservedErrorCodeCollisionError,
  Side,
  TYPE_INDEX,
  capability_entry,
  is_empty_ui_server_acknowledgement,
  is_extension_meta_key,
  is_in_reserved_server_error_range,
  is_reserved_meta_key,
  meta_key_entry,
  method_notification_entry,
  type_index_entry,
  type_index_is_alphabetical,
  validate_additional_error_code,
  validate_client_request_reserved_keys,
  validate_tool_ui_meta,
  validate_ui_host_value,
)


# A vendor-neutral, well-formed client _meta with the three REQUIRED keys.
def _client_meta(**overrides: object) -> dict[str, object]:
  meta: dict[str, object] = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientInfo": {
      "name": "example-client",
      "version": "1.4.0",
    },
    "io.modelcontextprotocol/clientCapabilities": {},
  }
  meta.update(overrides)
  return meta


# ===========================================================================
# AC-46.1 (R-AppB-a) — custom error code MUST NOT collide with a registry code
# ===========================================================================

@pytest.mark.parametrize("code", sorted(REGISTERED_ERROR_CODES))
def test_ac_46_1_custom_code_must_not_collide_with_registry(code: int) -> None:
  with pytest.raises(ReservedErrorCodeCollisionError):
    validate_additional_error_code(code)


def test_ac_46_1_registered_codes_match_spec_set() -> None:
  # The exact codes Appendix B / AC-46.1 enumerate.
  expected = {-32700, -32600, -32601, -32602, -32603, -32003, -32004, -32001}
  assert REGISTERED_ERROR_CODES == expected
  # And every concrete row in the registry is one of these codes.
  concrete = {e.code for e in ERROR_CODE_REGISTRY_ENTRIES if e.code is not None}
  assert concrete == expected


def test_registry_agrees_with_errors_module() -> None:
  # The consolidated table reuses S34's RESERVED_ERROR_CODES verbatim.
  from mcp_sdk_py.errors import RESERVED_ERROR_CODES as s34_reserved

  assert REGISTERED_ERROR_CODES == s34_reserved


# ===========================================================================
# AC-46.2 (R-AppB-b) — additions within -32000..-32099 if no collision
# ===========================================================================

def test_ac_46_2_range_additions_accepted_when_no_collision() -> None:
  # -32050 is the spec's worked example: in range, no collision with -32001.
  assert validate_additional_error_code(-32050) == -32050
  assert is_in_reserved_server_error_range(-32050)


def test_ac_46_2_range_collision_with_header_mismatch_rejected() -> None:
  # -32001 (HeaderMismatch) occupies one value of the reserved range.
  assert is_in_reserved_server_error_range(-32001)
  with pytest.raises(ReservedErrorCodeCollisionError):
    validate_additional_error_code(-32001)


def test_ac_46_2_reserved_range_is_minus32000_to_minus32099() -> None:
  assert is_in_reserved_server_error_range(-32000)
  assert is_in_reserved_server_error_range(-32099)
  assert not is_in_reserved_server_error_range(-31999)
  assert not is_in_reserved_server_error_range(-32100)
  # The registry carries a dedicated reserved-range row with those bounds.
  range_rows = [e for e in ERROR_CODE_REGISTRY_ENTRIES if e.code is None]
  assert len(range_rows) == 1
  row = range_rows[0]
  assert row.range_min == -32099
  assert row.range_max == -32000


# ===========================================================================
# AC-46.3 (R-AppC-a) — registry-reserved keys are permitted, not unknown
# ===========================================================================

@pytest.mark.parametrize(
  "key",
  [
    "io.modelcontextprotocol/protocolVersion",
    "io.modelcontextprotocol/clientInfo",
    "io.modelcontextprotocol/clientCapabilities",
    "io.modelcontextprotocol/logLevel",
    "io.modelcontextprotocol/subscriptionId",
    "io.modelcontextprotocol/tasks",
    "io.modelcontextprotocol/ui",
    "progressToken",
    "traceparent",
    "tracestate",
    "baggage",
    "ui",
  ],
)
def test_ac_46_3_registry_reserved_keys_are_permitted(key: str) -> None:
  assert is_reserved_meta_key(key)
  # Listed by literal value in the registry table.
  assert key in RESERVED_META_KEYS
  assert meta_key_entry(key) is not None


def test_ac_46_3_bare_reserved_keys_recognized() -> None:
  for key in ("progressToken", "traceparent", "tracestate", "baggage"):
    assert is_reserved_meta_key(key)
  # A truly unknown custom key is NOT registry-reserved.
  assert not is_reserved_meta_key("x-custom-unprefixed")


def test_reserved_keys_agree_with_meta_object_module() -> None:
  from mcp_sdk_py.meta_object import RESERVED_BARE_KEYS

  for key in RESERVED_BARE_KEYS:
    assert is_reserved_meta_key(key)


# ===========================================================================
# AC-46.4 (R-AppC-b) — protocolVersion REQUIRED on every client request
# ===========================================================================

def test_ac_46_4_missing_protocol_version_non_conformant() -> None:
  meta = _client_meta()
  del meta["io.modelcontextprotocol/protocolVersion"]
  with pytest.raises(MissingRequiredClientMetaKeyError) as ei:
    validate_client_request_reserved_keys(meta)
  assert ei.value.missing_key == "io.modelcontextprotocol/protocolVersion"


def test_ac_46_4_protocol_version_required_row() -> None:
  entry = meta_key_entry("io.modelcontextprotocol/protocolVersion")
  assert entry is not None
  assert entry.requirement is Requirement.REQUIRED
  assert "every client request" in entry.used_on
  assert "io.modelcontextprotocol/protocolVersion" in REQUIRED_CLIENT_REQUEST_META_KEYS


def test_ac_46_4_well_formed_client_meta_conformant() -> None:
  # No exception for the complete, well-formed _meta.
  validate_client_request_reserved_keys(_client_meta())


# ===========================================================================
# AC-46.5 (R-AppC-c) — clientInfo REQUIRED
# ===========================================================================

def test_ac_46_5_missing_client_info_non_conformant() -> None:
  meta = _client_meta()
  del meta["io.modelcontextprotocol/clientInfo"]
  with pytest.raises(MissingRequiredClientMetaKeyError) as ei:
    validate_client_request_reserved_keys(meta)
  assert ei.value.missing_key == "io.modelcontextprotocol/clientInfo"
  entry = meta_key_entry("io.modelcontextprotocol/clientInfo")
  assert entry is not None and entry.requirement is Requirement.REQUIRED
  assert "Implementation" in entry.meaning


# ===========================================================================
# AC-46.6 (R-AppC-d) — clientCapabilities REQUIRED
# ===========================================================================

def test_ac_46_6_missing_client_capabilities_non_conformant() -> None:
  meta = _client_meta()
  del meta["io.modelcontextprotocol/clientCapabilities"]
  with pytest.raises(MissingRequiredClientMetaKeyError) as ei:
    validate_client_request_reserved_keys(meta)
  assert ei.value.missing_key == "io.modelcontextprotocol/clientCapabilities"
  entry = meta_key_entry("io.modelcontextprotocol/clientCapabilities")
  assert entry is not None and entry.requirement is Requirement.REQUIRED
  assert "ClientCapabilities" in entry.meaning


def test_required_client_keys_agree_with_meta_object_module() -> None:
  from mcp_sdk_py.meta_object import REQUIRED_CLIENT_REQUEST_KEYS

  assert REQUIRED_CLIENT_REQUEST_META_KEYS == REQUIRED_CLIENT_REQUEST_KEYS


# ===========================================================================
# AC-46.7 (R-AppC-e) — logLevel OPTIONAL and Deprecated
# ===========================================================================

def test_ac_46_7_log_level_optional_and_deprecated() -> None:
  # Omitting logLevel is still conformant (OPTIONAL).
  meta = _client_meta()
  assert "io.modelcontextprotocol/logLevel" not in meta
  validate_client_request_reserved_keys(meta)  # no raise
  entry = meta_key_entry("io.modelcontextprotocol/logLevel")
  assert entry is not None
  assert entry.requirement is Requirement.OPTIONAL
  assert entry.deprecated is True


# ===========================================================================
# AC-46.8 (R-AppC-f) — progressToken OPTIONAL
# ===========================================================================

def test_ac_46_8_progress_token_optional() -> None:
  entry = meta_key_entry("progressToken")
  assert entry is not None
  assert entry.requirement is Requirement.OPTIONAL
  assert "notifications/progress" in entry.meaning
  assert "string or number" in entry.meaning
  # Request _meta with or without progressToken is conformant.
  validate_client_request_reserved_keys(_client_meta())
  validate_client_request_reserved_keys(_client_meta(progressToken="p-42"))
  validate_client_request_reserved_keys(_client_meta(progressToken=7))


# ===========================================================================
# AC-46.9 (R-AppC-g) — traceparent/tracestate/baggage OPTIONAL on both
# ===========================================================================

@pytest.mark.parametrize("key", ["traceparent", "tracestate", "baggage"])
def test_ac_46_9_trace_context_keys_optional_on_both(key: str) -> None:
  entry = meta_key_entry(key)
  assert entry is not None
  assert entry.requirement is Requirement.OPTIONAL
  assert "request and notification" in entry.used_on


def test_ac_46_9_any_trace_context_combination_conformant() -> None:
  # Present in any combination on a request: still conformant.
  validate_client_request_reserved_keys(
    _client_meta(
      traceparent="00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
      tracestate="vendor=value",
      baggage="k=v",
    )
  )
  # On a (non-client) notification _meta they are simply reserved, not required.
  notif_meta = {"traceparent": "00-abc-def-01"}
  assert is_reserved_meta_key("traceparent")
  assert "traceparent" in notif_meta


# ===========================================================================
# AC-46.10 (R-AppC-h, R-AppD-f) — UI host value requires mimeTypes
# ===========================================================================

def test_ac_46_10_ui_host_value_requires_mimetypes() -> None:
  validate_ui_host_value({"mimeTypes": ["text/html;profile=mcp-app"]})


def test_ac_46_10_ui_host_value_missing_mimetypes_non_conformant() -> None:
  with pytest.raises(InvalidUiHostValueError):
    validate_ui_host_value({})
  with pytest.raises(InvalidUiHostValueError):
    validate_ui_host_value({"other": 1})
  with pytest.raises(InvalidUiHostValueError):
    validate_ui_host_value("not-an-object")


def test_ac_46_10_ui_registry_row_marks_mimetypes_required() -> None:
  entry = meta_key_entry("io.modelcontextprotocol/ui")
  assert entry is not None
  assert entry.requirement is Requirement.REQUIRED
  assert "mimeTypes" in entry.meaning


# ===========================================================================
# AC-46.11 (R-AppC-i) — tool _meta.ui requires resourceUri (ui:// URI)
# ===========================================================================

def test_ac_46_11_tool_ui_meta_requires_resource_uri() -> None:
  validate_tool_ui_meta({"resourceUri": "ui://charts/line", "visibility": "inline"})
  # visibility OPTIONAL.
  validate_tool_ui_meta({"resourceUri": "ui://charts/line"})


def test_ac_46_11_tool_ui_meta_missing_resource_uri_non_conformant() -> None:
  with pytest.raises(InvalidToolUiMetaError):
    validate_tool_ui_meta({"visibility": "inline"})
  with pytest.raises(InvalidToolUiMetaError):
    validate_tool_ui_meta({})
  with pytest.raises(InvalidToolUiMetaError):
    validate_tool_ui_meta("not-an-object")


def test_ac_46_11_tool_ui_meta_non_ui_scheme_rejected() -> None:
  with pytest.raises(InvalidToolUiMetaError):
    validate_tool_ui_meta({"resourceUri": "https://example.test/x"})


def test_ac_46_11_tool_ui_registry_row() -> None:
  entry = meta_key_entry("ui")
  assert entry is not None
  assert entry.requirement is Requirement.REQUIRED
  assert "resourceUri" in entry.meaning
  assert "ui://" in entry.meaning
  assert "user-interface extension is active" in entry.meaning


# ===========================================================================
# AC-46.12 (R-AppC-j) — extension-defined keys permitted
# ===========================================================================

def test_ac_46_12_extension_key_permitted() -> None:
  # A namespaced, non-protocol-reserved extension key MAY appear.
  assert is_extension_meta_key("com.example/feature")
  assert is_extension_meta_key("org.vendor-x/setting")
  # And is recognized as not an unknown/forbidden key.
  assert not is_reserved_meta_key("com.example/feature")  # not protocol-reserved
  assert is_extension_meta_key("com.example/feature")


def test_ac_46_12_protocol_prefix_key_reserved_not_extension() -> None:
  # io.modelcontextprotocol/... keys are protocol-reserved, not extension keys.
  assert is_reserved_meta_key("io.modelcontextprotocol/somethingNew")
  assert not is_extension_meta_key("io.modelcontextprotocol/somethingNew")
  # A bare non-reserved key is neither protocol-reserved nor a valid extension key.
  assert not is_extension_meta_key("plainBareKey")


# ===========================================================================
# AC-46.13 (R-AppD-a) — elicitation: form OPTIONAL; url is other mode
# ===========================================================================

def test_ac_46_13_elicitation_form_optional_url_mode() -> None:
  entry = capability_entry("elicitation", side=Side.CLIENT)
  assert entry is not None
  assert entry.side is Side.CLIENT
  form = entry.sub_flag("form")
  assert form is not None
  assert form.requirement is Requirement.OPTIONAL
  # url mode is recognized as the other defined elicitation mode.
  assert reg.ELICITATION_URL_MODE == "url"
  assert "url" in form.note


# ===========================================================================
# AC-46.14 (R-AppD-b) — sampling: tools/context OPTIONAL, both/cap deprecated
# ===========================================================================

def test_ac_46_14_sampling_subflags_and_capability_deprecated() -> None:
  entry = capability_entry("sampling", side=Side.CLIENT)
  assert entry is not None
  assert entry.deprecated is True  # capability itself Deprecated.
  tools = entry.sub_flag("tools")
  context = entry.sub_flag("context")
  assert tools is not None and tools.requirement is Requirement.OPTIONAL
  assert tools.deprecated is False
  assert "toolChoice" in tools.note
  assert context is not None and context.requirement is Requirement.OPTIONAL
  assert context.deprecated is True
  assert "includeContext" in context.note


# ===========================================================================
# AC-46.15 (R-AppD-c) — tools.listChanged OPTIONAL boolean
# ===========================================================================

def test_ac_46_15_tools_list_changed_optional_boolean() -> None:
  entry = capability_entry("tools", side=Side.SERVER)
  assert entry is not None
  flag = entry.sub_flag("listChanged")
  assert flag is not None
  assert flag.requirement is Requirement.OPTIONAL
  assert "boolean" in flag.note


# ===========================================================================
# AC-46.16 (R-AppD-d) — resources.listChanged & subscribe OPTIONAL boolean
# ===========================================================================

def test_ac_46_16_resources_list_changed_and_subscribe() -> None:
  entry = capability_entry("resources", side=Side.SERVER)
  assert entry is not None
  for name in ("listChanged", "subscribe"):
    flag = entry.sub_flag(name)
    assert flag is not None, name
    assert flag.requirement is Requirement.OPTIONAL
    assert "boolean" in flag.note


# ===========================================================================
# AC-46.17 (R-AppD-e) — prompts.listChanged OPTIONAL boolean
# ===========================================================================

def test_ac_46_17_prompts_list_changed_optional_boolean() -> None:
  entry = capability_entry("prompts", side=Side.SERVER)
  assert entry is not None
  flag = entry.sub_flag("listChanged")
  assert flag is not None
  assert flag.requirement is Requirement.OPTIONAL
  assert "boolean" in flag.note


# ===========================================================================
# AC-46.18 (R-AppD-f) — UI host mimeTypes must include text/html;profile=mcp-app
# ===========================================================================

def test_ac_46_18_ui_host_mimetypes_includes_mcp_app() -> None:
  # Must include the verbatim MIME type.
  validate_ui_host_value({"mimeTypes": ["text/html;profile=mcp-app"]})
  with pytest.raises(InvalidUiHostValueError):
    validate_ui_host_value({"mimeTypes": ["text/plain"]})
  with pytest.raises(InvalidUiHostValueError):
    validate_ui_host_value({"mimeTypes": []})
  # mimeTypes must be a string array.
  with pytest.raises(InvalidUiHostValueError):
    validate_ui_host_value({"mimeTypes": "text/html;profile=mcp-app"})
  with pytest.raises(InvalidUiHostValueError):
    validate_ui_host_value({"mimeTypes": [123]})


def test_ac_46_18_empty_server_acknowledgement_conformant() -> None:
  # Server acknowledgement value MAY be empty.
  assert is_empty_ui_server_acknowledgement({})
  assert not is_empty_ui_server_acknowledgement({"mimeTypes": []})
  assert not is_empty_ui_server_acknowledgement(None)


def test_ac_46_18_ui_mime_type_agrees_with_ui_module() -> None:
  from mcp_sdk_py.ui import UI_MIME_TYPE

  assert UI_MIME_TYPE == "text/html;profile=mcp-app"
  validate_ui_host_value({"mimeTypes": [UI_MIME_TYPE]})


# ===========================================================================
# Appendix A — Method and Notification Index agreement & completeness
# ===========================================================================

def test_appendix_a_core_methods_agree_with_feature_modules() -> None:
  from mcp_sdk_py.completion import METHOD_COMPLETION_COMPLETE
  from mcp_sdk_py.progress import DISCOVER_METHOD
  from mcp_sdk_py.tasks_ops import (
    TASKS_CANCEL_METHOD,
    TASKS_GET_METHOD,
    TASKS_NOTIFICATION_METHOD,
    TASKS_UPDATE_METHOD,
  )
  from mcp_sdk_py.tools import METHOD_TOOLS_CALL, METHOD_TOOLS_LIST

  for name in (
    DISCOVER_METHOD,
    METHOD_TOOLS_LIST,
    METHOD_TOOLS_CALL,
    METHOD_COMPLETION_COMPLETE,
    TASKS_GET_METHOD,
    TASKS_UPDATE_METHOD,
    TASKS_CANCEL_METHOD,
    TASKS_NOTIFICATION_METHOD,
  ):
    assert method_notification_entry(name) is not None, name


def test_appendix_a_input_request_kinds_flagged() -> None:
  for name in ("elicitation/create", "sampling/createMessage", "roots/list"):
    entry = method_notification_entry(name)
    assert entry is not None
    assert entry.kind is Kind.INPUT_REQUEST_KIND
    assert "input-required result" in entry.direction
  # The footnote restates the embedded-delivery rule.
  assert "input-required result" in INPUT_REQUEST_KIND_NOTE
  assert "NOT a standalone" in INPUT_REQUEST_KIND_NOTE


def test_appendix_a_input_request_kinds_agree_with_mrtr() -> None:
  from mcp_sdk_py.multi_round_trip import RECOGNIZED_INPUT_REQUEST_METHODS

  kinds = {
    e.name for e in METHOD_NOTIFICATION_INDEX
    if e.kind is Kind.INPUT_REQUEST_KIND
  }
  assert kinds == set(RECOGNIZED_INPUT_REQUEST_METHODS)


def test_appendix_a_ui_dialect_names_in_scope_only_with_extension() -> None:
  # Every UI-dialect row is flagged ui_dialect=True; core rows are not.
  assert all(e.ui_dialect for e in METHOD_NOTIFICATION_INDEX_UI_DIALECT)
  assert all(not e.ui_dialect for e in METHOD_NOTIFICATION_INDEX_CORE)
  # A UI-dialect name is excluded when UI dialect is not requested.
  teardown = "ui/resource-teardown"
  assert method_notification_entry(teardown) is not None
  assert method_notification_entry(teardown, include_ui_dialect=False) is None


def test_appendix_a_ui_dialect_names_agree_with_ui_host_module() -> None:
  from mcp_sdk_py import ui_host

  expected_ui_dialect = {
    ui_host.NOTIFICATION_TOOL_INPUT,
    ui_host.NOTIFICATION_TOOL_INPUT_PARTIAL,
    ui_host.NOTIFICATION_TOOL_RESULT,
    ui_host.NOTIFICATION_TOOL_CANCELLED,
    ui_host.METHOD_TOOLS_CALL,
    ui_host.METHOD_RESOURCES_READ,
    ui_host.METHOD_UI_OPEN_LINK,
    ui_host.METHOD_UI_MESSAGE,
    ui_host.METHOD_UI_REQUEST_DISPLAY_MODE,
    ui_host.METHOD_UI_UPDATE_MODEL_CONTEXT,
    ui_host.NOTIFICATION_MESSAGE,
    ui_host.METHOD_PING,
    ui_host.NOTIFICATION_SIZE_CHANGED,
    ui_host.NOTIFICATION_HOST_CONTEXT_CHANGED,
    ui_host.METHOD_UI_RESOURCE_TEARDOWN,
    ui_host.NOTIFICATION_SANDBOX_PROXY_READY,
    ui_host.NOTIFICATION_SANDBOX_RESOURCE_READY,
  }
  actual = {e.name for e in METHOD_NOTIFICATION_INDEX_UI_DIALECT}
  assert actual == expected_ui_dialect


def test_appendix_a_index_has_no_duplicate_core_names() -> None:
  names = [e.name for e in METHOD_NOTIFICATION_INDEX_CORE]
  assert len(names) == len(set(names))


# ===========================================================================
# Appendix C — _meta key registry agreement
# ===========================================================================

def test_appendix_c_subscription_id_agrees_with_subscriptions_module() -> None:
  from mcp_sdk_py.subscriptions import SUBSCRIPTION_ID_META_KEY

  entry = meta_key_entry(SUBSCRIPTION_ID_META_KEY)
  assert entry is not None
  assert entry.key == "io.modelcontextprotocol/subscriptionId"


def test_appendix_c_extension_identifiers_agree_with_modules() -> None:
  from mcp_sdk_py.tasks import TASKS_EXTENSION_IDENTIFIER
  from mcp_sdk_py.ui import TOOL_UI_META_KEY, UI_EXTENSION_IDENTIFIER

  assert meta_key_entry(TASKS_EXTENSION_IDENTIFIER) is not None
  assert meta_key_entry(UI_EXTENSION_IDENTIFIER) is not None
  assert meta_key_entry(TOOL_UI_META_KEY) is not None
  assert TOOL_UI_META_KEY == "ui"


# ===========================================================================
# Appendix D — capability registry coverage
# ===========================================================================

def test_appendix_d_covers_all_capabilities() -> None:
  client = {
    (e.capability, e.side) for e in CAPABILITY_REGISTRY if e.side is Side.CLIENT
  }
  server = {
    (e.capability, e.side) for e in CAPABILITY_REGISTRY if e.side is Side.SERVER
  }
  assert {c for c, _ in client} == {
    "elicitation", "roots", "sampling", "extensions"
  }
  assert {c for c, _ in server} == {
    "tools", "resources", "prompts", "completions", "logging", "extensions"
  }
  # The two extension capabilities (negotiated via extensions).
  ext = {e.capability for e in CAPABILITY_REGISTRY if e.side in (
    Side.CLIENT_AND_SERVER, Side.HOST_CLIENT_AND_SERVER)}
  assert ext == {
    "io.modelcontextprotocol/tasks", "io.modelcontextprotocol/ui"
  }


def test_appendix_d_extensions_disambiguated_by_side() -> None:
  client_ext = capability_entry("extensions", side=Side.CLIENT)
  server_ext = capability_entry("extensions", side=Side.SERVER)
  assert client_ext is not None and client_ext.side is Side.CLIENT
  assert server_ext is not None and server_ext.side is Side.SERVER


def test_appendix_d_extension_caps_agree_with_modules() -> None:
  from mcp_sdk_py.tasks import TASKS_EXTENSION_IDENTIFIER
  from mcp_sdk_py.ui import UI_EXTENSION_IDENTIFIER

  assert capability_entry(TASKS_EXTENSION_IDENTIFIER) is not None
  assert capability_entry(UI_EXTENSION_IDENTIFIER) is not None


# ===========================================================================
# Appendix E — consolidated type index
# ===========================================================================

def test_appendix_e_sorted_alphabetically_case_insensitive() -> None:
  assert type_index_is_alphabetical()


def test_appendix_e_lookup_and_known_types() -> None:
  for name in (
    "Annotations", "CallToolResult", "Error", "JSONRPCMessage",
    "Tool", "ToolUiMeta", "WorkingTask",
  ):
    entry = type_index_entry(name)
    assert entry is not None, name
    assert entry.defined_in.startswith("§")
    assert entry.purpose


def test_appendix_e_no_duplicate_types() -> None:
  names = [e.type_name for e in TYPE_INDEX]
  assert len(names) == len(set(names))


def test_appendix_e_expected_size() -> None:
  # The Appendix E table lists 176 types.
  assert len(TYPE_INDEX) == 176


# ===========================================================================
# Module import smoke test
# ===========================================================================

def test_module_imports_cleanly() -> None:
  import mcp_sdk_py.registries  # noqa: F401

  assert reg.METHOD_NOTIFICATION_INDEX
  assert reg.ERROR_CODE_REGISTRY_ENTRIES
  assert reg.META_KEY_REGISTRY
  assert reg.CAPABILITY_REGISTRY
  assert reg.TYPE_INDEX
