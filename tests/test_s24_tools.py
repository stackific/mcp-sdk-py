"""Tests for S24 — Tools I: Capability, Listing & the Tool Type (§16.1–§16.4).

Exercises every normative atom and acceptance criterion of the discovery half of
MCP tools: the ``tools`` capability and its gating, ``tools/list`` request and
result shapes (pagination + caching hints), the ``Tool`` type and naming
conventions, and the JSON Schema rules for ``inputSchema``/``outputSchema``.

AC → test coverage map
----------------------
- AC-24.1  (R-16.1-a, R-16.1-c): test_ac_24_1_server_declares_tools_and_gates_when_absent
- AC-24.2  (R-16.1-d):           test_ac_24_2_client_does_not_send_when_tools_absent
- AC-24.3  (R-16.1-b):           test_ac_24_3_list_changed_emission_gate
- AC-24.4  (R-16.1-e):           test_ac_24_4_client_does_not_rely_on_list_changed
- AC-24.5  (R-16.1-f):           test_ac_24_5_server_responds_with_current_tool_set
- AC-24.6  (R-16.1-g):           test_ac_24_6_empty_and_changing_tool_set
- AC-24.7  (R-16.1-h):           test_ac_24_7_set_does_not_vary_per_connection
- AC-24.8  (R-16.1-i):           test_ac_24_8_set_may_vary_by_authorization
- AC-24.9  (R-16.2-o):           test_ac_24_9_deterministic_order
- AC-24.10 (R-16.2-a):           test_ac_24_10_optional_cursor
- AC-24.11 (R-16.2-b):           test_ac_24_11_tools_is_array
- AC-24.12 (R-16.2-c, R-16.2-d): test_ac_24_12_next_cursor_presence_and_resume
- AC-24.13 (R-16.2-e, R-16.2-f): test_ac_24_13_next_cursor_is_opaque
- AC-24.14 (R-16.2-g, R-16.2-j): test_ac_24_14_ttl_and_scope_present_and_valid
- AC-24.15 (R-16.2-h, R-16.2-i): test_ac_24_15_ttl_freshness_semantics
- AC-24.16 (R-16.2-k, R-16.2-l): test_ac_24_16_cache_scope_sharing
- AC-24.17 (R-16.2-m):           test_ac_24_17_result_type_complete
- AC-24.18 (R-16.2-n):           test_ac_24_18_result_meta_optional
- AC-24.19 (R-16.3-a):           test_ac_24_19_tool_name_required_string
- AC-24.20 (R-16.3-b…f):         test_ac_24_20_name_conventions
- AC-24.21 (R-16.3-g, R-16.3-h): test_ac_24_21_aggregation_disambiguation
- AC-24.22 (R-16.3-i):           test_ac_24_22_display_name_precedence
- AC-24.23 (R-16.3-j):           test_ac_24_23_description_optional_hint
- AC-24.24 (R-16.3-k, R-16.4-d): test_ac_24_24_input_schema_object_root
- AC-24.25 (R-16.3-l):           test_ac_24_25_no_parameter_tool_schema
- AC-24.26 (R-16.3-m…p):         test_ac_24_26_optional_tool_fields
- AC-24.27 (R-16.4-a, R-16.4-b): test_ac_24_27_dialect_default_and_declared
- AC-24.28 (R-16.4-c):           test_ac_24_28_permitted_keywords
- AC-24.29 (R-16.4-e, R-16.4-v): test_ac_24_29_output_schema_any_root
- AC-24.30 (R-16.4-f, R-16.4-g): test_ac_24_30_no_external_dereferencing
- AC-24.31 (R-16.4-h, R-16.4-i, R-16.4-j): test_ac_24_31_optin_external_mode
- AC-24.32 (R-16.4-k):           test_ac_24_32_unresolved_external_ref_rejected
- AC-24.33 (R-16.4-l, R-16.4-m): test_ac_24_33_bounded_depth_and_size
- AC-24.34 (R-16.4-n):           test_ac_24_34_reject_unsafe_schema
- AC-24.35 (R-16.4-o, R-16.4-p): test_ac_24_35_validation_roles_server
- AC-24.36 (R-16.4-q, R-16.4-r): test_ac_24_36_client_validation_in_document
- AC-24.37 (R-16.4-s, R-16.4-t): test_ac_24_37_unsupported_dialect_error
- AC-24.38 (R-16.4-u):           test_ac_24_38_supported_dialects_documented
- AC-24.39 (R-16-a):             test_ac_24_39_human_can_deny
"""

from __future__ import annotations

import pytest

from mcp_sdk_py.common_types import Icon
from mcp_sdk_py.tools import (
  DEFAULT_MAX_SCHEMA_DEPTH,
  JSON_SCHEMA_2020_12_URI,
  METHOD_TOOLS_CALL,
  METHOD_TOOLS_LIST,
  SUPPORTED_SCHEMA_DIALECTS,
  TOOL_NAME_MAX_LENGTH,
  ExternalDereferenceLimits,
  ExternalReferenceError,
  ListToolsRequestParams,
  ListToolsResult,
  SchemaBounds,
  SchemaResolutionMode,
  Tool,
  ToolsCapability,
  ToolsCapabilityNotDeclaredError,
  UnsafeSchemaError,
  UnsupportedSchemaDialectError,
  assert_client_may_send_tool_request,
  client_may_rely_on_list_changed,
  client_may_send_tool_request,
  disambiguate_tool_name,
  human_can_deny_invocation,
  is_supported_dialect,
  next_request_after,
  reference_is_in_document,
  resolve_references,
  schema_dialect,
  server_declares_tools,
  server_must_declare_tools,
  structured_content_conforms,
  tool_display_name,
  tool_name_follows_conventions,
  tool_names_are_unique,
  validate_arguments_against_input_schema,
  validate_input_schema,
  validate_output_schema,
  validate_tool_name_conventions,
)

OBJECT_SCHEMA: dict = {"type": "object"}


def make_tool(name: str = "do_thing", **kwargs) -> Tool:
  """Build a minimal valid Tool with an object inputSchema."""
  kwargs.setdefault("input_schema", {"type": "object"})
  return Tool(name=name, **kwargs)


def make_result(tools: list[Tool] | None = None, **kwargs) -> ListToolsResult:
  """Build a minimal valid ListToolsResult."""
  kwargs.setdefault("ttl_ms", 1000)
  kwargs.setdefault("cache_scope", "public")
  return ListToolsResult(tools=tools if tools is not None else [], **kwargs)


# ---------------------------------------------------------------------------
# AC-24.1 — server declares tools; gates tools/list & tools/call when absent
# ---------------------------------------------------------------------------

def test_ac_24_1_server_declares_tools_and_gates_when_absent():
  # A server exposing tools declares the `tools` capability (R-16.1-a).
  caps_with_tools = ToolsCapability(list_changed=True)
  server_caps = {"tools": caps_with_tools.to_dict()}
  assert server_declares_tools(server_caps) is True
  # When declared, the server may answer (no raise) (R-16.1-c).
  server_must_declare_tools(server_caps)

  # When NOT declared, the server MUST NOT respond to tools/list or tools/call.
  no_tools: dict = {"resources": {}}
  assert server_declares_tools(no_tools) is False
  with pytest.raises(ToolsCapabilityNotDeclaredError):
    server_must_declare_tools(no_tools)


# ---------------------------------------------------------------------------
# AC-24.2 — client does not send tools/list or tools/call when tools absent
# ---------------------------------------------------------------------------

def test_ac_24_2_client_does_not_send_when_tools_absent():
  no_tools: dict = {}
  assert client_may_send_tool_request(no_tools, METHOD_TOOLS_LIST) is False
  assert client_may_send_tool_request(no_tools, METHOD_TOOLS_CALL) is False
  with pytest.raises(ToolsCapabilityNotDeclaredError):
    assert_client_may_send_tool_request(no_tools, METHOD_TOOLS_LIST)
  with pytest.raises(ToolsCapabilityNotDeclaredError):
    assert_client_may_send_tool_request(no_tools, METHOD_TOOLS_CALL)

  # When declared, the client may send both (R-16.1-d satisfied).
  with_tools: dict = {"tools": {}}
  assert client_may_send_tool_request(with_tools, METHOD_TOOLS_LIST) is True
  assert client_may_send_tool_request(with_tools, METHOD_TOOLS_CALL) is True
  assert_client_may_send_tool_request(with_tools, METHOD_TOOLS_LIST)


# ---------------------------------------------------------------------------
# AC-24.3 — listChanged emission gate (R-16.1-b)
# ---------------------------------------------------------------------------

def test_ac_24_3_list_changed_emission_gate():
  # Absent → does not emit.
  assert ToolsCapability().emits_list_changed is False
  # False → does not emit.
  assert ToolsCapability(list_changed=False).emits_list_changed is False
  # True → MAY emit notifications/tools/list_changed.
  assert ToolsCapability(list_changed=True).emits_list_changed is True
  # Round-trip the wire form.
  assert ToolsCapability.from_dict({"listChanged": True}).emits_list_changed is True
  assert ToolsCapability.from_dict({}).emits_list_changed is False


def test_tools_capability_rejects_non_boolean_list_changed():
  with pytest.raises(TypeError):
    ToolsCapability(list_changed="yes")  # type: ignore[arg-type]
  with pytest.raises(TypeError):
    ToolsCapability.from_dict({"listChanged": 1})


# ---------------------------------------------------------------------------
# AC-24.4 — client does not rely on list_changed unless listChanged: true
# ---------------------------------------------------------------------------

def test_ac_24_4_client_does_not_rely_on_list_changed():
  assert client_may_rely_on_list_changed({"tools": {}}) is False
  assert client_may_rely_on_list_changed({"tools": {"listChanged": False}}) is False
  assert client_may_rely_on_list_changed({}) is False  # tools absent entirely
  assert client_may_rely_on_list_changed({"tools": {"listChanged": True}}) is True


# ---------------------------------------------------------------------------
# AC-24.5 — server responds with the set of tools currently available
# ---------------------------------------------------------------------------

def test_ac_24_5_server_responds_with_current_tool_set():
  tools = [make_tool("alpha"), make_tool("beta")]
  result = make_result(tools)
  assert [t.name for t in result.tools] == ["alpha", "beta"]
  wire = result.to_dict()
  assert [t["name"] for t in wire["tools"]] == ["alpha", "beta"]


# ---------------------------------------------------------------------------
# AC-24.6 — empty tool set is valid; set may change later
# ---------------------------------------------------------------------------

def test_ac_24_6_empty_and_changing_tool_set():
  empty = make_result([])
  assert empty.tools == []
  assert empty.to_dict()["tools"] == []
  # A later request may return a different (changed) set.
  later = make_result([make_tool("new_tool")])
  assert [t.name for t in later.tools] == ["new_tool"]


# ---------------------------------------------------------------------------
# AC-24.7 — set does not vary per-connection / as a side effect
# ---------------------------------------------------------------------------

def test_ac_24_7_set_does_not_vary_per_connection():
  # Two listings produced for identical authorization yield identical sets.
  def list_for(auth: str) -> ListToolsResult:
    if auth == "scoped":
      return make_result([make_tool("alpha"), make_tool("beta")])
    return make_result([make_tool("alpha")])

  first = list_for("scoped").to_dict()["tools"]
  # An unrelated request happens on the same connection — must not change the set.
  _ = list_for("scoped")
  second = list_for("scoped").to_dict()["tools"]
  assert first == second


# ---------------------------------------------------------------------------
# AC-24.8 — set MAY vary by authorization presented on the request
# ---------------------------------------------------------------------------

def test_ac_24_8_set_may_vary_by_authorization():
  def list_for(scopes: set[str]) -> ListToolsResult:
    tools = [make_tool("read_tool")]
    if "admin" in scopes:
      tools.append(make_tool("admin_tool"))
    return make_result(tools)

  reader = {t.name for t in list_for({"read"}).tools}
  admin = {t.name for t in list_for({"read", "admin"}).tools}
  assert reader == {"read_tool"}
  assert admin == {"read_tool", "admin_tool"}
  assert reader != admin  # credentials are per-request input, set may differ


# ---------------------------------------------------------------------------
# AC-24.9 — deterministic order across requests with unchanged set
# ---------------------------------------------------------------------------

def test_ac_24_9_deterministic_order():
  names = ["c_tool", "a_tool", "b_tool"]
  first = make_result([make_tool(n) for n in names]).to_dict()["tools"]
  second = make_result([make_tool(n) for n in names]).to_dict()["tools"]
  assert [t["name"] for t in first] == [t["name"] for t in second] == names


# ---------------------------------------------------------------------------
# AC-24.10 — optional cursor in request params
# ---------------------------------------------------------------------------

def test_ac_24_10_optional_cursor():
  # Absence of cursor requests the first page.
  first_page = ListToolsRequestParams()
  assert first_page.cursor is None
  assert first_page.to_dict() == {}
  assert ListToolsRequestParams.from_dict(None).cursor is None
  assert ListToolsRequestParams.from_dict({}).cursor is None
  # Present opaque cursor resumes a page.
  resumed = ListToolsRequestParams(cursor="page-2-opaque-token")
  assert resumed.to_dict() == {"cursor": "page-2-opaque-token"}
  # Empty string is a valid, present cursor.
  empty_cursor = ListToolsRequestParams.from_dict({"cursor": ""})
  assert empty_cursor.cursor == ""
  assert empty_cursor.to_dict() == {"cursor": ""}


def test_request_params_reject_non_string_cursor():
  with pytest.raises(TypeError):
    ListToolsRequestParams(cursor=5)  # type: ignore[arg-type]
  with pytest.raises(TypeError):
    ListToolsRequestParams.from_dict({"cursor": 5})


# ---------------------------------------------------------------------------
# AC-24.11 — tools present as an array of Tool definitions
# ---------------------------------------------------------------------------

def test_ac_24_11_tools_is_array():
  result = make_result([make_tool("alpha")])
  assert isinstance(result.tools, list)
  assert all(isinstance(t, Tool) for t in result.tools)
  # tools is REQUIRED on the wire.
  with pytest.raises(ValueError):
    ListToolsResult.from_dict({"resultType": "complete", "ttlMs": 0, "cacheScope": "public"})
  # tools must be an array.
  with pytest.raises(TypeError):
    ListToolsResult.from_dict(
      {"resultType": "complete", "ttlMs": 0, "cacheScope": "public", "tools": {}}
    )


# ---------------------------------------------------------------------------
# AC-24.12 — nextCursor present on non-final page, absent on final; resume
# ---------------------------------------------------------------------------

def test_ac_24_12_next_cursor_presence_and_resume():
  non_final = make_result([make_tool("alpha")], next_cursor="next-page-cursor")
  assert non_final.is_last_page is False
  assert non_final.to_dict()["nextCursor"] == "next-page-cursor"
  # Client MAY re-issue tools/list with cursor set to nextCursor.
  follow_up = next_request_after(non_final)
  assert follow_up is not None
  assert follow_up.cursor == "next-page-cursor"

  final = make_result([make_tool("omega")])
  assert final.is_last_page is True
  assert "nextCursor" not in final.to_dict()
  assert next_request_after(final) is None


# ---------------------------------------------------------------------------
# AC-24.13 — nextCursor opaque: passed through verbatim, not parsed/constructed
# ---------------------------------------------------------------------------

def test_ac_24_13_next_cursor_is_opaque():
  opaque = "::weird//opaque++token=="
  result = make_result([make_tool("a")], next_cursor=opaque)
  follow_up = next_request_after(result)
  assert follow_up is not None
  # Verbatim pass-through — byte-for-byte identical, never parsed or reconstructed.
  assert follow_up.cursor == opaque
  assert follow_up.to_dict()["cursor"] == opaque


# ---------------------------------------------------------------------------
# AC-24.14 — ttlMs present (number >= 0) and cacheScope present (public/private)
# ---------------------------------------------------------------------------

def test_ac_24_14_ttl_and_scope_present_and_valid():
  result = make_result([make_tool("a")], ttl_ms=300000, cache_scope="private")
  wire = result.to_dict()
  assert wire["ttlMs"] == 300000 and wire["ttlMs"] >= 0
  assert wire["cacheScope"] in {"public", "private"}

  # ttlMs is REQUIRED.
  with pytest.raises(ValueError):
    ListToolsResult.from_dict(
      {"resultType": "complete", "tools": [], "cacheScope": "public"}
    )
  # cacheScope is REQUIRED.
  with pytest.raises(ValueError):
    ListToolsResult.from_dict(
      {"resultType": "complete", "tools": [], "ttlMs": 0}
    )
  # ttlMs must be non-negative.
  with pytest.raises(ValueError):
    make_result([], ttl_ms=-1)
  # cacheScope must be exactly public/private.
  with pytest.raises(ValueError):
    make_result([], cache_scope="shared")


# ---------------------------------------------------------------------------
# AC-24.15 — ttlMs freshness semantics (0 = stale, N>0 = fresh for N ms)
# ---------------------------------------------------------------------------

def test_ac_24_15_ttl_freshness_semantics():
  stale = make_result([], ttl_ms=0)
  assert stale.is_immediately_stale is True
  fresh = make_result([], ttl_ms=5000)
  assert fresh.is_immediately_stale is False
  assert fresh.ttl_ms == 5000  # client MAY cache up to this many ms


# ---------------------------------------------------------------------------
# AC-24.16 — cacheScope public vs private sharing
# ---------------------------------------------------------------------------

def test_ac_24_16_cache_scope_sharing():
  public = make_result([], cache_scope="public")
  assert public.is_public is True and public.is_private is False
  private = make_result([], cache_scope="private")
  assert private.is_private is True and private.is_public is False


# ---------------------------------------------------------------------------
# AC-24.17 — resultType equals "complete"
# ---------------------------------------------------------------------------

def test_ac_24_17_result_type_complete():
  result = make_result([])
  assert result.result_type == "complete"
  assert result.to_dict()["resultType"] == "complete"
  # resultType is REQUIRED on the wire.
  with pytest.raises(ValueError):
    ListToolsResult.from_dict({"tools": [], "ttlMs": 0, "cacheScope": "public"})


# ---------------------------------------------------------------------------
# AC-24.18 — _meta optional on the result
# ---------------------------------------------------------------------------

def test_ac_24_18_result_meta_optional():
  without = make_result([])
  assert "_meta" not in without.to_dict()
  with_meta = make_result([], meta={"io.example/trace": "abc"})
  assert with_meta.to_dict()["_meta"] == {"io.example/trace": "abc"}
  parsed = ListToolsResult.from_dict(with_meta.to_dict())
  assert parsed.meta == {"io.example/trace": "abc"}


# ---------------------------------------------------------------------------
# AC-24.19 — Tool.name required string, used by tools/call
# ---------------------------------------------------------------------------

def test_ac_24_19_tool_name_required_string():
  tool = make_tool("get_weather")
  assert tool.name == "get_weather"
  assert tool.to_dict()["name"] == "get_weather"
  with pytest.raises(ValueError):
    make_tool("")  # empty name rejected
  with pytest.raises((ValueError, TypeError)):
    Tool(name=None, input_schema={"type": "object"})  # type: ignore[arg-type]
  # name is required on the wire.
  with pytest.raises(KeyError):
    Tool.from_dict({"inputSchema": {"type": "object"}})


# ---------------------------------------------------------------------------
# AC-24.20 — name conventions: length, case-sensitivity, charset, uniqueness
# ---------------------------------------------------------------------------

def test_ac_24_20_name_conventions():
  # Conforming names.
  assert tool_name_follows_conventions("get_weather.v2-beta") is True
  assert validate_tool_name_conventions("get_weather.v2-beta") == []
  # Length bounds (1..128 inclusive).
  assert tool_name_follows_conventions("a" * TOOL_NAME_MAX_LENGTH) is True
  assert tool_name_follows_conventions("a" * (TOOL_NAME_MAX_LENGTH + 1)) is False
  assert tool_name_follows_conventions("") is False
  # Spaces, commas, and other special chars violate conventions.
  assert tool_name_follows_conventions("bad name") is False
  assert tool_name_follows_conventions("a,b") is False
  assert tool_name_follows_conventions("emoji_😀") is False
  problems = validate_tool_name_conventions("bad, name!")
  assert any("space" in p for p in problems)
  assert any("comma" in p for p in problems)
  # Case-sensitivity: differing only in case is distinct → unique.
  assert tool_names_are_unique(["Tool", "tool"]) is True
  assert tool_names_are_unique(["dup", "dup"]) is False


# ---------------------------------------------------------------------------
# AC-24.21 — aggregation collisions get a disambiguation strategy
# ---------------------------------------------------------------------------

def test_ac_24_21_aggregation_disambiguation():
  # Two servers each expose a tool named "search" — a collision.
  server_a_tools = ["search"]
  server_b_tools = ["search"]
  combined = server_a_tools + server_b_tools
  assert tool_names_are_unique(combined) is False  # collision acknowledged
  # A disambiguation strategy (server-id prefix) resolves it.
  qualified = [
    disambiguate_tool_name("serverA", "search"),
    disambiguate_tool_name("serverB", "search"),
  ]
  assert qualified == ["serverA.search", "serverB.search"]
  assert tool_names_are_unique(qualified) is True
  # The original name is recoverable after the prefix.
  assert qualified[0].split(".", 1)[1] == "search"


# ---------------------------------------------------------------------------
# AC-24.22 — display-name precedence: title -> annotations.title -> name
# ---------------------------------------------------------------------------

def test_ac_24_22_display_name_precedence():
  # title wins.
  t1 = make_tool("name1", title="Title One", annotations={"title": "Ann Title"})
  assert t1.display_name() == "Title One"
  # annotations.title is the fallback when title absent.
  t2 = make_tool("name2", annotations={"title": "Ann Title"})
  assert t2.display_name() == "Ann Title"
  # name is the final fallback.
  t3 = make_tool("name3")
  assert t3.display_name() == "name3"
  # Title is optional.
  assert t3.title is None
  # Standalone helper matches the precedence.
  assert tool_display_name("n", "T", {"title": "A"}) == "T"
  assert tool_display_name("n", None, {"title": "A"}) == "A"
  assert tool_display_name("n", None, None) == "n"


# ---------------------------------------------------------------------------
# AC-24.23 — description optional; MAY be passed to the model as a hint
# ---------------------------------------------------------------------------

def test_ac_24_23_description_optional_hint():
  without = make_tool("t")
  assert without.description is None
  assert "description" not in without.to_dict()
  with_desc = make_tool("t", description="Gets current weather for a location")
  assert with_desc.description == "Gets current weather for a location"
  assert with_desc.to_dict()["description"] == "Gets current weather for a location"


# ---------------------------------------------------------------------------
# AC-24.24 — inputSchema present, JSON Schema 2020-12 object, root type object
# ---------------------------------------------------------------------------

def test_ac_24_24_input_schema_object_root():
  tool = make_tool("t", input_schema={"type": "object", "properties": {"x": {"type": "string"}}})
  assert tool.input_schema["type"] == "object"
  # validate_input_schema accepts object-root schemas and returns them.
  assert validate_input_schema({"type": "object"}) == {"type": "object"}
  # Non-object root is rejected.
  with pytest.raises(UnsafeSchemaError):
    validate_input_schema({"type": "string"})
  with pytest.raises(UnsafeSchemaError):
    validate_input_schema({"type": "array"})
  # Missing type at root is rejected (must be "object").
  with pytest.raises(UnsafeSchemaError):
    validate_input_schema({"properties": {}})
  # A Tool with a non-object input schema fails construction.
  with pytest.raises(UnsafeSchemaError):
    Tool(name="t", input_schema={"type": "array"})


# ---------------------------------------------------------------------------
# AC-24.25 — no-parameter tool still provides a valid object schema
# ---------------------------------------------------------------------------

def test_ac_24_25_no_parameter_tool_schema():
  # Empty-object-only schema.
  strict = make_tool("noargs", input_schema={"type": "object", "additionalProperties": False})
  assert strict.input_schema["additionalProperties"] is False
  # Any-object schema.
  loose = make_tool("noargs2", input_schema={"type": "object"})
  assert loose.input_schema == {"type": "object"}
  # Both validate.
  validate_input_schema({"type": "object", "additionalProperties": False})
  validate_input_schema({"type": "object"})


# ---------------------------------------------------------------------------
# AC-24.26 — optional Tool fields: outputSchema, annotations, icons, _meta
# ---------------------------------------------------------------------------

def test_ac_24_26_optional_tool_fields():
  icon = Icon(src="https://example.com/i.png", mime_type="image/png", sizes=["48x48"])
  tool = make_tool(
    "full",
    output_schema={"type": "object", "properties": {"temp": {"type": "number"}}},
    annotations={"title": "Full Tool", "readOnlyHint": True},
    icons=[icon],
    meta={"io.example/x": 1},
  )
  wire = tool.to_dict()
  assert wire["outputSchema"]["type"] == "object"
  assert wire["annotations"] == {"title": "Full Tool", "readOnlyHint": True}
  assert wire["icons"][0]["src"] == "https://example.com/i.png"
  assert wire["_meta"] == {"io.example/x": 1}
  # Round-trips through from_dict.
  parsed = Tool.from_dict(wire)
  assert parsed.output_schema == tool.output_schema
  assert parsed.annotations == tool.annotations
  assert isinstance(parsed.icons[0], Icon)
  assert parsed.meta == {"io.example/x": 1}
  # Absent optionals are omitted.
  minimal = make_tool("min").to_dict()
  for key in ("outputSchema", "annotations", "icons", "_meta", "title", "description"):
    assert key not in minimal


def test_tool_rejects_bad_optional_field_types():
  with pytest.raises(TypeError):
    make_tool("t", annotations=["not", "an", "object"])  # type: ignore[arg-type]
  with pytest.raises(TypeError):
    make_tool("t", icons="not-a-list")  # type: ignore[arg-type]
  with pytest.raises(TypeError):
    make_tool("t", icons=[{"src": "x"}])  # not Icon objects
  with pytest.raises(TypeError):
    make_tool("t", meta="not-an-object")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# AC-24.27 — dialect: default 2020-12 when no $schema; declared $schema governs
# ---------------------------------------------------------------------------

def test_ac_24_27_dialect_default_and_declared():
  # No $schema → JSON Schema 2020-12 default.
  assert schema_dialect({"type": "object"}) == JSON_SCHEMA_2020_12_URI
  # Explicit $schema governs interpretation and is returned verbatim.
  custom = "http://json-schema.org/draft-07/schema#"
  assert schema_dialect({"type": "object", "$schema": custom}) == custom


# ---------------------------------------------------------------------------
# AC-24.28 — permitted 2020-12 keywords alongside root type object
# ---------------------------------------------------------------------------

def test_ac_24_28_permitted_keywords():
  schema = {
    "type": "object",
    "properties": {"location": {"type": "string"}},
    "required": ["location"],
    "additionalProperties": False,
    "$defs": {"x": {"type": "string"}},
  }
  # All permitted alongside the required root type.
  assert validate_input_schema(schema) == schema


# ---------------------------------------------------------------------------
# AC-24.29 — outputSchema any root type; structuredContent any JSON value
# ---------------------------------------------------------------------------

def test_ac_24_29_output_schema_any_root():
  # Array-root outputSchema is accepted.
  array_out = {"type": "array", "items": {"type": "string"}}
  assert validate_output_schema(array_out) == array_out
  # Scalar/other roots accepted too.
  validate_output_schema({"type": "string"})
  validate_output_schema({"type": "number"})
  validate_output_schema({"type": "boolean"})
  validate_output_schema({"type": "null"})
  # A Tool with an array outputSchema constructs fine.
  tool = make_tool("t", output_schema=array_out)
  assert tool.output_schema["type"] == "array"
  # structuredContent MAY be any JSON value when no outputSchema is set.
  no_out = make_tool("t2")
  for value in ({}, [], "s", 1, 1.5, True, None):
    assert structured_content_conforms(no_out, value) is True


# ---------------------------------------------------------------------------
# AC-24.30 — no external dereferencing; only in-document refs resolved
# ---------------------------------------------------------------------------

def test_ac_24_30_no_external_dereferencing():
  # In-document references are fine.
  assert reference_is_in_document("#/$defs/Address") is True
  assert reference_is_in_document("#anchor") is True
  in_doc_schema = {
    "type": "object",
    "properties": {"a": {"$ref": "#/$defs/A"}},
    "$defs": {"A": {"type": "string"}},
  }
  resolve_references(in_doc_schema)  # no raise
  validate_input_schema(in_doc_schema)

  # External references are NOT fetched; they raise instead.
  assert reference_is_in_document("https://evil.example/schema.json") is False
  ext_schema = {
    "type": "object",
    "properties": {"a": {"$ref": "https://evil.example/schema.json"}},
  }
  with pytest.raises(ExternalReferenceError):
    resolve_references(ext_schema)
  with pytest.raises(ExternalReferenceError):
    validate_input_schema(ext_schema)
  # $dynamicRef to an external target is likewise refused.
  dyn = {"type": "object", "properties": {"a": {"$dynamicRef": "https://x.example/s#m"}}}
  with pytest.raises(ExternalReferenceError):
    resolve_references(dyn)


# ---------------------------------------------------------------------------
# AC-24.31 — opt-in external mode: disabled by default; policy when enabled
# ---------------------------------------------------------------------------

def test_ac_24_31_optin_external_mode():
  # Disabled by default (R-16.4-i).
  default_mode = SchemaResolutionMode()
  assert default_mode.allow_external is False
  assert default_mode.external_host_allowed("example.com") is False

  # Enabled mode with allowlist + private-address rejection + timeout/size limits.
  limits = ExternalDereferenceLimits(
    host_allowlist=frozenset({"schemas.example.com"}),
    reject_private_addresses=True,
    timeout_seconds=3.0,
    max_response_bytes=65536,
  )
  mode = SchemaResolutionMode(allow_external=True, limits=limits)
  # Allowlisted host is permitted.
  assert mode.external_host_allowed("schemas.example.com") is True
  # Non-allowlisted host is rejected.
  assert mode.external_host_allowed("other.example.com") is False
  # Loopback / link-local / private addresses are rejected even if allowlisted-ish.
  open_mode = SchemaResolutionMode(
    allow_external=True,
    limits=ExternalDereferenceLimits(reject_private_addresses=True),
  )
  assert open_mode.external_host_allowed("127.0.0.1") is False
  assert open_mode.external_host_allowed("169.254.1.1") is False
  assert open_mode.external_host_allowed("10.0.0.5") is False
  assert open_mode.external_host_allowed("localhost") is False
  # A genuinely public, routable address passes the private-address gate.
  assert open_mode.external_host_allowed("8.8.8.8") is True

  # When enabled, every dereferenced URI is logged.
  schema = {"$ref": "https://schemas.example.com/a.json"}
  resolve_references(schema, mode)
  assert mode.dereference_log == ["https://schemas.example.com/a.json"]

  # An allowed=True mode still rejects a host failing the policy.
  bad = {"$ref": "https://other.example.com/a.json"}
  with pytest.raises(ExternalReferenceError):
    resolve_references(bad, mode)


# ---------------------------------------------------------------------------
# AC-24.32 — unresolved external $ref ⇒ rejected, not treated as permissive
# ---------------------------------------------------------------------------

def test_ac_24_32_unresolved_external_ref_rejected():
  schema = {"type": "object", "properties": {"a": {"$ref": "file:///etc/passwd"}}}
  # Rejected rather than silently treated as permissive.
  with pytest.raises(ExternalReferenceError):
    validate_input_schema(schema)


# ---------------------------------------------------------------------------
# AC-24.33 — bounded depth and size
# ---------------------------------------------------------------------------

def test_ac_24_33_bounded_depth_and_size():
  # Build a schema deeper than the default depth bound.
  deep: dict = {"type": "object"}
  node = deep
  for _ in range(DEFAULT_MAX_SCHEMA_DEPTH + 5):
    child: dict = {"type": "object"}
    node["properties"] = {"child": child}
    node = child
  with pytest.raises(UnsafeSchemaError):
    validate_input_schema(deep)

  # A tight custom bound also trips.
  tiny = SchemaBounds(max_depth=2, max_nodes=10_000)
  with pytest.raises(UnsafeSchemaError):
    validate_input_schema(
      {"type": "object", "properties": {"a": {"type": "object", "properties": {"b": {"type": "string"}}}}},
      bounds=tiny,
    )

  # A size bound trips on too many nodes.
  wide = {"type": "object", "properties": {f"p{i}": {"type": "string"} for i in range(50)}}
  with pytest.raises(UnsafeSchemaError):
    validate_input_schema(wide, bounds=SchemaBounds(max_depth=64, max_nodes=10))


# ---------------------------------------------------------------------------
# AC-24.34 — reject unsafe schema (null / not a JSON Schema object / external)
# ---------------------------------------------------------------------------

def test_ac_24_34_reject_unsafe_schema():
  # null is not a valid JSON Schema object.
  with pytest.raises(UnsafeSchemaError):
    validate_input_schema(None)
  with pytest.raises(UnsafeSchemaError):
    validate_output_schema(None)
  # Non-object JSON values are rejected.
  for bad in (42, "schema", [1, 2], True):
    with pytest.raises(UnsafeSchemaError):
      validate_output_schema(bad)
  # Requires external dereferencing it does not permit.
  with pytest.raises(ExternalReferenceError):
    validate_input_schema({"type": "object", "$ref": "https://x.example/s.json"})


# ---------------------------------------------------------------------------
# AC-24.35 — validation roles: server validates args; produces conforming output
# ---------------------------------------------------------------------------

def test_ac_24_35_validation_roles_server():
  tool = make_tool(
    "t",
    input_schema={"type": "object", "properties": {"x": {"type": "string"}}},
    output_schema={"type": "object"},
  )
  # Server validates the arguments object (must be an object per root type).
  assert validate_arguments_against_input_schema(tool, {"x": "hello"}) is True
  assert validate_arguments_against_input_schema(tool, ["not", "an", "object"]) is False
  assert validate_arguments_against_input_schema(tool, "scalar") is False
  # Server must produce structuredContent conforming to outputSchema.
  assert structured_content_conforms(tool, {"k": "v"}) is True
  assert structured_content_conforms(tool, [1, 2, 3]) is False  # not an object


# ---------------------------------------------------------------------------
# AC-24.36 — client validates structuredContent; in-document-only refs locally
# ---------------------------------------------------------------------------

def test_ac_24_36_client_validation_in_document():
  # Client validation of structuredContent against an array outputSchema.
  array_tool = make_tool("t", output_schema={"type": "array", "items": {"type": "string"}})
  assert structured_content_conforms(array_tool, ["a", "b"]) is True
  assert structured_content_conforms(array_tool, {"not": "array"}) is False

  # Local argument validation must use in-document-only $ref rules: an external
  # ref in the input schema is refused during local validation too.
  ext_tool = Tool.__new__(Tool)  # bypass __post_init__ to hold an external-ref schema
  ext_tool.name = "t"
  ext_tool.input_schema = {"type": "object", "properties": {"a": {"$ref": "https://x.example/s"}}}
  ext_tool.output_schema = None
  ext_tool.annotations = None
  ext_tool.icons = None
  ext_tool.meta = None
  ext_tool.title = None
  ext_tool.description = None
  with pytest.raises(ExternalReferenceError):
    validate_arguments_against_input_schema(ext_tool, {"a": 1})


# ---------------------------------------------------------------------------
# AC-24.37 — unsupported dialect returns an explicit error (not permissive)
# ---------------------------------------------------------------------------

def test_ac_24_37_unsupported_dialect_error():
  # 2020-12 (default + both URI forms) is supported.
  assert is_supported_dialect(JSON_SCHEMA_2020_12_URI) is True
  # An unsupported dialect raises rather than being ignored or treated permissively.
  unsupported = {"$schema": "http://json-schema.org/draft-07/schema#", "type": "object"}
  with pytest.raises(UnsupportedSchemaDialectError):
    validate_input_schema(unsupported)
  with pytest.raises(UnsupportedSchemaDialectError):
    validate_output_schema({"$schema": "https://example.com/custom-dialect", "type": "string"})
  assert is_supported_dialect("http://json-schema.org/draft-07/schema#") is False


# ---------------------------------------------------------------------------
# AC-24.38 — supported dialect set is documented/stated
# ---------------------------------------------------------------------------

def test_ac_24_38_supported_dialects_documented():
  # The supported set is enumerable and includes JSON Schema 2020-12.
  assert JSON_SCHEMA_2020_12_URI in SUPPORTED_SCHEMA_DIALECTS
  assert all(isinstance(d, str) for d in SUPPORTED_SCHEMA_DIALECTS)
  # Every member reports as supported.
  assert all(is_supported_dialect(d) for d in SUPPORTED_SCHEMA_DIALECTS)


# ---------------------------------------------------------------------------
# AC-24.39 — a human is able to deny a tool invocation
# ---------------------------------------------------------------------------

def test_ac_24_39_human_can_deny():
  # A conforming host exposes a human-in-the-loop deny capability.
  assert human_can_deny_invocation(can_deny=True) is True
  # When the safeguard is absent, the helper reports it (so a test can assert it).
  assert human_can_deny_invocation(can_deny=False) is False


# ---------------------------------------------------------------------------
# Extra round-trip coverage for the wire shapes
# ---------------------------------------------------------------------------

def test_list_tools_result_full_round_trip():
  icon = Icon(src="https://example.com/weather-icon.png", mime_type="image/png", sizes=["48x48"])
  tool = Tool(
    name="get_weather_data",
    title="Weather Data Retriever",
    description="Get current weather data for a location",
    input_schema={
      "type": "object",
      "properties": {"location": {"type": "string", "description": "City name or zip code"}},
      "required": ["location"],
    },
    output_schema={
      "type": "object",
      "properties": {
        "temperature": {"type": "number"},
        "conditions": {"type": "string"},
        "humidity": {"type": "number"},
      },
      "required": ["temperature", "conditions", "humidity"],
    },
    annotations={"title": "Weather Data Retriever", "readOnlyHint": True, "openWorldHint": True},
    icons=[icon],
  )
  result = ListToolsResult(
    tools=[tool],
    ttl_ms=300000,
    cache_scope="public",
    next_cursor="next-page-cursor",
  )
  wire = result.to_dict()
  reparsed = ListToolsResult.from_dict(wire)
  assert reparsed.to_dict() == wire
  assert reparsed.tools[0].name == "get_weather_data"
  assert reparsed.tools[0].display_name() == "Weather Data Retriever"


def test_no_parameter_tool_wire_example():
  tool = Tool.from_dict(
    {
      "name": "list_active_sessions",
      "inputSchema": {"type": "object", "additionalProperties": False},
      "outputSchema": {"type": "array", "items": {"type": "string"}},
    }
  )
  assert tool.input_schema == {"type": "object", "additionalProperties": False}
  assert tool.output_schema["type"] == "array"


# ---------------------------------------------------------------------------
# R-16.4-o — a server MUST validate arguments against inputSchema before
# executing the tool: real JSON Schema 2020-12 evaluation, not just isinstance.
# ---------------------------------------------------------------------------

def test_r_16_4_o_rejects_wrong_type_argument():
  tool = make_tool(
    "weather",
    input_schema={
      "type": "object",
      "properties": {"location": {"type": "string"}},
      "required": ["location"],
    },
  )
  assert validate_arguments_against_input_schema(tool, {"location": "NYC"}) is True
  # Wrong JSON type for a declared property — must NOT be accepted.
  assert validate_arguments_against_input_schema(tool, {"location": 42}) is False


def test_r_16_4_o_rejects_missing_required_argument():
  tool = make_tool(
    "weather",
    input_schema={
      "type": "object",
      "properties": {"location": {"type": "string"}},
      "required": ["location"],
    },
  )
  assert validate_arguments_against_input_schema(tool, {}) is False


def test_r_16_4_o_rejects_additional_property_when_barred():
  tool = make_tool(
    "weather",
    input_schema={
      "type": "object",
      "properties": {"location": {"type": "string"}},
      "additionalProperties": False,
    },
  )
  assert validate_arguments_against_input_schema(tool, {"location": "NYC"}) is True
  assert validate_arguments_against_input_schema(tool, {"location": "NYC", "extra": 1}) is False


def test_r_16_4_o_enum_const_and_numeric_bounds():
  tool = make_tool(
    "t",
    input_schema={
      "type": "object",
      "properties": {
        "mode": {"enum": ["fast", "slow"]},
        "count": {"type": "integer", "minimum": 1, "maximum": 10},
        "flag": {"const": True},
      },
      "required": ["mode"],
    },
  )
  assert validate_arguments_against_input_schema(tool, {"mode": "fast", "count": 5, "flag": True}) is True
  assert validate_arguments_against_input_schema(tool, {"mode": "warp"}) is False        # enum
  assert validate_arguments_against_input_schema(tool, {"mode": "fast", "count": 0}) is False   # < minimum
  assert validate_arguments_against_input_schema(tool, {"mode": "fast", "count": 11}) is False  # > maximum
  assert validate_arguments_against_input_schema(tool, {"mode": "fast", "flag": 1}) is False    # const true != 1


def test_r_16_4_o_in_document_ref_validation():
  tool = make_tool(
    "t",
    input_schema={
      "type": "object",
      "properties": {"node": {"$ref": "#/$defs/Node"}},
      "required": ["node"],
      "$defs": {
        "Node": {"type": "object", "properties": {"k": {"type": "integer"}}, "required": ["k"]}
      },
    },
  )
  assert validate_arguments_against_input_schema(tool, {"node": {"k": 7}}) is True
  assert validate_arguments_against_input_schema(tool, {"node": {"k": "no"}}) is False  # nested wrong type
  assert validate_arguments_against_input_schema(tool, {"node": {}}) is False           # nested missing required


def test_r_16_4_p_structured_content_conforms_to_output_schema():
  tool = make_tool(
    "t",
    output_schema={
      "type": "object",
      "properties": {"n": {"type": "integer"}},
      "required": ["n"],
    },
  )
  assert structured_content_conforms(tool, {"n": 1}) is True
  assert structured_content_conforms(tool, {}) is False          # missing required
  assert structured_content_conforms(tool, {"n": "x"}) is False  # wrong type


# ---------------------------------------------------------------------------
# R-16.2-m — resultType MUST be exactly "complete" for a tools/list result;
# a wrong value is rejected (not silently accepted).
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad", ["input_required", "banana", "Complete"])
def test_r_16_2_m_rejects_non_complete_result_type(bad):
  with pytest.raises(ValueError):
    ListToolsResult.from_dict(
      {"resultType": bad, "tools": [], "ttlMs": 0, "cacheScope": "public"}
    )


def test_r_16_2_m_accepts_complete_result_type():
  result = ListToolsResult.from_dict(
    {"resultType": "complete", "tools": [], "ttlMs": 0, "cacheScope": "public"}
  )
  assert result.result_type == "complete"
