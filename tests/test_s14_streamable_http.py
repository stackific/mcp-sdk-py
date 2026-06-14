"""Tests for S14 — Streamable HTTP: Request, Headers & Routing.

Coverage map (33 story ACs):
  AC-14.1  → TestUtf8Body
  AC-14.2  → TestSingleMessageBody
  AC-14.3  → TestClientSupportsBothShapes
  AC-14.4  → TestPostMethod
  AC-14.5  → TestClientNeverSendsResponse
  AC-14.6  → TestNoBatch
  AC-14.7  → TestAllRequiredHeadersPresent
  AC-14.8  → TestNotificationResponse
  AC-14.9  → TestRequestResponseShape
  AC-14.10 → TestHeaderNameAndValueCasing
  AC-14.11 → TestContentType
  AC-14.12 → TestAccept
  AC-14.13 → TestProtocolVersionEqualsBody
  AC-14.14 → TestProtocolVersionAbsent
  AC-14.15 → TestProtocolVersionMismatch
  AC-14.16 → TestProtocolVersionUnsupported
  AC-14.17 → TestMcpMethod
  AC-14.18 → TestMcpName
  AC-14.19 → TestRoutingMismatch
  AC-14.20 → TestParamMechanismSupport
  AC-14.21 → TestInvalidXMcpHeaderRejected
  AC-14.22 → TestXMcpHeaderTypeConstraints
  AC-14.23 → TestRejectedToolIsolation
  AC-14.24 → TestClientEmitsParamHeaders
  AC-14.25 → TestPresentParamValidated
  AC-14.26 → TestNullOrAbsentOmitted
  AC-14.27 → TestOmittedHeaderWithBodyValueRejected
  AC-14.28 → TestStaleSchemaRetry
  AC-14.29 → TestValueEncoding
  AC-14.30 → TestReceiverDecodesSentinel
  AC-14.31 → TestIntermediaryForwardsUnknown
  AC-14.32 → TestReceiverRejectsBadHeaders
  AC-14.33 → TestIntegerNumericComparison
"""

import json

import pytest

from mcp_sdk_py.revision import UnsupportedRevisionError
from mcp_sdk_py.transport import MalformedMessageError
from mcp_sdk_py.meta_object import KEY_PROTOCOL_VERSION
from mcp_sdk_py.streamable_http import (
  ACCEPT_HEADER,
  ACCEPT_VALUE,
  CONTENT_TYPE_HEADER,
  CONTENT_TYPE_VALUE,
  MCP_METHOD_HEADER,
  MCP_NAME_HEADER,
  MCP_PARAM_PREFIX,
  MCP_PROTOCOL_VERSION_HEADER,
  NOTIFICATION_ACCEPTED_STATUS,
  HeaderMismatchError,
  NotASingleMessageError,
  XMcpHeaderError,
  accept_is_valid,
  build_param_headers,
  build_post_headers,
  build_routing_headers,
  collect_header_annotations,
  content_type_is_valid,
  decode_param_value,
  encode_param_value,
  filter_valid_tools,
  get_header,
  is_valid_tchar_token,
  notification_response,
  parse_post_body_bytes,
  send_without_param_headers,
  unsupported_protocol_version_response,
  validate_param_headers,
  validate_post_body,
  validate_protocol_version_header,
  validate_required_request_headers,
  validate_routing_headers,
  validate_x_mcp_header_value,
)

CURRENT = "2026-07-28"
SUPPORTED = frozenset({CURRENT})


def _body(method="tools/call", params=None, request_id=1):
  return {
    "jsonrpc": "2.0",
    "id": request_id,
    "method": method,
    "params": params if params is not None else {"_meta": {KEY_PROTOCOL_VERSION: CURRENT}},
  }


# AC-14.1 (R-9.1-a)
class TestUtf8Body:
  def test_utf8_body_accepted(self):
    raw = parse_post_body_bytes(json.dumps(_body()).encode("utf-8"))
    assert raw["method"] == "tools/call"

  def test_non_utf8_rejected(self):
    with pytest.raises(MalformedMessageError):
      parse_post_body_bytes(b"\xff\xfe not utf-8")


# AC-14.2 (R-9.1-b, R-9.2-c)
class TestSingleMessageBody:
  def test_single_request_accepted(self):
    msg = validate_post_body(_body())
    assert msg.method == "tools/call"

  def test_single_notification_accepted(self):
    msg = validate_post_body({"jsonrpc": "2.0", "method": "notifications/progress"})
    assert msg.method == "notifications/progress"


# AC-14.3 (R-9.1-c)
class TestClientSupportsBothShapes:
  def test_accept_advertises_both_response_shapes(self):
    # The client advertises support for both §9.6 shapes via the Accept header.
    assert accept_is_valid({ACCEPT_HEADER: ACCEPT_VALUE})

  def test_advertising_only_one_is_nonconforming(self):
    assert not accept_is_valid({ACCEPT_HEADER: "application/json"})


# AC-14.4 (R-9.2-a, R-9.2-b)
class TestPostMethod:
  def test_post_accepted(self):
    validate_post_body(_body(), http_method="POST")

  def test_non_post_rejected(self):
    with pytest.raises(NotASingleMessageError):
      validate_post_body(_body(), http_method="GET")


# AC-14.5 (R-9.2-d)
class TestClientNeverSendsResponse:
  def test_result_response_rejected(self):
    with pytest.raises(NotASingleMessageError):
      validate_post_body({"jsonrpc": "2.0", "id": 1, "result": {"resultType": "complete"}})

  def test_error_response_rejected(self):
    with pytest.raises(NotASingleMessageError):
      validate_post_body({"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": "x"}})


# AC-14.6 (R-9.2-e)
class TestNoBatch:
  def test_batch_array_rejected(self):
    with pytest.raises(NotASingleMessageError):
      validate_post_body([_body(), _body(request_id=2)])


# AC-14.7 (R-9.2-f)
class TestAllRequiredHeadersPresent:
  def test_post_headers_include_required_and_routing(self):
    headers = build_post_headers("tools/call", {"name": "t"}, CURRENT)
    assert headers[CONTENT_TYPE_HEADER] == CONTENT_TYPE_VALUE
    assert headers[ACCEPT_HEADER] == ACCEPT_VALUE
    assert headers[MCP_PROTOCOL_VERSION_HEADER] == CURRENT
    assert headers[MCP_METHOD_HEADER] == "tools/call"
    assert headers[MCP_NAME_HEADER] == "t"


# AC-14.8 (R-9.2-g/h/i)
class TestNotificationResponse:
  def test_accepted_is_202_empty(self):
    status, body = notification_response(True)
    assert status == NOTIFICATION_ACCEPTED_STATUS == 202
    assert body is None

  def test_rejected_is_error_with_id_omitted(self):
    status, body = notification_response(False)
    assert status == 400
    wire = body.to_dict()
    assert "id" not in wire
    assert "error" in wire


# AC-14.9 (R-9.2-j)
class TestRequestResponseShape:
  def test_request_classified_for_response(self):
    # A request body is classified, so the server must answer with a §9.6 shape.
    msg = validate_post_body(_body())
    assert msg.id == 1


# AC-14.10 (R-9.3-a/b/c)
class TestHeaderNameAndValueCasing:
  def test_field_names_case_insensitive(self):
    assert get_header({"content-TYPE": "application/json"}, "Content-Type") == "application/json"

  def test_mirrored_values_case_sensitive(self):
    # Mcp-Method value must match the body method exactly (case-sensitive).
    with pytest.raises(HeaderMismatchError):
      validate_routing_headers({MCP_METHOD_HEADER: "Tools/Call"}, "tools/call", {"name": "t"})


# AC-14.11 (R-9.3.1-a)
class TestContentType:
  def test_valid_content_type(self):
    assert content_type_is_valid({CONTENT_TYPE_HEADER: "application/json"})

  def test_other_content_type_nonconforming(self):
    assert not content_type_is_valid({CONTENT_TYPE_HEADER: "text/plain"})
    with pytest.raises(ValueError):
      validate_required_request_headers({CONTENT_TYPE_HEADER: "text/plain", ACCEPT_HEADER: ACCEPT_VALUE})


# AC-14.12 (R-9.3.2-a/b)
class TestAccept:
  def test_both_media_types_required(self):
    assert accept_is_valid({ACCEPT_HEADER: "application/json, text/event-stream"})

  def test_missing_either_nonconforming(self):
    assert not accept_is_valid({ACCEPT_HEADER: "text/event-stream"})
    assert not accept_is_valid({ACCEPT_HEADER: "application/json"})


# AC-14.13 (R-9.3.3-a)
class TestProtocolVersionEqualsBody:
  def test_header_equals_body_accepted(self):
    headers = {MCP_PROTOCOL_VERSION_HEADER: CURRENT}
    meta = {KEY_PROTOCOL_VERSION: CURRENT}
    assert validate_protocol_version_header(headers, meta, supported_versions=SUPPORTED) == CURRENT


# AC-14.14 (R-9.3.3-b, R-9.3.3-c)
class TestProtocolVersionAbsent:
  def test_absent_rejected_when_no_pre_header_support(self):
    with pytest.raises(HeaderMismatchError) as exc:
      validate_protocol_version_header({}, {KEY_PROTOCOL_VERSION: CURRENT}, supported_versions=SUPPORTED)
    assert exc.value.json_rpc_code == -32001
    assert exc.value.http_status == 400

  def test_absent_may_be_treated_as_body_version(self):
    result = validate_protocol_version_header(
      {}, {KEY_PROTOCOL_VERSION: CURRENT},
      supported_versions=SUPPORTED, supports_pre_header_clients=True,
    )
    assert result == CURRENT


# AC-14.15 (R-9.3.3-d)
class TestProtocolVersionMismatch:
  def test_header_differs_from_body_rejected(self):
    with pytest.raises(HeaderMismatchError) as exc:
      validate_protocol_version_header(
        {MCP_PROTOCOL_VERSION_HEADER: "2099-01-01"},
        {KEY_PROTOCOL_VERSION: CURRENT},
        supported_versions=SUPPORTED,
      )
    assert exc.value.json_rpc_code == -32001


# AC-14.16 (R-9.3.3-e)
class TestProtocolVersionUnsupported:
  def test_unsupported_version_raises_minus_32004(self):
    headers = {MCP_PROTOCOL_VERSION_HEADER: "2099-01-01"}
    meta = {KEY_PROTOCOL_VERSION: "2099-01-01"}
    with pytest.raises(UnsupportedRevisionError) as exc:
      validate_protocol_version_header(headers, meta, supported_versions=SUPPORTED)
    assert exc.value.json_rpc_code == -32004

  def test_mapped_response_has_supported_and_requested(self):
    err = UnsupportedRevisionError("2099-01-01", SUPPORTED)
    resp = unsupported_protocol_version_response(1, err)
    data = resp.to_dict()["error"]["data"]
    assert data["supported"] == [CURRENT]
    assert data["requested"] == "2099-01-01"
    assert resp.to_dict()["error"]["code"] == -32004


# AC-14.17 (R-9.4-a, R-9.4.1-a)
class TestMcpMethod:
  def test_mcp_method_required_and_verbatim(self):
    validate_routing_headers({MCP_METHOD_HEADER: "tools/list"}, "tools/list", None)

  def test_missing_mcp_method_rejected(self):
    with pytest.raises(HeaderMismatchError):
      validate_routing_headers({}, "tools/list", None)

  def test_notification_carries_mcp_method(self):
    headers = build_routing_headers("notifications/progress", {"progressToken": "x"})
    assert headers[MCP_METHOD_HEADER] == "notifications/progress"
    assert MCP_NAME_HEADER not in headers


# AC-14.18 (R-9.4-b, R-9.4.2-a..e)
class TestMcpName:
  def test_tools_call_uses_params_name(self):
    headers = build_routing_headers("tools/call", {"name": "execute_sql"})
    assert headers[MCP_NAME_HEADER] == "execute_sql"

  def test_prompts_get_uses_params_name(self):
    assert build_routing_headers("prompts/get", {"name": "greet"})[MCP_NAME_HEADER] == "greet"

  def test_resources_read_uses_params_uri(self):
    assert build_routing_headers("resources/read", {"uri": "file:///a"})[MCP_NAME_HEADER] == "file:///a"

  def test_absent_on_non_targeted_method(self):
    assert MCP_NAME_HEADER not in build_routing_headers("tools/list", None)

  def test_mcp_name_must_not_be_sent_for_non_targeted(self):
    with pytest.raises(HeaderMismatchError):
      validate_routing_headers(
        {MCP_METHOD_HEADER: "tools/list", MCP_NAME_HEADER: "x"}, "tools/list", None
      )

  def test_resources_read_validates_uri(self):
    validate_routing_headers(
      {MCP_METHOD_HEADER: "resources/read", MCP_NAME_HEADER: "file:///a"},
      "resources/read", {"uri": "file:///a"},
    )


# AC-14.19 (R-9.4.3-a)
class TestRoutingMismatch:
  def test_name_mismatch_rejected(self):
    with pytest.raises(HeaderMismatchError) as exc:
      validate_routing_headers(
        {MCP_METHOD_HEADER: "tools/call", MCP_NAME_HEADER: "wrong_tool"},
        "tools/call", {"name": "execute_sql"},
      )
    assert exc.value.json_rpc_code == -32001
    assert exc.value.http_status == 400

  def test_missing_required_name_rejected(self):
    with pytest.raises(HeaderMismatchError):
      validate_routing_headers(
        {MCP_METHOD_HEADER: "tools/call"}, "tools/call", {"name": "execute_sql"}
      )

  def test_response_carries_minus_32001(self):
    err = HeaderMismatchError("x", request_id=1)
    assert err.to_response().to_dict()["error"]["code"] == -32001


# AC-14.20 (R-9.5-a/b/c)
class TestParamMechanismSupport:
  def test_client_emits_headers_when_server_uses_mechanism(self):
    schema = {"type": "object", "properties": {"region": {"type": "string", "x-mcp-header": "Region"}}}
    headers = build_param_headers(schema, {"region": "us-west1"})
    assert headers == {"Mcp-Param-Region": "us-west1"}

  def test_mechanism_optional_for_server(self):
    # A tool with no annotations yields no param headers (server opted out).
    schema = {"type": "object", "properties": {"query": {"type": "string"}}}
    assert build_param_headers(schema, {"query": "x"}) == {}


# AC-14.21 (R-9.5.1-a/b/c/d)
class TestInvalidXMcpHeaderRejected:
  def test_empty_value_rejected(self):
    with pytest.raises(XMcpHeaderError):
      validate_x_mcp_header_value("", "string")

  def test_non_tchar_rejected(self):
    with pytest.raises(XMcpHeaderError):
      validate_x_mcp_header_value("Region Name", "string")  # space not a tchar

  def test_control_char_rejected(self):
    with pytest.raises(XMcpHeaderError):
      validate_x_mcp_header_value("Re\ngion", "string")

  def test_case_insensitive_collision_rejected(self):
    schema = {
      "type": "object",
      "properties": {
        "a": {"type": "string", "x-mcp-header": "Region"},
        "b": {"type": "string", "x-mcp-header": "region"},
      },
    }
    with pytest.raises(XMcpHeaderError):
      collect_header_annotations(schema)

  def test_tchar_helper(self):
    assert is_valid_tchar_token("Region")
    assert not is_valid_tchar_token("")
    assert not is_valid_tchar_token("a b")


# AC-14.22 (R-9.5.1-e/f/g/h)
class TestXMcpHeaderTypeConstraints:
  def test_number_type_rejected(self):
    with pytest.raises(XMcpHeaderError):
      validate_x_mcp_header_value("Lat", "number")

  def test_primitive_types_accepted(self):
    for t in ("integer", "string", "boolean"):
      validate_x_mcp_header_value("Param", t)

  def test_integer_out_of_range_rejected_at_encoding(self):
    with pytest.raises(ValueError):
      encode_param_value(2 ** 53, "integer")  # outside safe range

  def test_integer_in_range_ok(self):
    assert encode_param_value(2 ** 53 - 1, "integer") == str(2 ** 53 - 1)

  def test_nested_annotation_accepted(self):
    schema = {
      "type": "object",
      "properties": {
        "outer": {
          "type": "object",
          "properties": {"deep": {"type": "string", "x-mcp-header": "Deep"}},
        }
      },
    }
    anns = collect_header_annotations(schema)
    assert anns[0].path == ("outer", "deep")
    assert anns[0].header_name == "Deep"


# AC-14.23 (R-9.5.1-i/j/k/l)
class TestRejectedToolIsolation:
  def test_only_invalid_tool_excluded_and_warns(self, caplog):
    good = {"name": "good", "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}}
    bad = {
      "name": "bad",
      "inputSchema": {"type": "object", "properties": {"x": {"type": "number", "x-mcp-header": "X"}}},
    }
    import logging
    with caplog.at_level(logging.WARNING):
      valid, rejected = filter_valid_tools([good, bad])
    assert [t["name"] for t in valid] == ["good"]
    assert len(rejected) == 1 and rejected[0].name == "bad"
    assert "bad" in caplog.text  # warning names the rejected tool


# AC-14.24 (R-9.5.2-a/b/c/d)
class TestClientEmitsParamHeaders:
  def test_full_post_headers_for_tools_call(self):
    schema = {
      "type": "object",
      "properties": {
        "region": {"type": "string", "x-mcp-header": "Region"},
        "query": {"type": "string"},
      },
    }
    params = {"name": "execute_sql", "arguments": {"region": "us-west1", "query": "SELECT 1"}}
    headers = build_post_headers("tools/call", params, CURRENT, input_schema=schema)
    assert headers[MCP_METHOD_HEADER] == "tools/call"
    assert headers[MCP_NAME_HEADER] == "execute_sql"
    assert headers["Mcp-Param-Region"] == "us-west1"
    assert "Mcp-Param-Query" not in headers  # query is not annotated


# AC-14.25 (R-9.5.2-e/f)
class TestPresentParamValidated:
  def test_present_value_header_included_and_validates(self):
    schema = {"type": "object", "properties": {"region": {"type": "string", "x-mcp-header": "Region"}}}
    args = {"region": "us-west1"}
    headers = build_param_headers(schema, args)
    assert headers == {"Mcp-Param-Region": "us-west1"}
    validate_param_headers(headers, schema, args)  # no raise


# AC-14.26 (R-9.5.2-g/h/i/j)
class TestNullOrAbsentOmitted:
  def test_null_value_omits_header(self):
    schema = {"type": "object", "properties": {"region": {"type": "string", "x-mcp-header": "Region"}}}
    assert build_param_headers(schema, {"region": None}) == {}
    validate_param_headers({}, schema, {"region": None})  # server doesn't expect it

  def test_absent_value_omits_header(self):
    schema = {"type": "object", "properties": {"region": {"type": "string", "x-mcp-header": "Region"}}}
    assert build_param_headers(schema, {}) == {}
    validate_param_headers({}, schema, {})


# AC-14.27 (R-9.5.2-k)
class TestOmittedHeaderWithBodyValueRejected:
  def test_missing_header_with_body_value_rejected(self):
    schema = {"type": "object", "properties": {"region": {"type": "string", "x-mcp-header": "Region"}}}
    with pytest.raises(HeaderMismatchError) as exc:
      validate_param_headers({}, schema, {"region": "us-west1"})
    assert exc.value.json_rpc_code == -32001


# AC-14.28 (R-9.5.2-l/m/n)
class TestStaleSchemaRetry:
  def test_send_without_headers_when_schema_unknown(self):
    assert send_without_param_headers(schema_known=False) is True
    assert build_param_headers(None, {"region": "x"}) == {}

  def test_send_without_headers_when_stale(self):
    assert send_without_param_headers(schema_known=True, schema_stale=True) is True

  def test_emit_when_schema_known_and_fresh(self):
    assert send_without_param_headers(schema_known=True, schema_stale=False) is False


# AC-14.29 (R-9.5.3-a/b/c/e)
class TestValueEncoding:
  def test_string_as_is(self):
    assert encode_param_value("us-west1", "string") == "us-west1"

  def test_integer_decimal_string(self):
    assert encode_param_value(42, "integer") == "42"
    assert encode_param_value(-7, "integer") == "-7"

  def test_boolean_lowercase(self):
    assert encode_param_value(True, "boolean") == "true"
    assert encode_param_value(False, "boolean") == "false"

  def test_non_ascii_sentinel(self):
    assert encode_param_value("Hello, 世界", "string") == "=?base64?SGVsbG8sIOS4lueVjA==?="

  def test_leading_trailing_whitespace_sentinel(self):
    assert encode_param_value(" padded ", "string") == "=?base64?IHBhZGRlZCA=?="

  def test_control_char_sentinel(self):
    assert encode_param_value("line1\nline2", "string") == "=?base64?bGluZTEKbGluZTI=?="

  def test_sentinel_shaped_value_is_encoded(self):
    assert encode_param_value("=?base64?literal?=", "string") == "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?="

  def test_prefix_suffix_lowercase_exact(self):
    out = encode_param_value("Hello, 世界", "string")
    assert out.startswith("=?base64?") and out.endswith("?=")


# AC-14.30 (R-9.5.3-d)
class TestReceiverDecodesSentinel:
  def test_decode_sentinel_round_trip(self):
    for original in ("Hello, 世界", " padded ", "line1\nline2", "=?base64?literal?="):
      assert decode_param_value(encode_param_value(original, "string")) == original

  def test_decode_plain_passthrough(self):
    assert decode_param_value("us-west1") == "us-west1"


# AC-14.31 (R-9.5.4-a)
class TestIntermediaryForwardsUnknown:
  def test_unrecognized_param_header_ignored_by_body_receiver(self):
    # A header not declared by the schema is not validated (forwarded/ignored).
    schema = {"type": "object", "properties": {"region": {"type": "string", "x-mcp-header": "Region"}}}
    headers = {"Mcp-Param-Region": "us-west1", "Mcp-Param-Unknown": "whatever"}
    validate_param_headers(headers, schema, {"region": "us-west1"})  # no raise


# AC-14.32 (R-9.5.4-b/c)
class TestReceiverRejectsBadHeaders:
  def test_impermissible_chars_rejected(self):
    schema = {"type": "object", "properties": {"region": {"type": "string", "x-mcp-header": "Region"}}}
    headers = {"Mcp-Param-Region": "bad\nvalue"}  # control char in the raw header
    with pytest.raises(HeaderMismatchError) as exc:
      validate_param_headers(headers, schema, {"region": "bad\nvalue"})
    assert exc.value.json_rpc_code == -32001

  def test_value_mismatch_rejected(self):
    schema = {"type": "object", "properties": {"region": {"type": "string", "x-mcp-header": "Region"}}}
    headers = {"Mcp-Param-Region": "us-east1"}  # disagrees with body
    with pytest.raises(HeaderMismatchError):
      validate_param_headers(headers, schema, {"region": "us-west1"})

  def test_sentinel_value_matches_body(self):
    schema = {"type": "object", "properties": {"g": {"type": "string", "x-mcp-header": "Greeting"}}}
    args = {"g": "Hello, 世界"}
    headers = build_param_headers(schema, args)
    validate_param_headers(headers, schema, args)  # decoded sentinel matches body


# AC-14.33 (R-9.5.4-d)
class TestIntegerNumericComparison:
  def test_integer_compared_numerically(self):
    schema = {"type": "object", "properties": {"n": {"type": "integer", "x-mcp-header": "N"}}}
    # Header "42.0" should match body 42 numerically.
    validate_param_headers({"Mcp-Param-N": "42.0"}, schema, {"n": 42})

  def test_integer_exact_decimal_matches(self):
    schema = {"type": "object", "properties": {"n": {"type": "integer", "x-mcp-header": "N"}}}
    headers = build_param_headers(schema, {"n": 42})
    assert headers == {"Mcp-Param-N": "42"}
    validate_param_headers(headers, schema, {"n": 42})

  def test_integer_mismatch_rejected(self):
    schema = {"type": "object", "properties": {"n": {"type": "integer", "x-mcp-header": "N"}}}
    with pytest.raises(HeaderMismatchError):
      validate_param_headers({"Mcp-Param-N": "43"}, schema, {"n": 42})

  def test_non_numeric_integer_header_mismatch(self):
    schema = {"type": "object", "properties": {"n": {"type": "integer", "x-mcp-header": "N"}}}
    with pytest.raises(HeaderMismatchError):
      validate_param_headers({"Mcp-Param-N": "notanumber"}, schema, {"n": 42})


# Validation guards — encoding type checks, malformed sentinels, accept parsing
class TestStreamableHttpGuards:
  def test_encode_boolean_type_error(self):
    with pytest.raises(TypeError):
      encode_param_value("notabool", "boolean")

  def test_encode_integer_type_error(self):
    with pytest.raises(TypeError):
      encode_param_value("notanint", "integer")

  def test_encode_string_type_error(self):
    with pytest.raises(TypeError):
      encode_param_value(123, "string")

  def test_encode_unknown_type_error(self):
    with pytest.raises(TypeError):
      encode_param_value(1.5, "number")

  def test_encode_infers_python_type(self):
    assert encode_param_value(True) == "true"
    assert encode_param_value(42) == "42"
    assert encode_param_value("x") == "x"

  def test_boolean_header_validates(self):
    schema = {"type": "object", "properties": {"b": {"type": "boolean", "x-mcp-header": "B"}}}
    headers = build_param_headers(schema, {"b": True})
    assert headers == {"Mcp-Param-B": "true"}
    validate_param_headers(headers, schema, {"b": True})

  def test_malformed_sentinel_payload_rejected(self):
    schema = {"type": "object", "properties": {"g": {"type": "string", "x-mcp-header": "Greeting"}}}
    # A sentinel whose payload is not valid Base64.
    headers = {"Mcp-Param-Greeting": "=?base64?!!!notbase64!!!?="}
    with pytest.raises(HeaderMismatchError):
      validate_param_headers(headers, schema, {"g": "x"})

  def test_accept_missing_returns_false(self):
    assert accept_is_valid({}) is False

  def test_validate_required_headers_accept_invalid(self):
    with pytest.raises(ValueError):
      validate_required_request_headers(
        {CONTENT_TYPE_HEADER: "application/json", ACCEPT_HEADER: "application/json"}
      )

  def test_validate_required_headers_ok(self):
    validate_required_request_headers(
      {CONTENT_TYPE_HEADER: CONTENT_TYPE_VALUE, ACCEPT_HEADER: ACCEPT_VALUE}
    )
