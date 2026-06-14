"""Tests for S34 — Error Handling & Error Code Registry (§22).

Exercises the consolidated error-code registry and cross-cutting error
semantics assembled in ``mcp_sdk_py.errors``: the exactly-one-of result/error
envelope rule, code authority, normative §22.3 data shapes, the canonical
mapping of validation failures to -32602, the protocol-error vs. feature-level
error-result boundary, the transport status mapping, the id-omission and
no-response-to-notifications rules, and extension/unknown-code tolerance.

AC -> test coverage map:
  AC-34.1  (R-22.1-a)                  -> test_ac_34_1_*
  AC-34.2  (R-22.1-d)                  -> test_ac_34_2_*
  AC-34.3  (R-22.1-b/e, R-22.6-g)      -> test_ac_34_3_*
  AC-34.4  (R-22.1-f, R-22.6-h)        -> test_ac_34_4_*
  AC-34.5  (R-22.1-g, R-22.6-i)        -> test_ac_34_5_*
  AC-34.6  (R-22.1-c/h/i)              -> test_ac_34_6_*
  AC-34.7  (R-22.1-j)                  -> test_ac_34_7_*
  AC-34.8  (R-22.1-k, R-22.3-a)        -> test_ac_34_8_*
  AC-34.9  (R-22.2-a..f)               -> test_ac_34_9_*
  AC-34.10 (R-22.2-g)                  -> test_ac_34_10_*
  AC-34.11 (R-22.2-h, R-22.3.1-a/b)    -> test_ac_34_11_*
  AC-34.12 (R-22.3.1-b, R-22.3-a)      -> test_ac_34_12_*
  AC-34.13 (R-22.3.2-a, R-22.3-a)      -> test_ac_34_13_*
  AC-34.14 (R-22.3.2-b)                -> test_ac_34_14_*
  AC-34.15 (R-22.4-a..g)               -> test_ac_34_15_*
  AC-34.16 (R-22.4-h/i)                -> test_ac_34_16_*
  AC-34.17 (R-22.4-j)                  -> test_ac_34_17_*
  AC-34.18 (R-22.5-a..f)               -> test_ac_34_18_*
  AC-34.19 (R-22.6-a)                  -> test_ac_34_19_*
  AC-34.20 (R-22.6-b)                  -> test_ac_34_20_*
  AC-34.21 (R-22.6-c/d)                -> test_ac_34_21_*
  AC-34.22 (R-22.6-e/f)                -> test_ac_34_22_*
  AC-34.23 (R-22.7-a/b/c/d)            -> test_ac_34_23_*
  AC-34.24 (R-22.7-e)                  -> test_ac_34_24_*
  AC-34.25 (R-22-a)                    -> test_ac_34_25_*
"""

from __future__ import annotations

import pytest

from mcp_sdk_py.errors import (
  ERROR_CODE_REGISTRY,
  HEADER_MISMATCH_CODE,
  INTERNAL_ERROR_CODE,
  INVALID_PARAMS_CODE,
  INVALID_PARAMS_REASONS,
  INVALID_REQUEST_CODE,
  METHOD_NOT_FOUND_CODE,
  MISSING_REQUIRED_CLIENT_CAPABILITY_CODE,
  PARSE_ERROR_CODE,
  PROTOCOL_SPECIFIC_ERROR_CODES,
  RESERVED_ERROR_CODES,
  STANDARD_ERROR_CODES,
  UNSUPPORTED_PROTOCOL_VERSION_CODE,
  ErrorCodeEntry,
  MalformedErrorResponseError,
  ProtocolErrorMisuseError,
  Reason,
  ReservedErrorCodeCollisionError,
  SurfacedError,
  ToolFailureMode,
  TransportCondition,
  assert_tool_dispatch_failure_is_protocol_error,
  assert_tool_execution_failure_is_result,
  build_extension_error,
  build_invalid_params_error,
  build_resource_not_found_error,
  build_tool_execution_error_result,
  build_undeterminable_id_error_response,
  classify_by_code,
  classify_tool_failure,
  client_should_retry_on_unsupported_version,
  code_for_invalid_params_reason,
  code_for_invalid_request_object,
  code_for_unexpected_server_condition,
  code_for_unparseable_input,
  error_code_entry,
  error_code_name,
  error_id_for_request,
  is_error_response,
  is_known_error_code,
  is_reserved_error_code,
  is_resource_not_found_signalled_by_empty_contents,
  is_success_response,
  map_transport_condition,
  response_id_for_undeterminable_request,
  should_respond_to_message,
  surface_unknown_error,
  validate_error_response,
  validate_extension_error_code,
  validate_missing_required_client_capability_data,
  validate_success_response,
  validate_unsupported_protocol_version_data,
)
from mcp_sdk_py.negotiation import (
  build_missing_required_client_capability_error,
  build_unsupported_protocol_version_error,
)
from mcp_sdk_py.result_error import ErrorObject


# Helper to build a minimal well-formed error response envelope.
def _error_response(code: int, message: str, *, id_: object = 1, data=None) -> dict:
  err = {"code": code, "message": message}
  if data is not None:
    err["data"] = data
  resp = {"jsonrpc": "2.0", "id": id_, "error": err}
  return resp


# ---------------------------------------------------------------------------
# AC-34.1 — exactly one of result/error (R-22.1-a)
# ---------------------------------------------------------------------------

def test_ac_34_1_error_response_has_error_not_result():
  resp = _error_response(INVALID_PARAMS_CODE, "bad")
  assert is_error_response(resp)
  assert not is_success_response(resp)
  error = validate_error_response(resp)
  assert error.code == INVALID_PARAMS_CODE


def test_ac_34_1_success_response_has_result_not_error():
  resp = {"jsonrpc": "2.0", "id": 1, "result": {"resultType": "complete"}}
  assert is_success_response(resp)
  assert not is_error_response(resp)
  result = validate_success_response(resp)
  assert result == {"resultType": "complete"}


def test_ac_34_1_response_with_both_is_rejected():
  resp = {"jsonrpc": "2.0", "id": 1, "result": {}, "error": {"code": -32603, "message": "x"}}
  assert not is_error_response(resp)
  assert not is_success_response(resp)
  with pytest.raises(MalformedErrorResponseError, match="both"):
    validate_error_response(resp)
  with pytest.raises(MalformedErrorResponseError, match="both"):
    validate_success_response(resp)


def test_ac_34_1_response_with_neither_is_rejected():
  resp = {"jsonrpc": "2.0", "id": 1}
  with pytest.raises(MalformedErrorResponseError, match="neither"):
    validate_error_response(resp)
  with pytest.raises(MalformedErrorResponseError, match="neither"):
    validate_success_response(resp)


# ---------------------------------------------------------------------------
# AC-34.2 — jsonrpc is exactly "2.0" (R-22.1-d)
# ---------------------------------------------------------------------------

def test_ac_34_2_jsonrpc_must_be_exactly_2_0():
  error = validate_error_response(_error_response(INTERNAL_ERROR_CODE, "x"))
  assert error.code == INTERNAL_ERROR_CODE


@pytest.mark.parametrize("bad", ["2", "2.00", "1.0", 2.0, "", None])
def test_ac_34_2_wrong_jsonrpc_rejected(bad):
  resp = {"jsonrpc": bad, "id": 1, "error": {"code": -32603, "message": "x"}}
  with pytest.raises(MalformedErrorResponseError, match="jsonrpc"):
    validate_error_response(resp)


# ---------------------------------------------------------------------------
# AC-34.3 — error id equals request id (R-22.1-b/e, R-22.6-g)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rid", [7, "abc", 0, 3.5])
def test_ac_34_3_error_id_echoes_request_id(rid):
  assert error_id_for_request(rid) == rid


def test_ac_34_3_error_id_for_none_raises():
  with pytest.raises(ValueError, match="R-22.6-g"):
    error_id_for_request(None)


# ---------------------------------------------------------------------------
# AC-34.4 — id may be omitted/null when undeterminable (R-22.1-f, R-22.6-h)
# ---------------------------------------------------------------------------

def test_ac_34_4_undeterminable_id_omitted_by_default():
  assert response_id_for_undeterminable_request() is None


def test_ac_34_4_undeterminable_id_null_when_transport_requires_value():
  # None renders either as "omit id" or as JSON null when a value is required.
  assert response_id_for_undeterminable_request(transport_requires_value=True) is None


def test_ac_34_4_undeterminable_response_omits_id_on_wire():
  err = ErrorObject(code=PARSE_ERROR_CODE, message="Parse error")
  resp = build_undeterminable_id_error_response(err)
  wire = resp.to_dict()
  # S03 serializes a None id as absent; a value-requiring transport sends null.
  assert "id" not in wire
  assert wire["error"]["code"] == PARSE_ERROR_CODE


# ---------------------------------------------------------------------------
# AC-34.5 — no response to notifications (R-22.1-g, R-22.6-i)
# ---------------------------------------------------------------------------

def test_ac_34_5_notification_gets_no_response():
  assert should_respond_to_message(has_id=False) is False


def test_ac_34_5_request_gets_response():
  assert should_respond_to_message(has_id=True) is True


# ---------------------------------------------------------------------------
# AC-34.6 — code integer + message string (R-22.1-c/h/i)
# ---------------------------------------------------------------------------

def test_ac_34_6_valid_code_and_message():
  error = validate_error_response(_error_response(-32601, "Method not found"))
  assert isinstance(error.code, int)
  assert isinstance(error.message, str)


def test_ac_34_6_negative_code_allowed():
  error = validate_error_response(_error_response(-32099, "server error"))
  assert error.code == -32099


def test_ac_34_6_missing_code_rejected():
  resp = {"jsonrpc": "2.0", "id": 1, "error": {"message": "x"}}
  with pytest.raises(ValueError):
    validate_error_response(resp)


def test_ac_34_6_non_integer_code_rejected():
  resp = {"jsonrpc": "2.0", "id": 1, "error": {"code": "x", "message": "y"}}
  with pytest.raises(TypeError):
    validate_error_response(resp)


def test_ac_34_6_missing_message_rejected():
  resp = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32603}}
  with pytest.raises(ValueError):
    validate_error_response(resp)


def test_ac_34_6_non_string_message_rejected():
  resp = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32603, "message": 5}}
  with pytest.raises(TypeError):
    validate_error_response(resp)


# ---------------------------------------------------------------------------
# AC-34.7 — code is authoritative, not message (R-22.1-j)
# ---------------------------------------------------------------------------

def test_ac_34_7_classify_uses_code_not_message():
  a = ErrorObject(code=INVALID_PARAMS_CODE, message="Unknown tool: x")
  b = ErrorObject(code=INVALID_PARAMS_CODE, message="A completely different message")
  assert classify_by_code(a) == classify_by_code(b) == INVALID_PARAMS_CODE


def test_ac_34_7_classify_varying_only_message_is_stable():
  base = {"code": METHOD_NOT_FOUND_CODE, "message": "Method not found: prompts/list"}
  other = {"code": METHOD_NOT_FOUND_CODE, "message": "no such method"}
  assert classify_by_code(base) == classify_by_code(other) == METHOD_NOT_FOUND_CODE


def test_ac_34_7_classify_from_errorobject_and_dict_agree():
  obj = ErrorObject(code=-32603, message="boom")
  assert classify_by_code(obj) == classify_by_code({"code": -32603, "message": "different"})


# ---------------------------------------------------------------------------
# AC-34.8 — data optional; normative for -32003/-32004 (R-22.1-k, R-22.3-a)
# ---------------------------------------------------------------------------

def test_ac_34_8_data_is_optional():
  error = validate_error_response(_error_response(INVALID_PARAMS_CODE, "no data"))
  assert not error.has_data


def test_ac_34_8_other_code_data_is_sender_defined():
  error = validate_error_response(
    _error_response(INVALID_PARAMS_CODE, "tool", data={"toolName": "x"})
  )
  assert error.data == {"toolName": "x"}


def test_ac_34_8_minus_32003_data_validated_when_present():
  data = {"requiredCapabilities": {"elicitation": {}}}
  error = validate_error_response(
    _error_response(MISSING_REQUIRED_CLIENT_CAPABILITY_CODE, "x", data=data)
  )
  assert error.data == data


def test_ac_34_8_minus_32003_bad_data_rejected():
  bad = {"jsonrpc": "2.0", "id": 1, "error": {
    "code": MISSING_REQUIRED_CLIENT_CAPABILITY_CODE,
    "message": "x",
    "data": {"wrong": True},
  }}
  with pytest.raises(ValueError):
    validate_error_response(bad)


def test_ac_34_8_minus_32004_data_validated_when_present():
  data = {"supported": ["2026-07-28"], "requested": "1999-01-01"}
  error = validate_error_response(
    _error_response(UNSUPPORTED_PROTOCOL_VERSION_CODE, "x", data=data)
  )
  assert error.data == data


def test_ac_34_8_minus_32004_bad_data_rejected():
  bad = {"jsonrpc": "2.0", "id": 1, "error": {
    "code": UNSUPPORTED_PROTOCOL_VERSION_CODE,
    "message": "x",
    "data": {"supported": [], "requested": "1.0"},
  }}
  with pytest.raises(ValueError):
    validate_error_response(bad)


# ---------------------------------------------------------------------------
# AC-34.9 — standard codes for standard conditions (R-22.2-a..f)
# ---------------------------------------------------------------------------

def test_ac_34_9_standard_code_values():
  assert PARSE_ERROR_CODE == -32700
  assert INVALID_REQUEST_CODE == -32600
  assert METHOD_NOT_FOUND_CODE == -32601
  assert INVALID_PARAMS_CODE == -32602
  assert INTERNAL_ERROR_CODE == -32603


def test_ac_34_9_standard_codes_set():
  assert STANDARD_ERROR_CODES == frozenset({-32700, -32600, -32601, -32602, -32603})


def test_ac_34_9_registry_names_the_standard_conditions():
  assert error_code_name(PARSE_ERROR_CODE) == "Parse error"
  assert error_code_name(INVALID_REQUEST_CODE) == "Invalid Request"
  assert error_code_name(METHOD_NOT_FOUND_CODE) == "Method not found"
  assert error_code_name(INVALID_PARAMS_CODE) == "Invalid params"
  assert error_code_name(INTERNAL_ERROR_CODE) == "Internal error"


def test_ac_34_9_unparseable_uses_parse_error():
  assert code_for_unparseable_input() == PARSE_ERROR_CODE


def test_ac_34_9_invalid_request_object_uses_invalid_request():
  assert code_for_invalid_request_object() == INVALID_REQUEST_CODE


def test_ac_34_9_unexpected_internal_uses_internal_error():
  assert code_for_unexpected_server_condition() == INTERNAL_ERROR_CODE


# ---------------------------------------------------------------------------
# AC-34.10 — unadvertised server capability => -32601 (R-22.2-g)
# ---------------------------------------------------------------------------

def test_ac_34_10_prompts_list_without_capability_is_method_not_found():
  # A method gated behind an unadvertised *server* capability => -32601.
  entry = error_code_entry(METHOD_NOT_FOUND_CODE)
  assert entry is not None and entry.name == "Method not found"
  err = ErrorObject(code=METHOD_NOT_FOUND_CODE, message="Method not found: prompts/list")
  assert classify_by_code(err) == METHOD_NOT_FOUND_CODE
  # Distinct from -32003 (the *client*-capability complement).
  assert METHOD_NOT_FOUND_CODE != MISSING_REQUIRED_CLIENT_CAPABILITY_CODE


# ---------------------------------------------------------------------------
# AC-34.11 — undeclared client capability => -32003 not -32601 (R-22.2-h, R-22.3.1)
# ---------------------------------------------------------------------------

def test_ac_34_11_undeclared_client_capability_is_32003_not_32601():
  err = build_missing_required_client_capability_error({"elicitation": {}})
  assert err.code == MISSING_REQUIRED_CLIENT_CAPABILITY_CODE
  assert err.code != METHOD_NOT_FOUND_CODE


def test_ac_34_11_minus_32003_is_protocol_specific():
  assert MISSING_REQUIRED_CLIENT_CAPABILITY_CODE in PROTOCOL_SPECIFIC_ERROR_CODES


# ---------------------------------------------------------------------------
# AC-34.12 — -32003 data.requiredCapabilities (R-22.3.1-b, R-22.3-a)
# ---------------------------------------------------------------------------

def test_ac_34_12_required_capabilities_extracted():
  required = validate_missing_required_client_capability_data(
    {"requiredCapabilities": {"elicitation": {}}}
  )
  assert required == {"elicitation": {}}


def test_ac_34_12_missing_required_capabilities_rejected():
  with pytest.raises(ValueError, match="requiredCapabilities"):
    validate_missing_required_client_capability_data({})


def test_ac_34_12_required_capabilities_must_be_object():
  with pytest.raises(TypeError):
    validate_missing_required_client_capability_data({"requiredCapabilities": []})


def test_ac_34_12_built_error_carries_required_capabilities():
  err = build_missing_required_client_capability_error({"elicitation": {}})
  required = validate_missing_required_client_capability_data(err.data)
  assert required == {"elicitation": {}}


# ---------------------------------------------------------------------------
# AC-34.13 — -32004 data.supported + data.requested (R-22.3.2-a, R-22.3-a)
# ---------------------------------------------------------------------------

def test_ac_34_13_unsupported_version_data():
  supported, requested = validate_unsupported_protocol_version_data(
    {"supported": ["2026-07-28"], "requested": "1999-01-01"}
  )
  assert supported == ["2026-07-28"]
  assert requested == "1999-01-01"


def test_ac_34_13_empty_supported_rejected():
  with pytest.raises(ValueError, match="non-empty"):
    validate_unsupported_protocol_version_data({"supported": [], "requested": "1.0"})


def test_ac_34_13_missing_requested_rejected():
  with pytest.raises(ValueError, match="requested"):
    validate_unsupported_protocol_version_data({"supported": ["2026-07-28"]})


def test_ac_34_13_built_error_data():
  err = build_unsupported_protocol_version_error(["2026-07-28"], "1999-01-01")
  supported, requested = validate_unsupported_protocol_version_data(err.data)
  assert supported == ["2026-07-28"]
  assert requested == "1999-01-01"


# ---------------------------------------------------------------------------
# AC-34.14 — client retries from data.supported on -32004 (R-22.3.2-b)
# ---------------------------------------------------------------------------

def test_ac_34_14_client_retry_candidates_from_supported():
  err = build_unsupported_protocol_version_error(["2026-07-28", "2025-01-01"], "1999-01-01")
  candidates = client_should_retry_on_unsupported_version(err)
  assert candidates == ["2026-07-28", "2025-01-01"]


def test_ac_34_14_retry_rejects_non_32004():
  err = ErrorObject(code=INVALID_PARAMS_CODE, message="x")
  with pytest.raises(ValueError):
    client_should_retry_on_unsupported_version(err)


# ---------------------------------------------------------------------------
# AC-34.15 — canonical -32602 conditions (R-22.4-a..g)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("reason", list(Reason))
def test_ac_34_15_every_reason_maps_to_invalid_params(reason):
  assert code_for_invalid_params_reason(reason) == INVALID_PARAMS_CODE


def test_ac_34_15_minimum_set_lists_named_conditions():
  assert INVALID_PARAMS_REASONS == frozenset({
    Reason.UNKNOWN_TOOL_NAME,
    Reason.INVALID_TOOL_ARGUMENTS,
    Reason.UNKNOWN_PROMPT_NAME,
    Reason.MISSING_REQUIRED_PROMPT_ARGUMENT,
    Reason.UNKNOWN_RESOURCE_TEMPLATE,
    Reason.INVALID_OR_EXPIRED_CURSOR,
    Reason.RESOURCE_NOT_FOUND,
  })


def test_ac_34_15_other_param_validation_also_maps_to_32602():
  # The listed set is a minimum, not exhaustive (e.g. invalid logging level).
  assert code_for_invalid_params_reason(Reason.OTHER_PARAM_VALIDATION) == INVALID_PARAMS_CODE


def test_ac_34_15_build_invalid_params_error():
  err = build_invalid_params_error("Unknown tool: x", data={"toolName": "x"})
  assert err.code == INVALID_PARAMS_CODE
  assert err.data == {"toolName": "x"}


def test_ac_34_15_reason_rejects_non_reason():
  with pytest.raises(TypeError):
    code_for_invalid_params_reason("unknown_tool_name")


# ---------------------------------------------------------------------------
# AC-34.16 — resource-not-found data.uri; never empty contents (R-22.4-h/i)
# ---------------------------------------------------------------------------

def test_ac_34_16_resource_not_found_includes_uri():
  err = build_resource_not_found_error("file:///nonexistent.txt")
  assert err.code == INVALID_PARAMS_CODE
  assert err.data == {"uri": "file:///nonexistent.txt"}


def test_ac_34_16_resource_not_found_requires_string_uri():
  with pytest.raises(TypeError):
    build_resource_not_found_error(123)  # type: ignore[arg-type]


def test_ac_34_16_empty_contents_is_forbidden_signal():
  assert is_resource_not_found_signalled_by_empty_contents({"contents": []}) is True


def test_ac_34_16_non_empty_contents_is_not_the_forbidden_signal():
  assert is_resource_not_found_signalled_by_empty_contents(
    {"contents": [{"uri": "x", "text": "y"}]}
  ) is False
  assert is_resource_not_found_signalled_by_empty_contents({}) is False


# ---------------------------------------------------------------------------
# AC-34.17 — unexpected server-side condition => -32603 (R-22.4-j)
# ---------------------------------------------------------------------------

def test_ac_34_17_unexpected_condition_prefers_internal_error():
  assert code_for_unexpected_server_condition() == INTERNAL_ERROR_CODE
  assert code_for_unexpected_server_condition() != INVALID_PARAMS_CODE


# ---------------------------------------------------------------------------
# AC-34.18 — protocol error vs feature-level result (R-22.5-a..f)
# ---------------------------------------------------------------------------

def test_ac_34_18_undispatchable_tool_is_protocol_error():
  assert classify_tool_failure(tool_dispatched_and_ran=False) is ToolFailureMode.PROTOCOL_ERROR


def test_ac_34_18_ran_tool_failure_is_error_result():
  assert (
    classify_tool_failure(tool_dispatched_and_ran=True)
    is ToolFailureMode.EXECUTION_ERROR_RESULT
  )


def test_ac_34_18_execution_error_result_shape():
  result = build_tool_execution_error_result(
    [{"type": "text", "text": "Upstream weather API returned 503"}]
  )
  assert result["isError"] is True
  assert result["content"][0]["text"] == "Upstream weather API returned 503"
  # It is a result, not a JSON-RPC error: no `error`/`code` member.
  assert "error" not in result and "code" not in result


def test_ac_34_18_dispatch_failure_must_not_use_is_error():
  assert_tool_dispatch_failure_is_protocol_error(reported_as_is_error_result=False)
  with pytest.raises(ProtocolErrorMisuseError):
    assert_tool_dispatch_failure_is_protocol_error(reported_as_is_error_result=True)


def test_ac_34_18_execution_failure_must_not_use_json_rpc_error():
  assert_tool_execution_failure_is_result(reported_as_json_rpc_error=False)
  with pytest.raises(ProtocolErrorMisuseError):
    assert_tool_execution_failure_is_result(reported_as_json_rpc_error=True)


# ---------------------------------------------------------------------------
# AC-34.19 — -32003/-32004 => HTTP 400 (R-22.6-a)
# ---------------------------------------------------------------------------

def test_ac_34_19_missing_capability_maps_to_400():
  m = map_transport_condition(TransportCondition.MISSING_REQUIRED_CLIENT_CAPABILITY)
  assert m.code == MISSING_REQUIRED_CLIENT_CAPABILITY_CODE
  assert m.http_status == 400


def test_ac_34_19_unsupported_version_maps_to_400():
  m = map_transport_condition(TransportCondition.UNSUPPORTED_PROTOCOL_VERSION)
  assert m.code == UNSUPPORTED_PROTOCOL_VERSION_CODE
  assert m.http_status == 400


# ---------------------------------------------------------------------------
# AC-34.20 — routing-header failure => 400 + -32001 (R-22.6-b)
# ---------------------------------------------------------------------------

def test_ac_34_20_routing_header_failure_is_header_mismatch_400():
  m = map_transport_condition(TransportCondition.ROUTING_HEADER_INVALID)
  assert m.code == HEADER_MISMATCH_CODE == -32001
  assert m.http_status == 400


# ---------------------------------------------------------------------------
# AC-34.21 — structurally invalid => -32600; bad metadata => -32602 (R-22.6-c/d)
# ---------------------------------------------------------------------------

def test_ac_34_21_structurally_invalid_request_is_invalid_request():
  m = map_transport_condition(TransportCondition.STRUCTURALLY_INVALID_REQUEST)
  assert m.code == INVALID_REQUEST_CODE
  assert m.http_status == 400


def test_ac_34_21_invalid_per_request_metadata_is_invalid_params():
  m = map_transport_condition(TransportCondition.INVALID_PER_REQUEST_METADATA)
  assert m.code == INVALID_PARAMS_CODE
  assert m.http_status == 400


# ---------------------------------------------------------------------------
# AC-34.22 — unparseable => -32700; not-a-request => -32600 (R-22.6-e/f)
# ---------------------------------------------------------------------------

def test_ac_34_22_unparseable_json_is_parse_error():
  m = map_transport_condition(TransportCondition.UNPARSEABLE_JSON)
  assert m.code == PARSE_ERROR_CODE
  assert m.http_status == 400
  assert code_for_unparseable_input() == PARSE_ERROR_CODE


def test_ac_34_22_not_a_request_object_is_invalid_request():
  m = map_transport_condition(TransportCondition.NOT_A_REQUEST_OBJECT)
  assert m.code == INVALID_REQUEST_CODE
  assert m.http_status == 400
  assert code_for_invalid_request_object() == INVALID_REQUEST_CODE


# ---------------------------------------------------------------------------
# AC-34.23 — extension codes: integer, non-colliding, structured data (R-22.7-a..d)
# ---------------------------------------------------------------------------

def test_ac_34_23_extension_code_may_exist_and_is_integer():
  assert validate_extension_error_code(-31000) == -31000
  assert validate_extension_error_code(100) == 100


def test_ac_34_23_extension_code_must_be_integer():
  with pytest.raises(TypeError):
    validate_extension_error_code("123")  # type: ignore[arg-type]
  with pytest.raises(TypeError):
    validate_extension_error_code(True)  # bool is not a valid code


@pytest.mark.parametrize("reserved", sorted(RESERVED_ERROR_CODES))
def test_ac_34_23_extension_code_must_not_collide(reserved):
  with pytest.raises(ReservedErrorCodeCollisionError):
    validate_extension_error_code(reserved)


def test_ac_34_23_reserved_set_is_all_spec_codes():
  assert RESERVED_ERROR_CODES == frozenset({
    -32700, -32600, -32601, -32602, -32603,  # standard
    -32003, -32004,                            # protocol-specific
    -32001,                                    # transport HeaderMismatch
  })
  assert is_reserved_error_code(-32001)
  assert not is_reserved_error_code(-31000)


def test_ac_34_23_extension_error_should_carry_structured_data():
  err = build_extension_error(-31000, "custom", {"detail": "x"})
  assert err.code == -31000
  assert err.data == {"detail": "x"}
  with pytest.raises(ValueError, match="structured"):
    build_extension_error(-31000, "custom", None)


# ---------------------------------------------------------------------------
# AC-34.24 — tolerate & surface unknown codes (R-22.7-e)
# ---------------------------------------------------------------------------

def test_ac_34_24_unknown_code_is_surfaced_not_rejected():
  surfaced = surface_unknown_error(
    {"code": -41999, "message": "Something custom", "data": {"k": "v"}}
  )
  assert isinstance(surfaced, SurfacedError)
  assert surfaced.code == -41999
  assert surfaced.message == "Something custom"
  assert surfaced.data == {"k": "v"}
  assert surfaced.recognized is False


def test_ac_34_24_unknown_code_without_data_surfaced():
  surfaced = surface_unknown_error(ErrorObject(code=-41999, message="custom"))
  assert surfaced.code == -41999
  assert surfaced.data is None
  assert surfaced.recognized is False


def test_ac_34_24_known_code_surfaced_as_recognized():
  surfaced = surface_unknown_error(ErrorObject(code=INVALID_PARAMS_CODE, message="x"))
  assert surfaced.recognized is True


def test_ac_34_24_unknown_code_is_not_in_registry():
  assert not is_known_error_code(-41999)
  assert error_code_entry(-41999) is None
  assert error_code_name(-41999) is None


def test_ac_34_24_malformed_error_object_still_rejected():
  # An unknown *code* is tolerated, but a structurally malformed Error is not.
  with pytest.raises((TypeError, ValueError)):
    surface_unknown_error({"message": "no code"})


# ---------------------------------------------------------------------------
# AC-34.25 — exact, case-sensitive codes/names/shapes (R-22-a)
# ---------------------------------------------------------------------------

def test_ac_34_25_registry_codes_match_spec_exactly():
  expected = {
    -32700: "Parse error",
    -32600: "Invalid Request",
    -32601: "Method not found",
    -32602: "Invalid params",
    -32603: "Internal error",
    -32003: "MissingRequiredClientCapability",
    -32004: "UnsupportedProtocolVersion",
    -32001: "HeaderMismatch",
  }
  for code, name in expected.items():
    entry = ERROR_CODE_REGISTRY[code]
    assert isinstance(entry, ErrorCodeEntry)
    assert entry.code == code
    assert entry.name == name


def test_ac_34_25_only_protocol_specific_codes_are_data_normative():
  for code, entry in ERROR_CODE_REGISTRY.items():
    expected_normative = code in {-32003, -32004}
    assert entry.data_normative is expected_normative


def test_ac_34_25_field_names_are_case_sensitive():
  # "requiredCapabilities" exactly; a different case is not recognized.
  with pytest.raises(ValueError):
    validate_missing_required_client_capability_data({"requiredcapabilities": {}})
  with pytest.raises(ValueError):
    validate_unsupported_protocol_version_data({"Supported": ["x"], "requested": "y"})


def test_ac_34_25_data_shape_uri_member_exact():
  err = build_resource_not_found_error("file:///x.txt")
  assert "uri" in err.data
  assert "URI" not in err.data
