"""Tests for S17 — Multi-Round-Trip Requests (MRTR).

Coverage map (31 ACs):
  AC-17.1  → TestInputRequiredResultType
  AC-17.2  → TestInputRequestKinds
  AC-17.3  → TestAtLeastOneConstraint
  AC-17.4  → TestInputRequestKeyConstraints
  AC-17.5  → TestUnrecognizedKindError
  AC-17.6  → TestDeprecatedKinds
  AC-17.7  → TestRequestStateOpaque
  AC-17.8  → TestRequestStateMinting
  AC-17.9  → TestRequestStateValidation
  AC-17.10 → TestClientRetry
  AC-17.11 → TestResponseKeyMatch
  AC-17.12 → TestResultTypeClassification
  AC-17.13 → TestAbsentResultTypeIsComplete
  AC-17.14 → TestLoadShedding
  AC-17.15 → TestClientCapabilityCheck
  AC-17.16 → TestMRTRMethods
  AC-17.17 → TestInputResponseParams
  AC-17.18 → TestParseInputRequest
  AC-17.19 → TestValidateInputRequiredResult
  AC-17.20 → TestInputRequiredResultToDict
  AC-17.21 → TestInputRequestToDict
  AC-17.22 → TestInputResponseParamsToDict
  AC-17.23 → TestHmacRoundTrip
  AC-17.24 → TestHmacTamperDetection
  AC-17.25 → TestHmacMalformedToken
  AC-17.26 → TestMalformedResultMissingBoth
  AC-17.27 → TestResultTypeDistinctFrom
  AC-17.28 → TestRequestStateMustBeString
  AC-17.29 → TestInputRequestParamsMustBeObject
  AC-17.30 → TestIsLoadSheddingHelper
  AC-17.31 → TestResultTypeClassificationConstants
"""

import pytest

from mcp_sdk_py.multi_round_trip import (
  DEPRECATED_INPUT_REQUEST_METHODS,
  INPUT_REQUEST_ELICITATION,
  INPUT_REQUEST_ROOTS,
  INPUT_REQUEST_SAMPLING,
  MRTR_METHODS,
  RECOGNIZED_INPUT_REQUEST_METHODS,
  InputRequest,
  InputRequiredResult,
  InputResponseRequestParams,
  InvalidRequestStateError,
  MalformedInputRequiredResultError,
  ResultTypeClassification,
  UnrecognizedInputRequestKindError,
  classify_result_type,
  client_supports_input_kind,
  is_load_shedding_result,
  make_hmac_request_state,
  parse_input_request,
  parse_input_response_params,
  validate_input_required_result,
  validate_response_keys_match,
  verify_hmac_request_state,
)
from mcp_sdk_py.meta_object import KEY_CLIENT_CAPABILITIES


_SECRET = b"test-secret-key-for-hmac"

_SAMPLING_IR = {"method": INPUT_REQUEST_SAMPLING}
_ELICITATION_IR = {"method": INPUT_REQUEST_ELICITATION, "params": {"prompt": "Enter name:"}}
_ROOTS_IR = {"method": INPUT_REQUEST_ROOTS}


# ---------------------------------------------------------------------------
# AC-17.1 — resultType discriminator is always "input_required"  (R-11.2-a)
# ---------------------------------------------------------------------------

class TestInputRequiredResultType:
  def test_result_type_is_input_required(self):
    r = InputRequiredResult(
      input_requests={"a": InputRequest(method=INPUT_REQUEST_ELICITATION)},
    )
    assert r.result_type == "input_required"

  def test_result_type_matches_result_error_constant(self):
    from mcp_sdk_py.result_error import RESULT_TYPE_INPUT_REQUIRED
    r = InputRequiredResult(request_state="tok")
    assert r.result_type == RESULT_TYPE_INPUT_REQUIRED


# ---------------------------------------------------------------------------
# AC-17.2 — Three recognized input-request kinds  (R-11.2-k)
# ---------------------------------------------------------------------------

class TestInputRequestKinds:
  def test_all_three_recognized_kinds(self):
    assert INPUT_REQUEST_SAMPLING in RECOGNIZED_INPUT_REQUEST_METHODS
    assert INPUT_REQUEST_ELICITATION in RECOGNIZED_INPUT_REQUEST_METHODS
    assert INPUT_REQUEST_ROOTS in RECOGNIZED_INPUT_REQUEST_METHODS

  def test_recognized_set_has_exactly_three(self):
    assert len(RECOGNIZED_INPUT_REQUEST_METHODS) == 3

  def test_parse_each_recognized_kind(self):
    for raw in [_SAMPLING_IR, _ELICITATION_IR, _ROOTS_IR]:
      ir = parse_input_request(raw)
      assert ir.method in RECOGNIZED_INPUT_REQUEST_METHODS


# ---------------------------------------------------------------------------
# AC-17.3 — At least one of input_requests or request_state required  (R-11.2-b/c)
# ---------------------------------------------------------------------------

class TestAtLeastOneConstraint:
  def test_both_absent_raises_malformed(self):
    with pytest.raises(MalformedInputRequiredResultError):
      validate_input_required_result({"resultType": "input_required"})

  def test_only_input_requests_is_valid(self):
    raw = {
      "resultType": "input_required",
      "inputRequests": {"k": _ELICITATION_IR},
    }
    r = validate_input_required_result(raw)
    assert r.input_requests is not None
    assert r.request_state is None

  def test_only_request_state_is_valid(self):
    raw = {"resultType": "input_required", "requestState": "opaque-token"}
    r = validate_input_required_result(raw)
    assert r.request_state == "opaque-token"
    assert not r.input_requests

  def test_both_present_is_valid(self):
    raw = {
      "resultType": "input_required",
      "inputRequests": {"k": _ELICITATION_IR},
      "requestState": "tok",
    }
    r = validate_input_required_result(raw)
    assert r.input_requests
    assert r.request_state == "tok"


# ---------------------------------------------------------------------------
# AC-17.4 — inputRequests keys must be non-empty strings  (R-11.2-d/e)
# ---------------------------------------------------------------------------

class TestInputRequestKeyConstraints:
  def test_non_empty_key_accepted(self):
    raw = {
      "resultType": "input_required",
      "inputRequests": {"user-name": _ELICITATION_IR},
    }
    r = validate_input_required_result(raw)
    assert "user-name" in r.input_requests

  def test_empty_key_raises_value_error(self):
    raw = {
      "resultType": "input_required",
      "inputRequests": {"": _ELICITATION_IR},
    }
    with pytest.raises(ValueError, match="non-empty"):
      validate_input_required_result(raw)

  def test_multiple_keys_all_accepted(self):
    raw = {
      "resultType": "input_required",
      "inputRequests": {
        "k1": _ELICITATION_IR,
        "k2": _SAMPLING_IR,
      },
    }
    r = validate_input_required_result(raw)
    assert set(r.input_requests.keys()) == {"k1", "k2"}


# ---------------------------------------------------------------------------
# AC-17.5 — Unrecognized kind → error, MUST NOT fulfill  (R-11.2-k/l)
# ---------------------------------------------------------------------------

class TestUnrecognizedKindError:
  def test_unrecognized_method_raises(self):
    with pytest.raises(UnrecognizedInputRequestKindError) as exc_info:
      parse_input_request({"method": "custom/unknown"})
    assert exc_info.value.unrecognized_method == "custom/unknown"

  def test_unrecognized_in_input_required_propagates(self):
    raw = {
      "resultType": "input_required",
      "inputRequests": {"x": {"method": "no/such/kind"}},
    }
    with pytest.raises(UnrecognizedInputRequestKindError):
      validate_input_required_result(raw)


# ---------------------------------------------------------------------------
# AC-17.6 — Deprecated kinds: sampling and roots  (R-11.2-i)
# ---------------------------------------------------------------------------

class TestDeprecatedKinds:
  def test_sampling_in_deprecated(self):
    assert INPUT_REQUEST_SAMPLING in DEPRECATED_INPUT_REQUEST_METHODS

  def test_roots_in_deprecated(self):
    assert INPUT_REQUEST_ROOTS in DEPRECATED_INPUT_REQUEST_METHODS

  def test_elicitation_not_deprecated(self):
    assert INPUT_REQUEST_ELICITATION not in DEPRECATED_INPUT_REQUEST_METHODS

  def test_deprecated_are_still_recognized(self):
    """Deprecated != unrecognized; they still parse successfully."""
    for method in DEPRECATED_INPUT_REQUEST_METHODS:
      ir = parse_input_request({"method": method})
      assert ir.method == method


# ---------------------------------------------------------------------------
# AC-17.7 — requestState must be opaque string; client echoes verbatim  (R-11.3-a/b/c)
# ---------------------------------------------------------------------------

class TestRequestStateOpaque:
  def test_request_state_returned_verbatim_on_retry(self):
    state = "eyJmb28iOiJiYXIifQ.sig"
    raw = {"resultType": "input_required", "requestState": state}
    r = validate_input_required_result(raw)
    # Client echoes it verbatim on retry.
    retry = InputResponseRequestParams(
      meta={}, request_state=r.request_state
    )
    assert retry.request_state == state

  def test_non_string_request_state_raises(self):
    raw = {"resultType": "input_required", "requestState": 12345}
    with pytest.raises(TypeError):
      validate_input_required_result(raw)


# ---------------------------------------------------------------------------
# AC-17.8 — Server mints requestState token  (R-11.3-g)
# ---------------------------------------------------------------------------

class TestRequestStateMinting:
  def test_make_hmac_produces_non_empty_string(self):
    token = make_hmac_request_state("payload", _SECRET)
    assert isinstance(token, str)
    assert len(token) > 0

  def test_make_hmac_contains_dot_separator(self):
    token = make_hmac_request_state("data", _SECRET)
    assert "." in token

  def test_different_payloads_different_tokens(self):
    t1 = make_hmac_request_state("one", _SECRET)
    t2 = make_hmac_request_state("two", _SECRET)
    assert t1 != t2

  def test_different_secrets_different_tokens(self):
    t1 = make_hmac_request_state("payload", b"secret-A")
    t2 = make_hmac_request_state("payload", b"secret-B")
    assert t1 != t2


# ---------------------------------------------------------------------------
# AC-17.9 — Server validates requestState on retry  (R-11.3-h/i)
# ---------------------------------------------------------------------------

class TestRequestStateValidation:
  def test_verify_recovers_payload(self):
    payload = "user=alice&step=2"
    token = make_hmac_request_state(payload, _SECRET)
    recovered = verify_hmac_request_state(token, _SECRET)
    assert recovered == payload

  def test_empty_payload_round_trips(self):
    token = make_hmac_request_state("", _SECRET)
    assert verify_hmac_request_state(token, _SECRET) == ""

  def test_unicode_payload_round_trips(self):
    payload = "état=initial"
    token = make_hmac_request_state(payload, _SECRET)
    assert verify_hmac_request_state(token, _SECRET) == payload


# ---------------------------------------------------------------------------
# AC-17.10 — Client echoes requestState verbatim on retry  (R-11.3-c, R-11.4-g)
# ---------------------------------------------------------------------------

class TestClientRetry:
  def test_retry_params_carry_request_state_verbatim(self):
    state = "server-minted-token"
    params = parse_input_response_params({
      "_meta": {},
      "requestState": state,
      "inputResponses": {"k": {"value": "alice"}},
    })
    assert params.request_state == state

  def test_retry_params_meta_required(self):
    with pytest.raises(ValueError, match="_meta"):
      parse_input_response_params({"requestState": "tok"})


# ---------------------------------------------------------------------------
# AC-17.11 — inputResponses keys must be subset of inputRequests keys  (R-11.2-h)
# ---------------------------------------------------------------------------

class TestResponseKeyMatch:
  def test_matching_keys_pass(self):
    requests = {
      "name": InputRequest(method=INPUT_REQUEST_ELICITATION),
    }
    responses = {"name": {"value": "Alice"}}
    validate_response_keys_match(requests, responses)

  def test_extra_response_key_raises(self):
    requests = {"name": InputRequest(method=INPUT_REQUEST_ELICITATION)}
    responses = {"name": {"value": "Alice"}, "extra": "bad"}
    with pytest.raises(ValueError, match="extra"):
      validate_response_keys_match(requests, responses)

  def test_subset_of_keys_is_allowed(self):
    """Client may omit some keys (optional fulfillment)."""
    requests = {
      "k1": InputRequest(method=INPUT_REQUEST_ELICITATION),
      "k2": InputRequest(method=INPUT_REQUEST_ELICITATION),
    }
    responses = {"k1": {"value": "only one"}}
    validate_response_keys_match(requests, responses)


# ---------------------------------------------------------------------------
# AC-17.12 — Client branches on resultType  (R-11.5-c)
# ---------------------------------------------------------------------------

class TestResultTypeClassification:
  def test_complete_classified_correctly(self):
    assert classify_result_type({"resultType": "complete"}) == ResultTypeClassification.COMPLETE

  def test_input_required_classified_correctly(self):
    assert classify_result_type({"resultType": "input_required"}) == ResultTypeClassification.INPUT_REQUIRED

  def test_unknown_string_is_unknown(self):
    assert classify_result_type({"resultType": "future_type"}) == ResultTypeClassification.UNKNOWN

  def test_none_result_type_is_unknown(self):
    assert classify_result_type({"resultType": None}) == ResultTypeClassification.UNKNOWN


# ---------------------------------------------------------------------------
# AC-17.13 — Absent resultType treated as "complete"  (R-11.5-f)
# ---------------------------------------------------------------------------

class TestAbsentResultTypeIsComplete:
  def test_absent_result_type_is_absent(self):
    assert classify_result_type({}) == ResultTypeClassification.ABSENT

  def test_absent_is_distinct_from_complete(self):
    """ABSENT and COMPLETE are different strings; caller treats ABSENT as complete."""
    assert ResultTypeClassification.ABSENT != ResultTypeClassification.COMPLETE


# ---------------------------------------------------------------------------
# AC-17.14 — Load-shedding: no inputRequests, only requestState  (R-11.5-l/p)
# ---------------------------------------------------------------------------

class TestLoadShedding:
  def test_load_shedding_result_detected(self):
    raw = {"resultType": "input_required", "requestState": "retry-later"}
    assert is_load_shedding_result(raw)

  def test_normal_result_is_not_load_shedding(self):
    raw = {
      "resultType": "input_required",
      "inputRequests": {"k": _ELICITATION_IR},
      "requestState": "tok",
    }
    assert not is_load_shedding_result(raw)

  def test_load_shedding_property_on_parsed_result(self):
    raw = {"resultType": "input_required", "requestState": "shed"}
    r = validate_input_required_result(raw)
    assert r.is_load_shedding

  def test_non_input_required_is_not_load_shedding(self):
    assert not is_load_shedding_result({"resultType": "complete"})


# ---------------------------------------------------------------------------
# AC-17.15 — Server checks client capability before emitting kind  (R-11.2-j)
# ---------------------------------------------------------------------------

class TestClientCapabilityCheck:
  def test_elicitation_cap_detected(self):
    meta = {KEY_CLIENT_CAPABILITIES: {"elicitation": {}}}
    assert client_supports_input_kind(meta, INPUT_REQUEST_ELICITATION)

  def test_missing_cap_returns_false(self):
    meta = {KEY_CLIENT_CAPABILITIES: {}}
    assert not client_supports_input_kind(meta, INPUT_REQUEST_ELICITATION)

  def test_sampling_cap_detected(self):
    meta = {KEY_CLIENT_CAPABILITIES: {"sampling": {}}}
    assert client_supports_input_kind(meta, INPUT_REQUEST_SAMPLING)

  def test_roots_cap_detected(self):
    meta = {KEY_CLIENT_CAPABILITIES: {"roots": {}}}
    assert client_supports_input_kind(meta, INPUT_REQUEST_ROOTS)

  def test_no_client_capabilities_key_returns_false(self):
    meta = {}
    assert not client_supports_input_kind(meta, INPUT_REQUEST_ELICITATION)


# ---------------------------------------------------------------------------
# AC-17.16 — MRTR applies to tools/call, prompts/get, resources/read  (R-11.6-a)
# ---------------------------------------------------------------------------

class TestMRTRMethods:
  def test_all_three_mrtr_methods(self):
    assert "tools/call" in MRTR_METHODS
    assert "prompts/get" in MRTR_METHODS
    assert "resources/read" in MRTR_METHODS

  def test_other_methods_not_in_mrtr(self):
    assert "tools/list" not in MRTR_METHODS
    assert "resources/list" not in MRTR_METHODS


# ---------------------------------------------------------------------------
# AC-17.17 — InputResponseRequestParams: meta required, responses optional  (R-11.4-a/b)
# ---------------------------------------------------------------------------

class TestInputResponseParams:
  def test_minimal_retry_params_just_meta(self):
    p = parse_input_response_params({"_meta": {"foo": "bar"}})
    assert p.meta == {"foo": "bar"}
    assert p.input_responses is None
    assert p.request_state is None

  def test_full_retry_params(self):
    raw = {
      "_meta": {},
      "inputResponses": {"k": {"value": "v"}},
      "requestState": "state-tok",
    }
    p = parse_input_response_params(raw)
    assert p.input_responses == {"k": {"value": "v"}}
    assert p.request_state == "state-tok"

  def test_input_responses_must_be_object(self):
    with pytest.raises(TypeError):
      parse_input_response_params({
        "_meta": {},
        "inputResponses": "not-an-object",
      })

  def test_request_state_must_be_string(self):
    with pytest.raises(TypeError):
      parse_input_response_params({
        "_meta": {},
        "requestState": 99,
      })


# ---------------------------------------------------------------------------
# AC-17.18 — parse_input_request: validates method type and presence
# ---------------------------------------------------------------------------

class TestParseInputRequest:
  def test_missing_method_raises(self):
    with pytest.raises(ValueError, match="method"):
      parse_input_request({})

  def test_non_string_method_raises(self):
    with pytest.raises(TypeError):
      parse_input_request({"method": 42})

  def test_not_a_dict_raises(self):
    with pytest.raises(TypeError):
      parse_input_request(["elicitation/create"])

  def test_valid_parse_with_params(self):
    raw = {"method": INPUT_REQUEST_ELICITATION, "params": {"prompt": "Enter:"}}
    ir = parse_input_request(raw)
    assert ir.params == {"prompt": "Enter:"}

  def test_params_must_be_dict(self):
    raw = {"method": INPUT_REQUEST_ELICITATION, "params": "not-an-object"}
    with pytest.raises(TypeError):
      parse_input_request(raw)


# ---------------------------------------------------------------------------
# AC-17.19 — validate_input_required_result: resultType case-sensitive  (R-11.2-a)
# ---------------------------------------------------------------------------

class TestValidateInputRequiredResult:
  def test_wrong_case_result_type_raises(self):
    raw = {
      "resultType": "Input_Required",
      "inputRequests": {"k": _ELICITATION_IR},
    }
    with pytest.raises(ValueError, match="case-sensitive"):
      validate_input_required_result(raw)

  def test_complete_result_type_raises(self):
    with pytest.raises(ValueError):
      validate_input_required_result({
        "resultType": "complete",
        "inputRequests": {"k": _ELICITATION_IR},
      })

  def test_not_a_dict_raises(self):
    with pytest.raises(TypeError):
      validate_input_required_result(["input_required"])


# ---------------------------------------------------------------------------
# AC-17.20 — InputRequiredResult.to_dict serialization
# ---------------------------------------------------------------------------

class TestInputRequiredResultToDict:
  def test_minimal_with_request_state(self):
    r = InputRequiredResult(request_state="tok")
    d = r.to_dict()
    assert d["resultType"] == "input_required"
    assert d["requestState"] == "tok"
    assert "inputRequests" not in d

  def test_with_input_requests(self):
    r = InputRequiredResult(
      input_requests={"k": InputRequest(method=INPUT_REQUEST_ELICITATION)},
    )
    d = r.to_dict()
    assert "k" in d["inputRequests"]
    assert d["inputRequests"]["k"]["method"] == INPUT_REQUEST_ELICITATION

  def test_meta_included_when_present(self):
    r = InputRequiredResult(request_state="tok", meta={"trace": "id"})
    d = r.to_dict()
    assert d["_meta"] == {"trace": "id"}


# ---------------------------------------------------------------------------
# AC-17.21 — InputRequest.to_dict serialization
# ---------------------------------------------------------------------------

class TestInputRequestToDict:
  def test_minimal_no_params(self):
    ir = InputRequest(method=INPUT_REQUEST_SAMPLING)
    d = ir.to_dict()
    assert d == {"method": INPUT_REQUEST_SAMPLING}
    assert "params" not in d

  def test_with_params(self):
    ir = InputRequest(method=INPUT_REQUEST_ELICITATION, params={"p": 1})
    d = ir.to_dict()
    assert d == {"method": INPUT_REQUEST_ELICITATION, "params": {"p": 1}}


# ---------------------------------------------------------------------------
# AC-17.22 — InputResponseRequestParams.to_dict serialization
# ---------------------------------------------------------------------------

class TestInputResponseParamsToDict:
  def test_minimal_with_meta(self):
    p = InputResponseRequestParams(meta={"v": "x"})
    d = p.to_dict()
    assert d == {"_meta": {"v": "x"}}

  def test_full(self):
    p = InputResponseRequestParams(
      meta={"v": "x"},
      input_responses={"k": {"value": "v"}},
      request_state="tok",
    )
    d = p.to_dict()
    assert d["_meta"] == {"v": "x"}
    assert d["inputResponses"] == {"k": {"value": "v"}}
    assert d["requestState"] == "tok"


# ---------------------------------------------------------------------------
# AC-17.23 — HMAC round-trip: mint → verify → payload
# ---------------------------------------------------------------------------

class TestHmacRoundTrip:
  def test_round_trip_simple(self):
    payload = "step=3,user=bob"
    tok = make_hmac_request_state(payload, _SECRET)
    assert verify_hmac_request_state(tok, _SECRET) == payload

  def test_round_trip_json_payload(self):
    import json
    payload = json.dumps({"step": 2, "id": "abc"})
    tok = make_hmac_request_state(payload, _SECRET)
    assert verify_hmac_request_state(tok, _SECRET) == payload


# ---------------------------------------------------------------------------
# AC-17.24 — HMAC tamper detection  (R-11.3-i)
# ---------------------------------------------------------------------------

class TestHmacTamperDetection:
  def test_modified_payload_rejected(self):
    tok = make_hmac_request_state("original", _SECRET)
    # Modify the payload segment.
    parts = tok.split(".")
    tampered = f"dGFtcGVyZWQ.{parts[1]}"  # "tampered" in base64url
    with pytest.raises(InvalidRequestStateError):
      verify_hmac_request_state(tampered, _SECRET)

  def test_wrong_secret_rejected(self):
    tok = make_hmac_request_state("data", _SECRET)
    with pytest.raises(InvalidRequestStateError):
      verify_hmac_request_state(tok, b"wrong-secret")

  def test_modified_signature_rejected(self):
    tok = make_hmac_request_state("data", _SECRET)
    payload_b64 = tok.split(".")[0]
    with pytest.raises(InvalidRequestStateError):
      verify_hmac_request_state(f"{payload_b64}.AAAA", _SECRET)


# ---------------------------------------------------------------------------
# AC-17.25 — Malformed token raises InvalidRequestStateError  (R-11.3-i)
# ---------------------------------------------------------------------------

class TestHmacMalformedToken:
  def test_no_dot_separator_raises(self):
    with pytest.raises(InvalidRequestStateError):
      verify_hmac_request_state("nodothere", _SECRET)

  def test_empty_string_raises(self):
    with pytest.raises(InvalidRequestStateError):
      verify_hmac_request_state("", _SECRET)


# ---------------------------------------------------------------------------
# AC-17.26 — Both absent raises MalformedInputRequiredResultError  (R-11.2-b/c)
# ---------------------------------------------------------------------------

class TestMalformedResultMissingBoth:
  def test_error_class_has_json_rpc_code(self):
    assert MalformedInputRequiredResultError.json_rpc_code == -32600

  def test_raises_on_both_absent(self):
    with pytest.raises(MalformedInputRequiredResultError):
      validate_input_required_result({"resultType": "input_required"})


# ---------------------------------------------------------------------------
# AC-17.27 — ResultTypeClassification.COMPLETE != INPUT_REQUIRED  (R-11.5-c)
# ---------------------------------------------------------------------------

class TestResultTypeDistinctFrom:
  def test_complete_and_input_required_distinct(self):
    assert ResultTypeClassification.COMPLETE != ResultTypeClassification.INPUT_REQUIRED
    assert ResultTypeClassification.ABSENT != ResultTypeClassification.COMPLETE
    assert ResultTypeClassification.UNKNOWN != ResultTypeClassification.INPUT_REQUIRED


# ---------------------------------------------------------------------------
# AC-17.28 — requestState must be a string or None  (R-11.3-a)
# ---------------------------------------------------------------------------

class TestRequestStateMustBeString:
  def test_integer_request_state_raises(self):
    with pytest.raises(TypeError):
      validate_input_required_result({"resultType": "input_required", "requestState": 42})

  def test_null_request_state_absent(self):
    """Explicit null means absent — the constraint triggers for both absent."""
    with pytest.raises(MalformedInputRequiredResultError):
      validate_input_required_result({"resultType": "input_required", "requestState": None})


# ---------------------------------------------------------------------------
# AC-17.29 — InputRequest.params must be an object if present  (R-11.2)
# ---------------------------------------------------------------------------

class TestInputRequestParamsMustBeObject:
  def test_list_params_raises(self):
    with pytest.raises(TypeError):
      parse_input_request({"method": INPUT_REQUEST_ELICITATION, "params": [1, 2]})

  def test_string_params_raises(self):
    with pytest.raises(TypeError):
      parse_input_request({"method": INPUT_REQUEST_ELICITATION, "params": "str"})


# ---------------------------------------------------------------------------
# AC-17.30 — is_load_shedding_result helper  (R-11.5-l)
# ---------------------------------------------------------------------------

class TestIsLoadSheddingHelper:
  def test_load_shedding_has_only_request_state(self):
    assert is_load_shedding_result({
      "resultType": "input_required",
      "requestState": "tok",
    })

  def test_empty_input_requests_with_state_is_load_shedding(self):
    assert is_load_shedding_result({
      "resultType": "input_required",
      "inputRequests": {},
      "requestState": "tok",
    })

  def test_complete_result_is_not_load_shedding(self):
    assert not is_load_shedding_result({"resultType": "complete", "data": {}})

  def test_no_request_state_not_load_shedding(self):
    assert not is_load_shedding_result({
      "resultType": "input_required",
      "inputRequests": {"k": _ELICITATION_IR},
    })


# ---------------------------------------------------------------------------
# AC-17.31 — ResultTypeClassification constants are strings  (R-11.5-c)
# ---------------------------------------------------------------------------

class TestResultTypeClassificationConstants:
  def test_all_constants_are_strings(self):
    assert isinstance(ResultTypeClassification.COMPLETE, str)
    assert isinstance(ResultTypeClassification.INPUT_REQUIRED, str)
    assert isinstance(ResultTypeClassification.ABSENT, str)
    assert isinstance(ResultTypeClassification.UNKNOWN, str)

  def test_error_codes_on_exceptions(self):
    assert MalformedInputRequiredResultError.json_rpc_code == -32600
    assert InvalidRequestStateError.json_rpc_code == -32600
