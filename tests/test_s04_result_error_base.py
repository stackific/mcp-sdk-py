"""Tests for S04 — Result base, base params, error object, and empty result.

Coverage map:
  AC-04.1  → test_result_type_required_*
  AC-04.2  → test_result_meta_optional_*
  AC-04.3  → test_result_unknown_meta_keys_accepted
  AC-04.4  → test_result_extra_members_accepted
  AC-04.5  → test_result_type_extension_mechanism
  AC-04.6  → test_unknown_result_type_treated_as_error
  AC-04.7  → test_absent_result_type_interop_fallback
  AC-04.8  → test_request_params_meta_required
  AC-04.9  → test_notification_params_meta_optional
  AC-04.10 → test_progress_token_in_request_meta
  AC-04.11 → test_cursor_is_opaque
  AC-04.12 → test_error_code_required_integer
  AC-04.13 → test_error_code_no_constants_in_s04
  AC-04.14 → test_error_message_required_string
  AC-04.15 → test_error_data_optional
  AC-04.16 → test_error_data_structure_not_assumed
  AC-04.17 → test_empty_result_sets_result_type
  AC-04.18 → test_empty_result_only_base_members
"""

import pytest

from mcp_sdk_py.result_error import (
  RESULT_TYPE_COMPLETE,
  RESULT_TYPE_INPUT_REQUIRED,
  EmptyResult,
  ErrorObject,
  NotificationParams,
  ProgressToken,
  RequestParams,
  Result,
  UnknownResultTypeError,
  parse_empty_result,
  parse_notification_params,
  parse_request_params,
  parse_result,
  validate_cursor,
  validate_error_object,
  validate_progress_token,
)


# ---------------------------------------------------------------------------
# AC-04.1  resultType is REQUIRED on every result  (R-3.6-c, R-3.6-h)
# ---------------------------------------------------------------------------

class TestResultTypeRequired:
  def test_resulttype_present_is_valid(self):
    """parse_result succeeds when resultType is present."""
    r = parse_result({"resultType": "complete"})
    assert r.result_type == RESULT_TYPE_COMPLETE

  def test_resulttype_input_required_is_valid(self):
    r = parse_result({"resultType": "input_required"})
    assert r.result_type == RESULT_TYPE_INPUT_REQUIRED

  def test_resulttype_absent_raises_in_strict_mode(self):
    """Absent resultType raises ValueError in strict (default) mode."""
    with pytest.raises(ValueError, match="resultType is REQUIRED"):
      parse_result({})

  def test_resulttype_absent_with_other_members_raises(self):
    """Absent resultType raises even when other fields are present."""
    with pytest.raises(ValueError, match="resultType is REQUIRED"):
      parse_result({"tools": [], "_meta": {}})

  def test_result_to_dict_always_contains_result_type(self):
    """to_dict() always emits resultType — conformant server behaviour."""
    r = Result(result_type=RESULT_TYPE_COMPLETE)
    d = r.to_dict()
    assert "resultType" in d
    assert d["resultType"] == RESULT_TYPE_COMPLETE

  def test_resulttype_non_string_raises(self):
    with pytest.raises(TypeError, match="resultType must be a string"):
      parse_result({"resultType": 42})


# ---------------------------------------------------------------------------
# AC-04.2  _meta is optional on Result  (R-3.6-a)
# ---------------------------------------------------------------------------

class TestResultMetaOptional:
  def test_result_without_meta_is_valid(self):
    """_meta may be absent; result is still valid."""
    r = parse_result({"resultType": "complete"})
    assert r.meta is None

  def test_result_with_meta_object_is_valid(self):
    meta = {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}
    r = parse_result({"resultType": "complete", "_meta": meta})
    assert r.meta == meta

  def test_result_meta_roundtrips(self):
    meta = {"io.example/key": "value"}
    r = parse_result({"resultType": "complete", "_meta": meta})
    assert r.to_dict()["_meta"] == meta

  def test_result_meta_must_be_object_not_string(self):
    with pytest.raises(TypeError, match="_meta must be a JSON object"):
      parse_result({"resultType": "complete", "_meta": "not-an-object"})

  def test_result_meta_must_be_object_not_list(self):
    with pytest.raises(TypeError, match="_meta must be a JSON object"):
      parse_result({"resultType": "complete", "_meta": []})

  def test_result_to_dict_omits_meta_when_none(self):
    r = Result(result_type=RESULT_TYPE_COMPLETE)
    assert "_meta" not in r.to_dict()

  def test_result_to_dict_includes_meta_when_set(self):
    meta: dict = {"key": "val"}
    r = Result(result_type=RESULT_TYPE_COMPLETE, meta=meta)
    assert r.to_dict()["_meta"] == meta


# ---------------------------------------------------------------------------
# AC-04.3  Receiver does not act on assumed meaning of unknown _meta keys
#           (R-3.6-b)
# ---------------------------------------------------------------------------

class TestResultUnknownMetaKeysAccepted:
  def test_mcp_reserved_unknown_key_is_accepted(self):
    """Unknown MCP-reserved _meta key is parsed without error or assumed meaning."""
    meta = {"io.modelcontextprotocol/unknownFutureKey": 42}
    r = parse_result({"resultType": "complete", "_meta": meta})
    # The key is preserved as-is; no exception, no special handling.
    assert r.meta == meta

  def test_vendor_key_in_meta_is_accepted(self):
    meta = {"com.example/some-key": {"nested": True}}
    r = parse_result({"resultType": "complete", "_meta": meta})
    assert r.meta == meta

  def test_multiple_unknown_meta_keys_accepted(self):
    meta = {
      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
      "io.modelcontextprotocol/unknownKeyA": "x",
      "io.modelcontextprotocol/unknownKeyB": None,
    }
    r = parse_result({"resultType": "complete", "_meta": meta})
    assert r.meta == meta


# ---------------------------------------------------------------------------
# AC-04.4  Extra method-defined members are accepted  (R-3.6-d)
# ---------------------------------------------------------------------------

class TestResultExtraMembersAccepted:
  def test_extra_member_is_preserved(self):
    r = parse_result({"resultType": "complete", "tools": []})
    assert r.extra == {"tools": []}

  def test_multiple_extra_members(self):
    r = parse_result({
      "resultType": "complete",
      "tools": [{"name": "search"}],
      "nextCursor": "tok-abc",
    })
    assert r.extra["tools"] == [{"name": "search"}]
    assert r.extra["nextCursor"] == "tok-abc"

  def test_extra_members_survive_roundtrip(self):
    raw = {"resultType": "complete", "tools": [], "total": 5}
    r = parse_result(raw)
    out = r.to_dict()
    assert out["tools"] == []
    assert out["total"] == 5

  def test_extra_member_nested_object(self):
    r = parse_result({"resultType": "complete", "content": {"type": "text", "text": "hi"}})
    assert r.extra["content"] == {"type": "text", "text": "hi"}


# ---------------------------------------------------------------------------
# AC-04.5  New resultType requires extension mechanism  (R-3.6-e)
# ---------------------------------------------------------------------------

class TestResultTypeExtensionMechanism:
  def test_arbitrary_result_type_without_extension_is_rejected(self):
    """A resultType not in the protocol set and not in known_extensions raises."""
    with pytest.raises(UnknownResultTypeError) as exc_info:
      parse_result({"resultType": "streaming"})
    assert exc_info.value.result_type == "streaming"

  def test_extension_result_type_registered_is_accepted(self):
    """A resultType introduced via the extension set is accepted."""
    r = parse_result(
      {"resultType": "streaming"},
      known_extensions=frozenset({"streaming"}),
    )
    assert r.result_type == "streaming"

  def test_known_result_types_are_always_accepted(self):
    for rt in (RESULT_TYPE_COMPLETE, RESULT_TYPE_INPUT_REQUIRED):
      r = parse_result({"resultType": rt})
      assert r.result_type == rt


# ---------------------------------------------------------------------------
# AC-04.6  Unrecognized resultType → error; do not read other members
#           (R-3.6-f, R-3.6-g)
# ---------------------------------------------------------------------------

class TestUnknownResultTypeTreatedAsError:
  def test_raises_unknown_result_type_error(self):
    with pytest.raises(UnknownResultTypeError):
      parse_result({"resultType": "alien_type", "secret": "sensitive"})

  def test_exception_carries_the_unknown_value(self):
    with pytest.raises(UnknownResultTypeError) as exc_info:
      parse_result({"resultType": "alien_type"})
    assert exc_info.value.result_type == "alien_type"

  def test_other_members_not_returned_on_unknown_type(self):
    """Function raises before constructing a Result; no partial object returned."""
    caught = None
    try:
      parse_result({"resultType": "alien_type", "sensitive_data": "value"})
    except UnknownResultTypeError as exc:
      caught = exc
    assert caught is not None
    # No Result object escapes; the exception is the only observable output.
    assert not hasattr(caught, "extra")

  def test_unknown_type_with_meta_still_raises(self):
    """Even if _meta looks valid, the function raises on unknown resultType."""
    with pytest.raises(UnknownResultTypeError):
      parse_result({"resultType": "future_type", "_meta": {"key": "val"}})


# ---------------------------------------------------------------------------
# AC-04.7  Absent resultType treated as "complete" in interop mode  (R-3.6-i)
# ---------------------------------------------------------------------------

class TestAbsentResultTypeInteropFallback:
  def test_strict_mode_rejects_absent_result_type(self):
    with pytest.raises(ValueError, match="resultType is REQUIRED"):
      parse_result({}, interop_fallback=False)

  def test_interop_mode_treats_absent_as_complete(self):
    r = parse_result({}, interop_fallback=True)
    assert r.result_type == RESULT_TYPE_COMPLETE

  def test_interop_mode_preserves_extra_members(self):
    r = parse_result({"tools": [], "count": 0}, interop_fallback=True)
    assert r.result_type == RESULT_TYPE_COMPLETE
    assert r.extra["tools"] == []
    assert r.extra["count"] == 0

  def test_interop_mode_preserves_meta(self):
    r = parse_result({"_meta": {"io.example/k": "v"}}, interop_fallback=True)
    assert r.result_type == RESULT_TYPE_COMPLETE
    assert r.meta == {"io.example/k": "v"}

  def test_explicit_complete_not_affected_by_interop_flag(self):
    r = parse_result({"resultType": "complete"}, interop_fallback=True)
    assert r.result_type == RESULT_TYPE_COMPLETE


# ---------------------------------------------------------------------------
# AC-04.8  Request params _meta is REQUIRED  (R-3.7-a)
# ---------------------------------------------------------------------------

class TestRequestParamsMetaRequired:
  def test_request_params_with_meta_succeeds(self):
    meta = {
      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
      "io.modelcontextprotocol/clientInfo": {"name": "ExampleClient", "version": "1.0.0"},
    }
    p = parse_request_params({"_meta": meta})
    assert p.meta == meta

  def test_request_params_without_meta_raises(self):
    with pytest.raises(ValueError, match="_meta is REQUIRED"):
      parse_request_params({})

  def test_request_params_without_meta_with_other_keys_raises(self):
    with pytest.raises(ValueError, match="_meta is REQUIRED"):
      parse_request_params({"cursor": "tok"})

  def test_request_params_meta_must_be_object(self):
    with pytest.raises(TypeError, match="_meta must be a JSON object"):
      parse_request_params({"_meta": "not-an-object"})

  def test_request_params_meta_must_be_object_not_list(self):
    with pytest.raises(TypeError, match="_meta must be a JSON object"):
      parse_request_params({"_meta": []})

  def test_request_params_extra_members_preserved(self):
    p = parse_request_params({"_meta": {}, "cursor": "tok-abc"})
    assert p.extra == {"cursor": "tok-abc"}

  def test_request_params_roundtrip(self):
    meta = {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}
    p = parse_request_params({"_meta": meta})
    out = p.to_dict()
    assert out["_meta"] == meta

  def test_request_params_non_dict_raises(self):
    with pytest.raises(TypeError, match="params must be a JSON object"):
      parse_request_params("not-a-dict")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# AC-04.9  Notification params _meta is OPTIONAL  (R-3.7-b)
# ---------------------------------------------------------------------------

class TestNotificationParamsMetaOptional:
  def test_notification_params_without_meta_is_valid(self):
    """_meta may be absent on notification params."""
    p = parse_notification_params({"progressToken": "abc-123", "progress": 0.5})
    assert p.meta is None
    assert p.extra["progressToken"] == "abc-123"
    assert p.extra["progress"] == 0.5

  def test_notification_params_with_empty_dict_is_valid(self):
    p = parse_notification_params({})
    assert p.meta is None
    assert p.extra == {}

  def test_notification_params_with_meta_is_valid(self):
    meta = {"io.example/traceId": "xyz"}
    p = parse_notification_params({"_meta": meta})
    assert p.meta == meta

  def test_notification_params_meta_must_be_object_when_present(self):
    with pytest.raises(TypeError, match="_meta must be a JSON object"):
      parse_notification_params({"_meta": "not-an-object"})

  def test_notification_params_meta_absent_from_dict_output(self):
    p = parse_notification_params({"key": "val"})
    out = p.to_dict()
    assert "_meta" not in out
    assert out["key"] == "val"

  def test_notification_params_meta_in_dict_output_when_set(self):
    meta = {"io.example/k": "v"}
    p = parse_notification_params({"_meta": meta, "extra": 1})
    out = p.to_dict()
    assert out["_meta"] == meta
    assert out["extra"] == 1


# ---------------------------------------------------------------------------
# AC-04.10  Progress token in request _meta — receiver MAY emit progress
#            (R-3.7-c)
# ---------------------------------------------------------------------------

class TestProgressTokenInRequestMeta:
  def test_progress_token_string_in_request_meta(self):
    """A string progress token is valid and preserved in _meta."""
    meta = {"progressToken": "abc-123"}
    p = parse_request_params({"_meta": meta})
    assert p.meta["progressToken"] == "abc-123"

  def test_progress_token_integer_in_request_meta(self):
    """An integer progress token is valid."""
    meta = {"progressToken": 42}
    p = parse_request_params({"_meta": meta})
    assert p.meta["progressToken"] == 42

  def test_validate_progress_token_string(self):
    assert validate_progress_token("abc-123") == "abc-123"

  def test_validate_progress_token_integer(self):
    assert validate_progress_token(7) == 7

  def test_validate_progress_token_float(self):
    assert validate_progress_token(3.14) == 3.14

  def test_validate_progress_token_rejects_bool(self):
    with pytest.raises(TypeError, match="ProgressToken must be str or number"):
      validate_progress_token(True)

  def test_validate_progress_token_rejects_none(self):
    with pytest.raises(TypeError, match="ProgressToken must be str or number"):
      validate_progress_token(None)

  def test_validate_progress_token_rejects_list(self):
    with pytest.raises(TypeError, match="ProgressToken must be str or number"):
      validate_progress_token([1, 2])

  def test_receiver_without_progress_emission_is_conformant(self):
    """A receiver that parses the token but emits no progress is still valid (R-3.7-c MAY)."""
    # Parsing succeeds; the receiver is not obligated to do anything with the token.
    meta = {"progressToken": "tok", "io.modelcontextprotocol/protocolVersion": "2026-07-28"}
    p = parse_request_params({"_meta": meta})
    token = p.meta.get("progressToken")
    assert token == "tok"
    # Not emitting any notification — conformant.


# ---------------------------------------------------------------------------
# AC-04.11  Cursor is opaque; receivers must not parse it  (R-3.7-d)
# ---------------------------------------------------------------------------

class TestCursorIsOpaque:
  def test_validate_cursor_accepts_any_string(self):
    """Any string is a valid cursor; validate_cursor treats it opaquely."""
    for cursor_val in ("opaque-token", "12345678-abcd-efgh", "", "eyJwYWdlIjozfQ=="):
      result = validate_cursor(cursor_val)
      assert result == cursor_val

  def test_validate_cursor_does_not_parse_structure(self):
    """The function returns the cursor unchanged — it never inspects content."""
    cursor = "page=3&limit=10"
    assert validate_cursor(cursor) == cursor

  def test_validate_cursor_rejects_non_string(self):
    with pytest.raises(TypeError, match="Cursor must be a string"):
      validate_cursor(123)

  def test_validate_cursor_rejects_none(self):
    with pytest.raises(TypeError, match="Cursor must be a string"):
      validate_cursor(None)

  def test_validate_cursor_rejects_dict(self):
    with pytest.raises(TypeError, match="Cursor must be a string"):
      validate_cursor({"page": 3})


# ---------------------------------------------------------------------------
# AC-04.12  Error code is required integer  (R-3.8-a)
# ---------------------------------------------------------------------------

class TestErrorCodeRequiredInteger:
  def test_error_with_code_and_message_is_valid(self):
    e = validate_error_object({"code": -32601, "message": "Method not found"})
    assert e.code == -32601

  def test_error_missing_code_raises(self):
    with pytest.raises(ValueError, match="error.code is REQUIRED"):
      validate_error_object({"message": "oops"})

  def test_error_code_string_raises(self):
    with pytest.raises(TypeError, match="error.code must be an integer"):
      validate_error_object({"code": "-32601", "message": "err"})

  def test_error_code_bool_raises(self):
    """bool is a subclass of int in Python; reject it as code."""
    with pytest.raises(TypeError, match="error.code must be an integer"):
      validate_error_object({"code": True, "message": "err"})

  def test_error_code_float_raises(self):
    with pytest.raises(TypeError, match="error.code must be an integer"):
      validate_error_object({"code": -32601.0, "message": "err"})

  def test_error_code_positive_integer_is_valid(self):
    """Any integer is accepted; range restrictions come from §22/S34."""
    e = validate_error_object({"code": 1, "message": "custom"})
    assert e.code == 1

  def test_error_code_zero_is_valid(self):
    e = validate_error_object({"code": 0, "message": "zero"})
    assert e.code == 0


# ---------------------------------------------------------------------------
# AC-04.13  Error codes not defined in this module — S34 owns code values
#            (R-3.8-b)
# ---------------------------------------------------------------------------

class TestErrorCodeNoConstantsInS04:
  def test_result_error_module_defines_no_error_code_constants(self):
    """S04 must not enumerate or assign error codes; that is S34's domain (R-3.8-b)."""
    import mcp_sdk_py.result_error as m
    code_names = [
      name for name in dir(m)
      if not name.startswith("_") and "CODE" in name.upper() and "ERROR" in name.upper()
    ]
    assert code_names == [], (
      f"result_error.py must not define error code constants; "
      f"found: {code_names!r} (R-3.8-b)"
    )

  def test_validate_error_object_accepts_any_integer_code(self):
    """Code range validation is deferred to §22/S34; any int is accepted here."""
    for code in (-32700, -32600, -1, 0, 1, 32000, 32768):
      e = validate_error_object({"code": code, "message": "ok"})
      assert e.code == code


# ---------------------------------------------------------------------------
# AC-04.14  Error message is required string; SHOULD be single sentence
#            (R-3.8-c, R-3.8-d)
# ---------------------------------------------------------------------------

class TestErrorMessageRequiredString:
  def test_message_present_is_valid(self):
    e = validate_error_object({"code": -32601, "message": "Method not found"})
    assert e.message == "Method not found"

  def test_message_missing_raises(self):
    with pytest.raises(ValueError, match="error.message is REQUIRED"):
      validate_error_object({"code": -32601})

  def test_message_integer_raises(self):
    with pytest.raises(TypeError, match="error.message must be a string"):
      validate_error_object({"code": -32601, "message": 42})

  def test_message_none_raises(self):
    with pytest.raises(TypeError, match="error.message must be a string"):
      validate_error_object({"code": -32601, "message": None})

  def test_multi_sentence_message_is_not_a_hard_failure(self):
    """SHOULD (not MUST): multi-sentence message is a documented-justification
    deviation, not a hard validation failure (R-3.8-d)."""
    e = validate_error_object({
      "code": -32000,
      "message": "Something went wrong. Please try again later.",
    })
    assert "." in e.message  # accepted without error

  def test_empty_string_message_accepted(self):
    e = validate_error_object({"code": -32601, "message": ""})
    assert e.message == ""


# ---------------------------------------------------------------------------
# AC-04.15  Error data is optional; may be any sender-defined value  (R-3.8-e)
# ---------------------------------------------------------------------------

class TestErrorDataOptional:
  def test_absent_data_is_valid(self):
    e = validate_error_object({"code": -32601, "message": "Not found"})
    assert not e.has_data

  def test_data_dict_is_valid(self):
    e = validate_error_object({
      "code": -32601,
      "message": "Not found",
      "data": {"method": "tools/list"},
    })
    assert e.has_data
    assert e.data == {"method": "tools/list"}

  def test_data_null_is_valid(self):
    e = validate_error_object({"code": -32601, "message": "err", "data": None})
    assert e.has_data
    assert e.data is None

  def test_data_integer_is_valid(self):
    e = validate_error_object({"code": -32601, "message": "err", "data": 99})
    assert e.has_data
    assert e.data == 99

  def test_data_string_is_valid(self):
    e = validate_error_object({"code": -32601, "message": "err", "data": "extra info"})
    assert e.has_data
    assert e.data == "extra info"

  def test_data_list_is_valid(self):
    e = validate_error_object({"code": -32601, "message": "err", "data": [1, 2, 3]})
    assert e.has_data
    assert e.data == [1, 2, 3]

  def test_to_dict_omits_data_when_absent(self):
    e = validate_error_object({"code": -32601, "message": "err"})
    assert "data" not in e.to_dict()

  def test_to_dict_includes_data_when_present(self):
    e = validate_error_object({"code": -32601, "message": "err", "data": {"k": "v"}})
    assert e.to_dict()["data"] == {"k": "v"}

  def test_to_dict_includes_data_null(self):
    e = validate_error_object({"code": -32601, "message": "err", "data": None})
    d = e.to_dict()
    assert "data" in d
    assert d["data"] is None


# ---------------------------------------------------------------------------
# AC-04.16  Receiver does not assume data structure  (R-3.8-f)
# ---------------------------------------------------------------------------

class TestErrorDataStructureNotAssumed:
  """validate_error_object accepts any data shape without raising; callers
  must not assume structure unless the specific code defines one in §22/S34."""

  @pytest.mark.parametrize("data_value", [
    {"method": "tools/list", "details": "extra"},
    [1, 2, 3],
    "plain string",
    42,
    3.14,
    True,
    False,
    None,
    {},
    [],
  ])
  def test_varied_data_shapes_accepted(self, data_value):
    e = validate_error_object({"code": -32000, "message": "err", "data": data_value})
    assert e.has_data
    assert e.data == data_value


# ---------------------------------------------------------------------------
# AC-04.17  EmptyResult MUST still set resultType  (R-3.9-a)
# ---------------------------------------------------------------------------

class TestEmptyResultSetsResultType:
  def test_empty_result_default_result_type(self):
    """Default EmptyResult sets resultType to 'complete'."""
    e = EmptyResult()
    assert e.result_type == RESULT_TYPE_COMPLETE

  def test_empty_result_to_dict_contains_result_type(self):
    e = EmptyResult()
    d = e.to_dict()
    assert "resultType" in d
    assert d["resultType"] == RESULT_TYPE_COMPLETE

  def test_parse_empty_result_valid_wire_example(self):
    raw = {"resultType": "complete"}
    e = parse_empty_result(raw)
    assert e.result_type == RESULT_TYPE_COMPLETE
    assert e.meta is None

  def test_parse_empty_result_absent_result_type_raises_strict(self):
    with pytest.raises(ValueError, match="resultType is REQUIRED"):
      parse_empty_result({})

  def test_parse_empty_result_absent_result_type_interop(self):
    e = parse_empty_result({}, interop_fallback=True)
    assert e.result_type == RESULT_TYPE_COMPLETE

  def test_empty_result_custom_result_type(self):
    """Non-default resultType is set on the object."""
    e = EmptyResult(result_type=RESULT_TYPE_INPUT_REQUIRED)
    assert e.result_type == RESULT_TYPE_INPUT_REQUIRED
    assert e.to_dict()["resultType"] == RESULT_TYPE_INPUT_REQUIRED


# ---------------------------------------------------------------------------
# AC-04.18  EmptyResult carries no members beyond base  (R-3.9-b)
# ---------------------------------------------------------------------------

class TestEmptyResultOnlyBaseMembers:
  def test_empty_result_may_carry_meta(self):
    meta = {"io.example/k": "v"}
    e = parse_empty_result({"resultType": "complete", "_meta": meta})
    assert e.meta == meta

  def test_empty_result_to_dict_includes_meta_when_set(self):
    meta = {"io.example/k": "v"}
    e = EmptyResult(meta=meta)
    d = e.to_dict()
    assert d["_meta"] == meta

  def test_empty_result_to_dict_omits_meta_when_none(self):
    e = EmptyResult()
    assert "_meta" not in e.to_dict()

  def test_parse_empty_result_rejects_extra_members(self):
    """EmptyResult must not carry method-specific members (R-3.9-b)."""
    with pytest.raises(ValueError, match="extra keys found"):
      parse_empty_result({"resultType": "complete", "tools": []})

  def test_parse_empty_result_rejects_multiple_extra_members(self):
    with pytest.raises(ValueError, match="extra keys found"):
      parse_empty_result({
        "resultType": "complete",
        "tools": [],
        "nextCursor": "tok",
      })

  def test_empty_result_to_result_has_no_extra(self):
    e = EmptyResult(meta={"io.example/k": "v"})
    r = e.to_result()
    assert r.extra == {}
    assert r.result_type == RESULT_TYPE_COMPLETE
    assert r.meta == {"io.example/k": "v"}


# ---------------------------------------------------------------------------
# Wire examples from §9 of the story
# ---------------------------------------------------------------------------

class TestWireExamples:
  def test_request_wire_example(self):
    """Wire example: request with required _meta (§3.7)."""
    raw_params = {
      "_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "ExampleClient", "version": "1.0.0"},
        "io.modelcontextprotocol/clientCapabilities": {},
      }
    }
    p = parse_request_params(raw_params)
    assert "io.modelcontextprotocol/protocolVersion" in p.meta

  def test_notification_wire_example(self):
    """Wire example: notification params without _meta (§3.7)."""
    raw_params = {"progressToken": "abc-123", "progress": 0.5}
    p = parse_notification_params(raw_params)
    assert p.meta is None
    assert p.extra["progressToken"] == "abc-123"

  def test_success_response_wire_example(self):
    """Wire example: success result with resultType and method-defined member."""
    raw_result = {"resultType": "complete", "tools": []}
    r = parse_result(raw_result)
    assert r.result_type == RESULT_TYPE_COMPLETE
    assert r.extra["tools"] == []

  def test_error_response_wire_example(self):
    """Wire example: error object with optional data."""
    raw_error = {"code": -32601, "message": "Method not found", "data": {"method": "tools/list"}}
    e = validate_error_object(raw_error)
    assert e.code == -32601
    assert e.message == "Method not found"
    assert e.data == {"method": "tools/list"}

  def test_empty_success_response_wire_example(self):
    """Wire example: EmptyResult carrying only resultType."""
    raw_result = {"resultType": "complete"}
    er = parse_empty_result(raw_result)
    assert er.result_type == RESULT_TYPE_COMPLETE
    assert er.meta is None

  def test_empty_result_wire_roundtrip(self):
    er = parse_empty_result({"resultType": "complete"})
    assert er.to_dict() == {"resultType": "complete"}
