"""Tests for S25 — Tools II: Calling, Errors, Annotations & Change Notifications.

Exercises every normative atom and acceptance criterion of the runtime half of
MCP tools (§16.5–§16.9): the ``tools/call`` request and ``CallToolResult``, the
two-layer error model (tool-execution errors vs protocol errors), the
``input_required`` retry semantics, ``ToolAnnotations``, the
``notifications/tools/list_changed`` notification, and the non-normative
stateful-tools handle pattern.

AC → test coverage map
----------------------
- AC-25.1  (R-16.5-a):                     test_ac_25_1_name_required_string
- AC-25.2  (R-16.5-b, R-16.6-e):           test_ac_25_2_unknown_tool_is_protocol_error_32602
- AC-25.3  (R-16.5-c):                     test_ac_25_3_arguments_optional_shape
- AC-25.4  (R-16.5-d, R-16.6-f):           test_ac_25_4_invalid_arguments_32602_no_invoke
- AC-25.5  (R-16.5-e):                     test_ac_25_5_omitted_arguments_default_empty
- AC-25.6  (R-16.5-f, R-16.5-g):           test_ac_25_6_retry_carries_all_input_response_keys
- AC-25.7  (R-16.5-h, R-16.5-i, R-16.5-j): test_ac_25_7_request_state_echoed_opaque
- AC-25.8  (R-16.5-k):                     test_ac_25_8_meta_accepted
- AC-25.9  (R-16.5-l, R-16.5-m):           test_ac_25_9_content_array_empty_and_mixed
- AC-25.10 (R-16.5-n):                     test_ac_25_10_structured_content_any_json
- AC-25.11 (R-16.5-o):                     test_ac_25_11_output_schema_conformance
- AC-25.12 (R-16.5-p):                     test_ac_25_12_textual_fallback_for_structured
- AC-25.13 (R-16.5-q):                     test_ac_25_13_is_error_absent_is_false
- AC-25.14 (R-16.5-r):                     test_ac_25_14_result_type_required
- AC-25.15 (R-16.5-s):                     test_ac_25_15_result_meta_accepted
- AC-25.16 (R-16.5-t):                     test_ac_25_16_input_required_then_retry
- AC-25.17 (R-16.5-u):                     test_ac_25_17_retry_id_distinct
- AC-25.18 (R-16.6-a):                     test_ac_25_18_two_layers_never_conflated
- AC-25.19 (R-16.6-b):                     test_ac_25_19_tool_execution_error_is_result
- AC-25.20 (R-16.6-c):                     test_ac_25_20_tool_error_to_model
- AC-25.21 (R-16.6-d):                     test_ac_25_21_undispatchable_is_jsonrpc_error
- AC-25.22 (R-16.6-g):                     test_ac_25_22_protocol_error_may_go_to_model
- AC-25.23 (R-16.7-a):                     test_ac_25_23_annotations_title_optional
- AC-25.24 (R-16.7-b):                     test_ac_25_24_read_only_hint_default_false
- AC-25.25 (R-16.7-c):                     test_ac_25_25_destructive_hint_default_true
- AC-25.26 (R-16.7-d):                     test_ac_25_26_idempotent_hint_default_false
- AC-25.27 (R-16.7-e):                     test_ac_25_27_open_world_hint_default_true
- AC-25.28 (R-16.7-f, R-16.7-g):           test_ac_25_28_annotations_untrusted
- AC-25.29 (R-16.8-a):                     test_ac_25_29_list_changed_notification
- AC-25.30 (R-16.8-b):                     test_ac_25_30_notification_no_payload
- AC-25.31 (R-16.8-c, R-16.8-d):           test_ac_25_31_client_reaction_invalidate_relist
- AC-25.32 (R-16.9-a):                     test_ac_25_32_handle_passed_as_argument
- AC-25.33 (R-16.9-b):                     test_ac_25_33_authorization_validated_per_call
- AC-25.34 (R-16.9-c):                     test_ac_25_34_unauth_handle_high_entropy_bounded
- AC-25.35 (R-16.9-d, R-16.9-e):           test_ac_25_35_handle_opaque_and_retention_policy
- AC-25.36 (R-16.9-f):                     test_ac_25_36_expired_handle_tool_execution_error
"""

from __future__ import annotations

import json
import uuid

import pytest

from mcp_sdk_py.content_types import (
  AudioContent,
  ImageContent,
  TextContent,
)
from mcp_sdk_py.multi_round_trip import InputRequest, InputRequiredResult
from mcp_sdk_py.result_error import (
  RESULT_TYPE_COMPLETE,
  RESULT_TYPE_INPUT_REQUIRED,
)
from mcp_sdk_py.tools import Tool
from mcp_sdk_py.tools_call import (
  DEFAULT_DESTRUCTIVE_HINT,
  DEFAULT_IDEMPOTENT_HINT,
  DEFAULT_OPEN_WORLD_HINT,
  DEFAULT_READ_ONLY_HINT,
  JSONRPC_INVALID_PARAMS,
  CallToolRequestParams,
  CallToolResult,
  InvalidToolArgumentsError,
  MalformedCallToolRequestError,
  StateHandleAuthorizationError,
  StateHandleExpiredError,
  StateHandleRegistry,
  ToolAnnotations,
  ToolCallProtocolError,
  ToolListChangedNotification,
  ToolsNotSupportedError,
  UnknownToolError,
  build_input_required_retry,
  build_structured_tool_result,
  client_may_use_annotations,
  dispatch_tool_call,
  expired_or_unknown_handle_result,
  generate_state_handle,
  is_tool_execution_error,
  on_tools_list_changed,
  provide_error_to_model,
  retry_id_is_distinct,
  structured_output_is_valid,
  tool_execution_error_result,
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _weather_tool() -> Tool:
  """A tool whose inputSchema requires a string ``location``."""
  return Tool(
    name="get_weather_data",
    input_schema={
      "type": "object",
      "properties": {"location": {"type": "string"}},
      "required": ["location"],
      "additionalProperties": False,
    },
  )


def _structured_tool() -> Tool:
  """A tool declaring an object outputSchema with a numeric ``temperature``."""
  return Tool(
    name="get_temperature",
    input_schema={"type": "object", "additionalProperties": True},
    output_schema={
      "type": "object",
      "properties": {"temperature": {"type": "number"}},
      "required": ["temperature"],
    },
  )


# ---------------------------------------------------------------------------
# AC-25.1 — name present as a string, rejected when missing/non-string
# ---------------------------------------------------------------------------

class TestAC1NameRequired:
  def test_ac_25_1_name_required_string(self) -> None:
    params = CallToolRequestParams.from_dict({"name": "do_thing"})
    assert params.name == "do_thing"

    # Missing name → malformed protocol error.
    with pytest.raises(MalformedCallToolRequestError):
      CallToolRequestParams.from_dict({"arguments": {}})

    # Non-string name → malformed protocol error.
    with pytest.raises(MalformedCallToolRequestError):
      CallToolRequestParams(name=123)  # type: ignore[arg-type]

    # Empty string is not a usable name.
    with pytest.raises(MalformedCallToolRequestError):
      CallToolRequestParams(name="")

  def test_ac_25_1_malformed_is_protocol_error(self) -> None:
    # A malformed request is the protocol layer (a JSON-RPC error), code -32602.
    err = MalformedCallToolRequestError("missing name")
    assert isinstance(err, ToolCallProtocolError)
    assert err.json_rpc_code == JSONRPC_INVALID_PARAMS


# ---------------------------------------------------------------------------
# AC-25.2 — unknown tool name → JSON-RPC error code -32602
# ---------------------------------------------------------------------------

class TestAC2UnknownTool:
  def test_ac_25_2_unknown_tool_is_protocol_error_32602(self) -> None:
    tools = {"known": _weather_tool()}
    params = CallToolRequestParams(name="not_a_tool", arguments={"location": "X"})
    with pytest.raises(UnknownToolError) as excinfo:
      dispatch_tool_call(params, {"known": tools["known"]})
    assert excinfo.value.json_rpc_code == -32602
    assert excinfo.value.tool_name == "not_a_tool"
    # The error object is a JSON-RPC error, never a CallToolResult.
    obj = excinfo.value.to_error_object()
    assert obj["code"] == -32602
    assert "message" in obj


# ---------------------------------------------------------------------------
# AC-25.3 — arguments present or absent both yield a valid request shape
# ---------------------------------------------------------------------------

class TestAC3ArgumentsOptional:
  def test_ac_25_3_arguments_optional_shape(self) -> None:
    with_args = CallToolRequestParams(name="t", arguments={"a": 1})
    assert with_args.arguments == {"a": 1}
    assert with_args.to_dict()["arguments"] == {"a": 1}

    without_args = CallToolRequestParams(name="t")
    assert without_args.arguments is None
    assert "arguments" not in without_args.to_dict()

    # Non-object arguments are rejected.
    with pytest.raises(TypeError):
      CallToolRequestParams(name="t", arguments=[1, 2])  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# AC-25.4 — arguments fail inputSchema → -32602 and tool not invoked
# ---------------------------------------------------------------------------

class TestAC4InvalidArguments:
  def test_ac_25_4_invalid_arguments_32602_no_invoke(self) -> None:
    tool = _weather_tool()
    invoked = False

    def run_tool() -> None:
      nonlocal invoked
      invoked = True

    # location must be a string and is required; this omits it.
    params = CallToolRequestParams(name="get_weather_data", arguments={"wrong": 1})
    with pytest.raises(InvalidToolArgumentsError) as excinfo:
      dispatch_tool_call(params, {"get_weather_data": tool})
      run_tool()  # only reached if dispatch succeeds (it does not)
    assert excinfo.value.json_rpc_code == -32602
    # The tool was never invoked because dispatch raised first.
    assert invoked is False

  def test_ac_25_4_valid_arguments_dispatch_succeeds(self) -> None:
    tool = _weather_tool()
    params = CallToolRequestParams(
      name="get_weather_data", arguments={"location": "New York"}
    )
    resolved = dispatch_tool_call(params, {"get_weather_data": tool})
    assert resolved is tool


# ---------------------------------------------------------------------------
# AC-25.5 — omitted arguments treated as {}
# ---------------------------------------------------------------------------

class TestAC5OmittedArgumentsDefault:
  def test_ac_25_5_omitted_arguments_default_empty(self) -> None:
    params = CallToolRequestParams(name="no_params")
    assert params.effective_arguments == {}

    # A tool that accepts an empty object dispatches with no explicit arguments.
    tool = Tool(
      name="no_params",
      input_schema={"type": "object", "additionalProperties": False},
    )
    resolved = dispatch_tool_call(params, {"no_params": tool})
    assert resolved is tool


# ---------------------------------------------------------------------------
# AC-25.6 — retry carries every prior inputRequests key in inputResponses
# ---------------------------------------------------------------------------

class TestAC6RetryInputResponses:
  def test_ac_25_6_retry_carries_all_input_response_keys(self) -> None:
    original = CallToolRequestParams(name="book_flight", arguments={"from": "A"})
    prior = InputRequiredResult(
      input_requests={
        "seat_class": InputRequest(method="elicitation/create"),
        "meal": InputRequest(method="elicitation/create"),
      },
      request_state="opaque-token",
    )
    retry = build_input_required_retry(
      original,
      prior,
      {"seat_class": {"action": "accept"}, "meal": {"action": "accept"}},
    )
    assert set(retry.input_responses) == {"seat_class", "meal"}
    assert retry.name == "book_flight"

  def test_ac_25_6_missing_key_rejected(self) -> None:
    original = CallToolRequestParams(name="book_flight")
    prior = InputRequiredResult(
      input_requests={"seat_class": InputRequest(method="elicitation/create")},
      request_state="tok",
    )
    # Omitting the answer for "seat_class" violates R-16.5-g.
    with pytest.raises(ValueError):
      build_input_required_retry(original, prior, {})


# ---------------------------------------------------------------------------
# AC-25.7 — requestState echoed byte-for-byte, never parsed/mutated
# ---------------------------------------------------------------------------

class TestAC7RequestStateOpaque:
  def test_ac_25_7_request_state_echoed_opaque(self) -> None:
    token = "opaque-continuation-token-from-server"
    original = CallToolRequestParams(name="book_flight")
    prior = InputRequiredResult(
      input_requests={"k": InputRequest(method="elicitation/create")},
      request_state=token,
    )
    retry = build_input_required_retry(original, prior, {"k": {"action": "accept"}})
    # Echoed byte-for-byte, unchanged.
    assert retry.request_state == token
    assert retry.request_state is token  # not copied/derived
    # On the wire the same bytes appear.
    assert retry.to_dict()["requestState"] == token

  def test_ac_25_7_non_string_request_state_rejected(self) -> None:
    with pytest.raises(TypeError):
      CallToolRequestParams(name="t", request_state=123)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# AC-25.8 — _meta (e.g. progressToken) accepted; request stays valid
# ---------------------------------------------------------------------------

class TestAC8MetaAccepted:
  def test_ac_25_8_meta_accepted(self) -> None:
    params = CallToolRequestParams(
      name="t", arguments={}, meta={"progressToken": "p-1"}
    )
    assert params.meta == {"progressToken": "p-1"}
    assert params.to_dict()["_meta"] == {"progressToken": "p-1"}
    # Round-trips through from_dict.
    parsed = CallToolRequestParams.from_dict(params.to_dict())
    assert parsed.meta == {"progressToken": "p-1"}

  def test_ac_25_8_non_object_meta_rejected(self) -> None:
    with pytest.raises(TypeError):
      CallToolRequestParams(name="t", meta="nope")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# AC-25.9 — content present as array; empty and mixed-type accepted
# ---------------------------------------------------------------------------

class TestAC9Content:
  def test_ac_25_9_content_array_empty_and_mixed(self) -> None:
    # Empty content array is accepted (R-16.5-m).
    empty = CallToolResult(content=[])
    assert empty.content == []
    assert empty.to_dict()["content"] == []

    # Mixed block types are accepted.
    mixed = CallToolResult(
      content=[
        TextContent(text="hello"),
        ImageContent(data="aGk=", mime_type="image/png"),
        AudioContent(data="aGk=", mime_type="audio/wav"),
      ]
    )
    serialized = mixed.to_dict()["content"]
    assert [b["type"] for b in serialized] == ["text", "image", "audio"]

  def test_ac_25_9_content_required(self) -> None:
    with pytest.raises(ValueError):
      CallToolResult.from_dict({"resultType": "complete"})
    with pytest.raises(TypeError):
      CallToolResult(content="not a list")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# AC-25.10 — structuredContent may be ANY JSON value
# ---------------------------------------------------------------------------

class TestAC10StructuredAnyJson:
  @pytest.mark.parametrize(
    "value",
    [
      {"k": "v"},
      [1, 2, 3],
      "a string",
      42,
      3.14,
      True,
      None,
    ],
  )
  def test_ac_25_10_structured_content_any_json(self, value: object) -> None:
    result = CallToolResult(content=[], structured_content=value)
    assert result.has_structured_content is True
    assert result.to_dict()["structuredContent"] == value

  def test_ac_25_10_absent_vs_explicit_null(self) -> None:
    absent = CallToolResult(content=[])
    assert absent.has_structured_content is False
    assert "structuredContent" not in absent.to_dict()

    explicit_null = CallToolResult(content=[], structured_content=None)
    assert explicit_null.has_structured_content is True
    assert explicit_null.to_dict()["structuredContent"] is None


# ---------------------------------------------------------------------------
# AC-25.11 — declared outputSchema: structuredContent present and conforms
# ---------------------------------------------------------------------------

class TestAC11OutputSchemaConformance:
  def test_ac_25_11_output_schema_conformance(self) -> None:
    tool = _structured_tool()
    good = CallToolResult(content=[], structured_content={"temperature": 22.5})
    assert structured_output_is_valid(tool, good) is True

    # Non-conforming (wrong type) fails.
    bad = CallToolResult(content=[], structured_content={"temperature": "warm"})
    assert structured_output_is_valid(tool, bad) is False

    # Absent structuredContent when an outputSchema is declared fails.
    missing = CallToolResult(content=[TextContent(text="x")])
    assert structured_output_is_valid(tool, missing) is False

  def test_ac_25_11_no_output_schema_always_valid(self) -> None:
    tool = _weather_tool()  # no outputSchema
    assert structured_output_is_valid(tool, CallToolResult(content=[])) is True

  def test_ac_25_11_builder_rejects_nonconforming(self) -> None:
    tool = _structured_tool()
    with pytest.raises(ValueError):
      build_structured_tool_result(tool, {"temperature": "warm"})


# ---------------------------------------------------------------------------
# AC-25.12 — textual content fallback accompanies structured output
# ---------------------------------------------------------------------------

class TestAC12TextualFallback:
  def test_ac_25_12_textual_fallback_for_structured(self) -> None:
    tool = _structured_tool()
    structured = {"temperature": 22.5}
    result = build_structured_tool_result(tool, structured)
    assert result.has_structured_content
    assert result.structured_content == structured
    # A text block carries the serialized fallback.
    assert len(result.content) >= 1
    text_block = result.content[0]
    assert isinstance(text_block, TextContent)
    assert json.loads(text_block.text) == structured


# ---------------------------------------------------------------------------
# AC-25.13 — isError absent ⇒ false (success)
# ---------------------------------------------------------------------------

class TestAC13IsErrorDefault:
  def test_ac_25_13_is_error_absent_is_false(self) -> None:
    result = CallToolResult.from_dict(
      {"resultType": "complete", "content": [{"type": "text", "text": "ok"}]}
    )
    assert result.is_error is None
    assert result.ended_in_error is False
    # An explicit false also reads as success.
    explicit = CallToolResult(content=[], is_error=False)
    assert explicit.ended_in_error is False

  def test_ac_25_13_is_error_true_is_error(self) -> None:
    result = CallToolResult(content=[], is_error=True)
    assert result.ended_in_error is True


# ---------------------------------------------------------------------------
# AC-25.14 — resultType required; complete vs input_required; absence fails
# ---------------------------------------------------------------------------

class TestAC14ResultType:
  def test_ac_25_14_result_type_required(self) -> None:
    complete = CallToolResult(content=[], result_type=RESULT_TYPE_COMPLETE)
    assert complete.result_type == "complete"
    paused = CallToolResult(content=[], result_type=RESULT_TYPE_INPUT_REQUIRED)
    assert paused.result_type == "input_required"

    # Absence fails validation on parse.
    with pytest.raises(ValueError):
      CallToolResult.from_dict({"content": []})

    # A bogus discriminator value is rejected.
    with pytest.raises(ValueError):
      CallToolResult(content=[], result_type="bogus")


# ---------------------------------------------------------------------------
# AC-25.15 — result _meta accepted
# ---------------------------------------------------------------------------

class TestAC15ResultMeta:
  def test_ac_25_15_result_meta_accepted(self) -> None:
    result = CallToolResult(content=[], meta={"trace": "abc"})
    assert result.to_dict()["_meta"] == {"trace": "abc"}
    parsed = CallToolResult.from_dict(result.to_dict())
    assert parsed.meta == {"trace": "abc"}

  def test_ac_25_15_non_object_meta_rejected(self) -> None:
    with pytest.raises(TypeError):
      CallToolResult(content=[], meta=5)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# AC-25.16 — input_required result then retry with responses + state
# ---------------------------------------------------------------------------

class TestAC16InputRequiredRetry:
  def test_ac_25_16_input_required_then_retry(self) -> None:
    # The server returns an input_required CallToolResult.
    paused = CallToolResult(
      content=[],
      result_type=RESULT_TYPE_INPUT_REQUIRED,
    )
    assert paused.result_type == "input_required"

    # The S17 InputRequiredResult carries inputRequests and/or requestState.
    prior = InputRequiredResult(
      input_requests={"seat_class": InputRequest(method="elicitation/create")},
      request_state="state-1",
    )
    original = CallToolRequestParams(name="book_flight", arguments={"from": "A"})
    retry = build_input_required_retry(
      original, prior, {"seat_class": {"action": "accept"}}
    )
    assert retry.is_retry is True
    assert retry.input_responses == {"seat_class": {"action": "accept"}}
    assert retry.request_state == "state-1"


# ---------------------------------------------------------------------------
# AC-25.17 — retry JSON-RPC id differs from initial id
# ---------------------------------------------------------------------------

class TestAC17RetryIdDistinct:
  def test_ac_25_17_retry_id_distinct(self) -> None:
    assert retry_id_is_distinct(5, 6) is True
    assert retry_id_is_distinct(5, 5) is False
    # String vs number ids are distinct.
    assert retry_id_is_distinct("5", 5) is True


# ---------------------------------------------------------------------------
# AC-25.18 — the two error layers are never conflated
# ---------------------------------------------------------------------------

class TestAC18TwoLayers:
  def test_ac_25_18_two_layers_never_conflated(self) -> None:
    # Layer 1: tool-execution error → a SUCCESSFUL result with isError true.
    exec_error = tool_execution_error_result("the tool failed")
    assert isinstance(exec_error, CallToolResult)
    assert exec_error.ended_in_error is True
    assert is_tool_execution_error(exec_error) is True

    # Layer 2: protocol error → an exception (a JSON-RPC error), NOT a result.
    proto = UnknownToolError("nope")
    assert isinstance(proto, ToolCallProtocolError)
    assert not isinstance(proto, CallToolResult)
    # The protocol error renders to a JSON-RPC error object, never a result.
    assert "code" in proto.to_error_object()


# ---------------------------------------------------------------------------
# AC-25.19 — tool execution failure → result with isError true + explanation
# ---------------------------------------------------------------------------

class TestAC19ToolExecutionError:
  def test_ac_25_19_tool_execution_error_is_result(self) -> None:
    result = tool_execution_error_result(
      "Invalid departure date: must be in the future."
    )
    assert isinstance(result, CallToolResult)
    assert result.result_type == "complete"
    assert result.is_error is True
    # A human-/model-readable explanation is in content.
    assert isinstance(result.content[0], TextContent)
    assert "departure date" in result.content[0].text


# ---------------------------------------------------------------------------
# AC-25.20 — client provides tool-execution errors to the model
# ---------------------------------------------------------------------------

class TestAC20ErrorToModel:
  def test_ac_25_20_tool_error_to_model(self) -> None:
    # A tool-execution error SHOULD be provided to the model (R-16.6-c).
    assert provide_error_to_model(is_tool_execution_error=True) is True


# ---------------------------------------------------------------------------
# AC-25.21 — undispatchable requests are JSON-RPC errors, never results
# ---------------------------------------------------------------------------

class TestAC21UndispatchableErrors:
  def test_ac_25_21_undispatchable_is_jsonrpc_error(self) -> None:
    tools = {"known": _weather_tool()}

    # Unknown tool.
    with pytest.raises(UnknownToolError):
      dispatch_tool_call(CallToolRequestParams(name="x"), {})

    # Invalid arguments.
    with pytest.raises(InvalidToolArgumentsError):
      dispatch_tool_call(
        CallToolRequestParams(name="known", arguments={"bad": 1}), tools
      )

    # Server does not support tools.
    with pytest.raises(ToolsNotSupportedError):
      dispatch_tool_call(
        CallToolRequestParams(name="known", arguments={"location": "X"}),
        tools,
        tools_supported=False,
      )

    # All of these are protocol errors (exceptions), never CallToolResults.
    for exc_cls in (UnknownToolError, InvalidToolArgumentsError, ToolsNotSupportedError):
      assert issubclass(exc_cls, ToolCallProtocolError)


# ---------------------------------------------------------------------------
# AC-25.22 — protocol error MAY be passed to the model
# ---------------------------------------------------------------------------

class TestAC22ProtocolErrorToModel:
  def test_ac_25_22_protocol_error_may_go_to_model(self) -> None:
    # The MAY permission is modelled: a client may surface protocol errors.
    assert provide_error_to_model(is_tool_execution_error=False) is True


# ---------------------------------------------------------------------------
# AC-25.23 — annotations.title optional, ranks after tool.title, before name
# ---------------------------------------------------------------------------

class TestAC23AnnotationsTitle:
  def test_ac_25_23_annotations_title_optional(self) -> None:
    # title optional.
    assert ToolAnnotations().title is None
    ann = ToolAnnotations(title="Web Search")
    assert ann.title == "Web Search"
    assert ann.to_dict()["title"] == "Web Search"

  def test_ac_25_23_display_precedence_after_title_before_name(self) -> None:
    # tool.title beats annotations.title.
    t1 = Tool(
      name="web_search",
      input_schema={"type": "object"},
      title="Real Title",
      annotations=ToolAnnotations(title="Annotation Title").to_dict(),
    )
    assert t1.display_name() == "Real Title"
    # annotations.title beats name when tool.title absent.
    t2 = Tool(
      name="web_search",
      input_schema={"type": "object"},
      annotations=ToolAnnotations(title="Annotation Title").to_dict(),
    )
    assert t2.display_name() == "Annotation Title"
    # name is used when neither title is present.
    t3 = Tool(name="web_search", input_schema={"type": "object"})
    assert t3.display_name() == "web_search"

  def test_ac_25_23_non_string_title_rejected(self) -> None:
    with pytest.raises(TypeError):
      ToolAnnotations(title=5)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# AC-25.24 — readOnlyHint default false
# ---------------------------------------------------------------------------

class TestAC24ReadOnlyHint:
  def test_ac_25_24_read_only_hint_default_false(self) -> None:
    assert DEFAULT_READ_ONLY_HINT is False
    assert ToolAnnotations().effective_read_only_hint is False
    assert ToolAnnotations(read_only_hint=True).effective_read_only_hint is True
    # absent on the wire when not set.
    assert "readOnlyHint" not in ToolAnnotations().to_dict()


# ---------------------------------------------------------------------------
# AC-25.25 — destructiveHint default true, meaningful only when not read-only
# ---------------------------------------------------------------------------

class TestAC25DestructiveHint:
  def test_ac_25_25_destructive_hint_default_true(self) -> None:
    assert DEFAULT_DESTRUCTIVE_HINT is True
    assert ToolAnnotations().effective_destructive_hint is True
    assert ToolAnnotations(destructive_hint=False).effective_destructive_hint is False

  def test_ac_25_25_meaningful_only_when_not_read_only(self) -> None:
    not_ro = ToolAnnotations(read_only_hint=False)
    assert not_ro.destructive_hint_is_meaningful is True
    ro = ToolAnnotations(read_only_hint=True)
    assert ro.destructive_hint_is_meaningful is False


# ---------------------------------------------------------------------------
# AC-25.26 — idempotentHint default false, meaningful only when not read-only
# ---------------------------------------------------------------------------

class TestAC26IdempotentHint:
  def test_ac_25_26_idempotent_hint_default_false(self) -> None:
    assert DEFAULT_IDEMPOTENT_HINT is False
    assert ToolAnnotations().effective_idempotent_hint is False
    assert ToolAnnotations(idempotent_hint=True).effective_idempotent_hint is True

  def test_ac_25_26_meaningful_only_when_not_read_only(self) -> None:
    assert ToolAnnotations(read_only_hint=False).idempotent_hint_is_meaningful is True
    assert ToolAnnotations(read_only_hint=True).idempotent_hint_is_meaningful is False


# ---------------------------------------------------------------------------
# AC-25.27 — openWorldHint default true
# ---------------------------------------------------------------------------

class TestAC27OpenWorldHint:
  def test_ac_25_27_open_world_hint_default_true(self) -> None:
    assert DEFAULT_OPEN_WORLD_HINT is True
    assert ToolAnnotations().effective_open_world_hint is True
    assert ToolAnnotations(open_world_hint=False).effective_open_world_hint is False

  def test_ac_25_27_round_trip(self) -> None:
    ann = ToolAnnotations(
      title="Web Search", read_only_hint=True, open_world_hint=True
    )
    parsed = ToolAnnotations.from_dict(ann.to_dict())
    assert parsed.title == "Web Search"
    assert parsed.read_only_hint is True
    assert parsed.open_world_hint is True


# ---------------------------------------------------------------------------
# AC-25.28 — annotations are untrusted; no safety decisions from untrusted server
# ---------------------------------------------------------------------------

class TestAC28AnnotationsUntrusted:
  def test_ac_25_28_annotations_untrusted(self) -> None:
    # From an untrusted server, annotations MUST NOT drive tool-use/safety choices.
    assert client_may_use_annotations(server_is_trusted=False) is False
    # From a trusted server the client may rely on them.
    assert client_may_use_annotations(server_is_trusted=True) is True


# ---------------------------------------------------------------------------
# AC-25.29 — server with listChanged:true sends notifications/tools/list_changed
# ---------------------------------------------------------------------------

class TestAC29ListChangedNotification:
  def test_ac_25_29_list_changed_notification(self) -> None:
    note = ToolListChangedNotification()
    assert note.method == "notifications/tools/list_changed"
    assert note.to_dict() == {"method": "notifications/tools/list_changed"}

  def test_ac_25_29_wrong_method_rejected(self) -> None:
    with pytest.raises(ValueError):
      ToolListChangedNotification.from_dict({"method": "notifications/other"})


# ---------------------------------------------------------------------------
# AC-25.30 — notification needs no payload; no prior subscription required
# ---------------------------------------------------------------------------

class TestAC30NotificationNoPayload:
  def test_ac_25_30_notification_no_payload(self) -> None:
    # No params at all is valid.
    bare = ToolListChangedNotification.from_dict(
      {"method": "notifications/tools/list_changed"}
    )
    assert bare.params is None
    assert "params" not in bare.to_dict()

    # Optional params (with _meta and arbitrary keys) are also accepted.
    with_params = ToolListChangedNotification(params={"_meta": {"x": 1}, "extra": 2})
    assert with_params.to_dict()["params"] == {"_meta": {"x": 1}, "extra": 2}

  def test_ac_25_30_non_object_params_rejected(self) -> None:
    with pytest.raises(TypeError):
      ToolListChangedNotification(params=[1])  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# AC-25.31 — client invalidates cache and may re-list
# ---------------------------------------------------------------------------

class TestAC31ClientReaction:
  def test_ac_25_31_client_reaction_invalidate_relist(self) -> None:
    # SHOULD invalidate cache.
    reaction = on_tools_list_changed()
    assert reaction.cache_invalidated is True
    assert reaction.should_relist is False

    # MAY re-list.
    relisting = on_tools_list_changed(relist=True)
    assert relisting.cache_invalidated is True
    assert relisting.should_relist is True


# ---------------------------------------------------------------------------
# AC-25.32 — handle returned from creation tool, passed as later argument
# ---------------------------------------------------------------------------

class TestAC32HandleAsArgument:
  def test_ac_25_32_handle_passed_as_argument(self) -> None:
    registry = StateHandleRegistry()
    handle = registry.issue(payload={"cart": []})
    # The handle is an ordinary string returned from a creation tool...
    assert isinstance(handle.value, str)
    # ...and passed back as an ordinary argument on a later call.
    later = CallToolRequestParams(
      name="add_to_cart", arguments={"handle": handle.value, "item": "x"}
    )
    resolved = registry.resolve(later.arguments["handle"])
    assert resolved.payload == {"cart": []}


# ---------------------------------------------------------------------------
# AC-25.33 — authenticated server validates authorization on every call
# ---------------------------------------------------------------------------

class TestAC33AuthorizationPerCall:
  def test_ac_25_33_authorization_validated_per_call(self) -> None:
    registry = StateHandleRegistry()
    handle = registry.issue(owner="alice", payload={"tx": 1})

    # The rightful owner resolves the handle every time.
    assert registry.resolve(handle.value, caller="alice").payload == {"tx": 1}
    assert registry.resolve(handle.value, caller="alice").payload == {"tx": 1}

    # A different caller is rejected on every call.
    with pytest.raises(StateHandleAuthorizationError):
      registry.resolve(handle.value, caller="mallory")


# ---------------------------------------------------------------------------
# AC-25.34 — unauthenticated handle is high-entropy bearer token, bounded life
# ---------------------------------------------------------------------------

class TestAC34UnauthHandleEntropyBounded:
  def test_ac_25_34_unauth_handle_high_entropy_bounded(self) -> None:
    # High entropy: generate_state_handle returns a parseable UUIDv4.
    value = generate_state_handle()
    parsed = uuid.UUID(value)
    assert parsed.version == 4
    # Distinct each time.
    assert generate_state_handle() != generate_state_handle()

    # Bounded lifetime: a TTL'd handle expires.
    registry = StateHandleRegistry()
    handle = registry.issue(ttl_seconds=10.0, now=100.0)
    assert handle.is_expired(now=109.0) is False
    assert handle.is_expired(now=110.0) is True


# ---------------------------------------------------------------------------
# AC-25.35 — handle opaque; retention policy stated in creation tool description
# ---------------------------------------------------------------------------

class TestAC35HandleOpaqueRetention:
  def test_ac_25_35_handle_opaque_and_retention_policy(self) -> None:
    # Opaque: a UUIDv4 carries no parseable structure beyond being a UUID.
    handle = generate_state_handle()
    assert "-" in handle and len(handle) == 36  # canonical UUID form, no app data

    # Retention policy SHOULD be stated in the creation tool's description so the
    # model can see it (R-16.9-e).
    creation_tool = Tool(
      name="open_cart",
      input_schema={"type": "object", "additionalProperties": False},
      description=(
        "Opens a shopping cart and returns an opaque handle. Retention policy: "
        "the handle expires 15 minutes after the last call."
      ),
    )
    assert "Retention policy" in (creation_tool.description or "")


# ---------------------------------------------------------------------------
# AC-25.36 — expired/unknown handle → tool execution error (not protocol error)
# ---------------------------------------------------------------------------

class TestAC36ExpiredHandle:
  def test_ac_25_36_expired_handle_tool_execution_error(self) -> None:
    registry = StateHandleRegistry()
    handle = registry.issue(ttl_seconds=5.0, now=0.0)

    # Resolving an expired handle raises the internal signal...
    with pytest.raises(StateHandleExpiredError):
      registry.resolve(handle.value, now=10.0)

    # An unknown handle likewise.
    with pytest.raises(StateHandleExpiredError):
      registry.resolve("never-issued")

    # ...which the server reports as a tool-EXECUTION error (a result with
    # isError true), NOT a JSON-RPC protocol error (R-16.9-f, §16.6).
    result = expired_or_unknown_handle_result()
    assert isinstance(result, CallToolResult)
    assert result.is_error is True
    assert result.result_type == "complete"
    assert isinstance(result.content[0], TextContent)
    assert "expired or unknown" in result.content[0].text
