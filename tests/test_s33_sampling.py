"""Tests for S33 — Sampling (Deprecated).

Each test class maps to one or more acceptance criteria (AC-33.x) from the
story. The capability is Deprecated; these tests verify the SDK still *accepts*
``sampling/createMessage`` and its data shapes for interoperability while
honoring every normative rule.

AC → test coverage map:
  AC-33.1  Deprecated posture (not adopted; interoperability only) → TestAC1DeprecationPosture
  AC-33.2  Migration guidance toward direct provider integration   → TestAC2MigrationGuidance
  AC-33.3  Tool-use gating: server omits / client errors           → TestAC3ToolUseGating
  AC-33.4  includeContext omitted/"none" without sampling.context  → TestAC4IncludeContextGating
  AC-33.5  messages + maxTokens required; ordered oldest-to-newest → TestAC5RequiredFields
  AC-33.6  message list not retained across requests               → TestAC6NoMessageRetention
  AC-33.7  advisory fields may be ignored/modified silently        → TestAC7AdvisoryFields
  AC-33.8  includeContext may be modified/ignored silently         → TestAC8IncludeContextClientControl
  AC-33.9  maxTokens upper bound (may produce fewer, never more)   → TestAC9MaxTokens
  AC-33.10 tools scoped to request; need not be registered tools   → TestAC10ToolsScoped
  AC-33.11 omitted toolChoice ⇒ {"mode":"auto"}                    → TestAC11ToolChoiceDefault
  AC-33.12 toolChoice modes required / none                        → TestAC12ToolChoiceModes
  AC-33.13 SamplingMessage role + content required                 → TestAC13SamplingMessage
  AC-33.14 _meta of ToolUse/ToolResult preserved                   → TestAC14MetaPreservation
  AC-33.15 toolUseId matches a prior tool use id                   → TestAC15ToolUseIdMatch
  AC-33.16 ToolResultContent content/structured/isError            → TestAC16ToolResultContent
  AC-33.17 user tool_result message holds only tool_result blocks  → TestAC17ToolResultExclusivity
  AC-33.18 assistant tool_use ⇒ immediate user tool_result         → TestAC18ToolUseOrdering
  AC-33.19 CreateMessageResult required fields                     → TestAC19ResultRequiredFields
  AC-33.20 non-standard stopReason accepted (open string)          → TestAC20OpenStopReason
  AC-33.21 hints evaluated in order, first match; advisory         → TestAC21ModelPreferences
  AC-33.22 priorities optional numbers in 0..1; lenient handling   → TestAC22Priorities
  AC-33.23 ModelHint.name substring; mappable                      → TestAC23ModelHint
  AC-33.24 human-in-the-loop / deny / review prompt & result       → TestAC24Consent
  AC-33.25 rate limiting / content validation / iteration limits   → TestAC25SafetyControls
"""

import pytest

from mcp_sdk_py.capabilities import ClientCapabilities
from mcp_sdk_py.content_types import AudioContent, ImageContent, TextContent
from mcp_sdk_py.sampling import (
  SAMPLING_CREATE_MESSAGE_METHOD,
  SAMPLING_IS_DEPRECATED,
  SAMPLING_MIGRATION_GUIDANCE,
  STANDARD_STOP_REASONS,
  ClientSamplingCapability,
  ConsentDecision,
  CreateMessageRequestParams,
  CreateMessageResult,
  HumanInTheLoop,
  IncludeContext,
  MalformedSamplingRequestError,
  MalformedSamplingResultError,
  ModelHint,
  ModelPreferences,
  RateLimiter,
  SamplingDeniedError,
  SamplingMessage,
  SamplingToolsNotDeclaredError,
  ToolChoice,
  ToolChoiceMode,
  ToolResultContent,
  ToolUseContent,
  assert_tool_use_allowed,
  capability_supports_context,
  capability_supports_tools,
  clamp_max_tokens,
  hint_matches,
  sanitize_include_context,
  select_model,
  server_may_send_tool_request,
  validate_message_content,
  validate_tool_result_references,
  validate_tool_use_ordering,
  within_iteration_limit,
)

_PNG_B64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
_WAV_B64 = "UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQAAAAA="


def _text_msg(role: str, text: str) -> SamplingMessage:
  return SamplingMessage(role=role, content=[TextContent(text=text)])


def _simple_params(**overrides) -> CreateMessageRequestParams:
  base = dict(
    messages=[_text_msg("user", "hi")],
    max_tokens=100,
  )
  base.update(overrides)
  return CreateMessageRequestParams(**base)


# ---------------------------------------------------------------------------
# AC-33.1 — Deprecated posture (R-21.2-a, R-21.2.1-a)
# ---------------------------------------------------------------------------

class TestAC1DeprecationPosture:
  def test_module_flags_sampling_as_deprecated(self):
    assert SAMPLING_IS_DEPRECATED is True

  def test_capability_docstring_marks_deprecated(self):
    # The capability remains defined for interoperability; the dataclass exists
    # and round-trips, but the module surfaces the deprecation signal.
    assert "Deprecated" in (ClientSamplingCapability.__doc__ or "")

  def test_capability_still_accepted_for_interoperability(self):
    # Despite deprecation it MUST still be parseable for interop.
    cap = ClientSamplingCapability.from_dict({})
    assert isinstance(cap, ClientSamplingCapability)

  def test_method_name_is_recognized_input_request(self):
    assert SAMPLING_CREATE_MESSAGE_METHOD == "sampling/createMessage"


# ---------------------------------------------------------------------------
# AC-33.2 — Migration guidance (R-21.2.1-b)
# ---------------------------------------------------------------------------

class TestAC2MigrationGuidance:
  def test_migration_guidance_points_to_model_provider(self):
    assert "provider" in SAMPLING_MIGRATION_GUIDANCE.lower()

  def test_migration_guidance_is_non_empty_string(self):
    assert isinstance(SAMPLING_MIGRATION_GUIDANCE, str)
    assert SAMPLING_MIGRATION_GUIDANCE


# ---------------------------------------------------------------------------
# AC-33.3 — Tool-use gating (R-21.2.3-a/b, R-21.2.4-n/o)
# ---------------------------------------------------------------------------

class TestAC3ToolUseGating:
  def test_server_must_not_send_tool_request_without_sampling_tools(self):
    caps = ClientCapabilities(sampling={})  # declared sampling, no tools
    assert server_may_send_tool_request(caps) is False

  def test_server_may_send_tool_request_with_sampling_tools(self):
    caps = ClientCapabilities(sampling={"tools": {}})
    assert server_may_send_tool_request(caps) is True

  def test_client_errors_on_tools_without_sampling_tools(self):
    params = _simple_params(tools=[{"name": "t", "inputSchema": {}}])
    caps = ClientCapabilities(sampling={})
    with pytest.raises(SamplingToolsNotDeclaredError) as exc:
      assert_tool_use_allowed(params, caps)
    assert "tools" in exc.value.fields

  def test_client_errors_on_tool_choice_without_sampling_tools(self):
    params = _simple_params(tool_choice=ToolChoice(mode=ToolChoiceMode.AUTO))
    caps = ClientCapabilities(sampling={})
    with pytest.raises(SamplingToolsNotDeclaredError) as exc:
      assert_tool_use_allowed(params, caps)
    assert "toolChoice" in exc.value.fields

  def test_client_accepts_tools_when_sampling_tools_declared(self):
    params = _simple_params(tools=[{"name": "t", "inputSchema": {}}])
    caps = ClientCapabilities(sampling={"tools": {}})
    # No error.
    assert_tool_use_allowed(params, caps)

  def test_gate_accepts_raw_dict_and_bool(self):
    params = _simple_params(tools=[{"name": "t", "inputSchema": {}}])
    with pytest.raises(SamplingToolsNotDeclaredError):
      assert_tool_use_allowed(params, {"sampling": {}})
    assert_tool_use_allowed(params, {"sampling": {"tools": {}}})
    assert_tool_use_allowed(params, True)
    with pytest.raises(SamplingToolsNotDeclaredError):
      assert_tool_use_allowed(params, False)

  def test_no_tool_fields_never_errors(self):
    params = _simple_params()
    assert_tool_use_allowed(params, ClientCapabilities(sampling={}))


# ---------------------------------------------------------------------------
# AC-33.4 — includeContext gating (R-21.2.3-c, R-21.2.4-e)
# ---------------------------------------------------------------------------

class TestAC4IncludeContextGating:
  def test_deprecated_value_downgraded_without_context(self):
    out = sanitize_include_context(
      IncludeContext.THIS_SERVER, client_supports_context=False
    )
    assert out is IncludeContext.NONE

  def test_all_servers_downgraded_without_context(self):
    out = sanitize_include_context(
      "allServers", client_supports_context=False
    )
    assert out is IncludeContext.NONE

  def test_deprecated_value_kept_when_context_declared(self):
    out = sanitize_include_context(
      IncludeContext.THIS_SERVER, client_supports_context=True
    )
    assert out is IncludeContext.THIS_SERVER

  def test_none_value_passes_through(self):
    out = sanitize_include_context(IncludeContext.NONE, client_supports_context=False)
    assert out is IncludeContext.NONE

  def test_omitted_field_stays_omitted(self):
    assert sanitize_include_context(None, client_supports_context=False) is None

  def test_capability_helpers_detect_context_subflag(self):
    assert capability_supports_context({"context": {}}) is True
    assert capability_supports_context({}) is False

  def test_deprecated_values_flagged(self):
    assert IncludeContext.THIS_SERVER.is_deprecated is True
    assert IncludeContext.ALL_SERVERS.is_deprecated is True
    assert IncludeContext.NONE.is_deprecated is False


# ---------------------------------------------------------------------------
# AC-33.5 — messages + maxTokens required (R-21.2.4-a, R-21.2.4-h)
# ---------------------------------------------------------------------------

class TestAC5RequiredFields:
  def test_missing_messages_rejected(self):
    with pytest.raises(MalformedSamplingRequestError):
      CreateMessageRequestParams.from_dict({"maxTokens": 100})

  def test_missing_max_tokens_rejected(self):
    with pytest.raises(MalformedSamplingRequestError):
      CreateMessageRequestParams.from_dict(
        {"messages": [{"role": "user", "content": {"type": "text", "text": "x"}}]}
      )

  def test_empty_messages_rejected(self):
    with pytest.raises(MalformedSamplingRequestError):
      CreateMessageRequestParams(messages=[], max_tokens=100)

  def test_messages_preserve_oldest_to_newest_order(self):
    params = CreateMessageRequestParams.from_dict(
      {
        "messages": [
          {"role": "user", "content": {"type": "text", "text": "first"}},
          {"role": "assistant", "content": {"type": "text", "text": "second"}},
          {"role": "user", "content": {"type": "text", "text": "third"}},
        ],
        "maxTokens": 100,
      }
    )
    texts = [m.content[0].text for m in params.messages]
    assert texts == ["first", "second", "third"]

  def test_valid_request_round_trips(self):
    raw = {
      "messages": [{"role": "user", "content": {"type": "text", "text": "hi"}}],
      "maxTokens": 100,
    }
    params = CreateMessageRequestParams.from_dict(raw)
    assert params.max_tokens == 100
    out = params.to_dict()
    assert out["maxTokens"] == 100
    assert out["messages"][0]["role"] == "user"

  def test_non_numeric_max_tokens_rejected(self):
    with pytest.raises(MalformedSamplingRequestError):
      CreateMessageRequestParams(messages=[_text_msg("user", "x")], max_tokens="big")


# ---------------------------------------------------------------------------
# AC-33.6 — message list not retained across requests (R-21.2.4-b)
# ---------------------------------------------------------------------------

class TestAC6NoMessageRetention:
  def test_each_request_carries_its_own_messages(self):
    first = _simple_params(messages=[_text_msg("user", "one")])
    second = _simple_params(messages=[_text_msg("user", "two")])
    assert [m.content[0].text for m in first.messages] == ["one"]
    assert [m.content[0].text for m in second.messages] == ["two"]
    # No shared list identity between independent requests.
    assert first.messages is not second.messages

  def test_default_factory_does_not_share_state(self):
    a = _simple_params()
    b = _simple_params()
    a.messages.append(_text_msg("user", "leak"))
    assert len(b.messages) == 1


# ---------------------------------------------------------------------------
# AC-33.7 — advisory fields may be ignored/modified silently
#           (R-21.2.4-c/d/g/k/l)
# ---------------------------------------------------------------------------

class TestAC7AdvisoryFields:
  def test_advisory_fields_round_trip(self):
    params = _simple_params(
      model_preferences=ModelPreferences(cost_priority=0.5),
      system_prompt="be brief",
      temperature=0.2,
      stop_sequences=["STOP"],
      metadata={"provider": "x"},
    )
    out = params.to_dict()
    assert out["systemPrompt"] == "be brief"
    assert out["temperature"] == 0.2
    assert out["stopSequences"] == ["STOP"]
    assert out["metadata"] == {"provider": "x"}
    assert "modelPreferences" in out

  def test_client_may_ignore_advisory_fields(self):
    # Simulate a client that drops every advisory field; the exchange completes
    # because the required fields remain.
    params = _simple_params(
      system_prompt="ignored",
      temperature=0.9,
      stop_sequences=["x"],
      metadata={"a": 1},
    )
    stripped = CreateMessageRequestParams(
      messages=params.messages, max_tokens=params.max_tokens
    )
    out = stripped.to_dict()
    assert "systemPrompt" not in out
    assert "temperature" not in out
    assert "stopSequences" not in out
    assert "metadata" not in out
    assert out["maxTokens"] == 100

  def test_client_may_modify_advisory_fields_silently(self):
    params = _simple_params(temperature=0.9, system_prompt="orig")
    # Client modifies without telling the server: just build a new params.
    modified = CreateMessageRequestParams(
      messages=params.messages,
      max_tokens=params.max_tokens,
      temperature=0.1,
      system_prompt="rewritten",
    )
    assert modified.temperature == 0.1
    assert modified.system_prompt == "rewritten"


# ---------------------------------------------------------------------------
# AC-33.8 — includeContext client control (R-21.2.4-f)
# ---------------------------------------------------------------------------

class TestAC8IncludeContextClientControl:
  def test_client_may_ignore_include_context(self):
    params = _simple_params(include_context=IncludeContext.ALL_SERVERS)
    # Client ignores it (e.g. to avoid sharing sensitive info): drop it.
    constrained = CreateMessageRequestParams(
      messages=params.messages, max_tokens=params.max_tokens
    )
    assert constrained.include_context is None
    assert constrained.effective_include_context is IncludeContext.NONE

  def test_client_may_modify_include_context(self):
    params = _simple_params(include_context=IncludeContext.ALL_SERVERS)
    modified = CreateMessageRequestParams(
      messages=params.messages,
      max_tokens=params.max_tokens,
      include_context=IncludeContext.NONE,
    )
    assert modified.include_context is IncludeContext.NONE

  def test_effective_include_context_defaults_to_none(self):
    assert _simple_params().effective_include_context is IncludeContext.NONE


# ---------------------------------------------------------------------------
# AC-33.9 — maxTokens upper bound (R-21.2.4-i, R-21.2.4-j)
# ---------------------------------------------------------------------------

class TestAC9MaxTokens:
  def test_clamp_caps_at_requested_max(self):
    assert clamp_max_tokens(100, 250) == 100

  def test_client_may_sample_fewer(self):
    assert clamp_max_tokens(100, 40) == 40

  def test_exact_match_allowed(self):
    assert clamp_max_tokens(100, 100) == 100

  def test_never_exceeds_requested_max(self):
    for sampled in (0, 50, 99, 100, 101, 9999):
      assert clamp_max_tokens(100, sampled) <= 100

  def test_negative_sampled_rejected(self):
    with pytest.raises(ValueError):
      clamp_max_tokens(100, -1)


# ---------------------------------------------------------------------------
# AC-33.10 — tools scoped to the request (R-21.2.4-m)
# ---------------------------------------------------------------------------

class TestAC10ToolsScoped:
  def test_arbitrary_tool_definitions_accepted(self):
    caps = ClientCapabilities(sampling={"tools": {}})
    params = _simple_params(
      tools=[{"name": "not_a_registered_tool", "inputSchema": {"type": "object"}}]
    )
    # Accepted even though it corresponds to no registered server tool.
    assert_tool_use_allowed(params, caps)
    assert params.tools[0]["name"] == "not_a_registered_tool"

  def test_tools_survive_serialization(self):
    params = _simple_params(tools=[{"name": "x", "inputSchema": {}}])
    assert params.to_dict()["tools"] == [{"name": "x", "inputSchema": {}}]


# ---------------------------------------------------------------------------
# AC-33.11 — omitted toolChoice ⇒ auto (R-21.2.4-p)
# ---------------------------------------------------------------------------

class TestAC11ToolChoiceDefault:
  def test_omitted_tool_choice_defaults_to_auto(self):
    params = _simple_params()
    assert params.tool_choice is None
    assert params.effective_tool_choice.mode is ToolChoiceMode.AUTO

  def test_tool_choice_default_helper(self):
    assert ToolChoice.default().mode is ToolChoiceMode.AUTO

  def test_from_dict_missing_mode_is_auto(self):
    assert ToolChoice.from_dict({}).mode is ToolChoiceMode.AUTO


# ---------------------------------------------------------------------------
# AC-33.12 — toolChoice modes (R-21.2.5-a, R-21.2.5-b)
# ---------------------------------------------------------------------------

class TestAC12ToolChoiceModes:
  def test_required_mode_parsed(self):
    tc = ToolChoice.from_dict({"mode": "required"})
    assert tc.mode is ToolChoiceMode.REQUIRED

  def test_none_mode_parsed(self):
    tc = ToolChoice.from_dict({"mode": "none"})
    assert tc.mode is ToolChoiceMode.NONE

  def test_invalid_mode_rejected(self):
    with pytest.raises(ValueError):
      ToolChoice.from_dict({"mode": "sometimes"})

  def test_mode_round_trips(self):
    assert ToolChoice(mode=ToolChoiceMode.REQUIRED).to_dict() == {"mode": "required"}
    assert ToolChoice(mode=ToolChoiceMode.NONE).to_dict() == {"mode": "none"}


# ---------------------------------------------------------------------------
# AC-33.13 — SamplingMessage role + content (R-21.2.6-a, R-21.2.6-b)
# ---------------------------------------------------------------------------

class TestAC13SamplingMessage:
  def test_single_block_content_accepted(self):
    msg = SamplingMessage.from_dict(
      {"role": "user", "content": {"type": "text", "text": "hi"}}
    )
    assert msg.content_is_single is True
    assert isinstance(msg.content[0], TextContent)

  def test_array_content_accepted(self):
    msg = SamplingMessage.from_dict(
      {
        "role": "assistant",
        "content": [
          {"type": "text", "text": "a"},
          {"type": "text", "text": "b"},
        ],
      }
    )
    assert msg.content_is_single is False
    assert len(msg.content) == 2

  def test_missing_role_rejected(self):
    with pytest.raises(ValueError):
      SamplingMessage.from_dict({"content": {"type": "text", "text": "x"}})

  def test_missing_content_rejected(self):
    with pytest.raises(ValueError):
      SamplingMessage.from_dict({"role": "user"})

  def test_invalid_role_rejected(self):
    with pytest.raises(ValueError):
      SamplingMessage(role="system", content=[TextContent(text="x")])

  def test_single_block_round_trips_as_single(self):
    msg = SamplingMessage.from_dict(
      {"role": "user", "content": {"type": "text", "text": "hi"}}
    )
    assert isinstance(msg.to_dict()["content"], dict)

  def test_array_round_trips_as_array(self):
    msg = SamplingMessage(
      role="user",
      content=[TextContent(text="a")],
      content_is_single=False,
    )
    assert isinstance(msg.to_dict()["content"], list)


# ---------------------------------------------------------------------------
# AC-33.14 — _meta preservation (R-21.2.6-c, R-21.2.6-h)
# ---------------------------------------------------------------------------

class TestAC14MetaPreservation:
  def test_tool_use_meta_preserved(self):
    block = ToolUseContent.from_dict(
      {
        "type": "tool_use",
        "id": "call_1",
        "name": "get",
        "input": {},
        "_meta": {"cache": "key-1"},
      }
    )
    assert block.meta == {"cache": "key-1"}
    assert block.to_dict()["_meta"] == {"cache": "key-1"}

  def test_tool_result_meta_preserved(self):
    block = ToolResultContent.from_dict(
      {
        "type": "tool_result",
        "toolUseId": "call_1",
        "content": [{"type": "text", "text": "ok"}],
        "_meta": {"cache": "key-2"},
      }
    )
    assert block.meta == {"cache": "key-2"}
    assert block.to_dict()["_meta"] == {"cache": "key-2"}

  def test_meta_survives_full_message_round_trip(self):
    raw = {
      "role": "assistant",
      "content": [
        {"type": "tool_use", "id": "c1", "name": "n", "input": {}, "_meta": {"k": 1}}
      ],
    }
    msg = SamplingMessage.from_dict(raw)
    assert msg.to_dict()["content"][0]["_meta"] == {"k": 1}


# ---------------------------------------------------------------------------
# AC-33.15 — toolUseId matches a prior tool use (R-21.2.6-d)
# ---------------------------------------------------------------------------

class TestAC15ToolUseIdMatch:
  def test_matching_tool_use_id_valid(self):
    messages = [
      _text_msg("user", "weather?"),
      SamplingMessage(
        role="assistant",
        content=[ToolUseContent(id="c1", name="w", input={"city": "Paris"})],
      ),
      SamplingMessage(
        role="user",
        content=[ToolResultContent(tool_use_id="c1", content=[TextContent(text="ok")])],
      ),
    ]
    # No error.
    validate_tool_result_references(messages)

  def test_unmatched_tool_use_id_rejected(self):
    messages = [
      SamplingMessage(
        role="user",
        content=[ToolResultContent(tool_use_id="nope", content=[TextContent(text="x")])],
      ),
    ]
    with pytest.raises(MalformedSamplingRequestError):
      validate_tool_result_references(messages)

  def test_result_before_use_rejected(self):
    # A tool_result whose use appears later (not previous) is invalid.
    messages = [
      SamplingMessage(
        role="user",
        content=[ToolResultContent(tool_use_id="c1", content=[TextContent(text="x")])],
      ),
      SamplingMessage(
        role="assistant",
        content=[ToolUseContent(id="c1", name="w", input={})],
      ),
    ]
    with pytest.raises(MalformedSamplingRequestError):
      validate_tool_result_references(messages)

  def test_tool_use_id_empty_rejected(self):
    with pytest.raises(ValueError):
      ToolUseContent(id="", name="w", input={})


# ---------------------------------------------------------------------------
# AC-33.16 — ToolResultContent content/structured/isError
#            (R-21.2.6-e, R-21.2.6-f, R-21.2.6-g)
# ---------------------------------------------------------------------------

class TestAC16ToolResultContent:
  def test_content_may_carry_varied_blocks(self):
    block = ToolResultContent.from_dict(
      {
        "type": "tool_result",
        "toolUseId": "c1",
        "content": [
          {"type": "text", "text": "t"},
          {"type": "image", "data": _PNG_B64, "mimeType": "image/png"},
          {"type": "audio", "data": _WAV_B64, "mimeType": "audio/wav"},
          {"type": "resource_link", "uri": "file:///x", "name": "x"},
        ],
      }
    )
    types = {type(b).__name__ for b in block.content}
    assert "TextContent" in types
    assert "ImageContent" in types
    assert "AudioContent" in types
    assert "ResourceLink" in types

  def test_structured_content_preserved(self):
    block = ToolResultContent.from_dict(
      {
        "type": "tool_result",
        "toolUseId": "c1",
        "content": [{"type": "text", "text": "t"}],
        "structuredContent": {"temp": 18, "unit": "C"},
      }
    )
    assert block.structured_content == {"temp": 18, "unit": "C"}
    assert block.to_dict()["structuredContent"] == {"temp": 18, "unit": "C"}

  def test_is_error_default_false_when_omitted(self):
    block = ToolResultContent.from_dict(
      {"type": "tool_result", "toolUseId": "c1", "content": []}
    )
    assert block.is_error is False
    # Default false is implied, not serialized.
    assert "isError" not in block.to_dict()

  def test_is_error_true_serialized(self):
    block = ToolResultContent(
      tool_use_id="c1", content=[TextContent(text="boom")], is_error=True
    )
    assert block.to_dict()["isError"] is True

  def test_structured_content_null_preserved(self):
    block = ToolResultContent.from_dict(
      {
        "type": "tool_result",
        "toolUseId": "c1",
        "content": [],
        "structuredContent": None,
      }
    )
    assert block.to_dict()["structuredContent"] is None


# ---------------------------------------------------------------------------
# AC-33.17 — user tool_result exclusivity (R-21.2.7-a)
# ---------------------------------------------------------------------------

class TestAC17ToolResultExclusivity:
  def test_user_message_of_only_tool_results_valid(self):
    msg = SamplingMessage(
      role="user",
      content=[
        ToolResultContent(tool_use_id="c1", content=[TextContent(text="a")]),
        ToolResultContent(tool_use_id="c2", content=[TextContent(text="b")]),
      ],
    )
    assert msg.role == "user"

  def test_mixing_tool_result_with_text_rejected(self):
    with pytest.raises(MalformedSamplingRequestError):
      SamplingMessage(
        role="user",
        content=[
          ToolResultContent(tool_use_id="c1", content=[TextContent(text="a")]),
          TextContent(text="extra"),
        ],
      )

  def test_mixing_via_from_dict_rejected(self):
    with pytest.raises(MalformedSamplingRequestError):
      SamplingMessage.from_dict(
        {
          "role": "user",
          "content": [
            {"type": "tool_result", "toolUseId": "c1", "content": []},
            {"type": "image", "data": _PNG_B64, "mimeType": "image/png"},
          ],
        }
      )

  def test_assistant_may_mix_tool_use_with_text(self):
    # The exclusivity rule applies to user tool_result messages only.
    msg = SamplingMessage(
      role="assistant",
      content=[TextContent(text="let me check"), ToolUseContent(id="c1", name="w", input={})],
    )
    assert len(msg.content) == 2


# ---------------------------------------------------------------------------
# AC-33.18 — tool_use ordering (R-21.2.7-b)
# ---------------------------------------------------------------------------

class TestAC18ToolUseOrdering:
  def _exchange(self):
    return [
      _text_msg("user", "weather?"),
      SamplingMessage(
        role="assistant",
        content=[ToolUseContent(id="c1", name="w", input={"city": "Paris"})],
      ),
      SamplingMessage(
        role="user",
        content=[ToolResultContent(tool_use_id="c1", content=[TextContent(text="18C")])],
      ),
    ]

  def test_well_formed_exchange_valid(self):
    validate_tool_use_ordering(self._exchange())

  def test_parallel_tool_uses_matched(self):
    messages = [
      SamplingMessage(
        role="assistant",
        content=[
          ToolUseContent(id="c1", name="a", input={}),
          ToolUseContent(id="c2", name="b", input={}),
        ],
      ),
      SamplingMessage(
        role="user",
        content=[
          ToolResultContent(tool_use_id="c1", content=[]),
          ToolResultContent(tool_use_id="c2", content=[]),
        ],
      ),
    ]
    validate_tool_use_ordering(messages)

  def test_tool_use_not_followed_by_user_rejected(self):
    messages = [
      SamplingMessage(
        role="assistant", content=[ToolUseContent(id="c1", name="w", input={})]
      ),
      _text_msg("assistant", "no results message here"),
    ]
    with pytest.raises(MalformedSamplingRequestError):
      validate_tool_use_ordering(messages)

  def test_tool_use_last_message_rejected(self):
    messages = [
      SamplingMessage(
        role="assistant", content=[ToolUseContent(id="c1", name="w", input={})]
      ),
    ]
    with pytest.raises(MalformedSamplingRequestError):
      validate_tool_use_ordering(messages)

  def test_unmatched_ids_rejected(self):
    messages = [
      SamplingMessage(
        role="assistant", content=[ToolUseContent(id="c1", name="w", input={})]
      ),
      SamplingMessage(
        role="user",
        content=[ToolResultContent(tool_use_id="cX", content=[])],
      ),
    ]
    with pytest.raises(MalformedSamplingRequestError):
      validate_tool_use_ordering(messages)

  def test_following_user_must_be_only_tool_results(self):
    # The exclusivity rule (R-21.2.7-a) already blocks mixed user messages at
    # construction; ordering validation enforces the all-tool-result property
    # on a non-tool-result user message after a tool use.
    messages = [
      SamplingMessage(
        role="assistant", content=[ToolUseContent(id="c1", name="w", input={})]
      ),
      _text_msg("user", "just text, no tool result"),
    ]
    with pytest.raises(MalformedSamplingRequestError):
      validate_tool_use_ordering(messages)

  def test_ordering_validated_through_params(self):
    # CreateMessageRequestParams validates ordering on construction.
    with pytest.raises(MalformedSamplingRequestError):
      CreateMessageRequestParams(
        messages=[
          SamplingMessage(
            role="assistant",
            content=[ToolUseContent(id="c1", name="w", input={})],
          ),
        ],
        max_tokens=100,
      )


# ---------------------------------------------------------------------------
# AC-33.19 — CreateMessageResult required fields
#            (R-21.2.8-a/b/c/e)
# ---------------------------------------------------------------------------

class TestAC19ResultRequiredFields:
  def test_valid_result_parses(self):
    result = CreateMessageResult.from_dict(
      {
        "role": "assistant",
        "content": {"type": "text", "text": "Paris"},
        "model": "vendor-sonnet-20240307",
        "stopReason": "endTurn",
        "resultType": "complete",
      }
    )
    assert result.role == "assistant"
    assert result.model == "vendor-sonnet-20240307"
    assert result.result_type == "complete"
    assert isinstance(result.content[0], TextContent)

  @pytest.mark.parametrize("missing", ["role", "content", "model", "resultType"])
  def test_missing_required_field_rejected(self, missing):
    raw = {
      "role": "assistant",
      "content": {"type": "text", "text": "x"},
      "model": "m",
      "resultType": "complete",
    }
    del raw[missing]
    with pytest.raises(MalformedSamplingResultError):
      CreateMessageResult.from_dict(raw)

  def test_invalid_role_rejected(self):
    with pytest.raises(MalformedSamplingResultError):
      CreateMessageResult(
        role="system", content=[TextContent(text="x")], model="m"
      )

  def test_empty_model_rejected(self):
    with pytest.raises(MalformedSamplingResultError):
      CreateMessageResult(role="assistant", content=[TextContent(text="x")], model="")

  def test_result_type_defaults_to_complete(self):
    result = CreateMessageResult(
      role="assistant", content=[TextContent(text="x")], model="m"
    )
    assert result.result_type == "complete"

  def test_tool_use_result_content_array(self):
    result = CreateMessageResult.from_dict(
      {
        "role": "assistant",
        "content": [
          {"type": "tool_use", "id": "c1", "name": "w", "input": {"city": "Paris"}}
        ],
        "model": "m",
        "stopReason": "toolUse",
        "resultType": "complete",
      }
    )
    assert isinstance(result.content[0], ToolUseContent)
    assert result.stop_reason == "toolUse"

  def test_result_round_trips(self):
    raw = {
      "role": "assistant",
      "content": {"type": "text", "text": "Paris"},
      "model": "m",
      "stopReason": "endTurn",
      "resultType": "complete",
    }
    result = CreateMessageResult.from_dict(raw)
    out = result.to_dict()
    assert out["role"] == "assistant"
    assert isinstance(out["content"], dict)
    assert out["resultType"] == "complete"


# ---------------------------------------------------------------------------
# AC-33.20 — open stopReason (R-21.2.8-d)
# ---------------------------------------------------------------------------

class TestAC20OpenStopReason:
  def test_non_standard_stop_reason_accepted(self):
    result = CreateMessageResult.from_dict(
      {
        "role": "assistant",
        "content": {"type": "text", "text": "x"},
        "model": "m",
        "stopReason": "providerSpecificReason",
        "resultType": "complete",
      }
    )
    assert result.stop_reason == "providerSpecificReason"
    assert result.stop_reason_is_standard is False

  def test_standard_stop_reasons_recognized(self):
    for sr in STANDARD_STOP_REASONS:
      result = CreateMessageResult(
        role="assistant",
        content=[TextContent(text="x")],
        model="m",
        stop_reason=sr,
      )
      assert result.stop_reason_is_standard is True

  def test_stop_reason_optional(self):
    result = CreateMessageResult(
      role="assistant", content=[TextContent(text="x")], model="m"
    )
    assert result.stop_reason is None
    assert "stopReason" not in result.to_dict()


# ---------------------------------------------------------------------------
# AC-33.21 — model preferences (R-21.2.9-a/b/c/d)
# ---------------------------------------------------------------------------

class TestAC21ModelPreferences:
  def test_first_matching_hint_in_order(self):
    prefs = ModelPreferences(
      hints=[ModelHint(name="opus"), ModelHint(name="sonnet")]
    )
    # opus is listed first; if available it wins over sonnet.
    chosen = select_model(prefs, ["vendor-sonnet", "vendor-opus"])
    assert chosen == "vendor-opus"

  def test_first_hint_skipped_when_no_match(self):
    prefs = ModelPreferences(
      hints=[ModelHint(name="nomatch"), ModelHint(name="sonnet")]
    )
    chosen = select_model(prefs, ["vendor-sonnet"])
    assert chosen == "vendor-sonnet"

  def test_priorities_break_ties_within_first_hint(self):
    prefs = ModelPreferences(hints=[ModelHint(name="sonnet")])
    chosen = select_model(
      prefs,
      ["vendor-sonnet-fast", "vendor-sonnet-smart"],
      priority_tiebreak=lambda m: 1.0 if "smart" in m else 0.0,
    )
    assert chosen == "vendor-sonnet-smart"

  def test_preferences_advisory_caller_may_override(self):
    prefs = ModelPreferences(hints=[ModelHint(name="sonnet")])
    chosen = select_model(prefs, ["vendor-sonnet"])
    # The caller is free to ignore the return value entirely (advisory).
    final = "my-own-choice"  # client/host final decision (R-21.2.9-a)
    assert chosen == "vendor-sonnet"
    assert final == "my-own-choice"

  def test_no_models_returns_none(self):
    assert select_model(ModelPreferences(), []) is None

  def test_no_hints_falls_back(self):
    assert select_model(None, ["m1", "m2"]) == "m1"

  def test_round_trip(self):
    prefs = ModelPreferences.from_dict(
      {
        "hints": [{"name": "vendor-sonnet"}, {"name": "vendor"}],
        "costPriority": 0.3,
        "speedPriority": 0.5,
        "intelligencePriority": 0.8,
      }
    )
    out = prefs.to_dict()
    assert out["hints"] == [{"name": "vendor-sonnet"}, {"name": "vendor"}]
    assert out["costPriority"] == 0.3


# ---------------------------------------------------------------------------
# AC-33.22 — priorities optional numbers in 0..1 (R-21.2.9-e)
# ---------------------------------------------------------------------------

class TestAC22Priorities:
  def test_priorities_optional(self):
    prefs = ModelPreferences()
    assert prefs.cost_priority is None
    assert prefs.to_dict() == {}

  def test_in_range_priorities_kept(self):
    prefs = ModelPreferences.from_dict(
      {"costPriority": 0.0, "speedPriority": 1.0, "intelligencePriority": 0.5}
    )
    assert prefs.cost_priority == 0.0
    assert prefs.speed_priority == 1.0
    assert prefs.intelligence_priority == 0.5

  def test_out_of_range_not_hard_rejected(self):
    # The spec states no hard MUST-reject obligation; out-of-range values are
    # accepted on parse and MAY be ignored or clamped by the client.
    prefs = ModelPreferences.from_dict({"costPriority": 5.0})
    assert prefs.cost_priority == 5.0


# ---------------------------------------------------------------------------
# AC-33.23 — ModelHint.name substring + mappable (R-21.2.9-f, R-21.2.9-g)
# ---------------------------------------------------------------------------

class TestAC23ModelHint:
  def test_name_treated_as_substring(self):
    assert hint_matches(ModelHint(name="sonnet"), "vendor-sonnet-20241022") is True
    assert hint_matches(ModelHint(name="vendor"), "vendor-opus") is True
    assert hint_matches(ModelHint(name="nomatch"), "vendor-opus") is False

  def test_empty_hint_never_matches(self):
    assert hint_matches(ModelHint(name=None), "vendor-opus") is False

  def test_hint_may_map_to_other_provider(self):
    # The client MAY map a hint to a different provider's model. select_model
    # works on whatever candidate names the client offers, including a remap.
    prefs = ModelPreferences(hints=[ModelHint(name="sonnet")])
    # Client maps "sonnet" niche to its own equivalent model name list.
    chosen = select_model(prefs, ["vendor-equivalent-sonnet-tier"])
    assert chosen == "vendor-equivalent-sonnet-tier"

  def test_unknown_hint_keys_preserved(self):
    hint = ModelHint.from_dict({"name": "x", "vendor": "acme"})
    assert hint.extra == {"vendor": "acme"}
    assert hint.to_dict() == {"name": "x", "vendor": "acme"}


# ---------------------------------------------------------------------------
# AC-33.24 — consent & human-in-the-loop
#            (R-21.2.10-a/b/c/d/e)
# ---------------------------------------------------------------------------

class TestAC24Consent:
  def test_no_reviewer_denies_by_default(self):
    hitl = HumanInTheLoop()
    with pytest.raises(SamplingDeniedError):
      hitl.review_prompt(_simple_params())

  def test_user_can_deny_prompt(self):
    hitl = HumanInTheLoop(
      prompt_reviewer=lambda p: (ConsentDecision.REJECT, p)
    )
    with pytest.raises(SamplingDeniedError):
      hitl.review_prompt(_simple_params())

  def test_user_can_approve_prompt(self):
    params = _simple_params()
    hitl = HumanInTheLoop(
      prompt_reviewer=lambda p: (ConsentDecision.APPROVE, p)
    )
    assert hitl.review_prompt(params) is params

  def test_reviewer_may_edit_prompt_fields(self):
    params = _simple_params(system_prompt="orig", temperature=0.9)

    def review(p):
      edited = CreateMessageRequestParams(
        messages=p.messages,
        max_tokens=p.max_tokens,
        system_prompt="edited",
        temperature=0.1,
      )
      return ConsentDecision.APPROVE, edited

    hitl = HumanInTheLoop(prompt_reviewer=review)
    out = hitl.review_prompt(params)
    assert out.system_prompt == "edited"
    assert out.temperature == 0.1

  def test_result_reviewed_before_server_sees_it(self):
    result = CreateMessageResult(
      role="assistant", content=[TextContent(text="raw")], model="m"
    )
    hitl = HumanInTheLoop(
      result_reviewer=lambda r: (ConsentDecision.APPROVE, r)
    )
    assert hitl.review_result(result) is result

  def test_user_can_deny_result(self):
    result = CreateMessageResult(
      role="assistant", content=[TextContent(text="x")], model="m"
    )
    hitl = HumanInTheLoop(
      result_reviewer=lambda r: (ConsentDecision.REJECT, r)
    )
    with pytest.raises(SamplingDeniedError):
      hitl.review_result(result)

  def test_no_result_reviewer_denies(self):
    result = CreateMessageResult(
      role="assistant", content=[TextContent(text="x")], model="m"
    )
    with pytest.raises(SamplingDeniedError):
      HumanInTheLoop().review_result(result)


# ---------------------------------------------------------------------------
# AC-33.25 — rate limiting, content validation, iteration limits
#            (R-21.2.10-f/g/h/i)
# ---------------------------------------------------------------------------

class TestAC25SafetyControls:
  def test_rate_limiter_allows_within_window(self):
    rl = RateLimiter(max_requests=2, window_seconds=10)
    assert rl.allow(0.0) is True
    assert rl.allow(1.0) is True
    assert rl.allow(2.0) is False  # third within window blocked

  def test_rate_limiter_recovers_after_window(self):
    rl = RateLimiter(max_requests=1, window_seconds=10)
    assert rl.allow(0.0) is True
    assert rl.allow(5.0) is False
    assert rl.allow(11.0) is True  # window elapsed

  def test_rate_limiter_rejects_bad_config(self):
    with pytest.raises(ValueError):
      RateLimiter(max_requests=0, window_seconds=1)
    with pytest.raises(ValueError):
      RateLimiter(max_requests=1, window_seconds=0)

  def test_validate_message_content_passes_clean_conversation(self):
    messages = [
      _text_msg("user", "weather?"),
      SamplingMessage(
        role="assistant", content=[ToolUseContent(id="c1", name="w", input={})]
      ),
      SamplingMessage(
        role="user",
        content=[ToolResultContent(tool_use_id="c1", content=[TextContent(text="ok")])],
      ),
    ]
    validate_message_content(messages)

  def test_validate_message_content_catches_bad_reference(self):
    messages = [
      SamplingMessage(
        role="user",
        content=[ToolResultContent(tool_use_id="ghost", content=[])],
      ),
    ]
    with pytest.raises(MalformedSamplingRequestError):
      validate_message_content(messages)

  def test_iteration_limit(self):
    assert within_iteration_limit(0, 3) is True
    assert within_iteration_limit(2, 3) is True
    assert within_iteration_limit(3, 3) is False

  def test_iteration_limit_rejects_bad_config(self):
    with pytest.raises(ValueError):
      within_iteration_limit(0, 0)


# ---------------------------------------------------------------------------
# Capability dataclass round-trip (supporting §21.2.3)
# ---------------------------------------------------------------------------

class TestCapabilityShapes:
  def test_minimum_declaration_empty_object(self):
    cap = ClientSamplingCapability.from_dict({})
    assert cap.supports_tools is False
    assert cap.supports_context is False
    assert cap.to_dict() == {}

  def test_tools_declaration(self):
    cap = ClientSamplingCapability.from_dict({"tools": {}})
    assert cap.supports_tools is True
    assert cap.to_dict() == {"tools": {}}

  def test_context_declaration(self):
    cap = ClientSamplingCapability.from_dict({"context": {}})
    assert cap.supports_context is True

  def test_capability_helpers_match_dataclass(self):
    assert capability_supports_tools({"tools": {}}) is True
    assert capability_supports_tools({}) is False

  def test_unknown_subkeys_preserved(self):
    cap = ClientSamplingCapability.from_dict({"future": {"x": 1}})
    assert cap.extra == {"future": {"x": 1}}
    assert cap.to_dict() == {"future": {"x": 1}}

  def test_non_object_rejected(self):
    with pytest.raises(TypeError):
      ClientSamplingCapability.from_dict("nope")
