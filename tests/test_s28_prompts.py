"""Tests for S28 — Prompts: Capability, Listing, Retrieval & Types.

Verifies the prompts server feature (§18): the `prompts` capability and its
`listChanged` sub-flag plus gating, the paginated/cacheable/result-typed
`prompts/list` discovery exchange, the `Prompt`/`PromptArgument` data types, the
`prompts/get` retrieval request (with multi-round-trip retry fields and the
`input_required` alternative), the `PromptMessage` type and its valid content
kinds, the `notifications/prompts/list_changed` notification, the `-32602`/
`-32603` error model, and the argument-completion hook.

AC -> test coverage map (42 ACs):
  AC-28.1  -> TestUserControlledInteraction
  AC-28.2  -> TestCapabilityDeclaration
  AC-28.3  -> TestGatingWithoutCapability
  AC-28.4  -> TestCapabilityListChangedSubFlag
  AC-28.5  -> TestListChangedEmitPermission
  AC-28.6  -> TestListChangedAbsentOrFalse
  AC-28.7  -> TestAvailablePromptSet
  AC-28.8  -> TestAvailablePromptSet
  AC-28.9  -> TestAvailablePromptSet
  AC-28.10 -> TestAvailablePromptSet
  AC-28.11 -> TestListPromptsRequestCursor
  AC-28.12 -> TestListPromptsResultPromptsField
  AC-28.13 -> TestNextCursorOpacity
  AC-28.14 -> TestTtlMs
  AC-28.15 -> TestTtlMsZero
  AC-28.16 -> TestTtlMsPositive
  AC-28.17 -> TestCacheScope
  AC-28.18 -> TestListResultResultType
  AC-28.19 -> TestListResultMeta
  AC-28.20 -> TestListChangedOnSetChange
  AC-28.21 -> TestPromptNameAndTitle
  AC-28.22 -> TestPromptArgumentsAbsentOrEmpty
  AC-28.23 -> TestPromptIcons
  AC-28.24 -> TestPromptIconTrust
  AC-28.25 -> TestPromptIconSrc
  AC-28.26 -> TestPromptArgumentNameAndTitle
  AC-28.27 -> TestRequiredArgument
  AC-28.28 -> TestGetPromptMultiRoundTrip
  AC-28.29 -> TestGetPromptNameMatching
  AC-28.30 -> TestGetPromptArgumentValidation
  AC-28.31 -> TestRetryInputResponses
  AC-28.32 -> TestRetryRequestState
  AC-28.33 -> TestGetPromptResultMessages
  AC-28.34 -> TestGetPromptResultResultType
  AC-28.35 -> TestInputRequiredAlternative
  AC-28.36 -> TestErrorModel
  AC-28.37 -> TestPromptMessage
  AC-28.38 -> TestPromptMessageResourceLink
  AC-28.39 -> TestListChangedNotification
  AC-28.40 -> TestListChangedNotificationParams
  AC-28.41 -> TestClientReactionToListChanged
  AC-28.42 -> TestArgumentCompletionHook
"""

from __future__ import annotations

import pytest

from mcp_sdk_py.caching import CACHE_SCOPE_PRIVATE, CACHE_SCOPE_PUBLIC
from mcp_sdk_py.capabilities import ServerCapabilities
from mcp_sdk_py.common_types import Icon
from mcp_sdk_py.content_types import (
  AudioContent,
  EmbeddedResource,
  ImageContent,
  ParticipantRole,
  ResourceLink,
  TextContent,
  TextResourceContents,
)
from mcp_sdk_py.multi_round_trip import InputRequiredResult
from mcp_sdk_py.result_error import RESULT_TYPE_COMPLETE, RESULT_TYPE_INPUT_REQUIRED
from mcp_sdk_py.prompts import (
  JSONRPC_INTERNAL_ERROR,
  JSONRPC_INVALID_PARAMS,
  METHOD_COMPLETION_COMPLETE,
  METHOD_PROMPTS_GET,
  METHOD_PROMPTS_LIST,
  NOTIFICATION_PROMPTS_LIST_CHANGED,
  PROMPT_GATED_REQUESTS,
  PROMPTS_CAPABILITY_KEY,
  VALID_PROMPT_CONTENT_TYPES,
  GetPromptRequestParams,
  GetPromptResult,
  ListPromptsRequestParams,
  ListPromptsResult,
  MissingRequiredArgumentError,
  Prompt,
  PromptArgument,
  PromptArgumentCompletionTarget,
  PromptListChangedNotification,
  PromptMessage,
  PromptsCapability,
  PromptsCapabilityNotDeclaredError,
  UnknownPromptError,
  assert_client_may_send_prompt_request,
  build_get_prompt_retry,
  client_may_rely_on_list_changed,
  client_may_send_prompt_request,
  is_input_required,
  next_prompts_list_request,
  parse_get_prompt_response,
  prompts_capability_declared,
  resolve_prompt_for_get,
  server_may_emit_list_changed,
  should_invalidate_cached_prompts,
  validate_get_prompt_arguments,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _text_msg(text: str = "hello", role: ParticipantRole = ParticipantRole.USER) -> PromptMessage:
  return PromptMessage(role=role, content=TextContent(text=text))


def _list_result(**overrides):
  base = {
    "prompts": [Prompt(name="p")],
    "ttl_ms": 1000,
    "cache_scope": CACHE_SCOPE_PUBLIC,
  }
  base.update(overrides)
  return ListPromptsResult(**base)


# ---------------------------------------------------------------------------
# AC-28.1 — No specific user-interaction pattern is required. (R-18-a)
# ---------------------------------------------------------------------------

class TestUserControlledInteraction:
  def test_module_imposes_no_ui_requirement(self):
    # Nothing in the surface ties conformance to a UI such as slash commands:
    # a Prompt is usable with name alone; invocation pattern is unconstrained.
    prompt = Prompt(name="anything")
    assert prompt.name == "anything"
    # No symbol mentions/forces slash commands or any particular UI.
    import mcp_sdk_py.prompts as mod
    assert not any("slash" in n.lower() for n in dir(mod))

  def test_prompt_get_works_without_any_ui_construct(self):
    params = GetPromptRequestParams(name="p")
    assert params.to_dict() == {"name": "p"}


# ---------------------------------------------------------------------------
# AC-28.2 — `prompts` capability key present when a server offers prompts. (R-18.1-a)
# ---------------------------------------------------------------------------

class TestCapabilityDeclaration:
  def test_server_offering_prompts_declares_key(self):
    caps = ServerCapabilities(prompts={})
    assert PROMPTS_CAPABILITY_KEY in caps.to_dict()
    assert prompts_capability_declared(caps) is True

  def test_empty_capability_object_still_declares_feature(self):
    cap = PromptsCapability()
    assert cap.to_dict() == {}
    caps = ServerCapabilities(prompts=cap.to_dict())
    assert prompts_capability_declared(caps) is True

  def test_server_without_prompts_does_not_declare(self):
    caps = ServerCapabilities()
    assert PROMPTS_CAPABILITY_KEY not in caps.to_dict()
    assert prompts_capability_declared(caps) is False

  def test_capability_from_dict_rejects_non_object(self):
    with pytest.raises(TypeError):
      PromptsCapability.from_dict([])  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# AC-28.3 — Client does not send prompt methods to an undeclared server. (R-18.1-b)
# ---------------------------------------------------------------------------

class TestGatingWithoutCapability:
  def test_gated_request_set(self):
    assert PROMPT_GATED_REQUESTS == {METHOD_PROMPTS_LIST, METHOD_PROMPTS_GET}

  def test_client_may_not_send_when_undeclared(self):
    caps = ServerCapabilities()
    assert client_may_send_prompt_request(caps, METHOD_PROMPTS_LIST) is False
    assert client_may_send_prompt_request(caps, METHOD_PROMPTS_GET) is False

  def test_assert_raises_when_undeclared(self):
    caps = ServerCapabilities()
    with pytest.raises(PromptsCapabilityNotDeclaredError) as exc:
      assert_client_may_send_prompt_request(caps, METHOD_PROMPTS_GET)
    assert exc.value.method == METHOD_PROMPTS_GET

  def test_client_may_send_when_declared(self):
    caps = ServerCapabilities(prompts={})
    assert client_may_send_prompt_request(caps, METHOD_PROMPTS_LIST) is True
    assert client_may_send_prompt_request(caps, METHOD_PROMPTS_GET) is True
    assert_client_may_send_prompt_request(caps, METHOD_PROMPTS_GET)  # no raise

  def test_ungated_methods_pass_through(self):
    caps = ServerCapabilities()
    assert client_may_send_prompt_request(caps, "initialize") is True


# ---------------------------------------------------------------------------
# AC-28.4 — listChanged optional; both presence and absence accepted. (R-18.1-c)
# ---------------------------------------------------------------------------

class TestCapabilityListChangedSubFlag:
  def test_absent_is_valid(self):
    cap = PromptsCapability.from_dict({})
    assert cap.list_changed is None
    assert cap.to_dict() == {}

  def test_present_true_is_valid(self):
    cap = PromptsCapability.from_dict({"listChanged": True})
    assert cap.list_changed is True
    assert cap.to_dict() == {"listChanged": True}

  def test_present_false_is_valid(self):
    cap = PromptsCapability.from_dict({"listChanged": False})
    assert cap.list_changed is False
    assert cap.to_dict() == {"listChanged": False}

  def test_non_boolean_rejected(self):
    with pytest.raises(TypeError):
      PromptsCapability.from_dict({"listChanged": "yes"})
    with pytest.raises(TypeError):
      PromptsCapability(list_changed="yes")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# AC-28.5 — listChanged:true server is permitted to emit the notification. (R-18.1-d)
# ---------------------------------------------------------------------------

class TestListChangedEmitPermission:
  def test_emit_permitted_when_true(self):
    caps = ServerCapabilities(prompts={"listChanged": True})
    assert server_may_emit_list_changed(caps) is True
    assert PromptsCapability(list_changed=True).emits_list_changed is True


# ---------------------------------------------------------------------------
# AC-28.6 — listChanged absent/false: no notification expected, no reliance.
#           (R-18.1-e, R-18.1-f)
# ---------------------------------------------------------------------------

class TestListChangedAbsentOrFalse:
  def test_absent_means_no_emit_and_no_reliance(self):
    caps = ServerCapabilities(prompts={})
    assert server_may_emit_list_changed(caps) is False
    assert client_may_rely_on_list_changed(caps) is False

  def test_false_means_no_emit_and_no_reliance(self):
    caps = ServerCapabilities(prompts={"listChanged": False})
    assert server_may_emit_list_changed(caps) is False
    assert client_may_rely_on_list_changed(caps) is False

  def test_undeclared_capability_means_no_emit(self):
    caps = ServerCapabilities()
    assert server_may_emit_list_changed(caps) is False
    assert client_may_rely_on_list_changed(caps) is False

  def test_emits_list_changed_property_false_when_absent(self):
    assert PromptsCapability().emits_list_changed is False
    assert PromptsCapability(list_changed=False).emits_list_changed is False


# ---------------------------------------------------------------------------
# AC-28.7..28.10 — available-prompt set semantics. (R-18.1-g/h/i/j)
# ---------------------------------------------------------------------------

class TestAvailablePromptSet:
  def test_list_carries_available_set(self):  # AC-28.7
    result = _list_result(prompts=[Prompt(name="a"), Prompt(name="b")])
    assert [p.name for p in result.prompts] == ["a", "b"]

  def test_set_may_be_empty(self):  # AC-28.8
    result = _list_result(prompts=[])
    assert result.prompts == []
    assert result.to_dict()["prompts"] == []

  def test_set_may_change_between_calls(self):  # AC-28.8
    first = _list_result(prompts=[Prompt(name="a")])
    second = _list_result(prompts=[Prompt(name="a"), Prompt(name="c")])
    assert [p.name for p in first.prompts] != [p.name for p in second.prompts]

  def test_set_stable_across_unrelated_requests(self):  # AC-28.9
    # The set is a function of the request inputs, not connection state: two
    # results built from the same inputs are equal regardless of intervening
    # unrelated requests.
    a = _list_result(prompts=[Prompt(name="a")]).to_dict()
    b = _list_result(prompts=[Prompt(name="a")]).to_dict()
    assert a == b

  def test_set_may_vary_by_authorization(self):  # AC-28.10
    # Different authorization (a per-request input) may yield a different set.
    admin = _list_result(prompts=[Prompt(name="a"), Prompt(name="admin_only")])
    guest = _list_result(prompts=[Prompt(name="a")])
    assert {p.name for p in admin.prompts} != {p.name for p in guest.prompts}


# ---------------------------------------------------------------------------
# AC-28.11 — cursor optional and opaque. (R-18.2-a/b/c)
# ---------------------------------------------------------------------------

class TestListPromptsRequestCursor:
  def test_cursor_may_be_omitted(self):
    params = ListPromptsRequestParams.from_dict(None)
    assert params.cursor is None
    assert params.to_dict() == {}
    assert ListPromptsRequestParams.from_dict({}).cursor is None

  def test_cursor_sent_unmodified(self):
    opaque = "server-issued-opaque-cursor"
    params = ListPromptsRequestParams(cursor=opaque)
    assert params.to_dict()["cursor"] == opaque  # passed verbatim, never parsed
    parsed = ListPromptsRequestParams.from_dict({"cursor": opaque})
    assert parsed.cursor == opaque

  def test_empty_string_cursor_is_present(self):
    params = ListPromptsRequestParams.from_dict({"cursor": ""})
    assert params.cursor == ""
    assert params.to_dict()["cursor"] == ""

  def test_non_string_cursor_rejected(self):
    with pytest.raises(TypeError):
      ListPromptsRequestParams.from_dict({"cursor": 5})


# ---------------------------------------------------------------------------
# AC-28.12 — prompts present (possibly empty). (R-18.2-d)
# ---------------------------------------------------------------------------

class TestListPromptsResultPromptsField:
  def test_prompts_required_in_from_dict(self):
    with pytest.raises(ValueError):
      ListPromptsResult.from_dict({"ttlMs": 0, "cacheScope": "public", "resultType": "complete"})

  def test_prompts_may_be_empty(self):
    result = ListPromptsResult.from_dict(
      {"prompts": [], "ttlMs": 0, "cacheScope": "public", "resultType": "complete"}
    )
    assert result.prompts == []

  def test_prompts_must_be_array(self):
    with pytest.raises(TypeError):
      ListPromptsResult.from_dict(
        {"prompts": {}, "ttlMs": 0, "cacheScope": "public", "resultType": "complete"}
      )

  def test_entries_must_be_prompt_objects(self):
    with pytest.raises(TypeError):
      ListPromptsResult(prompts=["not-a-prompt"], ttl_ms=0, cache_scope="public")


# ---------------------------------------------------------------------------
# AC-28.13 — nextCursor opaque follow-up. (R-18.2-e/f/g)
# ---------------------------------------------------------------------------

class TestNextCursorOpacity:
  def test_next_request_uses_cursor_verbatim(self):
    result = _list_result(next_cursor="opaque-next")
    follow = next_prompts_list_request(result)
    assert follow is not None
    assert follow.cursor == "opaque-next"
    assert follow.to_dict()["cursor"] == "opaque-next"

  def test_absent_next_cursor_means_last_page(self):
    result = _list_result()
    assert result.is_last_page is True
    assert next_prompts_list_request(result) is None

  def test_present_next_cursor_not_last_page(self):
    result = _list_result(next_cursor="x")
    assert result.is_last_page is False

  def test_non_string_next_cursor_rejected(self):
    with pytest.raises(TypeError):
      _list_result(next_cursor=123)


# ---------------------------------------------------------------------------
# AC-28.14 — ttlMs present and >= 0; below 0 rejected. (R-18.2-h)
# ---------------------------------------------------------------------------

class TestTtlMs:
  def test_ttl_required_in_from_dict(self):
    with pytest.raises(ValueError):
      ListPromptsResult.from_dict({"prompts": [], "cacheScope": "public", "resultType": "complete"})

  def test_negative_ttl_rejected(self):
    with pytest.raises(ValueError):
      _list_result(ttl_ms=-1)

  def test_zero_and_positive_accepted(self):
    assert _list_result(ttl_ms=0).ttl_ms == 0
    assert _list_result(ttl_ms=600000).ttl_ms == 600000

  def test_boolean_ttl_rejected(self):
    with pytest.raises(ValueError):
      _list_result(ttl_ms=True)


# ---------------------------------------------------------------------------
# AC-28.15 — ttlMs == 0 => immediately stale, may re-fetch. (R-18.2-i/j)
# ---------------------------------------------------------------------------

class TestTtlMsZero:
  def test_immediately_stale_flag(self):
    assert _list_result(ttl_ms=0).is_immediately_stale is True

  def test_positive_not_immediately_stale(self):
    assert _list_result(ttl_ms=1).is_immediately_stale is False


# ---------------------------------------------------------------------------
# AC-28.16 — ttlMs positive => fresh for that many ms. (R-18.2-k)
# ---------------------------------------------------------------------------

class TestTtlMsPositive:
  def test_positive_ttl_preserved(self):
    # Freshness arithmetic itself lives in S19; here we confirm the value is
    # carried faithfully so a caching layer can apply it.
    result = _list_result(ttl_ms=600000)
    assert result.ttl_ms == 600000
    assert result.to_dict()["ttlMs"] == 600000


# ---------------------------------------------------------------------------
# AC-28.17 — cacheScope present and public/private; private not shared. (R-18.2-l/m)
# ---------------------------------------------------------------------------

class TestCacheScope:
  def test_cache_scope_required(self):
    with pytest.raises(ValueError):
      ListPromptsResult.from_dict({"prompts": [], "ttlMs": 0, "resultType": "complete"})

  def test_valid_values(self):
    assert _list_result(cache_scope=CACHE_SCOPE_PUBLIC).is_public is True
    assert _list_result(cache_scope=CACHE_SCOPE_PRIVATE).is_private is True

  def test_invalid_value_rejected(self):
    with pytest.raises(ValueError):
      _list_result(cache_scope="shared")

  def test_private_flagged_for_no_cross_user_serving(self):
    result = _list_result(cache_scope=CACHE_SCOPE_PRIVATE)
    assert result.is_private is True
    assert result.is_public is False


# ---------------------------------------------------------------------------
# AC-28.18 — resultType present "complete"; absent treated as complete. (R-18.2-n/o/p)
# ---------------------------------------------------------------------------

class TestListResultResultType:
  def test_server_includes_result_type(self):
    out = _list_result().to_dict()
    assert out["resultType"] == RESULT_TYPE_COMPLETE

  def test_absent_result_type_treated_as_complete(self):
    result = ListPromptsResult.from_dict(
      {"prompts": [], "ttlMs": 0, "cacheScope": "public"}
    )
    assert result.result_type == RESULT_TYPE_COMPLETE


# ---------------------------------------------------------------------------
# AC-28.19 — _meta optional. (R-18.2-q)
# ---------------------------------------------------------------------------

class TestListResultMeta:
  def test_meta_absent(self):
    assert "_meta" not in _list_result().to_dict()

  def test_meta_present(self):
    result = _list_result(meta={"k": "v"})
    assert result.to_dict()["_meta"] == {"k": "v"}

  def test_meta_wrong_type_rejected(self):
    with pytest.raises(TypeError):
      _list_result(meta=["nope"])


# ---------------------------------------------------------------------------
# AC-28.20 — set change informs listening clients via the notification. (R-18.2-r)
# ---------------------------------------------------------------------------

class TestListChangedOnSetChange:
  def test_capable_server_can_notify(self):
    caps = ServerCapabilities(prompts={"listChanged": True})
    assert server_may_emit_list_changed(caps) is True
    note = PromptListChangedNotification()
    assert note.method == NOTIFICATION_PROMPTS_LIST_CHANGED


# ---------------------------------------------------------------------------
# AC-28.21 — Prompt.name present; client lacking title uses name. (R-18.3-a/b)
# ---------------------------------------------------------------------------

class TestPromptNameAndTitle:
  def test_name_required(self):
    with pytest.raises(ValueError):
      Prompt(name="")
    with pytest.raises((KeyError, ValueError, TypeError)):
      Prompt.from_dict({})

  def test_display_uses_title_when_present(self):
    assert Prompt(name="code_review", title="Request Code Review").display_name() == "Request Code Review"

  def test_display_falls_back_to_name(self):
    assert Prompt(name="code_review").display_name() == "code_review"


# ---------------------------------------------------------------------------
# AC-28.22 — arguments absent/empty => accepts no arguments. (R-18.3-c)
# ---------------------------------------------------------------------------

class TestPromptArgumentsAbsentOrEmpty:
  def test_absent_arguments(self):
    p = Prompt(name="p")
    assert p.accepts_no_arguments is True
    assert "arguments" not in p.to_dict()

  def test_empty_arguments(self):
    p = Prompt(name="p", arguments=[])
    assert p.accepts_no_arguments is True

  def test_with_arguments_not_empty(self):
    p = Prompt(name="p", arguments=[PromptArgument(name="code")])
    assert p.accepts_no_arguments is False


# ---------------------------------------------------------------------------
# AC-28.23 — icons MAY be displayed; rendering MIME support is S20-owned. (R-18.3-d/e/f)
# ---------------------------------------------------------------------------

class TestPromptIcons:
  def test_prompt_carries_icons(self):
    icon = Icon(src="https://example.com/i.png", mime_type="image/png")
    p = Prompt(name="p", icons=[icon])
    assert p.to_dict()["icons"][0]["src"] == "https://example.com/i.png"

  def test_icons_round_trip_from_dict(self):
    data = {
      "name": "p",
      "icons": [{"src": "https://example.com/i.svg", "mimeType": "image/svg+xml", "sizes": ["any"]}],
    }
    p = Prompt.from_dict(data)
    assert p.icons is not None and p.icons[0].mime_type == "image/svg+xml"

  def test_non_rendering_client_may_ignore_icons(self):
    # A client that does not render simply does not read icons; the Prompt is
    # fully usable without them.
    p = Prompt.from_dict({"name": "p"})
    assert p.icons is None

  def test_icons_entries_must_be_icon(self):
    with pytest.raises(TypeError):
      Prompt(name="p", icons=["not-an-icon"])


# ---------------------------------------------------------------------------
# AC-28.24 — icon URL trust / SVG precautions (owned by S20). (R-18.3-g/h)
# ---------------------------------------------------------------------------

class TestPromptIconTrust:
  def test_same_domain_check_available_via_s20(self):
    from mcp_sdk_py.common_types import is_same_or_trusted_domain
    src = "https://peer.example/icon.png"
    assert is_same_or_trusted_domain(src, "peer.example") is True
    assert is_same_or_trusted_domain(src, "other.example") is False

  def test_svg_active_content_detection_available_via_s20(self):
    from mcp_sdk_py.common_types import svg_contains_active_content
    assert svg_contains_active_content(b"<svg><script>alert(1)</script></svg>") is True
    assert svg_contains_active_content(b"<svg><rect/></svg>") is False


# ---------------------------------------------------------------------------
# AC-28.25 — Icon.src present and an HTTP(S)/data URI (owned by S20). (R-18.3-i)
# ---------------------------------------------------------------------------

class TestPromptIconSrc:
  def test_https_src_accepted(self):
    p = Prompt(name="p", icons=[Icon(src="https://example.com/i.png")])
    assert p.icons is not None and p.icons[0].src.startswith("https://")

  def test_unsafe_scheme_rejected_by_s20(self):
    with pytest.raises(ValueError):
      Icon(src="javascript:alert(1)")


# ---------------------------------------------------------------------------
# AC-28.26 — PromptArgument.name present; lacking title uses name. (R-18.3-j/k)
# ---------------------------------------------------------------------------

class TestPromptArgumentNameAndTitle:
  def test_name_required(self):
    with pytest.raises(ValueError):
      PromptArgument(name="")

  def test_name_is_arguments_map_key(self):
    p = Prompt(name="p", arguments=[PromptArgument(name="code", required=True)])
    # The get-request arguments map is keyed by PromptArgument.name.
    validate_get_prompt_arguments(p, {"code": "x"})  # no raise

  def test_display_falls_back_to_name(self):
    assert PromptArgument(name="code").display_name() == "code"

  def test_display_uses_title(self):
    assert PromptArgument(name="code", title="Source Code").display_name() == "Source Code"


# ---------------------------------------------------------------------------
# AC-28.27 — required argument omitted => non-conformant; server -32602.
#           (R-18.3-l, R-18.3-m, R-18.4-e)
# ---------------------------------------------------------------------------

class TestRequiredArgument:
  def test_is_required_flag(self):
    assert PromptArgument(name="code", required=True).is_required is True
    assert PromptArgument(name="code").is_required is False
    assert PromptArgument(name="code", required=False).is_required is False

  def test_missing_required_rejected_with_invalid_params(self):
    p = Prompt(name="p", arguments=[PromptArgument(name="code", required=True)])
    with pytest.raises(MissingRequiredArgumentError) as exc:
      validate_get_prompt_arguments(p, {})
    assert exc.value.json_rpc_code == JSONRPC_INVALID_PARAMS
    assert exc.value.argument == "code"

  def test_missing_with_no_arguments_map_rejected(self):
    p = Prompt(name="p", arguments=[PromptArgument(name="code", required=True)])
    with pytest.raises(MissingRequiredArgumentError):
      validate_get_prompt_arguments(p, None)

  def test_supplied_required_passes(self):
    p = Prompt(name="p", arguments=[PromptArgument(name="code", required=True)])
    validate_get_prompt_arguments(p, {"code": "x"})  # no raise

  def test_optional_argument_may_be_omitted(self):
    p = Prompt(name="p", arguments=[PromptArgument(name="hint")])
    validate_get_prompt_arguments(p, {})  # no raise


# ---------------------------------------------------------------------------
# AC-28.28 — prompts/get MAY participate in a multi-round-trip exchange. (R-18.4-a)
# ---------------------------------------------------------------------------

class TestGetPromptMultiRoundTrip:
  def test_first_attempt_is_not_retry(self):
    assert GetPromptRequestParams(name="p").is_retry is False

  def test_retry_fields_carried(self):
    params = GetPromptRequestParams(
      name="p",
      input_responses={"confirm": {"action": "accept"}},
      request_state="blob",
    )
    assert params.is_retry is True
    out = params.to_dict()
    assert out["inputResponses"] == {"confirm": {"action": "accept"}}
    assert out["requestState"] == "blob"


# ---------------------------------------------------------------------------
# AC-28.29 — name present and matches an offered prompt; else -32602. (R-18.4-b/c/d)
# ---------------------------------------------------------------------------

class TestGetPromptNameMatching:
  def test_name_required(self):
    with pytest.raises(ValueError):
      GetPromptRequestParams(name="")
    with pytest.raises(ValueError):
      GetPromptRequestParams.from_dict({})

  def test_unknown_name_rejected_invalid_params(self):
    params = GetPromptRequestParams(name="nope")
    with pytest.raises(UnknownPromptError) as exc:
      resolve_prompt_for_get(params, [Prompt(name="known")])
    assert exc.value.json_rpc_code == JSONRPC_INVALID_PARAMS
    assert exc.value.name == "nope"

  def test_matching_name_resolves(self):
    params = GetPromptRequestParams(name="known")
    prompt = resolve_prompt_for_get(params, [Prompt(name="known")])
    assert prompt.name == "known"

  def test_resolve_accepts_dict_offering(self):
    params = GetPromptRequestParams(name="known")
    prompt = resolve_prompt_for_get(params, {"known": Prompt(name="known")})
    assert prompt.name == "known"


# ---------------------------------------------------------------------------
# AC-28.30 — server validates args; missing required => -32602. (R-18.4-f/g)
# ---------------------------------------------------------------------------

class TestGetPromptArgumentValidation:
  def test_resolve_validates_required_arguments(self):
    offered = [Prompt(name="p", arguments=[PromptArgument(name="code", required=True)])]
    params = GetPromptRequestParams(name="p", arguments={})
    with pytest.raises(MissingRequiredArgumentError) as exc:
      resolve_prompt_for_get(params, offered)
    assert exc.value.json_rpc_code == JSONRPC_INVALID_PARAMS

  def test_resolve_passes_with_valid_arguments(self):
    offered = [Prompt(name="p", arguments=[PromptArgument(name="code", required=True)])]
    params = GetPromptRequestParams(name="p", arguments={"code": "x"})
    assert resolve_prompt_for_get(params, offered).name == "p"


# ---------------------------------------------------------------------------
# AC-28.31 — retry inputResponses key parity with inputRequests. (R-18.4-h)
# ---------------------------------------------------------------------------

class TestRetryInputResponses:
  def test_build_retry_keys_match_input_requests(self):
    original = GetPromptRequestParams(name="p", arguments={"code": "x"})
    # Server's prior inputRequests had key "confirm"; response echoes that key.
    retry = build_get_prompt_retry(
      original,
      input_responses={"confirm": {"action": "accept"}},
      request_state="state",
    )
    assert set(retry.input_responses) == {"confirm"}
    assert retry.name == "p"
    assert retry.arguments == {"code": "x"}  # original arguments reused

  def test_retry_round_trips_to_wire(self):
    original = GetPromptRequestParams(name="code_review", arguments={"code": "def f(): pass"})
    retry = build_get_prompt_retry(
      original,
      input_responses={"confirm": {"action": "accept", "content": {"approved": True}}},
      request_state="opaque-server-state-blob",
    )
    out = retry.to_dict()
    assert out["name"] == "code_review"
    assert out["inputResponses"]["confirm"]["action"] == "accept"
    assert out["requestState"] == "opaque-server-state-blob"


# ---------------------------------------------------------------------------
# AC-28.32 — requestState echoed verbatim, opaque, unmodified. (R-18.4-i/j/k)
# ---------------------------------------------------------------------------

class TestRetryRequestState:
  def test_request_state_echoed_verbatim(self):
    blob = "opaque-server-state-blob"
    original = GetPromptRequestParams(name="p")
    retry = build_get_prompt_retry(original, input_responses={}, request_state=blob)
    assert retry.request_state == blob  # exact, unmodified
    assert retry.to_dict()["requestState"] == blob

  def test_request_state_is_opaque_string(self):
    with pytest.raises(TypeError):
      GetPromptRequestParams(name="p", request_state={"not": "a string"})

  def test_request_state_absent_when_none(self):
    retry = build_get_prompt_retry(
      GetPromptRequestParams(name="p"), input_responses={"k": {}}, request_state=None
    )
    assert "requestState" not in retry.to_dict()


# ---------------------------------------------------------------------------
# AC-28.33 — GetPromptResult.messages present (one or several). (R-18.4-l/m)
# ---------------------------------------------------------------------------

class TestGetPromptResultMessages:
  def test_messages_required(self):
    with pytest.raises(ValueError):
      GetPromptResult.from_dict({"resultType": "complete"})

  def test_single_message(self):
    result = GetPromptResult(messages=[_text_msg()])
    assert len(result.messages) == 1

  def test_several_messages(self):
    result = GetPromptResult(
      messages=[_text_msg("a", ParticipantRole.USER), _text_msg("b", ParticipantRole.ASSISTANT)]
    )
    assert len(result.messages) == 2

  def test_messages_must_be_array(self):
    with pytest.raises(TypeError):
      GetPromptResult.from_dict({"messages": {}, "resultType": "complete"})

  def test_entries_must_be_prompt_message(self):
    with pytest.raises(TypeError):
      GetPromptResult(messages=["nope"])


# ---------------------------------------------------------------------------
# AC-28.34 — resultType present "complete"; absent treated as complete. (R-18.4-n/o/p)
# ---------------------------------------------------------------------------

class TestGetPromptResultResultType:
  def test_server_includes_result_type(self):
    out = GetPromptResult(messages=[_text_msg()]).to_dict()
    assert out["resultType"] == RESULT_TYPE_COMPLETE

  def test_absent_result_type_treated_as_complete(self):
    result = GetPromptResult.from_dict(
      {"messages": [{"role": "user", "content": {"type": "text", "text": "hi"}}]}
    )
    assert result.result_type == RESULT_TYPE_COMPLETE


# ---------------------------------------------------------------------------
# AC-28.35 — input_required alternative; client inspects resultType first.
#           (R-18.4-q, R-18.4-r)
# ---------------------------------------------------------------------------

class TestInputRequiredAlternative:
  def test_is_input_required_discriminator(self):
    assert is_input_required({"resultType": RESULT_TYPE_INPUT_REQUIRED}) is True
    assert is_input_required({"resultType": RESULT_TYPE_COMPLETE}) is False
    assert is_input_required({}) is False  # absent => complete

  def test_parse_branches_to_input_required(self):
    raw = {
      "resultType": "input_required",
      "inputRequests": {"confirm": {"method": "elicitation/create"}},
      "requestState": "blob",
    }
    parsed = parse_get_prompt_response(raw)
    assert isinstance(parsed, InputRequiredResult)
    assert parsed.request_state == "blob"

  def test_parse_branches_to_complete(self):
    raw = {
      "resultType": "complete",
      "messages": [{"role": "user", "content": {"type": "text", "text": "hi"}}],
    }
    parsed = parse_get_prompt_response(raw)
    assert isinstance(parsed, GetPromptResult)
    assert parsed.messages[0].content.text == "hi"

  def test_parse_absent_result_type_is_complete(self):
    raw = {"messages": [{"role": "assistant", "content": {"type": "text", "text": "ok"}}]}
    parsed = parse_get_prompt_response(raw)
    assert isinstance(parsed, GetPromptResult)


# ---------------------------------------------------------------------------
# AC-28.36 — error mapping: unknown name & missing arg => -32602; internal => -32603.
#           (R-18.4-s)
# ---------------------------------------------------------------------------

class TestErrorModel:
  def test_unknown_name_code(self):
    assert UnknownPromptError("x").json_rpc_code == -32602

  def test_missing_argument_code(self):
    assert MissingRequiredArgumentError("a").json_rpc_code == -32602

  def test_error_code_constants(self):
    assert JSONRPC_INVALID_PARAMS == -32602
    assert JSONRPC_INTERNAL_ERROR == -32603


# ---------------------------------------------------------------------------
# AC-28.37 — PromptMessage.role present user/assistant; content one block. (R-18.5-a/b)
# ---------------------------------------------------------------------------

class TestPromptMessage:
  def test_valid_roles(self):
    assert PromptMessage(role=ParticipantRole.USER, content=TextContent(text="x")).role is ParticipantRole.USER
    assert PromptMessage(role=ParticipantRole.ASSISTANT, content=TextContent(text="x")).role is ParticipantRole.ASSISTANT

  def test_role_required_and_closed_enum(self):
    with pytest.raises(ValueError):
      PromptMessage.from_dict({"content": {"type": "text", "text": "x"}})
    with pytest.raises(ValueError):
      PromptMessage.from_dict({"role": "system", "content": {"type": "text", "text": "x"}})

  def test_content_is_single_object_not_array(self):
    with pytest.raises(TypeError):
      PromptMessage.from_dict({"role": "user", "content": [{"type": "text", "text": "x"}]})
    with pytest.raises(TypeError):
      PromptMessage(role=ParticipantRole.USER, content=[TextContent(text="x")])  # type: ignore[arg-type]

  def test_content_required(self):
    with pytest.raises(ValueError):
      PromptMessage.from_dict({"role": "user"})

  def test_valid_content_kinds_enumerated(self):
    assert VALID_PROMPT_CONTENT_TYPES == {"text", "image", "audio", "resource_link", "resource"}

  def test_each_valid_kind_accepted(self):
    img = "iVBORw0KGgo="  # valid base64
    msgs = [
      PromptMessage(role=ParticipantRole.USER, content=TextContent(text="t")),
      PromptMessage(role=ParticipantRole.USER, content=ImageContent(data=img, mime_type="image/png")),
      PromptMessage(role=ParticipantRole.USER, content=AudioContent(data=img, mime_type="audio/wav")),
      PromptMessage(role=ParticipantRole.USER, content=ResourceLink(uri="file:///a", name="a")),
      PromptMessage(
        role=ParticipantRole.USER,
        content=EmbeddedResource(resource=TextResourceContents(uri="file:///a", text="x")),
      ),
    ]
    for m in msgs:
      assert m.to_dict()["content"]["type"] in VALID_PROMPT_CONTENT_TYPES

  def test_round_trip_to_dict(self):
    m = PromptMessage(role=ParticipantRole.USER, content=TextContent(text="hi"))
    assert m.to_dict() == {"role": "user", "content": {"type": "text", "text": "hi"}}

  def test_unsupported_content_kind_rejected(self):
    with pytest.raises(TypeError):
      PromptMessage.from_dict({"role": "user", "content": {"type": "made_up"}})


# ---------------------------------------------------------------------------
# AC-28.38 — resource_link content MAY be fetched for context. (R-18.5-c)
# ---------------------------------------------------------------------------

class TestPromptMessageResourceLink:
  def test_resource_link_carried(self):
    link = ResourceLink(uri="https://example.com/doc", name="doc")
    msg = PromptMessage(role=ParticipantRole.USER, content=link)
    out = msg.to_dict()
    assert out["content"]["type"] == "resource_link"
    assert out["content"]["uri"] == "https://example.com/doc"

  def test_resource_link_parsed_from_wire(self):
    msg = PromptMessage.from_dict(
      {"role": "user", "content": {"type": "resource_link", "uri": "file:///x", "name": "x"}}
    )
    assert isinstance(msg.content, ResourceLink)
    assert msg.content.uri == "file:///x"  # client MAY fetch this uri


# ---------------------------------------------------------------------------
# AC-28.39 — listChanged:true server sends notification (exact method), optionally
#            unsubscribed; undeclared server not expected to. (R-18.6-a/b/d/g)
# ---------------------------------------------------------------------------

class TestListChangedNotification:
  def test_exact_method_string(self):
    assert NOTIFICATION_PROMPTS_LIST_CHANGED == "notifications/prompts/list_changed"
    assert PromptListChangedNotification().method == "notifications/prompts/list_changed"

  def test_bare_notification_wire_form(self):
    out = PromptListChangedNotification().to_dict()
    assert out == {"jsonrpc": "2.0", "method": "notifications/prompts/list_changed"}
    assert "id" not in out  # one-way, no id

  def test_from_dict_requires_exact_method(self):
    with pytest.raises(ValueError):
      PromptListChangedNotification.from_dict({"method": "notifications/prompts/changed"})

  def test_capable_server_may_emit_without_subscription(self):
    # No subscription state is required to construct/emit the notification.
    caps = ServerCapabilities(prompts={"listChanged": True})
    assert server_may_emit_list_changed(caps) is True

  def test_undeclared_server_not_expected_to_emit(self):
    assert server_may_emit_list_changed(ServerCapabilities(prompts={})) is False
    assert server_may_emit_list_changed(ServerCapabilities()) is False


# ---------------------------------------------------------------------------
# AC-28.40 — params, when present, carries only _meta. (R-18.6-c)
# ---------------------------------------------------------------------------

class TestListChangedNotificationParams:
  def test_meta_only_params(self):
    note = PromptListChangedNotification(meta={"trace": "abc"})
    out = note.to_dict()
    assert out["params"] == {"_meta": {"trace": "abc"}}

  def test_from_dict_accepts_meta_only_params(self):
    note = PromptListChangedNotification.from_dict(
      {"method": NOTIFICATION_PROMPTS_LIST_CHANGED, "params": {"_meta": {"x": 1}}}
    )
    assert note.meta == {"x": 1}

  def test_from_dict_rejects_non_meta_params(self):
    with pytest.raises(ValueError):
      PromptListChangedNotification.from_dict(
        {"method": NOTIFICATION_PROMPTS_LIST_CHANGED, "params": {"prompts": []}}
      )


# ---------------------------------------------------------------------------
# AC-28.41 — on receipt, client invalidates cache and MAY re-issue list. (R-18.6-e/f)
# ---------------------------------------------------------------------------

class TestClientReactionToListChanged:
  def test_invalidation_predicate(self):
    assert should_invalidate_cached_prompts(NOTIFICATION_PROMPTS_LIST_CHANGED) is True
    assert should_invalidate_cached_prompts("notifications/tools/list_changed") is False

  def test_may_reissue_list_after_invalidation(self):
    # After invalidation the client MAY re-issue prompts/list (a fresh request
    # with no cursor fetches the current set).
    assert should_invalidate_cached_prompts(NOTIFICATION_PROMPTS_LIST_CHANGED)
    fresh = ListPromptsRequestParams.from_dict(None)
    assert fresh.cursor is None


# ---------------------------------------------------------------------------
# AC-28.42 — client MAY request completions for a prompt argument value. (R-18.7-a)
# ---------------------------------------------------------------------------

class TestArgumentCompletionHook:
  def test_completion_target_identifies_prompt_and_argument(self):
    target = PromptArgumentCompletionTarget(
      prompt_name="code_review", argument_name="code", partial_value="de"
    )
    assert target.prompt_name == "code_review"
    assert target.argument_name == "code"
    assert target.partial_value == "de"

  def test_completion_method_is_completion_complete(self):
    target = PromptArgumentCompletionTarget(prompt_name="p", argument_name="a")
    assert target.completion_method == METHOD_COMPLETION_COMPLETE == "completion/complete"

  def test_required_fields_validated(self):
    with pytest.raises(ValueError):
      PromptArgumentCompletionTarget(prompt_name="", argument_name="a")
    with pytest.raises(ValueError):
      PromptArgumentCompletionTarget(prompt_name="p", argument_name="")
