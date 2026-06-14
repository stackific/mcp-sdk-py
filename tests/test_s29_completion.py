"""Tests for S29 — Completion (§19): argument autocompletion for prompts and
resource templates.

Every test class maps to one or more acceptance criteria (AC-29.x). All shapes
and behaviours are imported directly from ``mcp_sdk_py.completion``.

AC → test coverage map:
  AC-29.1  capabilities include `completions` (JSON object, baseline `{}`)
             → TestAC2901CompletionsCapability
  AC-29.2  undeclared `completions` ⇒ client must not send; server -32601
             → TestAC2902CapabilityGating
  AC-29.3  only `completion/complete`, client→server, exact case-sensitive name
             → TestAC2903MethodNameAndDirection
  AC-29.4  absent `ref` ⇒ -32602
             → TestAC2904RefRequired
  AC-29.5  variant selected by `ref.type`
             → TestAC2905RefVariantSelection
  AC-29.6  `ref.type` outside closed union ⇒ -32602
             → TestAC2906ClosedUnionRejection
  AC-29.7  missing/malformed argument/name/value ⇒ -32602
             → TestAC2907ArgumentRequired
  AC-29.8  empty seed ⇒ empty-input suggestions, no error
             → TestAC2908EmptySeed
  AC-29.9  context excludes argument.name; client populates siblings
             → TestAC2909ContextArguments
  AC-29.10 server MAY ignore context and still return a valid result
             → TestAC2910ContextMayBeIgnored
  AC-29.11 PromptReference type/name; ResourceTemplateReference type/uri
             → TestAC2911ReferenceShapes
  AC-29.12 ResourceTemplateReference.uri literal or template; name = variable
             → TestAC2912ResourceTemplateUri
  AC-29.13 result carries completion{values ranked}, optional total/hasMore
             → TestAC2913ResultShape
  AC-29.14 >100 matches ⇒ ≤100 values + hasMore true (+ optional total)
             → TestAC2914TruncationAndCap
  AC-29.15 no matches ⇒ empty values, still valid
             → TestAC2915EmptyValues
  AC-29.16 total MAY exceed values.length; omitted ⇒ unknown
             → TestAC2916TotalSemantics
  AC-29.17 omitted hasMore ⇒ treated as false
             → TestAC2917HasMoreOmitted
  AC-29.18 result has resultType "complete"; omitted ⇒ treated as "complete"
             → TestAC2918ResultType
  AC-29.19 advisory: value absent from results is not forbidden
             → TestAC2919AdvisorySemantics
  AC-29.20 non-empty seed matches; context refines
             → TestAC2920MatchingAndContext
  AC-29.21 validate inputs; rate-limit; -32603 on internal failure
             → TestAC2921RobustnessAndErrors
  AC-29.22 access control: never surface unentitled values
             → TestAC2922AccessControl
  AC-29.23 client debounce/cache; graceful empty/partial/missing-field handling
             → TestAC2923ClientBehavior
  AC-29.24 unknown prompt/template/argument ⇒ -32602 (not a not-found result)
             → TestAC2924UnknownTargets
"""

import pytest

from mcp_sdk_py.capabilities import ServerCapabilities
from mcp_sdk_py.prompts import Prompt, PromptArgument
from mcp_sdk_py.resources import ResourceTemplate
from mcp_sdk_py.completion import (
  COMPLETIONS_CAPABILITY_KEY,
  JSONRPC_INTERNAL_ERROR,
  JSONRPC_INVALID_PARAMS,
  JSONRPC_METHOD_NOT_FOUND,
  MAX_COMPLETION_VALUES,
  METHOD_COMPLETION_COMPLETE,
  REF_TYPE_PROMPT,
  REF_TYPE_RESOURCE,
  VALID_REF_TYPES,
  CompleteRequestParams,
  CompleteResult,
  Completion,
  CompletionArgument,
  CompletionContext,
  CompletionsCapability,
  CompletionsCapabilityNotDeclaredError,
  InvalidCompletionParamsError,
  PromptReference,
  Reference,
  ResourceTemplateReference,
  UnknownCompletionTargetError,
  assert_client_may_send_complete_request,
  build_complete_result,
  build_completion,
  build_completion_context,
  cap_completion_values,
  client_may_send_complete_request,
  completions_capability_declared,
  error_object_for,
  internal_error,
  invalid_params_error,
  method_not_found_error,
  parse_complete_result,
  parse_reference,
  rank_completion_candidates,
  resolve_completion_target_arguments,
)


# Vendor-neutral placeholders used across tests.
_PROMPT_NAME = "code_review"
_ARG_NAME = "framework"
_TEMPLATE_URI = "file:///{path}"


def _server_with_completions() -> ServerCapabilities:
  return ServerCapabilities.from_dict({"completions": {}})


def _server_without_completions() -> ServerCapabilities:
  return ServerCapabilities.from_dict({"prompts": {}})


def _prompt_with_args(*names: str) -> Prompt:
  return Prompt(
    name=_PROMPT_NAME,
    arguments=[PromptArgument(name=n) for n in names],
  )


# ---------------------------------------------------------------------------
# AC-29.1 — the `completions` capability (object; baseline `{}`)  (R-19.1-a/b)
# ---------------------------------------------------------------------------

class TestAC2901CompletionsCapability:
  def test_baseline_is_empty_object(self):
    assert CompletionsCapability.baseline().to_dict() == {}

  def test_from_dict_accepts_empty_object(self):
    cap = CompletionsCapability.from_dict({})
    assert cap.to_dict() == {}

  def test_from_dict_preserves_open_map_contents(self):
    cap = CompletionsCapability.from_dict({"x": 1})
    assert cap.to_dict() == {"x": 1}

  def test_capability_value_must_be_object(self):
    with pytest.raises(TypeError):
      CompletionsCapability.from_dict("not-an-object")

  def test_server_capabilities_carries_completions_as_object(self):
    caps = _server_with_completions()
    wire = caps.to_dict()
    assert COMPLETIONS_CAPABILITY_KEY in wire
    assert isinstance(wire[COMPLETIONS_CAPABILITY_KEY], dict)

  def test_declared_helper_true_when_present(self):
    assert completions_capability_declared(_server_with_completions()) is True

  def test_declared_helper_false_when_absent(self):
    assert completions_capability_declared(_server_without_completions()) is False


# ---------------------------------------------------------------------------
# AC-29.2 — gating: no capability ⇒ client must not send; server -32601
#           (R-19.1-c, R-19.1-d, R-19.5-q)
# ---------------------------------------------------------------------------

class TestAC2902CapabilityGating:
  def test_client_may_send_when_declared(self):
    assert client_may_send_complete_request(_server_with_completions()) is True

  def test_client_may_not_send_when_undeclared(self):
    assert client_may_send_complete_request(_server_without_completions()) is False

  def test_assert_raises_when_undeclared(self):
    with pytest.raises(CompletionsCapabilityNotDeclaredError):
      assert_client_may_send_complete_request(_server_without_completions())

  def test_assert_passes_when_declared(self):
    assert_client_may_send_complete_request(_server_with_completions())

  def test_method_not_found_error_code_is_32601(self):
    err = method_not_found_error()
    assert err["code"] == JSONRPC_METHOD_NOT_FOUND == -32601

  def test_method_not_found_error_names_the_method(self):
    assert METHOD_COMPLETION_COMPLETE in method_not_found_error()["message"]

  def test_capability_exception_carries_32601_code(self):
    assert CompletionsCapabilityNotDeclaredError.json_rpc_code == -32601


# ---------------------------------------------------------------------------
# AC-29.3 — only `completion/complete`, client→server, exact case  (R-19-a, R-19.2-a)
# ---------------------------------------------------------------------------

class TestAC2903MethodNameAndDirection:
  def test_method_name_is_exact_string(self):
    assert METHOD_COMPLETION_COMPLETE == "completion/complete"

  def test_method_name_is_case_sensitive(self):
    assert METHOD_COMPLETION_COMPLETE != "Completion/Complete"
    assert METHOD_COMPLETION_COMPLETE != "completion/Complete"

  def test_matches_capabilities_server_method_map(self):
    # The S10 gating map binds this exact method to the completions capability.
    from mcp_sdk_py.capabilities import SERVER_METHOD_CAPABILITIES

    assert SERVER_METHOD_CAPABILITIES[METHOD_COMPLETION_COMPLETE] == "completions"


# ---------------------------------------------------------------------------
# AC-29.4 — `ref` is REQUIRED; absent ⇒ -32602  (R-19.2-b, R-19.5-s)
# ---------------------------------------------------------------------------

class TestAC2904RefRequired:
  def test_missing_ref_raises_invalid_params(self):
    with pytest.raises(InvalidCompletionParamsError):
      CompleteRequestParams.from_dict(
        {"argument": {"name": _ARG_NAME, "value": "fla"}}
      )

  def test_invalid_params_error_code_is_32602(self):
    assert InvalidCompletionParamsError.json_rpc_code == -32602

  def test_non_object_ref_raises(self):
    with pytest.raises(InvalidCompletionParamsError):
      CompleteRequestParams.from_dict(
        {"ref": "not-an-object", "argument": {"name": _ARG_NAME, "value": ""}}
      )


# ---------------------------------------------------------------------------
# AC-29.5 — variant selected by `ref.type`  (R-19.2-c, R-19.2-d)
# ---------------------------------------------------------------------------

class TestAC2905RefVariantSelection:
  def test_ref_prompt_selects_prompt_reference(self):
    ref = parse_reference({"type": REF_TYPE_PROMPT, "name": _PROMPT_NAME})
    assert isinstance(ref, PromptReference)
    assert ref.name == _PROMPT_NAME

  def test_ref_resource_selects_template_reference(self):
    ref = parse_reference({"type": REF_TYPE_RESOURCE, "uri": _TEMPLATE_URI})
    assert isinstance(ref, ResourceTemplateReference)
    assert ref.uri == _TEMPLATE_URI

  def test_variant_chosen_strictly_by_type_not_by_payload(self):
    # A "name" key alongside ref/resource still resolves to a template ref.
    ref = parse_reference(
      {"type": REF_TYPE_RESOURCE, "uri": _TEMPLATE_URI, "name": "ignored"}
    )
    assert isinstance(ref, ResourceTemplateReference)

  def test_params_round_trip_preserves_variant(self):
    params = CompleteRequestParams.from_dict(
      {
        "ref": {"type": REF_TYPE_PROMPT, "name": _PROMPT_NAME},
        "argument": {"name": _ARG_NAME, "value": "fla"},
      }
    )
    assert isinstance(params.ref, PromptReference)
    assert params.to_dict()["ref"]["type"] == REF_TYPE_PROMPT


# ---------------------------------------------------------------------------
# AC-29.6 — closed union: other `ref.type` ⇒ -32602  (R-19.2-e, R-19.3-f, R-19.5-s)
# ---------------------------------------------------------------------------

class TestAC2906ClosedUnionRejection:
  @pytest.mark.parametrize("bad_type", ["ref/tool", "prompt", "", "REF/PROMPT", "ref/Prompt"])
  def test_unknown_type_rejected(self, bad_type):
    with pytest.raises(InvalidCompletionParamsError):
      parse_reference({"type": bad_type, "name": "x"})

  def test_missing_type_rejected(self):
    with pytest.raises(InvalidCompletionParamsError):
      parse_reference({"name": "x"})

  def test_valid_ref_types_is_exactly_two(self):
    assert VALID_REF_TYPES == frozenset({"ref/prompt", "ref/resource"})

  def test_from_dict_bad_type_is_invalid_params(self):
    with pytest.raises(InvalidCompletionParamsError):
      CompleteRequestParams.from_dict(
        {
          "ref": {"type": "ref/unknown", "name": "x"},
          "argument": {"name": _ARG_NAME, "value": ""},
        }
      )


# ---------------------------------------------------------------------------
# AC-29.7 — argument/name/value REQUIRED; missing/malformed ⇒ -32602
#           (R-19.2-f, R-19.2-g, R-19.2-h, R-19.5-s)
# ---------------------------------------------------------------------------

class TestAC2907ArgumentRequired:
  def _base(self, **arg):
    return {
      "ref": {"type": REF_TYPE_PROMPT, "name": _PROMPT_NAME},
      "argument": arg,
    }

  def test_missing_argument_object(self):
    with pytest.raises(InvalidCompletionParamsError):
      CompleteRequestParams.from_dict(
        {"ref": {"type": REF_TYPE_PROMPT, "name": _PROMPT_NAME}}
      )

  def test_missing_name(self):
    with pytest.raises(InvalidCompletionParamsError):
      CompleteRequestParams.from_dict(self._base(value="fla"))

  def test_missing_value(self):
    with pytest.raises(InvalidCompletionParamsError):
      CompleteRequestParams.from_dict(self._base(name=_ARG_NAME))

  def test_non_string_name(self):
    with pytest.raises(InvalidCompletionParamsError):
      CompleteRequestParams.from_dict(self._base(name=123, value="fla"))

  def test_non_string_value(self):
    with pytest.raises(InvalidCompletionParamsError):
      CompleteRequestParams.from_dict(self._base(name=_ARG_NAME, value=123))

  def test_non_object_argument(self):
    with pytest.raises(InvalidCompletionParamsError):
      CompleteRequestParams.from_dict(
        {
          "ref": {"type": REF_TYPE_PROMPT, "name": _PROMPT_NAME},
          "argument": "nope",
        }
      )

  def test_valid_argument_parses(self):
    arg = CompletionArgument.from_dict({"name": _ARG_NAME, "value": "fla"})
    assert arg.name == _ARG_NAME and arg.value == "fla"


# ---------------------------------------------------------------------------
# AC-29.8 — empty seed ⇒ empty-input suggestions, no error  (R-19.2-i)
# ---------------------------------------------------------------------------

class TestAC2908EmptySeed:
  def test_empty_value_is_accepted(self):
    arg = CompletionArgument.from_dict({"name": _ARG_NAME, "value": ""})
    assert arg.value == ""
    assert arg.is_empty_seed is True

  def test_params_accept_empty_seed(self):
    params = CompleteRequestParams.from_dict(
      {
        "ref": {"type": REF_TYPE_PROMPT, "name": _PROMPT_NAME},
        "argument": {"name": _ARG_NAME, "value": ""},
      }
    )
    assert params.argument.value == ""

  def test_empty_seed_ranks_all_candidates_in_order(self):
    candidates = ["python", "pytorch", "rust"]
    assert rank_completion_candidates(candidates, "") == candidates

  def test_empty_seed_does_not_raise(self):
    # An empty input yields suggestions, never an error.
    result = build_complete_result(rank_completion_candidates(["a", "b"], ""))
    assert result.completion.values == ["a", "b"]


# ---------------------------------------------------------------------------
# AC-29.9 — context excludes argument.name; client populates siblings
#           (R-19.2-j, R-19.2-k, R-19.5-m)
# ---------------------------------------------------------------------------

class TestAC2909ContextArguments:
  def test_build_context_excludes_completed_argument(self):
    ctx = build_completion_context(
      {"language": "python", _ARG_NAME: "fla"}, _ARG_NAME
    )
    assert _ARG_NAME not in (ctx.arguments or {})
    assert ctx.arguments == {"language": "python"}

  def test_build_context_with_only_self_yields_none(self):
    ctx = build_completion_context({_ARG_NAME: "fla"}, _ARG_NAME)
    assert ctx.arguments is None

  def test_params_reject_context_carrying_completed_argument(self):
    with pytest.raises(InvalidCompletionParamsError):
      CompleteRequestParams.from_dict(
        {
          "ref": {"type": REF_TYPE_PROMPT, "name": _PROMPT_NAME},
          "argument": {"name": _ARG_NAME, "value": "fla"},
          "context": {"arguments": {_ARG_NAME: "x", "language": "python"}},
        }
      )

  def test_params_accept_sibling_context(self):
    params = CompleteRequestParams.from_dict(
      {
        "ref": {"type": REF_TYPE_PROMPT, "name": _PROMPT_NAME},
        "argument": {"name": _ARG_NAME, "value": "fla"},
        "context": {"arguments": {"language": "python"}},
      }
    )
    assert params.context.arguments == {"language": "python"}

  def test_context_arguments_must_be_string_map(self):
    with pytest.raises(InvalidCompletionParamsError):
      CompletionContext.from_dict({"arguments": {"language": 5}})


# ---------------------------------------------------------------------------
# AC-29.10 — server MAY ignore context and still return a valid result
#            (R-19.2-l, R-19.5-f)
# ---------------------------------------------------------------------------

class TestAC2910ContextMayBeIgnored:
  def test_result_valid_without_consulting_context(self):
    params = CompleteRequestParams.from_dict(
      {
        "ref": {"type": REF_TYPE_PROMPT, "name": _PROMPT_NAME},
        "argument": {"name": _ARG_NAME, "value": "py"},
        "context": {"arguments": {"language": "python"}},
      }
    )
    # Server ignores params.context entirely and ranks the seed only.
    values = rank_completion_candidates(["python", "pytorch"], params.argument.value)
    result = build_complete_result(values)
    assert result.completion.values == ["python", "pytorch"]

  def test_params_without_context_are_valid(self):
    params = CompleteRequestParams.from_dict(
      {
        "ref": {"type": REF_TYPE_PROMPT, "name": _PROMPT_NAME},
        "argument": {"name": _ARG_NAME, "value": "py"},
      }
    )
    assert params.context is None


# ---------------------------------------------------------------------------
# AC-29.11 — reference shapes  (R-19.3-a/b/c/d)
# ---------------------------------------------------------------------------

class TestAC2911ReferenceShapes:
  def test_prompt_reference_type_and_name(self):
    ref = PromptReference(name=_PROMPT_NAME)
    assert ref.type == "ref/prompt"
    assert ref.name == _PROMPT_NAME

  def test_prompt_reference_title_optional(self):
    ref = PromptReference(name=_PROMPT_NAME, title="Code Review")
    assert ref.to_dict() == {"type": "ref/prompt", "name": _PROMPT_NAME, "title": "Code Review"}

  def test_prompt_reference_name_required(self):
    with pytest.raises(InvalidCompletionParamsError):
      PromptReference.from_dict({"type": "ref/prompt"})

  def test_prompt_reference_wrong_type_rejected(self):
    with pytest.raises(InvalidCompletionParamsError):
      PromptReference.from_dict({"type": "ref/resource", "name": "x"})

  def test_template_reference_type_and_uri(self):
    ref = ResourceTemplateReference(uri=_TEMPLATE_URI)
    assert ref.type == "ref/resource"
    assert ref.uri == _TEMPLATE_URI

  def test_template_reference_uri_required(self):
    with pytest.raises(InvalidCompletionParamsError):
      ResourceTemplateReference.from_dict({"type": "ref/resource"})

  def test_template_reference_wrong_type_rejected(self):
    with pytest.raises(InvalidCompletionParamsError):
      ResourceTemplateReference.from_dict({"type": "ref/prompt", "uri": "x"})

  def test_reference_union_alias_covers_both(self):
    assert PromptReference(name="x").type in VALID_REF_TYPES
    assert ResourceTemplateReference(uri="x").type in VALID_REF_TYPES


# ---------------------------------------------------------------------------
# AC-29.12 — uri literal or template; name = template variable  (R-19.3-e)
# ---------------------------------------------------------------------------

class TestAC2912ResourceTemplateUri:
  def test_literal_uri_is_not_a_template(self):
    ref = ResourceTemplateReference(uri="file:///etc/hosts")
    assert ref.is_template is False
    assert ref.template_variable_names() == set()

  def test_template_uri_exposes_variable(self):
    ref = ResourceTemplateReference(uri="file:///{path}")
    assert ref.is_template is True
    assert ref.template_variable_names() == {"path"}

  def test_multiple_variables_extracted(self):
    ref = ResourceTemplateReference(uri="https://api/{owner}/{repo}/{path}")
    assert ref.template_variable_names() == {"owner", "repo", "path"}

  def test_rfc6570_operators_and_modifiers_stripped(self):
    ref = ResourceTemplateReference(uri="https://api{?owner,repo}/{path*}{/seg:3}")
    assert ref.template_variable_names() == {"owner", "repo", "path", "seg"}

  def test_argument_name_resolves_against_inline_template(self):
    ref = ResourceTemplateReference(uri="file:///{path}")
    # "path" is a valid variable; no registry needed (inline template).
    resolve_completion_target_arguments(ref, "path")

  def test_unknown_inline_variable_rejected(self):
    ref = ResourceTemplateReference(uri="file:///{path}")
    with pytest.raises(UnknownCompletionTargetError):
      resolve_completion_target_arguments(ref, "nope")


# ---------------------------------------------------------------------------
# AC-29.13 — result shape: completion{values ranked}, optional total/hasMore
#            (R-19.4-a, R-19.4-b, R-19.5-c)
# ---------------------------------------------------------------------------

class TestAC2913ResultShape:
  def test_result_carries_completion_with_values(self):
    result = CompleteResult(completion=Completion(values=["python", "pytorch"]))
    assert result.completion.values == ["python", "pytorch"]

  def test_completion_required_in_result(self):
    with pytest.raises(ValueError):
      CompleteResult.from_dict({"resultType": "complete"})

  def test_values_required_in_completion(self):
    with pytest.raises(ValueError):
      Completion.from_dict({})

  def test_ranking_is_relevance_ordered(self):
    # Prefix matches outrank later substring matches.
    ranked = rank_completion_candidates(["mypytorch", "python", "pytorch"], "py")
    assert ranked == ["python", "pytorch", "mypytorch"]

  def test_optional_total_and_has_more_round_trip(self):
    result = CompleteResult.from_dict(
      {
        "resultType": "complete",
        "completion": {"values": ["a"], "total": 5, "hasMore": True},
      }
    )
    assert result.completion.total == 5
    assert result.completion.has_more is True


# ---------------------------------------------------------------------------
# AC-29.14 — cap at 100 + signal truncation via hasMore  (R-19.4-c/d/e/f, R-19.5-g/h)
# ---------------------------------------------------------------------------

class TestAC2914TruncationAndCap:
  def test_cap_constant_is_100(self):
    assert MAX_COMPLETION_VALUES == 100

  def test_values_over_100_rejected_by_completion(self):
    with pytest.raises(ValueError):
      Completion(values=[f"v{i}" for i in range(101)])

  def test_exactly_100_allowed(self):
    comp = Completion(values=[f"v{i}" for i in range(100)])
    assert len(comp.values) == 100

  def test_cap_helper_truncates_and_flags(self):
    capped, truncated = cap_completion_values([f"v{i}" for i in range(150)])
    assert len(capped) == 100
    assert truncated is True

  def test_build_completion_sets_has_more_on_truncation(self):
    comp = build_completion([f"v{i}" for i in range(150)], total=150)
    assert len(comp.values) == 100
    assert comp.has_more is True
    assert comp.total == 150

  def test_build_completion_no_truncation_leaves_has_more_unset(self):
    comp = build_completion(["a", "b"])
    assert comp.has_more is None
    assert comp.effective_has_more is False

  def test_from_dict_rejects_oversized_array(self):
    with pytest.raises(ValueError):
      Completion.from_dict({"values": [f"v{i}" for i in range(101)]})


# ---------------------------------------------------------------------------
# AC-29.15 — no matches ⇒ empty values, still valid  (R-19.4-g)
# ---------------------------------------------------------------------------

class TestAC2915EmptyValues:
  def test_empty_values_is_valid(self):
    comp = Completion(values=[])
    assert comp.values == []

  def test_empty_result_round_trips(self):
    result = build_complete_result([])
    wire = result.to_dict()
    assert wire["completion"]["values"] == []
    assert wire["resultType"] == "complete"

  def test_no_match_seed_yields_empty(self):
    values = rank_completion_candidates(["python", "rust"], "zzz")
    assert values == []


# ---------------------------------------------------------------------------
# AC-29.16 — total MAY exceed values.length; omitted ⇒ unknown  (R-19.4-h)
# ---------------------------------------------------------------------------

class TestAC2916TotalSemantics:
  def test_total_may_exceed_values_length(self):
    comp = Completion(values=["a", "b"], total=10)
    assert comp.total == 10 > len(comp.values)

  def test_total_omitted_is_none(self):
    comp = Completion.from_dict({"values": ["a"]})
    assert comp.total is None

  def test_negative_total_rejected(self):
    with pytest.raises(ValueError):
      Completion(values=[], total=-1)

  def test_total_omitted_from_wire_when_none(self):
    assert "total" not in Completion(values=["a"]).to_dict()


# ---------------------------------------------------------------------------
# AC-29.17 — omitted hasMore ⇒ treated as false  (R-19.4-i)
# ---------------------------------------------------------------------------

class TestAC2917HasMoreOmitted:
  def test_omitted_has_more_is_none(self):
    comp = Completion.from_dict({"values": ["a"]})
    assert comp.has_more is None

  def test_effective_has_more_false_when_omitted(self):
    comp = Completion.from_dict({"values": ["a"]})
    assert comp.effective_has_more is False

  def test_effective_has_more_true_when_set(self):
    comp = Completion.from_dict({"values": ["a"], "hasMore": True})
    assert comp.effective_has_more is True

  def test_has_more_omitted_from_wire_when_none(self):
    assert "hasMore" not in Completion(values=["a"]).to_dict()


# ---------------------------------------------------------------------------
# AC-29.18 — resultType "complete"; omitted ⇒ treated as "complete"
#            (R-19.4-j, R-19.4-k, R-19.4-l)
# ---------------------------------------------------------------------------

class TestAC2918ResultType:
  def test_default_result_type_is_complete(self):
    result = CompleteResult(completion=Completion(values=[]))
    assert result.result_type == "complete"

  def test_to_dict_includes_result_type(self):
    wire = CompleteResult(completion=Completion(values=[])).to_dict()
    assert wire["resultType"] == "complete"

  def test_omitted_result_type_treated_as_complete(self):
    result = parse_complete_result({"completion": {"values": ["a"]}})
    assert result.result_type == "complete"

  def test_explicit_result_type_preserved(self):
    result = parse_complete_result(
      {"resultType": "complete", "completion": {"values": ["a"]}}
    )
    assert result.result_type == "complete"


# ---------------------------------------------------------------------------
# AC-29.19 — advisory: a value absent from results is not forbidden  (R-19.5-a/b)
# ---------------------------------------------------------------------------

class TestAC2919AdvisorySemantics:
  def test_value_absent_from_results_still_submittable(self):
    # The matcher surfaces a small set; an unsurfaced value is not "invalid".
    ranked = rank_completion_candidates(["python"], "ja")
    assert "java" not in ranked
    # Submitting "java" is a normal CompletionArgument, never rejected here.
    arg = CompletionArgument(name=_ARG_NAME, value="java")
    assert arg.value == "java"

  def test_completion_does_not_constrain_membership(self):
    # An empty result does not forbid any value; values stay free-form strings.
    result = build_complete_result([])
    assert result.completion.values == []
    assert CompletionArgument(name=_ARG_NAME, value="anything").value == "anything"


# ---------------------------------------------------------------------------
# AC-29.20 — non-empty seed matches; context refines  (R-19.5-d, R-19.5-e)
# ---------------------------------------------------------------------------

class TestAC2920MatchingAndContext:
  def test_prefix_match_against_seed(self):
    ranked = rank_completion_candidates(["python", "pytorch", "rust"], "py")
    assert ranked == ["python", "pytorch"]

  def test_substring_match_against_seed(self):
    ranked = rank_completion_candidates(["mypy", "rust"], "py")
    assert ranked == ["mypy"]

  def test_match_is_case_insensitive(self):
    ranked = rank_completion_candidates(["Python", "Rust"], "py")
    assert ranked == ["Python"]

  def test_context_refines_candidate_universe(self):
    # A server uses context.arguments to choose which candidates to rank.
    params = CompleteRequestParams.from_dict(
      {
        "ref": {"type": REF_TYPE_PROMPT, "name": _PROMPT_NAME},
        "argument": {"name": _ARG_NAME, "value": "p"},
        "context": {"arguments": {"language": "python"}},
      }
    )
    universe = (
      ["python", "pytorch", "pyside"]
      if params.context.arguments.get("language") == "python"
      else ["spring", "rails"]
    )
    ranked = rank_completion_candidates(universe, params.argument.value)
    assert ranked == ["python", "pytorch", "pyside"]


# ---------------------------------------------------------------------------
# AC-29.21 — validate inputs; rate-limit; -32603 on internal failure
#            (R-19.5-i, R-19.5-j, R-19.5-t)
# ---------------------------------------------------------------------------

class TestAC2921RobustnessAndErrors:
  def test_internal_error_code_is_32603(self):
    assert internal_error()["code"] == JSONRPC_INTERNAL_ERROR == -32603

  def test_input_validation_rejects_malformed_params(self):
    with pytest.raises(InvalidCompletionParamsError):
      CompleteRequestParams.from_dict({"ref": {}, "argument": {}})

  def test_arbitrary_exception_maps_to_internal_error(self):
    err = error_object_for(RuntimeError("matcher exploded"))
    assert err["code"] == -32603

  def test_rate_limit_failure_surfaces_as_internal_error(self):
    # A server's rate limiter signals overload via an internal failure path.
    class _RateLimited(RuntimeError):
      pass

    err = error_object_for(_RateLimited("too many requests"))
    assert err["code"] == JSONRPC_INTERNAL_ERROR


# ---------------------------------------------------------------------------
# AC-29.22 — access control: never surface unentitled values  (R-19.5-k, R-19.5-l)
# ---------------------------------------------------------------------------

class TestAC2922AccessControl:
  def test_unentitled_values_filtered_before_ranking(self):
    universe = ["public-a", "public-b", "secret-x"]
    entitled = {"public-a", "public-b"}
    visible = [v for v in universe if v in entitled]
    result = build_complete_result(rank_completion_candidates(visible, ""))
    assert "secret-x" not in result.completion.values
    assert result.completion.values == ["public-a", "public-b"]

  def test_secret_never_appears_even_on_matching_seed(self):
    universe = ["secret-token"]
    entitled = set()  # requester is entitled to nothing
    visible = [v for v in universe if v in entitled]
    result = build_complete_result(rank_completion_candidates(visible, "sec"))
    assert result.completion.values == []


# ---------------------------------------------------------------------------
# AC-29.23 — client debounce/cache; graceful empty/partial/missing-field
#            (R-19.5-n, R-19.5-o, R-19.5-p)
# ---------------------------------------------------------------------------

class TestAC2923ClientBehavior:
  def test_parse_missing_total_and_has_more_gracefully(self):
    result = parse_complete_result({"completion": {"values": []}})
    assert result.completion.values == []
    assert result.completion.total is None
    assert result.completion.effective_has_more is False

  def test_parse_partial_result_with_only_values(self):
    result = parse_complete_result({"completion": {"values": ["a", "b"]}})
    assert result.completion.values == ["a", "b"]

  def test_client_can_cache_result_by_seed(self):
    # A simple debounce/cache keyed on (argument.name, seed) — results are reusable.
    cache: dict[tuple[str, str], CompleteResult] = {}
    key = (_ARG_NAME, "py")
    cache[key] = build_complete_result(["python", "pytorch"])
    assert cache[key].completion.values == ["python", "pytorch"]

  def test_missing_field_does_not_raise(self):
    # Omitted resultType + omitted total/hasMore must parse without error.
    parse_complete_result({"completion": {"values": ["x"]}})


# ---------------------------------------------------------------------------
# AC-29.24 — unknown prompt/template/argument ⇒ -32602 (not a not-found result)
#            (R-19.5-r)
# ---------------------------------------------------------------------------

class TestAC2924UnknownTargets:
  def test_unknown_prompt_name_is_invalid_params(self):
    ref = PromptReference(name="nonexistent")
    with pytest.raises(UnknownCompletionTargetError) as exc:
      resolve_completion_target_arguments(
        ref, _ARG_NAME, prompts=[_prompt_with_args(_ARG_NAME)]
      )
    assert exc.value.json_rpc_code == -32602

  def test_unknown_prompt_argument_is_invalid_params(self):
    ref = PromptReference(name=_PROMPT_NAME)
    with pytest.raises(UnknownCompletionTargetError):
      resolve_completion_target_arguments(
        ref, "not-an-arg", prompts=[_prompt_with_args(_ARG_NAME)]
      )

  def test_known_prompt_argument_resolves(self):
    ref = PromptReference(name=_PROMPT_NAME)
    resolve_completion_target_arguments(
      ref, _ARG_NAME, prompts={_PROMPT_NAME: _prompt_with_args(_ARG_NAME)}
    )

  def test_unknown_template_uri_is_invalid_params(self):
    ref = ResourceTemplateReference(uri="file:///{other}")
    templates = [ResourceTemplate(uri_template=_TEMPLATE_URI, name="files")]
    with pytest.raises(UnknownCompletionTargetError):
      resolve_completion_target_arguments(ref, "path", templates=templates)

  def test_unknown_template_variable_is_invalid_params(self):
    ref = ResourceTemplateReference(uri=_TEMPLATE_URI)
    templates = [ResourceTemplate(uri_template=_TEMPLATE_URI, name="files")]
    with pytest.raises(UnknownCompletionTargetError):
      resolve_completion_target_arguments(ref, "nope", templates=templates)

  def test_known_template_variable_resolves(self):
    ref = ResourceTemplateReference(uri=_TEMPLATE_URI)
    templates = [ResourceTemplate(uri_template=_TEMPLATE_URI, name="files")]
    resolve_completion_target_arguments(ref, "path", templates=templates)

  def test_unknown_target_maps_to_minus_32602_error_object(self):
    err = error_object_for(UnknownCompletionTargetError("Unknown prompt: x"))
    assert err["code"] == -32602

  def test_invalid_params_error_helper_code(self):
    assert invalid_params_error("bad")["code"] == JSONRPC_INVALID_PARAMS


# ---------------------------------------------------------------------------
# Reference alias sanity: the union alias is exported and usable as a type hint.
# ---------------------------------------------------------------------------

class TestReferenceAlias:
  def test_reference_alias_accepts_both_variants(self):
    refs: list[Reference] = [PromptReference(name="x"), ResourceTemplateReference(uri="y")]
    assert {type(r).__name__ for r in refs} == {
      "PromptReference",
      "ResourceTemplateReference",
    }
