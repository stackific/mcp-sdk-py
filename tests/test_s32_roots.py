"""Tests for S32 — Roots (Deprecated).

Exercises the ``roots`` client capability shape, its gating rules, the
``roots/list`` input request, the ``ListRootsResult`` / ``Root`` types, and the
client-consent / server-non-enforcement obligations defined in §21.1.

AC → test coverage map
----------------------
AC-32.1  (R-21-a, R-21.1-a, R-21.1.1-a, R-21.1.1-b) → TestAC321MigrationGuidance
AC-32.2  (R-21.1.1-c)                                → TestAC322HonorsWireContract
AC-32.3  (R-21.1.2-a)                                → TestAC323CapabilityValueShape
AC-32.4  (R-21.1.2-b)                                → TestAC324IgnoreUnknownMembers
AC-32.5  (R-21.1.2-c)                                → TestAC325NoListChanged
AC-32.6  (R-21.1.2-d, R-21.1.2-e)                    → TestAC326GatingUndeclared
AC-32.7  (R-21.1.3-a)                                → TestAC327DeliveredViaInputRequired
AC-32.8  (R-21.1.4-a)                                → TestAC328MethodDiscriminator
AC-32.9  (R-21.1.4-b, R-21.1.4-c)                    → TestAC329Params
AC-32.10 (R-21.1.5-a)                                → TestAC3210ListRootsResultRoots
AC-32.11 (R-21.1.5-b, R-21.1.5-d)                    → TestAC3211RootUriValidation
AC-32.12 (R-21.1.5-c)                                → TestAC3212NonFileSchemeRejectOrIgnore
AC-32.13 (R-21.1.5-e)                                → TestAC3213RootName
AC-32.14 (R-21.1.5-f)                                → TestAC3214IgnoreUnknownMeta
AC-32.15 (R-21.1.5-g, R-21.1.5-h)                    → TestAC3215ConsentAndInScope
AC-32.16 (R-21.1.5-i)                                → TestAC3216TraversalGuard
AC-32.17 (R-21.1.5-j)                                → TestAC3217ToleranceOfUnavailable
AC-32.18 (R-21.1.5-k, R-21.1.5-l)                    → TestAC3218ServerNonEnforcement
"""

import warnings

import pytest

from mcp_sdk_py.multi_round_trip import INPUT_REQUEST_ROOTS
from mcp_sdk_py.roots import (
  RECOMMENDED_MIGRATION_MECHANISMS,
  ROOTS_CAPABILITY_NAME,
  ROOTS_EARLIEST_REMOVAL,
  ROOTS_FEATURE_NAME,
  ROOTS_HAS_LIST_CHANGED,
  ROOTS_IS_DEPRECATED,
  ROOTS_LIST_METHOD,
  ROOTS_MIGRATION_NOTE,
  InvalidRootURIError,
  ListRootsRequest,
  ListRootsResult,
  Root,
  RootsCapabilityNotDeclaredError,
  RootsConsentError,
  assemble_listing,
  assert_server_may_request_roots,
  canonical_roots_capability_value,
  protocol_enforces_root_boundaries,
  recommended_migration_mechanisms,
  root_uri_is_file_scheme,
  roots_capability_declared,
  server_may_request_roots,
  server_proceed_without_roots,
  server_should_tolerate_unavailable_root,
  server_validates_derived_paths,
  validate_root_uri,
  validate_roots_capability_value,
  warn_roots_deprecated,
)


# ---------------------------------------------------------------------------
# AC-32.1 — roots is NOT adopted for new functionality; migration mechanisms are
# tool input parameters, resource URIs, or server configuration; roots support
# exists only for interoperability. (R-21-a, R-21.1-a, R-21.1.1-a, R-21.1.1-b)
# ---------------------------------------------------------------------------

class TestAC321MigrationGuidance:
  def test_roots_is_marked_deprecated(self):
    assert ROOTS_IS_DEPRECATED is True

  def test_recommended_mechanisms_are_the_three_non_roots_paths(self):
    mechs = recommended_migration_mechanisms()
    assert mechs == RECOMMENDED_MIGRATION_MECHANISMS
    assert mechs == ("tool input parameters", "resource URIs", "server configuration")

  def test_no_recommended_mechanism_is_roots(self):
    assert all("root" not in m.lower() for m in recommended_migration_mechanisms())

  def test_migration_note_points_away_from_roots(self):
    note = ROOTS_MIGRATION_NOTE.lower()
    assert "tool input parameters" in note
    assert "resource uris" in note
    assert "server configuration" in note

  def test_warn_emits_deprecation_warning(self):
    with pytest.warns(DeprecationWarning) as record:
      warn_roots_deprecated()
    assert any(ROOTS_FEATURE_NAME in str(w.message) for w in record)
    assert any(ROOTS_EARLIEST_REMOVAL in str(w.message) for w in record)


# ---------------------------------------------------------------------------
# AC-32.2 — a well-formed roots exchange is honored end-to-end despite the
# Deprecated status (declaration, request, result). (R-21.1.1-c)
# ---------------------------------------------------------------------------

class TestAC322HonorsWireContract:
  def test_full_exchange_round_trips_despite_deprecation(self):
    # Declaration: canonical {} is a valid declared capability.
    caps = {ROOTS_CAPABILITY_NAME: canonical_roots_capability_value()}
    assert roots_capability_declared(caps)
    # Request: the server's embedded roots/list input request.
    req = ListRootsRequest.from_dict({"method": "roots/list"})
    assert req.method == "roots/list"
    # Result: the client's listing supplied on retry.
    result = ListRootsResult.from_dict(
      {"roots": [{"uri": "file:///home/user/project", "name": "Project"}]}
    )
    assert result.roots[0].uri == "file:///home/user/project"
    # The deprecated capability is still fully honored on the wire.
    assert req.to_dict() == {"method": "roots/list"}
    assert result.to_dict() == {
      "roots": [{"uri": "file:///home/user/project", "name": "Project"}]
    }

  def test_deprecation_does_not_change_wire_form(self):
    # Emitting a deprecation warning never mutates the result it accompanies.
    with warnings.catch_warnings():
      warnings.simplefilter("ignore")
      warn_roots_deprecated()
    result = ListRootsResult.from_dict({"roots": []})
    assert result.to_dict() == {"roots": []}


# ---------------------------------------------------------------------------
# AC-32.3 — roots value is a JSON object whose canonical form is {}; a non-object
# value is invalid. (R-21.1.2-a)
# ---------------------------------------------------------------------------

class TestAC323CapabilityValueShape:
  def test_canonical_value_is_empty_object(self):
    assert canonical_roots_capability_value() == {}

  def test_empty_object_validates(self):
    assert validate_roots_capability_value({}) == {}

  def test_object_value_validates(self):
    assert validate_roots_capability_value({"x": 1}) == {"x": 1}

  @pytest.mark.parametrize("bad", [[], "", "{}", 0, 1, 1.5, True, False, None])
  def test_non_object_value_is_invalid(self, bad):
    with pytest.raises(TypeError):
      validate_roots_capability_value(bad)


# ---------------------------------------------------------------------------
# AC-32.4 — unrecognized members of the roots capability are ignored; the
# capability is still treated as declared (not rejected). (R-21.1.2-b)
# ---------------------------------------------------------------------------

class TestAC324IgnoreUnknownMembers:
  def test_unknown_members_do_not_reject_capability(self):
    value = {"listChanged": True, "future": {"x": 1}}
    # Validation accepts it (returns it unchanged) rather than rejecting.
    assert validate_roots_capability_value(value) == value

  def test_capability_with_unknown_members_is_still_declared(self):
    caps = {ROOTS_CAPABILITY_NAME: {"somethingNew": 1}}
    assert roots_capability_declared(caps)
    assert server_may_request_roots(caps)


# ---------------------------------------------------------------------------
# AC-32.5 — no listChanged sub-flag; clients do not rely on a listChanged-style
# mechanism for roots. (R-21.1.2-c)
# ---------------------------------------------------------------------------

class TestAC325NoListChanged:
  def test_no_list_changed_flag_defined(self):
    assert ROOTS_HAS_LIST_CHANGED is False

  def test_list_changed_member_is_ignored_not_a_subflag(self):
    # Even if a peer sends listChanged, it is just an ignored unknown member;
    # presence of the capability key alone is what signals support.
    caps = {ROOTS_CAPABILITY_NAME: {"listChanged": True}}
    assert roots_capability_declared(caps)
    # The value still validates as a plain object — listChanged is not honored.
    assert validate_roots_capability_value(caps[ROOTS_CAPABILITY_NAME]) == {"listChanged": True}


# ---------------------------------------------------------------------------
# AC-32.6 — a server does NOT request roots from a client that did not declare
# the capability, and instead proceeds without roots. (R-21.1.2-d, R-21.1.2-e)
# ---------------------------------------------------------------------------

class TestAC326GatingUndeclared:
  def test_declared_client_may_be_asked(self):
    caps = {ROOTS_CAPABILITY_NAME: {}}
    assert server_may_request_roots(caps) is True
    assert server_proceed_without_roots(caps) is False
    # assert helper does not raise when declared.
    assert_server_may_request_roots(caps)

  def test_undeclared_client_may_not_be_asked(self):
    caps = {"elicitation": {}}  # roots absent
    assert server_may_request_roots(caps) is False
    assert roots_capability_declared(caps) is False

  def test_undeclared_means_proceed_without_roots(self):
    assert server_proceed_without_roots({}) is True

  def test_assert_raises_for_undeclared_client(self):
    with pytest.raises(RootsCapabilityNotDeclaredError):
      assert_server_may_request_roots({})

  def test_non_dict_capabilities_not_declared(self):
    assert roots_capability_declared(None) is False  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# AC-32.7 — roots are requested via an input-required result whose embedded
# input request method is "roots/list", not a server-initiated JSON-RPC request;
# the client supplies them by retrying. (R-21.1.3-a)
# ---------------------------------------------------------------------------

class TestAC327DeliveredViaInputRequired:
  def test_method_matches_the_mrtr_recognized_kind(self):
    # The roots/list method is the same constant S17 registers as a recognized
    # input-request kind — confirming delivery is via the MRTR input-required
    # mechanism, not a dedicated JSON-RPC roots request.
    assert ROOTS_LIST_METHOD == INPUT_REQUEST_ROOTS == "roots/list"

  def test_input_request_envelope_carries_roots_list_method(self):
    req = ListRootsRequest()
    assert req.method == "roots/list"
    assert req.to_dict() == {"method": "roots/list"}


# ---------------------------------------------------------------------------
# AC-32.8 — roots/list method is present, a string, exactly "roots/list"; a
# differing-case value (e.g. "Roots/List") is invalid. (R-21.1.4-a)
# ---------------------------------------------------------------------------

class TestAC328MethodDiscriminator:
  def test_exact_method_accepted(self):
    assert ListRootsRequest.from_dict({"method": "roots/list"}).method == "roots/list"

  @pytest.mark.parametrize("bad", ["Roots/List", "ROOTS/LIST", "roots/List", "roots_list", "roots/"])
  def test_wrong_case_or_spelling_is_invalid(self, bad):
    with pytest.raises(ValueError):
      ListRootsRequest.from_dict({"method": bad})

  def test_missing_method_is_invalid(self):
    with pytest.raises(ValueError):
      ListRootsRequest.from_dict({})

  def test_non_string_method_is_invalid(self):
    with pytest.raises(TypeError):
      ListRootsRequest.from_dict({"method": 123})

  def test_constructor_default_is_roots_list(self):
    assert ListRootsRequest().method == "roots/list"


# ---------------------------------------------------------------------------
# AC-32.9 — params carries no roots-specific members and MAY carry only _meta;
# absent params is still accepted. (R-21.1.4-b, R-21.1.4-c)
# ---------------------------------------------------------------------------

class TestAC329Params:
  def test_absent_params_is_tolerated(self):
    req = ListRootsRequest.from_dict({"method": "roots/list"})
    assert req.params is None
    assert "params" not in req.to_dict()

  def test_params_may_carry_meta(self):
    req = ListRootsRequest.from_dict(
      {"method": "roots/list", "params": {"_meta": {"com.example/x": 1}}}
    )
    assert req.params == {"_meta": {"com.example/x": 1}}
    assert req.to_dict()["params"] == {"_meta": {"com.example/x": 1}}

  def test_empty_params_object_is_accepted(self):
    req = ListRootsRequest.from_dict({"method": "roots/list", "params": {}})
    assert req.params == {}

  def test_non_object_params_is_invalid(self):
    with pytest.raises(TypeError):
      ListRootsRequest.from_dict({"method": "roots/list", "params": []})


# ---------------------------------------------------------------------------
# AC-32.10 — ListRootsResult requires a roots array; missing roots is invalid;
# roots: [] is accepted as "no roots exposed". (R-21.1.5-a)
# ---------------------------------------------------------------------------

class TestAC3210ListRootsResultRoots:
  def test_missing_roots_is_invalid(self):
    with pytest.raises(ValueError):
      ListRootsResult.from_dict({})

  def test_empty_array_is_no_roots_exposed(self):
    result = ListRootsResult.from_dict({"roots": []})
    assert result.roots == []
    assert result.is_empty is True
    assert result.to_dict() == {"roots": []}

  def test_non_array_roots_is_invalid(self):
    with pytest.raises(TypeError):
      ListRootsResult.from_dict({"roots": {}})

  def test_populated_array_round_trips(self):
    data = {"roots": [{"uri": "file:///a"}, {"uri": "file:///b", "name": "B"}]}
    result = ListRootsResult.from_dict(data)
    assert len(result.roots) == 2
    assert result.is_empty is False
    assert result.to_dict() == {
      "roots": [{"uri": "file:///a"}, {"uri": "file:///b", "name": "B"}]
    }

  def test_empty_result_always_serializes_roots_key(self):
    assert ListRootsResult().to_dict() == {"roots": []}


# ---------------------------------------------------------------------------
# AC-32.11 — Root.uri is present, a string beginning with file://, and a valid
# RFC 3986 URI; missing/non-file/malformed fails client-side validation.
# (R-21.1.5-b, R-21.1.5-d)
# ---------------------------------------------------------------------------

class TestAC3211RootUriValidation:
  def test_valid_file_uri_accepted(self):
    assert validate_root_uri("file:///home/user/project") == "file:///home/user/project"
    root = Root(uri="file:///home/user/project")
    assert root.uri == "file:///home/user/project"

  def test_missing_uri_is_invalid(self):
    with pytest.raises(ValueError):
      Root.from_dict({"name": "no uri"})

  @pytest.mark.parametrize("bad", [None, 123, [], {}, True])
  def test_non_string_uri_is_invalid(self, bad):
    with pytest.raises(InvalidRootURIError):
      validate_root_uri(bad)

  @pytest.mark.parametrize(
    "bad",
    [
      "http://example.com/x",
      "https://example.com/x",
      "/home/user/project",
      "ftp://host/path",
      "file:relative",
      "",
    ],
  )
  def test_non_file_or_missing_scheme_fails_client_validation(self, bad):
    with pytest.raises(InvalidRootURIError):
      validate_root_uri(bad)

  def test_malformed_uri_fails_rfc3986(self):
    # An invalid port makes urlsplit raise — caught and surfaced as invalid.
    with pytest.raises(InvalidRootURIError):
      validate_root_uri("file://host:notaport/path")

  def test_root_constructor_validates_uri_by_default(self):
    with pytest.raises(InvalidRootURIError):
      Root(uri="https://example.com/x")


# ---------------------------------------------------------------------------
# AC-32.12 — a Root whose uri is not file-scheme MAY be either rejected or
# ignored by a receiver; both are conformant. (R-21.1.5-c)
# ---------------------------------------------------------------------------

class TestAC3212NonFileSchemeRejectOrIgnore:
  def test_reject_path_validates_uri_and_raises(self):
    with pytest.raises(InvalidRootURIError):
      Root.from_dict({"uri": "http://example.com/x"})

  def test_ignore_path_predicate_flags_non_file(self):
    assert root_uri_is_file_scheme("http://example.com/x") is False
    assert root_uri_is_file_scheme("file:///ok") is True

  def test_ignore_path_can_construct_without_validation(self):
    # A tolerant receiver may carry a non-file root rather than reject it.
    root = Root.from_dict({"uri": "http://example.com/x"}, validate=False)
    assert root.uri == "http://example.com/x"
    assert root_uri_is_file_scheme(root.uri) is False

  def test_result_can_ignore_non_file_roots_when_not_validating(self):
    result = ListRootsResult.from_dict(
      {"roots": [{"uri": "file:///ok"}, {"uri": "http://x/y"}]}, validate=False
    )
    file_roots = [r for r in result.roots if root_uri_is_file_scheme(r.uri)]
    assert len(file_roots) == 1


# ---------------------------------------------------------------------------
# AC-32.13 — Root.name is an optional human-readable string; when absent no
# display name is implied (the root is still valid). (R-21.1.5-e)
# ---------------------------------------------------------------------------

class TestAC3213RootName:
  def test_name_present_is_string(self):
    root = Root.from_dict({"uri": "file:///a", "name": "My Project"})
    assert root.name == "My Project"
    assert root.has_display_name is True

  def test_name_absent_is_valid_no_display_name(self):
    root = Root.from_dict({"uri": "file:///a"})
    assert root.name is None
    assert root.has_display_name is False
    assert "name" not in root.to_dict()

  def test_non_string_name_is_invalid(self):
    with pytest.raises(TypeError):
      Root(uri="file:///a", name=123)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# AC-32.14 — unrecognized Root._meta members are ignored, not cause for failure.
# (R-21.1.5-f)
# ---------------------------------------------------------------------------

class TestAC3214IgnoreUnknownMeta:
  def test_unknown_meta_members_are_carried_not_interpreted(self):
    root = Root.from_dict(
      {"uri": "file:///a", "_meta": {"com.vendor/unknown": {"deep": [1, 2]}}}
    )
    # Carried verbatim, never interpreted; round-trips unchanged.
    assert root.meta == {"com.vendor/unknown": {"deep": [1, 2]}}
    assert root.to_dict()["_meta"] == {"com.vendor/unknown": {"deep": [1, 2]}}

  def test_meta_absent_is_fine(self):
    root = Root.from_dict({"uri": "file:///a"})
    assert root.meta is None
    assert "_meta" not in root.to_dict()

  def test_unknown_top_level_keys_are_tolerated(self):
    root = Root.from_dict({"uri": "file:///a", "futureField": 7})
    assert root.uri == "file:///a"

  def test_non_object_meta_is_invalid(self):
    with pytest.raises(TypeError):
      Root(uri="file:///a", meta=[1, 2])  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# AC-32.15 — a client exposes only in-scope roots and obtains user consent
# before exposing them. (R-21.1.5-g, R-21.1.5-h)
# ---------------------------------------------------------------------------

class TestAC3215ConsentAndInScope:
  def test_consent_required_to_assemble(self):
    roots = [Root(uri="file:///home/user/project")]
    with pytest.raises(RootsConsentError):
      assemble_listing(roots, user_consented=False)

  def test_consented_listing_contains_only_supplied_roots(self):
    roots = [Root(uri="file:///a"), Root(uri="file:///b")]
    result = assemble_listing(roots, user_consented=True)
    assert [r.uri for r in result.roots] == ["file:///a", "file:///b"]

  def test_empty_in_scope_set_yields_empty_listing(self):
    result = assemble_listing([], user_consented=True)
    assert result.to_dict() == {"roots": []}


# ---------------------------------------------------------------------------
# AC-32.16 — a client guards against path-traversal artifacts before exposing.
# (R-21.1.5-i)
# ---------------------------------------------------------------------------

class TestAC3216TraversalGuard:
  @pytest.mark.parametrize(
    "bad",
    [
      "file:///home/user/../../etc/passwd",
      "file:///home/user/..",
      "file:///a/%2e%2e/b",
      "file:///a/%2E%2E/b",
    ],
  )
  def test_traversal_artifact_fails_validation(self, bad):
    with pytest.raises(InvalidRootURIError):
      validate_root_uri(bad)

  def test_assemble_listing_rejects_traversal_root(self):
    bad = Root.from_dict(
      {"uri": "file:///home/user/../secret"}, validate=False
    )
    with pytest.raises(InvalidRootURIError):
      assemble_listing([bad], user_consented=True)

  def test_traversal_check_can_be_disabled_for_receiver(self):
    # A receiver inspecting an already-received root may skip the client guard.
    assert validate_root_uri(
      "file:///a/../b", reject_traversal=False
    ) == "file:///a/../b"


# ---------------------------------------------------------------------------
# AC-32.17 — a server tolerates a previously reported root becoming unavailable
# rather than failing. (R-21.1.5-j)
# ---------------------------------------------------------------------------

class TestAC3217ToleranceOfUnavailable:
  def test_server_tolerates_unavailable_root(self):
    assert server_should_tolerate_unavailable_root() is True


# ---------------------------------------------------------------------------
# AC-32.18 — a server validates derived paths against the reported roots and does
# NOT assume the protocol enforces root boundaries. (R-21.1.5-k, R-21.1.5-l)
# ---------------------------------------------------------------------------

class TestAC3218ServerNonEnforcement:
  def test_server_validates_derived_paths(self):
    assert server_validates_derived_paths() is True

  def test_protocol_does_not_enforce_boundaries(self):
    assert protocol_enforces_root_boundaries() is False
