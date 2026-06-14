"""Tests for S31 — Elicitation II: Restricted Form Schema, Results & Consent.

Each test class maps to one or more acceptance criteria (AC-31.x). All vendor /
model names in test data are vendor-neutral placeholders.

AC → test coverage map:
  AC-31.1  flat primitives-only schema; nested-object / array-of-objects rejected
           → TestAC311RestrictedFormSchema
  AC-31.2  client MAY generate form / validate / guide — no protocol error
           → TestAC312ClientMayUseSchema
  AC-31.3  default pre-population by a defaults-aware client
           → TestAC313DefaultPrePopulation
  AC-31.4  StringSchema.format limited to the four literals
           → TestAC314StringFormat
  AC-31.5  NumberSchema.type limited to number/integer
           → TestAC315NumberType
  AC-31.6  Legacy form not adopted for new work; still accepted from a peer
           → TestAC316LegacyEnumDeprecated
  AC-31.7  per-option labels via TitledSingleSelectEnumSchema, not enumNames
           → TestAC317TitledSingleSelect
  AC-31.8  ElicitResult.action required, exactly one of the three literals
           → TestAC318ActionRequired
  AC-31.9  content present only on form-mode accept; URL accept-with-content malformed
           → TestAC319ContentPresence
  AC-31.10 content values typed; map conforms to requestedSchema
           → TestAC3110ContentConforms
  AC-31.11 accept → process (form) / consent-to-proceed (URL), distinct from completion
           → TestAC3111AcceptHandling
  AC-31.12 decline → decline-handling branch
           → TestAC3112DeclineHandling
  AC-31.13 cancel → dismissal-handling branch
           → TestAC3113CancelHandling
  AC-31.14 server does not assume success; branches for decline/cancel/failure
           → TestAC3114NoAssumeSuccess
  AC-31.15 client validates content before send; server validates on receipt
           → TestAC3115ValidateBothSides
  AC-31.16 server MAY send complete notification; method + params match shape
           → TestAC3116CompleteNotificationShape
  AC-31.17 elicitationId equals original; delivered only to initiating client
           → TestAC3117CompleteCorrelation
  AC-31.18 unknown / already-completed id → ignored, no action
           → TestAC3118IgnoreUnknownOrDone
  AC-31.19 MAY auto-retry/update via notification; manual controls provided
           → TestAC3119AutoRetryAndManual
  AC-31.20 UI: which server, decline+cancel anytime, privacy
           → TestAC3120UserControl
  AC-31.21 form mode: review and modify before sending
           → TestAC3121ReviewAndModify
  AC-31.22 present what+why, approval controls, decline anytime
           → TestAC3122ApprovalControls
  AC-31.23 sensitive info → not form mode (URL mode); contact/profile allowed
           → TestAC3123SensitiveInformation
  AC-31.24 bind to client+user identity; no unverified client-provided identity
           → TestAC3124IdentityBinding
  AC-31.25 URL mode: verify opener identity == initiator before accepting
           → TestAC3125CrossUserVerification
  AC-31.26 verify via authz subject not URL identity; resilient to URL tampering
           → TestAC3126ResilientVerification
  AC-31.27 constructed URL: no sensitive info; not pre-authenticated
           → TestAC3127SafeUrlConstruction
  AC-31.28 form mode: no clickable URLs; HTTPS outside dev
           → TestAC3128NoClickableUrlsHttps
  AC-31.29 client: no auto-prefetch; no open without consent
           → TestAC3129NoPrefetchNoOpen
  AC-31.30 show full URL + host; open isolated from inspection
           → TestAC3130ShowUrlIsolatedOpen
  AC-31.31 highlight domain, warn Punycode; clickable only for url field
           → TestAC3131DomainWarnClickable
  AC-31.32 not used to authorize client; credentials not transmitted to client
           → TestAC3132NotAuthorization
"""

import pytest

from mcp_sdk_py.elicitation import MODE_FORM, MODE_URL
from mcp_sdk_py.jsonrpc import JSONRPCNotification
from mcp_sdk_py.elicitation_form import (
  ACTION_ACCEPT,
  ACTION_CANCEL,
  ACTION_DECLINE,
  DEPRECATED_ENUM_SCHEMAS,
  ELICITATION_COMPLETE_METHOD,
  BooleanSchema,
  ElicitationCompleteNotification,
  ElicitationCompleteTracker,
  ElicitationIdentityBinding,
  ElicitationOutcome,
  ElicitResult,
  InvalidElicitationCompleteNotificationError,
  InvalidElicitResultError,
  InvalidPrimitiveSchemaError,
  LegacyTitledEnumSchema,
  NumberSchema,
  RestrictedFormSchema,
  StringSchema,
  TitledMultiSelectEnumSchema,
  TitledSingleSelectEnumSchema,
  UnsafeElicitationUrlError,
  UntitledMultiSelectEnumSchema,
  UntitledSingleSelectEnumSchema,
  UrlConsentDecision,
  UserControlRequirements,
  accept_form_result,
  accept_url_result,
  assert_credentials_not_transmitted_to_client,
  assert_form_mode_not_sensitive,
  assert_no_clickable_urls_in_form,
  assert_not_used_for_authorization,
  assert_safe_elicitation_url,
  cancel_result,
  classify_elicit_outcome,
  decline_result,
  is_clickable_url_field_allowed,
  is_punycode_host,
  is_sensitive_field,
  open_url_with_consent,
  parse_primitive_schema,
  prepare_url_for_consent,
  reject_client_provided_identity,
  url_host,
  validate_content_against_schema,
  validate_requested_schema,
)


# A wire-shaped form schema exercising primitives, an enum, and defaults.
_FORM_SCHEMA = {
  "type": "object",
  "properties": {
    "name": {"type": "string", "description": "Your full name", "maxLength": 120},
    "email": {"type": "string", "format": "email", "description": "Your email address"},
    "age": {"type": "integer", "minimum": 18, "default": 18},
    "newsletter": {"type": "boolean", "default": False},
    "plan": {
      "type": "string",
      "title": "Plan",
      "oneOf": [
        {"const": "free", "title": "Free"},
        {"const": "pro", "title": "Pro"},
      ],
      "default": "free",
    },
  },
  "required": ["name", "email"],
}


# ---------------------------------------------------------------------------
# AC-31.1 — restricted form schema: flat, primitives only (R-20.4-a)
# ---------------------------------------------------------------------------

class TestAC311RestrictedFormSchema:
  def test_flat_primitives_schema_accepted(self):
    schema = validate_requested_schema(_FORM_SCHEMA)
    assert set(schema.properties) == {"name", "email", "age", "newsletter", "plan"}
    assert isinstance(schema.properties["name"], StringSchema)
    assert isinstance(schema.properties["age"], NumberSchema)
    assert isinstance(schema.properties["newsletter"], BooleanSchema)
    assert isinstance(schema.properties["plan"], TitledSingleSelectEnumSchema)

  def test_nested_object_property_rejected(self):
    schema = {
      "type": "object",
      "properties": {"addr": {"type": "object", "properties": {"city": {"type": "string"}}}},
    }
    with pytest.raises(InvalidPrimitiveSchemaError):
      validate_requested_schema(schema)

  def test_array_of_objects_property_rejected(self):
    schema = {
      "type": "object",
      "properties": {
        "rows": {"type": "array", "items": {"type": "object", "properties": {}}},
      },
    }
    with pytest.raises(InvalidPrimitiveSchemaError):
      validate_requested_schema(schema)

  def test_enum_array_form_is_allowed_array(self):
    # The enum array forms are the *only* permitted array shape.
    schema = {
      "type": "object",
      "properties": {
        "tags": {"type": "array", "items": {"type": "string", "enum": ["a", "b"]}},
      },
    }
    parsed = validate_requested_schema(schema)
    assert isinstance(parsed.properties["tags"], UntitledMultiSelectEnumSchema)

  def test_unknown_primitive_type_rejected(self):
    with pytest.raises(InvalidPrimitiveSchemaError):
      parse_primitive_schema({"type": "null"})

  def test_top_level_type_must_be_object(self):
    with pytest.raises(InvalidPrimitiveSchemaError):
      validate_requested_schema({"type": "string", "properties": {}})


# ---------------------------------------------------------------------------
# AC-31.2 — client MAY generate/validate/guide; no protocol error (R-20.4-b)
# ---------------------------------------------------------------------------

class TestAC312ClientMayUseSchema:
  def test_parsing_for_form_generation_does_not_error(self):
    # Using the schema to drive a form / validation is permitted and side-effect free.
    schema = validate_requested_schema(_FORM_SCHEMA)
    # "generate input form" — enumerate fields without error.
    fields = list(schema.properties.items())
    assert len(fields) == 5

  def test_choosing_not_to_validate_is_also_fine(self):
    # A client that does NOT pre-validate simply never calls the validator; the
    # round-trip remains valid. Constructing the result without validation works.
    result = ElicitResult(action=ACTION_ACCEPT, content={"name": "x", "email": "x@y.z"})
    assert result.is_accept


# ---------------------------------------------------------------------------
# AC-31.3 — default pre-population (R-20.4-c)
# ---------------------------------------------------------------------------

class TestAC313DefaultPrePopulation:
  def test_defaults_extracted_for_prepopulation(self):
    schema = validate_requested_schema(_FORM_SCHEMA)
    defaults = schema.defaults()
    assert defaults == {"age": 18, "newsletter": False, "plan": "free"}

  def test_fields_without_default_absent_from_defaults(self):
    schema = validate_requested_schema(_FORM_SCHEMA)
    assert "name" not in schema.defaults()
    assert "email" not in schema.defaults()

  def test_default_false_boolean_is_preserved(self):
    # default == False must still be offered for pre-population (not dropped).
    schema = validate_requested_schema(_FORM_SCHEMA)
    assert schema.defaults()["newsletter"] is False


# ---------------------------------------------------------------------------
# AC-31.4 — StringSchema.format constrained (R-20.4-d)
# ---------------------------------------------------------------------------

class TestAC314StringFormat:
  @pytest.mark.parametrize("fmt", ["email", "uri", "date", "date-time"])
  def test_allowed_formats_accepted(self, fmt):
    s = StringSchema(format=fmt)
    assert s.format == fmt

  def test_phone_format_rejected(self):
    with pytest.raises(InvalidPrimitiveSchemaError):
      StringSchema(format="phone")

  def test_format_rejected_via_parse(self):
    with pytest.raises(InvalidPrimitiveSchemaError):
      parse_primitive_schema({"type": "string", "format": "uuid"})

  def test_no_format_is_fine(self):
    assert StringSchema().format is None


# ---------------------------------------------------------------------------
# AC-31.5 — NumberSchema.type constrained (R-20.4-e)
# ---------------------------------------------------------------------------

class TestAC315NumberType:
  @pytest.mark.parametrize("t", ["number", "integer"])
  def test_allowed_number_types(self, t):
    assert NumberSchema(type=t).type == t

  def test_bad_number_type_rejected(self):
    with pytest.raises(InvalidPrimitiveSchemaError):
      NumberSchema(type="float")

  def test_dispatch_number_and_integer(self):
    assert isinstance(parse_primitive_schema({"type": "number"}), NumberSchema)
    assert isinstance(parse_primitive_schema({"type": "integer"}), NumberSchema)


# ---------------------------------------------------------------------------
# AC-31.6 — Legacy form Deprecated but accepted for interop (R-20.4-f)
# ---------------------------------------------------------------------------

class TestAC316LegacyEnumDeprecated:
  def test_legacy_marked_deprecated(self):
    assert LegacyTitledEnumSchema in DEPRECATED_ENUM_SCHEMAS
    legacy = LegacyTitledEnumSchema(enum=["a", "b"])
    assert legacy.deprecated is True

  def test_titled_single_select_not_deprecated(self):
    assert TitledSingleSelectEnumSchema not in DEPRECATED_ENUM_SCHEMAS

  def test_legacy_received_from_peer_is_accepted(self):
    parsed = parse_primitive_schema(
      {"type": "string", "enum": ["a", "b"], "enumNames": ["A", "B"]}
    )
    assert isinstance(parsed, LegacyTitledEnumSchema)
    assert parsed.enum_names == ["A", "B"]

  def test_new_work_choosing_titled_avoids_legacy(self):
    # A new implementation needing labels selects the titled form (no enumNames).
    chosen = TitledSingleSelectEnumSchema(
      one_of=[{"const": "a", "title": "A"}, {"const": "b", "title": "B"}]
    )
    assert type(chosen) not in DEPRECATED_ENUM_SCHEMAS


# ---------------------------------------------------------------------------
# AC-31.7 — per-option labels via TitledSingleSelectEnumSchema (R-20.4-g)
# ---------------------------------------------------------------------------

class TestAC317TitledSingleSelect:
  def test_oneof_dispatches_to_titled_single_select(self):
    parsed = parse_primitive_schema(
      {"type": "string", "oneOf": [{"const": "free", "title": "Free"}]}
    )
    assert isinstance(parsed, TitledSingleSelectEnumSchema)
    assert parsed.consts == ["free"]

  def test_titled_requires_const_and_title(self):
    with pytest.raises(InvalidPrimitiveSchemaError):
      TitledSingleSelectEnumSchema(one_of=[{"const": "free"}])
    with pytest.raises(InvalidPrimitiveSchemaError):
      TitledSingleSelectEnumSchema(one_of=[{"title": "Free"}])

  def test_titled_default_must_be_a_const(self):
    with pytest.raises(InvalidPrimitiveSchemaError):
      TitledSingleSelectEnumSchema(
        one_of=[{"const": "free", "title": "Free"}], default="enterprise"
      )

  def test_recommended_over_legacy_for_labels(self):
    # Same intent, two encodings: the recommended one is not deprecated.
    titled = TitledSingleSelectEnumSchema(one_of=[{"const": "a", "title": "A"}])
    legacy = LegacyTitledEnumSchema(enum=["a"], enum_names=["A"])
    assert type(titled) not in DEPRECATED_ENUM_SCHEMAS
    assert type(legacy) in DEPRECATED_ENUM_SCHEMAS


# ---------------------------------------------------------------------------
# AC-31.8 — action required and one of three literals (R-20.5-a)
# ---------------------------------------------------------------------------

class TestAC318ActionRequired:
  @pytest.mark.parametrize("action", ["accept", "decline", "cancel"])
  def test_valid_actions(self, action):
    assert ElicitResult(action=action).action == action

  def test_missing_action_rejected(self):
    with pytest.raises(InvalidElicitResultError):
      ElicitResult.from_dict({})

  def test_unknown_action_rejected(self):
    with pytest.raises(InvalidElicitResultError):
      ElicitResult(action="approve")

  def test_from_dict_unknown_action_rejected(self):
    with pytest.raises(InvalidElicitResultError):
      ElicitResult.from_dict({"action": "submit"})


# ---------------------------------------------------------------------------
# AC-31.9 — content presence rules (R-20.5-b)
# ---------------------------------------------------------------------------

class TestAC319ContentPresence:
  def test_form_accept_with_content_ok(self):
    r = ElicitResult.from_dict(
      {"action": "accept", "content": {"name": "x", "email": "a@b.co"}},
      mode=MODE_FORM,
      requested_schema=_FORM_SCHEMA,
    )
    assert r.content == {"name": "x", "email": "a@b.co"}

  def test_url_accept_omits_content(self):
    r = ElicitResult.from_dict({"action": "accept"}, mode=MODE_URL)
    assert r.content is None

  def test_url_accept_with_content_is_malformed(self):
    with pytest.raises(InvalidElicitResultError):
      ElicitResult.from_dict({"action": "accept", "content": {"x": 1}}, mode=MODE_URL)

  def test_decline_with_content_is_malformed(self):
    with pytest.raises(InvalidElicitResultError):
      ElicitResult(action=ACTION_DECLINE, content={"x": 1})

  def test_cancel_with_content_is_malformed(self):
    with pytest.raises(InvalidElicitResultError):
      ElicitResult(action=ACTION_CANCEL, content={"x": 1})

  def test_decline_and_cancel_omit_content(self):
    assert decline_result().content is None
    assert cancel_result().content is None


# ---------------------------------------------------------------------------
# AC-31.10 — content value typing + schema conformance (R-20.5-c)
# ---------------------------------------------------------------------------

class TestAC3110ContentConforms:
  def test_conforming_content_passes(self):
    validate_content_against_schema(
      {"name": "Monalisa Octocat", "email": "octocat@example.com", "age": 30},
      _FORM_SCHEMA,
    )

  def test_array_of_strings_value_allowed(self):
    schema = {
      "type": "object",
      "properties": {"tags": {"type": "array", "items": {"type": "string", "enum": ["a", "b"]}}},
    }
    validate_content_against_schema({"tags": ["a", "b"]}, schema)

  def test_disallowed_value_type_rejected(self):
    # A nested object is not a string/number/boolean/array-of-strings.
    with pytest.raises(InvalidElicitResultError):
      validate_content_against_schema({"name": {"nested": 1}}, _FORM_SCHEMA)

  def test_array_of_non_strings_rejected(self):
    schema = {
      "type": "object",
      "properties": {"tags": {"type": "array", "items": {"type": "string", "enum": ["a"]}}},
    }
    with pytest.raises(InvalidElicitResultError):
      validate_content_against_schema({"tags": [1, 2]}, schema)

  def test_field_violating_schema_rejected(self):
    # age below minimum 18.
    with pytest.raises(InvalidElicitResultError):
      validate_content_against_schema(
        {"name": "x", "email": "a@b.co", "age": 10}, _FORM_SCHEMA
      )

  def test_bad_email_format_rejected(self):
    with pytest.raises(InvalidElicitResultError):
      validate_content_against_schema(
        {"name": "x", "email": "not-an-email"}, _FORM_SCHEMA
      )

  def test_integer_field_rejects_non_integer(self):
    with pytest.raises(InvalidElicitResultError):
      validate_content_against_schema(
        {"name": "x", "email": "a@b.co", "age": 30.5}, _FORM_SCHEMA
      )

  def test_enum_membership_enforced(self):
    with pytest.raises(InvalidElicitResultError):
      validate_content_against_schema(
        {"name": "x", "email": "a@b.co", "plan": "enterprise"}, _FORM_SCHEMA
      )

  def test_unknown_key_rejected(self):
    with pytest.raises(InvalidElicitResultError):
      validate_content_against_schema(
        {"name": "x", "email": "a@b.co", "unexpected": "v"}, _FORM_SCHEMA
      )

  def test_missing_required_property_rejected(self):
    with pytest.raises(InvalidElicitResultError):
      validate_content_against_schema({"name": "x"}, _FORM_SCHEMA)

  def test_multi_select_count_bounds(self):
    schema = {
      "type": "object",
      "properties": {
        "picks": {
          "type": "array",
          "minItems": 1,
          "maxItems": 2,
          "items": {"type": "string", "enum": ["a", "b", "c"]},
        }
      },
    }
    validate_content_against_schema({"picks": ["a", "b"]}, schema)
    with pytest.raises(InvalidElicitResultError):
      validate_content_against_schema({"picks": []}, schema)
    with pytest.raises(InvalidElicitResultError):
      validate_content_against_schema({"picks": ["a", "b", "c"]}, schema)


# ---------------------------------------------------------------------------
# AC-31.11 — accept handling distinct from completion (R-20.5-d)
# ---------------------------------------------------------------------------

class TestAC3111AcceptHandling:
  def test_form_accept_classifies_accepted(self):
    r = accept_form_result({"name": "x", "email": "a@b.co"}, _FORM_SCHEMA)
    assert classify_elicit_outcome(r) == ElicitationOutcome.ACCEPTED

  def test_url_accept_is_consent_not_completion(self):
    r = accept_url_result()
    # Accept signals consent; there is no content, completion is signalled later.
    assert r.is_accept
    assert r.content is None
    assert classify_elicit_outcome(r) == ElicitationOutcome.ACCEPTED


# ---------------------------------------------------------------------------
# AC-31.12 — decline handling branch (R-20.5-e)
# ---------------------------------------------------------------------------

class TestAC3112DeclineHandling:
  def test_decline_branch(self):
    assert classify_elicit_outcome(decline_result()) == ElicitationOutcome.DECLINED

  def test_decline_is_not_accepted(self):
    assert classify_elicit_outcome(decline_result()) != ElicitationOutcome.ACCEPTED


# ---------------------------------------------------------------------------
# AC-31.13 — cancel handling branch (R-20.5-f)
# ---------------------------------------------------------------------------

class TestAC3113CancelHandling:
  def test_cancel_branch(self):
    assert classify_elicit_outcome(cancel_result()) == ElicitationOutcome.CANCELLED

  def test_cancel_is_not_accepted(self):
    assert classify_elicit_outcome(cancel_result()) != ElicitationOutcome.ACCEPTED


# ---------------------------------------------------------------------------
# AC-31.14 — server does not assume success (R-20.5-g, R-20.5-h)
# ---------------------------------------------------------------------------

class TestAC3114NoAssumeSuccess:
  def test_all_four_branches_distinct(self):
    outcomes = {
      classify_elicit_outcome(accept_url_result()),
      classify_elicit_outcome(decline_result()),
      classify_elicit_outcome(cancel_result()),
      classify_elicit_outcome(None),
    }
    assert outcomes == {
      ElicitationOutcome.ACCEPTED,
      ElicitationOutcome.DECLINED,
      ElicitationOutcome.CANCELLED,
      ElicitationOutcome.FAILED,
    }

  def test_client_failure_maps_to_failed(self):
    # No result at all (client failed to process) is a defined branch.
    assert classify_elicit_outcome(None) == ElicitationOutcome.FAILED


# ---------------------------------------------------------------------------
# AC-31.15 — validate on both sides (R-20.5-i, R-20.5-j)
# ---------------------------------------------------------------------------

class TestAC3115ValidateBothSides:
  def test_client_validates_before_send(self):
    # accept_form_result performs the client-side pre-send validation (R-20.5-i).
    with pytest.raises(InvalidElicitResultError):
      accept_form_result({"name": "x", "email": "bad"}, _FORM_SCHEMA)

  def test_server_validates_on_receipt(self):
    # The server runs the same validation on the received content (R-20.5-j).
    good = {"name": "x", "email": "a@b.co"}
    validate_content_against_schema(good, _FORM_SCHEMA)
    with pytest.raises(InvalidElicitResultError):
      validate_content_against_schema({"name": "x", "email": "a@b.co", "age": 5}, _FORM_SCHEMA)

  def test_validation_accepts_prevalidated_schema_object(self):
    parsed = RestrictedFormSchema.from_dict(_FORM_SCHEMA)
    validate_content_against_schema({"name": "x", "email": "a@b.co"}, parsed)


# ---------------------------------------------------------------------------
# AC-31.16 — complete notification shape (R-20.6-a)
# ---------------------------------------------------------------------------

class TestAC3116CompleteNotificationShape:
  def test_method_literal(self):
    n = ElicitationCompleteNotification(elicitation_id="abc")
    assert n.method == ELICITATION_COMPLETE_METHOD == "notifications/elicitation/complete"

  def test_to_dict_matches_jsonrpc_notification_shape(self):
    n = ElicitationCompleteNotification(elicitation_id="abc")
    d = n.to_dict()
    assert d == {
      "jsonrpc": "2.0",
      "method": "notifications/elicitation/complete",
      "params": {"elicitationId": "abc"},
    }

  def test_to_jsonrpc_returns_notification(self):
    n = ElicitationCompleteNotification(elicitation_id="abc")
    assert isinstance(n.to_jsonrpc(), JSONRPCNotification)

  def test_parse_roundtrip(self):
    raw = {
      "jsonrpc": "2.0",
      "method": "notifications/elicitation/complete",
      "params": {"elicitationId": "550e8400"},
    }
    n = ElicitationCompleteNotification.from_dict(raw)
    assert n.elicitation_id == "550e8400"

  def test_wrong_method_rejected(self):
    with pytest.raises(InvalidElicitationCompleteNotificationError):
      ElicitationCompleteNotification.from_dict(
        {"method": "notifications/other", "params": {"elicitationId": "x"}}
      )


# ---------------------------------------------------------------------------
# AC-31.17 — elicitationId correlation + delivery to initiator (R-20.6-b/c)
# ---------------------------------------------------------------------------

class TestAC3117CompleteCorrelation:
  def test_id_equals_original(self):
    original_id = "550e8400-e29b-41d4-a716-446655440000"
    n = ElicitationCompleteNotification(elicitation_id=original_id)
    assert n.to_dict()["params"]["elicitationId"] == original_id

  def test_missing_id_rejected(self):
    with pytest.raises(InvalidElicitationCompleteNotificationError):
      ElicitationCompleteNotification.from_dict(
        {"method": ELICITATION_COMPLETE_METHOD, "params": {}}
      )

  def test_empty_id_rejected(self):
    with pytest.raises(InvalidElicitationCompleteNotificationError):
      ElicitationCompleteNotification(elicitation_id="")

  def test_delivery_only_to_initiating_client(self):
    # The initiating client's tracker recognises its own id; another client's
    # tracker (which never registered it) ignores it — modelling R-20.6-c.
    initiator = ElicitationCompleteTracker()
    other = ElicitationCompleteTracker()
    initiator.register("e-1")
    n = ElicitationCompleteNotification(elicitation_id="e-1")
    assert other.receive(n) is False
    assert initiator.receive(n) is True


# ---------------------------------------------------------------------------
# AC-31.18 — ignore unknown / already-completed (R-20.6-d)
# ---------------------------------------------------------------------------

class TestAC3118IgnoreUnknownOrDone:
  def test_unknown_id_ignored(self):
    t = ElicitationCompleteTracker()
    assert t.receive("never-registered") is False

  def test_already_completed_ignored(self):
    t = ElicitationCompleteTracker()
    t.register("e-1")
    assert t.receive("e-1") is True
    # Duplicate / already-completed → ignored, no action.
    assert t.receive("e-1") is False

  def test_ignore_takes_no_state_action(self):
    t = ElicitationCompleteTracker()
    t.receive("ghost")
    assert not t.is_pending("ghost")
    assert not t.is_completed("ghost")


# ---------------------------------------------------------------------------
# AC-31.19 — auto-retry permitted + manual controls (R-20.6-e/f)
# ---------------------------------------------------------------------------

class TestAC3119AutoRetryAndManual:
  def test_notification_enables_auto_continue(self):
    t = ElicitationCompleteTracker()
    t.register("e-1")
    # receive() returning True is the signal a client MAY auto-retry / update UI.
    assert t.receive("e-1") is True
    assert t.is_completed("e-1")

  def test_manual_resolution_when_notification_never_arrives(self):
    t = ElicitationCompleteTracker()
    t.register("e-1")
    # No notification arrives; user manually retries/cancels.
    t.resolve_manually("e-1")
    assert not t.is_pending("e-1")
    # A late notification is then ignored.
    assert t.receive("e-1") is False


# ---------------------------------------------------------------------------
# AC-31.20 — user control UI (R-20.7-a/b/c)
# ---------------------------------------------------------------------------

class TestAC3120UserControl:
  def _full(self, **overrides):
    base = dict(
      shows_requesting_server=True,
      offers_decline=True,
      offers_cancel=True,
      respects_privacy=True,
      allows_review_and_modify=True,
      explains_what_and_why=True,
      implements_approval_controls=True,
    )
    base.update(overrides)
    return UserControlRequirements(**base)

  def test_conformant_ui_passes(self):
    self._full().assert_conformant()

  def test_missing_server_identity_fails(self):
    with pytest.raises(PermissionError):
      self._full(shows_requesting_server=False).assert_conformant()

  def test_missing_decline_fails(self):
    with pytest.raises(PermissionError):
      self._full(offers_decline=False).assert_conformant()

  def test_missing_cancel_fails(self):
    with pytest.raises(PermissionError):
      self._full(offers_cancel=False).assert_conformant()

  def test_missing_privacy_fails(self):
    with pytest.raises(PermissionError):
      self._full(respects_privacy=False).assert_conformant()


# ---------------------------------------------------------------------------
# AC-31.21 — form review and modify before send (R-20.7-d)
# ---------------------------------------------------------------------------

class TestAC3121ReviewAndModify:
  def test_form_mode_requires_review_modify(self):
    ui = UserControlRequirements(
      shows_requesting_server=True,
      offers_decline=True,
      offers_cancel=True,
      respects_privacy=True,
      allows_review_and_modify=False,
    )
    with pytest.raises(PermissionError):
      ui.assert_conformant(form_mode=True)

  def test_url_mode_does_not_require_form_review(self):
    ui = UserControlRequirements(
      shows_requesting_server=True,
      offers_decline=True,
      offers_cancel=True,
      respects_privacy=True,
      allows_review_and_modify=False,
    )
    # The review/modify MUST is form-mode-specific.
    ui.assert_conformant(form_mode=False)


# ---------------------------------------------------------------------------
# AC-31.22 — present what+why, approval, decline anytime (R-20.7-e/f/g)
# ---------------------------------------------------------------------------

class TestAC3122ApprovalControls:
  def test_should_level_flags_present_on_conformant_ui(self):
    ui = UserControlRequirements(
      shows_requesting_server=True,
      offers_decline=True,
      offers_cancel=True,
      respects_privacy=True,
      allows_review_and_modify=True,
      explains_what_and_why=True,
      implements_approval_controls=True,
    )
    ui.assert_conformant()
    assert ui.explains_what_and_why
    assert ui.implements_approval_controls
    assert ui.offers_decline  # decline available at any time (R-20.7-g)


# ---------------------------------------------------------------------------
# AC-31.23 — sensitive info → URL mode; contact/profile allowed (R-20.7-h/i)
# ---------------------------------------------------------------------------

class TestAC3123SensitiveInformation:
  @pytest.mark.parametrize(
    "name",
    ["password", "api_key", "access_token", "payment_card", "cvv"],
  )
  def test_sensitive_field_detected(self, name):
    assert is_sensitive_field(name)

  @pytest.mark.parametrize("name", ["name", "email", "username", "full_name"])
  def test_contact_profile_not_sensitive(self, name):
    assert not is_sensitive_field(name)

  def test_form_with_sensitive_field_rejected(self):
    schema = {
      "type": "object",
      "properties": {"password": {"type": "string"}},
    }
    with pytest.raises(PermissionError):
      assert_form_mode_not_sensitive(schema)

  def test_sensitive_in_description_detected(self):
    schema = {
      "type": "object",
      "properties": {"secret": {"type": "string", "description": "Your API key"}},
    }
    with pytest.raises(PermissionError):
      assert_form_mode_not_sensitive(schema)

  def test_contact_form_allowed(self):
    schema = {
      "type": "object",
      "properties": {
        "name": {"type": "string"},
        "email": {"type": "string", "format": "email"},
      },
    }
    assert_form_mode_not_sensitive(schema)  # no raise


# ---------------------------------------------------------------------------
# AC-31.24 — identity binding; no unverified client identity (R-20.7-j/k)
# ---------------------------------------------------------------------------

class TestAC3124IdentityBinding:
  def test_binding_records_client_and_user(self):
    b = ElicitationIdentityBinding(
      elicitation_id="e-1", client_id="client-x", server_verified_subject="sub-123"
    )
    assert b.client_id == "client-x"
    assert b.server_verified_subject == "sub-123"

  def test_unverified_client_identity_rejected(self):
    with pytest.raises(PermissionError):
      reject_client_provided_identity(has_server_verification=False)

  def test_verified_identity_accepted(self):
    reject_client_provided_identity(has_server_verification=True)  # no raise


# ---------------------------------------------------------------------------
# AC-31.25 — cross-user verification before accepting (R-20.7-l/m)
# ---------------------------------------------------------------------------

class TestAC3125CrossUserVerification:
  def test_same_subject_verifies(self):
    b = ElicitationIdentityBinding(
      elicitation_id="e-1", client_id="c", server_verified_subject="sub-A"
    )
    assert b.verify_completion_subject("sub-A") is True

  def test_different_subject_rejected(self):
    b = ElicitationIdentityBinding(
      elicitation_id="e-1", client_id="c", server_verified_subject="sub-A"
    )
    # Forwarded-URL attacker completes as a different subject → rejected.
    assert b.verify_completion_subject("sub-ATTACKER") is False

  def test_empty_subject_rejected(self):
    b = ElicitationIdentityBinding(
      elicitation_id="e-1", client_id="c", server_verified_subject="sub-A"
    )
    assert b.verify_completion_subject("") is False


# ---------------------------------------------------------------------------
# AC-31.26 — verify via authz subject; resilient to URL tampering (R-20.7-n/o)
# ---------------------------------------------------------------------------

class TestAC3126ResilientVerification:
  def test_verification_uses_server_subject_not_url(self):
    # The binding's subject is server-established; verification compares against
    # the browser-session subject — neither value is read from the URL.
    b = ElicitationIdentityBinding(
      elicitation_id="e-1", client_id="c", server_verified_subject="sub-real"
    )
    # An attacker who modifies the URL cannot change the server-side subject;
    # the comparison still depends only on the authz subjects.
    assert b.verify_completion_subject("sub-real") is True
    assert b.verify_completion_subject("sub-from-tampered-url") is False

  def test_subject_is_immutable_binding(self):
    b = ElicitationIdentityBinding(
      elicitation_id="e-1", client_id="c", server_verified_subject="sub-real"
    )
    with pytest.raises(Exception):
      b.server_verified_subject = "sub-other"  # frozen dataclass


# ---------------------------------------------------------------------------
# AC-31.27 — safe URL construction (R-20.7-p/q)
# ---------------------------------------------------------------------------

class TestAC3127SafeUrlConstruction:
  def test_clean_url_accepted(self):
    url = "https://mcp.example.com/ui/set_api_key"
    assert assert_safe_elicitation_url(url) == url

  def test_url_with_sensitive_value_rejected(self):
    url = "https://mcp.example.com/cb?token=SECRET123"
    with pytest.raises(UnsafeElicitationUrlError):
      assert_safe_elicitation_url(url, sensitive_values=["SECRET123"])

  def test_pre_authenticated_url_rejected(self):
    with pytest.raises(UnsafeElicitationUrlError):
      assert_safe_elicitation_url(
        "https://mcp.example.com/ui", pre_authenticated=True
      )


# ---------------------------------------------------------------------------
# AC-31.28 — no clickable URLs in form; HTTPS outside dev (R-20.7-r/s)
# ---------------------------------------------------------------------------

class TestAC3128NoClickableUrlsHttps:
  def test_form_field_with_url_rejected(self):
    schema = {
      "type": "object",
      "properties": {
        "bio": {"type": "string", "description": "See https://example.com for help"},
      },
    }
    with pytest.raises(PermissionError):
      assert_no_clickable_urls_in_form(schema)

  def test_clean_form_passes(self):
    schema = {"type": "object", "properties": {"name": {"type": "string"}}}
    assert_no_clickable_urls_in_form(schema)  # no raise

  def test_https_required_outside_dev(self):
    with pytest.raises(UnsafeElicitationUrlError):
      assert_safe_elicitation_url("http://mcp.example.com/ui", require_https=True)

  def test_http_allowed_in_dev(self):
    url = "http://localhost:8080/ui"
    assert assert_safe_elicitation_url(url, require_https=False) == url


# ---------------------------------------------------------------------------
# AC-31.29 — no auto-prefetch; no open without consent (R-20.7-t/u)
# ---------------------------------------------------------------------------

class TestAC3129NoPrefetchNoOpen:
  def test_prepare_does_not_fetch(self):
    # prepare_url_for_consent performs no network access (pure parsing).
    decision = prepare_url_for_consent("https://mcp.example.com/ui")
    assert isinstance(decision, UrlConsentDecision)
    assert decision.url == "https://mcp.example.com/ui"

  def test_open_without_consent_rejected(self):
    decision = prepare_url_for_consent("https://mcp.example.com/ui")
    with pytest.raises(UnsafeElicitationUrlError):
      open_url_with_consent(decision, user_consented=False)

  def test_open_with_consent_returns_url(self):
    decision = prepare_url_for_consent("https://mcp.example.com/ui")
    assert open_url_with_consent(decision, user_consented=True) == decision.url


# ---------------------------------------------------------------------------
# AC-31.30 — show full URL + host; isolated open (R-20.7-v/w)
# ---------------------------------------------------------------------------

class TestAC3130ShowUrlIsolatedOpen:
  def test_full_url_and_host_exposed(self):
    decision = prepare_url_for_consent("https://mcp.example.com/ui/path?x=1")
    assert decision.url == "https://mcp.example.com/ui/path?x=1"
    assert decision.host == "mcp.example.com"

  def test_url_host_helper(self):
    assert url_host("https://sub.example.com/a") == "sub.example.com"

  def test_open_is_gated_for_isolated_handling(self):
    # The client only obtains the URL post-consent; the caller then opens it in
    # an isolated surface (R-20.7-w). Gating is what this layer enforces.
    decision = prepare_url_for_consent("https://mcp.example.com/ui")
    assert open_url_with_consent(decision, user_consented=True) == decision.url


# ---------------------------------------------------------------------------
# AC-31.31 — highlight domain, warn Punycode; clickable only url field (R-20.7-x/y)
# ---------------------------------------------------------------------------

class TestAC3131DomainWarnClickable:
  def test_punycode_host_flagged(self):
    assert is_punycode_host("xn--80ak6aa92e.example.com")
    decision = prepare_url_for_consent("https://xn--80ak6aa92e.com/ui")
    assert decision.is_suspicious is True

  def test_normal_host_not_flagged(self):
    decision = prepare_url_for_consent("https://example.com/ui")
    assert decision.is_suspicious is False

  def test_clickable_only_for_url_field_of_url_mode(self):
    assert is_clickable_url_field_allowed("url", mode=MODE_URL) is True

  def test_clickable_not_allowed_for_other_fields(self):
    assert is_clickable_url_field_allowed("homepage", mode=MODE_URL) is False
    assert is_clickable_url_field_allowed("url", mode=MODE_FORM) is False


# ---------------------------------------------------------------------------
# AC-31.32 — not an authorization mechanism (R-20.7-z/aa)
# ---------------------------------------------------------------------------

class TestAC3132NotAuthorization:
  def test_authorizing_client_rejected(self):
    with pytest.raises(PermissionError):
      assert_not_used_for_authorization(used_to_authorize_client=True)

  def test_non_authorizing_use_allowed(self):
    assert_not_used_for_authorization(used_to_authorize_client=False)  # no raise

  def test_transmitting_credentials_rejected(self):
    with pytest.raises(PermissionError):
      assert_credentials_not_transmitted_to_client(transmits_credentials=True)

  def test_not_transmitting_credentials_allowed(self):
    assert_credentials_not_transmitted_to_client(transmits_credentials=False)  # no raise
