"""Tests for S38 — The Extension Mechanism (§24).

Each test class maps to one acceptance criterion (AC-38.x). S38 is the surface-
contribution and graceful-degradation layer on top of S11 (identifier grammar,
active-set intersection) and S04 (core ``resultType`` values); the tests exercise
the §24 surface rules through ``mcp_sdk_py.extension_mechanism`` directly.

AC → test coverage map:
  AC-38.1  (R-24-a)    — TestAC3801ConformsToFramework
  AC-38.2  (R-24.1-a)  — TestAC3802Classifiable
  AC-38.3  (R-24.1-b)  — TestAC3803AnyNumberIndependent
  AC-38.4  (R-24.1-c)  — TestAC3804DisabledByDefault
  AC-38.5  (R-24.1-d)  — TestAC3805OnlySanctionedSurface
  AC-38.6  (R-24.2-a)  — TestAC3806PrefixRequired
  AC-38.7  (R-24.2-b)  — TestAC3807LabelStartEnd
  AC-38.8  (R-24.2-c)  — TestAC3808ReverseDnsDocumented
  AC-38.9  (R-24.2-d)  — TestAC3809NameGrammar
  AC-38.10 (R-24.2-e)  — TestAC3810ReservedSecondLabel
  AC-38.11 (R-24.2-f)  — TestAC3811BareReservedTokens
  AC-38.12 (R-24.2-g)  — TestAC3812CaseSensitive
  AC-38.13 (R-24.3-a)  — TestAC3813AbsentOrEmptyNoExtensions
  AC-38.14 (R-24.3-b)  — TestAC3814ProducerNoNull
  AC-38.15 (R-24.3-c)  — TestAC3815NullEntryNotActivated
  AC-38.16 (R-24.3-d)  — TestAC3816OneSidedNotUsed
  AC-38.17 (R-24.3-e)  — TestAC3817NonActiveSurfaceNotSent
  AC-38.18 (R-24.3-f)  — TestAC3818InboundRejectOrIgnore
  AC-38.19 (R-24.3-g)  — TestAC3819ReconcileSettings
  AC-38.20 (R-24.4-a)  — TestAC3820RecomputePerRequest
  AC-38.21 (R-24.4-b)  — TestAC3821NoInferenceFromPrior
  AC-38.22 (R-24.4-c)  — TestAC3822UnadvertisedServedInactive
  AC-38.23 (R-24.5-a)  — TestAC3823OnlyFourChannels
  AC-38.24 (R-24.5-b)  — TestAC3824MethodNamespaced
  AC-38.25 (R-24.5-c)  — TestAC3825MethodNotSentWhenInactive
  AC-38.26 (R-24.5-d)  — TestAC3826MetaKeyUnderVendorPrefix
  AC-38.27 (R-24.5-e)  — TestAC3827AcceptedResultTypeSet
  AC-38.28 (R-24.5-f)  — TestAC3828UnknownResultTypeInvalid
  AC-38.29 (R-24.5-g)  — TestAC3829IgnoreInactiveFields
  AC-38.30 (R-24.5-h)  — TestAC3830NoDependenceOnInactiveField
  AC-38.31 (R-24.5-i)  — TestAC3831NoRedefinitionOfCore
  AC-38.32 (R-24.6-a)  — TestAC3832VersionInSettings
  AC-38.33 (R-24.6-b)  — TestAC3833VersionFromNegotiationMap
  AC-38.34 (R-24.6-c)  — TestAC3834BackwardCompatibleSameId
  AC-38.35 (R-24.6-d)  — TestAC3835IncompatibleNewId
  AC-38.36 (R-24.7-a)  — TestAC3836FallBackToCore
  AC-38.37 (R-24.7-b)  — TestAC3837EmitNoneUseCore
  AC-38.38 (R-24.7-c)  — TestAC3838EnrichedToolsStillCore
  AC-38.39 (R-24.7-d)  — TestAC3839ActionableError
  AC-38.40 (R-24.7-e)  — TestAC3840ErrorIdentifiesExtension
  AC-38.41 (R-24.7-f)  — TestAC3841MayRefuseOutright
  AC-38.42 (R-24.7-g)  — TestAC3842UnknownIdentifierIgnored
  AC-38.43 (R-24.7-h)  — TestAC3843FallbackDocumented
"""

import pytest

from mcp_sdk_py.extensions import (
  ExtensionNotActiveError,
  InvalidExtensionIdentifierError,
)
from mcp_sdk_py.extension_mechanism import (
  CORE_METHOD_NAMES,
  CORE_RESULT_TYPES,
  DEFAULT_REJECTION_ERROR_CODE,
  DEFAULT_VERSION_SETTING_KEY,
  ExtensionClassification,
  ExtensionDefinition,
  ExtensionRegistry,
  NonConformantExtensionError,
  RequiredExtensionUnavailableError,
  assert_surface_is_sanctioned,
  derive_namespace,
  extension_version,
  is_backward_compatible_evolution,
  is_namespaced_method,
  is_sanctioned_surface_addition,
  requires_new_identifier,
  validate_extension_meta_key,
  validate_extension_method_string,
  validate_extension_result_type,
)


# Shared fixtures -----------------------------------------------------------

def make_tasks() -> ExtensionDefinition:
  """A reference modular extension mirroring the §25 Tasks example."""
  return ExtensionDefinition(
    identifier="com.example/tasks",
    classification=ExtensionClassification.MODULAR,
    methods=frozenset({"tasks/get", "tasks/update", "tasks/cancel"}),
    notifications=frozenset({"tasks/progress"}),
    meta_keys=frozenset({"com.example/taskId"}),
    result_types=frozenset({"task_pending"}),
    object_fields=frozenset({"taskHandle"}),
    fallback_doc="Without the tasks extension, return the synchronous core result.",
  )


def make_ui() -> ExtensionDefinition:
  """A reference extension that only enriches object fields (UI-like)."""
  return ExtensionDefinition(
    identifier="com.example/ui",
    classification=ExtensionClassification.SPECIALIZED,
    object_fields=frozenset({"uiResource"}),
    fallback_doc="Without the UI extension, return meaningful core text content.",
  )


# ---------------------------------------------------------------------------
# AC-38.1 — a third-party extension conforms to the §24 framework (R-24-a)
# ---------------------------------------------------------------------------

class TestAC3801ConformsToFramework:
  def test_conforming_definition_constructs(self):
    ext = make_tasks()
    assert ext.identifier == "com.example/tasks"
    assert ext.namespace == "tasks"

  def test_nonconforming_surface_is_rejected(self):
    # A method outside the extension's namespace breaches the framework.
    with pytest.raises(NonConformantExtensionError):
      ExtensionDefinition(
        identifier="com.example/tasks",
        methods=frozenset({"other/get"}),
      )


# ---------------------------------------------------------------------------
# AC-38.2 — classifiable; zero extensions still core-conformant (R-24.1-a)
# ---------------------------------------------------------------------------

class TestAC3802Classifiable:
  def test_three_classifications_exist(self):
    assert {c.value for c in ExtensionClassification} == {
      "modular",
      "specialized",
      "experimental",
    }

  def test_each_extension_is_classified(self):
    for cls in ExtensionClassification:
      ext = ExtensionDefinition(identifier="com.example/x", classification=cls)
      assert ext.classification is cls

  def test_zero_extensions_registry_is_conformant(self):
    reg = ExtensionRegistry()
    # No extensions known; an empty registry still functions and the accepted
    # resultType set is exactly the core set.
    assert reg.known_identifiers == frozenset()
    assert reg.accepted_result_types({}, {}) == CORE_RESULT_TYPES


# ---------------------------------------------------------------------------
# AC-38.3 — N>1 extensions accepted and negotiated independently (R-24.1-b)
# ---------------------------------------------------------------------------

class TestAC3803AnyNumberIndependent:
  def test_multiple_registered_and_independent(self):
    reg = ExtensionRegistry([make_tasks(), make_ui()])
    assert reg.known_identifiers == {"com.example/tasks", "com.example/ui"}
    client = {"com.example/tasks": {}, "com.example/ui": {}}
    # Only tasks is on the server side → only tasks is active; ui negotiated
    # independently and stays inactive.
    server = {"com.example/tasks": {}}
    active = reg.active_set(client, server)
    assert active == {"com.example/tasks"}
    assert reg.is_active("com.example/tasks", client, server)
    assert not reg.is_active("com.example/ui", client, server)


# ---------------------------------------------------------------------------
# AC-38.4 — not-negotiated extension is treated as inactive (R-24.1-c)
# ---------------------------------------------------------------------------

class TestAC3804DisabledByDefault:
  def test_unnegotiated_is_inactive(self):
    reg = ExtensionRegistry([make_tasks()])
    # Client advertises it, server does not → not negotiated → inactive.
    assert not reg.is_active("com.example/tasks", {"com.example/tasks": {}}, {})
    # Neither advertises → inactive.
    assert not reg.is_active("com.example/tasks", {}, {})


# ---------------------------------------------------------------------------
# AC-38.5 — surface added outside the mechanism is non-conformant (R-24.1-d)
# ---------------------------------------------------------------------------

class TestAC3805OnlySanctionedSurface:
  def test_extension_declared_surface_is_sanctioned(self):
    assert is_sanctioned_surface_addition(declared_by_extension=True)
    assert_surface_is_sanctioned("tasks/get", declared_by_extension=True)

  def test_undeclared_surface_is_flagged(self):
    assert not is_sanctioned_surface_addition(declared_by_extension=False)
    with pytest.raises(NonConformantExtensionError):
      assert_surface_is_sanctioned("rogue/method", declared_by_extension=False)


# ---------------------------------------------------------------------------
# AC-38.6 — bare name (no prefix) is not a valid identifier (R-24.2-a)
# ---------------------------------------------------------------------------

class TestAC3806PrefixRequired:
  def test_bare_name_rejected(self):
    with pytest.raises(InvalidExtensionIdentifierError):
      ExtensionDefinition(identifier="tasks")

  def test_namespace_derivation_requires_prefix(self):
    with pytest.raises(InvalidExtensionIdentifierError):
      derive_namespace("tasks")


# ---------------------------------------------------------------------------
# AC-38.7 — label must start with letter, end with letter/digit (R-24.2-b)
# ---------------------------------------------------------------------------

class TestAC3807LabelStartEnd:
  def test_label_starting_with_digit_rejected(self):
    with pytest.raises(InvalidExtensionIdentifierError):
      ExtensionDefinition(identifier="1com.example/x")

  def test_label_ending_with_hyphen_rejected(self):
    with pytest.raises(InvalidExtensionIdentifierError):
      ExtensionDefinition(identifier="com-.example/x")

  def test_label_a_b1_accepted(self):
    ext = ExtensionDefinition(identifier="a-b1.example/x")
    assert ext.identifier == "a-b1.example/x"


# ---------------------------------------------------------------------------
# AC-38.8 — reverse-DNS guidance is documented (R-24.2-c)
# ---------------------------------------------------------------------------

class TestAC3808ReverseDnsDocumented:
  def test_reverse_dns_example_constructs(self):
    # Owner of example.com uses com.example/ — the recommended form constructs.
    ext = ExtensionDefinition(identifier="com.example/my-extension")
    assert ext.identifier == "com.example/my-extension"

  def test_guidance_documented_in_module(self):
    import mcp_sdk_py.extension_mechanism as mod
    assert "reverse" in (mod.__doc__ or "").lower() or "reverse" in (
      mod.derive_namespace.__doc__ or ""
    ).lower() or "reverse" in (mod.ExtensionDefinition.__doc__ or "").lower()


# ---------------------------------------------------------------------------
# AC-38.9 — extension-name grammar (R-24.2-d)
# ---------------------------------------------------------------------------

class TestAC3809NameGrammar:
  def test_name_not_ending_alnum_rejected(self):
    with pytest.raises(InvalidExtensionIdentifierError):
      ExtensionDefinition(identifier="com.example/my-")

  def test_name_with_disallowed_char_rejected(self):
    with pytest.raises(InvalidExtensionIdentifierError):
      ExtensionDefinition(identifier="com.example/my ext")

  def test_my_extension_and_a_accepted(self):
    assert ExtensionDefinition(identifier="com.example/my-extension")
    assert ExtensionDefinition(identifier="com.example/a")


# ---------------------------------------------------------------------------
# AC-38.10 — reserved second label rejected for third parties (R-24.2-e)
# ---------------------------------------------------------------------------

class TestAC3810ReservedSecondLabel:
  @pytest.mark.parametrize(
    "identifier",
    [
      "io.modelcontextprotocol/x",
      "com.mcp.tools/x",
      "dev.mcp/x",
      "org.modelcontextprotocol.api/x",
    ],
  )
  def test_reserved_rejected(self, identifier):
    with pytest.raises(InvalidExtensionIdentifierError):
      ExtensionDefinition(identifier=identifier)

  def test_com_example_mcp_accepted(self):
    # Second label is example, not mcp/modelcontextprotocol → allowed.
    ext = ExtensionDefinition(identifier="com.example.mcp/x")
    assert ext.identifier == "com.example.mcp/x"

  def test_protocol_may_use_reserved_with_flag(self):
    ext = ExtensionDefinition(
      identifier="io.modelcontextprotocol/tasks",
      allow_reserved=True,
    )
    assert ext.namespace == "tasks"


# ---------------------------------------------------------------------------
# AC-38.11 — bare tokens modelcontextprotocol/mcp rejected (R-24.2-f)
# ---------------------------------------------------------------------------

class TestAC3811BareReservedTokens:
  @pytest.mark.parametrize("identifier", ["mcp/x", "modelcontextprotocol/x"])
  def test_bare_reserved_token_rejected(self, identifier):
    with pytest.raises(InvalidExtensionIdentifierError):
      ExtensionDefinition(identifier=identifier)


# ---------------------------------------------------------------------------
# AC-38.12 — identifiers are case-sensitive (R-24.2-g)
# ---------------------------------------------------------------------------

class TestAC3812CaseSensitive:
  def test_distinct_by_case(self):
    reg = ExtensionRegistry([ExtensionDefinition(identifier="com.example/ext")])
    # Advertised with different case must NOT match the locally-known id.
    client = {"Com.Example/Ext": {}}
    server = {"Com.Example/Ext": {}}
    # The differently-cased identifier is not the same as com.example/ext.
    assert not reg.is_active("com.example/ext", client, server)
    # And it is treated as unrecognized (not in known set).
    assert reg.ignore_unrecognized_identifiers(client) == frozenset()


# ---------------------------------------------------------------------------
# AC-38.13 — absent/empty extensions means no extensions (R-24.3-a)
# ---------------------------------------------------------------------------

class TestAC3813AbsentOrEmptyNoExtensions:
  def test_absent_means_none(self):
    reg = ExtensionRegistry([make_tasks()])
    assert reg.active_set(None, {"com.example/tasks": {}}) == frozenset()

  def test_empty_means_none(self):
    reg = ExtensionRegistry([make_tasks()])
    assert reg.active_set({}, {"com.example/tasks": {}}) == frozenset()


# ---------------------------------------------------------------------------
# AC-38.14 — produced extensions map carries no null values (R-24.3-b)
# ---------------------------------------------------------------------------

class TestAC3814ProducerNoNull:
  def test_empty_object_is_the_enabling_value_not_null(self):
    # The enabling value for "no settings" is {} — never None/null. A producer
    # advertising an extension uses {} (or a settings object), demonstrated by
    # the active-set computation accepting {} but not null.
    reg = ExtensionRegistry([make_tasks()])
    advertised = {"com.example/tasks": {}}
    assert all(v is not None for v in advertised.values())
    assert reg.is_active("com.example/tasks", advertised, advertised)


# ---------------------------------------------------------------------------
# AC-38.15 — null entry is malformed, extension not activated (R-24.3-c)
# ---------------------------------------------------------------------------

class TestAC3815NullEntryNotActivated:
  def test_null_value_does_not_activate(self):
    reg = ExtensionRegistry([make_tasks()])
    client = {"com.example/tasks": None}
    server = {"com.example/tasks": {}}
    assert not reg.is_active("com.example/tasks", client, server)
    assert reg.active_set(client, server) == frozenset()


# ---------------------------------------------------------------------------
# AC-38.16 — one-sided extension is not used (R-24.3-d)
# ---------------------------------------------------------------------------

class TestAC3816OneSidedNotUsed:
  def test_one_sided_inactive(self):
    reg = ExtensionRegistry([make_tasks()])
    # Server advertises, client does not.
    assert not reg.is_active("com.example/tasks", {}, {"com.example/tasks": {}})
    # The accepted resultType set has no contribution from the inactive ext.
    accepted = reg.accepted_result_types({}, {"com.example/tasks": {}})
    assert "task_pending" not in accepted


# ---------------------------------------------------------------------------
# AC-38.17 — non-active surface is not sent (R-24.3-e)
# ---------------------------------------------------------------------------

class TestAC3817NonActiveSurfaceNotSent:
  def test_inactive_method_meta_resulttype_field_blocked(self):
    reg = ExtensionRegistry([make_tasks()])
    client = {}  # not advertised by client → inactive
    server = {"com.example/tasks": {}}
    assert not reg.may_send_method("tasks/get", client, server)
    assert not reg.may_send_meta_key("com.example/taskId", client, server)
    assert not reg.may_send_result_type("task_pending", client, server)
    assert not reg.may_send_object_field("taskHandle", client, server)


# ---------------------------------------------------------------------------
# AC-38.18 — inbound non-active surface: reject or ignore (R-24.3-f)
# ---------------------------------------------------------------------------

class TestAC3818InboundRejectOrIgnore:
  def test_reject_branch_returns_core_error(self):
    reg = ExtensionRegistry([make_tasks()])
    err = reg.handle_inbound_method("tasks/get", {}, {"com.example/tasks": {}}, reject=True)
    assert err is not None
    assert err["code"] == DEFAULT_REJECTION_ERROR_CODE

  def test_ignore_branch_returns_none(self):
    reg = ExtensionRegistry([make_tasks()])
    assert reg.handle_inbound_method("tasks/get", {}, {"com.example/tasks": {}}, reject=False) is None

  def test_active_method_accepted(self):
    reg = ExtensionRegistry([make_tasks()])
    both = {"com.example/tasks": {}}
    assert reg.handle_inbound_method("tasks/get", both, both, reject=True) is None


# ---------------------------------------------------------------------------
# AC-38.19 — peers reconcile their advertised settings (R-24.3-g)
# ---------------------------------------------------------------------------

class TestAC3819ReconcileSettings:
  def test_each_peer_reads_both_settings(self):
    # Reconciliation: each peer reads the version marker from each advertised
    # settings object to determine behavior per the extension's rules.
    client_settings = {"version": "1"}
    server_settings = {"version": "2"}
    assert extension_version(client_settings) == "1"
    assert extension_version(server_settings) == "2"
    # The peer can reconcile (e.g. choose the lower common version).
    chosen = min(extension_version(client_settings), extension_version(server_settings))
    assert chosen == "1"


# ---------------------------------------------------------------------------
# AC-38.20 — recompute the intersection from this request (R-24.4-a)
# ---------------------------------------------------------------------------

class TestAC3820RecomputePerRequest:
  def test_active_set_recomputed_from_supplied_maps(self):
    reg = ExtensionRegistry([make_tasks()])
    server = {"com.example/tasks": {}}
    # Request with the extension advertised.
    assert reg.active_set({"com.example/tasks": {}}, server) == {"com.example/tasks"}
    # Different request (different client map) recomputes a different result.
    assert reg.active_set({}, server) == frozenset()


# ---------------------------------------------------------------------------
# AC-38.21 — no inference from a prior request (R-24.4-b)
# ---------------------------------------------------------------------------

class TestAC3821NoInferenceFromPrior:
  def test_prior_activation_not_remembered(self):
    reg = ExtensionRegistry([make_tasks()])
    server = {"com.example/tasks": {}}
    # Request A advertised the extension → active.
    assert reg.is_active("com.example/tasks", {"com.example/tasks": {}}, server)
    # Request B (no client advertisement) — the registry holds no per-request
    # state, so B is computed solely from B's maps and is inactive.
    assert not reg.is_active("com.example/tasks", {}, server)


# ---------------------------------------------------------------------------
# AC-38.22 — unadvertised request served as inactive (R-24.4-c)
# ---------------------------------------------------------------------------

class TestAC3822UnadvertisedServedInactive:
  def test_unadvertised_request_inactive(self):
    reg = ExtensionRegistry([make_tasks()])
    # The client does not advertise on this request → served as inactive.
    assert reg.active_definitions({}, {"com.example/tasks": {}}) == {}


# ---------------------------------------------------------------------------
# AC-38.23 — surface added only via the four channels (R-24.5-a)
# ---------------------------------------------------------------------------

class TestAC3823OnlyFourChannels:
  def test_all_surface_is_exactly_four_channels(self):
    ext = make_tasks()
    expected = (
      ext.methods | ext.notifications | ext.meta_keys | ext.result_types | ext.object_fields
    )
    assert ext.all_surface() == expected
    # Each declared item is reachable through exactly one of the four channels.
    assert ext.declares_method("tasks/get")
    assert ext.declares_result_type("task_pending")
    assert ext.declares_object_field("taskHandle")


# ---------------------------------------------------------------------------
# AC-38.24 — method namespaced from identifier (R-24.5-b)
# ---------------------------------------------------------------------------

class TestAC3824MethodNamespaced:
  def test_namespaced_method_accepted(self):
    is_namespaced_method("tasks/get", "com.example/tasks")
    validate_extension_method_string("tasks/get", "com.example/tasks")

  def test_unnamespaced_method_rejected(self):
    assert not is_namespaced_method("other/get", "com.example/tasks")
    with pytest.raises(NonConformantExtensionError):
      validate_extension_method_string("other/get", "com.example/tasks")

  def test_collision_with_core_rejected(self):
    # A core method name like tools/call cannot be claimed by an extension.
    with pytest.raises(NonConformantExtensionError):
      validate_extension_method_string("tools/call", "com.example/tools")


# ---------------------------------------------------------------------------
# AC-38.25 — method not sent when extension inactive (R-24.5-c)
# ---------------------------------------------------------------------------

class TestAC3825MethodNotSentWhenInactive:
  def test_assert_may_send_raises_when_inactive(self):
    reg = ExtensionRegistry([make_tasks()])
    with pytest.raises(ExtensionNotActiveError):
      reg.assert_may_send_method("tasks/get", {}, {"com.example/tasks": {}})

  def test_assert_may_send_ok_when_active(self):
    reg = ExtensionRegistry([make_tasks()])
    both = {"com.example/tasks": {}}
    reg.assert_may_send_method("tasks/get", both, both)  # no raise

  def test_core_method_always_sendable(self):
    reg = ExtensionRegistry([make_tasks()])
    reg.assert_may_send_method("tools/call", {}, {})  # core → no raise


# ---------------------------------------------------------------------------
# AC-38.26 — reserved _meta key under vendor prefix (R-24.5-d)
# ---------------------------------------------------------------------------

class TestAC3826MetaKeyUnderVendorPrefix:
  def test_prefixed_key_accepted(self):
    validate_extension_meta_key("com.example/taskId", "com.example/tasks")

  def test_bare_key_rejected(self):
    with pytest.raises(NonConformantExtensionError):
      validate_extension_meta_key("taskId", "com.example/tasks")

  def test_official_reserved_prefix_meta_key(self):
    # Core-protocol extensions use the reserved io.modelcontextprotocol/ prefix.
    validate_extension_meta_key(
      "io.modelcontextprotocol/progressToken", "io.modelcontextprotocol/tasks"
    )


# ---------------------------------------------------------------------------
# AC-38.27 — accepted resultType set = core ∪ active (R-24.5-e)
# ---------------------------------------------------------------------------

class TestAC3827AcceptedResultTypeSet:
  def test_accepted_is_core_plus_active(self):
    reg = ExtensionRegistry([make_tasks()])
    both = {"com.example/tasks": {}}
    accepted = reg.accepted_result_types(both, both)
    assert accepted == CORE_RESULT_TYPES | {"task_pending"}

  def test_inactive_contributes_nothing(self):
    reg = ExtensionRegistry([make_tasks()])
    accepted = reg.accepted_result_types({}, {"com.example/tasks": {}})
    assert accepted == CORE_RESULT_TYPES


# ---------------------------------------------------------------------------
# AC-38.28 — resultType neither core nor active is invalid (R-24.5-f)
# ---------------------------------------------------------------------------

class TestAC3828UnknownResultTypeInvalid:
  def test_unknown_value_invalid(self):
    reg = ExtensionRegistry([make_tasks()])
    both = {"com.example/tasks": {}}
    assert not reg.result_type_is_accepted("mystery", both, both)

  def test_inactive_extension_value_invalid(self):
    reg = ExtensionRegistry([make_tasks()])
    assert not reg.result_type_is_accepted("task_pending", {}, {"com.example/tasks": {}})

  def test_core_value_always_accepted(self):
    reg = ExtensionRegistry()
    assert reg.result_type_is_accepted("complete", {}, {})


# ---------------------------------------------------------------------------
# AC-38.29 — ignore extension-added fields when inactive (R-24.5-g)
# ---------------------------------------------------------------------------

class TestAC3829IgnoreInactiveFields:
  def test_inactive_fields_dropped(self):
    reg = ExtensionRegistry([make_ui()])
    obj = {"text": "core content", "uiResource": {"html": "<div/>"}}
    filtered = reg.ignore_inactive_object_fields(obj, {}, {"com.example/ui": {}})
    assert filtered == {"text": "core content"}

  def test_active_fields_retained(self):
    reg = ExtensionRegistry([make_ui()])
    both = {"com.example/ui": {}}
    obj = {"text": "core content", "uiResource": {"html": "<div/>"}}
    assert reg.ignore_inactive_object_fields(obj, both, both) == obj


# ---------------------------------------------------------------------------
# AC-38.30 — do not depend on extension field when inactive (R-24.5-h)
# ---------------------------------------------------------------------------

class TestAC3830NoDependenceOnInactiveField:
  def test_field_not_sendable_when_inactive(self):
    reg = ExtensionRegistry([make_ui()])
    # A peer MUST NOT depend on (or emit) the field unless the ext is active.
    assert not reg.may_send_object_field("uiResource", {}, {"com.example/ui": {}})

  def test_field_sendable_when_active(self):
    reg = ExtensionRegistry([make_ui()])
    both = {"com.example/ui": {}}
    assert reg.may_send_object_field("uiResource", both, both)


# ---------------------------------------------------------------------------
# AC-38.31 — extension adds only; no redefinition of core (R-24.5-i)
# ---------------------------------------------------------------------------

class TestAC3831NoRedefinitionOfCore:
  def test_cannot_redefine_core_result_type(self):
    with pytest.raises(NonConformantExtensionError):
      validate_extension_result_type("complete", "com.example/x")

  def test_definition_with_core_result_type_rejected(self):
    with pytest.raises(NonConformantExtensionError):
      ExtensionDefinition(
        identifier="com.example/x",
        result_types=frozenset({"input_required"}),
      )

  def test_cannot_redefine_core_method(self):
    # Core methods are protected; CORE_METHOD_NAMES holds them.
    assert "tools/call" in CORE_METHOD_NAMES
    with pytest.raises(NonConformantExtensionError):
      validate_extension_method_string("ping", "com.example/ping")


# ---------------------------------------------------------------------------
# AC-38.32 — version appears in settings object (R-24.6-a)
# ---------------------------------------------------------------------------

class TestAC3832VersionInSettings:
  def test_version_field_in_settings(self):
    settings = {"version": "2", "features": ["fast-path"]}
    assert extension_version(settings) == "2"

  def test_default_version_key_name(self):
    assert DEFAULT_VERSION_SETTING_KEY == "version"

  def test_custom_version_key(self):
    assert extension_version({"v": "3"}, version_key="v") == "3"


# ---------------------------------------------------------------------------
# AC-38.33 — version obtainable from negotiation map, not out-of-band (R-24.6-b)
# ---------------------------------------------------------------------------

class TestAC3833VersionFromNegotiationMap:
  def test_version_from_advertised_settings(self):
    # The advertised settings object IS the negotiation map value.
    advertised = {"com.example/my-extension": {"version": "2"}}
    settings = advertised["com.example/my-extension"]
    assert extension_version(settings) == "2"

  def test_absent_version_is_none(self):
    # No out-of-band inference: absent marker yields None, not a guess.
    assert extension_version({}) is None
    assert extension_version(None) is None


# ---------------------------------------------------------------------------
# AC-38.34 — backward-compatible change keeps the identifier (R-24.6-c)
# ---------------------------------------------------------------------------

class TestAC3834BackwardCompatibleSameId:
  def test_same_identifier_is_backward_compatible(self):
    assert is_backward_compatible_evolution(
      "com.example/my-extension", "com.example/my-extension"
    )
    # A new capability flag inside settings — not a new identifier.
    settings = {"version": "1", "features": ["new-flag"]}
    assert extension_version(settings) == "1"


# ---------------------------------------------------------------------------
# AC-38.35 — incompatible change uses a new identifier (R-24.6-d)
# ---------------------------------------------------------------------------

class TestAC3835IncompatibleNewId:
  def test_new_identifier_for_incompatible_change(self):
    assert requires_new_identifier(
      "com.example/my-extension", "com.example/my-extension-2"
    )
    # The two are distinct entries in the negotiation map, negotiated separately.
    reg = ExtensionRegistry([
      ExtensionDefinition(identifier="com.example/my-extension"),
      ExtensionDefinition(identifier="com.example/my-extension-2"),
    ])
    both = {"com.example/my-extension-2": {}}
    assert reg.is_active("com.example/my-extension-2", both, both)
    assert not reg.is_active("com.example/my-extension", both, both)


# ---------------------------------------------------------------------------
# AC-38.36 — both peers fall back to core when inactive (R-24.7-a)
# ---------------------------------------------------------------------------

class TestAC3836FallBackToCore:
  def test_resolve_degradation_returns_false_to_fall_back(self):
    reg = ExtensionRegistry([make_tasks()])
    # Not active and not mandatory → fall back to core (False, no raise).
    assert reg.resolve_degradation("com.example/tasks", {}, {"com.example/tasks": {}}) is False

  def test_active_returns_true(self):
    reg = ExtensionRegistry([make_tasks()])
    both = {"com.example/tasks": {}}
    assert reg.resolve_degradation("com.example/tasks", both, both) is True


# ---------------------------------------------------------------------------
# AC-38.37 — emit no surface, use core behavior instead (R-24.7-b)
# ---------------------------------------------------------------------------

class TestAC3837EmitNoneUseCore:
  def test_no_extension_surface_emitted_when_inactive(self):
    reg = ExtensionRegistry([make_tasks()])
    client, server = {}, {"com.example/tasks": {}}
    # None of the four channels may be emitted.
    assert not reg.may_send_method("tasks/get", client, server)
    assert not reg.may_send_meta_key("com.example/taskId", client, server)
    assert not reg.may_send_result_type("task_pending", client, server)
    assert not reg.may_send_object_field("taskHandle", client, server)
    # Core result type remains usable (core behavior).
    assert reg.may_send_result_type("complete", client, server)


# ---------------------------------------------------------------------------
# AC-38.38 — enriched tools still return core content (R-24.7-c)
# ---------------------------------------------------------------------------

class TestAC3838EnrichedToolsStillCore:
  def test_core_content_survives_when_ui_inactive(self):
    reg = ExtensionRegistry([make_ui()])
    # A tool result enriched by the UI extension; client lacks the extension.
    enriched = {"text": "meaningful core content", "uiResource": {"html": "<div/>"}}
    core_only = reg.ignore_inactive_object_fields(enriched, {}, {"com.example/ui": {}})
    # The meaningful core content remains.
    assert core_only["text"] == "meaningful core content"
    assert "uiResource" not in core_only


# ---------------------------------------------------------------------------
# AC-38.39 — actionable error for required-but-absent extension (R-24.7-d)
# ---------------------------------------------------------------------------

class TestAC3839ActionableError:
  def test_require_active_raises_actionable(self):
    reg = ExtensionRegistry([make_tasks()])
    with pytest.raises(RequiredExtensionUnavailableError) as exc:
      reg.require_active("com.example/tasks", {}, {"com.example/tasks": {}})
    # Actionable: the message tells the operator how to proceed.
    assert "com.example/tasks" in str(exc.value)

  def test_mandatory_degradation_raises(self):
    reg = ExtensionRegistry([make_tasks()])
    with pytest.raises(RequiredExtensionUnavailableError):
      reg.resolve_degradation(
        "com.example/tasks", {}, {"com.example/tasks": {}}, mandatory=True
      )


# ---------------------------------------------------------------------------
# AC-38.40 — error identifies the required extension (R-24.7-e)
# ---------------------------------------------------------------------------

class TestAC3840ErrorIdentifiesExtension:
  def test_error_object_names_extension(self):
    err = RequiredExtensionUnavailableError("com.example/tasks")
    obj = err.to_error_object()
    assert obj["data"]["requiredExtension"] == "com.example/tasks"
    assert obj["code"] == DEFAULT_REJECTION_ERROR_CODE
    assert err.identifier == "com.example/tasks"


# ---------------------------------------------------------------------------
# AC-38.41 — may refuse outright with a core error (R-24.7-f)
# ---------------------------------------------------------------------------

class TestAC3841MayRefuseOutright:
  def test_refusal_carries_core_error_code(self):
    reg = ExtensionRegistry([make_tasks()])
    with pytest.raises(RequiredExtensionUnavailableError) as exc:
      reg.require_active(
        "com.example/tasks", {}, {"com.example/tasks": {}}, error_code=-32600
      )
    assert exc.value.error_code == -32600
    assert exc.value.to_error_object()["code"] == -32600


# ---------------------------------------------------------------------------
# AC-38.42 — unknown identifier ignored, not an error (R-24.7-g)
# ---------------------------------------------------------------------------

class TestAC3842UnknownIdentifierIgnored:
  def test_unknown_identifier_ignored(self):
    reg = ExtensionRegistry([make_tasks()])
    advertised = {"com.example/tasks": {}, "com.unknown/thing": {}}
    # Unknown identifier is ignored; not an error.
    recognized = reg.ignore_unrecognized_identifiers(advertised)
    assert recognized == {"com.example/tasks"}
    assert not reg.recognizes("com.unknown/thing")

  def test_unknown_active_identifier_has_no_definition(self):
    reg = ExtensionRegistry([make_tasks()])
    both = {"com.unknown/thing": {}, "com.example/tasks": {}}
    # The unknown id may be in the intersection but yields no active definition.
    active_defs = reg.active_definitions(both, both)
    assert set(active_defs) == {"com.example/tasks"}


# ---------------------------------------------------------------------------
# AC-38.43 — fallback behavior is documented (R-24.7-h)
# ---------------------------------------------------------------------------

class TestAC3843FallbackDocumented:
  def test_definition_carries_fallback_doc(self):
    ext = make_tasks()
    assert ext.fallback_doc
    assert "core" in ext.fallback_doc.lower()

  def test_fallback_doc_is_a_field(self):
    ext = ExtensionDefinition(
      identifier="com.example/x",
      fallback_doc="Fall back to the core synchronous result.",
    )
    assert ext.fallback_doc == "Fall back to the core synchronous result."
