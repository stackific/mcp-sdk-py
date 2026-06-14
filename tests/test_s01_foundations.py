"""Tests for S01 — Protocol Foundations & Conformance Model.

Every test is mapped to one or more acceptance criteria from the story.
The criterion tag in each docstring (e.g. "AC-01.28") is the traceability
reference to the story's acceptance-criteria table.
"""

import pytest

from mcp_sdk_py.common_types import Icon
from mcp_sdk_py.foundations import (
  CONFORMANCE_BASELINE,
  ConformanceError,
  DeprecationStatus,
  Implementation,
  MessageKind,
  MissingCapabilityError,
  RequirementLevel,
  Role,
)


# ---------------------------------------------------------------------------
# AC-01.1  Role topology: Host, Client, Server exist
# ---------------------------------------------------------------------------

class TestRoleTopology:
  """AC-01.1: A host MAY run many clients; each client bound to one server."""

  def test_all_roles_defined(self):
    assert Role.HOST.value == "host"
    assert Role.CLIENT.value == "client"
    assert Role.SERVER.value == "server"

  def test_roles_are_distinct(self):
    assert Role.HOST is not Role.CLIENT
    assert Role.CLIENT is not Role.SERVER
    assert Role.HOST is not Role.SERVER

  def test_role_enum_has_exactly_three_members(self):
    """Exactly three roles are defined by the spec (§1.1)."""
    assert len(Role) == 3


# ---------------------------------------------------------------------------
# AC-01.2  Discovery is optional before other requests
# (structural: client role exists; behavioural rule documented in S08)
# ---------------------------------------------------------------------------

class TestDiscoveryOptional:
  """AC-01.2: A client MAY issue discovery before any other request; it is
  not required to do so.  The Role and MessageKind types support this without
  imposing a mandatory step.
  """

  def test_client_role_exists(self):
    """Client role must be available so the host can create connectors."""
    assert Role.CLIENT in list(Role)

  def test_server_role_exists(self):
    """Server role must be available to represent the receiving endpoint."""
    assert Role.SERVER in list(Role)


# ---------------------------------------------------------------------------
# AC-01.3 / AC-01.4  Clients and servers MAY receive/send embedded input
# (structural: MessageKind supports all three message kinds)
# ---------------------------------------------------------------------------

class TestMessageKindExists:
  """AC-01.3, AC-01.4: Client and server endpoints can receive/send all
  three message kinds (including notifications and embedded input requests
  which arrive as result payloads; the latter are defined in §11 / S11).
  """

  def test_all_message_kinds_defined(self):
    assert MessageKind.REQUEST.value == "request"
    assert MessageKind.RESPONSE.value == "response"
    assert MessageKind.NOTIFICATION.value == "notification"

  def test_message_kind_enum_has_exactly_three_members(self):
    assert len(MessageKind) == 3


# ---------------------------------------------------------------------------
# AC-01.5  Request → exactly one response  [R-2.2-c]
# ---------------------------------------------------------------------------

class TestRequestRequiresResponse:
  """AC-01.5: A REQUEST requires the receiver to return exactly one
  matching response (R-2.2-c).
  """

  def test_request_requires_response(self):
    assert MessageKind.REQUEST.requires_response is True

  def test_response_does_not_require_another_response(self):
    assert MessageKind.RESPONSE.requires_response is False

  def test_notification_does_not_require_response(self):
    assert MessageKind.NOTIFICATION.requires_response is False


# ---------------------------------------------------------------------------
# AC-01.6  Request carries id, method, optional params  [R-2.2-d]
# ---------------------------------------------------------------------------

class TestRequestShape:
  """AC-01.6: A request carries an id, a method, and OPTIONAL parameters."""

  def test_request_has_id(self):
    assert MessageKind.REQUEST.has_id is True

  def test_response_has_id(self):
    """Responses also carry the correlation id."""
    assert MessageKind.RESPONSE.has_id is True

  def test_notification_has_no_id(self):
    """Notifications MUST NOT carry an id (R-2.2-e)."""
    assert MessageKind.NOTIFICATION.has_id is False


# ---------------------------------------------------------------------------
# AC-01.7  Notification: method + optional params, no id, no response
# [R-2.2-e]
# ---------------------------------------------------------------------------

class TestNotificationShape:
  """AC-01.7: A notification carries a method and OPTIONAL parameters but
  no id; the receiver MUST NOT send any response to it (R-2.2-e).
  """

  def test_notification_must_not_respond(self):
    assert MessageKind.NOTIFICATION.must_not_respond is True

  def test_request_may_receive_response(self):
    assert MessageKind.REQUEST.must_not_respond is False

  def test_response_does_not_trigger_further_response(self):
    assert MessageKind.RESPONSE.must_not_respond is False


# ---------------------------------------------------------------------------
# AC-01.8  Statelessness: server derives state only from current request
# [R-1.5-a]
#
# The stateless per-request model is operationalised in S06; here we verify
# that the SDK exposes no mechanism for a server to store per-connection state
# in the foundation layer — only per-request context will be threaded through.
# ---------------------------------------------------------------------------

class TestStatelessness:
  """AC-01.8, AC-01.9, AC-01.10, AC-01.11: Statelessness invariants.

  The foundation module itself holds no mutable per-connection state,
  confirming the design principle: servers MUST NOT infer state from prior
  requests (R-1.5-a, R-1.5-b).
  """

  def test_foundations_module_holds_no_mutable_connection_state(self):
    """The module-level objects in foundations.py are all immutable."""
    import mcp_sdk_py.foundations as f
    mutable_module_attrs = [
      k for k, v in vars(f).items()
      if not k.startswith("_") and isinstance(v, (list, dict, set))
    ]
    assert mutable_module_attrs == [], (
      f"Unexpected mutable module-level state: {mutable_module_attrs}"
    )

  def test_implementation_is_not_a_connection_proxy(self):
    """Implementation descriptor carries identity metadata, not session state.
    It contains only name, version, title, icons — no connection/session handle.
    """
    impl = Implementation(name="x", version="1")
    assert not hasattr(impl, "connection")
    assert not hasattr(impl, "session")
    assert not hasattr(impl, "_requests")


# ---------------------------------------------------------------------------
# AC-01.12 / AC-01.13  Capability respect and non-exercise  [R-1.5-e / f]
# AC-01.14  No capability inference from prior request  [R-2.2.2-a]
# AC-01.15  Missing-capability rejection  [R-2.2.2-c]
# ---------------------------------------------------------------------------

class TestCapabilityModel:
  """AC-01.12–AC-01.15: Capability negotiation foundation."""

  def test_missing_capability_error_exists(self):
    """AC-01.15: SDK exposes MissingCapabilityError for servers to raise
    when a request requires an undeclared capability (R-2.2.2-c).
    """
    assert issubclass(MissingCapabilityError, Exception)

  def test_missing_capability_error_is_conformance_error(self):
    """MissingCapabilityError extends ConformanceError for typed catch blocks."""
    assert issubclass(MissingCapabilityError, ConformanceError)

  def test_missing_capability_error_can_be_raised(self):
    with pytest.raises(MissingCapabilityError):
      raise MissingCapabilityError("client did not declare capability 'tools'")

  def test_conformance_error_is_catchable_base(self):
    with pytest.raises(ConformanceError):
      raise MissingCapabilityError("missing capability")


# ---------------------------------------------------------------------------
# AC-01.16  RFC 2119 keywords bear meaning only in uppercase  [R-1.4-c]
# ---------------------------------------------------------------------------

class TestRFC2119KeywordCaseSensitivity:
  """AC-01.16: Requirement keywords carry normative force only in ALL CAPS."""

  def test_all_requirement_levels_are_uppercase(self):
    """Every RequirementLevel value is its uppercase canonical form."""
    for level in RequirementLevel:
      assert level.value == level.value.upper() or "_" in level.value, (
        f"Unexpected casing for {level}"
      )

  def test_nine_or_ten_keywords_defined(self):
    """RFC 2119 defines 9 keywords; RFC 8174 confirms them. We model 10
    (splitting REQUIRED separately from MUST) for precision.
    """
    assert len(RequirementLevel) == 10


# ---------------------------------------------------------------------------
# AC-01.17  MUST / REQUIRED / SHALL = absolute requirement  [R-2.1-a]
# ---------------------------------------------------------------------------

class TestAbsoluteRequirement:
  """AC-01.17: MUST, REQUIRED, SHALL are absolute — no exceptions."""

  @pytest.mark.parametrize("level", [
    RequirementLevel.MUST,
    RequirementLevel.REQUIRED,
    RequirementLevel.SHALL,
  ])
  def test_absolute_requirement_flag(self, level):
    assert level.is_absolute_requirement is True

  @pytest.mark.parametrize("level", [
    RequirementLevel.MUST_NOT,
    RequirementLevel.SHOULD,
    RequirementLevel.MAY,
    RequirementLevel.OPTIONAL,
  ])
  def test_non_requirement_not_flagged(self, level):
    assert level.is_absolute_requirement is False


# ---------------------------------------------------------------------------
# AC-01.18  MUST NOT / SHALL NOT = absolute prohibition  [R-2.1-b]
# ---------------------------------------------------------------------------

class TestAbsoluteProhibition:
  """AC-01.18: MUST NOT, SHALL NOT are absolute prohibitions."""

  @pytest.mark.parametrize("level", [
    RequirementLevel.MUST_NOT,
    RequirementLevel.SHALL_NOT,
  ])
  def test_absolute_prohibition_flag(self, level):
    assert level.is_absolute_prohibition is True

  @pytest.mark.parametrize("level", [
    RequirementLevel.MUST,
    RequirementLevel.SHOULD,
    RequirementLevel.MAY,
  ])
  def test_non_prohibition_not_flagged(self, level):
    assert level.is_absolute_prohibition is False


# ---------------------------------------------------------------------------
# AC-01.19  SHOULD / RECOMMENDED: deviation only with valid reason  [R-2.1-c]
# ---------------------------------------------------------------------------

class TestConditionalRequirement:
  """AC-01.19: SHOULD and RECOMMENDED allow deviation when fully understood."""

  @pytest.mark.parametrize("level", [
    RequirementLevel.SHOULD,
    RequirementLevel.RECOMMENDED,
  ])
  def test_conditional_flag(self, level):
    assert level.is_conditional is True

  def test_must_is_not_conditional(self):
    assert RequirementLevel.MUST.is_conditional is False


# ---------------------------------------------------------------------------
# AC-01.20  SHOULD NOT: adoption only with valid reason  [R-2.1-d]
# ---------------------------------------------------------------------------

class TestConditionalProhibition:
  """AC-01.20: SHOULD NOT is a conditional prohibition."""

  def test_should_not_is_conditional_prohibition(self):
    assert RequirementLevel.SHOULD_NOT.is_conditional_prohibition is True

  def test_must_not_is_not_conditional_prohibition(self):
    assert RequirementLevel.MUST_NOT.is_conditional_prohibition is False


# ---------------------------------------------------------------------------
# AC-01.21  MAY / OPTIONAL: both choices are conforming  [R-2.1-e]
# ---------------------------------------------------------------------------

class TestDiscretionary:
  """AC-01.21: MAY/OPTIONAL are truly discretionary; both parties must
  interoperate regardless of whether a MAY feature is included or omitted.
  """

  @pytest.mark.parametrize("level", [
    RequirementLevel.MAY,
    RequirementLevel.OPTIONAL,
  ])
  def test_discretionary_flag(self, level):
    assert level.is_discretionary is True

  @pytest.mark.parametrize("level", [
    RequirementLevel.MUST,
    RequirementLevel.MUST_NOT,
    RequirementLevel.SHOULD,
  ])
  def test_non_discretionary_not_flagged(self, level):
    assert level.is_discretionary is False


# ---------------------------------------------------------------------------
# AC-01.22  Conformance = satisfying every MUST/SHALL for implemented features
# [R-2.1-f]
# (structural: the SDK models this via ConformanceError and clear type system)
# ---------------------------------------------------------------------------

class TestConformanceDefinition:
  """AC-01.22: An implementation is conforming iff it satisfies every
  applicable MUST/MUST NOT/SHALL/SHALL NOT for its implemented roles/features.

  The SDK enforces this by raising ConformanceError subclasses at the point
  of violation, enabling callers to catch and handle violations by type.
  """

  def test_conformance_error_is_exception(self):
    assert issubclass(ConformanceError, Exception)

  def test_conformance_error_can_be_raised(self):
    with pytest.raises(ConformanceError):
      raise ConformanceError("conformance violation")


# ---------------------------------------------------------------------------
# AC-01.23  Conformance baseline: every party MUST support it  [R-1.4-a, R-2.1-g]
# ---------------------------------------------------------------------------

class TestConformanceBaseline:
  """AC-01.23: Every conforming party supports base message format,
  protocol revision handling, and core message patterns.
  """

  def test_baseline_is_non_empty(self):
    assert len(CONFORMANCE_BASELINE) > 0

  def test_baseline_contains_required_items(self):
    assert "base-message-format" in CONFORMANCE_BASELINE
    assert "protocol-revision-handling" in CONFORMANCE_BASELINE
    assert "core-message-patterns" in CONFORMANCE_BASELINE

  def test_baseline_is_immutable_tuple(self):
    """Immutable to prevent accidental runtime modification."""
    assert isinstance(CONFORMANCE_BASELINE, tuple)


# ---------------------------------------------------------------------------
# AC-01.24  Features beyond the base set MAY be omitted  [R-1.4-b, R-2.1-h]
# (structural: RequirementLevel.MAY models this precisely)
# ---------------------------------------------------------------------------

class TestOptionalFeatures:
  """AC-01.24: Tools, Resources, Prompts, Completion, Elicitation, utilities,
  and the extension mechanism are all MAY / OPTIONAL — implementors may omit
  them without losing conformance.
  """

  def test_may_is_discretionary(self):
    assert RequirementLevel.MAY.is_discretionary is True

  def test_optional_is_discretionary(self):
    assert RequirementLevel.OPTIONAL.is_discretionary is True


# ---------------------------------------------------------------------------
# AC-01.25  Implemented optional features must conform  [R-2.1-i]
# (structural: SDK will raise ConformanceError for rule violations within
# any implemented optional feature)
# ---------------------------------------------------------------------------

class TestImplementedFeaturesMustConform:
  """AC-01.25: When an optional feature is implemented it MUST still satisfy
  every rule defined for it.  The SDK signals violations via ConformanceError.
  """

  def test_conformance_error_hierarchy(self):
    """MissingCapabilityError is a ConformanceError, establishing the pattern
    that all per-feature violations extend ConformanceError.
    """
    assert issubclass(MissingCapabilityError, ConformanceError)


# ---------------------------------------------------------------------------
# AC-01.26  Deprecated features SHOULD NOT be relied on by new impls
# [R-1.3-b, R-2.2-g]
# ---------------------------------------------------------------------------

class TestDeprecationShouldNotRely:
  """AC-01.26: New implementations should not rely on deprecated features."""

  def test_deprecated_status_should_not_rely_on(self):
    assert DeprecationStatus.DEPRECATED.should_not_rely_on is True

  def test_active_status_is_reliance_safe(self):
    assert DeprecationStatus.ACTIVE.should_not_rely_on is False

  def test_deprecation_status_has_two_values(self):
    assert len(DeprecationStatus) == 2


# ---------------------------------------------------------------------------
# AC-01.27  Deprecated features MUST still be accepted  [R-2.2-f, R-2.2-h]
# ---------------------------------------------------------------------------

class TestDeprecationMustAccept:
  """AC-01.27: Receivers MUST accept deprecated features and process them
  per their definition while they bear the Deprecated status.
  """

  def test_deprecated_must_still_accept(self):
    assert DeprecationStatus.DEPRECATED.must_still_accept is True

  def test_active_must_not_mark_as_deprecated_accept(self):
    """ACTIVE features don't carry the 'must accept despite deprecation' flag."""
    assert DeprecationStatus.ACTIVE.must_still_accept is False


# ---------------------------------------------------------------------------
# AC-01.28  Implementation requires name and version  [R-2.2.1-a–c]
# ---------------------------------------------------------------------------

class TestImplementationRequiredFields:
  """AC-01.28: An Implementation MUST have name (R-2.2.1-b) and version
  (R-2.2.1-c); both are non-empty strings.
  """

  def test_minimal_implementation(self):
    impl = Implementation(name="example-server", version="1.0.0")
    assert impl.name == "example-server"
    assert impl.version == "1.0.0"

  def test_missing_name_raises(self):
    with pytest.raises((ValueError, TypeError, KeyError)):
      Implementation(name="", version="1.0.0")  # empty string = missing

  def test_none_name_raises(self):
    with pytest.raises((ValueError, TypeError)):
      Implementation(name=None, version="1.0.0")  # type: ignore[arg-type]

  def test_missing_version_raises(self):
    with pytest.raises((ValueError, TypeError, KeyError)):
      Implementation(name="server", version="")

  def test_none_version_raises(self):
    with pytest.raises((ValueError, TypeError)):
      Implementation(name="server", version=None)  # type: ignore[arg-type]

  def test_from_dict_minimal(self):
    data = {"name": "example-mcp-server", "version": "1.4.2"}
    impl = Implementation.from_dict(data)
    assert impl.name == "example-mcp-server"
    assert impl.version == "1.4.2"

  def test_from_dict_missing_name_raises(self):
    with pytest.raises(KeyError):
      Implementation.from_dict({"version": "1.0"})

  def test_from_dict_missing_version_raises(self):
    with pytest.raises(KeyError):
      Implementation.from_dict({"name": "server"})

  def test_to_dict_minimal(self):
    impl = Implementation(name="example-mcp-server", version="1.4.2")
    assert impl.to_dict() == {"name": "example-mcp-server", "version": "1.4.2"}


# ---------------------------------------------------------------------------
# AC-01.29  Implementation OPTIONAL fields: title and icons  [R-2.2.1-d–e]
# ---------------------------------------------------------------------------

class TestImplementationOptionalFields:
  """AC-01.29: title and icons MAY be present or absent without making the
  object invalid (R-2.2.1-d, R-2.2.1-e).
  """

  def test_title_absent_by_default(self):
    impl = Implementation(name="s", version="1")
    assert impl.title is None

  def test_icons_absent_by_default(self):
    impl = Implementation(name="s", version="1")
    assert impl.icons is None

  def test_title_present(self):
    impl = Implementation(name="s", version="1", title="Example MCP Server")
    assert impl.title == "Example MCP Server"

  def test_icons_present(self):
    icons = [Icon(src="https://example.com/icon.png")]
    impl = Implementation(name="s", version="1", icons=icons)
    assert impl.icons == icons

  def test_to_dict_omits_absent_optional_fields(self):
    impl = Implementation(name="s", version="1")
    d = impl.to_dict()
    assert "title" not in d
    assert "icons" not in d

  def test_to_dict_includes_present_optional_fields(self):
    impl = Implementation(
      name="s",
      version="1",
      title="My Server",
      icons=[Icon(src="https://example.com/icon.png")],
    )
    d = impl.to_dict()
    assert d["title"] == "My Server"
    assert d["icons"] == [{"src": "https://example.com/icon.png"}]

  def test_from_dict_with_optional_fields(self):
    data = {
      "name": "example-mcp-server",
      "version": "1.4.2",
      "title": "Example MCP Server",
      "icons": [{"src": "https://example.com/icon.png"}],
    }
    impl = Implementation.from_dict(data)
    assert impl.title == "Example MCP Server"
    assert impl.icons == [Icon(src="https://example.com/icon.png")]


# ---------------------------------------------------------------------------
# AC-01.30  Implementation ignores unknown implementation-defined properties
# [R-2.2.1-f, R-2.2.1-g, §2.3.4]
# ---------------------------------------------------------------------------

class TestImplementationIgnoresUnknownFields:
  """AC-01.30: Additional implementation-defined properties MAY appear in an
  Implementation object; receivers MUST ignore those they do not recognise
  (R-2.2.1-g, §2.3.4).
  """

  def test_from_dict_ignores_unknown_vendor_field(self):
    """Vendor-extension key must not cause an error (forward-compatibility)."""
    data = {
      "name": "example-mcp-server",
      "version": "1.4.2",
      "x-vendor-buildId": "2026-06-13-abc123",
    }
    impl = Implementation.from_dict(data)
    assert impl.name == "example-mcp-server"
    assert impl.version == "1.4.2"
    assert not hasattr(impl, "x-vendor-buildId")

  def test_from_dict_ignores_multiple_unknown_fields(self):
    data = {
      "name": "srv",
      "version": "2",
      "unknown-a": 42,
      "unknown-b": {"nested": True},
      "unknown-c": [1, 2, 3],
    }
    impl = Implementation.from_dict(data)
    assert impl.name == "srv"
    assert impl.version == "2"

  def test_from_dict_full_spec_example(self):
    """Wire example from the story: a 'fuller' Implementation object with
    optional fields and a vendor extension (R-2.2.1-f, R-2.2.1-g).
    """
    data = {
      "name": "example-mcp-server",
      "version": "1.4.2",
      "title": "Example MCP Server",
      "icons": [{"src": "https://example.com/icon.png"}],
      "x-vendor-buildId": "2026-06-13-abc123",
    }
    impl = Implementation.from_dict(data)
    assert impl.name == "example-mcp-server"
    assert impl.version == "1.4.2"
    assert impl.title == "Example MCP Server"
    assert impl.icons == [Icon(src="https://example.com/icon.png")]
