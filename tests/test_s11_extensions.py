"""Tests for S11 — The Extensions Map & Forward Compatibility (§6.5–§6.7).

Each test class maps to one or more acceptance criteria (AC-11.x). The §6.7
worked examples are exercised verbatim where they appear in the story.

AC → test coverage map:
  AC-11.1  (R-6.5-a) — TestAC1101PrefixRequired
  AC-11.2  (R-6.5-b) — TestAC1102LabelStartEnd
  AC-11.3  (R-6.5-c) — TestAC1103LabelInteriorHyphen
  AC-11.4  (R-6.5-d) — TestAC1104ReverseDnsRecommended
  AC-11.5  (R-6.5-e) — TestAC1105NameBeginsEndsAlnum
  AC-11.6  (R-6.5-f) — TestAC1106NameInteriorChars
  AC-11.7  (R-6.5-g) — TestAC1107ReservedPrefixes
  AC-11.8  (R-6.5-h) — TestAC1108EmptyObjectEnables
  AC-11.9  (R-6.5-i) — TestAC1109ProducerNoNull
  AC-11.10 (R-6.5-j) — TestAC1110NullEntryIgnored
  AC-11.11 (R-6.5-k) — TestAC1111IgnoreUndefinedSettings
  AC-11.12 (R-6.5-l) — TestAC1112ActivationByIntersection
  AC-11.13 (R-6.5-m) — TestAC1113DisabledByDefault
  AC-11.14 (R-6.5-n) — TestAC1114OneSidedFallbackOrReject
  AC-11.15 (R-6.6-a) — TestAC1115TolerateUnknown
  AC-11.16 (R-6.6-b) — TestAC1116IgnoreUnknownCapabilityField
  AC-11.17 (R-6.6-c) — TestAC1117UnknownFieldNoReject
  AC-11.18 (R-6.6-d) — TestAC1118IgnoreUnknownExtensionKey
  AC-11.19 (R-6.6-e) — TestAC1119IgnoreUnknownSettingsKey
  AC-11.20 (R-6.6-f) — TestAC1120UnknownNotError
  AC-11.21 (R-6.6-g) — TestAC1121AbsenceImpliesNothing
  AC-11.22 (R-6.7-a) — TestAC1122Section67Examples
"""

import pytest

from mcp_sdk_py.capabilities import ClientCapabilities, ServerCapabilities
from mcp_sdk_py.extensions import (
  KNOWN_CLIENT_CAPABILITY_FIELDS,
  KNOWN_SERVER_CAPABILITY_FIELDS,
  CapabilityFieldSupport,
  ExtensionNotActiveError,
  InvalidExtensionIdentifierError,
  MandatoryExtensionUnavailableError,
  active_extensions,
  advertised_extension_ids,
  assert_extension_active,
  extension_setting,
  ignore_unknown_capability_fields,
  is_extension_active,
  is_forward_compatible_error,
  is_reserved_extension_prefix,
  is_valid_extension_label,
  is_valid_extension_name,
  is_valid_extension_prefix,
  is_valid_settings_value,
  is_well_formed_extension_identifier,
  parse_extensions_map,
  recognized_extensions,
  resolve_one_sided_extension,
  select_known_settings,
  split_extension_identifier,
  unknown_capability_fields,
  validate_extension_identifier,
)


# ---------------------------------------------------------------------------
# AC-11.1 — a prefix is REQUIRED (R-6.5-a)
# ---------------------------------------------------------------------------

class TestAC1101PrefixRequired:
  def test_slashless_name_has_no_prefix(self):
    prefix, name = split_extension_identifier("/tasks")
    # "/tasks" -> first slash at index 0 -> empty prefix, but split keeps it as
    # the segment before the slash; the empty prefix is itself invalid.
    assert prefix == ""
    assert name == "tasks"

  def test_no_slash_means_missing_prefix(self):
    prefix, name = split_extension_identifier("tasks")
    assert prefix is None
    assert name == "tasks"

  def test_identifier_without_prefix_is_malformed(self):
    assert not is_well_formed_extension_identifier("/tasks")

  def test_validate_rejects_missing_prefix(self):
    with pytest.raises(InvalidExtensionIdentifierError):
      validate_extension_identifier("/tasks")

  def test_validate_rejects_no_slash_at_all(self):
    with pytest.raises(InvalidExtensionIdentifierError):
      validate_extension_identifier("tasks")

  def test_well_formed_identifier_with_prefix_passes(self):
    assert is_well_formed_extension_identifier("io.modelcontextprotocol/tasks")
    validate_extension_identifier("com.example/tasks")  # does not raise


# ---------------------------------------------------------------------------
# AC-11.2 — each label starts with a letter, ends with letter/digit (R-6.5-b)
# ---------------------------------------------------------------------------

class TestAC1102LabelStartEnd:
  def test_label_not_starting_with_letter_invalid(self):
    assert not is_valid_extension_label("1com")
    assert not is_valid_extension_prefix("1com")
    assert not is_well_formed_extension_identifier("1com/x")
    with pytest.raises(InvalidExtensionIdentifierError):
      validate_extension_identifier("1com/x")

  def test_label_not_ending_with_letter_or_digit_invalid(self):
    assert not is_valid_extension_label("com-")
    assert not is_valid_extension_prefix("com-")
    assert not is_well_formed_extension_identifier("com-/x")
    with pytest.raises(InvalidExtensionIdentifierError):
      validate_extension_identifier("com-/x")

  def test_simple_letter_label_is_valid(self):
    assert is_valid_extension_label("com")
    assert is_valid_extension_prefix("com")

  def test_label_ending_in_digit_is_valid(self):
    assert is_valid_extension_label("v2")
    assert is_valid_extension_label("abc123")

  def test_single_letter_label_is_valid(self):
    # First char (a letter) is also the last char (a letter) — valid.
    assert is_valid_extension_label("a")
    assert is_valid_extension_prefix("a")


# ---------------------------------------------------------------------------
# AC-11.3 — interior hyphen surrounded by valid chars (R-6.5-c)
# ---------------------------------------------------------------------------

class TestAC1103LabelInteriorHyphen:
  def test_interior_hyphen_label_accepted(self):
    assert is_valid_extension_label("my-org")
    assert is_valid_extension_prefix("my-org")
    assert is_well_formed_extension_identifier("my-org/ext")

  def test_multiple_interior_hyphens_accepted(self):
    assert is_valid_extension_label("a-b-c")

  def test_leading_or_trailing_hyphen_rejected(self):
    assert not is_valid_extension_label("-org")
    assert not is_valid_extension_label("org-")


# ---------------------------------------------------------------------------
# AC-11.4 — reverse-DNS RECOMMENDED and well-formed (R-6.5-d)
# ---------------------------------------------------------------------------

class TestAC1104ReverseDnsRecommended:
  def test_reverse_dns_identifier_is_well_formed(self):
    assert is_valid_extension_prefix("com.example")
    assert is_well_formed_extension_identifier("com.example/my-extension")
    validate_extension_identifier("com.example/my-extension")  # no raise

  def test_multi_label_reverse_dns_accepted(self):
    assert is_valid_extension_prefix("org.example.sub")
    assert is_well_formed_extension_identifier("org.example.sub/ext")


# ---------------------------------------------------------------------------
# AC-11.5 — non-empty name begins/ends alphanumeric; empty name allowed (R-6.5-e)
# ---------------------------------------------------------------------------

class TestAC1105NameBeginsEndsAlnum:
  def test_name_not_starting_alnum_invalid(self):
    assert not is_valid_extension_name("-tasks")
    assert not is_well_formed_extension_identifier("com.example/-tasks")
    with pytest.raises(InvalidExtensionIdentifierError):
      validate_extension_identifier("com.example/-tasks")

  def test_name_not_ending_alnum_invalid(self):
    assert not is_valid_extension_name("tasks-")
    assert not is_well_formed_extension_identifier("com.example/tasks-")
    with pytest.raises(InvalidExtensionIdentifierError):
      validate_extension_identifier("com.example/tasks-")

  def test_valid_name_accepted(self):
    assert is_valid_extension_name("oauth-client-credentials")
    assert is_well_formed_extension_identifier(
      "io.modelcontextprotocol/oauth-client-credentials"
    )

  def test_empty_name_after_slash_is_permitted(self):
    assert is_valid_extension_name("")
    assert is_well_formed_extension_identifier("com.example/")
    validate_extension_identifier("com.example/")  # no raise
    prefix, name = split_extension_identifier("com.example/")
    assert prefix == "com.example"
    assert name == ""


# ---------------------------------------------------------------------------
# AC-11.6 — non-empty name interior may use - _ . alnum (R-6.5-f)
# ---------------------------------------------------------------------------

class TestAC1106NameInteriorChars:
  def test_name_with_all_interior_classes_accepted(self):
    assert is_valid_extension_name("oauth-client_credentials.v2")
    assert is_well_formed_extension_identifier(
      "com.example/oauth-client_credentials.v2"
    )
    validate_extension_identifier("com.example/oauth-client_credentials.v2")

  def test_underscore_and_dot_interior_accepted(self):
    assert is_valid_extension_name("a_b.c-d")

  def test_interior_only_chars_not_allowed_at_edges(self):
    assert not is_valid_extension_name("_tasks")
    assert not is_valid_extension_name("tasks.")
    assert not is_valid_extension_name(".tasks")


# ---------------------------------------------------------------------------
# AC-11.7 — reserved prefixes (second label) (R-6.5-g)
# ---------------------------------------------------------------------------

class TestAC1107ReservedPrefixes:
  @pytest.mark.parametrize(
    "identifier",
    [
      "io.modelcontextprotocol/x",
      "dev.mcp/x",
      "org.modelcontextprotocol.api/x",
      "com.mcp/x",
    ],
  )
  def test_third_party_reserved_prefix_rejected(self, identifier):
    prefix, _ = split_extension_identifier(identifier)
    assert is_reserved_extension_prefix(prefix)
    with pytest.raises(InvalidExtensionIdentifierError):
      validate_extension_identifier(identifier)

  def test_mcp_as_non_second_label_not_reserved(self):
    prefix, _ = split_extension_identifier("com.example.mcp/x")
    assert not is_reserved_extension_prefix(prefix)
    # Well-formed AND allowed for third parties (its second label is "example").
    assert is_well_formed_extension_identifier("com.example.mcp/x")
    validate_extension_identifier("com.example.mcp/x")  # no raise

  def test_single_label_prefix_has_no_second_label(self):
    assert not is_reserved_extension_prefix("mcp")  # no second label
    validate_extension_identifier("mcp/x")  # single-label "mcp" is not reserved

  def test_protocol_may_mint_reserved_with_allow_reserved(self):
    # The protocol itself mints official ids; the prohibition is third-party only.
    validate_extension_identifier(
      "io.modelcontextprotocol/tasks", allow_reserved=True
    )

  def test_reserved_identifier_is_still_well_formed(self):
    # Reserved ≠ malformed: grammar is fine, only third-party use is prohibited.
    assert is_well_formed_extension_identifier("io.modelcontextprotocol/tasks")


# ---------------------------------------------------------------------------
# AC-11.8 — {} means enabled-no-settings, not absence (R-6.5-h)
# ---------------------------------------------------------------------------

class TestAC1108EmptyObjectEnables:
  def test_empty_object_is_valid_settings(self):
    assert is_valid_settings_value({})

  def test_empty_object_entry_is_advertised(self):
    raw = {"io.modelcontextprotocol/tasks": {}}
    parsed = parse_extensions_map(raw)
    assert "io.modelcontextprotocol/tasks" in parsed
    assert parsed["io.modelcontextprotocol/tasks"] == {}
    assert "io.modelcontextprotocol/tasks" in advertised_extension_ids(raw)

  def test_empty_object_treated_as_present_for_intersection(self):
    client = {"io.modelcontextprotocol/ui": {}}
    server = {"io.modelcontextprotocol/ui": {}}
    assert is_extension_active("io.modelcontextprotocol/ui", client, server)


# ---------------------------------------------------------------------------
# AC-11.9 — producer's serialized map has no null values (R-6.5-i)
# ---------------------------------------------------------------------------

class TestAC1109ProducerNoNull:
  def test_null_is_not_a_valid_settings_value(self):
    assert not is_valid_settings_value(None)

  def test_parsed_map_never_emits_null_value(self):
    raw = {
      "com.example/a": {},
      "com.example/b": {"k": 1},
      "com.example/c": None,  # malformed — must be dropped
    }
    parsed = parse_extensions_map(raw)
    assert None not in parsed.values()
    assert all(isinstance(v, dict) for v in parsed.values())

  def test_capability_object_roundtrip_has_no_null(self):
    caps = ClientCapabilities(
      extensions={"io.modelcontextprotocol/ui": {"mimeTypes": ["x"]}}
    )
    wire = caps.to_dict()
    for value in wire["extensions"].values():
      assert value is not None


# ---------------------------------------------------------------------------
# AC-11.10 — null-valued entry is malformed, ignored, not advertised (R-6.5-j)
# ---------------------------------------------------------------------------

class TestAC1110NullEntryIgnored:
  def test_null_entry_dropped_from_parsed_map(self):
    raw = {"io.modelcontextprotocol/broken": None, "com.example/ok": {}}
    parsed = parse_extensions_map(raw)
    assert "io.modelcontextprotocol/broken" not in parsed
    assert "com.example/ok" in parsed

  def test_null_entry_not_in_advertised_set(self):
    raw = {"io.modelcontextprotocol/broken": None}
    assert advertised_extension_ids(raw) == frozenset()

  def test_null_entry_never_active(self):
    client = {"com.example/x": None}
    server = {"com.example/x": {}}
    assert not is_extension_active("com.example/x", client, server)

  def test_non_object_scalar_also_dropped(self):
    raw = {"com.example/a": 42, "com.example/b": "str", "com.example/c": [1]}
    assert parse_extensions_map(raw) == {}


# ---------------------------------------------------------------------------
# AC-11.11 — receiver ignores undefined settings keys (R-6.5-k)
# ---------------------------------------------------------------------------

class TestAC1111IgnoreUndefinedSettings:
  def test_undefined_keys_ignored_via_select(self):
    settings = {"mimeTypes": ["x"], "undefinedKey": 7}
    known = select_known_settings(settings, frozenset({"mimeTypes"}))
    assert known == {"mimeTypes": ["x"]}
    assert "undefinedKey" not in known

  def test_extension_setting_reads_only_defined_key(self):
    settings = {"mimeTypes": ["x"], "undefinedKey": 7}
    assert extension_setting(settings, "mimeTypes") == ["x"]
    # Reading a defined key never trips over undefined ones.
    assert extension_setting(settings, "absent", default="d") == "d"

  def test_non_object_settings_yields_empty(self):
    assert select_known_settings(None, frozenset({"a"})) == {}
    assert extension_setting(None, "a", default="d") == "d"


# ---------------------------------------------------------------------------
# AC-11.12 — active only in the intersection of both maps (R-6.5-l)
# ---------------------------------------------------------------------------

class TestAC1112ActivationByIntersection:
  def test_client_only_extension_not_active(self):
    client = {"com.example/E": {}}
    server = {}
    assert not is_extension_active("com.example/E", client, server)

  def test_server_only_extension_not_active(self):
    client = {}
    server = {"com.example/E": {}}
    assert not is_extension_active("com.example/E", client, server)

  def test_both_advertise_means_active(self):
    client = {"com.example/E": {}}
    server = {"com.example/E": {}}
    assert is_extension_active("com.example/E", client, server)
    assert active_extensions(client, server) == frozenset({"com.example/E"})

  def test_intersection_only_includes_shared_ids(self):
    client = {"com.example/E": {}, "com.example/onlyClient": {}}
    server = {"com.example/E": {}, "com.example/onlyServer": {}}
    assert active_extensions(client, server) == frozenset({"com.example/E"})

  def test_assert_active_raises_when_unilateral(self):
    client = {"com.example/E": {}}
    server = {}
    with pytest.raises(ExtensionNotActiveError):
      assert_extension_active("com.example/E", client, server)

  def test_assert_active_passes_when_shared(self):
    client = {"com.example/E": {}}
    server = {"com.example/E": {}}
    assert_extension_active("com.example/E", client, server)  # no raise


# ---------------------------------------------------------------------------
# AC-11.13 — disabled by default: not advertised unless enabled (R-6.5-m)
# ---------------------------------------------------------------------------

class TestAC1113DisabledByDefault:
  def test_absent_extensions_field_advertises_nothing(self):
    caps = ClientCapabilities()
    assert caps.extensions is None
    assert "extensions" not in caps.to_dict()
    assert advertised_extension_ids(caps.extensions) == frozenset()

  def test_empty_extensions_map_advertises_nothing(self):
    assert advertised_extension_ids({}) == frozenset()

  def test_unenabled_extension_absent_from_map(self):
    caps = ServerCapabilities(extensions={"io.modelcontextprotocol/tasks": {}})
    advertised = advertised_extension_ids(caps.extensions)
    assert "io.modelcontextprotocol/tasks" in advertised
    assert "io.modelcontextprotocol/ui" not in advertised  # never enabled


# ---------------------------------------------------------------------------
# AC-11.14 — one-sided support: fallback, or reject if mandatory (R-6.5-n)
# ---------------------------------------------------------------------------

class TestAC1114OneSidedFallbackOrReject:
  def test_non_mandatory_one_sided_falls_back(self):
    client = {"com.example/E": {}}
    server = {}
    # Not active and not mandatory → fall back to core (returns False, no raise).
    assert resolve_one_sided_extension(
      "com.example/E", client, server, mandatory=False
    ) is False

  def test_mandatory_one_sided_rejects(self):
    client = {"com.example/E": {}}
    server = {}
    with pytest.raises(MandatoryExtensionUnavailableError):
      resolve_one_sided_extension(
        "com.example/E", client, server, mandatory=True
      )

  def test_active_extension_may_be_used(self):
    client = {"com.example/E": {}}
    server = {"com.example/E": {}}
    assert resolve_one_sided_extension(
      "com.example/E", client, server, mandatory=True
    ) is True

  def test_mandatory_error_carries_identifier(self):
    with pytest.raises(MandatoryExtensionUnavailableError) as exc_info:
      resolve_one_sided_extension("com.example/E", {"com.example/E": {}}, {}, mandatory=True)
    assert exc_info.value.identifier == "com.example/E"


# ---------------------------------------------------------------------------
# AC-11.15 — tolerate unknown fields/keys without failing (R-6.6-a)
# ---------------------------------------------------------------------------

class TestAC1115TolerateUnknown:
  def test_unknown_capability_field_tolerated(self):
    caps = {"tools": {}, "futureFeature": {"anything": True}}
    # No exception; the unknown field is merely identified.
    assert unknown_capability_fields(caps, KNOWN_SERVER_CAPABILITY_FIELDS) == frozenset(
      {"futureFeature"}
    )

  def test_unknown_extension_key_tolerated(self):
    raw = {"com.other/unknown": {}, "io.modelcontextprotocol/ui": {}}
    # parse_extensions_map never raises on unknown identifiers.
    parsed = parse_extensions_map(raw)
    assert "com.other/unknown" in parsed  # well-formed value, just unrecognized

  def test_capabilities_from_dict_keeps_unknown_in_extra(self):
    caps = ServerCapabilities.from_dict(
      {"tools": {"listChanged": True}, "futureFeature": {"anything": True}}
    )
    assert caps.extra == {"futureFeature": {"anything": True}}


# ---------------------------------------------------------------------------
# AC-11.16 — receiver ignores unrecognized capability field (R-6.6-b)
# ---------------------------------------------------------------------------

class TestAC1116IgnoreUnknownCapabilityField:
  def test_ignore_returns_only_known_fields(self):
    caps = {"tools": {"listChanged": True}, "futureFeature": {"x": 1}}
    kept = ignore_unknown_capability_fields(caps, KNOWN_SERVER_CAPABILITY_FIELDS)
    assert kept == {"tools": {"listChanged": True}}
    assert "futureFeature" not in kept

  def test_ignore_on_client_fields(self):
    caps = {"elicitation": {}, "somethingNew": 1}
    kept = ignore_unknown_capability_fields(caps, KNOWN_CLIENT_CAPABILITY_FIELDS)
    assert kept == {"elicitation": {}}

  def test_non_object_input_yields_empty(self):
    assert ignore_unknown_capability_fields(None, KNOWN_SERVER_CAPABILITY_FIELDS) == {}


# ---------------------------------------------------------------------------
# AC-11.17 — unknown field MUST NOT cause rejection (R-6.6-c)
# ---------------------------------------------------------------------------

class TestAC1117UnknownFieldNoReject:
  def test_from_dict_does_not_reject_unknown_field(self):
    # Must not raise despite the unknown 'futureFeature' field.
    caps = ClientCapabilities.from_dict(
      {"elicitation": {"form": {}}, "futureFeature": {"anything": True}}
    )
    assert caps.elicitation == {"form": {}}

  def test_ignore_helper_never_raises_on_unknown(self):
    # The whole message survives; helper just drops the unknown field.
    caps = {"tools": {}, "anUnknownCapability": {"deep": {"nested": True}}}
    kept = ignore_unknown_capability_fields(caps, KNOWN_SERVER_CAPABILITY_FIELDS)
    assert "tools" in kept

  def test_unknown_extension_field_value_preserved_for_known(self):
    caps = ServerCapabilities.from_dict(
      {"completions": {}, "weird": [1, 2, 3]}
    )
    # The capability object parses fine; the message is not rejected.
    assert caps.supports_completions
    assert caps.extra == {"weird": [1, 2, 3]}


# ---------------------------------------------------------------------------
# AC-11.18 — ignore unknown extensions/experimental key; not in intersection (R-6.6-d)
# ---------------------------------------------------------------------------

class TestAC1118IgnoreUnknownExtensionKey:
  def test_unrecognized_extension_excluded_from_recognized(self):
    raw = {
      "io.modelcontextprotocol/ui": {},
      "com.other/unknown": {},
    }
    recognized = recognized_extensions(
      raw, frozenset({"io.modelcontextprotocol/ui"})
    )
    assert recognized == {"io.modelcontextprotocol/ui": {}}
    assert "com.other/unknown" not in recognized

  def test_unrecognized_extension_not_active(self):
    # Even though both advertise it, if a receiver doesn't recognize it, it
    # treats it as not active. Here we model "recognized" via the recognized set.
    raw = {"com.other/unknown": {}}
    recognized = recognized_extensions(raw, frozenset())
    assert recognized == {}

  def test_same_rule_applies_to_experimental_map(self):
    # The experimental map's unknown keys obey the same ignore-unknown rule.
    experimental = {"com.vendor/featureX": {}, "com.vendor/featureY": {}}
    recognized = recognized_extensions(
      experimental, frozenset({"com.vendor/featureX"})
    )
    assert recognized == {"com.vendor/featureX": {}}


# ---------------------------------------------------------------------------
# AC-11.19 — ignore newer/unknown settings keys (R-6.6-e)
# ---------------------------------------------------------------------------

class TestAC1119IgnoreUnknownSettingsKey:
  def test_older_receiver_ignores_new_settings_key(self):
    # Newer extension version adds 'newSetting'; older receiver knows only 'mimeTypes'.
    settings = {"mimeTypes": ["x"], "newSetting": "future"}
    known = select_known_settings(settings, frozenset({"mimeTypes"}))
    assert known == {"mimeTypes": ["x"]}

  def test_reading_known_key_unaffected_by_new_keys(self):
    settings = {"mimeTypes": ["x"], "newSetting": "future"}
    assert extension_setting(settings, "mimeTypes") == ["x"]

  def test_no_known_keys_yields_empty_not_error(self):
    settings = {"unknownSetting": 42}
    assert select_known_settings(settings, frozenset({"mimeTypes"})) == {}


# ---------------------------------------------------------------------------
# AC-11.20 — unknown caps/extensions/settings MUST NOT be errors (R-6.6-f)
# ---------------------------------------------------------------------------

class TestAC1120UnknownNotError:
  def test_unknown_capability_does_not_raise(self):
    # None of these forward-compat helpers raise on unknown input.
    ignore_unknown_capability_fields(
      {"unknownCap": {}}, KNOWN_SERVER_CAPABILITY_FIELDS
    )
    unknown_capability_fields({"unknownCap": {}}, KNOWN_SERVER_CAPABILITY_FIELDS)

  def test_unknown_extension_does_not_raise(self):
    parse_extensions_map({"com.other/unknown": {}})
    recognized_extensions({"com.other/unknown": {}}, frozenset())

  def test_unknown_settings_does_not_raise(self):
    select_known_settings({"unknownSetting": 1}, frozenset({"known"}))
    extension_setting({"unknownSetting": 1}, "known", default=None)

  def test_forward_compat_is_never_an_error(self):
    assert is_forward_compatible_error(ValueError("x")) is False


# ---------------------------------------------------------------------------
# AC-11.21 — absence of un-understood field implies nothing (R-6.6-g)
# ---------------------------------------------------------------------------

class TestAC1121AbsenceImpliesNothing:
  def test_support_decided_only_by_known_field_presence(self):
    support_tools = CapabilityFieldSupport("tools")
    # 'tools' present → supported, regardless of any unknown field being absent.
    assert support_tools.supported({"tools": {}})
    assert not support_tools.supported({"prompts": {}})

  def test_absence_of_unknown_field_does_not_flip_support(self):
    support_tools = CapabilityFieldSupport("tools")
    with_unknown = {"tools": {}, "futureFeature": {}}
    without_unknown = {"tools": {}}
    # Whether or not the unknown field is present, support for 'tools' is the same.
    assert support_tools.supported(with_unknown) == support_tools.supported(
      without_unknown
    )
    assert support_tools.supported(with_unknown) is True

  def test_non_object_is_unsupported(self):
    assert not CapabilityFieldSupport("tools").supported(None)


# ---------------------------------------------------------------------------
# AC-11.22 — §6.7 worked examples; active only if both advertise (R-6.7-a)
# ---------------------------------------------------------------------------

class TestAC1122Section67Examples:
  # The two §6.7 capability objects, verbatim.
  CLIENT_CAPS = {
    "elicitation": {"form": {}, "url": {}},
    "extensions": {
      "io.modelcontextprotocol/ui": {"mimeTypes": ["text/html;profile=mcp-app"]}
    },
  }
  SERVER_CAPS = {
    "tools": {"listChanged": True},
    "resources": {"subscribe": True, "listChanged": True},
    "prompts": {"listChanged": False},
    "completions": {},
    "extensions": {"io.modelcontextprotocol/tasks": {}},
  }

  def test_ui_not_active_when_server_lacks_it(self):
    # Client advertises ui, server advertises tasks → no overlap.
    assert not is_extension_active(
      "io.modelcontextprotocol/ui",
      self.CLIENT_CAPS["extensions"],
      self.SERVER_CAPS["extensions"],
    )

  def test_tasks_not_active_when_client_lacks_it(self):
    assert not is_extension_active(
      "io.modelcontextprotocol/tasks",
      self.CLIENT_CAPS["extensions"],
      self.SERVER_CAPS["extensions"],
    )

  def test_no_extensions_active_in_disjoint_example(self):
    assert active_extensions(
      self.CLIENT_CAPS["extensions"], self.SERVER_CAPS["extensions"]
    ) == frozenset()

  def test_ui_active_only_when_both_advertise(self):
    server_with_ui = {"io.modelcontextprotocol/ui": {}}
    assert is_extension_active(
      "io.modelcontextprotocol/ui",
      self.CLIENT_CAPS["extensions"],
      server_with_ui,
    )

  def test_capability_objects_roundtrip_through_s10(self):
    # The §6.7 objects parse cleanly via the S10 capability parsers.
    cc = ClientCapabilities.from_dict(self.CLIENT_CAPS)
    sc = ServerCapabilities.from_dict(self.SERVER_CAPS)
    assert cc.extensions == self.CLIENT_CAPS["extensions"]
    assert sc.extensions == self.SERVER_CAPS["extensions"]

  def test_forward_compat_example_from_story(self):
    # The story's last §9 example: a receiver ignores futureFeature, the
    # unknown com.other/unknown extension, the unknownSetting key, and the
    # null-valued broken entry; only io.modelcontextprotocol/ui is advertised.
    raw_caps = {
      "tools": {"listChanged": True},
      "futureFeature": {"anything": True},
      "extensions": {
        "io.modelcontextprotocol/ui": {
          "mimeTypes": ["text/html;profile=mcp-app"],
          "unknownSetting": 42,
        },
        "com.other/unknown": {},
        "io.modelcontextprotocol/broken": None,
      },
    }
    # Unknown capability field ignored.
    kept = ignore_unknown_capability_fields(raw_caps, KNOWN_SERVER_CAPABILITY_FIELDS)
    assert "futureFeature" not in kept
    assert "tools" in kept

    recognized = recognized_extensions(
      raw_caps["extensions"], frozenset({"io.modelcontextprotocol/ui"})
    )
    # broken (null) dropped; com.other/unknown ignored; ui recognized.
    assert set(recognized) == {"io.modelcontextprotocol/ui"}

    # The unknown settings key within the recognized extension is ignored.
    ui_settings = recognized["io.modelcontextprotocol/ui"]
    known = select_known_settings(ui_settings, frozenset({"mimeTypes"}))
    assert known == {"mimeTypes": ["text/html;profile=mcp-app"]}
