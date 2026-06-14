"""Tests for S08 — Discovery via server/discover.

Coverage map (12 story ACs):
  AC-08.1  → TestDiscoverMethodName
  AC-08.2  → TestDiscoverRequestMetaRequired
  AC-08.3  → TestDiscoverRequestMetaExtras
  AC-08.4  → TestDiscoverUnsupportedRevision
  AC-08.5  → TestDiscoverResultType
  AC-08.6  → TestDiscoverSupportedVersions
  AC-08.7  → TestDiscoverVersionOrdering
  AC-08.8  → TestDiscoverCapabilities
  AC-08.9  → TestDiscoverServerInfo
  AC-08.10 → TestDiscoverInstructions
  AC-08.11 → TestDiscoverNoInstructions
  AC-08.12 → TestDiscoverResultMeta
"""

import pytest

from mcp_sdk_py.discovery import (
  DISCOVER_METHOD_NAME,
  DISCOVER_REQUIRED_META_KEYS,
  DiscoverResult,
  DiscoverResultResponse,
  EmptySupportedVersionsError,
  InvalidServerInfoError,
  MissingDiscoverMetaKeyError,
  build_unsupported_version_error_data,
  check_discover_revision,
  validate_discover_request_meta,
  validate_discover_result,
)
from mcp_sdk_py.meta_object import (
  KEY_CLIENT_CAPABILITIES,
  KEY_CLIENT_INFO,
  KEY_PROTOCOL_VERSION,
)
from mcp_sdk_py.revision import UnsupportedRevisionError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_meta(version: str = "2026-07-28") -> dict:
  return {
    KEY_PROTOCOL_VERSION: version,
    KEY_CLIENT_INFO: {"name": "TestClient", "version": "1.0"},
    KEY_CLIENT_CAPABILITIES: {},
  }


def _minimal_result(*, versions: list = None, instructions: str | None = None) -> dict:
  r: dict = {
    "resultType": "complete",
    "supportedVersions": versions if versions is not None else ["2026-07-28"],
    "capabilities": {},
    "serverInfo": {"name": "TestServer", "version": "2.0.0"},
  }
  if instructions is not None:
    r["instructions"] = instructions
  return r


# ---------------------------------------------------------------------------
# AC-08.1 — server/discover method name is implemented  (R-5.3-a)
# ---------------------------------------------------------------------------

class TestDiscoverMethodName:
  def test_method_constant_value(self):
    assert DISCOVER_METHOD_NAME == "server/discover"

  def test_method_name_imported_from_progress(self):
    """DISCOVER_METHOD_NAME re-exports progress.DISCOVER_METHOD; they must agree."""
    from mcp_sdk_py.progress import DISCOVER_METHOD
    assert DISCOVER_METHOD_NAME == DISCOVER_METHOD

  def test_required_meta_keys_set(self):
    assert KEY_PROTOCOL_VERSION in DISCOVER_REQUIRED_META_KEYS
    assert KEY_CLIENT_INFO in DISCOVER_REQUIRED_META_KEYS
    assert KEY_CLIENT_CAPABILITIES in DISCOVER_REQUIRED_META_KEYS
    assert len(DISCOVER_REQUIRED_META_KEYS) == 3


# ---------------------------------------------------------------------------
# AC-08.2 — request _meta must carry all three required keys  (R-5.3.1-a–d)
# ---------------------------------------------------------------------------

class TestDiscoverRequestMetaRequired:
  def test_valid_meta_passes(self):
    meta = _minimal_meta()
    result = validate_discover_request_meta(meta)
    assert result is meta

  def test_missing_protocol_version_raises(self):
    meta = {
      KEY_CLIENT_INFO: {"name": "C", "version": "1"},
      KEY_CLIENT_CAPABILITIES: {},
    }
    with pytest.raises(MissingDiscoverMetaKeyError) as exc_info:
      validate_discover_request_meta(meta)
    assert exc_info.value.missing_key == KEY_PROTOCOL_VERSION

  def test_missing_client_info_raises(self):
    meta = {
      KEY_PROTOCOL_VERSION: "2026-07-28",
      KEY_CLIENT_CAPABILITIES: {},
    }
    with pytest.raises(MissingDiscoverMetaKeyError) as exc_info:
      validate_discover_request_meta(meta)
    assert exc_info.value.missing_key == KEY_CLIENT_INFO

  def test_missing_client_capabilities_raises(self):
    meta = {
      KEY_PROTOCOL_VERSION: "2026-07-28",
      KEY_CLIENT_INFO: {"name": "C", "version": "1"},
    }
    with pytest.raises(MissingDiscoverMetaKeyError) as exc_info:
      validate_discover_request_meta(meta)
    assert exc_info.value.missing_key == KEY_CLIENT_CAPABILITIES

  def test_not_a_dict_raises(self):
    with pytest.raises(TypeError):
      validate_discover_request_meta(["not", "a", "dict"])

  def test_missing_key_error_has_json_rpc_code(self):
    assert MissingDiscoverMetaKeyError.json_rpc_code == -32602

  def test_empty_meta_raises(self):
    with pytest.raises(MissingDiscoverMetaKeyError):
      validate_discover_request_meta({})


# ---------------------------------------------------------------------------
# AC-08.3 — extra _meta keys beyond the required three are accepted  (R-5.3.1-e)
# ---------------------------------------------------------------------------

class TestDiscoverRequestMetaExtras:
  def test_extra_keys_allowed(self):
    meta = {
      **_minimal_meta(),
      "io.example.com/custom": "value",
      "traceparent": "00-...",
    }
    result = validate_discover_request_meta(meta)
    assert result["io.example.com/custom"] == "value"

  def test_extra_bare_key_allowed(self):
    meta = {**_minimal_meta(), "someExtraKey": 42}
    validate_discover_request_meta(meta)  # must not raise


# ---------------------------------------------------------------------------
# AC-08.4 — unsupported requested revision → UnsupportedRevisionError  (R-5.3.1-f/g)
# ---------------------------------------------------------------------------

class TestDiscoverUnsupportedRevision:
  def test_supported_revision_passes(self):
    meta = _minimal_meta("2026-07-28")
    rev = check_discover_revision(meta, ["2026-07-28"])
    assert rev == "2026-07-28"

  def test_unsupported_revision_raises(self):
    meta = _minimal_meta("2019-01-01")
    with pytest.raises(UnsupportedRevisionError) as exc_info:
      check_discover_revision(meta, ["2026-07-28"])
    assert exc_info.value.requested == "2019-01-01"
    assert "2026-07-28" in exc_info.value.supported

  def test_unsupported_error_has_json_rpc_code(self):
    assert UnsupportedRevisionError.json_rpc_code == -32004

  def test_build_error_data_structure(self):
    data = build_unsupported_version_error_data(["2026-07-28"], "2019-01-01")
    assert data["requested"] == "2019-01-01"
    assert "2026-07-28" in data["supported"]

  def test_build_error_data_multiple_supported(self):
    data = build_unsupported_version_error_data(
      ["2026-07-28", "2025-01-01"], "2000-01-01"
    )
    assert len(data["supported"]) == 2
    assert "2000-01-01" not in data["supported"]

  def test_server_does_not_crash_on_unsupported_revision(self):
    """R-5.3.1-f: server must be PREPARED to receive unsupported revision; must not crash."""
    meta = _minimal_meta("1900-01-01")
    # The check raises, which is the correct graceful handling (not a crash/hang).
    try:
      check_discover_revision(meta, ["2026-07-28"])
    except UnsupportedRevisionError:
      pass  # expected — not a crash

  def test_check_revision_missing_version_key_raises(self):
    meta = {KEY_CLIENT_INFO: {"name": "C", "version": "1"}, KEY_CLIENT_CAPABILITIES: {}}
    with pytest.raises(ValueError):
      check_discover_revision(meta, ["2026-07-28"])

  def test_check_revision_non_string_raises(self):
    meta = {**_minimal_meta(), KEY_PROTOCOL_VERSION: 42}
    with pytest.raises(ValueError):
      check_discover_revision(meta, ["2026-07-28"])

  def test_frozenset_supported_accepted(self):
    meta = _minimal_meta("2026-07-28")
    rev = check_discover_revision(meta, frozenset({"2026-07-28"}))
    assert rev == "2026-07-28"


# ---------------------------------------------------------------------------
# AC-08.5 — resultType is present in a successful result  (R-5.3.2-a)
# ---------------------------------------------------------------------------

class TestDiscoverResultType:
  def test_result_type_present_in_result(self):
    r = validate_discover_result(_minimal_result())
    assert r.result_type == "complete"

  def test_result_type_present_in_to_dict(self):
    r = validate_discover_result(_minimal_result())
    assert r.to_dict()["resultType"] == "complete"

  def test_non_string_result_type_raises(self):
    raw = {**_minimal_result(), "resultType": 1}
    with pytest.raises(TypeError, match="resultType"):
      validate_discover_result(raw)

  def test_result_type_complete_constant_matches(self):
    """resultType 'complete' is the base Result discriminator (S04)."""
    from mcp_sdk_py.result_error import RESULT_TYPE_COMPLETE
    r = validate_discover_result(_minimal_result())
    assert r.result_type == RESULT_TYPE_COMPLETE


# ---------------------------------------------------------------------------
# AC-08.6 — supportedVersions is non-empty list of strings  (R-5.3.2-b/c)
# ---------------------------------------------------------------------------

class TestDiscoverSupportedVersions:
  def test_single_version_valid(self):
    r = validate_discover_result(_minimal_result(versions=["2026-07-28"]))
    assert r.supported_versions == ["2026-07-28"]

  def test_multiple_versions_valid(self):
    r = validate_discover_result(_minimal_result(versions=["2026-07-28", "2025-01-01"]))
    assert len(r.supported_versions) == 2

  def test_empty_list_raises(self):
    raw = {**_minimal_result(), "supportedVersions": []}
    with pytest.raises(EmptySupportedVersionsError):
      validate_discover_result(raw)

  def test_missing_supported_versions_raises(self):
    raw = _minimal_result()
    del raw["supportedVersions"]
    with pytest.raises(ValueError, match="supportedVersions"):
      validate_discover_result(raw)

  def test_non_string_element_raises(self):
    raw = {**_minimal_result(), "supportedVersions": [42]}
    with pytest.raises(TypeError):
      validate_discover_result(raw)

  def test_supported_versions_not_list_raises(self):
    raw = {**_minimal_result(), "supportedVersions": "2026-07-28"}
    with pytest.raises(TypeError):
      validate_discover_result(raw)

  def test_empty_supported_versions_error_code(self):
    assert EmptySupportedVersionsError.json_rpc_code == -32600


# ---------------------------------------------------------------------------
# AC-08.7 — supportedVersions ordering carries no preference  (R-5.3.2-d)
# ---------------------------------------------------------------------------

class TestDiscoverVersionOrdering:
  def test_reordering_preserves_content(self):
    """Clients MUST NOT rely on ordering; any permutation must still be valid."""
    versions_a = ["2026-07-28", "2025-01-01"]
    versions_b = ["2025-01-01", "2026-07-28"]
    r_a = validate_discover_result(_minimal_result(versions=versions_a))
    r_b = validate_discover_result(_minimal_result(versions=versions_b))
    # Both are valid; as a set the content is identical.
    assert frozenset(r_a.supported_versions) == frozenset(r_b.supported_versions)

  def test_any_order_valid(self):
    """Both orderings parse without error (no FIFO or preference requirement)."""
    for order in [["2026-07-28", "2025-01-01"], ["2025-01-01", "2026-07-28"]]:
      r = validate_discover_result(_minimal_result(versions=order))
      assert len(r.supported_versions) == 2


# ---------------------------------------------------------------------------
# AC-08.8 — capabilities is required; empty {} is valid  (R-5.3.2-e)
# ---------------------------------------------------------------------------

class TestDiscoverCapabilities:
  def test_empty_capabilities_valid(self):
    r = validate_discover_result(_minimal_result())
    assert r.capabilities == {}

  def test_non_empty_capabilities_valid(self):
    raw = {**_minimal_result(), "capabilities": {"tools": {}, "resources": {}}}
    r = validate_discover_result(raw)
    assert "tools" in r.capabilities

  def test_missing_capabilities_raises(self):
    raw = _minimal_result()
    del raw["capabilities"]
    with pytest.raises(ValueError, match="capabilities"):
      validate_discover_result(raw)

  def test_non_dict_capabilities_raises(self):
    raw = {**_minimal_result(), "capabilities": ["tools"]}
    with pytest.raises(TypeError):
      validate_discover_result(raw)

  def test_capabilities_in_to_dict(self):
    r = validate_discover_result(_minimal_result())
    assert "capabilities" in r.to_dict()


# ---------------------------------------------------------------------------
# AC-08.9 — serverInfo requires name and version strings  (R-5.3.2-f)
# ---------------------------------------------------------------------------

class TestDiscoverServerInfo:
  def test_valid_server_info(self):
    r = validate_discover_result(_minimal_result())
    assert r.server_info["name"] == "TestServer"
    assert r.server_info["version"] == "2.0.0"

  def test_missing_server_info_raises(self):
    raw = _minimal_result()
    del raw["serverInfo"]
    with pytest.raises(ValueError, match="serverInfo"):
      validate_discover_result(raw)

  def test_missing_name_raises(self):
    raw = {**_minimal_result(), "serverInfo": {"version": "1.0"}}
    with pytest.raises(InvalidServerInfoError) as exc_info:
      validate_discover_result(raw)
    assert exc_info.value.missing_field == "name"

  def test_missing_version_raises(self):
    raw = {**_minimal_result(), "serverInfo": {"name": "Server"}}
    with pytest.raises(InvalidServerInfoError) as exc_info:
      validate_discover_result(raw)
    assert exc_info.value.missing_field == "version"

  def test_non_string_name_raises(self):
    raw = {**_minimal_result(), "serverInfo": {"name": 42, "version": "1.0"}}
    with pytest.raises(InvalidServerInfoError) as exc_info:
      validate_discover_result(raw)
    assert exc_info.value.missing_field == "name"

  def test_non_string_version_raises(self):
    raw = {**_minimal_result(), "serverInfo": {"name": "Server", "version": None}}
    with pytest.raises(InvalidServerInfoError) as exc_info:
      validate_discover_result(raw)
    assert exc_info.value.missing_field == "version"

  def test_non_dict_server_info_raises(self):
    raw = {**_minimal_result(), "serverInfo": "ExampleServer"}
    with pytest.raises(TypeError):
      validate_discover_result(raw)

  def test_extra_fields_in_server_info_allowed(self):
    raw = {
      **_minimal_result(),
      "serverInfo": {"name": "S", "version": "1.0", "vendor": "ACME"},
    }
    r = validate_discover_result(raw)
    assert r.server_info["vendor"] == "ACME"

  def test_invalid_server_info_error_code(self):
    assert InvalidServerInfoError.json_rpc_code == -32600


# ---------------------------------------------------------------------------
# AC-08.10 — instructions is an optional string  (R-5.3.2-g/h/i)
# ---------------------------------------------------------------------------

class TestDiscoverInstructions:
  def test_instructions_present(self):
    raw = _minimal_result(instructions="Use search before analysis.")
    r = validate_discover_result(raw)
    assert r.instructions == "Use search before analysis."

  def test_instructions_in_to_dict(self):
    raw = _minimal_result(instructions="Guidance text.")
    r = validate_discover_result(raw)
    assert r.to_dict()["instructions"] == "Guidance text."

  def test_non_string_instructions_raises(self):
    raw = {**_minimal_result(), "instructions": 999}
    with pytest.raises(TypeError):
      validate_discover_result(raw)

  def test_instructions_is_string(self):
    r = validate_discover_result(_minimal_result(instructions="ok"))
    assert isinstance(r.instructions, str)


# ---------------------------------------------------------------------------
# AC-08.11 — absent instructions → no guidance fabricated  (R-5.3.2-j)
# ---------------------------------------------------------------------------

class TestDiscoverNoInstructions:
  def test_absent_instructions_is_none(self):
    r = validate_discover_result(_minimal_result())
    assert r.instructions is None

  def test_absent_instructions_not_in_dict(self):
    r = validate_discover_result(_minimal_result())
    assert "instructions" not in r.to_dict()

  def test_absent_instructions_means_no_guidance(self):
    """Clients MUST NOT assume guidance when instructions is absent (R-5.3.2-j)."""
    r = validate_discover_result(_minimal_result())
    # Confirm there is no default/fabricated value — caller must use r.instructions is None check.
    assert r.instructions is None


# ---------------------------------------------------------------------------
# AC-08.12 — result-level _meta is optional and accepted  (R-5.3.2-k)
# ---------------------------------------------------------------------------

class TestDiscoverResultMeta:
  def test_meta_accepted_when_present(self):
    raw = {**_minimal_result(), "_meta": {"traceId": "xyz"}}
    r = validate_discover_result(raw)
    assert r.meta == {"traceId": "xyz"}

  def test_meta_in_to_dict(self):
    raw = {**_minimal_result(), "_meta": {"k": "v"}}
    r = validate_discover_result(raw)
    assert r.to_dict()["_meta"] == {"k": "v"}

  def test_absent_meta_is_none(self):
    r = validate_discover_result(_minimal_result())
    assert r.meta is None

  def test_absent_meta_not_in_dict(self):
    r = validate_discover_result(_minimal_result())
    assert "_meta" not in r.to_dict()

  def test_non_dict_meta_raises(self):
    raw = {**_minimal_result(), "_meta": "not-an-object"}
    with pytest.raises(TypeError):
      validate_discover_result(raw)


# ---------------------------------------------------------------------------
# Additional: DiscoverResultResponse round-trip
# ---------------------------------------------------------------------------

class TestDiscoverResultResponse:
  def test_to_dict_structure(self):
    result = validate_discover_result(_minimal_result())
    resp = DiscoverResultResponse(id=1, result=result)
    d = resp.to_dict()
    assert d["jsonrpc"] == "2.0"
    assert d["id"] == 1
    assert "result" in d
    assert d["result"]["resultType"] == "complete"

  def test_jsonrpc_field_auto_set(self):
    result = validate_discover_result(_minimal_result())
    resp = DiscoverResultResponse(id="req-1", result=result)
    assert resp.jsonrpc == "2.0"

  def test_string_id_accepted(self):
    result = validate_discover_result(_minimal_result())
    resp = DiscoverResultResponse(id="discover-1", result=result)
    assert resp.to_dict()["id"] == "discover-1"

  def test_full_result_roundtrip(self):
    raw = {
      **_minimal_result(versions=["2026-07-28", "2025-01-01"]),
      "instructions": "Prefer search over analysis.",
      "_meta": {"trace": "abc"},
    }
    result = validate_discover_result(raw)
    resp = DiscoverResultResponse(id=99, result=result)
    d = resp.to_dict()
    r = d["result"]
    assert set(r["supportedVersions"]) == {"2026-07-28", "2025-01-01"}
    assert r["instructions"] == "Prefer search over analysis."
    assert r["_meta"] == {"trace": "abc"}

  def test_minimal_valid_result_wire_example(self):
    """Wire example from §5.3: minimal valid result."""
    raw = {
      "resultType": "complete",
      "supportedVersions": ["2026-07-28"],
      "capabilities": {},
      "serverInfo": {"name": "ExampleServer", "version": "2.3.1"},
    }
    r = validate_discover_result(raw)
    assert r.result_type == "complete"
    assert r.supported_versions == ["2026-07-28"]
    assert r.capabilities == {}
    assert r.instructions is None

  def test_full_wire_example(self):
    """Wire example from §5.3: full result with capabilities and instructions."""
    raw = {
      "resultType": "complete",
      "supportedVersions": ["2026-07-28"],
      "capabilities": {
        "tools": {},
        "resources": {},
        "extensions": {"io.modelcontextprotocol/tasks": {}},
      },
      "serverInfo": {"name": "ExampleServer", "version": "2.3.1"},
      "instructions": (
        "This server exposes file-search and code-analysis tools. "
        "Prefer search before analysis for large repositories."
      ),
    }
    r = validate_discover_result(raw)
    assert r.capabilities["tools"] == {}
    assert "io.modelcontextprotocol/tasks" in r.capabilities["extensions"]
    assert "Prefer search" in r.instructions
