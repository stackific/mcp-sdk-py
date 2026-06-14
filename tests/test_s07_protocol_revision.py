"""Tests for S07 — Protocol Revision Identifier & Transport Mirroring.

Coverage map (8 ACs):
  AC-07.1 → TestRevisionFormat
  AC-07.2 → TestExactMatchOnly
  AC-07.3 → TestSupportedRevisionSet
  AC-07.4 → TestNoRevisionInference
  AC-07.5 → TestHttpHeaderRequirement
  AC-07.6 → TestHttpHeaderMismatch
  AC-07.7 → TestErrorCode
  AC-07.8 → TestRevisionExtraction
"""

import pytest

from mcp_sdk_py.revision import (
  HTTP_PROTOCOL_VERSION_HEADER,
  PROTOCOL_REVISION_CURRENT,
  SUPPORTED_REVISIONS,
  InvalidRevisionFormatError,
  ProtocolVersionHeaderMismatchError,
  UnsupportedRevisionError,
  extract_request_revision,
  is_supported_revision,
  is_valid_revision_format,
  revisions_are_equal,
  validate_http_revision_header,
  validate_revision_format,
  validate_supported_revision,
)
from mcp_sdk_py.meta_object import CURRENT_PROTOCOL_VERSION, KEY_PROTOCOL_VERSION


# ---------------------------------------------------------------------------
# AC-07.1 — Revision identifier: string, YYYY-MM-DD format  (R-5.1-a, R-5.2-b)
# ---------------------------------------------------------------------------

class TestRevisionFormat:
  def test_current_revision_passes_format(self):
    assert is_valid_revision_format(PROTOCOL_REVISION_CURRENT)

  def test_valid_format_strings(self):
    for rev in ["2024-01-01", "2026-07-28", "9999-12-31"]:
      assert is_valid_revision_format(rev), rev

  def test_invalid_format_not_date_shape(self):
    assert not is_valid_revision_format("v2026-07-28")
    assert not is_valid_revision_format("2026/07/28")
    assert not is_valid_revision_format("20260728")
    assert not is_valid_revision_format("2026-7-28")
    assert not is_valid_revision_format("2026-07")
    assert not is_valid_revision_format("")

  def test_non_string_invalid(self):
    assert not is_valid_revision_format(20260728)
    assert not is_valid_revision_format(None)
    assert not is_valid_revision_format(["2026-07-28"])

  def test_validate_revision_format_returns_string(self):
    assert validate_revision_format("2026-07-28") == "2026-07-28"

  def test_validate_revision_format_raises_for_bad_format(self):
    with pytest.raises(InvalidRevisionFormatError):
      validate_revision_format("NOT-A-DATE")

  def test_validate_revision_format_raises_for_non_string(self):
    with pytest.raises(InvalidRevisionFormatError):
      validate_revision_format(None)


# ---------------------------------------------------------------------------
# AC-07.2 — Exact string match; no lexical/chronological comparison  (R-5.1-a, R-5.1-b)
# ---------------------------------------------------------------------------

class TestExactMatchOnly:
  def test_revisions_are_equal_same(self):
    assert revisions_are_equal("2026-07-28", "2026-07-28")

  def test_revisions_are_not_equal_different_date(self):
    assert not revisions_are_equal("2026-07-28", "2025-01-01")
    assert not revisions_are_equal("2026-07-28", "2027-01-01")

  def test_revisions_are_not_equal_case_sensitive(self):
    assert not revisions_are_equal("2026-07-28", "2026-07-28 ")
    assert not revisions_are_equal("2026-07-28", "2026-07-28\n")

  def test_ordering_not_used_for_support_decisions(self):
    """Ensure the equality check is implemented as equality, not ordering."""
    a = "2026-07-28"
    b = "2099-12-31"
    # A "newer" revision is still not equal and not supported.
    assert not revisions_are_equal(a, b)
    assert not is_supported_revision(b, frozenset({a}))


# ---------------------------------------------------------------------------
# AC-07.3 — SUPPORTED_REVISIONS set; membership-only check  (R-5.1-a)
# ---------------------------------------------------------------------------

class TestSupportedRevisionSet:
  def test_current_revision_in_supported_set(self):
    assert PROTOCOL_REVISION_CURRENT in SUPPORTED_REVISIONS

  def test_is_supported_revision_true_for_current(self):
    assert is_supported_revision(PROTOCOL_REVISION_CURRENT, SUPPORTED_REVISIONS)

  def test_is_supported_revision_false_for_unknown(self):
    assert not is_supported_revision("1999-01-01", SUPPORTED_REVISIONS)
    assert not is_supported_revision("2099-12-31", SUPPORTED_REVISIONS)

  def test_validate_supported_revision_passes_for_current(self):
    validate_supported_revision(PROTOCOL_REVISION_CURRENT, SUPPORTED_REVISIONS)

  def test_validate_supported_revision_raises_for_unknown(self):
    with pytest.raises(UnsupportedRevisionError) as exc_info:
      validate_supported_revision("1999-01-01", SUPPORTED_REVISIONS)
    assert exc_info.value.requested == "1999-01-01"
    assert PROTOCOL_REVISION_CURRENT in exc_info.value.supported

  def test_custom_supported_set_works(self):
    custom = frozenset({"2024-01-01", "2025-06-15"})
    assert is_supported_revision("2024-01-01", custom)
    assert not is_supported_revision("2026-07-28", custom)


# ---------------------------------------------------------------------------
# AC-07.4 — No per-request revision inference  (R-5.1-c)
# ---------------------------------------------------------------------------

class TestNoRevisionInference:
  def test_extract_request_revision_reads_from_meta(self):
    meta = {KEY_PROTOCOL_VERSION: PROTOCOL_REVISION_CURRENT}
    assert extract_request_revision(meta) == PROTOCOL_REVISION_CURRENT

  def test_extract_request_revision_raises_when_absent(self):
    with pytest.raises(ValueError):
      extract_request_revision({})

  def test_extract_request_revision_raises_for_non_string_type(self):
    with pytest.raises(TypeError):
      extract_request_revision({KEY_PROTOCOL_VERSION: 20260728})

  def test_extract_request_revision_independent_of_prior(self):
    """Each meta is processed independently; call on two different metas."""
    meta1 = {KEY_PROTOCOL_VERSION: "2024-01-01"}
    meta2 = {KEY_PROTOCOL_VERSION: PROTOCOL_REVISION_CURRENT}
    assert extract_request_revision(meta1) == "2024-01-01"
    assert extract_request_revision(meta2) == PROTOCOL_REVISION_CURRENT


# ---------------------------------------------------------------------------
# AC-07.5 — HTTP transport MUST carry MCP-Protocol-Version header  (R-5.2-c/d)
# ---------------------------------------------------------------------------

class TestHttpHeaderRequirement:
  def test_header_name_constant(self):
    assert HTTP_PROTOCOL_VERSION_HEADER == "MCP-Protocol-Version"

  def test_validate_http_revision_header_passes_when_equal(self):
    validate_http_revision_header(PROTOCOL_REVISION_CURRENT, PROTOCOL_REVISION_CURRENT)

  def test_validate_http_revision_header_raises_when_absent(self):
    with pytest.raises(ProtocolVersionHeaderMismatchError):
      validate_http_revision_header(PROTOCOL_REVISION_CURRENT, None)

  def test_validate_http_revision_header_absent_reports_http_400(self):
    with pytest.raises(ProtocolVersionHeaderMismatchError) as exc_info:
      validate_http_revision_header("2026-07-28", None)
    assert exc_info.value.http_status == 400


# ---------------------------------------------------------------------------
# AC-07.6 — Mismatch between header and _meta → HTTP 400  (R-5.2-e)
# ---------------------------------------------------------------------------

class TestHttpHeaderMismatch:
  def test_header_different_from_meta_raises(self):
    with pytest.raises(ProtocolVersionHeaderMismatchError) as exc_info:
      validate_http_revision_header("2026-07-28", "2025-01-01")
    err = exc_info.value
    assert err.meta_version == "2026-07-28"
    assert err.header_version == "2025-01-01"
    assert err.http_status == 400

  def test_header_with_extra_whitespace_raises(self):
    """Even trailing space is a mismatch — exact string equality."""
    with pytest.raises(ProtocolVersionHeaderMismatchError):
      validate_http_revision_header("2026-07-28", "2026-07-28 ")

  def test_header_with_extra_newline_raises(self):
    """Newline in the header value makes it different — still a mismatch."""
    with pytest.raises(ProtocolVersionHeaderMismatchError):
      validate_http_revision_header("2026-07-28", "2026-07-28\n")


# ---------------------------------------------------------------------------
# AC-07.7 — Unsupported revision → JSON-RPC -32004  (R-5.1-a)
# ---------------------------------------------------------------------------

class TestErrorCode:
  def test_unsupported_revision_error_code(self):
    with pytest.raises(UnsupportedRevisionError) as exc_info:
      validate_supported_revision("1900-01-01", SUPPORTED_REVISIONS)
    assert exc_info.value.json_rpc_code == -32004

  def test_invalid_format_error_is_value_error(self):
    with pytest.raises(InvalidRevisionFormatError) as exc_info:
      validate_revision_format("bad")
    assert isinstance(exc_info.value, ValueError)


# ---------------------------------------------------------------------------
# AC-07.8 — protocol version alias matches meta_object  (R-5.1-a)
# ---------------------------------------------------------------------------

class TestRevisionExtraction:
  def test_protocol_revision_current_matches_meta_object(self):
    """PROTOCOL_REVISION_CURRENT is the canonical alias of CURRENT_PROTOCOL_VERSION."""
    assert PROTOCOL_REVISION_CURRENT == CURRENT_PROTOCOL_VERSION

  def test_supported_revisions_contains_only_current(self):
    assert SUPPORTED_REVISIONS == frozenset({PROTOCOL_REVISION_CURRENT})

  def test_extract_then_validate_full_round_trip(self):
    meta = {KEY_PROTOCOL_VERSION: PROTOCOL_REVISION_CURRENT}
    rev = extract_request_revision(meta)
    validate_revision_format(rev)
    validate_supported_revision(rev, SUPPORTED_REVISIONS)
