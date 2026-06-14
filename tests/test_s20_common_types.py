"""Tests for S20 — Common Data Types I: BaseMetadata, Icons & Implementation.

Every test maps to one or more acceptance criteria (AC-20.x).
"""

from unittest.mock import MagicMock, patch

import pytest

from mcp_sdk_py.common_types import (
  ALLOWED_ICON_SCHEMES,
  SUPPORTED_MIME_TYPES,
  SUPPORTED_MIME_TYPES_RECOMMENDED,
  SUPPORTED_MIME_TYPES_REQUIRED,
  UNSAFE_ICON_SCHEMES,
  BaseMetadata,
  Icon,
  IconFetchError,
  IconTheme,
  Implementation,
  _SafeIconRedirectHandler,
  detect_image_mime_type,
  fetch_icon,
  is_valid_size_entry,
  resolve_tool_display_name,
  validate_icon_data,
  validate_icon_src,
)


# ---------------------------------------------------------------------------
# AC-20.1  Case-sensitive field names, discriminators, enum values  [R-14-a]
# ---------------------------------------------------------------------------

class TestCaseSensitivity:
  """AC-20.1: Field names and enum values are case-sensitive and byte-for-byte."""

  def test_mime_type_field_name_is_camel_case_in_dict(self):
    icon = Icon(src="https://example.com/icon.png", mime_type="image/png")
    d = icon.to_dict()
    assert "mimeType" in d
    assert "mimetype" not in d

  def test_website_url_field_name_is_camel_case_in_dict(self):
    impl = Implementation(name="s", version="1", website_url="https://example.com")
    d = impl.to_dict()
    assert "websiteUrl" in d
    assert "websiteurl" not in d

  def test_icon_theme_light_value_is_lowercase(self):
    theme = IconTheme.LIGHT
    assert theme.value == "light"
    assert theme.value != "Light"
    assert theme.value != "LIGHT"

  def test_icon_theme_dark_value_is_lowercase(self):
    assert IconTheme.DARK.value == "dark"


# ---------------------------------------------------------------------------
# AC-20.2  _meta field is accepted when present  [R-14-b]
# ---------------------------------------------------------------------------

class TestMetaFieldAccepted:
  """AC-20.2: A conforming consumer accepts a §14 structure that carries _meta."""

  def test_implementation_from_dict_accepts_meta_field(self):
    data = {
      "name": "report-generator",
      "version": "1.0",
      "title": "Report Generator",
      "_meta": {"example.com/category": "analytics"},
    }
    impl = Implementation.from_dict(data)
    assert impl.name == "report-generator"
    # _meta is silently ignored (unknown key) — no error raised

  def test_base_metadata_dict_with_meta_is_valid(self):
    data = {
      "name": "report-generator",
      "title": "Report Generator",
      "_meta": {"example.com/category": "analytics"},
    }
    # Parsed via from_dict — _meta is ignored
    meta = BaseMetadata(name=data["name"], title=data.get("title"))
    assert meta.name == "report-generator"


# ---------------------------------------------------------------------------
# AC-20.3  BaseMetadata: name required, title optional  [R-14.1-a, -b]
# ---------------------------------------------------------------------------

class TestBaseMetadataFields:
  """AC-20.3: name is REQUIRED; title is OPTIONAL."""

  def test_name_is_required(self):
    meta = BaseMetadata(name="my-tool")
    assert meta.name == "my-tool"

  def test_absent_name_raises(self):
    with pytest.raises((ValueError, TypeError)):
      BaseMetadata(name="")

  def test_none_name_raises(self):
    with pytest.raises((ValueError, TypeError)):
      BaseMetadata(name=None)  # type: ignore[arg-type]

  def test_title_is_optional(self):
    meta = BaseMetadata(name="my-tool")
    assert meta.title is None

  def test_title_present(self):
    meta = BaseMetadata(name="my-tool", title="My Tool")
    assert meta.title == "My Tool"


# ---------------------------------------------------------------------------
# AC-20.4  Display name prefers title  [R-14.1-c]
# ---------------------------------------------------------------------------

class TestDisplayNamePrefersTitle:
  """AC-20.4: When title is present, display_name() returns title."""

  def test_display_name_uses_title_when_present(self):
    meta = BaseMetadata(name="my-tool", title="My Tool")
    assert meta.display_name() == "My Tool"

  def test_implementation_display_name_uses_title(self):
    impl = Implementation(name="srv", version="1", title="My Server")
    assert impl.display_name() == "My Server"


# ---------------------------------------------------------------------------
# AC-20.5  Display name falls back to name  [R-14.1-d]
# ---------------------------------------------------------------------------

class TestDisplayNameFallsBackToName:
  """AC-20.5: When title is absent, display_name() returns name."""

  def test_display_name_uses_name_when_title_absent(self):
    meta = BaseMetadata(name="my-tool")
    assert meta.display_name() == "my-tool"

  def test_implementation_display_name_uses_name_when_title_absent(self):
    impl = Implementation(name="srv", version="1")
    assert impl.display_name() == "srv"


# ---------------------------------------------------------------------------
# AC-20.6  Tool annotations.title precedence (structural)  [R-14.1-e]
# ---------------------------------------------------------------------------

class TestAnnotationsTitlePrecedence:
  """AC-20.6: For tools, precedence is title → annotations.title → name (R-14.1-e)."""

  def test_title_beats_annotations_title_beats_name(self):
    """Full 3-tier precedence via resolve_tool_display_name (R-14.1-c, e, d)."""
    assert resolve_tool_display_name(
      "tool-id",
      title="Explicit Title",
      annotations_title="Annotations Title",
    ) == "Explicit Title"

  def test_annotations_title_beats_name_when_title_absent(self):
    assert resolve_tool_display_name(
      "tool-id",
      title=None,
      annotations_title="Annotations Title",
    ) == "Annotations Title"

  def test_name_is_fallback_when_both_absent(self):
    assert resolve_tool_display_name("tool-id", title=None, annotations_title=None) == "tool-id"

  def test_title_wins_even_when_annotations_title_present(self):
    result = resolve_tool_display_name(
      "n", title="T", annotations_title="AT"
    )
    assert result == "T"

  def test_basemetadata_display_name_two_tier(self):
    """BaseMetadata.display_name() still implements the title → name two-tier rule."""
    assert BaseMetadata(name="n", title="T").display_name() == "T"
    assert BaseMetadata(name="n").display_name() == "n"


# ---------------------------------------------------------------------------
# AC-20.7  name not assumed unique globally  [R-14.1-f]
# ---------------------------------------------------------------------------

class TestNameNotAssumedUnique:
  """AC-20.7: name is not unique unless a feature section says so."""

  def test_two_objects_sharing_same_name_are_both_valid(self):
    a = BaseMetadata(name="shared-name", title="First")
    b = BaseMetadata(name="shared-name", title="Second")
    # Both are valid — no uniqueness violation at this level
    assert a.name == b.name == "shared-name"


# ---------------------------------------------------------------------------
# AC-20.8  Icon rendering is permitted, not required  [R-14.2-a]
# ---------------------------------------------------------------------------

class TestIconRenderingIsOptional:
  """AC-20.8: A consumer MAY render an Icon; rendering is discretionary."""

  def test_icon_can_be_constructed(self):
    icon = Icon(src="https://example.com/icon.png")
    assert icon.src == "https://example.com/icon.png"


# ---------------------------------------------------------------------------
# AC-20.9  Icons array optional; omission is valid  [R-14.2-b, R-14.2-v]
# ---------------------------------------------------------------------------

class TestIconsOptional:
  """AC-20.9: icons array MAY be present or omitted."""

  def test_implementation_with_no_icons(self):
    impl = Implementation(name="s", version="1")
    assert impl.icons is None

  def test_implementation_with_empty_icons_list(self):
    impl = Implementation(name="s", version="1", icons=[])
    assert impl.icons == []

  def test_implementation_with_icons(self):
    icons = [Icon(src="https://example.com/icon.png")]
    impl = Implementation(name="s", version="1", icons=icons)
    assert len(impl.icons) == 1


# ---------------------------------------------------------------------------
# AC-20.10  Icon.src is required  [R-14.2-c]
# ---------------------------------------------------------------------------

class TestIconSrcRequired:
  """AC-20.10: Icon.src MUST be present; absence is rejected."""

  def test_src_present(self):
    icon = Icon(src="https://example.com/icon.png")
    assert icon.src == "https://example.com/icon.png"

  def test_absent_src_raises(self):
    with pytest.raises((ValueError, TypeError)):
      Icon(src="")

  def test_none_src_raises(self):
    with pytest.raises((ValueError, TypeError)):
      Icon(src=None)  # type: ignore[arg-type]

  def test_from_dict_missing_src_raises(self):
    with pytest.raises(KeyError):
      Icon.from_dict({"mimeType": "image/png"})


# ---------------------------------------------------------------------------
# AC-20.11  Icon.src must be http/https/data  [R-14.2-d]
# AC-20.22  Only https or data accepted by consumer  [R-14.2-o]
# ---------------------------------------------------------------------------

class TestIconSrcScheme:
  """AC-20.11, AC-20.22: Icon src must be https: URL or data: URI."""

  def test_https_url_is_accepted(self):
    icon = Icon(src="https://example.com/icon.png")
    assert icon.src.startswith("https://")

  def test_data_uri_is_accepted(self):
    data_uri = (
      "data:image/png;base64,"
      "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
    )
    icon = Icon(src=data_uri)
    assert icon.src.startswith("data:")

  def test_http_url_is_rejected(self):
    """AC-20.22: only https, not http (R-14.2-o is stricter than R-14.2-d)."""
    with pytest.raises(ValueError, match="https"):
      Icon(src="http://example.com/icon.png")

  def test_ftp_url_is_rejected(self):
    with pytest.raises(ValueError):
      Icon(src="ftp://example.com/icon.png")

  def test_allowed_and_unsafe_scheme_sets(self):
    assert "https" in ALLOWED_ICON_SCHEMES
    assert "data" in ALLOWED_ICON_SCHEMES
    assert "javascript" in UNSAFE_ICON_SCHEMES
    assert "file" in UNSAFE_ICON_SCHEMES
    assert "ftp" in UNSAFE_ICON_SCHEMES
    assert "ws" in UNSAFE_ICON_SCHEMES


# ---------------------------------------------------------------------------
# AC-20.12  Same-/trusted-domain check for icon URLs  [R-14.2-e]
# (structural: the rule is documented; runtime enforcement is the consumer's)
# ---------------------------------------------------------------------------

class TestIconDomainCheck:
  """AC-20.12: Consumers SHOULD check icon URL domain trust (R-14.2-e)."""

  def test_icon_src_scheme_validation_enforces_safety(self):
    """validate_icon_src enforces scheme allowlist — first line of icon safety."""
    validate_icon_src("https://trusted.example.com/icon.png")  # no exception

  def test_cross_origin_redirect_blocked_by_safe_handler(self):
    """_SafeIconRedirectHandler blocks cross-origin redirect (R-14.2-p)."""
    handler = _SafeIconRedirectHandler("https://example.com/icon.png")
    mock_req = MagicMock()
    mock_req.full_url = "https://example.com/icon.png"
    with pytest.raises(IconFetchError, match="Cross-origin"):
      handler.redirect_request(
        mock_req, None, 302, "Found", {},
        "https://attacker.com/evil.png",
      )

  def test_same_origin_redirect_allowed(self):
    """Redirect to same origin and scheme must not raise IconFetchError."""
    import urllib.request as _ur
    handler = _SafeIconRedirectHandler("https://example.com/icon.png")
    orig_req = _ur.Request("https://example.com/icon.png")
    # No IconFetchError expected for same-origin redirect
    new_req = handler.redirect_request(
      orig_req, MagicMock(), 302, "Found", {}, "https://example.com/icon-v2.png"
    )
    assert new_req is not None


# ---------------------------------------------------------------------------
# AC-20.13  SVG icons require additional precautions  [R-14.2-f]
# ---------------------------------------------------------------------------

class TestSVGPrecautions:
  """AC-20.13: SVG icons identified by magic bytes; consumers apply extra precautions."""

  def test_svg_detected_from_xml_magic_bytes(self):
    svg_bytes = b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"/>'
    detected = detect_image_mime_type(svg_bytes)
    assert detected == "image/svg+xml"

  def test_svg_detected_from_svg_tag(self):
    svg_bytes = b'<svg xmlns="http://www.w3.org/2000/svg"/>'
    assert detect_image_mime_type(svg_bytes) == "image/svg+xml"

  def test_svg_with_bom_detected(self):
    bom = b'\xef\xbb\xbf'
    svg_bytes = bom + b'<?xml version="1.0"?><svg/>'
    assert detect_image_mime_type(svg_bytes) == "image/svg+xml"


# ---------------------------------------------------------------------------
# AC-20.14  Icon.mimeType optional  [R-14.2-g]
# ---------------------------------------------------------------------------

class TestIconMimeType:
  """AC-20.14: mimeType is OPTIONAL; when present it is a string."""

  def test_mime_type_absent_by_default(self):
    icon = Icon(src="https://example.com/icon.png")
    assert icon.mime_type is None

  def test_mime_type_present(self):
    icon = Icon(src="https://example.com/icon.png", mime_type="image/png")
    assert icon.mime_type == "image/png"

  def test_from_dict_reads_mime_type_from_camel_case(self):
    icon = Icon.from_dict({"src": "https://example.com/icon.png", "mimeType": "image/jpeg"})
    assert icon.mime_type == "image/jpeg"

  def test_to_dict_writes_mime_type_as_camel_case(self):
    icon = Icon(src="https://example.com/icon.png", mime_type="image/png")
    d = icon.to_dict()
    assert d["mimeType"] == "image/png"


# ---------------------------------------------------------------------------
# AC-20.15  Icon.sizes optional; valid entries are WxH or "any"  [R-14.2-h]
# ---------------------------------------------------------------------------

class TestIconSizes:
  """AC-20.15: sizes is OPTIONAL; each entry must be 'any' or 'WxH'."""

  def test_sizes_absent_by_default(self):
    icon = Icon(src="https://example.com/icon.png")
    assert icon.sizes is None

  def test_sizes_any(self):
    icon = Icon(src="https://example.com/icon.png", sizes=["any"])
    assert icon.sizes == ["any"]

  def test_sizes_pixel_specifier(self):
    icon = Icon(src="https://example.com/icon.png", sizes=["48x48", "96x96"])
    assert icon.sizes == ["48x48", "96x96"]

  def test_invalid_size_entry_raises(self):
    with pytest.raises(ValueError, match="size"):
      Icon(src="https://example.com/icon.png", sizes=["48px"])

  def test_is_valid_size_entry_for_any(self):
    assert is_valid_size_entry("any") is True

  def test_is_valid_size_entry_for_wxh(self):
    assert is_valid_size_entry("48x48") is True
    assert is_valid_size_entry("256x256") is True

  def test_is_valid_size_entry_rejects_invalid(self):
    assert is_valid_size_entry("48px") is False
    assert is_valid_size_entry("48") is False


# ---------------------------------------------------------------------------
# AC-20.16  Absent sizes → usable at any size  [R-14.2-i]
# ---------------------------------------------------------------------------

class TestIconSizesAbsent:
  """AC-20.16: When sizes is absent, consumer treats icon as usable at any size."""

  def test_absent_sizes_is_any_size(self):
    icon = Icon(src="https://example.com/icon.png")
    assert icon.sizes is None  # absent → consumer assumes any size


# ---------------------------------------------------------------------------
# AC-20.17  Icon.theme optional; when present is "light" or "dark"  [R-14.2-j]
# ---------------------------------------------------------------------------

class TestIconTheme:
  """AC-20.17: theme is OPTIONAL; when present must be 'light' or 'dark'."""

  def test_theme_absent_by_default(self):
    icon = Icon(src="https://example.com/icon.png")
    assert icon.theme is None

  def test_theme_light(self):
    icon = Icon(src="https://example.com/icon.png", theme=IconTheme.LIGHT)
    assert icon.theme is IconTheme.LIGHT

  def test_theme_dark(self):
    icon = Icon(src="https://example.com/icon.png", theme=IconTheme.DARK)
    assert icon.theme is IconTheme.DARK

  def test_invalid_theme_raises(self):
    with pytest.raises((ValueError, TypeError)):
      Icon(src="https://example.com/icon.png", theme="medium")  # type: ignore[arg-type]

  def test_from_dict_parses_theme_string(self):
    icon = Icon.from_dict({"src": "https://example.com/icon.png", "theme": "dark"})
    assert icon.theme is IconTheme.DARK

  def test_to_dict_writes_theme_as_string(self):
    icon = Icon(src="https://example.com/icon.png", theme=IconTheme.LIGHT)
    d = icon.to_dict()
    assert d["theme"] == "light"


# ---------------------------------------------------------------------------
# AC-20.18  Absent theme → usable with any theme  [R-14.2-k]
# ---------------------------------------------------------------------------

class TestIconThemeAbsent:
  """AC-20.18: When theme is absent, consumer treats icon as usable with any theme."""

  def test_absent_theme_means_any_theme(self):
    icon = Icon(src="https://example.com/icon.png")
    assert icon.theme is None   # absent → any theme


# ---------------------------------------------------------------------------
# AC-20.19  MUST support png and jpeg  [R-14.2-l]
# ---------------------------------------------------------------------------

class TestRequiredMimeTypes:
  """AC-20.19: Consumers MUST support image/png and image/jpeg."""

  def test_required_mime_types_include_png(self):
    assert "image/png" in SUPPORTED_MIME_TYPES_REQUIRED

  def test_required_mime_types_include_jpeg(self):
    assert "image/jpeg" in SUPPORTED_MIME_TYPES_REQUIRED

  def test_required_mime_types_include_jpg_alias(self):
    assert "image/jpg" in SUPPORTED_MIME_TYPES_REQUIRED

  def test_all_required_types_in_full_set(self):
    assert SUPPORTED_MIME_TYPES_REQUIRED.issubset(SUPPORTED_MIME_TYPES)


# ---------------------------------------------------------------------------
# AC-20.20  SHOULD support svg and webp  [R-14.2-m]
# ---------------------------------------------------------------------------

class TestRecommendedMimeTypes:
  """AC-20.20: Consumers SHOULD support image/svg+xml and image/webp."""

  def test_recommended_includes_svg(self):
    assert "image/svg+xml" in SUPPORTED_MIME_TYPES_RECOMMENDED

  def test_recommended_includes_webp(self):
    assert "image/webp" in SUPPORTED_MIME_TYPES_RECOMMENDED

  def test_all_recommended_types_in_full_set(self):
    assert SUPPORTED_MIME_TYPES_RECOMMENDED.issubset(SUPPORTED_MIME_TYPES)


# ---------------------------------------------------------------------------
# AC-20.21  Unsafe schemes rejected  [R-14.2-n]
# ---------------------------------------------------------------------------

class TestUnsafeIconSchemes:
  """AC-20.21: javascript:, file:, ftp:, ws: and similar schemes MUST be rejected."""

  @pytest.mark.parametrize("src", [
    "javascript:alert(1)",
    "file:///etc/passwd",
    "ftp://example.com/icon.png",
    "ws://example.com/icon.png",
  ])
  def test_unsafe_scheme_rejected(self, src):
    with pytest.raises(ValueError):
      Icon(src=src)

  def test_unsafe_schemes_set_is_correct(self):
    assert UNSAFE_ICON_SCHEMES == frozenset({"javascript", "file", "ftp", "ws"})


# ---------------------------------------------------------------------------
# AC-20.22  Only https or data accepted  [R-14.2-o]
# ---------------------------------------------------------------------------

class TestIconSrcOnlyHttpsOrData:
  """AC-20.22: Consumer MUST accept only https: URL or data: URI."""

  @pytest.mark.parametrize("src", [
    "https://example.com/icon.png",
    "data:image/png;base64,abc123==",
  ])
  def test_accepted_schemes(self, src):
    validate_icon_src(src)  # no exception

  @pytest.mark.parametrize("src", [
    "http://example.com/icon.png",
    "javascript:alert(1)",
    "file:///icon.png",
    "ftp://icon.example.com/x.png",
  ])
  def test_rejected_schemes(self, src):
    with pytest.raises(ValueError):
      validate_icon_src(src)


# ---------------------------------------------------------------------------
# AC-20.23  No cross-origin redirect following  [R-14.2-p]
# (structural: rule is documented; enforcement is at HTTP fetch time)
# ---------------------------------------------------------------------------

class TestNoCrossOriginRedirect:
  """AC-20.23: Consumer MUST NOT follow cross-origin or scheme-change redirects (R-14.2-p)."""

  def test_cross_origin_redirect_raises_icon_fetch_error(self):
    """fetch_icon must raise when redirected to a different origin."""
    handler = _SafeIconRedirectHandler("https://example.com/icon.png")
    mock_req = MagicMock()
    mock_req.full_url = "https://example.com/icon.png"
    with pytest.raises(IconFetchError, match="Cross-origin"):
      handler.redirect_request(
        mock_req, None, 302, "Found", {},
        "https://evil.com/steal.png",
      )

  def test_scheme_change_redirect_rejected(self):
    """A redirect that changes scheme (https→http) must be blocked."""
    handler = _SafeIconRedirectHandler("https://example.com/icon.png")
    mock_req = MagicMock()
    mock_req.full_url = "https://example.com/icon.png"
    with pytest.raises(IconFetchError, match="Cross-origin"):
      handler.redirect_request(
        mock_req, None, 302, "Found", {},
        "http://example.com/icon.png",  # scheme changed
      )


# ---------------------------------------------------------------------------
# AC-20.24  Icon fetched without credentials  [R-14.2-q]
# ---------------------------------------------------------------------------

class TestIconFetchedWithoutCredentials:
  """AC-20.24: fetch_icon MUST NOT send cookies, Authorization, or client credentials."""

  _PNG = b'\x89PNG\r\n\x1a\n' + bytes(100)

  def test_fetch_icon_issues_no_authorization_header(self):
    """The Request object created by fetch_icon must have no Authorization header."""
    captured: list = []
    mock_resp = MagicMock()
    mock_resp.read.return_value = self._PNG
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    def capture_open(req, timeout=None):
      captured.append(req)
      return mock_resp

    mock_opener = MagicMock()
    mock_opener.open.side_effect = capture_open

    with patch("mcp_sdk_py.common_types.urllib.request.build_opener", return_value=mock_opener):
      fetch_icon("https://example.com/icon.png")

    req = captured[0]
    assert req.get_header("Authorization") is None

  def test_fetch_icon_does_not_add_cookie_header(self):
    """No Cookie header should be injected into the icon request."""
    captured: list = []
    mock_resp = MagicMock()
    mock_resp.read.return_value = self._PNG
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    def capture_open(req, timeout=None):
      captured.append(req)
      return mock_resp

    mock_opener = MagicMock()
    mock_opener.open.side_effect = capture_open

    with patch("mcp_sdk_py.common_types.urllib.request.build_opener", return_value=mock_opener):
      fetch_icon("https://example.com/icon.png")

    req = captured[0]
    cookie = req.get_header("Cookie")
    assert cookie is None or cookie == ""


# ---------------------------------------------------------------------------
# AC-20.25  Validate MIME type and file contents before rendering  [R-14.2-r]
# AC-20.26  Declared type is advisory; detect from magic bytes  [R-14.2-s]
# AC-20.27  Mismatch or unknown type → reject  [R-14.2-t]
# AC-20.28  Strict allowlist; types outside it rejected  [R-14.2-u]
# ---------------------------------------------------------------------------

class TestIconContentValidation:
  """AC-20.25–20.28: Magic-byte detection, mismatch rejection, allowlist enforcement."""

  _PNG = b'\x89PNG\r\n\x1a\n' + bytes(100)
  _JPEG = b'\xff\xd8\xff\xe0' + bytes(100)
  _WEBP = b'RIFF\x00\x00\x00\x00WEBP' + bytes(100)
  _SVG = b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"/>'
  _NOT_IMAGE = b'not an image at all, just text bytes'

  # AC-20.26: magic bytes determine type, not declared mimeType

  def test_detect_png_from_magic_bytes(self):
    assert detect_image_mime_type(self._PNG) == "image/png"

  def test_detect_jpeg_from_magic_bytes(self):
    assert detect_image_mime_type(self._JPEG) == "image/jpeg"

  def test_detect_webp_from_magic_bytes(self):
    assert detect_image_mime_type(self._WEBP) == "image/webp"

  def test_detect_svg_from_magic_bytes(self):
    assert detect_image_mime_type(self._SVG) == "image/svg+xml"

  def test_unknown_content_returns_none(self):
    assert detect_image_mime_type(self._NOT_IMAGE) is None

  # AC-20.25: validate_icon_data checks both type and content

  def test_validate_icon_data_accepts_valid_png(self):
    detected = validate_icon_data(self._PNG)
    assert detected == "image/png"

  def test_validate_icon_data_accepts_correct_declared_type(self):
    detected = validate_icon_data(self._PNG, declared_mime_type="image/png")
    assert detected == "image/png"

  # AC-20.26 + AC-20.27: declared type is advisory; mismatch is rejected

  def test_validate_icon_data_rejects_declared_mime_mismatch(self):
    """Declaring image/webp but sending PNG bytes must be rejected (R-14.2-t)."""
    with pytest.raises(IconFetchError, match="mismatch"):
      validate_icon_data(self._PNG, declared_mime_type="image/webp")

  def test_validate_icon_data_ignores_declared_type_for_detection(self):
    """Declared type is advisory; magic bytes are the source of truth (R-14.2-s)."""
    # JPEG bytes with a wrong declared type must still be caught by magic bytes
    with pytest.raises(IconFetchError, match="mismatch"):
      validate_icon_data(self._JPEG, declared_mime_type="image/png")

  # AC-20.27: unknown type rejected

  def test_validate_icon_data_rejects_unknown_content_type(self):
    with pytest.raises(IconFetchError, match="not a recognized image"):
      validate_icon_data(self._NOT_IMAGE)

  # AC-20.28: strict allowlist enforced

  def test_validate_icon_data_rejects_type_outside_allowlist(self):
    """GIF is detectable but outside SUPPORTED_MIME_TYPES — must be rejected."""
    gif_bytes = b'GIF89a' + bytes(50)
    assert detect_image_mime_type(gif_bytes) is None  # not in our detection set
    with pytest.raises(IconFetchError):
      validate_icon_data(gif_bytes)

  def test_supported_mime_types_form_the_allowlist(self):
    """R-14.2-u: only types in SUPPORTED_MIME_TYPES are accepted."""
    assert len(SUPPORTED_MIME_TYPES) >= 5
    assert "image/bmp" not in SUPPORTED_MIME_TYPES
    assert "image/tiff" not in SUPPORTED_MIME_TYPES

  # data: URI fetch (no network required)

  def test_fetch_icon_data_uri_valid_png(self):
    """fetch_icon decodes data: URI base64 payload and validates magic bytes."""
    import base64
    b64 = base64.b64encode(self._PNG).decode()
    result = fetch_icon(f"data:image/png;base64,{b64}")
    assert result == self._PNG

  def test_fetch_icon_data_uri_mime_mismatch_rejected(self):
    """data: URI with declared image/webp but PNG bytes must be rejected."""
    import base64
    b64 = base64.b64encode(self._PNG).decode()
    with pytest.raises(IconFetchError, match="mismatch"):
      fetch_icon(f"data:image/webp;base64,{b64}")

  def test_fetch_icon_https_success(self):
    """fetch_icon returns validated bytes for a valid https: PNG response."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = self._PNG
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    mock_opener = MagicMock()
    mock_opener.open.return_value = mock_resp

    with patch("mcp_sdk_py.common_types.urllib.request.build_opener", return_value=mock_opener):
      result = fetch_icon("https://example.com/icon.png")

    assert result == self._PNG

  def test_fetch_icon_https_rejects_non_image_response(self):
    """HTTP response with non-image bytes must raise IconFetchError (R-14.2-t)."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = b"<html><body>Not an image</body></html>"
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    mock_opener = MagicMock()
    mock_opener.open.return_value = mock_resp

    with patch("mcp_sdk_py.common_types.urllib.request.build_opener", return_value=mock_opener):
      with pytest.raises(IconFetchError):
        fetch_icon("https://example.com/not-an-image.html")


# ---------------------------------------------------------------------------
# AC-20.29  Implementation fields  [R-14.3-a–f]
# AC-20.30  version string format is implementation-defined  [R-14.3-d]
# ---------------------------------------------------------------------------

class TestImplementation:
  """AC-20.29, AC-20.30: Implementation required and optional fields."""

  def test_minimal_implementation(self):
    impl = Implementation(name="example-client", version="0.1.0")
    assert impl.name == "example-client"
    assert impl.version == "0.1.0"
    assert impl.title is None
    assert impl.icons is None
    assert impl.description is None
    assert impl.website_url is None

  def test_full_implementation(self):
    impl = Implementation(
      name="example-server",
      version="2.4.1",
      title="Example MCP Server",
      description="Provides filesystem and search tools.",
      website_url="https://example.com/mcp",
      icons=[
        Icon(
          src="https://example.com/icons/server-48.png",
          mime_type="image/png",
          sizes=["48x48"],
          theme=IconTheme.LIGHT,
        )
      ],
    )
    assert impl.name == "example-server"
    assert impl.version == "2.4.1"
    assert impl.title == "Example MCP Server"
    assert impl.description == "Provides filesystem and search tools."
    assert impl.website_url == "https://example.com/mcp"
    assert len(impl.icons) == 1

  def test_missing_name_raises(self):
    with pytest.raises((ValueError, TypeError)):
      Implementation(name="", version="1.0")

  def test_missing_version_raises(self):
    with pytest.raises((ValueError, TypeError)):
      Implementation(name="srv", version="")

  def test_version_format_is_implementation_defined(self):
    """AC-20.30: version string carries no protocol semantics (R-14.3-d)."""
    arbitrary_versions = ["1.0.0", "2026-06-14", "v3-alpha", "git-abc1234", "SNAPSHOT"]
    for v in arbitrary_versions:
      impl = Implementation(name="srv", version=v)
      assert impl.version == v

  def test_from_dict_full_wire_example(self):
    """AC-20.29: The fully-populated wire example from the story."""
    data = {
      "name": "example-server",
      "title": "Example MCP Server",
      "version": "2.4.1",
      "description": "Provides filesystem and search tools.",
      "websiteUrl": "https://example.com/mcp",
      "icons": [
        {
          "src": "https://example.com/icons/server-48.png",
          "mimeType": "image/png",
          "sizes": ["48x48"],
          "theme": "light",
        },
        {
          "src": "https://example.com/icons/server.svg",
          "mimeType": "image/svg+xml",
          "sizes": ["any"],
        },
      ],
    }
    impl = Implementation.from_dict(data)
    assert impl.name == "example-server"
    assert impl.version == "2.4.1"
    assert impl.description == "Provides filesystem and search tools."
    assert impl.website_url == "https://example.com/mcp"
    assert len(impl.icons) == 2
    assert impl.icons[0].mime_type == "image/png"
    assert impl.icons[0].theme is IconTheme.LIGHT
    assert impl.icons[1].sizes == ["any"]

  def test_from_dict_minimal_wire_example(self):
    data = {"name": "example-client", "version": "0.1.0"}
    impl = Implementation.from_dict(data)
    assert impl.name == "example-client"
    assert impl.version == "0.1.0"

  def test_from_dict_ignores_unknown_keys(self):
    data = {
      "name": "srv",
      "version": "1",
      "x-vendor-field": "should-be-ignored",
    }
    impl = Implementation.from_dict(data)
    assert impl.name == "srv"

  def test_to_dict_full(self):
    impl = Implementation(
      name="srv",
      version="1.0",
      title="Server",
      description="A server",
      website_url="https://example.com",
      icons=[Icon(src="https://example.com/icon.png", mime_type="image/png")],
    )
    d = impl.to_dict()
    assert d["name"] == "srv"
    assert d["version"] == "1.0"
    assert d["title"] == "Server"
    assert d["description"] == "A server"
    assert d["websiteUrl"] == "https://example.com"
    assert d["icons"] == [{"src": "https://example.com/icon.png", "mimeType": "image/png"}]

  def test_to_dict_omits_absent_optional_fields(self):
    impl = Implementation(name="srv", version="1")
    d = impl.to_dict()
    assert d == {"name": "srv", "version": "1"}
    assert "title" not in d
    assert "description" not in d
    assert "websiteUrl" not in d
    assert "icons" not in d
