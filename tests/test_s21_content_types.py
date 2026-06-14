"""Tests for S21 — Common Data Types II: ContentBlock, ResourceContents,
Annotations & Role.

Every test class maps to one or more acceptance criteria (AC-21.x).
"""

import pytest

from mcp_sdk_py.content_types import (
  Annotations,
  AudioContent,
  BlobResourceContents,
  ContentBlock,
  EmbeddedResource,
  ImageContent,
  ParticipantRole,
  ResourceContents,
  ResourceLink,
  TextContent,
  TextResourceContents,
  UnsupportedContentBlock,
  parse_content_block,
  parse_resource_contents,
)

# Minimal valid Base64 strings used across tests
_PNG_B64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
_WAV_B64 = "UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQAAAAA="


# ---------------------------------------------------------------------------
# AC-21.1: dispatch is exact and case-sensitive (R-14.4-a)
# ---------------------------------------------------------------------------

class TestAC211CaseSensitiveDispatch:
  def test_lowercase_text_dispatches_to_text_content(self):
    block = parse_content_block({"type": "text", "text": "hello"})
    assert isinstance(block, TextContent)

  def test_uppercase_TEXT_is_not_text_content(self):
    block = parse_content_block({"type": "TEXT", "text": "hello"})
    assert isinstance(block, UnsupportedContentBlock)
    assert block.type == "TEXT"

  def test_mixed_case_Text_is_not_text_content(self):
    block = parse_content_block({"type": "Text", "text": "hello"})
    assert isinstance(block, UnsupportedContentBlock)

  def test_uppercase_IMAGE_is_not_image_content(self):
    block = parse_content_block({"type": "IMAGE", "data": _PNG_B64, "mimeType": "image/png"})
    assert isinstance(block, UnsupportedContentBlock)


# ---------------------------------------------------------------------------
# AC-21.2: unknown type → unsupported block, not a message failure (R-14.4-b)
# ---------------------------------------------------------------------------

class TestAC212UnknownTypeUnsupported:
  def test_unknown_type_returns_unsupported_sentinel(self):
    block = parse_content_block({"type": "some/future/type", "data": "extra"})
    assert isinstance(block, UnsupportedContentBlock)
    assert block.type == "some/future/type"

  def test_unsupported_block_preserves_raw(self):
    raw = {"type": "future", "extra": 42}
    block = parse_content_block(raw)
    assert isinstance(block, UnsupportedContentBlock)
    assert block.raw == raw

  def test_empty_string_type_is_unsupported(self):
    block = parse_content_block({"type": "", "text": "x"})
    assert isinstance(block, UnsupportedContentBlock)


# ---------------------------------------------------------------------------
# AC-21.3: TextContent validation (R-14.4.1-a/b/c/d)
# ---------------------------------------------------------------------------

class TestAC213TextContent:
  def test_minimal_text_content_valid(self):
    block = parse_content_block({"type": "text", "text": "hello"})
    assert isinstance(block, TextContent)
    assert block.text == "hello"
    assert block.annotations is None
    assert block.meta is None

  def test_text_content_with_annotations(self):
    raw = {
      "type": "text",
      "text": "hi",
      "annotations": {"audience": ["user"], "priority": 0.5},
    }
    block = parse_content_block(raw)
    assert isinstance(block, TextContent)
    assert block.annotations is not None
    assert block.annotations.priority == 0.5

  def test_text_content_with_meta(self):
    block = parse_content_block({"type": "text", "text": "hi", "_meta": {"x": 1}})
    assert isinstance(block, TextContent)
    assert block.meta == {"x": 1}

  def test_text_content_missing_text_raises(self):
    with pytest.raises((KeyError, TypeError, ValueError)):
      TextContent.from_dict({"type": "text"})

  def test_text_content_type_field_is_text(self):
    block = TextContent(text="hello")
    assert block.type == "text"

  def test_text_content_to_dict_round_trip(self):
    raw = {"type": "text", "text": "The build completed successfully."}
    block = parse_content_block(raw)
    assert isinstance(block, TextContent)
    assert block.to_dict() == raw


# ---------------------------------------------------------------------------
# AC-21.4: ImageContent validation (R-14.4.2-a/b/c/e/f)
# ---------------------------------------------------------------------------

class TestAC214ImageContent:
  def test_valid_image_content(self):
    block = parse_content_block({
      "type": "image",
      "data": _PNG_B64,
      "mimeType": "image/png",
    })
    assert isinstance(block, ImageContent)
    assert block.mime_type == "image/png"

  def test_image_content_with_annotations_and_meta(self):
    block = parse_content_block({
      "type": "image",
      "data": _PNG_B64,
      "mimeType": "image/png",
      "annotations": {"audience": ["user"]},
      "_meta": {"x": 1},
    })
    assert isinstance(block, ImageContent)
    assert block.annotations is not None
    assert block.meta == {"x": 1}

  def test_invalid_base64_data_rejected(self):
    with pytest.raises(ValueError):
      ImageContent(data="not!!valid!!base64!!", mime_type="image/png")

  def test_missing_mime_type_raises(self):
    with pytest.raises((KeyError, TypeError)):
      ImageContent.from_dict({"type": "image", "data": _PNG_B64})

  def test_image_content_type_field(self):
    block = ImageContent(data=_PNG_B64, mime_type="image/png")
    assert block.type == "image"


# ---------------------------------------------------------------------------
# AC-21.5: different image MIME types are both well-formed (R-14.4.2-d)
# ---------------------------------------------------------------------------

class TestAC215ImageMimeTypes:
  def test_image_png_valid(self):
    block = ImageContent(data=_PNG_B64, mime_type="image/png")
    assert block.mime_type == "image/png"

  def test_image_jpeg_valid(self):
    block = ImageContent(data=_PNG_B64, mime_type="image/jpeg")
    assert block.mime_type == "image/jpeg"

  def test_image_gif_valid(self):
    block = ImageContent(data=_PNG_B64, mime_type="image/gif")
    assert block.mime_type == "image/gif"


# ---------------------------------------------------------------------------
# AC-21.6: AudioContent validation (R-14.4.3-a/b/c/e/f)
# ---------------------------------------------------------------------------

class TestAC216AudioContent:
  def test_valid_audio_content(self):
    block = parse_content_block({
      "type": "audio",
      "data": _WAV_B64,
      "mimeType": "audio/wav",
    })
    assert isinstance(block, AudioContent)
    assert block.mime_type == "audio/wav"

  def test_audio_content_with_annotations(self):
    block = parse_content_block({
      "type": "audio",
      "data": _WAV_B64,
      "mimeType": "audio/wav",
      "annotations": {"priority": 0.1},
    })
    assert isinstance(block, AudioContent)
    assert block.annotations is not None

  def test_audio_content_with_meta(self):
    block = parse_content_block({
      "type": "audio",
      "data": _WAV_B64,
      "mimeType": "audio/wav",
      "_meta": {"src": "mic"},
    })
    assert isinstance(block, AudioContent)
    assert block.meta == {"src": "mic"}

  def test_invalid_audio_base64_rejected(self):
    with pytest.raises(ValueError):
      AudioContent(data="!!!not base64!!!", mime_type="audio/wav")

  def test_audio_content_type_field(self):
    block = AudioContent(data=_WAV_B64, mime_type="audio/wav")
    assert block.type == "audio"


# ---------------------------------------------------------------------------
# AC-21.7: different audio MIME types are both well-formed (R-14.4.3-d)
# ---------------------------------------------------------------------------

class TestAC217AudioMimeTypes:
  def test_audio_wav_valid(self):
    block = AudioContent(data=_WAV_B64, mime_type="audio/wav")
    assert block.mime_type == "audio/wav"

  def test_audio_mpeg_valid(self):
    block = AudioContent(data=_WAV_B64, mime_type="audio/mpeg")
    assert block.mime_type == "audio/mpeg"


# ---------------------------------------------------------------------------
# AC-21.8: ResourceLink validation (R-14.4.4-a–k)
# ---------------------------------------------------------------------------

class TestAC218ResourceLink:
  def test_minimal_resource_link_valid(self):
    block = parse_content_block({
      "type": "resource_link",
      "uri": "file:///project/src/main.rs",
      "name": "main.rs",
    })
    assert isinstance(block, ResourceLink)
    assert block.uri == "file:///project/src/main.rs"
    assert block.name == "main.rs"

  def test_resource_link_all_optional_fields(self):
    block = parse_content_block({
      "type": "resource_link",
      "uri": "file:///project/src/main.rs",
      "name": "main.rs",
      "title": "Main entry point",
      "description": "CLI argument parsing.",
      "mimeType": "text/x-rust",
      "size": 4096,
      "annotations": {"audience": ["assistant"]},
      "_meta": {"custom": True},
    })
    assert isinstance(block, ResourceLink)
    assert block.title == "Main entry point"
    assert block.description == "CLI argument parsing."
    assert block.mime_type == "text/x-rust"
    assert block.size == 4096
    assert block.annotations is not None
    assert block.meta == {"custom": True}

  def test_resource_link_missing_uri_raises(self):
    with pytest.raises((KeyError, ValueError)):
      ResourceLink.from_dict({"type": "resource_link", "name": "x"})

  def test_resource_link_missing_name_raises(self):
    with pytest.raises((KeyError, ValueError)):
      ResourceLink.from_dict({"type": "resource_link", "uri": "file:///x"})

  def test_resource_link_optional_fields_absent_valid(self):
    block = ResourceLink(uri="file:///x", name="x")
    assert block.title is None
    assert block.icons is None
    assert block.description is None
    assert block.mime_type is None
    assert block.annotations is None
    assert block.size is None
    assert block.meta is None

  def test_resource_link_type_field(self):
    block = ResourceLink(uri="file:///x", name="x")
    assert block.type == "resource_link"


# ---------------------------------------------------------------------------
# AC-21.9: ResourceLink.size may be used for file-size display (R-14.4.4-j)
# ---------------------------------------------------------------------------

class TestAC219ResourceLinkSize:
  def test_size_present_is_accepted(self):
    block = ResourceLink(uri="file:///x", name="x", size=1024)
    assert block.size == 1024

  def test_size_absent_is_accepted(self):
    block = ResourceLink(uri="file:///x", name="x")
    assert block.size is None

  def test_size_appears_in_to_dict_when_set(self):
    block = ResourceLink(uri="file:///x", name="x", size=512)
    assert block.to_dict()["size"] == 512

  def test_size_omitted_from_to_dict_when_absent(self):
    block = ResourceLink(uri="file:///x", name="x")
    assert "size" not in block.to_dict()


# ---------------------------------------------------------------------------
# AC-21.10: ResourceLink need not appear in resources/list (R-14.4.4-l)
# ---------------------------------------------------------------------------

class TestAC2110ResourceLinkNotInList:
  def test_resource_link_valid_without_list_membership(self):
    # No resources/list exists here; the link is still a valid content block
    block = ResourceLink(uri="file:///unlisted.txt", name="unlisted.txt")
    assert block.uri == "file:///unlisted.txt"


# ---------------------------------------------------------------------------
# AC-21.11: EmbeddedResource validation (R-14.4.5-a/b/c/d)
# ---------------------------------------------------------------------------

class TestAC2111EmbeddedResource:
  def test_embedded_text_resource(self):
    block = parse_content_block({
      "type": "resource",
      "resource": {
        "uri": "file:///project/README.md",
        "mimeType": "text/markdown",
        "text": "# Example",
      },
    })
    assert isinstance(block, EmbeddedResource)
    assert isinstance(block.resource, TextResourceContents)

  def test_embedded_blob_resource(self):
    block = parse_content_block({
      "type": "resource",
      "resource": {
        "uri": "file:///logo.png",
        "mimeType": "image/png",
        "blob": _PNG_B64,
      },
    })
    assert isinstance(block, EmbeddedResource)
    assert isinstance(block.resource, BlobResourceContents)

  def test_embedded_resource_with_annotations_and_meta(self):
    block = parse_content_block({
      "type": "resource",
      "resource": {"uri": "file:///x", "text": "hello"},
      "annotations": {"priority": 0.8},
      "_meta": {"x": 1},
    })
    assert isinstance(block, EmbeddedResource)
    assert block.annotations is not None
    assert block.meta == {"x": 1}

  def test_embedded_resource_missing_resource_raises(self):
    with pytest.raises((KeyError, ValueError)):
      EmbeddedResource.from_dict({"type": "resource"})

  def test_embedded_resource_type_field(self):
    res = TextResourceContents(uri="file:///x", text="hello")
    block = EmbeddedResource(resource=res)
    assert block.type == "resource"


# ---------------------------------------------------------------------------
# AC-21.12: ResourceContents base validation (R-14.5-a/b/c)
# ---------------------------------------------------------------------------

class TestAC2112ResourceContentsBase:
  def test_uri_required(self):
    with pytest.raises(ValueError):
      TextResourceContents(uri="", text="x")

  def test_mime_type_optional(self):
    rc = TextResourceContents(uri="file:///x", text="hello")
    assert rc.mime_type is None

  def test_meta_optional(self):
    rc = TextResourceContents(uri="file:///x", text="hello")
    assert rc.meta is None

  def test_mime_type_accepted_when_present(self):
    rc = TextResourceContents(uri="file:///x", text="hello", mime_type="text/plain")
    assert rc.mime_type == "text/plain"


# ---------------------------------------------------------------------------
# AC-21.13: TextResourceContents validation (R-14.5-d/e)
# ---------------------------------------------------------------------------

class TestAC2113TextResourceContents:
  def test_text_required(self):
    with pytest.raises(TypeError):
      TextResourceContents(uri="file:///x", text=None)  # type: ignore

  def test_text_content_roundtrip(self):
    rc = TextResourceContents(
      uri="file:///project/README.md",
      mime_type="text/markdown",
      text="# Example Project",
    )
    d = rc.to_dict()
    assert d["uri"] == "file:///project/README.md"
    assert d["text"] == "# Example Project"
    assert d["mimeType"] == "text/markdown"


# ---------------------------------------------------------------------------
# AC-21.14: BlobResourceContents validation (R-14.5-f)
# ---------------------------------------------------------------------------

class TestAC2114BlobResourceContents:
  def test_blob_must_be_valid_base64(self):
    with pytest.raises(ValueError):
      BlobResourceContents(uri="file:///x", blob="not!!base64!!")

  def test_valid_blob_accepted(self):
    rc = BlobResourceContents(uri="file:///logo.png", blob=_PNG_B64, mime_type="image/png")
    assert rc.blob == _PNG_B64

  def test_blob_roundtrip(self):
    rc = BlobResourceContents(uri="file:///logo.png", blob=_PNG_B64)
    d = rc.to_dict()
    assert d["blob"] == _PNG_B64
    assert d["uri"] == "file:///logo.png"


# ---------------------------------------------------------------------------
# AC-21.15: variant selected by text vs blob; both together rejected (R-14.5-g/h)
# ---------------------------------------------------------------------------

class TestAC2115ResourceContentsVariant:
  def test_text_field_selects_text_variant(self):
    rc = parse_resource_contents({"uri": "file:///x", "text": "hello"})
    assert isinstance(rc, TextResourceContents)

  def test_blob_field_selects_blob_variant(self):
    rc = parse_resource_contents({"uri": "file:///x", "blob": _PNG_B64})
    assert isinstance(rc, BlobResourceContents)

  def test_both_text_and_blob_rejected(self):
    with pytest.raises(ValueError, match="MUST NOT carry both"):
      parse_resource_contents({"uri": "file:///x", "text": "hello", "blob": "aGVsbG8="})

  def test_neither_text_nor_blob_rejected(self):
    with pytest.raises(ValueError):
      parse_resource_contents({"uri": "file:///x"})


# ---------------------------------------------------------------------------
# AC-21.16: Annotations all-optional; audience is array; lastModified is string
#           (R-14.6-a/b/c/e)
# ---------------------------------------------------------------------------

class TestAC2116Annotations:
  def test_empty_annotations_valid(self):
    ann = Annotations()
    assert ann.audience is None
    assert ann.priority is None
    assert ann.last_modified is None

  def test_annotations_from_empty_dict_valid(self):
    ann = Annotations.from_dict({})
    assert ann.audience is None

  def test_audience_with_multiple_roles(self):
    ann = Annotations(audience=[ParticipantRole.USER, ParticipantRole.ASSISTANT])
    assert len(ann.audience) == 2

  def test_audience_serializes_as_role_values(self):
    ann = Annotations(audience=[ParticipantRole.USER])
    d = ann.to_dict()
    assert d["audience"] == ["user"]

  def test_last_modified_iso8601_string_accepted(self):
    ann = Annotations(last_modified="2026-07-28T09:15:00Z")
    assert ann.last_modified == "2026-07-28T09:15:00Z"

  def test_annotations_roundtrip(self):
    raw = {"audience": ["user", "assistant"], "priority": 0.8, "lastModified": "2026-01-01T00:00:00Z"}
    ann = Annotations.from_dict(raw)
    assert ann.to_dict() == raw

  def test_omitted_fields_not_in_to_dict(self):
    ann = Annotations()
    assert ann.to_dict() == {}


# ---------------------------------------------------------------------------
# AC-21.17: priority in 0..1 inclusive; outside rejected (R-14.6-d)
# ---------------------------------------------------------------------------

class TestAC2117AnnotationsPriority:
  @pytest.mark.parametrize("p", [0.0, 0.5, 1.0, 0, 1])
  def test_priority_in_range_accepted(self, p):
    ann = Annotations(priority=p)
    assert ann.priority == p

  @pytest.mark.parametrize("p", [1.5, -0.1, 2.0, -1])
  def test_priority_outside_range_rejected(self, p):
    with pytest.raises(ValueError):
      Annotations(priority=p)

  def test_bool_priority_rejected(self):
    with pytest.raises(TypeError):
      Annotations(priority=True)  # type: ignore


# ---------------------------------------------------------------------------
# AC-21.18: annotations are untrusted hints (R-14.6-f/g)
# (Documented in design; tested via absence of enforcement beyond the type)
# ---------------------------------------------------------------------------

class TestAC2118AnnotationsUntrusted:
  def test_annotations_do_not_affect_content_block_parsing(self):
    # Annotations with high priority do not change the parsed block type
    block = parse_content_block({
      "type": "text",
      "text": "sensitive",
      "annotations": {"priority": 1, "audience": ["user"]},
    })
    assert isinstance(block, TextContent)
    assert block.text == "sensitive"


# ---------------------------------------------------------------------------
# AC-21.19: Role values "user" and "assistant" valid; others invalid (R-14.7-a)
# ---------------------------------------------------------------------------

class TestAC2119ParticipantRole:
  def test_user_role_valid(self):
    role = ParticipantRole("user")
    assert role == ParticipantRole.USER

  def test_assistant_role_valid(self):
    role = ParticipantRole("assistant")
    assert role == ParticipantRole.ASSISTANT

  def test_system_role_invalid(self):
    with pytest.raises(ValueError):
      ParticipantRole("system")

  def test_empty_string_role_invalid(self):
    with pytest.raises(ValueError):
      ParticipantRole("")

  def test_uppercase_user_invalid(self):
    with pytest.raises(ValueError):
      ParticipantRole("User")

  def test_audience_with_invalid_role_raises(self):
    with pytest.raises(ValueError):
      Annotations.from_dict({"audience": ["system"]})


# ---------------------------------------------------------------------------
# AC-21.20: tool_use / tool_result forbidden in ContentBlock positions (R-14.8-a/b)
# ---------------------------------------------------------------------------

class TestAC2120ForbiddenSamplingTypes:
  def test_tool_use_type_rejected(self):
    with pytest.raises(ValueError, match="sampling-only"):
      parse_content_block({"type": "tool_use", "id": "x", "name": "search"})

  def test_tool_result_type_rejected(self):
    with pytest.raises(ValueError, match="sampling-only"):
      parse_content_block({"type": "tool_result", "tool_use_id": "x"})

  def test_non_forbidden_unknown_type_not_rejected(self):
    # An unknown type that is NOT a forbidden sampling type returns unsupported
    block = parse_content_block({"type": "future_type", "data": "x"})
    assert isinstance(block, UnsupportedContentBlock)
