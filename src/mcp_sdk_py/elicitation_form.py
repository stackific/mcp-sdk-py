"""Elicitation II: Restricted Form Schema, Results & Consent — S31.

This story completes elicitation (§20) by giving the parameters S30 already
routed their concrete *payload and outcome* shapes. It owns four things:

  - The *restricted form schema* — the ``PrimitiveSchemaDefinition`` union and
    the flat, primitives-only object a form-mode ``requestedSchema`` is built
    from: ``StringSchema``, ``NumberSchema``, ``BooleanSchema``, and the
    ``EnumSchema`` family (untitled/titled single- and multi-select, plus the
    Deprecated ``LegacyTitledEnumSchema``) — §20.4.
  - The ``ElicitResult`` the client returns on retry (per S17): its three
    ``action`` literals (``accept`` / ``decline`` / ``cancel``), the ``content``
    map's presence rules (form-mode accept only), and validation of that map
    against the ``requestedSchema`` — §20.5.
  - The ``notifications/elicitation/complete`` URL-mode completion notification
    and the client-side ignore / auto-retry / manual-control rules — §20.6.
  - The security-and-consent rules governing both modes: user-control UI,
    sensitive-information restrictions (form vs URL), server-side identity
    binding and cross-user phishing verification, safe URL construction
    (server) and handling (client), and the non-authorization rule — §20.7.

Out of scope (owned elsewhere, referenced only): the ``elicitation`` capability
and gating, the input-required *delivery* of ``elicitation/create``, and the
``form`` / ``url`` mode parameter containers (``mode``, ``message``,
``requestedSchema`` envelope, ``elicitationId``, ``url``) — all S30
(``elicitation.py``). The multi-round-trip envelope and the input-required
result discriminator that carry the ``ElicitResult`` back — S17
(``multi_round_trip.py``). The base JSON-RPC notification shape and the
``notifications/`` naming convention — S03 (``jsonrpc.py``). The ``_meta`` and
content/role vocabulary referenced as pass-through — S05 / S21. The
authorization model used to identify users for cross-user verification — S35–S37.

Spec: §20.4–§20.8 (lines 5109–5454)
Depends on: S30 (elicitation.py), S21 (content_types.py), S17 (multi_round_trip.py),
  S03 (jsonrpc.py)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Union
from urllib.parse import urlsplit

from mcp_sdk_py.elicitation import (
  MODE_FORM,
  MODE_URL,
  SCHEMA_TYPE_OBJECT,
  validate_elicitation_url,
)
from mcp_sdk_py.jsonrpc import JSONRPCNotification

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: The three ``ElicitResult.action`` literals (§20.5, R-20.5-a). Exactly one of
#: these MUST be present.
ACTION_ACCEPT: str = "accept"
ACTION_DECLINE: str = "decline"
ACTION_CANCEL: str = "cancel"

#: The closed set of valid actions (R-20.5-a).
ELICIT_ACTIONS: frozenset[str] = frozenset({ACTION_ACCEPT, ACTION_DECLINE, ACTION_CANCEL})

#: The exact, case-sensitive method literal of the URL-mode completion
#: notification (§20.6, R-20.6-a/b).
ELICITATION_COMPLETE_METHOD: str = "notifications/elicitation/complete"

#: The closed set of ``StringSchema.format`` literals (§20.4, R-20.4-d). When
#: ``format`` is present it MUST be one of these four.
STRING_FORMATS: frozenset[str] = frozenset({"email", "uri", "date", "date-time"})

#: The two literals a ``NumberSchema.type`` MUST equal (§20.4, R-20.4-e).
NUMBER_TYPES: frozenset[str] = frozenset({"number", "integer"})

#: Primitive ``type`` discriminators a restricted form schema property may use.
SCHEMA_TYPE_STRING: str = "string"
SCHEMA_TYPE_NUMBER: str = "number"
SCHEMA_TYPE_INTEGER: str = "integer"
SCHEMA_TYPE_BOOLEAN: str = "boolean"
SCHEMA_TYPE_ARRAY: str = "array"

#: Substrings that mark a field name / description as requesting *sensitive*
#: information a server MUST NOT collect in form mode (§20.7, R-20.7-h). General
#: contact/profile data (name, email, username) is deliberately NOT here
#: (R-20.7-i).
SENSITIVE_FIELD_MARKERS: frozenset[str] = frozenset({
  "password",
  "passwd",
  "passphrase",
  "secret",
  "api key",
  "apikey",
  "api_key",
  "access token",
  "accesstoken",
  "access_token",
  "token",
  "credential",
  "card number",
  "cardnumber",
  "card_number",
  "cvv",
  "cvc",
  "payment",
  "ssn",
})

#: A loose URL detector used to flag clickable URLs embedded in form-mode field
#: text (§20.7, R-20.7-r / R-20.7-y).
_URL_IN_TEXT = re.compile(r"https?://|ftp://|www\.", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class InvalidPrimitiveSchemaError(Exception):
  """Raised when a form-schema property is not a valid ``PrimitiveSchemaDefinition`` (§20.4).

  Covers a property whose ``type`` is not one of the primitive discriminators, a
  ``StringSchema.format`` outside the four allowed literals (R-20.4-d), a
  ``NumberSchema.type`` other than ``number``/``integer`` (R-20.4-e), and an
  enum form whose required ``enum``/``oneOf``/``items``/``anyOf`` shape is
  malformed. It also fires when a property declares a nested object or an
  array-of-objects that is not one of the defined enum array forms (R-20.4-a).
  """


class InvalidElicitResultError(Exception):
  """Raised when an ``ElicitResult`` is structurally invalid (§20.5).

  Covers a missing/invalid ``action`` (R-20.5-a), ``content`` present where the
  action/mode forbid it (R-20.5-b), a ``content`` value of a disallowed type, or
  a ``content`` map that does not conform to the ``requestedSchema`` (R-20.5-c).
  """


class InvalidElicitationCompleteNotificationError(Exception):
  """Raised when a ``notifications/elicitation/complete`` notification is malformed (§20.6).

  Covers a wrong ``method`` literal or a missing/non-string ``params.elicitationId``
  (R-20.6-a/b).
  """


class UnsafeElicitationUrlError(Exception):
  """Raised when an elicitation URL or its handling violates a §20.7 safety rule.

  Covers a server constructing a URL that carries sensitive end-user data or is
  pre-authenticated (R-20.7-p/q), and a client attempting to act on a URL in a
  way the §20.7 client rules forbid (e.g. pre-fetch, or open without consent —
  R-20.7-t/u).
  """


# ---------------------------------------------------------------------------
# §20.4  PrimitiveSchemaDefinition members
# ---------------------------------------------------------------------------

@dataclass
class StringSchema:
  """A free-text form field, optionally length-bounded and format-hinted (§20.4).

  ``type`` is the literal ``"string"``. ``format``, when present, MUST be one of
  ``"email"``, ``"uri"``, ``"date"``, ``"date-time"`` (R-20.4-d). ``default`` is
  OPTIONAL; a defaults-aware client SHOULD pre-populate it (R-20.4-c).

  Fields:
    title, description: OPTIONAL display strings.
    min_length, max_length: OPTIONAL bounds. JSON: ``minLength`` / ``maxLength``.
    format: OPTIONAL constrained hint (R-20.4-d).
    default: OPTIONAL default string (R-20.4-c).
  """

  title: str | None = None
  description: str | None = None
  min_length: int | None = None
  max_length: int | None = None
  format: str | None = None
  default: str | None = None
  type: str = field(default=SCHEMA_TYPE_STRING, init=False)

  def __post_init__(self) -> None:
    # R-20.4-d: format, when present, MUST be one of the four literals.
    if self.format is not None and self.format not in STRING_FORMATS:
      raise InvalidPrimitiveSchemaError(
        f"StringSchema.format, when present, MUST be one of "
        f"{sorted(STRING_FORMATS)!r}; got {self.format!r} (R-20.4-d)"
      )
    if self.default is not None and not isinstance(self.default, str):
      raise InvalidPrimitiveSchemaError(
        f"StringSchema.default, when present, MUST be a string; "
        f"got {type(self.default).__name__} (§20.4)"
      )

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> StringSchema:
    """Parse a ``StringSchema`` from a wire dict (§20.4)."""
    return cls(
      title=data.get("title"),
      description=data.get("description"),
      min_length=data.get("minLength"),
      max_length=data.get("maxLength"),
      format=data.get("format"),
      default=data.get("default"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire dict; omits absent optional fields (§20.4)."""
    out: dict[str, Any] = {"type": self.type}
    if self.title is not None:
      out["title"] = self.title
    if self.description is not None:
      out["description"] = self.description
    if self.min_length is not None:
      out["minLength"] = self.min_length
    if self.max_length is not None:
      out["maxLength"] = self.max_length
    if self.format is not None:
      out["format"] = self.format
    if self.default is not None:
      out["default"] = self.default
    return out

  def validate_value(self, value: Any) -> None:
    """Validate one collected value against this schema (R-20.5-c)."""
    if not isinstance(value, str) or isinstance(value, bool):
      raise InvalidElicitResultError(
        f"value for a StringSchema field MUST be a string; "
        f"got {type(value).__name__} (R-20.5-c)"
      )
    if self.min_length is not None and len(value) < self.min_length:
      raise InvalidElicitResultError(
        f"value length {len(value)} is below minLength {self.min_length} (R-20.5-c)"
      )
    if self.max_length is not None and len(value) > self.max_length:
      raise InvalidElicitResultError(
        f"value length {len(value)} exceeds maxLength {self.max_length} (R-20.5-c)"
      )
    if self.format is not None and not _format_matches(self.format, value):
      raise InvalidElicitResultError(
        f"value {value!r} does not satisfy format {self.format!r} (R-20.5-c)"
      )


@dataclass
class NumberSchema:
  """A numeric form field, integer or real, optionally bounded (§20.4).

  ``type`` MUST be ``"number"`` or ``"integer"`` (R-20.4-e). ``default`` is
  OPTIONAL (R-20.4-c).

  Fields:
    type: REQUIRED discriminator (``"number"`` or ``"integer"``) (R-20.4-e).
    title, description: OPTIONAL display strings.
    minimum, maximum: OPTIONAL inclusive bounds.
    default: OPTIONAL default number (R-20.4-c).
  """

  type: str = SCHEMA_TYPE_NUMBER
  title: str | None = None
  description: str | None = None
  minimum: float | None = None
  maximum: float | None = None
  default: float | None = None

  def __post_init__(self) -> None:
    # R-20.4-e: type MUST be "number" or "integer".
    if self.type not in NUMBER_TYPES:
      raise InvalidPrimitiveSchemaError(
        f"NumberSchema.type MUST be one of {sorted(NUMBER_TYPES)!r}; "
        f"got {self.type!r} (R-20.4-e)"
      )
    if self.default is not None and (
      isinstance(self.default, bool) or not isinstance(self.default, (int, float))
    ):
      raise InvalidPrimitiveSchemaError(
        f"NumberSchema.default, when present, MUST be a number; "
        f"got {type(self.default).__name__} (§20.4)"
      )

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> NumberSchema:
    """Parse a ``NumberSchema`` from a wire dict (§20.4)."""
    return cls(
      type=data.get("type", SCHEMA_TYPE_NUMBER),
      title=data.get("title"),
      description=data.get("description"),
      minimum=data.get("minimum"),
      maximum=data.get("maximum"),
      default=data.get("default"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire dict; omits absent optional fields (§20.4)."""
    out: dict[str, Any] = {"type": self.type}
    if self.title is not None:
      out["title"] = self.title
    if self.description is not None:
      out["description"] = self.description
    if self.minimum is not None:
      out["minimum"] = self.minimum
    if self.maximum is not None:
      out["maximum"] = self.maximum
    if self.default is not None:
      out["default"] = self.default
    return out

  def validate_value(self, value: Any) -> None:
    """Validate one collected value against this schema (R-20.5-c)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
      raise InvalidElicitResultError(
        f"value for a NumberSchema field MUST be a number; "
        f"got {type(value).__name__} (R-20.5-c)"
      )
    if self.type == SCHEMA_TYPE_INTEGER and not float(value).is_integer():
      raise InvalidElicitResultError(
        f"value {value!r} is not an integer but type is 'integer' (R-20.5-c)"
      )
    if self.minimum is not None and value < self.minimum:
      raise InvalidElicitResultError(
        f"value {value!r} is below minimum {self.minimum} (R-20.5-c)"
      )
    if self.maximum is not None and value > self.maximum:
      raise InvalidElicitResultError(
        f"value {value!r} exceeds maximum {self.maximum} (R-20.5-c)"
      )


@dataclass
class BooleanSchema:
  """A true/false form field (§20.4).

  ``type`` is the literal ``"boolean"``. ``default`` is an OPTIONAL boolean
  (R-20.4-c). No constraint beyond the literal ``type`` (§20.4 / §7.2 of S31).

  Fields:
    title, description: OPTIONAL display strings.
    default: OPTIONAL default boolean (R-20.4-c).
  """

  title: str | None = None
  description: str | None = None
  default: bool | None = None
  type: str = field(default=SCHEMA_TYPE_BOOLEAN, init=False)

  def __post_init__(self) -> None:
    if self.default is not None and not isinstance(self.default, bool):
      raise InvalidPrimitiveSchemaError(
        f"BooleanSchema.default, when present, MUST be a boolean; "
        f"got {type(self.default).__name__} (§20.4)"
      )

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> BooleanSchema:
    """Parse a ``BooleanSchema`` from a wire dict (§20.4)."""
    return cls(
      title=data.get("title"),
      description=data.get("description"),
      default=data.get("default"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire dict; omits absent optional fields (§20.4)."""
    out: dict[str, Any] = {"type": self.type}
    if self.title is not None:
      out["title"] = self.title
    if self.description is not None:
      out["description"] = self.description
    if self.default is not None:
      out["default"] = self.default
    return out

  def validate_value(self, value: Any) -> None:
    """Validate one collected value against this schema (R-20.5-c)."""
    if not isinstance(value, bool):
      raise InvalidElicitResultError(
        f"value for a BooleanSchema field MUST be a boolean; "
        f"got {type(value).__name__} (R-20.5-c)"
      )


def _validate_const_title_options(options: Any, container: str) -> list[dict[str, str]]:
  """Validate an array of ``{const, title}`` option objects (§20.4).

  Used by titled single-select (``oneOf``) and titled multi-select
  (``items.anyOf``). Each entry MUST be an object with a required string
  ``const`` (the enum value) and a required string ``title`` (the option label).
  """
  if not isinstance(options, list) or not options:
    raise InvalidPrimitiveSchemaError(
      f"{container} MUST be a non-empty array of {{const, title}} objects (§20.4)"
    )
  parsed: list[dict[str, str]] = []
  for entry in options:
    if not isinstance(entry, dict):
      raise InvalidPrimitiveSchemaError(
        f"{container} entries MUST be objects with 'const' and 'title' (§20.4)"
      )
    const = entry.get("const")
    title = entry.get("title")
    if not isinstance(const, str):
      raise InvalidPrimitiveSchemaError(
        f"{container} entry 'const' is REQUIRED and MUST be a string (§20.4)"
      )
    if not isinstance(title, str):
      raise InvalidPrimitiveSchemaError(
        f"{container} entry 'title' is REQUIRED and MUST be a string (§20.4)"
      )
    parsed.append({"const": const, "title": title})
  return parsed


def _validate_string_enum(values: Any, container: str) -> list[str]:
  """Validate a required ``enum`` array of strings (§20.4)."""
  if not isinstance(values, list) or not values:
    raise InvalidPrimitiveSchemaError(
      f"{container} MUST be a non-empty array of strings (§20.4)"
    )
  for v in values:
    if not isinstance(v, str):
      raise InvalidPrimitiveSchemaError(
        f"{container} entries MUST be strings; got {type(v).__name__} (§20.4)"
      )
  return list(values)


@dataclass
class UntitledSingleSelectEnumSchema:
  """One choice from a list of string values, no separate labels (§20.4).

  ``type`` is ``"string"``; ``enum`` is the REQUIRED non-empty list of choosable
  values. ``default``, when present, MUST be one of the enum values.

  Fields:
    enum: REQUIRED values to choose from.
    title, description: OPTIONAL display strings.
    default: OPTIONAL default value (R-20.4-c).
  """

  enum: list[str]
  title: str | None = None
  description: str | None = None
  default: str | None = None
  type: str = field(default=SCHEMA_TYPE_STRING, init=False)

  def __post_init__(self) -> None:
    self.enum = _validate_string_enum(self.enum, "UntitledSingleSelectEnumSchema.enum")
    if self.default is not None and self.default not in self.enum:
      raise InvalidPrimitiveSchemaError(
        f"UntitledSingleSelectEnumSchema.default {self.default!r} MUST be one of "
        f"the enum values (§20.4)"
      )

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> UntitledSingleSelectEnumSchema:
    """Parse from a wire dict (§20.4)."""
    return cls(
      enum=data.get("enum"),
      title=data.get("title"),
      description=data.get("description"),
      default=data.get("default"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire dict; omits absent optional fields (§20.4)."""
    out: dict[str, Any] = {"type": self.type, "enum": list(self.enum)}
    if self.title is not None:
      out["title"] = self.title
    if self.description is not None:
      out["description"] = self.description
    if self.default is not None:
      out["default"] = self.default
    return out

  def validate_value(self, value: Any) -> None:
    """Validate one collected value against this schema (R-20.5-c)."""
    if not isinstance(value, str) or isinstance(value, bool):
      raise InvalidElicitResultError(
        f"value for a single-select enum MUST be a string; "
        f"got {type(value).__name__} (R-20.5-c)"
      )
    if value not in self.enum:
      raise InvalidElicitResultError(
        f"value {value!r} is not one of the enum values {self.enum!r} (R-20.5-c)"
      )


@dataclass
class TitledSingleSelectEnumSchema:
  """One choice where each option carries a separate display label (§20.4).

  ``type`` is ``"string"``; ``oneOf`` is the REQUIRED array of ``{const, title}``
  option objects. This is the RECOMMENDED form when per-option labels are needed
  (R-20.4-g) — preferred over the Deprecated ``LegacyTitledEnumSchema``.

  Fields:
    one_of: REQUIRED option objects. JSON: ``oneOf``.
    title, description: OPTIONAL display strings.
    default: OPTIONAL default value (a member of the option consts) (R-20.4-c).
  """

  one_of: list[dict[str, str]]
  title: str | None = None
  description: str | None = None
  default: str | None = None
  type: str = field(default=SCHEMA_TYPE_STRING, init=False)

  def __post_init__(self) -> None:
    self.one_of = _validate_const_title_options(
      self.one_of, "TitledSingleSelectEnumSchema.oneOf"
    )
    consts = {o["const"] for o in self.one_of}
    if self.default is not None and self.default not in consts:
      raise InvalidPrimitiveSchemaError(
        f"TitledSingleSelectEnumSchema.default {self.default!r} MUST be one of "
        f"the option consts (§20.4)"
      )

  @property
  def consts(self) -> list[str]:
    """The selectable ``const`` values, in declared order."""
    return [o["const"] for o in self.one_of]

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> TitledSingleSelectEnumSchema:
    """Parse from a wire dict (§20.4)."""
    return cls(
      one_of=data.get("oneOf"),
      title=data.get("title"),
      description=data.get("description"),
      default=data.get("default"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire dict; omits absent optional fields (§20.4)."""
    out: dict[str, Any] = {"type": self.type, "oneOf": [dict(o) for o in self.one_of]}
    if self.title is not None:
      out["title"] = self.title
    if self.description is not None:
      out["description"] = self.description
    if self.default is not None:
      out["default"] = self.default
    return out

  def validate_value(self, value: Any) -> None:
    """Validate one collected value against this schema (R-20.5-c)."""
    if not isinstance(value, str) or isinstance(value, bool):
      raise InvalidElicitResultError(
        f"value for a titled single-select enum MUST be a string; "
        f"got {type(value).__name__} (R-20.5-c)"
      )
    if value not in self.consts:
      raise InvalidElicitResultError(
        f"value {value!r} is not one of the option consts {self.consts!r} (R-20.5-c)"
      )


@dataclass
class UntitledMultiSelectEnumSchema:
  """Zero or more values from a list, no separate labels (§20.4).

  ``type`` is ``"array"``; ``items`` is the REQUIRED item schema carrying
  ``type`` == ``"string"`` and a required ``enum`` of choosable values.

  Fields:
    enum: REQUIRED values to choose from (read out of ``items.enum``).
    title, description: OPTIONAL display strings.
    min_items, max_items: OPTIONAL selection-count bounds. JSON:
      ``minItems`` / ``maxItems``.
    default: OPTIONAL default selection (list of enum values) (R-20.4-c).
  """

  enum: list[str]
  title: str | None = None
  description: str | None = None
  min_items: int | None = None
  max_items: int | None = None
  default: list[str] | None = None
  type: str = field(default=SCHEMA_TYPE_ARRAY, init=False)

  def __post_init__(self) -> None:
    self.enum = _validate_string_enum(self.enum, "UntitledMultiSelectEnumSchema.items.enum")
    if self.default is not None:
      if not isinstance(self.default, list) or any(d not in self.enum for d in self.default):
        raise InvalidPrimitiveSchemaError(
          f"UntitledMultiSelectEnumSchema.default MUST be a list of enum values "
          f"(§20.4)"
        )

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> UntitledMultiSelectEnumSchema:
    """Parse from a wire dict (§20.4)."""
    items = data.get("items")
    if not isinstance(items, dict):
      raise InvalidPrimitiveSchemaError(
        "UntitledMultiSelectEnumSchema.items is REQUIRED and MUST be an object (§20.4)"
      )
    if items.get("type") != SCHEMA_TYPE_STRING:
      raise InvalidPrimitiveSchemaError(
        "UntitledMultiSelectEnumSchema.items.type MUST be the literal 'string' (§20.4)"
      )
    return cls(
      enum=items.get("enum"),
      title=data.get("title"),
      description=data.get("description"),
      min_items=data.get("minItems"),
      max_items=data.get("maxItems"),
      default=data.get("default"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire dict; omits absent optional fields (§20.4)."""
    out: dict[str, Any] = {
      "type": self.type,
      "items": {"type": SCHEMA_TYPE_STRING, "enum": list(self.enum)},
    }
    if self.title is not None:
      out["title"] = self.title
    if self.description is not None:
      out["description"] = self.description
    if self.min_items is not None:
      out["minItems"] = self.min_items
    if self.max_items is not None:
      out["maxItems"] = self.max_items
    if self.default is not None:
      out["default"] = list(self.default)
    return out

  def validate_value(self, value: Any) -> None:
    """Validate one collected value against this schema (R-20.5-c)."""
    _validate_multi_select_value(value, self.enum, self.min_items, self.max_items)


@dataclass
class TitledMultiSelectEnumSchema:
  """Zero or more values where each option carries a display label (§20.4).

  ``type`` is ``"array"``; ``items.anyOf`` is the REQUIRED array of
  ``{const, title}`` option objects.

  Fields:
    any_of: REQUIRED option objects (read out of ``items.anyOf``). JSON nested
      under ``items.anyOf``.
    title, description: OPTIONAL display strings.
    min_items, max_items: OPTIONAL selection-count bounds.
    default: OPTIONAL default selection (R-20.4-c).
  """

  any_of: list[dict[str, str]]
  title: str | None = None
  description: str | None = None
  min_items: int | None = None
  max_items: int | None = None
  default: list[str] | None = None
  type: str = field(default=SCHEMA_TYPE_ARRAY, init=False)

  def __post_init__(self) -> None:
    self.any_of = _validate_const_title_options(
      self.any_of, "TitledMultiSelectEnumSchema.items.anyOf"
    )
    consts = {o["const"] for o in self.any_of}
    if self.default is not None:
      if not isinstance(self.default, list) or any(d not in consts for d in self.default):
        raise InvalidPrimitiveSchemaError(
          f"TitledMultiSelectEnumSchema.default MUST be a list of option consts "
          f"(§20.4)"
        )

  @property
  def consts(self) -> list[str]:
    """The selectable ``const`` values, in declared order."""
    return [o["const"] for o in self.any_of]

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> TitledMultiSelectEnumSchema:
    """Parse from a wire dict (§20.4)."""
    items = data.get("items")
    if not isinstance(items, dict):
      raise InvalidPrimitiveSchemaError(
        "TitledMultiSelectEnumSchema.items is REQUIRED and MUST be an object (§20.4)"
      )
    return cls(
      any_of=items.get("anyOf"),
      title=data.get("title"),
      description=data.get("description"),
      min_items=data.get("minItems"),
      max_items=data.get("maxItems"),
      default=data.get("default"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire dict; omits absent optional fields (§20.4)."""
    out: dict[str, Any] = {
      "type": self.type,
      "items": {"anyOf": [dict(o) for o in self.any_of]},
    }
    if self.title is not None:
      out["title"] = self.title
    if self.description is not None:
      out["description"] = self.description
    if self.min_items is not None:
      out["minItems"] = self.min_items
    if self.max_items is not None:
      out["maxItems"] = self.max_items
    if self.default is not None:
      out["default"] = list(self.default)
    return out

  def validate_value(self, value: Any) -> None:
    """Validate one collected value against this schema (R-20.5-c)."""
    _validate_multi_select_value(value, self.consts, self.min_items, self.max_items)


@dataclass
class LegacyTitledEnumSchema:
  """Deprecated per-value display labels via a parallel ``enumNames`` array (§20.4).

  This enum form is Deprecated: implementations SHOULD NOT adopt it for new
  functionality (R-20.4-f); it remains defined ONLY for interoperability and is
  still accepted when received from a peer. Implementations needing per-option
  labels SHOULD use :class:`TitledSingleSelectEnumSchema` instead (R-20.4-g).

  ``type`` is ``"string"``; ``enum`` is REQUIRED; ``enumNames``, when present,
  is positionally aligned with ``enum``.

  Fields:
    enum: REQUIRED values to choose from.
    enum_names: OPTIONAL parallel display labels. JSON: ``enumNames``.
    title, description: OPTIONAL display strings.
    default: OPTIONAL default value (R-20.4-c).
  """

  #: Class-level marker: this schema member is Deprecated (R-20.4-f).
  deprecated: bool = field(default=True, init=False)

  enum: list[str] = field(default_factory=list)
  enum_names: list[str] | None = None
  title: str | None = None
  description: str | None = None
  default: str | None = None
  type: str = field(default=SCHEMA_TYPE_STRING, init=False)

  def __post_init__(self) -> None:
    self.enum = _validate_string_enum(self.enum, "LegacyTitledEnumSchema.enum")
    if self.enum_names is not None:
      if not isinstance(self.enum_names, list) or any(
        not isinstance(n, str) for n in self.enum_names
      ):
        raise InvalidPrimitiveSchemaError(
          "LegacyTitledEnumSchema.enumNames, when present, MUST be an array of "
          "strings (§20.4)"
        )
    if self.default is not None and self.default not in self.enum:
      raise InvalidPrimitiveSchemaError(
        f"LegacyTitledEnumSchema.default {self.default!r} MUST be one of the enum "
        f"values (§20.4)"
      )

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> LegacyTitledEnumSchema:
    """Parse from a wire dict (§20.4). Accepted for interoperability (R-20.4-f)."""
    return cls(
      enum=data.get("enum", []),
      enum_names=data.get("enumNames"),
      title=data.get("title"),
      description=data.get("description"),
      default=data.get("default"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire dict; omits absent optional fields (§20.4)."""
    out: dict[str, Any] = {"type": self.type, "enum": list(self.enum)}
    if self.enum_names is not None:
      out["enumNames"] = list(self.enum_names)
    if self.title is not None:
      out["title"] = self.title
    if self.description is not None:
      out["description"] = self.description
    if self.default is not None:
      out["default"] = self.default
    return out

  def validate_value(self, value: Any) -> None:
    """Validate one collected value against this schema (R-20.5-c)."""
    if not isinstance(value, str) or isinstance(value, bool):
      raise InvalidElicitResultError(
        f"value for a legacy titled enum MUST be a string; "
        f"got {type(value).__name__} (R-20.5-c)"
      )
    if value not in self.enum:
      raise InvalidElicitResultError(
        f"value {value!r} is not one of the enum values {self.enum!r} (R-20.5-c)"
      )


#: The ``EnumSchema`` union: single-select / multi-select (each untitled or
#: titled) plus the Deprecated legacy form (§20.4).
EnumSchema = Union[
  UntitledSingleSelectEnumSchema,
  TitledSingleSelectEnumSchema,
  UntitledMultiSelectEnumSchema,
  TitledMultiSelectEnumSchema,
  LegacyTitledEnumSchema,
]

#: The ``PrimitiveSchemaDefinition`` union: the schema for one form field
#: (§20.4). A restricted subset of JSON Schema — one of the four primitive
#: members (the enum members fold into ``EnumSchema``).
PrimitiveSchemaDefinition = Union[
  StringSchema,
  NumberSchema,
  BooleanSchema,
  EnumSchema,
]

#: Members whose adoption for new functionality is discouraged (R-20.4-f).
DEPRECATED_ENUM_SCHEMAS: frozenset[type] = frozenset({LegacyTitledEnumSchema})


def _validate_multi_select_value(
  value: Any,
  allowed: list[str],
  min_items: int | None,
  max_items: int | None,
) -> None:
  """Validate a multi-select collected value (an array of strings) (R-20.5-c)."""
  if not isinstance(value, list):
    raise InvalidElicitResultError(
      f"value for a multi-select enum MUST be an array of strings; "
      f"got {type(value).__name__} (R-20.5-c)"
    )
  for item in value:
    if not isinstance(item, str) or isinstance(item, bool):
      raise InvalidElicitResultError(
        f"multi-select entries MUST be strings; got {type(item).__name__} (R-20.5-c)"
      )
    if item not in allowed:
      raise InvalidElicitResultError(
        f"multi-select value {item!r} is not one of {allowed!r} (R-20.5-c)"
      )
  if min_items is not None and len(value) < min_items:
    raise InvalidElicitResultError(
      f"multi-select has {len(value)} items, below minItems {min_items} (R-20.5-c)"
    )
  if max_items is not None and len(value) > max_items:
    raise InvalidElicitResultError(
      f"multi-select has {len(value)} items, above maxItems {max_items} (R-20.5-c)"
    )


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_DATE_TIME_RE = re.compile(
  r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})?$"
)


def _format_matches(fmt: str, value: str) -> bool:
  """Return True if ``value`` satisfies the ``format`` hint (R-20.4-d / R-20.5-c)."""
  if fmt == "email":
    return bool(_EMAIL_RE.match(value))
  if fmt == "uri":
    parts = urlsplit(value)
    return bool(parts.scheme)
  if fmt == "date":
    return bool(_DATE_RE.match(value))
  if fmt == "date-time":
    return bool(_DATE_TIME_RE.match(value))
  return False


def parse_primitive_schema(data: dict[str, Any]) -> PrimitiveSchemaDefinition:
  """Select and parse the correct ``PrimitiveSchemaDefinition`` member (§20.4).

  Selection is structural, by ``type`` plus the presence of
  ``enum`` / ``oneOf`` / ``items`` / ``anyOf`` / ``enumNames``:

  - ``type`` == ``"boolean"`` → :class:`BooleanSchema`.
  - ``type`` in {``"number"``, ``"integer"``} → :class:`NumberSchema` (R-20.4-e).
  - ``type`` == ``"string"``:
      - with ``enumNames`` → :class:`LegacyTitledEnumSchema` (Deprecated;
        accepted for interoperability — R-20.4-f).
      - with ``oneOf`` → :class:`TitledSingleSelectEnumSchema`.
      - with ``enum`` → :class:`UntitledSingleSelectEnumSchema`.
      - otherwise → :class:`StringSchema`.
  - ``type`` == ``"array"`` (multi-select enum):
      - ``items.anyOf`` → :class:`TitledMultiSelectEnumSchema`.
      - ``items.enum`` → :class:`UntitledMultiSelectEnumSchema`.

  Any other ``type``, a nested-object property, or an array that is not one of
  the two defined enum array forms is rejected — the restricted form schema
  supports primitives only (R-20.4-a).

  Raises:
    InvalidPrimitiveSchemaError: the property is not a valid primitive schema
      (R-20.4-a/d/e), or its enum shape is malformed.
  """
  if not isinstance(data, dict):
    raise InvalidPrimitiveSchemaError(
      f"a form property schema MUST be an object; got {type(data).__name__} "
      f"(R-20.4-a)"
    )
  schema_type = data.get("type")
  if schema_type == SCHEMA_TYPE_BOOLEAN:
    return BooleanSchema.from_dict(data)
  if schema_type in NUMBER_TYPES:
    return NumberSchema.from_dict(data)
  if schema_type == SCHEMA_TYPE_STRING:
    if "enumNames" in data:
      # Deprecated legacy form, still accepted from a peer (R-20.4-f).
      return LegacyTitledEnumSchema.from_dict(data)
    if "oneOf" in data:
      return TitledSingleSelectEnumSchema.from_dict(data)
    if "enum" in data:
      return UntitledSingleSelectEnumSchema.from_dict(data)
    return StringSchema.from_dict(data)
  if schema_type == SCHEMA_TYPE_ARRAY:
    items = data.get("items")
    if isinstance(items, dict) and "anyOf" in items:
      return TitledMultiSelectEnumSchema.from_dict(data)
    if isinstance(items, dict) and "enum" in items:
      return UntitledMultiSelectEnumSchema.from_dict(data)
    # An "array" whose items are objects (or anything else) is an
    # array-of-objects outside the defined enum forms — not supported.
    raise InvalidPrimitiveSchemaError(
      "an 'array' property is supported ONLY as a multi-select enum form "
      "(items.enum or items.anyOf); arrays of objects are not supported "
      "(R-20.4-a)"
    )
  if schema_type == SCHEMA_TYPE_OBJECT:
    raise InvalidPrimitiveSchemaError(
      "a nested object property is not supported by the restricted form schema; "
      "properties MUST be primitive types only (R-20.4-a)"
    )
  raise InvalidPrimitiveSchemaError(
    f"unsupported form property 'type' {schema_type!r}; the restricted form "
    f"schema supports only string/number/integer/boolean/array(enum) primitives "
    f"(R-20.4-a)"
  )


# ---------------------------------------------------------------------------
# §20.4  Restricted form schema (flat object, primitives only)  [R-20.4-a]
# ---------------------------------------------------------------------------

@dataclass
class RestrictedFormSchema:
  """A parsed, validated form-mode ``requestedSchema`` (§20.4).

  A flat object whose ``properties`` map field names to primitive schemas only
  (R-20.4-a). Complex nested structures, arrays of objects (beyond the enum
  array forms), and other advanced JSON Schema features are intentionally not
  supported and MUST NOT be relied upon (R-20.4-a). Parsing each property
  through :func:`parse_primitive_schema` rejects any such non-primitive shape.

  The enclosing ``requestedSchema`` envelope (``type`` == ``"object"``,
  ``properties`` REQUIRED, ``required`` / ``$schema`` OPTIONAL) is owned by S30;
  this type re-validates the envelope to a degree but its purpose is the
  primitives-only property check.

  Fields:
    properties: field name → parsed primitive schema.
    required: OPTIONAL list of REQUIRED property names.
  """

  properties: dict[str, PrimitiveSchemaDefinition]
  required: list[str] = field(default_factory=list)

  @classmethod
  def from_dict(cls, schema: dict[str, Any]) -> RestrictedFormSchema:
    """Parse and validate a restricted form schema from a wire dict (§20.4).

    Raises:
      InvalidPrimitiveSchemaError: the schema is not a flat object whose
        properties are primitive schemas (R-20.4-a).
    """
    if not isinstance(schema, dict):
      raise InvalidPrimitiveSchemaError(
        f"requestedSchema MUST be an object; got {type(schema).__name__} (R-20.4-a)"
      )
    if schema.get("type") != SCHEMA_TYPE_OBJECT:
      raise InvalidPrimitiveSchemaError(
        f"requestedSchema.type MUST be the literal {SCHEMA_TYPE_OBJECT!r}; "
        f"got {schema.get('type')!r} (R-20.4-a)"
      )
    raw_props = schema.get("properties")
    if not isinstance(raw_props, dict):
      raise InvalidPrimitiveSchemaError(
        "requestedSchema.properties is REQUIRED and MUST be a flat object map "
        "(R-20.4-a)"
      )
    properties: dict[str, PrimitiveSchemaDefinition] = {}
    for name, prop in raw_props.items():
      if not isinstance(name, str):
        raise InvalidPrimitiveSchemaError(
          "requestedSchema.properties keys MUST be strings (R-20.4-a)"
        )
      # Each property MUST be a primitive schema; this rejects nested objects
      # and arrays-of-objects (R-20.4-a).
      properties[name] = parse_primitive_schema(prop)
    required = schema.get("required", [])
    if not isinstance(required, list) or any(not isinstance(r, str) for r in required):
      raise InvalidPrimitiveSchemaError(
        "requestedSchema.required, when present, MUST be an array of property "
        "names (R-20.4-a)"
      )
    return cls(properties=properties, required=list(required))

  def defaults(self) -> dict[str, Any]:
    """Return the per-field ``default`` values a defaults-aware client pre-populates.

    A client that supports defaults SHOULD pre-populate each field with its
    schema ``default`` (R-20.4-c). Only fields whose primitive schema declares a
    ``default`` appear in the result.
    """
    out: dict[str, Any] = {}
    for name, prop in self.properties.items():
      default = getattr(prop, "default", None)
      if default is not None:
        out[name] = default
    return out


def validate_requested_schema(schema: dict[str, Any]) -> RestrictedFormSchema:
  """Validate a form-mode ``requestedSchema`` is a flat, primitives-only object (R-20.4-a).

  Convenience wrapper over :meth:`RestrictedFormSchema.from_dict`. Accepts the
  schema only when it is a flat object whose ``properties`` are primitive field
  schemas; a nested-object property or an array-of-objects property (outside the
  defined enum array forms) is rejected (AC-31.1).

  Raises:
    InvalidPrimitiveSchemaError: the schema is not a valid restricted form schema.
  """
  return RestrictedFormSchema.from_dict(schema)


def validate_content_against_schema(
  content: dict[str, Any],
  requested_schema: dict[str, Any] | RestrictedFormSchema,
) -> None:
  """Validate a collected ``content`` map against ``requestedSchema`` (R-20.5-c).

  Performs the *real* conformance check the spec requires (not an isinstance
  shortcut): every value MUST be a string, number, boolean, or array of strings
  (R-20.5-c); every key MUST be a declared property; every value MUST satisfy
  its property's primitive constraints (format / bounds / enum membership /
  selection count); and every ``required`` property MUST be present.

  A client SHOULD call this before sending (R-20.5-i) and a server SHOULD call
  it on receipt (R-20.5-j).

  Raises:
    InvalidElicitResultError: a value has a disallowed type, an unknown key is
      present, a value violates its schema, or a required property is missing.
  """
  schema = (
    requested_schema
    if isinstance(requested_schema, RestrictedFormSchema)
    else RestrictedFormSchema.from_dict(requested_schema)
  )
  if not isinstance(content, dict):
    raise InvalidElicitResultError(
      f"content MUST be a JSON object map; got {type(content).__name__} (R-20.5-c)"
    )
  for key, value in content.items():
    if key not in schema.properties:
      raise InvalidElicitResultError(
        f"content key {key!r} is not a declared property of requestedSchema "
        f"(R-20.5-c)"
      )
    # R-20.5-c: each value is a string, number, boolean, or array of strings.
    if not _is_allowed_content_value(value):
      raise InvalidElicitResultError(
        f"content[{key!r}] MUST be a string, number, boolean, or array of "
        f"strings; got {type(value).__name__} (R-20.5-c)"
      )
    schema.properties[key].validate_value(value)
  # Every required property MUST be present and conform.
  for req in schema.required:
    if req not in content:
      raise InvalidElicitResultError(
        f"required property {req!r} is missing from content (R-20.5-c)"
      )


def _is_allowed_content_value(value: Any) -> bool:
  """Return True if ``value`` is a string, number, boolean, or array of strings (R-20.5-c)."""
  if isinstance(value, bool):
    return True
  if isinstance(value, (str, int, float)):
    return True
  if isinstance(value, list):
    return all(isinstance(v, str) and not isinstance(v, bool) for v in value)
  return False


# ---------------------------------------------------------------------------
# §20.5  ElicitResult and response actions  [R-20.5-a–c]
# ---------------------------------------------------------------------------

@dataclass
class ElicitResult:
  """The value the client returns on retry, carrying the user's decision (§20.5).

  Field rules:

  - ``action`` is REQUIRED and is exactly one of ``"accept"`` / ``"decline"`` /
    ``"cancel"`` (R-20.5-a, AC-31.8).
  - ``content`` is OPTIONAL and is present ONLY when ``action`` == ``"accept"``
    and the mode was ``"form"``; it is omitted for URL-mode responses and is
    typically omitted for decline/cancel (R-20.5-b, AC-31.9). An accept carrying
    ``content`` in URL mode is malformed.
  - When present, each ``content`` value is a string, number, boolean, or array
    of strings, and the map MUST conform to the ``requestedSchema`` (R-20.5-c).

  Fields:
    action: REQUIRED action literal (R-20.5-a).
    content: OPTIONAL collected-values map (R-20.5-b/c).
  """

  action: str
  content: dict[str, Any] | None = None

  def __post_init__(self) -> None:
    # R-20.5-a: action REQUIRED, exactly one of the three literals.
    if self.action not in ELICIT_ACTIONS:
      raise InvalidElicitResultError(
        f"ElicitResult.action is REQUIRED and MUST be exactly one of "
        f"{sorted(ELICIT_ACTIONS)!r}; got {self.action!r} (R-20.5-a)"
      )
    if self.content is not None:
      if not isinstance(self.content, dict):
        raise InvalidElicitResultError(
          f"ElicitResult.content, when present, MUST be an object map; "
          f"got {type(self.content).__name__} (R-20.5-c)"
        )
      # R-20.5-b: content is meaningful only on an accept. A decline/cancel
      # carrying content is malformed.
      if self.action != ACTION_ACCEPT:
        raise InvalidElicitResultError(
          f"ElicitResult.content MUST be omitted unless action is "
          f"{ACTION_ACCEPT!r}; got action {self.action!r} (R-20.5-b)"
        )

  @property
  def is_accept(self) -> bool:
    """True when the user explicitly approved and submitted (``accept``)."""
    return self.action == ACTION_ACCEPT

  @property
  def is_decline(self) -> bool:
    """True when the user explicitly declined (``decline``)."""
    return self.action == ACTION_DECLINE

  @property
  def is_cancel(self) -> bool:
    """True when the user dismissed without choosing (``cancel``)."""
    return self.action == ACTION_CANCEL

  @classmethod
  def from_dict(
    cls,
    data: dict[str, Any],
    *,
    mode: str | None = None,
    requested_schema: dict[str, Any] | RestrictedFormSchema | None = None,
  ) -> ElicitResult:
    """Parse and validate an ``ElicitResult`` from a wire dict (§20.5).

    When ``mode`` is supplied, the form-vs-URL presence rule for ``content`` is
    enforced (R-20.5-b): a URL-mode accept carrying ``content`` is rejected as
    malformed (AC-31.9). When ``requested_schema`` is also supplied, the
    ``content`` map is validated against it (R-20.5-c, AC-31.10) — performing the
    real conformance check a client SHOULD do before sending (R-20.5-i) and a
    server SHOULD do on receipt (R-20.5-j).

    Args:
      data: the raw result object.
      mode: OPTIONAL originating mode (``"form"`` / ``"url"``) used to enforce
        the content presence rule.
      requested_schema: OPTIONAL schema (raw or parsed) to validate content
        against.

    Raises:
      InvalidElicitResultError: any field rule is violated.
    """
    if not isinstance(data, dict):
      raise InvalidElicitResultError(
        f"ElicitResult MUST be a JSON object; got {type(data).__name__} (R-20.5-a)"
      )
    if "action" not in data:
      raise InvalidElicitResultError(
        "ElicitResult.action is REQUIRED (R-20.5-a)"
      )
    result = cls(action=data["action"], content=data.get("content"))
    # R-20.5-b: content is present only on a form-mode accept. A URL-mode accept
    # MUST NOT carry content.
    if mode == MODE_URL and result.content is not None:
      raise InvalidElicitResultError(
        "a URL-mode ElicitResult MUST NOT carry 'content'; acceptance signals "
        "consent only (R-20.5-b)"
      )
    if (
      result.content is not None
      and requested_schema is not None
      and (mode is None or mode == MODE_FORM)
    ):
      validate_content_against_schema(result.content, requested_schema)
    return result

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire dict; omits ``content`` when absent (§20.5)."""
    out: dict[str, Any] = {"action": self.action}
    if self.content is not None:
      out["content"] = self.content
    return out


def accept_form_result(
  content: dict[str, Any],
  requested_schema: dict[str, Any] | RestrictedFormSchema,
) -> ElicitResult:
  """Build a validated form-mode ``accept`` result (R-20.5-b/c, R-20.5-i).

  Validates ``content`` against ``requestedSchema`` before constructing the
  result — the check a client SHOULD perform before sending (R-20.5-i).
  """
  validate_content_against_schema(content, requested_schema)
  return ElicitResult(action=ACTION_ACCEPT, content=dict(content))


def accept_url_result() -> ElicitResult:
  """Build a URL-mode ``accept`` result — consent only, no ``content`` (R-20.5-b/d).

  In URL mode acceptance signals the user CONSENTED to the out-of-band
  interaction; it does NOT mean the interaction is complete (completion is
  signalled separately by §20.6). No ``content`` is carried.
  """
  return ElicitResult(action=ACTION_ACCEPT)


def decline_result() -> ElicitResult:
  """Build a ``decline`` result (R-20.5-e). Carries no ``content``."""
  return ElicitResult(action=ACTION_DECLINE)


def cancel_result() -> ElicitResult:
  """Build a ``cancel`` result (R-20.5-f). Carries no ``content``."""
  return ElicitResult(action=ACTION_CANCEL)


# ---------------------------------------------------------------------------
# §20.5  Server handling of the three actions  [R-20.5-d–h]
# ---------------------------------------------------------------------------

class ElicitationOutcome:
  """Classification of an ``ElicitResult`` for a server's mandatory branches (§20.5).

  A server MUST NOT assume success and MUST have defined branches for decline,
  cancel, and a client failing to process the request (R-20.5-g/h, AC-31.14).
  These constants name those branches.
  """

  #: User approved and submitted; server SHOULD process the data (form) or treat
  #: as consent to proceed (URL) (R-20.5-d).
  ACCEPTED = "accepted"
  #: User explicitly declined; server SHOULD offer alternatives (R-20.5-e).
  DECLINED = "declined"
  #: User dismissed; server SHOULD prompt again later (R-20.5-f).
  CANCELLED = "cancelled"
  #: Client failed to process (no/invalid result); server MUST handle (R-20.5-h).
  FAILED = "failed"


def classify_elicit_outcome(result: ElicitResult | None) -> str:
  """Map an ``ElicitResult`` to one of the four mandatory server branches (R-20.5-d–h).

  A server MUST NOT assume an elicitation will succeed and MUST handle decline,
  cancel, and client-failure paths distinctly from the accept path (R-20.5-g/h,
  AC-31.14). A ``None`` result (the client failed to process the request) maps to
  :attr:`ElicitationOutcome.FAILED`.

  Returns one of the :class:`ElicitationOutcome` string constants.
  """
  if result is None:
    return ElicitationOutcome.FAILED
  if result.is_accept:
    return ElicitationOutcome.ACCEPTED
  if result.is_decline:
    return ElicitationOutcome.DECLINED
  return ElicitationOutcome.CANCELLED


# ---------------------------------------------------------------------------
# §20.6  Elicitation-complete notification (URL mode)  [R-20.6-a–f]
# ---------------------------------------------------------------------------

@dataclass
class ElicitationCompleteNotification:
  """A server→client JSON-RPC notification: an out-of-band URL interaction finished (§20.6).

  Built on the S03 JSON-RPC notification shape; this story adds the one concrete
  method literal ``notifications/elicitation/complete`` (R-20.6-a). A server
  sending it MUST include the ``elicitationId`` from the original
  ``elicitation/create`` request (R-20.6-b) and MUST send it only to the
  initiating client (R-20.6-c — a delivery obligation enforced by the
  transport/session layer, not by this value type).

  Fields:
    elicitation_id: REQUIRED id correlating with the original request. JSON:
      ``params.elicitationId``.
  """

  elicitation_id: str
  method: str = field(default=ELICITATION_COMPLETE_METHOD, init=False)

  def __post_init__(self) -> None:
    # R-20.6-b: elicitationId is REQUIRED and matches the original request id.
    if not isinstance(self.elicitation_id, str) or not self.elicitation_id:
      raise InvalidElicitationCompleteNotificationError(
        f"params.elicitationId is REQUIRED and MUST be a non-empty string; "
        f"got {self.elicitation_id!r} (R-20.6-b)"
      )

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> ElicitationCompleteNotification:
    """Parse and validate the notification from a wire dict (§20.6).

    Enforces the exact ``method`` literal (R-20.6-a) and a present, non-empty
    string ``params.elicitationId`` (R-20.6-b).

    Raises:
      InvalidElicitationCompleteNotificationError: the method is wrong or the
        elicitationId is missing/invalid.
    """
    if not isinstance(data, dict):
      raise InvalidElicitationCompleteNotificationError(
        f"notification MUST be a JSON object; got {type(data).__name__} (R-20.6-a)"
      )
    method = data.get("method")
    if method != ELICITATION_COMPLETE_METHOD:
      raise InvalidElicitationCompleteNotificationError(
        f"notification 'method' MUST be the exact literal "
        f"{ELICITATION_COMPLETE_METHOD!r}; got {method!r} (R-20.6-a)"
      )
    params = data.get("params")
    if not isinstance(params, dict):
      raise InvalidElicitationCompleteNotificationError(
        "notification 'params' is REQUIRED and MUST be an object carrying "
        "elicitationId (R-20.6-b)"
      )
    return cls(elicitation_id=params.get("elicitationId"))

  def to_jsonrpc(self) -> JSONRPCNotification:
    """Build the S03 :class:`~mcp_sdk_py.jsonrpc.JSONRPCNotification` form (§20.6)."""
    return JSONRPCNotification(
      method=self.method,
      params={"elicitationId": self.elicitation_id},
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a full JSON-RPC notification wire dict (§20.6)."""
    return self.to_jsonrpc().to_dict()


class ElicitationCompleteTracker:
  """Client-side registry that applies the §20.6 ignore / retry rules (R-20.6-d–f).

  Tracks which URL-mode ``elicitationId``s are pending (awaiting completion) and
  which are already completed, so the client can:

  - IGNORE a completion notification whose id is unknown or already-completed
    (R-20.6-d, AC-31.18) — :meth:`receive` returns False and takes no action.
  - act on a notification for a known-pending id (R-20.6-e) — :meth:`receive`
    returns True, marking it completed so a later duplicate is ignored.

  A client SHOULD also expose manual retry/cancel controls so the flow is
  recoverable if the notification never arrives (R-20.6-f); this tracker does not
  prevent :meth:`resolve_manually` while pending.
  """

  def __init__(self) -> None:
    self._pending: set[str] = set()
    self._completed: set[str] = set()

  def register(self, elicitation_id: str) -> None:
    """Record a URL-mode elicitation as pending (awaiting completion)."""
    if not isinstance(elicitation_id, str) or not elicitation_id:
      raise ValueError("elicitation_id must be a non-empty string")
    self._pending.add(elicitation_id)

  def is_pending(self, elicitation_id: str) -> bool:
    """Return True if the id is currently awaiting completion."""
    return elicitation_id in self._pending

  def is_completed(self, elicitation_id: str) -> bool:
    """Return True if the id has already been completed."""
    return elicitation_id in self._completed

  def receive(self, notification: ElicitationCompleteNotification | str) -> bool:
    """Apply a completion notification; return True iff it was acted upon (R-20.6-d/e).

    A client MUST ignore a notification referencing an unknown or already-completed
    ``elicitationId`` (R-20.6-d): for such ids this returns False and changes no
    state. For a known-pending id it marks the elicitation completed and returns
    True, so the client MAY auto-retry / update its UI (R-20.6-e); a subsequent
    duplicate is then ignored.
    """
    eid = (
      notification.elicitation_id
      if isinstance(notification, ElicitationCompleteNotification)
      else notification
    )
    # R-20.6-d: unknown or already-completed → ignore, no action.
    if eid not in self._pending or eid in self._completed:
      return False
    self._pending.discard(eid)
    self._completed.add(eid)
    return True

  def resolve_manually(self, elicitation_id: str) -> None:
    """Resolve a pending elicitation via a manual control (R-20.6-f).

    Supports the recoverability the spec requires when the completion
    notification never arrives: a user-driven retry/cancel/resume clears the
    pending state so the client is not stuck waiting.
    """
    self._pending.discard(elicitation_id)
    self._completed.add(elicitation_id)


# ---------------------------------------------------------------------------
# §20.7  Security & consent
# ---------------------------------------------------------------------------

#: Outcome of a §20.7 user-control UI self-check (R-20.7-a–g).
@dataclass(frozen=True)
class UserControlRequirements:
  """The user-control UI obligations a conformant client MUST/SHOULD satisfy (§20.7).

  This is a declarative checklist a client uses to assert its elicitation UI is
  conformant. The MUSTs (R-20.7-a/b/c/d) and SHOULDs (R-20.7-e/f/g) are recorded
  as booleans; :meth:`assert_conformant` raises if a MUST is unmet.

  Fields (all default False so an unconfigured client is non-conformant):
    shows_requesting_server: UI makes clear which server requests info (R-20.7-a).
    offers_decline: clear decline option at any time (R-20.7-b/g).
    offers_cancel: clear cancel option at any time (R-20.7-b).
    respects_privacy: respects user privacy (R-20.7-c).
    allows_review_and_modify: form-mode review/edit before send (R-20.7-d).
    explains_what_and_why: presents what is requested and why (R-20.7-e).
    implements_approval_controls: user approval controls (R-20.7-f).
  """

  shows_requesting_server: bool = False
  offers_decline: bool = False
  offers_cancel: bool = False
  respects_privacy: bool = False
  allows_review_and_modify: bool = False
  explains_what_and_why: bool = False
  implements_approval_controls: bool = False

  def assert_conformant(self, *, form_mode: bool = True) -> None:
    """Raise unless every applicable MUST is satisfied (R-20.7-a/b/c/d).

    The form-mode review/modify obligation (R-20.7-d) applies only when
    ``form_mode`` is True.

    Raises:
      PermissionError: a required user-control obligation is unmet.
    """
    missing: list[str] = []
    if not self.shows_requesting_server:
      missing.append("MUST make clear which server is requesting info (R-20.7-a)")
    if not self.offers_decline:
      missing.append("MUST offer decline at any time (R-20.7-b)")
    if not self.offers_cancel:
      missing.append("MUST offer cancel at any time (R-20.7-b)")
    if not self.respects_privacy:
      missing.append("MUST respect user privacy (R-20.7-c)")
    if form_mode and not self.allows_review_and_modify:
      missing.append("MUST allow review/modify before sending in form mode (R-20.7-d)")
    if missing:
      raise PermissionError(
        "elicitation UI is not conformant: " + "; ".join(missing)
      )


def is_sensitive_field(name: str, *, description: str | None = None) -> bool:
  """Return True if a field name/description requests sensitive information (R-20.7-h).

  Sensitive information — passwords, API keys, access tokens, payment
  credentials — MUST NOT be collected in form mode (R-20.7-h); URL mode MUST be
  used instead (R-20.7-i). General contact/profile data (name, email, username)
  is NOT flagged, since it is not categorically prohibited in form mode
  (R-20.7-i).
  """
  haystacks = [name.lower()]
  if description:
    haystacks.append(description.lower())
  for hay in haystacks:
    for marker in SENSITIVE_FIELD_MARKERS:
      if marker in hay:
        return True
  return False


def assert_form_mode_not_sensitive(
  requested_schema: dict[str, Any] | RestrictedFormSchema,
) -> None:
  """Raise if a form-mode schema requests sensitive information (R-20.7-h, AC-31.23).

  A server MUST NOT use form mode for passwords, API keys, access tokens, or
  payment credentials (R-20.7-h) — those MUST be collected via URL mode
  (R-20.7-i). General contact/profile fields remain permissible (R-20.7-i).

  Raises:
    PermissionError: a form field names/describes sensitive information.
  """
  schema = (
    requested_schema
    if isinstance(requested_schema, RestrictedFormSchema)
    else RestrictedFormSchema.from_dict(requested_schema)
  )
  offending: list[str] = []
  for name, prop in schema.properties.items():
    description = getattr(prop, "description", None)
    if is_sensitive_field(name, description=description):
      offending.append(name)
  if offending:
    raise PermissionError(
      f"form mode MUST NOT request sensitive information; offending field(s): "
      f"{offending!r}. Use URL mode instead (R-20.7-h, R-20.7-i)"
    )


def assert_no_clickable_urls_in_form(
  requested_schema: dict[str, Any] | RestrictedFormSchema,
) -> None:
  """Raise if a form-mode field carries a clickable URL (R-20.7-r, AC-31.28).

  A server SHOULD NOT include clickable URLs in any field of a form-mode
  request (R-20.7-r); a client SHOULD NOT render them clickable except the
  ``url`` field of a URL-mode request (R-20.7-y). This checks the title /
  description / enum-label text of each property.

  Raises:
    PermissionError: a form field's display text contains a URL.
  """
  schema = (
    requested_schema
    if isinstance(requested_schema, RestrictedFormSchema)
    else RestrictedFormSchema.from_dict(requested_schema)
  )
  offending: list[str] = []
  for name, prop in schema.properties.items():
    texts: list[str] = []
    for attr in ("title", "description", "default"):
      val = getattr(prop, attr, None)
      if isinstance(val, str):
        texts.append(val)
    for one_of in getattr(prop, "one_of", []) or []:
      texts.append(one_of.get("title", ""))
    for any_of in getattr(prop, "any_of", []) or []:
      texts.append(any_of.get("title", ""))
    for enum_name in getattr(prop, "enum_names", None) or []:
      texts.append(enum_name)
    if any(_URL_IN_TEXT.search(t) for t in texts):
      offending.append(name)
  if offending:
    raise PermissionError(
      f"form-mode fields SHOULD NOT contain clickable URLs; offending field(s): "
      f"{offending!r} (R-20.7-r, R-20.7-y)"
    )


def assert_safe_elicitation_url(
  url: str,
  *,
  sensitive_values: list[str] | None = None,
  pre_authenticated: bool = False,
  require_https: bool = True,
) -> str:
  """Raise unless a server-constructed elicitation URL is safe (R-20.7-p/q/s, AC-31.27/31.28).

  Enforces the server-side construction rules:

  - MUST NOT include sensitive end-user information in the URL (R-20.7-p): each
    string in ``sensitive_values`` MUST NOT appear anywhere in ``url``.
  - MUST NOT be pre-authenticated to a protected resource (R-20.7-q): the caller
    asserts via ``pre_authenticated``.
  - SHOULD use HTTPS outside development (R-20.7-s): when ``require_https`` the
    scheme MUST be ``https``.

  The URL is first validated as a navigable URL via S30's
  :func:`~mcp_sdk_py.elicitation.validate_elicitation_url`.

  Returns ``url`` unchanged when safe.

  Raises:
    UnsafeElicitationUrlError: any construction rule is violated.
  """
  validate_elicitation_url(url)
  if pre_authenticated:
    raise UnsafeElicitationUrlError(
      "a server MUST NOT provide a URL pre-authenticated to a protected resource "
      "(R-20.7-q)"
    )
  for secret in sensitive_values or []:
    if secret and secret in url:
      raise UnsafeElicitationUrlError(
        "a server MUST NOT include sensitive end-user information in the "
        "elicitation URL (R-20.7-p)"
      )
  if require_https and urlsplit(url).scheme.lower() != "https":
    raise UnsafeElicitationUrlError(
      "a server SHOULD use HTTPS URLs outside development environments "
      "(R-20.7-s)"
    )
  return url


def url_host(url: str) -> str:
  """Return the host/domain a client MUST display for examination (R-20.7-v)."""
  return urlsplit(url).hostname or ""


def is_punycode_host(host: str) -> bool:
  """Return True if a host contains a Punycode (``xn--``) label (R-20.7-x).

  A client SHOULD warn about ambiguous/suspicious URIs such as those containing
  Punycode, which can be used for homograph/subdomain spoofing (R-20.7-x).
  """
  return any(label.startswith("xn--") for label in host.lower().split("."))


@dataclass
class UrlConsentDecision:
  """Result of presenting a URL-mode URL to the user for consent (R-20.7-t/u/v/w/x).

  Captures the client-side safe-URL-handling checks for one URL. A client:

  - MUST NOT pre-fetch the URL or its metadata (R-20.7-t).
  - MUST NOT open the URL without explicit user consent (R-20.7-u).
  - MUST show the full URL with the target host before consent (R-20.7-v).
  - MUST open it so neither client nor LLM can inspect page/inputs (R-20.7-w).
  - SHOULD warn about Punycode / suspicious hosts (R-20.7-x).

  Fields:
    url, host: the full URL and its extracted host.
    is_suspicious: True when the host triggers a SHOULD-warn (e.g. Punycode).
  """

  url: str
  host: str
  is_suspicious: bool


def prepare_url_for_consent(url: str) -> UrlConsentDecision:
  """Build the consent-presentation data for a URL-mode URL WITHOUT fetching it (R-20.7-t/v/x).

  Performs no network access — it MUST NOT pre-fetch the URL or its metadata
  (R-20.7-t). It extracts the full URL and host to display for examination
  (R-20.7-v) and flags suspicious hosts (e.g. Punycode) for a warning
  (R-20.7-x). Opening the URL is gated separately by :func:`open_url_with_consent`.
  """
  validate_elicitation_url(url)
  host = url_host(url)
  return UrlConsentDecision(url=url, host=host, is_suspicious=is_punycode_host(host))


def open_url_with_consent(decision: UrlConsentDecision, *, user_consented: bool) -> str:
  """Return the URL to open ONLY after explicit user consent (R-20.7-u/w).

  A client MUST NOT open the URL without explicit user consent (R-20.7-u). This
  refuses to yield the URL unless ``user_consented`` is True; the caller is
  responsible for opening it in an isolated manner that prevents the client or an
  LLM from inspecting the page or the user's inputs (R-20.7-w).

  Raises:
    UnsafeElicitationUrlError: ``user_consented`` is False.
  """
  if not user_consented:
    raise UnsafeElicitationUrlError(
      "a client MUST NOT open the elicitation URL without explicit user consent "
      "(R-20.7-u)"
    )
  return decision.url


def is_clickable_url_field_allowed(field_name: str, *, mode: str) -> bool:
  """Return True only for the ``url`` field of a URL-mode request (R-20.7-y, AC-31.31).

  A client SHOULD NOT render URLs as clickable in any field of an elicitation
  request, EXCEPT the ``url`` field of a URL-mode request (R-20.7-y). Every other
  field, in either mode, returns False.
  """
  return mode == MODE_URL and field_name == "url"


# ---------------------------------------------------------------------------
# §20.7  Server-side identity binding & cross-user verification  [R-20.7-j–o]
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ElicitationIdentityBinding:
  """A server-side binding of an elicitation to a verified client+user identity (§20.7).

  A server MUST bind elicitation requests to the client and user identity
  (R-20.7-j) and MUST NOT rely on client-provided user identification without
  server-side verification (R-20.7-k). For URL mode, the server MUST verify that
  the user who opens the URL is the SAME user who started the elicitation
  (R-20.7-l/m), SHOULD do so via its authorization server's authoritative
  subject (``sub``) rather than any identity carried in the URL (R-20.7-n), and
  the mechanism MUST be resilient to URL tampering (R-20.7-o).

  Fields:
    elicitation_id: the elicitation this binding is for.
    client_id: the identity of the initiating client.
    server_verified_subject: the authoritative ``sub`` established server-side
      for the MCP session (NOT taken from the URL) (R-20.7-k/n).
  """

  elicitation_id: str
  client_id: str
  server_verified_subject: str

  def verify_completion_subject(self, browser_session_subject: str) -> bool:
    """Return True iff the out-of-band user matches the initiating user (R-20.7-l/m/n).

    Compares the authoritative MCP-session subject against the subject of the
    browser session that opened the URL (R-20.7-n). Both subjects are obtained
    server-side from the authorization server; NEITHER is read from the URL,
    which keeps the check resilient to an attacker modifying the URL (R-20.7-o).
    A mismatch means a forwarded-URL / cross-user phishing attempt and MUST be
    rejected before accepting any out-of-band information (R-20.7-l/m).
    """
    if not browser_session_subject:
      return False
    return browser_session_subject == self.server_verified_subject


def reject_client_provided_identity(*, has_server_verification: bool) -> None:
  """Raise unless client-provided identity is backed by server-side verification (R-20.7-k).

  A server MUST NOT rely on client-provided user identification without
  server-side verification, since such identification can be forged (R-20.7-k).

  Raises:
    PermissionError: ``has_server_verification`` is False.
  """
  if not has_server_verification:
    raise PermissionError(
      "a server MUST NOT rely on client-provided user identification without "
      "server-side verification (R-20.7-k)"
    )


# ---------------------------------------------------------------------------
# §20.7  URL-mode elicitation is NOT an authorization mechanism  [R-20.7-z/aa]
# ---------------------------------------------------------------------------

def assert_not_used_for_authorization(*, used_to_authorize_client: bool) -> None:
  """Raise if URL-mode elicitation is being used to authorize the client (R-20.7-z, AC-31.32).

  URL-mode elicitation is NOT a mechanism for authorizing the client's own
  access to the server; that is the §23 authorization model's job. A server MUST
  NOT rely on URL-mode elicitation to authorize users for itself (R-20.7-z).

  Raises:
    PermissionError: ``used_to_authorize_client`` is True.
  """
  if used_to_authorize_client:
    raise PermissionError(
      "URL-mode elicitation MUST NOT be used to authorize the client for the "
      "server itself; use the §23 authorization model (R-20.7-z)"
    )


def assert_credentials_not_transmitted_to_client(*, transmits_credentials: bool) -> None:
  """Raise if out-of-band credentials would be transmitted to the client (R-20.7-aa, AC-31.32).

  A server MUST NOT transmit credentials obtained through URL-mode elicitation to
  the client (R-20.7-aa). The out-of-band interaction keeps such secrets server
  side; only the §20.6 completion signal (an id, never a credential) crosses back.

  Raises:
    PermissionError: ``transmits_credentials`` is True.
  """
  if transmits_credentials:
    raise PermissionError(
      "a server MUST NOT transmit credentials obtained through URL-mode "
      "elicitation to the client (R-20.7-aa)"
    )
