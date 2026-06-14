"""Completion: argument autocompletion for prompts & resource templates — S29.

Delivers the **completion** server feature (§19): a best-effort, advisory
facility that suggests ranked candidate values for one argument of a prompt
(§18 / S28) or one variable of a resource template (§17 / S26). As a user fills
in an argument — typically in a filtering dropdown — the client sends a single
``completion/complete`` request carrying the current partial value (the seed)
and optionally already-resolved sibling arguments, and the server returns a
ranked, capped list of candidate strings.

This story owns:
  - ``CompletionsCapability`` and the gating discipline (§19.1): the server
    advertises the ``completions`` capability (the empty object ``{}`` is the
    RECOMMENDED baseline); a client MUST NOT call ``completion/complete`` against
    a server that did not declare it; an undeclared server SHOULD answer with
    ``-32601`` (Method not found) (R-19.1-a … R-19.1-d, R-19.5-q).
  - The ``completion/complete`` method name (exact, case-sensitive) and direction
    (client → server) (R-19-a, R-19.2-a).
  - ``CompleteRequestParams`` and its members ``ref`` / ``argument`` / optional
    ``context`` / optional ``_meta`` (§19.2).
  - The closed reference union ``PromptReference`` (``ref/prompt``) and
    ``ResourceTemplateReference`` (``ref/resource``), variant selection by
    ``ref.type``, and closed-union rejection (§19.3).
  - ``CompleteResult`` and its ``completion`` object (``values`` ≤ 100, optional
    ``total`` / ``hasMore``), the required ``resultType`` discriminator, and
    optional ``_meta`` (§19.4).
  - Server behaviour: ranking, matching, context use, the 100-item cap and
    truncation signalling, empty-input handling, validation, rate limiting, and
    access control over suggested values (§19.5).
  - Client behaviour: populating context (excluding the completed argument),
    debouncing, caching, and graceful handling of empty/partial results (§19.5).
  - Error mapping: ``-32601`` (no capability), ``-32602`` (unknown ref / unknown
    argument / missing-or-malformed params / bad ``ref.type``), ``-32603``
    (internal failure) (§19.5).

It REUSES rather than re-implements earlier-wave work:
  - ``ServerCapabilities`` / ``capability_is_present`` (S10, capabilities) for
    capability-presence gating; the ``completions`` field already lives on
    ``ServerCapabilities``.
  - ``RESULT_TYPE_COMPLETE`` / ``ResultType`` (S04, result_error) for the
    ``resultType`` discriminator.
  - ``Prompt`` / ``PromptArgument`` (S28, prompts) for resolving a prompt and
    its declared argument names.
  - ``ResourceTemplate`` (S26, resources) for resolving a resource template and
    its URI-template variable names.

Out of scope (owned elsewhere): the definition of prompts and their argument
names and ``prompts/list`` / ``prompts/get`` (S28); resources, resource
templates, URI templates and their variables (S26); the place of ``completions``
within ``ServerCapabilities`` and the negotiation/gating machinery (S10); the
base request/response envelope, the ``resultType`` field definition and ``_meta``
semantics (S03–S05); the canonical error-code registry (S34); and the detailed
access-control/security rationale (S44, referenced not redefined).

Spec: §19.1–§19.6
Depends on: S10 (capability gating), S28 (Prompts), S26 (Resources I),
            S04 (resultType discriminator)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from mcp_sdk_py.capabilities import ServerCapabilities, capability_is_present
from mcp_sdk_py.prompts import Prompt
from mcp_sdk_py.resources import ResourceTemplate
from mcp_sdk_py.result_error import RESULT_TYPE_COMPLETE, ResultType


# ---------------------------------------------------------------------------
# §19  Method name, capability key, discriminators & error codes
# ---------------------------------------------------------------------------

#: The single completion method, sent client → server (R-19-a). The name is the
#: exact, case-sensitive string ``completion/complete`` (R-19.2-a). NOTE: this
#: symbol shadows the same-named constant exported by S28 (prompts), which names
#: the method only as the argument-completion hook reference; both hold the
#: identical value, so the clash is a duplicate name, not a value conflict.
METHOD_COMPLETION_COMPLETE: str = "completion/complete"

#: The key under a server's capabilities object whose mere presence enables
#: argument autocompletion (§19.1, R-19.1-a). The field itself lives on
#: ``ServerCapabilities`` (S10); this names the wire key.
COMPLETIONS_CAPABILITY_KEY: str = "completions"

#: The exact discriminator value selecting the ``PromptReference`` variant of
#: ``ref`` (R-19.2-c, R-19.3-a).
REF_TYPE_PROMPT: str = "ref/prompt"

#: The exact discriminator value selecting the ``ResourceTemplateReference``
#: variant of ``ref`` (R-19.2-c, R-19.3-c).
REF_TYPE_RESOURCE: str = "ref/resource"

#: The closed set of ``ref.type`` values; any other value MUST be rejected with
#: ``-32602`` (R-19.2-e, R-19.3-f, R-19.5-s).
VALID_REF_TYPES: frozenset[str] = frozenset({REF_TYPE_PROMPT, REF_TYPE_RESOURCE})

#: The maximum number of items permitted in ``completion.values`` (R-19.4-c/d,
#: R-19.5-g). A server with more than this many matches MUST cap the array here.
MAX_COMPLETION_VALUES: int = 100

#: JSON-RPC error code for Method not found — returned by a server that has not
#: advertised the ``completions`` capability (R-19.1-d, R-19.5-q).
JSONRPC_METHOD_NOT_FOUND: int = -32601

#: JSON-RPC error code for Invalid params — a missing/malformed parameter, a
#: ``ref.type`` outside the closed union, an unknown prompt/template, or an
#: unknown argument (R-19.2-e, R-19.3-f, R-19.5-r, R-19.5-s).
JSONRPC_INVALID_PARAMS: int = -32602

#: JSON-RPC error code for Internal error — an internal failure while computing
#: completions (R-19.5-j, R-19.5-t).
JSONRPC_INTERNAL_ERROR: int = -32603

#: Matches a single RFC6570 URI-template variable name inside ``{…}`` braces, so
#: the set of completable variable names of a ``ResourceTemplateReference.uri``
#: can be derived to validate ``argument.name`` (R-19.3-e, R-19.5-r). Operator
#: prefixes (``+#./;?&``) and explode/prefix modifiers are stripped so the bare
#: variable names remain.
_TEMPLATE_VAR_PATTERN: re.Pattern[str] = re.compile(r"\{([^{}]+)\}")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class CompletionsCapabilityNotDeclaredError(Exception):
  """A ``completion/complete`` call was attempted though ``completions`` was undeclared.

  Raised by the client gate (R-19.1-c): a client MUST NOT send
  ``completion/complete`` to a server that has not advertised the
  ``completions`` capability during version negotiation. This is a local
  conformance guard. On the wire, a server that has not advertised the
  capability SHOULD respond with ``-32601`` (Method not found) instead
  (R-19.1-d, R-19.5-q) — see :func:`method_not_found_error`.

  Attributes:
    json_rpc_code: the code a server returns for this condition (``-32601``).
  """

  json_rpc_code: int = JSONRPC_METHOD_NOT_FOUND

  def __init__(self) -> None:
    super().__init__(
      f"Method {METHOD_COMPLETION_COMPLETE!r} requires the {COMPLETIONS_CAPABILITY_KEY!r} "
      f"capability, which the server did not advertise; a client MUST NOT send it "
      f"and an undeclared server SHOULD respond with {JSONRPC_METHOD_NOT_FOUND} "
      f"(Method not found) (R-19.1-c, R-19.1-d, R-19.5-q)"
    )


class InvalidCompletionParamsError(Exception):
  """A ``completion/complete`` parameter is missing or malformed.

  Covers a missing/non-object ``ref``, a ``ref.type`` outside the closed union,
  a missing/non-object ``argument``, or a missing/non-string ``argument.name`` /
  ``argument.value``. The server MUST respond with ``-32602`` (Invalid params)
  (R-19.2-b/e, R-19.2-f/g/h, R-19.3-f, R-19.5-s, AC-29.4, AC-29.6, AC-29.7).

  Attributes:
    json_rpc_code: always ``-32602`` for callers building error responses.
  """

  json_rpc_code: int = JSONRPC_INVALID_PARAMS

  def __init__(self, message: str) -> None:
    super().__init__(f"{message} (reject with JSON-RPC {JSONRPC_INVALID_PARAMS}, Invalid params)")


class UnknownCompletionTargetError(Exception):
  """``ref`` names an unknown prompt/template, or an argument it does not declare.

  Unknown completion targets are reported via Invalid Params rather than as a
  not-found result: the server MUST respond with ``-32602`` (Invalid params)
  (R-19.5-r, AC-29.24). This covers an unknown prompt ``name``, an unknown
  template ``uri``, and an ``argument.name`` that is not a valid argument of the
  referenced prompt or a variable of the referenced template.

  Attributes:
    json_rpc_code: always ``-32602`` for callers building error responses.
  """

  json_rpc_code: int = JSONRPC_INVALID_PARAMS

  def __init__(self, message: str) -> None:
    super().__init__(f"{message} (reject with JSON-RPC {JSONRPC_INVALID_PARAMS}, Invalid params)")


# ---------------------------------------------------------------------------
# §19.1  The `completions` capability  [R-19.1-a, R-19.1-b]
# ---------------------------------------------------------------------------

@dataclass
class CompletionsCapability:
  """The value of the ``completions`` key in a server's capabilities object (§19.1).

  Its mere *presence* (not its contents) signals that the server supports
  argument autocompletion; it is an open map whose keys carry no protocol-defined
  meaning here (R-19.1-a). The empty object ``{}`` is the minimum baseline and
  the RECOMMENDED value (R-19.1-b, AC-29.1).

  Fields:
    extra: arbitrary open-map members carried verbatim; an empty mapping
      serialises to the RECOMMENDED ``{}`` (R-19.1-a/b).
  """

  extra: dict[str, Any] = field(default_factory=dict)

  def __post_init__(self) -> None:
    if not isinstance(self.extra, dict):
      raise TypeError(
        "CompletionsCapability must be a JSON object (open map); got "
        f"{type(self.extra).__name__} (R-19.1-a)"
      )

  @classmethod
  def baseline(cls) -> CompletionsCapability:
    """Return the RECOMMENDED baseline capability — the empty object ``{}`` (R-19.1-b)."""
    return cls()

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> CompletionsCapability:
    """Parse a wire ``completions`` capability value; an empty object ``{}`` is valid.

    Presence signals support; contents are an open map preserved verbatim
    (R-19.1-a). The RECOMMENDED value is the empty object (R-19.1-b).

    Raises:
      TypeError: ``data`` is not a JSON object.
    """
    if not isinstance(data, dict):
      raise TypeError(
        "CompletionsCapability must be a JSON object; got "
        f"{type(data).__name__} (R-19.1-a)"
      )
    return cls(extra=dict(data))

  def to_dict(self) -> dict[str, Any]:
    """Serialise to the wire object; an empty capability is the baseline ``{}`` (R-19.1-b)."""
    return dict(self.extra)


# ---------------------------------------------------------------------------
# §19.1  Capability gating  [R-19.1-a, R-19.1-c, R-19.1-d, R-19.5-q]
# ---------------------------------------------------------------------------

def completions_capability_declared(server_caps: ServerCapabilities) -> bool:
  """Return True if the server advertised the ``completions`` capability (R-19.1-a, §6.1).

  Presence-means-supported (§6.1): the ``completions`` field — even with an empty
  object value ``{}`` — declares support; absence declares it unsupported
  (AC-29.1). This single gate opens the ``completion/complete`` request.
  """
  return capability_is_present(server_caps.to_dict(), COMPLETIONS_CAPABILITY_KEY)


def client_may_send_complete_request(server_caps: ServerCapabilities) -> bool:
  """Return True if a client may send ``completion/complete`` to this server (R-19.1-c).

  A client MUST NOT send the request to a server that has not advertised the
  ``completions`` capability (AC-29.2). Gating is by capability presence alone.
  """
  return completions_capability_declared(server_caps)


def assert_client_may_send_complete_request(server_caps: ServerCapabilities) -> None:
  """Raise if a client may not send ``completion/complete`` (R-19.1-c).

  Call this on the client before issuing the request.

  Raises:
    CompletionsCapabilityNotDeclaredError: the server has not declared
      ``completions``; the matching wire error is ``-32601`` (R-19.1-d).
  """
  if not client_may_send_complete_request(server_caps):
    raise CompletionsCapabilityNotDeclaredError()


def method_not_found_error() -> dict[str, Any]:
  """Build the ``-32601`` error a server returns when ``completions`` is undeclared.

  A server that has not advertised ``completions`` and receives a
  ``completion/complete`` request SHOULD respond with ``-32601`` (Method not
  found) (R-19.1-d, R-19.5-q, AC-29.2). Returns the JSON-RPC ``error`` object.
  """
  return {
    "code": JSONRPC_METHOD_NOT_FOUND,
    "message": f"Method not found: {METHOD_COMPLETION_COMPLETE}",
  }


# ---------------------------------------------------------------------------
# §19.3  Reference union: PromptReference & ResourceTemplateReference
#        [R-19.3-a … R-19.3-f]
# ---------------------------------------------------------------------------

@dataclass
class PromptReference:
  """Identifies a prompt by name; discriminator ``type === "ref/prompt"`` (§19.3).

  Fields:
    name: REQUIRED programmatic name of the prompt being completed; matches a
      ``Prompt.name`` exposed via §18 (R-19.3-b, AC-29.11).
    title: OPTIONAL human-readable display name; NOT load-bearing for matching —
      servers resolve the prompt by ``name`` (R-19.3-a note, AC-29.11).
  """

  name: str
  title: str | None = None

  #: The closed discriminator; REQUIRED to equal exactly ``ref/prompt`` (R-19.3-a).
  type: str = field(default=REF_TYPE_PROMPT, init=False)

  def __post_init__(self) -> None:
    # R-19.3-b: name is REQUIRED and is the programmatic prompt name.
    if not isinstance(self.name, str) or not self.name:
      raise InvalidCompletionParamsError(
        "PromptReference.name is REQUIRED and must be a non-empty string (R-19.3-b)"
      )
    if self.title is not None and not isinstance(self.title, str):
      raise InvalidCompletionParamsError(
        "PromptReference.title must be a string when present (R-19.3-a)"
      )

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> PromptReference:
    """Parse a ``PromptReference`` from a wire dict; ``type`` MUST be ``ref/prompt``.

    Raises:
      InvalidCompletionParamsError: ``data`` is not an object, ``type`` is not
        exactly ``ref/prompt``, or ``name`` is missing/malformed (R-19.3-a/b,
        R-19.5-s).
    """
    if not isinstance(data, dict):
      raise InvalidCompletionParamsError(
        f"PromptReference must be a JSON object; got {type(data).__name__} (R-19.3-a)"
      )
    if data.get("type") != REF_TYPE_PROMPT:
      raise InvalidCompletionParamsError(
        f"PromptReference.type MUST be exactly {REF_TYPE_PROMPT!r}; got "
        f"{data.get('type')!r} (R-19.3-a)"
      )
    name = data.get("name")
    if not isinstance(name, str) or not name:
      raise InvalidCompletionParamsError(
        "PromptReference.name is REQUIRED and must be a non-empty string (R-19.3-b)"
      )
    return cls(name=name, title=data.get("title"))

  def to_dict(self) -> dict[str, Any]:
    """Serialise to the wire object; omits ``title`` when absent (§19.3)."""
    out: dict[str, Any] = {"type": self.type, "name": self.name}
    if self.title is not None:
      out["title"] = self.title
    return out


@dataclass
class ResourceTemplateReference:
  """Identifies a resource (template) by URI; discriminator ``type === "ref/resource"`` (§19.3).

  Fields:
    uri: REQUIRED URI or URI template whose variables are being completed; matches
      a resource template exposed per §17. MAY be a literal URI or a URI template
      containing ``{…}`` variables (e.g. ``file:///{path}``); when it is a
      template, ``argument.name`` identifies the variable being completed
      (R-19.3-d, R-19.3-e, AC-29.11, AC-29.12).
  """

  uri: str

  #: The closed discriminator; REQUIRED to equal exactly ``ref/resource`` (R-19.3-c).
  type: str = field(default=REF_TYPE_RESOURCE, init=False)

  def __post_init__(self) -> None:
    # R-19.3-d: uri is REQUIRED.
    if not isinstance(self.uri, str) or not self.uri:
      raise InvalidCompletionParamsError(
        "ResourceTemplateReference.uri is REQUIRED and must be a non-empty string "
        "(R-19.3-d)"
      )

  @property
  def is_template(self) -> bool:
    """True when ``uri`` contains at least one ``{…}`` variable (R-19.3-e, AC-29.12)."""
    return bool(_TEMPLATE_VAR_PATTERN.search(self.uri))

  def template_variable_names(self) -> set[str]:
    """The bare variable names appearing in ``uri`` (empty for a literal URI) (R-19.3-e).

    Used to validate that ``argument.name`` names a variable of the template
    (R-19.5-r). RFC6570 operator prefixes and modifiers are stripped so only the
    variable names remain.
    """
    return _extract_template_variable_names(self.uri)

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> ResourceTemplateReference:
    """Parse a ``ResourceTemplateReference``; ``type`` MUST be ``ref/resource``.

    Raises:
      InvalidCompletionParamsError: ``data`` is not an object, ``type`` is not
        exactly ``ref/resource``, or ``uri`` is missing/malformed (R-19.3-c/d,
        R-19.5-s).
    """
    if not isinstance(data, dict):
      raise InvalidCompletionParamsError(
        f"ResourceTemplateReference must be a JSON object; got {type(data).__name__} "
        "(R-19.3-c)"
      )
    if data.get("type") != REF_TYPE_RESOURCE:
      raise InvalidCompletionParamsError(
        f"ResourceTemplateReference.type MUST be exactly {REF_TYPE_RESOURCE!r}; got "
        f"{data.get('type')!r} (R-19.3-c)"
      )
    uri = data.get("uri")
    if not isinstance(uri, str) or not uri:
      raise InvalidCompletionParamsError(
        "ResourceTemplateReference.uri is REQUIRED and must be a non-empty string "
        "(R-19.3-d)"
      )
    return cls(uri=uri)

  def to_dict(self) -> dict[str, Any]:
    """Serialise to the wire object (§19.3)."""
    return {"type": self.type, "uri": self.uri}


#: The reference union; a ``ref`` is exactly one of these two variants (§19.3).
Reference = PromptReference | ResourceTemplateReference


def _extract_template_variable_names(uri: str) -> set[str]:
  """Return the bare RFC6570 variable names in ``uri`` (R-19.3-e).

  Each ``{…}`` expression MAY carry an operator prefix (``+#./;?&``) and one or
  more comma-separated variable specs, each of which MAY carry an explode (``*``)
  or prefix (``:n``) modifier. Only the bare variable names are returned.
  """
  names: set[str] = set()
  for expression in _TEMPLATE_VAR_PATTERN.findall(uri):
    body = expression.lstrip("+#./;?&")
    for spec in body.split(","):
      spec = spec.strip()
      if not spec:
        continue
      name = spec.split(":", 1)[0].rstrip("*").strip()
      if name:
        names.add(name)
  return names


def parse_reference(data: dict[str, Any]) -> Reference:
  """Select and parse the ``ref`` variant by ``ref.type`` (R-19.2-c/d/e, R-19.3-f).

  Treats the union as closed: a ``ref`` whose ``type`` is neither ``ref/prompt``
  nor ``ref/resource`` is invalid and is rejected with ``-32602`` (R-19.2-e,
  R-19.3-f, R-19.5-s, AC-29.5, AC-29.6).

  Args:
    data: the raw ``ref`` object from ``params``.

  Returns:
    A ``PromptReference`` when ``type`` is ``ref/prompt``, a
    ``ResourceTemplateReference`` when ``type`` is ``ref/resource``.

  Raises:
    InvalidCompletionParamsError: ``ref`` is not an object, lacks ``type``, or
      carries a ``type`` outside the closed union (code -32602).
  """
  if not isinstance(data, dict):
    raise InvalidCompletionParamsError(
      f"ref must be a JSON object; got {type(data).__name__} (R-19.2-c)"
    )
  ref_type = data.get("type")
  # R-19.2-d: select the variant strictly by the value of ref.type.
  if ref_type == REF_TYPE_PROMPT:
    return PromptReference.from_dict(data)
  if ref_type == REF_TYPE_RESOURCE:
    return ResourceTemplateReference.from_dict(data)
  # R-19.2-e / R-19.3-f: the union is closed — reject any other type.
  raise InvalidCompletionParamsError(
    f"ref.type MUST be one of {sorted(VALID_REF_TYPES)!r} (closed union); got "
    f"{ref_type!r} (R-19.2-e, R-19.3-f)"
  )


# ---------------------------------------------------------------------------
# §19.2  CompleteRequestParams  [R-19.2-b … R-19.2-l]
# ---------------------------------------------------------------------------

@dataclass
class CompletionArgument:
  """The single ``argument`` object of ``CompleteRequestParams`` (§19.2).

  Fields:
    name: REQUIRED name of the argument being completed — a prompt argument name
      or a URI-template variable name (R-19.2-g, AC-29.7).
    value: REQUIRED current partial value the user entered; the match seed. MAY
      be the empty string ``""``, for which the server SHOULD return suggestions
      appropriate to empty input (R-19.2-h, R-19.2-i, AC-29.7, AC-29.8).
  """

  name: str
  value: str

  def __post_init__(self) -> None:
    # R-19.2-g: argument.name is REQUIRED and a non-empty string.
    if not isinstance(self.name, str) or not self.name:
      raise InvalidCompletionParamsError(
        "argument.name is REQUIRED and must be a non-empty string (R-19.2-g)"
      )
    # R-19.2-h: argument.value is REQUIRED and a string; the empty string is
    # valid (R-19.2-i) — only a non-string or absent value is malformed.
    if not isinstance(self.value, str):
      raise InvalidCompletionParamsError(
        "argument.value is REQUIRED and must be a string (the empty string is "
        "permitted) (R-19.2-h, R-19.2-i)"
      )

  @property
  def is_empty_seed(self) -> bool:
    """True when ``value`` is the empty string — suggestions for empty input (R-19.2-i, AC-29.8)."""
    return self.value == ""

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> CompletionArgument:
    """Parse the ``argument`` object; both ``name`` and ``value`` are REQUIRED strings.

    Raises:
      InvalidCompletionParamsError: ``data`` is not an object, or ``name`` /
        ``value`` is missing or not a string (R-19.2-f/g/h, R-19.5-s).
    """
    if not isinstance(data, dict):
      raise InvalidCompletionParamsError(
        f"argument must be a JSON object; got {type(data).__name__} (R-19.2-f)"
      )
    name = data.get("name")
    if not isinstance(name, str) or not name:
      raise InvalidCompletionParamsError(
        "argument.name is REQUIRED and must be a non-empty string (R-19.2-g)"
      )
    if "value" not in data:
      raise InvalidCompletionParamsError(
        "argument.value is REQUIRED (R-19.2-h)"
      )
    value = data["value"]
    if not isinstance(value, str):
      raise InvalidCompletionParamsError(
        "argument.value is REQUIRED and must be a string (the empty string is "
        "permitted) (R-19.2-h, R-19.2-i)"
      )
    return cls(name=name, value=value)

  def to_dict(self) -> dict[str, Any]:
    """Serialise the ``argument`` object (§19.2)."""
    return {"name": self.name, "value": self.value}


@dataclass
class CompletionContext:
  """The optional ``context`` object of ``CompleteRequestParams`` (§19.2).

  Fields:
    arguments: OPTIONAL map of already-resolved sibling argument names → string
      values, supplied so the server can produce context-sensitive suggestions.
      Keys MUST NOT include the argument named in ``argument.name`` (R-19.2-j/k,
      R-19.5-m, AC-29.9). Servers MAY ignore the context entirely (R-19.2-l,
      R-19.5-f, AC-29.10).
  """

  arguments: dict[str, str] | None = None

  def __post_init__(self) -> None:
    if self.arguments is not None:
      if not isinstance(self.arguments, dict):
        raise InvalidCompletionParamsError(
          "context.arguments must be a JSON object (map of string → string) when "
          "present (R-19.2-j)"
        )
      for key, val in self.arguments.items():
        if not isinstance(key, str) or not isinstance(val, str):
          raise InvalidCompletionParamsError(
            "context.arguments must map string keys to string values (R-19.2-j)"
          )

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> CompletionContext:
    """Parse the ``context`` object; ``arguments`` is an optional string→string map.

    Raises:
      InvalidCompletionParamsError: ``data`` or ``arguments`` is malformed
        (R-19.2-j).
    """
    if not isinstance(data, dict):
      raise InvalidCompletionParamsError(
        f"context must be a JSON object; got {type(data).__name__} (R-19.2-l)"
      )
    return cls(arguments=data.get("arguments"))

  def to_dict(self) -> dict[str, Any]:
    """Serialise the ``context`` object; omits ``arguments`` when absent (§19.2)."""
    out: dict[str, Any] = {}
    if self.arguments is not None:
      out["arguments"] = dict(self.arguments)
    return out


def build_completion_context(
  resolved_arguments: dict[str, str],
  argument_name: str,
) -> CompletionContext:
  """Build a ``context`` excluding the argument being completed (R-19.2-k, R-19.5-m).

  A client SHOULD populate ``context.arguments`` with already-resolved sibling
  argument values so the server can disambiguate across a multi-argument prompt
  or template (R-19.2-j, R-19.5-m, AC-29.9); the key for the argument currently
  being completed MUST NOT appear (R-19.2-k). This helper drops that key
  defensively so the resulting context is conformant by construction.

  Args:
    resolved_arguments: all sibling argument values resolved so far.
    argument_name: the ``argument.name`` being completed — excluded from context.

  Returns:
    A ``CompletionContext`` whose ``arguments`` never includes ``argument_name``.
  """
  arguments = {k: v for k, v in resolved_arguments.items() if k != argument_name}
  return CompletionContext(arguments=arguments or None)


@dataclass
class CompleteRequestParams:
  """The ``params`` of a ``completion/complete`` request (§19.2).

  Fields:
    ref: REQUIRED reference identifying what is being completed; the closed union
      discriminated by ``ref.type`` (R-19.2-b/c/d, AC-29.4, AC-29.5).
    argument: REQUIRED single argument being completed (R-19.2-f, AC-29.7).
    context: OPTIONAL additional completion context; servers MAY ignore it
      (R-19.2-l, AC-29.10).
    meta: OPTIONAL request metadata, per §4 (R-19.2 ``_meta``). Wire key:
      ``_meta``.
  """

  ref: Reference
  argument: CompletionArgument
  context: CompletionContext | None = None
  meta: dict[str, Any] | None = None  # JSON key: _meta

  def __post_init__(self) -> None:
    if not isinstance(self.ref, (PromptReference, ResourceTemplateReference)):
      raise InvalidCompletionParamsError(
        "ref is REQUIRED and must be a PromptReference or ResourceTemplateReference "
        "(R-19.2-b/c)"
      )
    if not isinstance(self.argument, CompletionArgument):
      raise InvalidCompletionParamsError(
        "argument is REQUIRED and must be a CompletionArgument (R-19.2-f)"
      )
    if self.context is not None and not isinstance(self.context, CompletionContext):
      raise InvalidCompletionParamsError(
        "context must be a CompletionContext when present (R-19.2-l)"
      )
    # R-19.2-k: a context MUST NOT carry the argument named in argument.name.
    if self.context is not None and self.context.arguments is not None:
      if self.argument.name in self.context.arguments:
        raise InvalidCompletionParamsError(
          f"context.arguments MUST NOT include the argument being completed "
          f"({self.argument.name!r}) (R-19.2-k)"
        )
    if self.meta is not None and not isinstance(self.meta, dict):
      raise InvalidCompletionParamsError(
        "_meta must be a JSON object when present (§4)"
      )

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> CompleteRequestParams:
    """Parse and validate ``completion/complete`` params (§19.2).

    Enforces every REQUIRED-or-malformed rule that maps to ``-32602``: a missing
    ``ref`` (R-19.2-b), a ``ref.type`` outside the closed union (R-19.2-e,
    R-19.3-f), a missing ``argument`` / ``argument.name`` / ``argument.value``
    (R-19.2-f/g/h), and a ``context`` carrying the completed argument's key
    (R-19.2-k). The empty seed ``argument.value === ""`` is accepted (R-19.2-i).

    Raises:
      InvalidCompletionParamsError: a required parameter is missing or malformed
        (code -32602, R-19.5-s).
    """
    if not isinstance(data, dict):
      raise InvalidCompletionParamsError(
        f"completion/complete params must be a JSON object; got {type(data).__name__} "
        "(R-19.2-b)"
      )
    if "ref" not in data:
      raise InvalidCompletionParamsError("ref is REQUIRED (R-19.2-b)")
    ref = parse_reference(data["ref"])
    if "argument" not in data:
      raise InvalidCompletionParamsError("argument is REQUIRED (R-19.2-f)")
    argument = CompletionArgument.from_dict(data["argument"])
    raw_context = data.get("context")
    context = CompletionContext.from_dict(raw_context) if raw_context is not None else None
    meta = data.get("_meta")
    if meta is not None and not isinstance(meta, dict):
      raise InvalidCompletionParamsError("_meta must be a JSON object when present (§4)")
    return cls(ref=ref, argument=argument, context=context, meta=meta)

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire-compatible ``params`` dict; omits absent optionals (§19.2)."""
    out: dict[str, Any] = {
      "ref": self.ref.to_dict(),
      "argument": self.argument.to_dict(),
    }
    if self.context is not None:
      out["context"] = self.context.to_dict()
    if self.meta is not None:
      out["_meta"] = self.meta
    return out


# ---------------------------------------------------------------------------
# §19.4  CompleteResult & the completion object  [R-19.4-a … R-19.4-l]
# ---------------------------------------------------------------------------

@dataclass
class Completion:
  """The ``completion`` object inside ``CompleteResult`` (§19.4).

  Fields:
    values: REQUIRED candidate values ranked by descending relevance; MUST NOT
      exceed 100 items (R-19.4-b/c/d, R-19.5-c, AC-29.13, AC-29.14). MAY be empty
      when there are no matches (R-19.4-g, AC-29.15).
    total: OPTIONAL total number of matching options available; MAY exceed
      ``len(values)``; unknown when omitted (R-19.4-f/h, AC-29.16).
    has_more: OPTIONAL whether more matches exist beyond ``values``; clients
      treat omission as ``False`` (R-19.4-e/i, AC-29.14, AC-29.17). Wire key:
      ``hasMore``.
  """

  values: list[str]
  total: int | None = None
  has_more: bool | None = None  # JSON key: hasMore

  def __post_init__(self) -> None:
    # R-19.4-b: values is REQUIRED and is an array of strings.
    if not isinstance(self.values, list):
      raise ValueError("completion.values is REQUIRED and must be an array (R-19.4-b)")
    for entry in self.values:
      if not isinstance(entry, str):
        raise TypeError(
          f"completion.values entries must be strings; got {entry!r} (R-19.4-b)"
        )
    # R-19.4-c: the array MUST NOT contain more than 100 items.
    if len(self.values) > MAX_COMPLETION_VALUES:
      raise ValueError(
        f"completion.values MUST NOT exceed {MAX_COMPLETION_VALUES} items; got "
        f"{len(self.values)} (R-19.4-c, R-19.4-d, R-19.5-g)"
      )
    if self.total is not None:
      if isinstance(self.total, bool) or not isinstance(self.total, int):
        raise TypeError("completion.total must be an integer when present (R-19.4-f/h)")
      if self.total < 0:
        raise ValueError("completion.total must be non-negative when present (R-19.4-f)")
    if self.has_more is not None and not isinstance(self.has_more, bool):
      raise TypeError("completion.hasMore must be a boolean when present (R-19.4-e/i)")

  @property
  def effective_has_more(self) -> bool:
    """``hasMore`` with omission resolved to ``False`` (R-19.4-i, AC-29.17)."""
    return self.has_more is True

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> Completion:
    """Parse the ``completion`` object (§19.4).

    Validates ``values`` is a present array of ≤ 100 strings (R-19.4-b/c). An
    omitted ``hasMore`` is left as ``None`` and resolves to ``False`` via
    :attr:`effective_has_more` (R-19.4-i).

    Raises:
      TypeError / ValueError: ``values`` is absent/oversized, or a field has the
        wrong type.
    """
    if not isinstance(data, dict):
      raise TypeError(f"completion must be a JSON object; got {type(data).__name__}")
    if "values" not in data:
      raise ValueError("completion.values is REQUIRED (R-19.4-b)")
    raw_values = data["values"]
    if not isinstance(raw_values, list):
      raise TypeError("completion.values must be an array (R-19.4-b)")
    return cls(
      values=raw_values,
      total=data.get("total"),
      has_more=data.get("hasMore"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise the ``completion`` object; omits ``total`` / ``hasMore`` when absent (§19.4)."""
    out: dict[str, Any] = {"values": list(self.values)}
    if self.total is not None:
      out["total"] = self.total
    if self.has_more is not None:
      out["hasMore"] = self.has_more
    return out


@dataclass
class CompleteResult:
  """The successful result of ``completion/complete`` (§19.4).

  Fields:
    completion: REQUIRED container for the ranked suggestions (R-19.4-a,
      AC-29.13).
    result_type: REQUIRED result-type discriminator; for a successful completion
      the value is ``"complete"`` (R-19.4-j/k, §3, AC-29.18). A client receiving
      a result that omits it MUST treat the absent field as ``"complete"``
      (R-19.4-l) — see :func:`parse_complete_result`. Wire key: ``resultType``.
    meta: OPTIONAL result metadata, per §4. Wire key: ``_meta``.
  """

  completion: Completion
  result_type: ResultType = RESULT_TYPE_COMPLETE  # JSON key: resultType
  meta: dict[str, Any] | None = None              # JSON key: _meta

  def __post_init__(self) -> None:
    # R-19.4-a: completion is REQUIRED.
    if not isinstance(self.completion, Completion):
      raise TypeError("CompleteResult.completion is REQUIRED and must be a Completion (R-19.4-a)")
    # R-19.4-j/k: resultType is REQUIRED; for a completion it is "complete".
    if not isinstance(self.result_type, str) or not self.result_type:
      raise ValueError("CompleteResult.resultType is REQUIRED (R-19.4-j/k)")
    if self.meta is not None and not isinstance(self.meta, dict):
      raise TypeError("CompleteResult._meta must be a JSON object when present (§4)")

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> CompleteResult:
    """Parse a wire ``CompleteResult`` (§19.4).

    A result that omits ``resultType`` is treated as ``"complete"`` (R-19.4-l,
    AC-29.18); a client MUST handle empty/partial/missing-field results gracefully
    (R-19.5-p, AC-29.23), so an omitted ``total``/``hasMore`` is accepted.

    Raises:
      TypeError / ValueError: ``completion`` is absent or malformed.
    """
    if not isinstance(data, dict):
      raise TypeError(f"CompleteResult must be a JSON object; got {type(data).__name__}")
    if "completion" not in data:
      raise ValueError("CompleteResult.completion is REQUIRED (R-19.4-a)")
    return cls(
      completion=Completion.from_dict(data["completion"]),
      result_type=data.get("resultType", RESULT_TYPE_COMPLETE),
      meta=data.get("_meta"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire-compatible result dict (§19.4).

    A server MUST include ``resultType`` (R-19.4-k); ``completion`` is always
    present (REQUIRED).
    """
    out: dict[str, Any] = {
      "resultType": self.result_type,
      "completion": self.completion.to_dict(),
    }
    if self.meta is not None:
      out["_meta"] = self.meta
    return out


def parse_complete_result(data: dict[str, Any]) -> CompleteResult:
  """Parse a ``completion/complete`` response, treating an absent ``resultType`` as complete.

  A client receiving a ``CompleteResult`` that omits ``resultType`` MUST treat the
  absent field as ``"complete"`` (R-19.4-l, AC-29.18), and MUST handle empty,
  partial, or missing-field results gracefully (R-19.5-p, AC-29.23). This is the
  client-side entry point that applies both rules.

  Raises:
    TypeError / ValueError: ``completion`` is absent or malformed.
  """
  return CompleteResult.from_dict(data)


# ---------------------------------------------------------------------------
# §19.5  Server: target resolution, matching, ranking, capping & errors
#        [R-19.4-c/d, R-19.5-b … R-19.5-t]
# ---------------------------------------------------------------------------

def resolve_completion_target_arguments(
  ref: Reference,
  argument_name: str,
  *,
  prompts: dict[str, Prompt] | list[Prompt] | None = None,
  templates: dict[str, ResourceTemplate] | list[ResourceTemplate] | None = None,
) -> None:
  """Validate that ``ref`` names a known target carrying ``argument_name`` (R-19.5-r).

  Unknown references and unknown arguments are Invalid Params, not not-found
  results (R-19.5-r, AC-29.24):
    - a ``PromptReference`` whose ``name`` matches no offered prompt, or whose
      ``argument_name`` is not one of that prompt's declared argument names, is
      rejected with ``-32602``;
    - a ``ResourceTemplateReference`` whose ``uri`` matches no offered template
      (when a registry is supplied), or whose ``argument_name`` is not a variable
      of the referenced template, is rejected with ``-32602``.

  When the referenced ``uri`` is itself a URI template (carries ``{…}``
  variables), its own variable set is authoritative for the argument check even
  if no ``templates`` registry is supplied — this supports the inline-template
  reference of R-19.3-e (AC-29.12).

  Args:
    ref: the parsed reference.
    argument_name: the ``argument.name`` being completed.
    prompts: the offered prompts (name→Prompt map or list), or None to skip the
      prompt-existence check.
    templates: the offered resource templates (uriTemplate→ResourceTemplate map
      or list), or None to skip the template-existence check.

  Raises:
    UnknownCompletionTargetError: the target or the argument is unknown
      (code -32602).
  """
  if isinstance(ref, PromptReference):
    _resolve_prompt_argument(ref, argument_name, prompts)
    return
  _resolve_template_variable(ref, argument_name, templates)


def _resolve_prompt_argument(
  ref: PromptReference,
  argument_name: str,
  prompts: dict[str, Prompt] | list[Prompt] | None,
) -> None:
  """Check a ``PromptReference`` against the offered prompts and their arguments (R-19.5-r)."""
  if prompts is None:
    return
  by_name = prompts if isinstance(prompts, dict) else {p.name: p for p in prompts}
  prompt = by_name.get(ref.name)
  if prompt is None:
    raise UnknownCompletionTargetError(
      f"Unknown prompt: no prompt named {ref.name!r} (R-19.5-r)"
    )
  declared = {a.name for a in (prompt.arguments or [])}
  if argument_name not in declared:
    raise UnknownCompletionTargetError(
      f"Unknown argument {argument_name!r}: prompt {ref.name!r} declares no such "
      f"argument (R-19.5-r)"
    )


def _resolve_template_variable(
  ref: ResourceTemplateReference,
  argument_name: str,
  templates: dict[str, ResourceTemplate] | list[ResourceTemplate] | None,
) -> None:
  """Check a ``ResourceTemplateReference`` against templates and their variables (R-19.5-r)."""
  if templates is not None:
    by_uri = (
      templates
      if isinstance(templates, dict)
      else {t.uri_template: t for t in templates}
    )
    template = by_uri.get(ref.uri)
    if template is None:
      raise UnknownCompletionTargetError(
        f"Unknown resource template: no template matching uri {ref.uri!r} (R-19.5-r)"
      )
    variables = _extract_template_variable_names(template.uri_template)
  elif ref.is_template:
    # R-19.3-e: an inline URI template's own variable set is authoritative.
    variables = ref.template_variable_names()
  else:
    # A literal URI with no registry: nothing to validate the argument against.
    return
  if argument_name not in variables:
    raise UnknownCompletionTargetError(
      f"Unknown argument {argument_name!r}: the resource template names no such "
      f"variable (R-19.5-r)"
    )


def rank_completion_candidates(
  candidates: list[str],
  seed: str,
) -> list[str]:
  """Match ``candidates`` against ``seed`` and rank them most-relevant-first (R-19.5-c/d).

  Implements the matching the spec describes as appropriate to an argument: a
  case-insensitive blend of prefix, then substring matching against
  ``argument.value`` (R-19.5-d, AC-29.20), ranked by descending relevance —
  prefix matches outrank later-substring matches, ties broken by the original
  order (R-19.5-c, AC-29.13). An empty seed returns all candidates in their
  given order, i.e. suggestions appropriate to empty input (R-19.2-i, AC-29.8).

  This is best-effort and advisory: a value absent from the result is not thereby
  forbidden (R-19.5-a/b, AC-29.19); callers MAY substitute their own matcher.

  Args:
    candidates: the universe of candidate strings to rank.
    seed: the ``argument.value`` partial value to match against.

  Returns:
    The matching candidates ordered by descending relevance (uncapped; apply
    :func:`cap_completion_values` to enforce the 100-item limit).
  """
  if seed == "":
    return list(candidates)
  needle = seed.casefold()
  scored: list[tuple[int, int, str]] = []
  for index, candidate in enumerate(candidates):
    hay = candidate.casefold()
    position = hay.find(needle)
    if position < 0:
      continue
    # Rank 0 = prefix match, rank 1 = later substring; ties keep input order.
    rank = 0 if position == 0 else 1
    scored.append((rank, index, candidate))
  scored.sort(key=lambda item: (item[0], item[1]))
  return [candidate for _, _, candidate in scored]


def cap_completion_values(values: list[str]) -> tuple[list[str], bool]:
  """Cap ``values`` at 100 items and report whether truncation occurred (R-19.4-c/d, R-19.5-g/h).

  A server with more than 100 matches MUST cap ``values`` at 100 (R-19.4-c/d,
  R-19.5-g) and SHOULD signal truncation via ``hasMore`` (R-19.4-e, R-19.5-h).

  Args:
    values: the ranked, matched candidate values (possibly more than 100).

  Returns:
    A ``(capped, truncated)`` tuple: ``capped`` is at most 100 items; ``truncated``
    is True exactly when items were dropped (the caller SHOULD set ``hasMore``).
  """
  if len(values) > MAX_COMPLETION_VALUES:
    return values[:MAX_COMPLETION_VALUES], True
  return list(values), False


def build_completion(
  values: list[str],
  *,
  total: int | None = None,
) -> Completion:
  """Cap ``values``, set ``hasMore`` on truncation, and build a ``Completion`` (§19.4/§19.5).

  Enforces the cap (R-19.4-c/d, R-19.5-g) and signals truncation via ``hasMore``
  (R-19.4-e, R-19.5-h, AC-29.14). When more than 100 matches were supplied, the
  result keeps the first 100 and sets ``hasMore = True``; the OPTIONAL ``total``
  is carried through and MAY exceed ``len(values)`` (R-19.4-f/h, AC-29.16). An
  empty ``values`` is a valid no-match result (R-19.4-g, AC-29.15).

  Args:
    values: the ranked candidate values (already matched against the seed).
    total: OPTIONAL total number of matching options available.

  Returns:
    A ``Completion`` with at most 100 values and ``hasMore`` set when truncated.
  """
  capped, truncated = cap_completion_values(values)
  has_more = True if truncated else None
  return Completion(values=capped, total=total, has_more=has_more)


def build_complete_result(
  values: list[str],
  *,
  total: int | None = None,
  meta: dict[str, Any] | None = None,
) -> CompleteResult:
  """Assemble a ``CompleteResult`` (capped values, ``resultType: "complete"``) (§19.4).

  Convenience for a server: caps ``values`` and signals truncation via
  :func:`build_completion`, then wraps it with the REQUIRED ``resultType`` of
  ``"complete"`` (R-19.4-j/k, AC-29.18).
  """
  return CompleteResult(
    completion=build_completion(values, total=total),
    meta=meta,
  )


def invalid_params_error(message: str) -> dict[str, Any]:
  """Build the ``-32602`` (Invalid params) JSON-RPC ``error`` object (R-19.5-r/s).

  For an unknown ref / unknown argument / missing-or-malformed param / bad
  ``ref.type`` (R-19.5-r, R-19.5-s, AC-29.4/6/7/24).
  """
  return {"code": JSONRPC_INVALID_PARAMS, "message": message}


def internal_error(message: str = "Internal error computing completions") -> dict[str, Any]:
  """Build the ``-32603`` (Internal error) JSON-RPC ``error`` object (R-19.5-j/t).

  For an internal failure while computing completions (R-19.5-t, AC-29.21).
  """
  return {"code": JSONRPC_INTERNAL_ERROR, "message": message}


def error_object_for(exc: Exception) -> dict[str, Any]:
  """Map a completion exception to its JSON-RPC ``error`` object (§19.5).

  Translates the story's local guards into the wire error codes the server
  returns (AC-29.2, AC-29.6, AC-29.7, AC-29.21, AC-29.24):
    - :class:`CompletionsCapabilityNotDeclaredError` ⇒ ``-32601`` (R-19.1-d);
    - :class:`InvalidCompletionParamsError` ⇒ ``-32602`` (R-19.5-s);
    - :class:`UnknownCompletionTargetError` ⇒ ``-32602`` (R-19.5-r);
    - any other exception (an internal failure) ⇒ ``-32603`` (R-19.5-t).

  Args:
    exc: the raised exception.

  Returns:
    The JSON-RPC ``error`` object with the mapped ``code`` and a message.
  """
  if isinstance(exc, CompletionsCapabilityNotDeclaredError):
    return method_not_found_error()
  if isinstance(exc, (InvalidCompletionParamsError, UnknownCompletionTargetError)):
    return invalid_params_error(str(exc))
  # R-19.5-t: any other failure while computing completions is an Internal error.
  return internal_error()
