"""The model, behind an abstraction, and disabled by default.

No provider SDK is imported here and no credential is read. A deployment that wants
Semantic Kernel, or an OpenAI or Azure client, implements `ModelProvider` and passes it
in; the gateway never learns which one it got, and the provider never learns anything
about the tenant beyond the evidence the tools already returned.

`DisabledProvider` is the default, and it is not a stub for testing -- it is what runs in
production until somebody deliberately configures otherwise. Every workflow completes
with it, which is the property the whole design rests on.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class Completion:
    """What a provider returns. Structured, never free text.

    A provider that hands back prose has already lost the argument: the narrative schema
    is strict and rejects unknown fields, so a model that improvises a shape produces
    nothing rather than something almost right.
    """

    payload: dict[str, Any]
    tokens_used: int = 0
    cost_units: float = 0.0


class ProviderUnavailableError(RuntimeError):
    """The provider could not be reached, or refused.

    A distinct type because the caller's response is distinct: an unavailable provider is
    not a failed assessment, it is an assessment without the optional narrative.
    """


class ModelProvider(Protocol):
    # Read-only, so a frozen implementation satisfies the protocol. A mutable attribute
    # here would require every provider to allow its own name to be reassigned, which is
    # the opposite of what an audit record wants from it.
    @property
    def name(self) -> str: ...

    @property
    def model(self) -> str: ...

    def complete(self, instructions: str, data: dict[str, Any]) -> Completion:
        """`instructions` is written by this repository. `data` is everything else.

        Two parameters rather than one prompt string, deliberately: an implementation
        cannot accidentally concatenate untrusted tool output into the instruction
        position, because it never receives them already joined.
        """
        ...


@dataclass(frozen=True)
class DisabledProvider:
    """The default. Produces nothing and says so."""

    name: str = "disabled"
    model: str = "none"

    def complete(self, instructions: str, data: dict[str, Any]) -> Completion:
        del instructions, data
        raise ProviderUnavailableError("the model is disabled")
