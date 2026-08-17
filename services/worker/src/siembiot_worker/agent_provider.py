"""An OpenAI-compatible provider, behind the same abstraction as every other.

**It lives in the worker, not in the gateway, and that is enforced.** The gateway package
is asserted to contain no network or database client at all -- a test reads its source and
fails on `httpx`, `socket`, `psycopg` and the rest -- because a module that could acquire
a connection later is one nobody notices acquiring it. The first version of this file was
written inside the gateway and that test caught it.

So the gateway stays pure analysis and receives a `ModelProvider`; the worker, which
already reaches the network to collect evidence, is where something that reaches the
network belongs. The gateway never learns which provider it got, which is what lets the
whole analysis path be tested without a key and run in production without one.

**No SDK.** `httpx` is already a dependency and the request is one POST; adding a vendor
client would pull a transitive tree into the image that handles retries, telemetry and
streaming this platform does not use. It would also make "which model did this" a
question about a library version rather than about a string this repository controls.

**What is sent.** The instructions this repository wrote, and evidence the platform
already collected about the domain being assessed. Nothing about the institution beyond
that: no organisation name, no user, no membership, no other domain. The gateway's tool
broker decides what evidence is in scope; this module only carries it.

**What comes back is not trusted.** The response is parsed as JSON and handed to the
gateway, which validates every claim against the run's evidence identifiers and drops
whatever it cannot support. A model that returns prose, invents an identifier, or states
a score produces nothing rather than something almost right -- that is the grounding
validator's job and it was written before any of this existed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import httpx
from siembiot_agent.provider import Completion, ProviderUnavailableError

#: The request is one call and the run has a deadline. A model that has not answered in
#: this long has failed, and the assessment completes without a narrative rather than
#: waiting -- the narrative is the optional part by design.
DEFAULT_TIMEOUT_SECONDS = 45.0

#: A ceiling on what one analysis may cost, independent of the run budget the gateway
#: also applies. Two limits rather than one because they fail differently: the gateway's
#: budget stops a run making many calls, and this stops one call being enormous.
#:
#: **Reasoning counts against this.** On a reasoning model `max_completion_tokens` covers
#: the thinking as well as the answer, and at 2,000 a real assessment spent the entire
#: budget reasoning and returned an empty string -- `finish_reason: length`, 2,000
#: reasoning tokens, no content. Worse than a clean failure, it was intermittent: a small
#: evidence set fitted and a full one did not, so the same code produced a narrative on
#: one domain and silence on the next.
#:
#: Sized for the whole of one domain's evidence with room for the model to think about
#: it. Overridable, because a different model reasons at a different length and this
#: number is about the model rather than about the platform.
DEFAULT_MAX_OUTPUT_TOKENS = 16_000


@dataclass(frozen=True)
class OpenAIProvider:
    """Calls an OpenAI-compatible chat completions endpoint.

    Frozen, so the name and model recorded in the audit trail cannot be reassigned after
    the run they describe.
    """

    api_key: str
    model: str
    base_url: str = "https://api.openai.com/v1"
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS
    name: str = field(default="openai")

    def __post_init__(self) -> None:
        if not self.api_key:
            # Refused at construction rather than at the first call. A provider built
            # without a key would look configured everywhere it was passed around and
            # fail once, deep inside a run, with the least useful stack available.
            raise ProviderUnavailableError("no api key configured")
        if not self.model:
            raise ProviderUnavailableError("no model configured")

    def complete(self, instructions: str, data: dict[str, Any]) -> Completion:
        """One request. Instructions and data stay separate to the last moment.

        They are two message roles rather than one concatenated prompt, which is the same
        reason the protocol takes two parameters: evidence collected from somebody else's
        infrastructure must never land in the instruction position, where a sentence in a
        mail server's banner would read as something this platform asked for.
        """
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": instructions},
                # Serialized as JSON rather than pasted as text, so a string inside the
                # evidence cannot terminate the surrounding structure.
                {"role": "user", "content": json.dumps(data, ensure_ascii=False, sort_keys=True)},
            ],
            # The narrative contract is strict and rejects unknown fields, so asking for
            # an object rather than prose removes the most common way a run produces
            # nothing: a model that explains itself before answering.
            "response_format": {"type": "json_object"},
            "max_completion_tokens": self.max_output_tokens,
        }

        try:
            response = httpx.post(
                f"{self.base_url.rstrip('/')}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=self.timeout_seconds,
            )
        except httpx.HTTPError as error:
            # The message, not the exception: an httpx error can carry the request, and
            # the request carries the key in a header.
            raise ProviderUnavailableError(
                f"provider unreachable: {type(error).__name__}"
            ) from None

        if response.status_code != 200:
            # The body is not included. A provider error page can echo the request, and
            # this exception message reaches logs.
            raise ProviderUnavailableError(f"provider returned {response.status_code}")

        try:
            body = response.json()
            choice = body["choices"][0]
            content = choice["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError):
            raise ProviderUnavailableError("provider returned no completion") from None

        # Named separately from a parse failure, because the fix is different and the
        # symptom is identical: both arrive as unusable content. This one means the
        # budget ran out mid-answer, which on a reasoning model happens without the
        # answer having started.
        if choice.get("finish_reason") == "length":
            raise ProviderUnavailableError(
                "provider ran out of tokens before finishing; raise max_output_tokens"
            )

        try:
            parsed = json.loads(content)
        except (ValueError, TypeError):
            raise ProviderUnavailableError(
                "provider returned something that is not a document"
            ) from None

        if not isinstance(parsed, dict):
            raise ProviderUnavailableError("provider returned a document of the wrong shape")

        usage = body.get("usage") or {}
        return Completion(
            payload=parsed,
            tokens_used=int(usage.get("total_tokens", 0) or 0),
        )
