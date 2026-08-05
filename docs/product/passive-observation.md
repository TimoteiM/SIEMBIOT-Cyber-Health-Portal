# Passive observation

## Why this exists

The product has two lawful paths to a domain, and they were always in the design:

**Authorized assessment** requires verified domain control, a signed scope manifest and
recorded consent. It is how an organization assesses its own estate.

**Passive observation** requires none of that, because it asks the domain for nothing
that the domain does not already publish to everyone. It is how the Public Observatory
can report on public institutions that have never enrolled — the brief's own wording:
*"Passive public-observatory checks may run on public domains. Any active network check
requires verified domain control."*

Testing the product's capabilities against real domains therefore does not need the
architecture bent. It needs the second path built.

## What passive mode does

| Source | What it reads |
| --- | --- |
| DNS | Records the domain publishes to any resolver |
| RDAP | The public registration record |
| Certificate Transparency | Public append-only logs |
| HTTPS | One GET of the site root, exactly as a visitor's browser does |
| TLS | One handshake on 443, sending no application data |

Every check in methodology v1 is classified `passive`, so an observation run covers the
**entire catalog**. That is a property of the current catalog, not a permanent promise:
a future active check would be withheld automatically.

## What it cannot do

Operations are restricted by an allowlist in `siembiot_worker/observation/mode.py`, not
by convention. `PASSIVE_OPERATION_CLASSES` and `AUTHORIZED_ONLY_OPERATION_CLASSES`
partition every operation class, and a test asserts the partition is exhaustive — so a
new operation class cannot be added without a deliberate decision about which side it
falls on.

Passive mode cannot perform ownership verification, and the policy refuses such a
request at **every** broker checkpoint, not just the first.

A check that this mode may not perform resolves to `not_applicable` with the reason
`requires_authorized_assessment` — never to a pass. A thin passive run must not look
like a clean authorized one.

## Politeness

A public-interest observatory has no reason to be fast. Requests are limited to two per
second with a 250 ms minimum spacing, concurrency is capped at two, and the TLS protocol
probe is opt-in because it means several extra handshakes purely to see what is refused.

An in-process kill switch stops observation immediately and outranks every permission.

## Using it

```bash
DOMAIN=example.com make observe
python scripts/observe_domain.py example.com --json
python scripts/observe_domain.py example.com --dkim-selector selector1
```

DKIM selectors are never guessed; pass the ones you know are in use.

## Limits worth stating

- Results are **private by default**. Publishing anything is a separate, consented act
  with its own safety rules (Milestone 9).
- Methodology v1.0.0 has not passed its security, fairness or counsel review. Scores
  from it must not be published.
- Certificate Transparency needs a configured source; without one the CT checks report
  not-applicable rather than implying a domain has no certificates.
- Reputation needs an opt-in provider; without one it stays `unknown`.
