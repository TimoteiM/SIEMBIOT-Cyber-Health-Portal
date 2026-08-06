# Running a demo

**You do not need to validate a domain.** That was never the intended constraint — it
was a gap in what the interface exposed.

## Why

The platform has two lawful paths to a domain, and they are different in kind rather
than in degree.

**Passive observation** reads what the domain already publishes: DNS records, RDAP, the
Certificate Transparency logs, the TLS certificate it serves, and the home page any
visitor would fetch. It asks the target for nothing a member of the public could not
already request, so proof of control would be a ceremony that protects nobody — and it
would put the methodology out of reach of exactly the people who need it most: a
regulator surveying a sector, a journalist checking a claim, somebody deciding whether
to trust a supplier.

**Authorized assessment** can reach past what a visitor sees, so it keeps every
requirement it ever had: verified control, a signed scope manifest, recorded consent.

Passive is not authorized-with-the-checks-off. It is a strictly smaller set of
operations, held to an allowlist in `observation/mode.py` so that no check added later
can quietly widen what an unauthorized run may do.

And the useful part for a demo: **all 22 checks in the published catalog are reachable
passively.** Nothing is withheld. A passive run exercises the entire methodology.

## The demo path

```
make stack-up
make migrate
python -m uv run --frozen --env-file .env python scripts/publish_methodology.py
make api-serve      # separate terminal
make worker-serve   # separate terminal
make beat-serve     # separate terminal
make web-serve      # separate terminal
```

Then, in the browser: create an organization, add any domain, and press **Observă
public**. No verification step, no waiting for DNS propagation. **Evaluare autorizată**
sits next to it, disabled with the reason on hover, so the distinction is visible rather
than hidden.

Expect a real result in about a minute. Pick a domain that is actually reachable from
wherever you are running this — a run against a host you cannot reach reports
`site_unreachable` honestly rather than inventing a score, which is correct but makes
for a poor demo.

## Without a browser

```
DOMAIN=example.com make observe
```

Passive observation from the command line, no enrollment at all. Useful for checking
that egress works before demoing.

## What a thin run looks like

If collection largely fails, the result will say **"Dovezi insuficiente pentru un
scor"** rather than showing a number. Below 60% coverage the methodology replaces the
band, because a run that observed almost nothing must not be presented as a confident
result — a 100 from three checks would be the most misleading thing this product could
display. The raw value stays visible as an audit detail.

This is worth showing deliberately in a demo rather than avoiding: it is the honesty
property the whole methodology is built around.

## What is recorded

Every assessment stores the mode it ran in, and the audit event carries it too, so
"what did this platform do to that domain, and under what authority" is answerable from
the log alone. An `authorized_assessment` row without an authorization is rejected by a
database constraint, not by whichever code path happened to create it — so the mode is a
guarantee rather than a label.
