"""The Tyche gateway: bounded, grounded, optional analysis.

This service exists to let a model explain evidence the platform already gathered. It
holds no database credential, no network credential and no provider secret of its own;
everything it can reach arrives as a callable from the caller, which is already scoped to
one tenant.

The four things it must never do, and the reason each is structural rather than a rule:

* **Expand authority.** Tools are a closed enum. There is no shell, no fetch, no SQL and
  no code execution to refuse, because none can be named.
* **Change evidence or scores.** Every tool reads. Nothing in the narrative schema can
  carry a score, a band or a severity.
* **Leak another tenant.** Every tool call is checked against a scope the platform built
  from an authorization, and evidence identifiers are re-checked against the database.
* **Be required.** The model is disabled by default and every workflow completes without
  it.
"""
