# Three ways verification fails quietly

Written 2026-08-12, from findings in a single session on this codebase. Every example is
real and every one of them was introduced here by somebody trying to do the right thing —
including the person writing this document. That is the point: none of these are careless
mistakes, which is why they survive review.

They look alike from a distance and they call for three different habits, so they are kept
apart.

---

## Shape 1 — the check that cannot fail

A mechanism is present, green, and structurally incapable of catching the thing it is
named for.

**What it looked like here.** `audit_events` carried `previous_hash` and `event_hash` from
migration `0001`, with a CHECK constraint fixing them at 32 bytes. Nothing ever wrote
either column. The schema read as tamper-evidence for five months and provided none.

The same shape, four more times in one session:

* an alert rule matching `siembiot_network_operations`, a metric the exporter dropped
  whenever its table was empty — the rule could never fire, and nothing said so;
* an alert-rules parser that read `expr: >-` as an empty string, so the one multi-line
  expression in the file — the most complex one — was being "checked" against nothing;
* a quota ledger where four workers each stopped at a compliant ten while forty calls went
  out, and an assertion on the final count would have passed on the bug;
* a reproduction of a security defect that returned the expected `403` without ever
  reaching the code under test, because the request was refused by an origin check first.

And the one that names the whole shape: the first `audit_chain_breaks()` run against live
data returned EMPTY over **one** chained row out of twenty-six. **An empty result over one
row proves almost nothing.**

**Prevention: mutation-style testing.** Delete the feature, or break it deliberately, and
run the check. If it still passes, it was never a check. Applied here: the escaping was
removed from the report renderer and four tests failed; the pre-fix `authorize` was fed to
the append-then-raise detector and it found the bug. A detector that has never found
anything is indistinguishable from one that cannot.

**Cost.** Very cheap to introduce — you write a test, it passes, nothing signals. Cheap to
catch, but only deliberately: the mutation takes a minute and nobody does it by accident.

---

## Shape 2 — the write discarded by control flow it was not written with awareness of

Code that is correct in isolation and wrong in composition. Nothing is checking it, so
nothing goes green falsely; the mechanism simply is not there and looks like it is.

**What it looked like here.** `authorize()` appended an `authorization.denied` audit event
and then raised `AppError(403)` — both inside the request's transaction. `engine.begin()`
rolls back on an exception, so **every refusal since migration `0001` was recorded and
discarded in the same breath.** The database held fifteen `assessment.queued` rows and
zero `authorization.denied` rows, and refusals had certainly happened.

The audit write was correct. The raise was correct. Neither author was wrong about their
own line.

**Prevention: audit transaction boundaries around every write that carries security or
evidence value.** Not the audit log specifically — the same rollback would silently
discard a consent record, a takedown, or a revocation. The question to ask of any such
write is: *what happens to this if the surrounding request fails?* If the answer is "it
disappears" and the write is a record of the failure, it belongs on its own connection.

**Cost.** Moderately cheap to introduce — it needs a specific composition, so not every
day. Expensive to discover the *first* time, because nothing fails and you only find it by
going looking. Then very cheap to sweep for, once the shape is known: a targeted scan of
this codebase found no further instances and took two minutes.

---

## Shape 3 — the measurement that is a proxy for the property

You verified something. The verification was real, it ran, it passed. It measured
something adjacent to what you cared about.

**What it looked like here.** A report was rendered to PDF and checked: `%PDF-` header,
36 KB, no exception. All true, and **it would have passed identically on a document that
was a page of boxes**, because a missing font produces valid PDF bytes. The property that
mattered was "a Romanian institution can read this", not "this is a PDF". Converting the
first page to an image and looking at it — CONFIDENȚIAL, *igienă cibernetică*, *fără scor*
— was a different check answering a different question.

**Prevention: name the property before choosing the measurement.** Write down what must be
true in a sentence, then ask what would show you that, specifically. "Is it a PDF" and "is
it a readable Romanian document" are different questions, and only one of them was the
requirement.

**Cost.** The cheapest of the three to introduce, and the most common, precisely because it
happens *while genuinely trying to verify something*. You are doing the right thing and
still get it wrong, so nothing about the moment feels like a shortcut. Cheapest of the
three to catch at the moment of writing — it costs one question — and the most expensive
later, because catching it afterwards means reconstructing what the original author
actually meant to establish.

---

## Where to spend review time

Given the costs above, they warrant different treatment rather than one rule:

| Shape | Habit | When |
| --- | --- | --- |
| 1 — cannot fail | mutation: delete the feature, rerun the check | when writing any test that guards a security or evidence property |
| 2 — discarded write | trace the transaction boundary | at review, for any write that records a refusal, a consent, or a revocation |
| 3 — proxy measurement | state the property, then pick the measurement | at review, on every verification claim — this is the review question |

**Shape 3 is where review time actually pays.** It is the most frequent, it cannot be
automated away, and "what property does this measure?" is a question a reviewer can ask of
a diff in seconds. Shape 1 is best handled mechanically rather than by attention, since
attention is exactly what a green test does not attract. Shape 2 is rare enough to be a
periodic sweep rather than a standing habit.

## The question underneath all three

*What would this show me if the thing it is checking were absent?*

If the honest answer is "the same thing it shows me now", there is no verification, however
much machinery is attached to it.
