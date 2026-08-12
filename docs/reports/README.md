# Reports

The one artefact that leaves this platform. An institution downloads it, forwards it, and
opens it on a machine that may have no route back here — possibly a year later, possibly
in front of an auditor. Everything below follows from that.

## What a report is

A single self-contained file, in Romanian or English, marked CONFIDENTIAL on its face
rather than only in the covering message. It carries the score, the coverage it rests on,
the pillar breakdown, every open finding with its guidance and caveats, the checks that
could not be determined, the checks that were never attempted, and the methodology version
and policy digest that produced all of it.

Available as **HTML** everywhere, and as **PDF** where the deployment has a renderer.

## Properties, and why each one

**It fetches nothing.** No stylesheet link, no font URL, no image host, no script. A page
that fetches anything tells whoever hosts that thing when a confidential document was
opened and by whom. It also has to render from a downloads folder with no connectivity,
which the same property gives for free.

**It cannot be injected into.** A report carries text this platform did not write: an
institution's own name, host names lifted from certificate transparency logs, a mail
server's greeting. The renderer builds an element tree and escapes on serialization, so
there is no path that concatenates untrusted text into markup. Both escape paths are
covered by tests that fail when the escaping is removed.

**It is reproducible.** The same stored snapshot renders to the same bytes. Nothing is
read at render time — not a clock, not a dictionary iteration order, not a generated
identifier — and findings have a total order. A report that differs from itself cannot be
defended when somebody disputes it.

**It prints the policy digest.** So a disputed report can be checked against the exact
catalogue that produced it. Without it, "methodology 1.1.0" is a name rather than a proof.

**It says when the workings are gone.** Once retention removes the evidence a score was
computed from, the snapshot is stamped and the report says the score can no longer be
recomputed — beside the number, not in the footer, because a reader who takes the number
and stops reading should still have been told.

**It never prints a band it is not entitled to.** Below the coverage floor the score
stands and the band is withheld. A band is a conclusion, and a reader who sees one assumes
somebody was entitled to draw it.

## How it is delivered

Two steps. Asking for a report mints a short-lived, single-use grant; downloading redeems
it. A single-step URL would produce a confidential document every time it was opened, and
such URLs end up in browser history, referrer headers and chat threads.

The token is **stored hashed**, so reading the table yields no working link. The grant is
**bound to the person who asked**, so a copied URL is inert in anybody else's hands. It is
**single use** and expires in five minutes. All four failure modes — unknown, spent,
expired, not yours — return one empty result from one database function, because "this
token existed but is spent" confirms to a holder that the link was real.

The language and the format are fixed when the grant is minted. A reader's URL must not
change the form or the language of a document somebody else is accountable for sending.

## PDF

Rendered with WeasyPrint, not a headless browser, and not for weight. **WeasyPrint
executes no JavaScript and opens no sockets.** For a document assembled from third-party
evidence, a renderer that *cannot* run a script is a stronger guarantee than one that
merely has nothing to run.

It is optional. The renderer needs system libraries the API image carries and a Windows
developer machine does not, so a deployment without them reports PDF as unavailable —
named, at the moment the report is asked for rather than when the link is clicked — and
the HTML report still works. A missing renderer costs one format, not the feature.

Verified by rendering a real report inside the Linux image and reading the result:
`%PDF-`, correct pagination, and Romanian diacritics intact. Diacritics are checked
visually because a missing font produces a document full of boxes that still looks like a
successful render.

## What is not here

No branding, no logo, no letterhead. This is a free platform and a report is evidence
about an institution's own systems, not a marketing artefact.

No executive summary written by a model. The narrative layer is optional, disabled by
default, and everything above is produced deterministically without it.
