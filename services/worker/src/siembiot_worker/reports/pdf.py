"""The report as a PDF, when a renderer is available.

An institution takes a report to a board, a supplier or an auditor, and those readers
want a document rather than a web page. The HTML is already print-ready; this turns it
into a file.

**WeasyPrint rather than a headless browser**, and the reason is not weight. WeasyPrint
does not execute JavaScript. The report is built from evidence this platform did not
write -- a mail server's greeting, a host name from a certificate log -- and although the
markup layer escapes all of it, a renderer that *cannot* execute a script is a stronger
guarantee than one that merely has nothing to execute. It also opens no sockets, which
matters for the same reason the HTML fetches nothing.

**Optional, and honestly so.** The renderer needs system libraries that are present in
the worker image and absent on a Windows developer machine. Rather than making the import
mandatory and the product unbuildable in half its environments, PDF is an enhancement:
when it is unavailable the HTML report still downloads and the interface says why, in the
same way the platform reports every other capability it lacks rather than failing
mysteriously.
"""

from __future__ import annotations

from functools import lru_cache

#: Reported to the caller when the renderer is not installed. A named reason rather than
#: a generic failure: "PDF is unavailable in this deployment" is a sentence somebody can
#: act on, and "500" is not.
RENDERER_UNAVAILABLE = "pdf_renderer_unavailable"


@lru_cache(maxsize=1)
def renderer_available() -> bool:
    """Whether this process can produce a PDF.

    Cached because the answer cannot change while the process runs, and because the
    import is expensive enough that asking on every request would be felt.

    The import is attempted rather than the package being looked up: WeasyPrint installs
    cleanly and then fails to import when its system libraries are missing, so presence
    on disk is not the question.
    """
    try:
        import weasyprint  # noqa: F401
    except Exception:  # noqa: BLE001 - any import failure means the same thing here
        return False
    return True


def render_pdf(html: str, base_url: str | None = None) -> bytes | None:
    """The document as PDF bytes, or None when no renderer is available.

    `base_url` is deliberately not defaulted to anything. WeasyPrint resolves relative
    URLs against it, and the report is self-contained precisely so that nothing is
    resolved; passing a real base would create the possibility of a fetch that the HTML
    was written to avoid.
    """
    if not renderer_available():
        return None

    import weasyprint

    document = weasyprint.HTML(string=html, base_url=base_url)
    return bytes(document.write_pdf())
