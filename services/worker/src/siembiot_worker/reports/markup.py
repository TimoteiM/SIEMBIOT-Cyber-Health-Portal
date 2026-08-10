"""A tiny element tree, so a report cannot be injected into.

Reports carry text this platform did not write: an organisation's own name, host names
lifted out of certificate transparency logs, a mail server's greeting, an HTTP header
value. Any of it can contain `<script>`, and a report is read in a browser by somebody
who is signed in.

The usual answer is "remember to escape". That works until the one place somebody
forgets, and the failure is silent -- the report renders, looks right, and carries
whatever was in the evidence. So there is no string concatenation here at all. A
document is a tree; text nodes are escaped when the tree is serialized, and the only way
to emit unescaped markup is `Raw`, which exists for our own stylesheet and is greppable.

Serialization is deterministic: attributes keep insertion order, nothing is sorted by
hash, and no identifiers are generated. The same document renders to the same bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from html import escape
from typing import Union

#: Elements that carry no children and close themselves.
VOID_ELEMENTS = frozenset({"meta", "link", "br", "hr", "img"})


@dataclass(frozen=True)
class Raw:
    """Markup emitted verbatim.

    For content this repository authors -- the stylesheet, a doctype -- and nothing
    else. Every use is visible to `grep Raw(`, which is the point: the safety of this
    module is "text is escaped unless somebody explicitly said otherwise", and that
    exception should be small enough to read in one sitting.
    """

    markup: str


Node = Union[str, Raw, "Element"]


@dataclass(frozen=True)
class Element:
    tag: str
    attributes: dict[str, str] = field(default_factory=dict)
    children: tuple[Node, ...] = ()


def element(tag: str, *children: Node, **attributes: str) -> Element:
    """`class` and `for` are Python keywords, so they are written `class_` and `for_`."""
    return Element(
        tag,
        {name.rstrip("_").replace("_", "-"): value for name, value in attributes.items()},
        tuple(children),
    )


def render(node: Node) -> str:
    if isinstance(node, str):
        # `quote=True` also escapes " and ', so the same helper is correct for text and
        # for attribute values. One rule is easier to keep right than two.
        return escape(node, quote=True)
    if isinstance(node, Raw):
        return node.markup
    return _render_element(node)


def _render_element(node: Element) -> str:
    attributes = "".join(
        f' {name}="{escape(value, quote=True)}"' for name, value in node.attributes.items()
    )
    if node.tag in VOID_ELEMENTS:
        if node.children:
            # A void element with children means the caller expected content to appear
            # and it silently would not. Louder than a confusing report.
            raise ValueError(f"<{node.tag}> cannot have children")
        return f"<{node.tag}{attributes} />"
    inner = "".join(render(child) for child in node.children)
    return f"<{node.tag}{attributes}>{inner}</{node.tag}>"


def document(*children: Node, lang: str) -> str:
    """A complete HTML document, byte-for-byte reproducible from its inputs."""
    return "<!DOCTYPE html>\n" + render(element("html", *children, lang=lang)) + "\n"
