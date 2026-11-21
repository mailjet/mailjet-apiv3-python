"""Lazy HTML XSS and tag-bomb analysis helpers for SpamGuard."""

from __future__ import annotations

import re
import sys
from typing import TYPE_CHECKING, Any, Final

from mailjet_rest.errors import ValidationError


if TYPE_CHECKING:
    from collections.abc import Callable

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override


__all__ = ["XSS_PATTERN", "LazyHtmlGuardMeta", "analyze_html_safety", "build_spam_guard_parser"]


XSS_PATTERN: Final = re.compile(r"<(script|svg|iframe|object|embed|applet)|javascript:|onload=", re.IGNORECASE)


def _inspect_starttag(parser: Any, tag: str, attrs: list[tuple[str, str | None]]) -> None:
    parser._count_tag()  # ruff: ignore[private-member-access]
    if tag.lower() in {"script", "iframe", "object", "embed", "applet"}:
        parser.has_script = True
        parser.is_safe = False
        parser.issues.append(f"Blocked executable tag: <{tag}>")

    for attr, _ in attrs:
        if attr.lower().startswith("on"):
            parser.has_script = True
            parser.is_safe = False
            parser.issues.append(f"Blocked event handler: {attr}")


def build_spam_guard_parser() -> type[Any]:
    """Lazily build the SpamGuard HTMLParser subclass on first HTML analysis.

    Returns:
        type[Any]: Dynamically constructed HTMLParser subclass enforcing tag ceilings.
    """
    from html.parser import HTMLParser  # ruff: ignore[import-outside-top-level]

    class _SpamGuardParser(HTMLParser):
        """Internal lightweight HTML analyzer to preemptively catch XSS and tag bombs."""

        __slots__ = ("has_script", "is_safe", "issues", "max_tags", "tag_count")

        def __init__(self, max_tags: int = 10000) -> None:
            super().__init__()
            self.has_script: bool = False
            self.is_safe: bool = True
            self.issues: list[str] = []
            self.tag_count: int = 0
            self.max_tags: int = max_tags

        def _count_tag(self) -> None:
            self.tag_count += 1
            if self.tag_count > self.max_tags:
                msg = f"HTML structure exceeds maximum tag limit ({self.max_tags}): DoS protection triggered."
                raise ValidationError(msg)

        @override
        def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            _inspect_starttag(self, tag, attrs)

        @override
        def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            self.handle_starttag(tag, attrs)

        @override
        def handle_endtag(self, tag: str) -> None:
            self._count_tag()

        @override
        def handle_comment(self, data: str) -> None:
            self._count_tag()

    return _SpamGuardParser


class LazyHtmlGuardMeta(type):
    """Defer importing html.parser until HTML safety checks run."""

    def __getattr__(cls, name: str) -> Any:
        """Lazily initialize ``_SpamGuardParser`` when requested on SecurityGuard.

        Returns:
            Any: The lazily built parser class.
        """
        if name == "_SpamGuardParser":
            parser_cls = build_spam_guard_parser()
            type.__setattr__(cls, "_SpamGuardParser", parser_cls)
            return parser_cls
        msg = f"type object {cls.__name__!r} has no attribute {name!r}"
        raise AttributeError(msg)


def analyze_html_safety(
    html_content: str,
    *,
    parser_factory: Callable[[], Any],
    max_html_size: int = 5 * 1024 * 1024,
    max_tag_count: int = 10000,
) -> dict[str, Any]:
    """Analyze HTML payloads for XSS triggers, unsafe tags, and tag-bomb DoS.

    Returns:
        dict[str, Any]: Analysis report containing boolean ``is_safe`` and ``issues``.
    """
    if not html_content or (isinstance(html_content, str) and html_content.isspace()):
        return {"is_safe": True, "issues": []}

    if len(html_content) > max_html_size:
        sys.audit("mailjet.security.resource_exhaustion", "HTMLPart")
        msg = "Security Violation: HTML payload exceeds maximum safe length."
        raise ValueError(msg)

    if XSS_PATTERN.search(html_content):
        sys.audit("mailjet.security.xss_attempt", "HTMLPart")
        msg = "Security Violation: HTML contains executable Javascript/XSS vectors."
        raise ValueError(msg)

    parser = parser_factory()
    if hasattr(parser, "max_tags"):
        parser.max_tags = max_tag_count

    try:
        parser.feed(html_content)
        parser.close()
    except ValidationError:
        raise
    except Exception as e:
        msg = f"Fatal HTML parsing error (DoS protection triggered): {e}"
        raise ValidationError(msg) from e

    if parser.has_script:
        sys.audit("mailjet.security.xss_attempt", "HTMLPart")
        msg = "Security Violation: HTML contains blocked script/event execution tags."
        raise ValueError(msg)

    return {
        "is_safe": parser.is_safe and not parser.has_script,
        "issues": parser.issues,
    }
