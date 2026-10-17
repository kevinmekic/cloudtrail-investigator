"""Render a report model as Markdown or self-contained HTML (Jinja2 templates).

Every CloudTrail field is attacker-controlled, so every value a template
outputs is escaped; the templates' own text is the only markup.

* HTML: Jinja2 autoescaping is on, so text and attribute values are
  HTML-escaped (quotes included). The page loads nothing: styles are inline and
  a Content-Security-Policy forbids scripts, frames, forms and external
  resources, in case escaping were ever bypassed.
* Markdown: every output value is escaped by ``md_escape`` (the environment's
  ``finalize`` hook, so a template cannot forget it). It backslash-escapes
  the characters that make links, images, HTML, emphasis, code and table cells,
  and the characters autolinking needs (``://``, and the dot in ``www.`` and
  other domain names, which renderers such as markdown-it's linkify turn into
  links even without ``www.``). GitHub links e-mail addresses, @mentions and
  issue references (``#1``, ``GH-1``, ``owner/repo#1``) even when escaped, but
  never inside a code span, so a word with ``@``, ``#`` and a digit, or ``GH-``
  and a digit becomes a code span, without its surrounding punctuation.
* Both: control, format and line-separator characters (newlines, bidirectional
  overrides, zero-width characters) are shown as ``\\uXXXX`` text, so a value
  cannot break a line or table row, or display differently from what it is.
"""

import re
import unicodedata
from datetime import datetime
from typing import Any

from jinja2 import Environment, PackageLoader, StrictUndefined
from markupsafe import Markup

_HIDDEN = {"Cc", "Cf", "Zl", "Zp"}

# Backslash escapes are valid before any ASCII punctuation in CommonMark/GFM, so
# escaping more than needed only changes the source, never the rendered text.
_MD_ESCAPE = re.compile(
    r"[\\`*_{}\[\]<>()#+!|~&$]"  # links, images, HTML, emphasis, code, tables, math
    r"|:(?=//)"  # http:// autolinks
    r"|(?<=[0-9A-Za-z])\.(?=[A-Za-z])"  # www. and bare-domain autolinks (not IPs)
    r"|^[-=](?=[-= \t]|$)"  # a list item, rule or heading underline, should a value start a line
)
_MD_ORDERED = re.compile(r"^(\d{1,9})\.(?=[ \t]|$)")  # an ordered list item, likewise
# A word ends at whitespace, a table pipe or a backtick, so a code span made of it
# needs no longer fence and cannot split a table cell.
_MD_WORD = re.compile(r"[^\s|`]+")
_MD_LINKABLE = re.compile(r"@|#[0-9]|(?i:gh)-[0-9]")  # e-mail, @mention, issue reference
_MD_LEAD, _MD_TRAIL = "([{<\"'", ")]}>\"'.,;:!?"  # punctuation kept outside the code span


def visible(text: str) -> str:
    """Show control, format and line-separator characters as \\uXXXX text."""
    if text.isprintable():
        return text
    return "".join(
        (f"\\u{ord(c):04x}" if ord(c) <= 0xFFFF else f"\\U{ord(c):08x}")
        if unicodedata.category(c) in _HIDDEN
        else c
        for c in text
    )


def _md_text(text: str) -> str:
    return _MD_ESCAPE.sub(lambda m: "\\" + m.group(), text)


def md_escape(text: str) -> str:
    text = visible(text)
    parts, done = [], 0
    for word in _MD_WORD.finditer(text):
        if _MD_LINKABLE.search(word.group()):
            # The linkable characters are not punctuation, so they stay inside.
            start = word.end() - len(word.group().lstrip(_MD_LEAD))
            end = word.start() + len(word.group().rstrip(_MD_TRAIL))
            parts += [_md_text(text[done:start]), f"`{text[start:end]}`"]
            done = end
    parts.append(_md_text(text[done:]))
    return _MD_ORDERED.sub(r"\1\\.", "".join(parts))


def _html_finalize(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, str) and not isinstance(value, Markup):
        return visible(value)
    return value


def _md_finalize(value: Any) -> str:
    return "" if value is None else md_escape(str(value))


def _num(value: int | float) -> str:
    return f"{value:,}"


def _count(value: int, word: str, plural: str | None = None) -> str:
    """'1 resource', '2 resources'."""
    return f"{value:,} {word if value == 1 else plural or word + 's'}"


def _time(value: datetime | None) -> str:
    return value.isoformat(sep=" ") if value else "-"


def _span(first: datetime | None, last: datetime | None) -> str:
    if first == last:
        return _time(first)
    if first and last and first.date() == last.date():
        return f"{_time(first)} – {last.time().isoformat()}"
    return f"{_time(first)} – {_time(last)}"


def _some(values: list, shown: int = 3) -> str:
    """'a, b, c, +2 more' for a list of strings."""
    text = ", ".join(str(v) for v in values[:shown])
    return text + (f", +{len(values) - shown:,} more" if len(values) > shown else "")


def _top(entry: dict, shown: int | None = None) -> str:
    """'value (events), ... +N more' for a session's top values and distinct count."""
    top = entry["top"][:shown] if shown else entry["top"]
    text = ", ".join(f"{value} ({n:,})" for value, n in top)
    more = entry["distinct"] - len(top)
    return (text + (f", +{more:,} more" if more > 0 else "")) or "-"


def _duration(seconds: int) -> str:
    return f"{seconds // 60} minutes" if seconds % 60 == 0 else f"{seconds} seconds"


def _environment(autoescape: bool) -> Environment:
    env = Environment(
        loader=PackageLoader("ctinv", "templates"),
        autoescape=autoescape,
        finalize=_html_finalize if autoescape else _md_finalize,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters.update(
        num=_num, count=_count, time=_time, span=_span, some=_some, top=_top, duration=_duration
    )
    return env


def render_html(model: dict[str, Any]) -> str:
    return _environment(True).get_template("report.html.j2").render(r=model)


def render_markdown(model: dict[str, Any]) -> str:
    return _environment(False).get_template("report.md.j2").render(r=model)
