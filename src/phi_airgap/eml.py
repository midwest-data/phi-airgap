"""Scrub a raw email (.eml, RFC 822 / MIME) before it reaches a transcript.

Line-scanning the raw bytes is not enough: bodies are base64 or
quoted-printable (an SSN split by a QP soft break, or a whole base64 HTML
part, sails past a regex), and headers use RFC 2047 encoded words. So the
message is parsed, every text part is decoded, scrubbed and re-encoded, and
everything that cannot be scrubbed is removed. Fail-closed throughout:

- headers: an allowlist. Received/Return-Path/X-*/DKIM/Message-ID carry IPs,
  hostnames and mailbox names and are dropped outright. From/To/Cc/Reply-To
  keep only the domain (`REDACTED <redacted@summahealth.org>`); Subject goes
  through the scrubber; Date is kept (day precision — see the verdict).
- text/* parts: decoded, HTML flattened to text, scrubbed, re-encoded as UTF-8.
- every other part (PDF, image, Office, calendar blobs): replaced by a one-line
  placeholder naming only the content type and size. The filename is dropped —
  `Doe_Jane_labs.pdf` is itself PHI. Run `pq git scan` / the PDF extra on an
  attachment separately if it has to survive.
- message/rfc822 (a forwarded mail): recursed, its headers allowlisted too.

Email prose carries identifiers an aggregate result never does — "Patient:
Jane Doe", "DOB 03/14/1961", a street address — so this adds keyword-anchored
patterns on top of the shared deterministic floor. NER does the rest of the
names; without it, unanchored names in prose survive and the CLI says so.
"""

from __future__ import annotations

import html.parser
import re
from collections import Counter
from dataclasses import dataclass, field
from email import policy
from email.headerregistry import Address
from email.message import EmailMessage
from email.parser import BytesParser

from . import scrub

REDACT = scrub.REDACT
_ADDRESS_HEADERS = {"from", "to", "cc", "reply-to", "sender"}
_KEEP_HEADERS = _ADDRESS_HEADERS | {"subject", "date"}

_DATE = (
    r"(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{2}-\d{2}"
    r"|[A-Z][a-z]{2,8}\.?\s+\d{1,2},?\s+\d{4}|\d{1,2}\s+[A-Z][a-z]{2,8}\.?\s+\d{4})"
)
# (label, pattern) — group 1 is the anchor kept in the output, group 2 is redacted.
# ponytail: keyword-anchored names miss bare names in prose; NER is the layer for those.
_EMAIL_EXTRA: list[tuple[str, re.Pattern]] = [
    (
        "DATE_OF_BIRTH",
        re.compile(
            r"(?i)(\b(?:dob|d\.o\.b\.?|date\s+of\s+birth|birth\s*date|born(?:\s+on)?)"
            r"[^\w\n]{0,6})(" + _DATE + ")"
        ),
    ),
    (
        "PERSON",
        re.compile(
            r"((?i:\b(?:patient(?:\s+name)?|pt|name|dear|mr|mrs|ms|miss)\b)\.?[ \t]*[:,-]?[ \t]*"
            r"(?:(?i:dr|mr|mrs|ms)\.?[ \t]+)?)"
            r"([A-Z][a-z'-]+(?:,?[ \t]+[A-Z](?:[a-z'-]+|\.))*)"
        ),
    ),
    (
        "ADDRESS",
        re.compile(
            r"()(\b\d{1,6}[ \t]+(?:[A-Z0-9][\w.'-]*[ \t]+){1,4}"
            r"(?:St|Street|Ave|Avenue|Rd|Road|Blvd|Boulevard|Dr|Drive|Ln|Lane|Ct|Court"
            r"|Way|Pl|Place|Pkwy|Parkway|Cir|Circle|Ter|Terrace|Hwy|Highway)\b\.?"
            r"(?:,?[ \t]*(?:Apt|Unit|Suite|Ste|#)\.?[ \t]*\w+)?)"
        ),
    ),
    ("ZIP_CODE", re.compile(r"(\b[A-Z]{2}[ \t]+)(\d{5}(?:-\d{4})?)\b")),
]


@dataclass
class EmlReport:
    identifiers: Counter = field(default_factory=Counter)  # deterministic: unambiguous
    names: Counter = field(default_factory=Counter)  # NER: advisory
    dropped_parts: list[str] = field(default_factory=list)  # "application/pdf, 48211 bytes"
    dropped_headers: Counter = field(default_factory=Counter)
    ner_ran: bool = False


class _Text(html.parser.HTMLParser):
    _BLOCK = {"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "table", "blockquote"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "head"):
            self._skip += 1
        elif tag in self._BLOCK:
            self.out.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style", "head"):
            self._skip = max(0, self._skip - 1)
        elif tag in self._BLOCK:
            self.out.append("\n")

    def handle_data(self, data):
        if not self._skip:
            self.out.append(data)


def html_to_text(markup: str) -> str:
    """Flatten HTML so `123-<b>45</b>-6789` reads as one token. Links/attrs go too."""
    p = _Text()
    p.feed(markup)
    p.close()
    return re.sub(r"\n[ \t]*\n(?:[ \t]*\n)+", "\n\n", "".join(p.out)).strip() + "\n"


def _scrub_text(text: str, rep: EmlReport) -> str:
    for label, pattern in _EMAIL_EXTRA:
        text, n = pattern.subn(lambda m, lb=label: m.group(1) + REDACT.format(lb), text)
        rep.identifiers[label] += n
    text, det, ner = scrub.scrub_text(text, run_ner=rep.ner_ran)
    rep.identifiers.update(det)
    rep.names.update(ner)
    return text


def _part_text(part) -> str:
    try:
        return part.get_content()
    except (LookupError, UnicodeError, AssertionError):  # unknown/lying charset
        return (part.get_payload(decode=True) or b"").decode("utf-8", "replace")


def _clean_leaf(part, rep: EmlReport) -> None:
    ctype = part.get_content_type()
    if part.get_content_maintype() == "text":
        text = _part_text(part)
        subtype = part.get_content_subtype()
        if subtype == "html":
            text, subtype = html_to_text(text), "plain"
        part.set_content(_scrub_text(text, rep), subtype=subtype)
        return
    size = len(part.get_payload(decode=True) or b"")
    rep.dropped_parts.append(f"{ctype}, {size} bytes")
    part.set_content(
        f"[phi-airgap: {ctype} part removed ({size} bytes) - not scrubbable]\n"
    )


def _clean_headers(msg, rep: EmlReport, root: bool) -> None:
    for name in dict.fromkeys(msg.keys()):  # unique, order kept
        low = name.lower()
        if low.startswith("content-") or (root and low == "mime-version"):
            continue
        if low == "mime-version":  # set_content() stamps it on subparts too
            del msg[name]
            continue
        values = msg.get_all(name)
        del msg[name]
        if not root or low not in _KEEP_HEADERS:
            rep.dropped_headers[low] += len(values)
            continue
        for v in values:
            if low in _ADDRESS_HEADERS:
                addrs = getattr(v, "addresses", ()) or ()
                rep.identifiers["EMAIL_ADDRESS"] += max(len(addrs), 1)
                msg[name] = ", ".join(
                    str(Address("REDACTED", "redacted", a.domain or "redacted.invalid"))
                    for a in addrs
                ) or "redacted@redacted.invalid"
            elif low == "subject":
                msg[name] = _scrub_text(str(v), rep).strip()
            else:
                msg[name] = str(v)


def _clean(msg, rep: EmlReport, root: bool) -> None:
    if msg.is_multipart():
        msg.preamble = msg.epilogue = None  # free text outside any part
        inner_root = msg.get_content_type() == "message/rfc822"
        for sub in msg.get_payload():
            _clean(sub, rep, root=inner_root)
    else:
        _clean_leaf(msg, rep)
    _clean_headers(msg, rep, root)


def _ner_available() -> bool:
    try:
        scrub._get_analyzer()
        return True
    except Exception:
        return False


def scrub_eml(raw: bytes, run_ner: bool = True) -> tuple[bytes, EmlReport]:
    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)
    rep = EmlReport(ner_ran=run_ner and _ner_available())
    _clean(msg, rep, root=True)
    return msg.as_bytes(), rep


def text_of(raw: bytes) -> str:
    """Decoded headers + text parts, for line scanning (`pq git scan`). No rewriting."""
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    lines = []
    for part in msg.walk():
        lines += [f"{k}: {v}" for k, v in part.items()]
        if part.get_content_maintype() == "text" and not part.is_multipart():
            text = _part_text(part)
            lines.append(html_to_text(text) if part.get_content_subtype() == "html" else text)
    return "\n".join(lines)
