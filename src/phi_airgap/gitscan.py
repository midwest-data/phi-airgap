"""PHI screen for git: staged files, pushed commits, commit messages.

Reuses the scrubber's deterministic layer per line (the floor: SSN, phone,
email, MRN, token shapes) and its NER pass as an advisory. Reports labels and
line numbers only — never the matched value, since the report itself lands in
a terminal and possibly a transcript.

Office documents (.docx/.xlsx/.pptx) are unzipped with the stdlib and their XML
text scanned; .pdf needs the optional `pypdf` extra. Anything that cannot be
read (legacy .doc/.xls, a PDF without pypdf, an oversize blob) is reported as
unscannable and blocks by default: a document the screen cannot read is exactly
the kind of attachment that carries an extract.
"""

from __future__ import annotations

import logging
import re
import subprocess
import zipfile
from dataclasses import dataclass, field
from fnmatch import fnmatch
from io import BytesIO
from pathlib import Path

from . import scrub

DOC_EXTS = {".docx", ".xlsx", ".pptx", ".pdf", ".doc", ".xls", ".ppt"}
ALLOW_LINE = "phi-airgap: allow"  # on a line: that line is a reviewed false positive
ALLOW_FILE = "phi-airgap: allow-file"  # in the first 20 lines: the whole file is
IGNORE_FILE = ".phi-airgap-ignore"
MAX_BYTES = 20_000_000
_ZERO_SHA = "0" * 40
_TAG = re.compile(r"<[^>]+>")


@dataclass
class FileResult:
    path: str
    hits: list[tuple[int, list[str]]] = field(default_factory=list)  # (line_no, kinds)
    ner: list[str] = field(default_factory=list)  # advisory labels, deduped
    unscannable: str | None = None

    @property
    def blocked(self) -> bool:
        return bool(self.hits)


# --- text extraction ---------------------------------------------------------


def _zip_text(data: bytes, members: re.Pattern) -> str:
    with zipfile.ZipFile(BytesIO(data)) as z:
        parts = [z.read(n).decode("utf-8", "replace") for n in z.namelist() if members.match(n)]
    # One cell/paragraph per line so the report's line numbers mean something.
    xml = "\n".join(parts)
    xml = re.sub(r"</(?:w:p|a:p|si|row|t)>", "\n", xml)
    return "\n".join(ln.strip() for ln in _TAG.sub(" ", xml).splitlines() if ln.strip())


_OFFICE = {
    ".docx": re.compile(r"word/(?:document|header\d*|footer\d*|footnotes|comments)\.xml$"),
    ".xlsx": re.compile(r"xl/(?:sharedStrings\.xml|worksheets/sheet\d+\.xml)$"),
    ".pptx": re.compile(r"ppt/(?:slides|notesSlides)/[^/]+\.xml$"),
}


class Unscannable(Exception):
    """No text could be extracted; the message says why."""


def extract_text(name: str, data: bytes) -> str:
    """Text to scan ("" for a plain binary, which is skipped). Raises Unscannable."""
    ext = Path(name).suffix.lower()
    if ext in _OFFICE:
        try:
            return _zip_text(data, _OFFICE[ext])
        except (zipfile.BadZipFile, KeyError, UnicodeDecodeError) as e:
            raise Unscannable(f"{ext}: not a readable office document ({e})") from e
    if ext == ".pdf":
        try:
            import pypdf
        except ImportError as e:
            raise Unscannable("pdf: pypdf not installed (pip install 'phi-airgap[pdf]')") from e
        logging.getLogger("pypdf").setLevel(logging.ERROR)  # its warnings are not ours to print
        try:
            return "\n".join(
                (p.extract_text() or "") for p in pypdf.PdfReader(BytesIO(data)).pages
            )
        except Exception as e:
            raise Unscannable(f"pdf: unreadable ({type(e).__name__})") from e
    if ext in DOC_EXTS:
        raise Unscannable(f"{ext}: legacy binary format; save as {ext}x")
    if b"\0" in data[:8192]:
        return ""
    return data.decode("utf-8", "replace")


# --- scanning ----------------------------------------------------------------


def scan_text(path: str, text: str, *, run_ner: bool) -> FileResult:
    res = FileResult(path)
    lines = text.splitlines()
    if any(ALLOW_FILE in ln for ln in lines[:20]):
        return res
    ner: set[str] = set()
    for no, line in enumerate(lines, 1):
        if ALLOW_LINE in line:
            continue
        _, kinds = scrub.deterministic(line)
        if kinds:
            res.hits.append((no, sorted(set(kinds))))
        if run_ner and len(line.strip()) >= 3:
            try:
                ner.update(x.entity_type for x in scrub._hits(line))
            except Exception:
                run_ner = False  # a broken spaCy degrades to regex-only, as scrub_text does
    res.ner = sorted(ner)
    return res


def scan_blob(path: str, data: bytes, *, run_ner: bool) -> FileResult:
    if len(data) > MAX_BYTES:
        return FileResult(path, unscannable=f"{len(data) // 1_000_000} MB exceeds the 20 MB cap")
    try:
        text = extract_text(path, data)
    except Unscannable as e:
        return FileResult(path, unscannable=str(e))
    return scan_text(path, text, run_ner=run_ner)


def load_ignore(root: Path) -> list[str]:
    p = root / IGNORE_FILE
    if not p.exists():
        return []
    return [ln.strip() for ln in p.read_text().splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")]


def ignored(path: str, globs: list[str]) -> bool:
    name = Path(path).name
    return any(fnmatch(path, g) or fnmatch(name, g) for g in globs)


# --- git plumbing ------------------------------------------------------------


def _git(*args: str, data: bytes | None = None) -> bytes:
    r = subprocess.run(["git", *args], input=data, capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.decode(errors="replace").strip() or f"git {args[0]} failed")
    return r.stdout


def repo_root() -> Path:
    return Path(_git("rev-parse", "--show-toplevel").decode().strip())


def hooks_dir() -> Path:
    return Path(_git("rev-parse", "--git-path", "hooks").decode().strip()).resolve()


def _z(out: bytes) -> list[str]:
    return [p.decode("utf-8", "replace") for p in out.split(b"\0") if p]


def staged_files() -> list[str]:
    return _z(_git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"))


def staged_blob(path: str) -> bytes:
    return _git("show", f":{path}")


def all_files() -> list[str]:
    return _z(_git("ls-files", "-z"))


def commit_blob(rev: str, path: str) -> bytes:
    return _git("show", f"{rev}:{path}")


def range_files(revs: list[str]) -> list[str]:
    """Paths added or modified by any commit selected by `revs` (rev-list syntax)."""
    shas = _git("rev-list", *revs).decode().split()
    seen: dict[str, None] = {}
    for sha in shas:
        for p in _z(_git("diff-tree", "--no-commit-id", "--root", "-r", "--name-only",
                         "--diff-filter=ACMR", "-z", sha)):
            seen.setdefault(p, None)
    return list(seen)


def range_messages(revs: list[str]) -> str:
    return _git("log", "--format=%B", *revs).decode("utf-8", "replace")


def push_ranges(stdin: str) -> list[tuple[list[str], str]]:
    """pre-push stdin -> [(rev-list selector, tip sha)].

    Each line is `local_ref local_sha remote_ref remote_sha`. A zero remote sha
    is a new branch: everything not already on some remote is outbound.
    """
    out = []
    for line in stdin.splitlines():
        parts = line.split()
        if len(parts) != 4 or parts[1] == _ZERO_SHA:  # malformed, or a delete
            continue
        _, local, _, remote = parts
        revs = [local, "--not", "--remotes"] if remote == _ZERO_SHA else [f"{remote}..{local}"]
        out.append((revs, local))
    return out
