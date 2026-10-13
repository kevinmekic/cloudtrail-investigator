"""Streaming reader for CloudTrail log files.

Two layouts are supported, plain or gzip-compressed (``.gz``):

* the CloudTrail delivery format, a single object ``{"Records": [ ... ]}``
* newline-delimited JSON (one event per line), as exported by many tools

Records are decoded one at a time from a sliding text buffer, so memory use is
bounded by the largest single record instead of the file size.
"""

import gzip
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import IO, Any

CHUNK_CHARS = 1 << 20
# A single CloudTrail event is far smaller than this; hitting the limit means the
# file is malformed or not CloudTrail, and we stop instead of buffering it all.
MAX_RECORD_CHARS = 32 << 20

_ENVELOPE = re.compile(r'\s*\{\s*"Records"\s*:\s*\[')
_WHITESPACE = re.compile(r"\s*")


class RecordFormatError(ValueError):
    """Raised when a file cannot be read as a sequence of CloudTrail records."""


def open_text(path: Path) -> IO[str]:
    """Open a plain or gzip-compressed file as UTF-8 text (a leading BOM is ignored)."""
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8-sig")
    return path.open("r", encoding="utf-8-sig")


def iter_records(
    path: str | Path,
    *,
    chunk_chars: int = CHUNK_CHARS,
    max_record_chars: int = MAX_RECORD_CHARS,
) -> Iterator[Any]:
    """Yield every decoded record of a CloudTrail file, in file order.

    Records are yielded as decoded JSON values without validation; deciding what
    a valid event is belongs to the caller.

    Raises:
        RecordFormatError: the file is truncated, malformed, or a single record
            exceeds ``max_record_chars``.
    """
    path = Path(path)
    with open_text(path) as fh:
        yield from _Parser(fh, path, chunk_chars, max_record_chars).records()


class _Parser:
    def __init__(self, fh: IO[str], path: Path, chunk_chars: int, max_record_chars: int) -> None:
        self._fh = fh
        self._path = path
        self._chunk_chars = chunk_chars
        self._max_record_chars = max_record_chars
        self._decoder = json.JSONDecoder()
        self._buf = ""
        self._pos = 0
        self._eof = False

    def records(self) -> Iterator[Any]:
        # Fill until the envelope prefix can be recognised, or the file is exhausted.
        while not self._eof and len(self._buf) < 64:
            self._fill()
        match = _ENVELOPE.match(self._buf)
        if match:
            self._pos = match.end()
            yield from self._envelope_records()
        else:
            yield from self._stream_records()

    def _envelope_records(self) -> Iterator[Any]:
        expect_comma = False
        while True:
            char = self._next_char()
            if char is None:
                raise self._error("unexpected end of file inside the Records array")
            if char == "]":
                return
            if expect_comma:
                if char != ",":
                    raise self._error(f"expected ',' or ']' between records, found {char!r}")
                self._pos += 1
                expect_comma = False
                continue
            yield self._decode_one()
            expect_comma = True

    def _stream_records(self) -> Iterator[Any]:
        while self._next_char() is not None:
            yield self._decode_one()

    def _next_char(self) -> str | None:
        """Skip whitespace and return the next character without consuming it."""
        while True:
            self._pos = _WHITESPACE.match(self._buf, self._pos).end()
            if self._pos < len(self._buf):
                return self._buf[self._pos]
            if self._eof:
                return None
            self._fill()

    def _decode_one(self) -> Any:
        while True:
            try:
                value, end = self._decoder.raw_decode(self._buf, self._pos)
            except json.JSONDecodeError as exc:
                if self._eof:
                    raise self._error(f"invalid JSON: {exc.msg}") from exc
            else:
                # A value ending exactly at the buffer edge may be a truncated number
                # or literal; only accept it once more input proves it complete.
                if end < len(self._buf) or self._eof:
                    self._pos = end
                    return value
            if len(self._buf) - self._pos > self._max_record_chars:
                raise self._error(f"record exceeds {self._max_record_chars} characters")
            self._fill()

    def _fill(self) -> None:
        chunk = self._fh.read(self._chunk_chars)
        if not chunk:
            self._eof = True
            return
        self._buf = self._buf[self._pos :] + chunk
        self._pos = 0

    def _error(self, message: str) -> RecordFormatError:
        return RecordFormatError(f"{self._path}: {message}")
