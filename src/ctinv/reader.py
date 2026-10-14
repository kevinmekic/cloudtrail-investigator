"""Streaming reader for CloudTrail log files.

Three layouts are supported, plain or gzip-compressed (``.gz``):

* the CloudTrail delivery format, a single object ``{"Records": [ ... ]}``
* newline-delimited JSON (one event per line), as exported by many tools
* a single JSON event

Records are decoded one at a time from a sliding text buffer, so memory use is
bounded by the largest single record instead of the file size.
"""

import gzip
import io
import json
import re
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

CHUNK_CHARS = 1 << 20
# A single CloudTrail event is far smaller than this; hitting the limit means the
# file is malformed or not CloudTrail, and we stop instead of buffering it all.
MAX_RECORD_CHARS = 32 << 20

# Text kept from an invalid stretch of input, for the quarantine.
MALFORMED_TEXT_CHARS = 10_000

_ENVELOPE = re.compile(r'\s*\{\s*"Records"\s*:\s*\[')
_WHITESPACE = re.compile(r"\s*")


class RecordFormatError(ValueError):
    """Raised when a file cannot be read as a sequence of CloudTrail records."""


@dataclass(frozen=True)
class MalformedRecord:
    """Input that is not valid JSON, skipped in recover mode (see ``iter_records``)."""

    reason: str
    text: str


class _InvalidJSON(Exception):
    def __init__(self, msg: str) -> None:
        super().__init__(msg)
        self.msg = msg


class _GzipSource(io.RawIOBase):
    """Decompressed bytes of a gzip file that end, instead of failing, where it is damaged.

    gzip raises only after it has returned every byte it could decompress, but a
    text reader on top would discard the text it had already decoded in that
    read. Here the error ends the byte stream and is kept, so the caller can read
    every intact record first and report the damage afterwards.
    """

    def __init__(self, path: Path) -> None:
        self._gz = gzip.GzipFile(path, "rb")
        self.error: Exception | None = None

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        if self.error is not None:
            return 0
        try:
            data = self._gz.read1(len(buffer))
        except (EOFError, zlib.error, gzip.BadGzipFile) as exc:
            self.error = exc
            return 0
        buffer[: len(data)] = data
        return len(data)

    def close(self) -> None:
        self._gz.close()
        super().close()


def iter_records(
    path: str | Path,
    *,
    recover: bool = False,
    chunk_chars: int = CHUNK_CHARS,
    max_record_chars: int = MAX_RECORD_CHARS,
) -> Iterator[Any]:
    """Yield every decoded record of a CloudTrail file, in file order.

    Records are yielded as decoded JSON values without validation; deciding what
    a valid event is belongs to the caller.

    With ``recover=True``, newline-delimited input continues after invalid JSON:
    the invalid stretch, up to the next line that starts with ``{``, is yielded
    as a ``MalformedRecord``. A broken ``Records`` envelope cannot be
    resynchronised safely and still raises.

    Raises:
        RecordFormatError: the file is truncated, malformed, or a single record
            exceeds ``max_record_chars``.
    """
    path = Path(path)
    source = _GzipSource(path) if path.suffix == ".gz" else None
    if source is not None:
        fh: IO[str] = io.TextIOWrapper(io.BufferedReader(source, 1 << 16), encoding="utf-8-sig")
    else:
        fh = path.open("r", encoding="utf-8-sig")
    with fh:
        try:
            yield from _Parser(fh, path, recover, chunk_chars, max_record_chars).records()
        except RecordFormatError:
            if source is None or source.error is None:
                raise
        if source is not None and source.error is not None:
            # Reported after all intact records; it explains any truncated record before it.
            raise RecordFormatError(
                f"{path}: compressed data is damaged or ends early ({source.error})"
            ) from source.error


class _Parser:
    def __init__(
        self, fh: IO[str], path: Path, recover: bool, chunk_chars: int, max_record_chars: int
    ) -> None:
        self._fh = fh
        self._path = path
        self._recover = recover
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
            try:
                yield self._decode_one()
            except _InvalidJSON as exc:
                raise self._error(f"invalid JSON: {exc.msg}") from None
            expect_comma = True

    def _stream_records(self) -> Iterator[Any]:
        while self._next_char() is not None:
            try:
                yield self._decode_one()
            except _InvalidJSON as exc:
                if not self._recover:
                    raise self._error(f"invalid JSON: {exc.msg}") from None
                yield self._skip_malformed(exc.msg)

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
                if self._eof or not self._may_be_cut_off(exc):
                    raise _InvalidJSON(exc.msg) from exc
            else:
                # A value ending exactly at the buffer edge may be a truncated number
                # or literal; only accept it once more input proves it complete.
                if end < len(self._buf) or self._eof:
                    self._pos = end
                    return value
            if len(self._buf) - self._pos > self._max_record_chars:
                raise self._error(f"record exceeds {self._max_record_chars} characters")
            self._fill()

    def _may_be_cut_off(self, exc: json.JSONDecodeError) -> bool:
        """True if the error could come from the buffer ending, not from the data.

        Only an unterminated string or a literal or escape cut short at the very
        end of the buffer qualifies. JSON strings cannot contain raw newlines, so
        a genuinely unterminated string fails earlier, at its line end.
        """
        return exc.msg.startswith("Unterminated string") or exc.pos >= len(self._buf) - 8

    def _skip_malformed(self, reason: str) -> MalformedRecord:
        """Skip to the next line that starts with ``{`` and return what was skipped."""
        offset = 1
        while True:
            found = self._buf.find("\n{", self._pos + offset)
            if found != -1:
                end = found + 1
                break
            if self._eof:
                end = len(self._buf)
                break
            if len(self._buf) - self._pos > self._max_record_chars:
                raise self._error(f"invalid input exceeds {self._max_record_chars} characters")
            offset = max(1, len(self._buf) - self._pos - 1)
            self._fill()
        text = self._buf[self._pos : end].strip()
        self._pos = end
        return MalformedRecord(reason=f"invalid JSON: {reason}", text=text[:MALFORMED_TEXT_CHARS])

    def _fill(self) -> None:
        chunk = self._fh.read(self._chunk_chars)
        if not chunk:
            self._eof = True
            return
        self._buf = self._buf[self._pos :] + chunk
        self._pos = 0

    def _error(self, message: str) -> RecordFormatError:
        return RecordFormatError(f"{self._path}: {message}")
