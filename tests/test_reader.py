"""Tests for the streaming CloudTrail record reader."""

import gzip
import json
from pathlib import Path

import pytest

from ctinv.reader import RecordFormatError, iter_records

ACCOUNT_ID = "111122223333"


def make_event(n: int) -> dict:
    return {
        "eventVersion": "1.08",
        "eventID": f"00000000-0000-0000-0000-{n:012d}",
        "eventTime": "2023-01-01T00:00:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "ListUsers",
        "recipientAccountId": ACCOUNT_ID,
        "userIdentity": {"type": "IAMUser", "arn": f"arn:aws:iam::{ACCOUNT_ID}:user/alice"},
        "requestParameters": {"note": 'brackets ] and braces } inside strings, "quotes" too'},
    }


EVENTS = [make_event(n) for n in range(5)]


def write(path: Path, text: str) -> Path:
    if path.suffix == ".gz":
        with gzip.open(path, "wt", encoding="utf-8") as fh:
            fh.write(text)
    else:
        path.write_text(text, encoding="utf-8")
    return path


def envelope(events: list[dict], indent: int | None = None) -> str:
    return json.dumps({"Records": events}, indent=indent)


def ndjson(events: list[dict]) -> str:
    return "".join(json.dumps(e) + "\n" for e in events)


@pytest.mark.parametrize("name", ["log.json", "log.json.gz"])
@pytest.mark.parametrize("render", [envelope, ndjson], ids=["envelope", "ndjson"])
def test_reads_all_records_in_order(tmp_path: Path, name: str, render) -> None:
    path = write(tmp_path / name, render(EVENTS))
    assert list(iter_records(path)) == EVENTS


@pytest.mark.parametrize("render", [envelope, ndjson], ids=["envelope", "ndjson"])
@pytest.mark.parametrize("chunk_chars", [1, 7, 64])
def test_records_spanning_chunk_boundaries(tmp_path: Path, render, chunk_chars: int) -> None:
    path = write(tmp_path / "log.json", render(EVENTS))
    assert list(iter_records(path, chunk_chars=chunk_chars)) == EVENTS


def test_pretty_printed_envelope(tmp_path: Path) -> None:
    path = write(tmp_path / "log.json", envelope(EVENTS, indent=2))
    assert list(iter_records(path, chunk_chars=5)) == EVENTS


def test_single_event_file(tmp_path: Path) -> None:
    path = write(tmp_path / "log.json", json.dumps(EVENTS[0], indent=2))
    assert list(iter_records(path)) == [EVENTS[0]]


@pytest.mark.parametrize("text", ['{"Records": []}', "", "  \n"])
def test_empty_inputs_yield_nothing(tmp_path: Path, text: str) -> None:
    assert list(iter_records(write(tmp_path / "log.json", text))) == []


def test_utf8_bom_is_ignored(tmp_path: Path) -> None:
    path = tmp_path / "log.json"
    path.write_bytes(b"\xef\xbb\xbf" + envelope(EVENTS).encode())
    assert list(iter_records(path)) == EVENTS


def test_truncated_envelope_raises(tmp_path: Path) -> None:
    text = envelope(EVENTS)
    path = write(tmp_path / "log.json", text[: len(text) // 2])
    with pytest.raises(RecordFormatError):
        list(iter_records(path))


def test_missing_comma_between_records_raises(tmp_path: Path) -> None:
    text = '{"Records": [' + json.dumps(EVENTS[0]) + json.dumps(EVENTS[1]) + "]}"
    with pytest.raises(RecordFormatError, match="expected ','"):
        list(iter_records(write(tmp_path / "log.json", text)))


def test_invalid_ndjson_line_raises_after_valid_records(tmp_path: Path) -> None:
    path = write(tmp_path / "log.json", ndjson(EVENTS[:2]) + "{not json}\n")
    records = iter_records(path)
    assert next(records) == EVENTS[0]
    assert next(records) == EVENTS[1]
    with pytest.raises(RecordFormatError, match="invalid JSON"):
        next(records)


def test_oversized_record_is_bounded(tmp_path: Path) -> None:
    # An unterminated string would otherwise make the reader buffer the whole file.
    path = write(tmp_path / "log.json", '{"Records": [{"eventID": "' + "x" * 10_000)
    with pytest.raises(RecordFormatError, match="exceeds"):
        list(iter_records(path, chunk_chars=256, max_record_chars=1_000))
