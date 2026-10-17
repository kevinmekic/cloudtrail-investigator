"""Smoke tests for the ctinv command-line interface."""

import json
from pathlib import Path

import pytest

from cloudtrail_events import iam_user
from ctinv.cli import COMMANDS, HANDLERS, main

EXPECTED_COMMANDS = ("ingest", "detect", "investigate", "report", "evaluate")


def test_help_lists_all_subcommands(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for command in EXPECTED_COMMANDS:
        assert command in out


def test_every_subcommand_is_implemented() -> None:
    assert set(HANDLERS) == set(COMMANDS) == set(EXPECTED_COMMANDS)


def test_messages_are_not_broken_at_the_console_width(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Without a terminal (pipes, log files, CI) the console width is 80 columns, so where a
    # message would break depended on the length of the paths in it.
    monkeypatch.setenv("COLUMNS", "20")
    db = tmp_path / "none.duckdb"
    assert main(["investigate", "--db", str(db), "--access-key", "AKIAEXAMPLEALICE0001"]) == 2
    assert capsys.readouterr().err == f"error: database {db} not found; run ctinv ingest first\n"
    log = tmp_path / "events.json"
    log.write_text(json.dumps({"Records": [iam_user(1)]}))
    db = tmp_path / "x.duckdb"
    assert main(["ingest", str(log), "--db", str(db), "--dataset", "test"]) == 0
    out = capsys.readouterr().out
    assert out.startswith(f"{log}: read 1, inserted 1, duplicates 0, quarantined 0\n")
