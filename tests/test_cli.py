"""Smoke tests for the ctinv command-line interface."""

import pytest

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
