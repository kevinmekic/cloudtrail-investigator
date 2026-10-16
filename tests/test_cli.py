"""Smoke tests for the ctinv command-line interface."""

import pytest

from ctinv.cli import main

EXPECTED_COMMANDS = ("ingest", "detect", "investigate", "report", "evaluate")


def test_help_lists_all_subcommands(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for command in EXPECTED_COMMANDS:
        assert command in out


@pytest.mark.parametrize("command", ["report", "evaluate"])
def test_placeholder_subcommands(command: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert main([command]) == 1
    assert capsys.readouterr().err.strip() == f"{command}: not implemented yet"
