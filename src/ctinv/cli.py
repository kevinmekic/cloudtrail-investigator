"""Command-line interface for ctinv."""

import argparse
import sys
from collections.abc import Sequence

from ctinv import __version__

# Subcommand name -> one-line help text. All are placeholders until their milestone lands.
COMMANDS: dict[str, str] = {
    "ingest": "Load CloudTrail JSON / .json.gz files into a local DuckDB database.",
    "detect": "Run detection rules and store findings with their evidence eventIDs.",
    "investigate": "Pivot from an access key or principal: timeline, sessions, blast radius.",
    "report": "Render findings or an investigation as Markdown and HTML reports.",
    "evaluate": "Measure detection rate per attack technique against labelled data.",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctinv",
        description="CloudTrail Investigator: offline forensic analysis of AWS CloudTrail logs.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="<command>", required=True)
    for name, help_text in COMMANDS.items():
        sub = subparsers.add_parser(name, help=help_text, description=help_text)
        sub.set_defaults(handler=_not_implemented)
    return parser


def _not_implemented(args: argparse.Namespace) -> int:
    # Non-zero exit so scripts never mistake a placeholder for a successful run.
    print(f"{args.command}: not implemented yet", file=sys.stderr)
    return 1


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.handler(args)
