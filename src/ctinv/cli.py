"""Command-line interface for ctinv."""

import argparse
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from ctinv import __version__

# Subcommand name -> one-line help text. Commands without a handler below are
# placeholders until they are implemented.
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
        configure, handler = HANDLERS.get(name, (None, _not_implemented))
        if configure:
            configure(sub)
        sub.set_defaults(handler=handler)
    return parser


def _configure_ingest(sub: argparse.ArgumentParser) -> None:
    sub.add_argument("paths", nargs="+", type=Path, metavar="PATH", help="files or directories")
    sub.add_argument(
        "--db", type=Path, default=Path("ctinv.duckdb"), help="DuckDB file (default: ctinv.duckdb)"
    )
    sub.add_argument(
        "--dataset",
        help="dataset name for all files (default: look each file up in DATA_DIR/MANIFEST.json)",
    )
    sub.add_argument(
        "--data-dir",
        type=Path,
        default=Path("data"),
        help="data directory; source_file is stored relative to it (default: ./data)",
    )
    sub.add_argument(
        "--memory-limit",
        default="1GB",
        help="DuckDB memory limit; it spills to disk beyond it (default: 1GB)",
    )
    sub.add_argument("--batch-size", type=int, default=50_000, help=argparse.SUPPRESS)


def _run_ingest(args: argparse.Namespace) -> int:
    # Imported here so that `ctinv --help` stays fast and works without DuckDB.
    from rich.console import Console
    from rich.table import Table

    from ctinv.ingest import DatasetResolutionError, FileResult, ingest, plan_files

    err = Console(stderr=True)
    try:
        plans = plan_files(args.paths, args.data_dir, args.dataset)
    except (DatasetResolutionError, FileNotFoundError) as exc:
        err.print(f"[red]error:[/red] {exc}", highlight=False)
        return 2

    out = Console()

    def show(result: FileResult) -> None:
        line = (
            f"{result.source_file}: read {result.records_read:,}, inserted {result.inserted:,}, "
            f"duplicates {result.duplicates:,}, quarantined {result.quarantined:,}"
        )
        out.print(
            line + (f" [red]FILE ERROR: {result.file_error}[/red]" if result.file_error else ""),
            highlight=False,
        )

    stats = ingest(
        args.db, plans, batch_size=args.batch_size, memory_limit=args.memory_limit, on_file=show
    )
    table = Table(title=f"Ingest into {args.db}", title_justify="left")
    for column in (
        "files",
        "read",
        "inserted",
        "duplicates",
        "quarantined",
        "file errors",
        "elapsed",
    ):
        table.add_column(column, justify="right")
    table.add_row(
        f"{len(stats.files):,}",
        f"{stats.total('records_read'):,}",
        f"{stats.total('inserted'):,}",
        f"{stats.total('duplicates'):,}",
        f"{stats.total('quarantined'):,}",
        f"{stats.file_errors:,}",
        f"{stats.elapsed_seconds:.1f} s",
    )
    out.print(table)
    return 1 if stats.file_errors else 0


def _not_implemented(args: argparse.Namespace) -> int:
    # Non-zero exit so scripts never mistake a placeholder for a successful run.
    print(f"{args.command}: not implemented yet", file=sys.stderr)
    return 1


def _configure_detect(sub: argparse.ArgumentParser) -> None:
    sub.add_argument(
        "--db", type=Path, default=Path("ctinv.duckdb"), help="DuckDB file (default: ctinv.duckdb)"
    )
    sub.add_argument(
        "--rule", action="append", metavar="ID", help="run only this rule (repeatable)"
    )
    sub.add_argument(
        "--rules-dir", type=Path, help="directory with rule files (default: the built-in rules)"
    )


def _run_detect(args: argparse.Namespace) -> int:
    from rich.console import Console
    from rich.table import Table

    from ctinv.detect import RuleError, load_rules, run_rules
    from ctinv.schema import connect

    err = Console(stderr=True)
    if not args.db.exists():
        err.print(f"[red]error:[/red] database {args.db} not found; run ctinv ingest first")
        return 2
    try:
        rules = load_rules(args.rules_dir)
    except RuleError as exc:
        err.print(f"[red]error:[/red] {exc}", highlight=False)
        return 2
    if args.rule:
        unknown = sorted(set(args.rule) - {r.id for r in rules})
        if unknown:
            err.print(f"[red]error:[/red] unknown rule(s): {', '.join(unknown)}")
            return 2
        rules = [r for r in rules if r.id in set(args.rule)]

    con = connect(args.db)
    try:
        results = run_rules(con, rules)
    except RuleError as exc:
        err.print(f"[red]error:[/red] {exc}", highlight=False)
        return 1
    finally:
        con.close()

    table = Table(title=f"Detection results in {args.db}", title_justify="left")
    for column in ("rule", "severity", "ATT&CK", "findings", "outcome", "evidence events"):
        table.add_column(
            column, justify="right" if column in ("findings", "evidence events") else "left"
        )
    for result in results:
        outcome = ", ".join(f"{n} {name}" for name, n in result.outcomes.items()) or "-"
        table.add_row(
            result.rule.id,
            result.rule.severity,
            result.rule.technique_label,
            f"{result.findings:,}",
            outcome,
            f"{result.evidence_events:,}",
        )
    Console().print(table)
    return 0


Handler = Callable[[argparse.Namespace], int]
HANDLERS: dict[str, tuple[Callable[[argparse.ArgumentParser], None] | None, Handler]] = {
    "ingest": (_configure_ingest, _run_ingest),
    "detect": (_configure_detect, _run_detect),
}


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.handler(args)
