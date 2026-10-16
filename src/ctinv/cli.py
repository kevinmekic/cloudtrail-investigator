"""Command-line interface for ctinv."""

import argparse
import json
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
    sub.add_argument(
        "--set",
        action="append",
        default=[],
        metavar="RULE.PARAM=VALUE",
        help="change a rule parameter for this run, e.g. discovery-burst.min_apis=30 "
        "(repeatable; recorded in the rule_runs table)",
    )


def _run_detect(args: argparse.Namespace) -> int:
    from rich.console import Console
    from rich.table import Table

    from ctinv.detect import RuleError, apply_overrides, load_rules, run_rules
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
    rule_defaults = {r.id: r.parameters for r in rules}
    try:
        rules = apply_overrides(rules, args.set)
    except RuleError as exc:
        err.print(f"[red]error:[/red] {exc}", highlight=False)
        return 2

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
    out = Console()
    out.print(table)
    for rule in rules:
        for name, value in rule.overrides.items():
            out.print(
                f"{rule.id}: {name} = {json.dumps(value)} "
                f"(default {json.dumps(rule_defaults[rule.id][name])})",
                highlight=False,
            )
    return 0


def _time_argument(text: str):
    from ctinv.investigate import parse_time

    try:
        return parse_time(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _count_argument(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a whole number") from None
    if value < 0:
        raise argparse.ArgumentTypeError(f"{value} is negative")
    return value


def _configure_investigate(sub: argparse.ArgumentParser) -> None:
    sub.add_argument(
        "--db", type=Path, default=Path("ctinv.duckdb"), help="DuckDB file (default: ctinv.duckdb)"
    )
    start = sub.add_mutually_exclusive_group(required=True)
    start.add_argument("--access-key", metavar="ID", help="start from this access key ID")
    start.add_argument(
        "--principal",
        metavar="ARN",
        help="start from this principal (userIdentity.arn); a role ARN stands for every "
        "session of the role",
    )
    sub.add_argument(
        "--from",
        dest="start",
        type=_time_argument,
        metavar="TIME",
        help="only events at or after TIME: ISO 8601 date or date and time, e.g. 2019-08-21 "
        "or 2019-08-21T07:41:00Z (without an offset: UTC)",
    )
    sub.add_argument(
        "--to", dest="end", type=_time_argument, metavar="TIME", help="only events before TIME"
    )
    sub.add_argument(
        "--max-depth",
        type=_count_argument,
        default=3,
        metavar="N",
        help="follow obtained credentials at most N pivots deep (default: 3; 0: no pivots)",
    )
    sub.add_argument(
        "--max-sessions",
        type=_count_argument,
        default=1000,
        metavar="N",
        help="follow at most N sessions besides the start (default: 1000)",
    )
    sub.add_argument(
        "--max-events",
        type=_count_argument,
        default=100_000,
        metavar="N",
        help="list at most N events in the JSON timeline; counts stay complete (default: 100000)",
    )
    sub.add_argument(
        "--follow-created-keys",
        action="store_true",
        help="also follow long-term keys created with iam:CreateAccessKey (often handed "
        "to someone else, so off by default)",
    )
    sub.add_argument(
        "--output", "-o", type=Path, metavar="FILE", help="write the investigation as JSON to FILE"
    )


def _run_investigate(args: argparse.Namespace) -> int:
    from rich.console import Console

    from ctinv.investigate import InvestigationError, Scope, investigate, write_json
    from ctinv.schema import connect
    from ctinv.summary import print_investigation

    err = Console(stderr=True)
    if not args.db.exists():
        err.print(f"[red]error:[/red] database {args.db} not found; run ctinv ingest first")
        return 2
    try:
        scope = Scope(
            access_key=args.access_key,
            principal=args.principal,
            start=args.start,
            end=args.end,
            max_depth=args.max_depth,
            max_sessions=args.max_sessions,
            max_events=args.max_events,
            follow_created_keys=args.follow_created_keys,
        )
    except InvestigationError as exc:
        err.print(f"[red]error:[/red] {exc}", highlight=False)
        return 2
    con = connect(args.db)
    try:
        inv = investigate(con, scope)
    except InvestigationError as exc:
        err.print(f"[red]error:[/red] {exc}", highlight=False)
        return 1
    finally:
        con.close()

    out = Console()
    print_investigation(out, inv, str(args.db))
    if args.output:
        write_json(inv, args.output, str(args.db))
        out.print(f"\nInvestigation written to {args.output}", highlight=False)
    return 0


Handler = Callable[[argparse.Namespace], int]
HANDLERS: dict[str, tuple[Callable[[argparse.ArgumentParser], None] | None, Handler]] = {
    "ingest": (_configure_ingest, _run_ingest),
    "detect": (_configure_detect, _run_detect),
    "investigate": (_configure_investigate, _run_investigate),
}


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.handler(args)
