"""Readable console summary of an investigation (the JSON output has everything)."""

from collections import Counter
from datetime import datetime
from typing import Any

from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.tree import Tree

from ctinv.investigate import OUTCOMES, Investigation, Pivot, Session

SHOW_EVENTS = 20
SHOW_APIS = 15
SHOW_CHILDREN = 20
SHOW_RESOURCES = 5
_STYLE = {"succeeded": "green", "denied": "red", "failed": "yellow"}


def _time(value: datetime | None) -> str:
    return value.isoformat(sep=" ") if value else "-"


def _colour(outcome: str, text: str) -> str:
    return f"[{_STYLE[outcome]}]{text}[/{_STYLE[outcome]}]"


def _counts(item: Any) -> str:
    """'N events (a succeeded · b denied · c failed)' for a session or summary."""
    get = item.get if isinstance(item, dict) else lambda name: getattr(item, name)
    parts = " · ".join(_colour(o, f"{get(o):,} {o}") for o in OUTCOMES if get(o))
    return f"{get('events'):,} events" + (f" ({parts})" if parts else "")


def _top(values: list[dict], distinct: int, shown: int = 3) -> str:
    text = ", ".join(f"{escape(str(v['value']))} ({v['events']:,})" for v in values[:shown])
    return text + (f", +{distinct - shown:,} more" if distinct > shown else "")


def print_investigation(console: Console, inv: Investigation, database: str) -> None:
    scope, summary = inv.scope, inv.summary
    labels = {s.id: f"S{n}" for n, s in enumerate(inv.sessions)}
    what = "access key" if scope.access_key else "principal"
    window = (
        f" from {_time(scope.start) if scope.start else 'the start'}"
        f" to {_time(scope.end) if scope.end else 'the end'} (UTC)"
        if scope.start or scope.end
        else ""
    )
    console.print(
        f"[bold]Investigation of {what} {escape(scope.root)}[/bold]{window} in {escape(database)}"
    )
    console.print(
        f"{_counts(summary)}, {_time(summary['first_seen'])} – {_time(summary['last_seen'])} UTC"
    )
    statuses = ", ".join(
        f"{n:,} {status.replace('_', ' ')}" for status, n in summary["pivot_statuses"].items() if n
    )
    console.print(
        f"{summary['sessions']:,} session(s), up to {summary['deepest_session']} pivot(s) deep; "
        f"{summary['pivots']:,} credential call(s)" + (f": {statuses}" if statuses else "")
    )
    _print_graph(console, inv, labels)
    _print_apis(console, inv)
    _print_timeline(console, inv, labels)
    _print_blast_radius(console, inv)
    _print_findings(console, inv)


def _session_label(s: Session, label: str) -> str:
    identity = ", ".join(escape(str(v["value"])) for v in s.identities[:2])
    if s.distinct.get("identities", 0) > 2:
        identity += f", +{s.distinct['identities'] - 2:,} more"
    return (
        f"[bold]{label}[/bold] {escape(s.id)} ({s.kind}) {identity}\n"
        f"{_counts(s)}, {_time(s.first_seen)} – {_time(s.last_seen)}\n"
        f"source IPs: {_top(s.source_ips, s.distinct.get('source_ips', 0))}"
    )


def _print_graph(console: Console, inv: Investigation, labels: dict[str, str]) -> None:
    sessions = {s.id: s for s in inv.sessions}
    root = inv.sessions[0]
    tree = Tree(_session_label(root, labels[root.id]))
    for origin in root.issued_by:
        tree.add(
            f"[dim]key issued by {origin['api']} at {_time(origin['event_time'])}, "
            f"caller {escape(str(origin['caller']))}, event {origin['event_id']}[/dim]"
        )
    followed: dict[str, list[Pivot]] = {}
    for pivot in inv.pivots:
        if pivot.status == "followed":
            followed.setdefault(pivot.from_session, []).append(pivot)

    def grow(node: Tree, session_id: str) -> None:
        children = followed.get(session_id, [])
        for pivot in children[:SHOW_CHILDREN]:
            child = sessions[pivot.to_session]  # type: ignore[index]
            target = f" {escape(pivot.target)}" if pivot.target else ""
            branch = node.add(
                f"via {pivot.api}{target} at {_time(pivot.event_time)}, event {pivot.event_id}\n"
                + _session_label(child, labels[child.id])
            )
            grow(branch, child.id)
        if len(children) > SHOW_CHILDREN:
            node.add(f"… {len(children) - SHOW_CHILDREN:,} more sessions (see the JSON output)")

    grow(tree, root.id)
    console.print()
    console.print("[bold]Session graph[/bold]")
    console.print(tree)

    not_followed = Counter(
        (p.status, p.api) for p in inv.pivots if p.status not in ("followed", "already_in_graph")
    )
    for (status, api), n in sorted(not_followed.items(), key=lambda item: (-item[1], item[0])):
        console.print(f"  not followed: {n:,} × {api}, {status.replace('_', ' ')}")
    if inv.summary["pivot_statuses"]["already_in_graph"]:
        n = inv.summary["pivot_statuses"]["already_in_graph"]
        console.print(f"  {n:,} credential call(s) led to keys already in the graph")


def _print_apis(console: Console, inv: Investigation) -> None:
    table = Table(
        title=f"APIs ({min(SHOW_APIS, len(inv.apis))} of {len(inv.apis):,} by events)",
        title_justify="left",
    )
    table.add_column("API")
    for outcome in OUTCOMES:
        table.add_column(outcome, justify="right", style=_STYLE[outcome])
    for api in inv.apis[:SHOW_APIS]:
        table.add_row(api["api"], *(f"{api[o]:,}" if api[o] else "" for o in OUTCOMES))
    console.print()
    console.print(table)


def _print_timeline(console: Console, inv: Investigation, labels: dict[str, str]) -> None:
    total = inv.summary["events"]
    table = Table(
        title=f"Timeline, UTC (first {min(SHOW_EVENTS, total):,} of {total:,} events)",
        title_justify="left",
    )
    for column in ("time", "", "API", "region", "source IP", "result", "eventID"):
        table.add_column(column, no_wrap=column in ("time", "eventID"))
    for event in inv.timeline[:SHOW_EVENTS]:
        outcome = event["outcome"]
        result = outcome if outcome == "succeeded" else f"{outcome}: {event['error_code']}"
        table.add_row(
            _time(event["event_time"]),
            labels[event["session"]],
            event["api"],
            event["region"] or "",
            escape(event["source_ip"] or ""),
            _colour(outcome, escape(result)),
            event["event_id"],
        )
    console.print()
    console.print(table)
    if len(inv.timeline) < total:
        console.print(
            f"  the JSON timeline lists {len(inv.timeline):,} of {total:,} events "
            f"(--max-events); all counts are complete"
        )


def _print_blast_radius(console: Console, inv: Investigation) -> None:
    blast = inv.blast_radius
    table = Table(
        title=f"Blast radius (top {SHOW_RESOURCES} resources per service, events per outcome)",
        title_justify="left",
    )
    table.add_column("service")
    table.add_column("resource")
    for outcome in OUTCOMES:
        table.add_column(outcome, justify="right", style=_STYLE[outcome])
    for service in blast["services"]:
        totals = " / ".join(_colour(o, f"{service[f'{o}_resources']:,}") for o in OUTCOMES)
        for n, entry in enumerate(service["listed"][:SHOW_RESOURCES]):
            table.add_row(
                f"[bold]{service['service']}[/bold]\n{service['resources']:,} "
                f"resource{'' if service['resources'] == 1 else 's'} ({totals})"
                if n == 0
                else "",
                f"{entry['type']} {escape(entry['resource'])}",
                *(f"{entry[o]['events']:,}" if entry[o] else "" for o in OUTCOMES),
            )
        table.add_section()
    console.print()
    console.print(table)
    without = blast["events_without_resource"]
    if without["events"]:
        apis = ", ".join(f"{a['api']} {a['events']:,}" for a in without["apis"][:5])
        console.print(f"  {without['events']:,} events name no resource: {apis}")


def _print_findings(console: Console, inv: Investigation) -> None:
    console.print()
    if inv.findings is None:
        console.print("[bold]Findings[/bold]: detection has not been run on this database")
        return
    if not inv.findings:
        console.print("[bold]Findings[/bold]: none with evidence in this investigation")
        return
    rules: dict[str, list[dict]] = {}
    for finding in inv.findings:
        rules.setdefault(finding["rule_id"], []).append(finding)
    table = Table(
        title=f"Findings ({len(inv.findings):,}) with evidence in this investigation, by rule",
        title_justify="left",
    )
    for column in ("rule", "severity", "ATT&CK", "findings", "first – last seen", "evidence"):
        table.add_column(column, justify="right" if column in ("findings", "evidence") else "left")
    for rule_id, findings in rules.items():
        first = findings[0]
        technique = first["technique_id"] + (
            f" (formerly {', '.join(first['former_technique_ids'])})"
            if first["former_technique_ids"]
            else ""
        )
        outcomes = Counter(f["outcome"] for f in findings)
        table.add_row(
            rule_id,
            first["severity"],
            technique,
            f"{len(findings):,} ("
            + ", ".join(f"{n:,} {outcome}" for outcome, n in sorted(outcomes.items()))
            + ")",
            f"{_time(min(f['first_seen'] for f in findings))} –\n"
            f"{_time(max(f['last_seen'] for f in findings))}",
            f"{sum(f['evidence_in_investigation'] for f in findings):,} events",
        )
    console.print(table)
