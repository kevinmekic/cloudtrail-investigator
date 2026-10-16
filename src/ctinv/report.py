"""Investigation and findings reports as Markdown and self-contained HTML.

A report is built in two steps. ``investigation_report`` and
``findings_report`` query the database and return a ``Report``: ``model`` is
what the report shows (long lists cut to ``Limits``), ``data`` is what the JSON
file next to it holds (complete lists, and for an investigation the whole
investigation with its event timeline). ``write_report`` renders Markdown and
HTML from the model (``ctinv.render``), optionally after masking account IDs
and access keys (``ctinv.redact``), and writes the three files.

Every statement and row of a report cites eventIDs as evidence, and every
cited eventID is listed in the report's evidence index with its time, call,
caller, source address and source file.

Everything taken from CloudTrail is untrusted text: the model keeps it as plain
strings, and the renderers escape every value they output.
"""

import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import duckdb

from ctinv import __version__, macros
from ctinv.datasets import describe
from ctinv.detect import TACTIC_NAMES
from ctinv.investigate import (
    CALLER_SQL,
    ISSUED_KEY_SQL,
    ISSUING_SQL,
    OUTCOME_SQL,
    OUTCOMES,
    PIVOT_STATUSES,
    Investigation,
    dump_json,
    key_kind,
    to_dict,
)
from ctinv.redact import Redactor

# Activity periods: calls of one session to one API with one outcome stay in one
# period while no gap between them is longer than this.
PERIOD_GAP_SECONDS = 900
# Key moments: the first window of this many seconds that holds at least this
# many denied (or failed) calls is the first burst of them.
BURST_EVENTS = 10
BURST_SECONDS = 60

# Fields a dataset publisher can anonymise (datasets.yml): how a report names
# them, and what readers must not take them for.
ANONYMISED_FIELDS = {
    "source_ips": ("Source IPs", "infrastructure"),
    "account_ids": ("account IDs", "accounts"),
    "access_keys": ("access keys", "credentials"),
}


def _listed(items: list[str], last: str) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + f" {last} " + items[-1]


def _anonymised(fields: list[str]) -> tuple[str, str]:
    """('Source IPs, account IDs and access keys', 'infrastructure, accounts or credentials')."""
    present = [f for f in ANONYMISED_FIELDS if f in fields]
    names = _listed([ANONYMISED_FIELDS[f][0] for f in present], "and")
    return names[0].upper() + names[1:], _listed([ANONYMISED_FIELDS[f][1] for f in present], "or")


def anonymisation_warning(fields: list[str]) -> str:
    """The label of a report's indicators when the dataset publisher anonymised ``fields``."""
    names, real = _anonymised(fields)
    return (
        f"{names} were anonymised by the dataset publisher - not real {real}. "
        "Do not block, look up or report them."
    )


REPORT_FORMAT = "ctinv-report/1"
FINDINGS_FORMAT = "ctinv-findings/1"

_API = "replace(e.event_source, '.amazonaws.com', '') || ':' || e.event_name"
_REP = "rep_events r JOIN events e ON e.event_id = r.event_id"
_FIRST = "first(e.event_id ORDER BY e.event_time, e.event_id)"
# The error of a failed call: its errorCode, or for a failed sign-in, which has
# none, its errorMessage. NULL for calls that succeeded.
_ERROR = f"CASE WHEN {macros.FAILED_SQL} THEN coalesce(e.error_code, e.error_message) END"
_LAST = "last(e.event_id ORDER BY e.event_time, e.event_id)"
# Order of key moments that share a second.
_MOMENT_ORDER = (
    "key created",
    "key issued",
    "key issued, not followed",
    "credential request denied",
    "credential request failed",
    "first use of key",
    "first success",
    "first denied burst",
    "first failed burst",
    "finding",
)


@dataclass(frozen=True)
class Limits:
    """How many rows each list of the report shows (the JSON has them all)."""

    periods: int = 500
    moments: int = 200
    findings: int = 100  # per tactic
    resources: int = 20  # per service
    iocs: int = 50  # per kind
    children: int = 20  # sessions shown under one session


DEFAULT_LIMITS = Limits()


@dataclass
class Report:
    kind: str  # "investigation" or "findings"
    model: dict[str, Any]
    data: dict[str, Any] = field(repr=False)


def _n(count: int, word: str, plural: str | None = None) -> str:
    return f"{count:,} {word if count == 1 else plural or word + 's'}"


def _t(value: datetime | None) -> str:
    return value.isoformat(sep=" ") if value else "-"


def _stmt(text: str, evidence: list[str | None] | None = None) -> dict[str, Any]:
    ids = list(dict.fromkeys(i for i in evidence or [] if i))
    return {"text": text, "evidence": ids}


def _technique(finding: dict[str, Any]) -> str:
    former = finding["former_technique_ids"]
    return finding["technique_id"] + (f" (formerly {', '.join(former)})" if former else "")


def _table(con: duckdb.DuckDBPyConnection, sql: str, params: dict | None = None) -> list[dict]:
    cursor = con.execute(sql, params or {})
    names = [d[0] for d in cursor.description]
    return [dict(zip(names, row, strict=True)) for row in cursor.fetchall()]


# --- shared pieces -----------------------------------------------------------


def _datasets(con: duckdb.DuckDBPyConnection) -> tuple[list[dict], dict | None]:
    names = [
        r[0] for r in con.execute(f"SELECT DISTINCT e.dataset FROM {_REP} ORDER BY 1").fetchall()
    ]
    datasets = describe(names)
    fields = [f for f in ANONYMISED_FIELDS if any(f in d["anonymised"] for d in datasets)]
    if not fields:
        return datasets, None
    return datasets, {
        "text": anonymisation_warning(fields),
        "fields": fields,
        "datasets": [d["name"] for d in datasets if d["anonymised"]],
    }


def _iocs(
    con: duckdb.DuckDBPyConnection,
    labels: dict[str, str],
    datasets: list[dict],
    pivots: list[Any],
    limit: int,
) -> dict[str, Any]:
    # Per field, the datasets whose publisher anonymised it.
    anonymised = {
        f: {d["name"] for d in datasets if f in d["anonymised"]} for f in ANONYMISED_FIELDS
    }

    def values(expression: str) -> list[dict]:
        rows = _table(
            con,
            f"""
            SELECT {expression} AS value, count(*) AS events,
                   min(e.event_time) AS first_seen, max(e.event_time) AS last_seen,
                   list_sort(list(DISTINCT r.session) FILTER (WHERE r.session IS NOT NULL))
                       AS sessions,
                   list_sort(list(DISTINCT e.dataset)) AS datasets,
                   {_FIRST} AS first_id, {_LAST} AS last_id
            FROM {_REP} WHERE {expression} IS NOT NULL
            GROUP BY 1 ORDER BY events DESC, value
            """,
        )
        for row in rows:
            row["sessions"] = sorted((labels[s] for s in row["sessions"] or []), key=_label_key)
            row["evidence"] = list(dict.fromkeys([row.pop("first_id"), row.pop("last_id")]))
        return rows

    ips, services = [], []
    for row in values("e.source_ip_address"):
        try:
            address = ipaddress.ip_address(row["value"])
        except ValueError:
            services.append(row)
            continue
        row["scope"] = "public" if address.is_global else "not public"
        row["anonymised"] = set(row["datasets"]) <= anonymised["source_ips"]
        ips.append(row)
    agents = values("e.user_agent")
    keys = values("e.access_key_id")
    for row in keys:
        row["kind"] = key_kind(row["value"])
        row["anonymised"] = set(row["datasets"]) <= anonymised["access_keys"]
    arns = [row | {"seen_as": "caller"} for row in values("e.identity_arn")]
    arns += [row | {"seen_as": "role of the caller"} for row in values("e.session_issuer_arn")]
    requested: dict[str, list] = defaultdict(list)
    for pivot in pivots:
        if pivot.target and pivot.target.startswith("arn:"):
            requested[pivot.target].append(pivot)
    for arn, calls in requested.items():
        arns.append(
            {
                "value": arn,
                "seen_as": "requested in a credential call",
                "events": len(calls),
                "first_seen": calls[0].event_time,
                "last_seen": calls[-1].event_time,
                "sessions": sorted({labels[p.from_session] for p in calls}, key=_label_key),
                "datasets": [],
                "evidence": list(dict.fromkeys([calls[0].event_id, calls[-1].event_id])),
            }
        )
    arns.sort(key=lambda row: (-row["events"], row["value"], row["seen_as"]))

    return {
        "source_ips": _cut(ips, limit),
        "other_sources": _cut(services, limit),
        "user_agents": _cut(agents, limit),
        "access_keys": _cut(keys, limit),
        "arns": _cut(arns, limit),
        "full": {
            "source_ips": ips,
            "other_sources": services,
            "user_agents": agents,
            "access_keys": keys,
            "arns": arns,
        },
    }


def _label_key(label: str) -> tuple[int, str]:
    return (int(label[1:]), label) if label[1:].isdigit() else (-1, label)


def _limitations(
    con: duckdb.DuckDBPyConnection, datasets: list[dict], extra: list[dict]
) -> list[dict]:
    notes = []
    for d in datasets:
        if not d["described"]:
            notes.append(
                _stmt(
                    f"Dataset {d['name']} is not described in ctinv's dataset registry: "
                    "whether its publisher changed IP addresses, account IDs or keys is "
                    "unknown. Check before acting on any indicator from it."
                )
            )
            continue
        notes.append(_stmt(f"Dataset {d['name']}: {d['title']}, described at {d['url']}."))
        if d["anonymisation"]:
            notes.append(_stmt(f"{d['name']}: {d['anonymisation']}"))
        notes += [_stmt(f"{d['name']}: {c}") for c in d["caveats"]]

    (total, missing, examples) = con.execute(
        f"""
        WITH keys AS (
            SELECT e.access_key_id AS key, {_FIRST} AS first_id
            FROM {_REP} WHERE e.access_key_id LIKE 'ASIA%' GROUP BY 1
        ), issued AS (
            SELECT DISTINCT {ISSUED_KEY_SQL} AS key FROM events e
            WHERE NOT {macros.FAILED_SQL} AND {ISSUING_SQL}
              AND {ISSUED_KEY_SQL} IN (SELECT key FROM keys)
        )
        SELECT count(*), count(*) FILTER (WHERE key NOT IN (SELECT key FROM issued)),
               list(first_id ORDER BY first_id)
                   FILTER (WHERE key NOT IN (SELECT key FROM issued))
        FROM keys
        """
    ).fetchone()
    if missing:
        notes.append(
            _stmt(
                f"{missing:,} of {_n(total, 'temporary key')} (ASIA...) used in these events "
                "have no issuing call in the data, so where they came from is unknown "
                "(evidence: the first use of up to three of them).",
                (examples or [])[:3],
            )
        )
    notes += extra
    notes += [
        _stmt(
            "CloudTrail records times to the second, so the order of events within one "
            "second is unknown; this report orders them by eventID."
        ),
        _stmt(
            "Outcomes come from errorCode: succeeded means the API accepted the call, "
            "denied a permission error, failed any other error. Sign-in events have no "
            "errorCode; a failed sign-in is recorded as Failure in responseElements and "
            "counts as failed."
        ),
        _stmt(
            "Lists in this report are cut where marked; the JSON file written with it has "
            "the complete lists."
        ),
    ]
    return notes


def _evidence(con: duckdb.DuckDBPyConnection, model: dict, labels: dict[str, str]) -> None:
    """Add the evidence index: every eventID the model cites, with its details."""
    cited: dict[str, None] = {}

    def collect(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "evidence" and isinstance(item, list):
                    cited.update(dict.fromkeys(item))
                else:
                    collect(item)
        elif isinstance(value, list):
            for item in value:
                collect(item)

    collect(model)
    con.execute(
        "CREATE OR REPLACE TEMP TABLE rep_cited AS SELECT unnest($ids::VARCHAR[]) AS event_id",
        {"ids": list(cited)},
    )
    rows = _table(
        con,
        f"""
        SELECT e.event_id, e.event_time, r.session, {_API} AS api, e.aws_region AS region,
               {CALLER_SQL} AS caller, e.source_ip_address AS source_ip,
               e.user_agent, {OUTCOME_SQL} AS outcome, e.error_code, e.dataset,
               e.source_file, e.source_index
        FROM rep_cited c JOIN events e ON e.event_id = c.event_id
        LEFT JOIN rep_events r ON r.event_id = e.event_id
        ORDER BY e.event_time, e.event_id
        """,
    )
    missing = set(cited) - {row["event_id"] for row in rows}
    if missing:  # every cited eventID comes from the events table
        raise ValueError(f"cited eventIDs not in the database: {sorted(missing)[:3]}")
    for n, row in enumerate(rows, 1):
        row["n"] = n
        row["session"] = labels.get(row["session"], "") if row["session"] else ""
    model["evidence"] = rows
    model["evidence_index"] = {row["event_id"]: row["n"] for row in rows}


def _cut(rows: list, limit: int) -> dict[str, Any]:
    return {"rows": rows[:limit], "total": len(rows)}


# --- investigation report ----------------------------------------------------


def investigation_report(
    con: duckdb.DuckDBPyConnection,
    inv: Investigation,
    database: str,
    limits: Limits = DEFAULT_LIMITS,
    period_gap: int = PERIOD_GAP_SECONDS,
) -> Report:
    """The report of an investigation; ``con`` must be the connection it ran on."""
    macros.register(con)
    con.execute(
        "CREATE OR REPLACE TEMP TABLE rep_events AS SELECT event_id, session FROM inv_events"
    )
    labels = {s.id: f"S{n}" for n, s in enumerate(inv.sessions)}
    datasets, warning = _datasets(con)
    periods = _activity_periods(con, labels, period_gap)
    iocs = _iocs(con, labels, datasets, inv.pivots, limits.iocs)
    graph = _session_graph(con, inv, labels, limits)
    blast = _blast_radius(con, inv, limits)
    findings, finding_rows = _findings_by_tactic(inv.findings, labels, limits.findings)
    moments = _investigation_moments(con, inv, labels, finding_rows)
    scope = inv.scope
    what = key_kind(scope.root) if scope.access_key else "principal"

    extra = []
    stopped = [p for p in inv.pivots if p.status in ("depth_limit", "session_limit")]
    if stopped:
        extra.append(
            _stmt(
                f"{_n(len(stopped), 'credential call')} led to keys that were not followed "
                "because the depth or session limit was reached.",
                [p.event_id for p in stopped[:3]],
            )
        )
    if len(inv.timeline) < inv.summary["events"]:
        extra.append(
            _stmt(
                f"The JSON timeline lists the first {len(inv.timeline):,} of "
                f"{inv.summary['events']:,} events (--max-events); all counts are complete."
            )
        )
    model: dict[str, Any] = {
        "kind": "investigation",
        "title": f"Investigation of the {what} {scope.root}",
        "generated_at": datetime.now(UTC).replace(tzinfo=None, microsecond=0),
        "ctinv_version": __version__,
        "database": database,
        "scope": {
            "start_point": f"{what} {scope.root}",
            "time_range": _time_range(scope.start, scope.end),
            "limits": (
                f"max depth {scope.max_depth}, max sessions {scope.max_sessions:,}, "
                f"max events listed in the JSON {scope.max_events:,}"
                + (", following created keys" if scope.follow_created_keys else "")
            ),
        },
        "summary": _investigation_summary(
            con, inv, labels, datasets, warning, blast, findings, finding_rows
        ),
        "datasets": datasets,
        "anonymised": warning,
        "moments": _cut(moments, limits.moments)
        | {"burst_events": BURST_EVENTS, "burst_seconds": BURST_SECONDS},
        "periods": _cut(periods, limits.periods) | {"gap_seconds": period_gap},
        "findings": findings,
        "graph": graph,
        "blast": blast,
        "iocs": {k: v for k, v in iocs.items() if k != "full"},
        "limitations": _limitations(con, datasets, extra),
    }
    _evidence(con, model, labels)
    data = to_dict(inv, database) | {
        "report": {
            "format": REPORT_FORMAT,
            "period_gap_seconds": period_gap,
            "key_moments": moments,
            "activity_periods": periods,
            "iocs": iocs["full"],
            "datasets": datasets,
        }
    }
    return Report("investigation", model, data)


def _time_range(start: datetime | None, end: datetime | None) -> str:
    if not start and not end:
        return "whole database"
    return f"{_t(start) if start else 'start'} to {_t(end) if end else 'end'} (end excluded)"


def _activity_periods(
    con: duckdb.DuckDBPyConnection, labels: dict[str, str], gap: int
) -> list[dict[str, Any]]:
    rows = _table(
        con,
        f"""
        WITH o AS (
            SELECT r.session, e.event_id, e.event_time, e.aws_region,
                   {_ERROR} AS error_code, {_API} AS api, {OUTCOME_SQL} AS outcome
            FROM {_REP}
        ), g AS (
            SELECT *, sum(CASE WHEN previous IS NULL
                                    OR event_time - previous > to_seconds($gap) THEN 1 ELSE 0 END)
                          OVER (PARTITION BY session, api, outcome
                                ORDER BY event_time, event_id) AS period
            FROM (SELECT *, lag(event_time) OVER (PARTITION BY session, api, outcome
                                                  ORDER BY event_time, event_id) AS previous
                  FROM o)
        )
        SELECT session, api, outcome, count(*) AS events,
               min(event_time) AS first_seen, max(event_time) AS last_seen,
               list_sort(list(DISTINCT aws_region) FILTER (WHERE aws_region IS NOT NULL))
                   AS regions,
               histogram(error_code) FILTER (WHERE error_code IS NOT NULL) AS errors,
               first(event_id ORDER BY event_time, event_id) AS first_id,
               last(event_id ORDER BY event_time, event_id) AS last_id
        FROM g GROUP BY session, api, outcome, period
        """,
        {"gap": float(gap)},
    )
    for row in rows:
        row["session"] = labels[row["session"]]
        errors = row.pop("errors") or {}
        row["error_codes"] = [
            {"code": code, "events": n}
            for code, n in sorted(errors.items(), key=lambda item: (-item[1], item[0]))
        ]
        row["evidence"] = list(dict.fromkeys([row.pop("first_id"), row.pop("last_id")]))
    rows.sort(
        key=lambda r: (
            r["first_seen"],
            _label_key(r["session"]),
            r["api"],
            r["outcome"],
            r["evidence"][0],
        )
    )
    return rows


def _moment(
    time: datetime, kind: str, session: str, text: str, evidence: list[str | None]
) -> dict[str, Any]:
    return {"time": time, "kind": kind, "session": session} | _stmt(text, evidence)


def _investigation_moments(
    con: duckdb.DuckDBPyConnection,
    inv: Investigation,
    labels: dict[str, str],
    finding_rows: list[dict],
) -> list[dict[str, Any]]:
    moments = []
    seen: set[str] = set()
    before = inv.scope.start
    pivots = {p.event_id: p for p in inv.pivots}
    for s in inv.sessions:
        for origin in s.issued_by:
            if origin["event_id"] in seen:
                continue
            seen.add(origin["event_id"])
            created = origin["api"] == "iam:CreateAccessKey"
            text = (
                f"{origin['api']} by {origin['caller']} {'created' if created else 'issued'} "
                f"the {key_kind(s.id)} {s.id}, used in session {labels[s.id]}"
            )
            if before and origin["event_time"] < before:
                text += " (before the investigated time range)"
            pivot = pivots.get(origin["event_id"])
            moments.append(
                _moment(
                    origin["event_time"],
                    "key created" if created else "key issued",
                    labels[pivot.from_session] if pivot else "",
                    text,
                    [origin["event_id"]],
                )
            )
    for p in inv.pivots:
        if p.event_id in seen:
            continue
        target = f" for {p.target}" if p.target else ""
        caller = p.caller or "an unknown caller"
        if p.outcome == "succeeded":
            text = f"{p.api} by {caller}{target} issued {p.issued_key or 'a key'}"
            kind = "key issued"
            if p.status != "followed":
                kind = "key issued, not followed"
                text += f"; not followed: {PIVOT_STATUSES[p.status]}"
        else:
            kind = f"credential request {p.outcome}"
            text = f"{p.api} by {caller}{target} {p.outcome} with {p.error_code}"
        moments.append(_moment(p.event_time, kind, labels[p.from_session], text, [p.event_id]))

    for row in _table(
        con,
        f"""
        SELECT e.access_key_id AS key, min(e.event_time) AS time, count(*) AS events,
               first(r.session ORDER BY e.event_time, e.event_id) AS session,
               first({_API} ORDER BY e.event_time, e.event_id) AS api,
               first({OUTCOME_SQL} ORDER BY e.event_time, e.event_id) AS outcome,
               {_FIRST} AS first_id
        FROM {_REP} WHERE e.access_key_id IS NOT NULL GROUP BY 1
        """,
    ):
        moments.append(
            _moment(
                row["time"],
                "first use of key",
                labels[row["session"]],
                f"First use of the {key_kind(row['key'])} {row['key']}: {row['api']}, "
                f"{row['outcome']} ({_n(row['events'], 'event')} with this key)",
                [row["first_id"]],
            )
        )

    first = con.execute(
        f"""
        SELECT e.event_time, r.session, {_API}, {CALLER_SQL}, e.event_id FROM {_REP}
        WHERE NOT {macros.FAILED_SQL} ORDER BY e.event_time, e.event_id LIMIT 1
        """
    ).fetchone()
    if first:
        time, session, api, caller, event_id = first
        moments.append(
            _moment(
                time,
                "first success",
                labels[session],
                f"First successful call: {api} by {caller}",
                [event_id],
            )
        )
    moments += _bursts(con, labels)
    moments += _finding_moments(con, finding_rows)
    order = {kind: n for n, kind in enumerate(_MOMENT_ORDER)}
    moments.sort(key=lambda m: (m["time"], order[m["kind"]], m["text"]))
    return moments


def _bursts(con: duckdb.DuckDBPyConnection, labels: dict[str, str]) -> list[dict[str, Any]]:
    moments = []
    for outcome in ("denied", "failed"):
        start = con.execute(
            f"""
            SELECT event_time FROM (
                SELECT e.event_time, e.event_id,
                       count(*) OVER (ORDER BY e.event_time RANGE BETWEEN CURRENT ROW
                                      AND to_seconds($seconds) FOLLOWING) AS n
                FROM {_REP} WHERE {OUTCOME_SQL} = $outcome)
            WHERE n >= $min ORDER BY event_time, event_id LIMIT 1
            """,
            {"outcome": outcome, "seconds": float(BURST_SECONDS), "min": BURST_EVENTS},
        ).fetchone()
        if not start:
            continue
        rows = _table(
            con,
            f"""
            SELECT e.event_id, e.event_time, r.session, {_API} AS api,
                   {_ERROR} AS error_code
            FROM {_REP}
            WHERE {OUTCOME_SQL} = $outcome AND e.event_time >= $start
              AND e.event_time <= $start + to_seconds($seconds)
            ORDER BY e.event_time, e.event_id
            """,
            {"outcome": outcome, "start": start[0], "seconds": float(BURST_SECONDS)},
        )
        apis = Counter(row["api"] for row in rows).most_common(3)
        codes = Counter(row["error_code"] for row in rows).most_common(3)
        sessions = sorted({labels[row["session"]] for row in rows}, key=_label_key)
        moments.append(
            _moment(
                start[0],
                f"first {outcome} burst",
                ", ".join(sessions),
                f"First burst of {outcome} calls: {len(rows):,} within {BURST_SECONDS} seconds "
                f"({', '.join(f'{api} {n:,}' for api, n in apis)}; "
                f"{', '.join(f'{code} {n:,}' for code, n in codes)})",
                [row["event_id"] for row in rows[:3]],
            )
        )
    return moments


def _finding_moments(con: duckdb.DuckDBPyConnection, findings: list[dict]) -> list[dict[str, Any]]:
    """One moment per finding (report rows), at its first evidence event in the report."""
    if not findings:
        return []
    firsts = [f["evidence"][0] for f in findings]
    times = dict(
        con.execute(
            "SELECT event_id, event_time FROM events WHERE event_id IN "
            "(SELECT unnest($ids::VARCHAR[]))",
            {"ids": firsts},
        ).fetchall()
    )
    return [
        _moment(
            times[f["evidence"][0]],
            "finding",
            ", ".join(f["sessions"]),
            f"Finding {f['rule_id']} ({f['technique']}, {f['severity']}): {f['summary']}",
            f["evidence"],
        )
        for f in findings
    ]


def _session_graph(
    con: duckdb.DuckDBPyConnection,
    inv: Investigation,
    labels: dict[str, str],
    limits: Limits,
) -> dict[str, Any]:
    bounds = {
        session: (first, last)
        for session, first, last in con.execute(
            f"SELECT r.session, {_FIRST}, {_LAST} FROM {_REP} GROUP BY 1"
        ).fetchall()
    }
    via = {p.to_session: p for p in inv.pivots if p.status == "followed"}
    nodes: dict[str, dict[str, Any]] = {}
    for s in inv.sessions:
        pivot = via.get(s.id)
        node = {
            "label": labels[s.id],
            "id": s.id,
            "kind": s.kind,
            "depth": s.depth,
            "events": s.events,
            **{o: getattr(s, o) for o in OUTCOMES},
            "first_seen": s.first_seen,
            "last_seen": s.last_seen,
            "via": None,
            "issued_by": [
                {k: o[k] for k in ("api", "caller", "event_time", "event_id")} for o in s.issued_by
            ],
            "more": 0,
        }
        for name, shown in (
            ("identities", 3),
            ("source_ips", 3),
            ("user_agents", 2),
            ("regions", 5),
        ):
            node[name] = {
                "top": [(v["value"], v["events"]) for v in getattr(s, name)[:shown]],
                "distinct": s.distinct.get(name, 0),
            }
        evidence = []
        if pivot:
            node["via"] = {
                "api": pivot.api,
                "target": pivot.target,
                "time": pivot.event_time,
                "from": labels[pivot.from_session],
            }
            evidence.append(pivot.event_id)
        evidence += [o["event_id"] for o in s.issued_by]
        evidence += list(bounds.get(s.id, ()))
        node["evidence"] = list(dict.fromkeys(evidence))
        nodes[s.id] = node
    # The tree as a list in depth-first order, so templates need no recursion
    # (whose rendered output Markdown escaping would escape twice).
    children: dict[str, list[str]] = defaultdict(list)
    for s in inv.sessions[1:]:
        if s.parent in nodes:
            children[s.parent].append(s.id)
    tree: list[dict[str, Any]] = []

    def visit(session: str, level: int) -> None:
        tree.append(nodes[session] | {"level": level})
        for child in children[session][: limits.children]:
            visit(child, level + 1)
        if len(children[session]) > limits.children:
            tree.append({"level": level + 1, "more": len(children[session]) - limits.children})

    visit(inv.sessions[0].id, 0)

    groups: dict[tuple[str, str], list] = defaultdict(list)
    for p in inv.pivots:
        if p.status != "followed":
            groups[(p.status, p.api)].append(p)
    not_followed = [
        {
            "status": status,
            "meaning": PIVOT_STATUSES[status],
            "api": api,
            "calls": len(pivots),
            "evidence": [p.event_id for p in pivots[:3]],
        }
        for (status, api), pivots in sorted(groups.items(), key=lambda g: (-len(g[1]), g[0]))
    ]
    return {
        "tree": tree,
        "sessions": len(inv.sessions),
        "deepest": inv.summary["deepest_session"],
        "not_followed": not_followed,
    }


def _blast_radius(
    con: duckdb.DuckDBPyConnection, inv: Investigation, limits: Limits
) -> dict[str, Any]:
    services = []
    for service in inv.blast_radius["services"]:
        rows = []
        for entry in service["listed"][: limits.resources]:
            present = [entry[o] for o in OUTCOMES if entry[o]]
            apis: Counter[str] = Counter()
            for part in present:
                apis.update(part["apis"])
            rows.append(
                {
                    "type": entry["type"],
                    "resource": entry["resource"],
                    "events": entry["events"],
                    **{o: entry[o]["events"] if entry[o] else 0 for o in OUTCOMES},
                    "apis": [api for api, _ in apis.most_common(3)],
                    "more_apis": max(0, len(apis) - 3),
                    "first_seen": min(part["first_seen"] for part in present),
                    "last_seen": max(part["last_seen"] for part in present),
                    "evidence": [part["event_ids"][0] for part in present],
                }
            )
        services.append(
            {
                "service": service["service"],
                "events": service["events"],
                "resources": service["resources"],
                **{f"{o}_resources": service[f"{o}_resources"] for o in OUTCOMES},
                "rows": rows,
            }
        )
    unnamed = _table(
        con,
        f"""
        SELECT {_API} AS api, count(*) AS events, {_FIRST} AS first_id
        FROM {_REP} ANTI JOIN (SELECT DISTINCT event_id FROM inv_refs) x
             ON x.event_id = e.event_id
        GROUP BY 1 ORDER BY events DESC, api
        """,
    )
    resources = sum(s["resources"] for s in services)
    succeeded = sum(s["succeeded_resources"] for s in services)
    return {
        "services": services,
        "resources": resources,
        "with_success": succeeded,
        "attempted_only": resources - succeeded,
        "without_resource": {
            "events": sum(row["events"] for row in unnamed),
            "apis": [
                {"api": row["api"], "events": row["events"], "evidence": [row["first_id"]]}
                for row in unnamed[:5]
            ],
            "more_apis": max(0, len(unnamed) - 5),
        },
    }


def _findings_by_tactic(
    findings: list[dict] | None, labels: dict[str, str], limit: int
) -> tuple[dict[str, Any], list[dict]]:
    """Findings grouped by ATT&CK tactic (each under every tactic of its rule), and all rows."""
    if findings is None:
        return {"status": "not_run", "total": 0, "rules": 0, "tactics": []}, []
    rows = [
        {
            "finding_id": f["finding_id"],
            "rule_id": f["rule_id"],
            "rule_title": f["rule_title"],
            "severity": f["severity"],
            "technique": _technique(f),
            "technique_name": f["technique_name"],
            "tactics": list(f["tactics"]),
            "principal": f["principal"],
            "summary": f["summary"],
            "outcome": f["outcome"],
            "first_seen": f["first_seen"],
            "last_seen": f["last_seen"],
            "evidence_count": f["evidence_count"],
            "evidence_here": f.get("evidence_in_investigation", f["evidence_count"]),
            "sessions": sorted((labels[s] for s in f.get("sessions", [])), key=_label_key),
            "evidence": list(f["event_ids"][:3]),
        }
        for f in findings
    ]
    tactics = []
    for tactic, name in TACTIC_NAMES.items():
        members = [r for r in rows if tactic in r["tactics"]]
        if members:
            tactics.append(
                {
                    "tactic": tactic,
                    "name": name,
                    "rules": sorted({r["rule_id"] for r in members}),
                }
                | _cut(members, limit)
            )
    return {
        "status": "some" if rows else "none",
        "total": len(rows),
        "rules": len({r["rule_id"] for r in rows}),
        "tactics": tactics,
    }, rows


def _investigation_summary(
    con: duckdb.DuckDBPyConnection,
    inv: Investigation,
    labels: dict[str, str],
    datasets: list[dict],
    warning: dict | None,
    blast: dict,
    findings: dict,
    finding_rows: list[dict],
) -> list[dict[str, Any]]:
    s, scope = inv.summary, inv.scope
    first_ids = dict(
        con.execute(
            f"SELECT {OUTCOME_SQL}, {_FIRST} FROM {_REP} GROUP BY 1",
        ).fetchall()
    )
    (first_id, last_id) = con.execute(f"SELECT {_FIRST}, {_LAST} FROM {_REP}").fetchone()
    what = f"the {key_kind(scope.root)}" if scope.access_key else "the principal"
    window = f" from {_time_range(scope.start, scope.end)}" if scope.start or scope.end else ""
    statements = [
        _stmt(
            f"Investigated {what} {scope.root}{window}, in {_n(len(datasets), 'dataset')}: "
            + ", ".join(d["name"] for d in datasets)
            + ".",
            [first_id, last_id],
        ),
        _stmt(
            f"{_n(s['events'], 'event')} between {_t(s['first_seen'])} and "
            f"{_t(s['last_seen'])} UTC: " + ", ".join(f"{s[o]:,} {o}" for o in OUTCOMES) + ".",
            [first_ids.get(o) for o in OUTCOMES],
        ),
    ]
    root = inv.sessions[0]
    if scope.access_key:
        if root.issued_by:
            origin = root.issued_by[0]
            created = origin["api"] == "iam:CreateAccessKey"
            statements.append(
                _stmt(
                    f"The key was {'created' if created else 'issued'} on "
                    f"{_t(origin['event_time'])} by {origin['api']}, called by "
                    f"{origin['caller']}"
                    + (
                        " (before the investigated time range)."
                        if scope.start and origin["event_time"] < scope.start
                        else "."
                    ),
                    [origin["event_id"]],
                )
            )
        else:
            statements.append(
                _stmt(
                    "No call that issued or created the key is in the data, so its origin "
                    "is unknown (evidence: its first use).",
                    [first_id],
                )
            )
    followed = [p for p in inv.pivots if p.status == "followed"]
    sessions = {x.id: x for x in inv.sessions}
    if followed:
        shown = followed[:3]
        statements.append(
            _stmt(
                f"It obtained and used {_n(len(followed), 'other credential')}, up to "
                f"{_n(s['deepest_session'], 'pivot')} deep: "
                + "; ".join(
                    f"{labels[p.to_session]} {p.to_session} via {p.api} at {_t(p.event_time)} "
                    f"({_n(sessions[p.to_session].events, 'event')})"
                    for p in shown
                )
                + (f"; and {len(followed) - 3:,} more" if len(followed) > 3 else "")
                + ".",
                [p.event_id for p in shown] + [_session_first(con, p.to_session) for p in shown],
            )
        )
    elif inv.pivots:
        statements.append(
            _stmt(
                f"None of its {_n(len(inv.pivots), 'credential call')} led to a key that "
                "was used in the investigated events.",
                [p.event_id for p in inv.pivots[:3]],
            )
        )
    else:
        statements.append(_stmt("It made no call that issues credentials."))
    others = Counter(
        (p.api, p.outcome, p.error_code) for p in inv.pivots if p.outcome != "succeeded"
    )
    if others:
        statements.append(
            _stmt(
                "Credential requests that returned an error: "
                + ", ".join(
                    f"{n:,} x {api} ({outcome}, {code})"
                    for (api, outcome, code), n in others.most_common(5)
                )
                + ".",
                [p.event_id for p in inv.pivots if p.outcome != "succeeded"][:3],
            )
        )

    counts = ", ".join(f"count(*) FILTER (WHERE {OUTCOME_SQL} = '{o}') AS {o}" for o in OUTCOMES)
    top = _table(
        con,
        f"""
        SELECT {_API} AS api, count(*) AS events,
               count(DISTINCT e.aws_region) AS regions, {counts},
               {_FIRST} AS first_id
        FROM {_REP} GROUP BY 1 ORDER BY events DESC, api LIMIT 3
        """,
    )
    statements.append(
        _stmt(
            "Most frequent calls: "
            + "; ".join(
                f"{row['api']} {_n(row['events'], 'event')} in {_n(row['regions'], 'region')} ("
                + ", ".join(f"{row[o]:,} {o}" for o in OUTCOMES if row[o])
                + ")"
                for row in top
            )
            + ".",
            [row["first_id"] for row in top],
        )
    )
    if blast["resources"]:
        # Evidence: the first resource with a successful call and the first one
        # without (row evidence lists the first eventID per outcome, succeeded first).
        rows = [row for service in blast["services"] for row in service["rows"]]
        evidence = [
            next((row["evidence"][0] for row in rows if test(row["succeeded"])), None)
            for test in (bool, lambda n: not n)
        ]
        statements.append(
            _stmt(
                f"The events name {_n(blast['resources'], 'resource')} in "
                f"{_n(len(blast['services']), 'service')}: {blast['with_success']:,} with at "
                f"least one successful call, {blast['attempted_only']:,} only in denied or "
                f"failed calls; {_n(blast['without_resource']['events'], 'event')} name no "
                "resource.",
                evidence,
            )
        )
    statements.append(_findings_statement(findings, finding_rows))
    if warning:
        statements.append(_anonymised_statement(warning))
    return statements


def _anonymised_statement(warning: dict) -> dict[str, Any]:
    names, real = _anonymised(warning["fields"])
    return _stmt(
        f"{names} in this data were anonymised by the dataset publisher "
        f"({', '.join(warning['datasets'])}): they are not real {real}."
    )


def _session_first(con: duckdb.DuckDBPyConnection, session: str) -> str:
    return con.execute(
        f"SELECT {_FIRST} FROM {_REP} WHERE r.session = $s", {"s": session}
    ).fetchone()[0]


def _findings_statement(findings: dict, rows: list[dict]) -> dict[str, Any]:
    if findings["status"] == "not_run":
        return _stmt("Detection has not been run on this database, so findings are unknown.")
    if findings["status"] == "none":
        return _stmt("No detection finding has evidence in these events.")
    by_rule: dict[str, list] = defaultdict(list)
    for row in rows:
        by_rule[row["rule_id"]].append(row)
    ranked = sorted(by_rule.items(), key=lambda item: (-len(item[1]), item[0]))
    return _stmt(
        f"{_n(findings['total'], 'finding')} of {_n(findings['rules'], 'rule')} "
        "have evidence here: "
        + "; ".join(
            f"{rule} ({rows[0]['technique']}, {rows[0]['severity']}) {len(rows):,}"
            for rule, rows in ranked
        )
        + ".",
        [rows[0]["evidence"][0] for _, rows in ranked[:5]],
    )


# --- findings report ---------------------------------------------------------


class ReportError(ValueError):
    """The report cannot be built, e.g. detection was never run."""


def findings_report(
    con: duckdb.DuckDBPyConnection,
    database: str,
    rules: list[str] | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    limits: Limits = DEFAULT_LIMITS,
) -> Report:
    """A report of the findings of ``ctinv detect``, optionally by rule and time range.

    A finding is included if its time span overlaps the range.
    """
    macros.register(con)
    if not con.execute("SELECT count(*) FROM rule_runs").fetchone()[0]:
        raise ReportError("detection has not been run on this database; run ctinv detect first")
    conditions, params = ["true"], {}
    if rules:
        conditions.append("rule_id IN (SELECT unnest($rules::VARCHAR[]))")
        params["rules"] = rules
    if start:
        conditions.append("last_seen >= $start")
        params["start"] = start
    if end:
        conditions.append("first_seen < $end")
        params["end"] = end
    con.execute(
        "CREATE OR REPLACE TEMP TABLE rep_findings AS SELECT * FROM findings WHERE "
        + " AND ".join(conditions),
        params,
    )
    con.execute(
        "CREATE OR REPLACE TEMP TABLE rep_events AS "
        "SELECT DISTINCT unnest(evidence_event_ids) AS event_id, NULL::VARCHAR AS session "
        "FROM rep_findings"
    )
    first_three = dict(
        con.execute(
            """
            SELECT finding_id, list(event_id ORDER BY event_time, event_id) FROM (
                SELECT u.finding_id, u.event_id, e.event_time,
                       row_number() OVER (PARTITION BY u.finding_id
                                          ORDER BY e.event_time, u.event_id) AS n
                FROM (SELECT finding_id, unnest(evidence_event_ids) AS event_id
                      FROM rep_findings) u
                JOIN events e ON e.event_id = u.event_id)
            WHERE n <= 3 GROUP BY 1
            """
        ).fetchall()
    )
    stored = _table(con, "SELECT * FROM rep_findings ORDER BY first_seen, rule_id, finding_id")
    for f in stored:
        f["event_ids"] = first_three[f["finding_id"]]
    findings, rows = _findings_by_tactic(stored, {}, limits.findings)
    datasets, warning = _datasets(con)
    iocs = _iocs(con, {}, datasets, [], limits.iocs)
    moments = _finding_moments(con, rows)
    moments.sort(key=lambda m: (m["time"], m["text"]))
    rule_text = ", ".join(rules) if rules else "all rules"
    model: dict[str, Any] = {
        "kind": "findings",
        "title": "Detection findings",
        "generated_at": datetime.now(UTC).replace(tzinfo=None, microsecond=0),
        "ctinv_version": __version__,
        "database": database,
        "scope": {"rules": rule_text, "time_range": _time_range(start, end)},
        "summary": _findings_summary(stored, findings, datasets, warning, rule_text),
        "datasets": datasets,
        "anonymised": warning,
        "moments": _cut(moments, limits.moments),
        "periods": None,
        "findings": findings,
        "graph": None,
        "blast": None,
        "iocs": {k: v for k, v in iocs.items() if k != "full"},
        "limitations": _limitations(
            con,
            datasets,
            [
                _stmt(
                    "Findings depend on each rule's logic and thresholds; known false "
                    "positives and gaps are listed in each rule file."
                )
            ],
        ),
    }
    _evidence(con, model, {})
    runs = _table(
        con,
        "SELECT rule_id, rule_sha256, parameters, overrides, detected_at FROM rule_runs "
        "QUALIFY row_number() OVER (PARTITION BY rule_id ORDER BY detected_at DESC) = 1 "
        "ORDER BY rule_id",
    )
    data = {
        "format": FINDINGS_FORMAT,
        "ctinv_version": __version__,
        "generated_at": model["generated_at"],
        "database": database,
        "scope": {"rules": rules, "start": start, "end": end},
        "rule_runs": runs,
        "datasets": datasets,
        "findings": stored,
        "key_moments": moments,
        "iocs": iocs["full"],
    }
    return Report("findings", model, data)


def _findings_summary(
    stored: list[dict],
    findings: dict,
    datasets: list[dict],
    warning: dict | None,
    rule_text: str,
) -> list[dict[str, Any]]:
    if not stored:
        return [_stmt(f"No findings match ({rule_text}).")]
    first = min(stored, key=lambda f: (f["first_seen"], f["finding_id"]))
    last = max(stored, key=lambda f: (f["last_seen"], f["finding_id"]))
    statements = [
        _stmt(
            f"{_n(len(stored), 'finding')} of {_n(findings['rules'], 'rule')} ({rule_text}), "
            f"from {_t(first['first_seen'])} to {_t(last['last_seen'])} UTC, in "
            f"{_n(len(datasets), 'dataset')}: " + ", ".join(d["name"] for d in datasets) + ".",
            [first["event_ids"][0], last["event_ids"][0]],
        )
    ]
    severities: dict[str, list] = defaultdict(list)
    for f in stored:
        severities[f["severity"]].append(f)
    order = ("critical", "high", "medium", "low")
    ranked = sorted(severities.items(), key=lambda item: order.index(item[0]))
    statements.append(
        _stmt(
            "By severity: " + ", ".join(f"{sev} {len(fs):,}" for sev, fs in ranked) + ".",
            [fs[0]["event_ids"][0] for _, fs in ranked],
        )
    )
    statements.append(
        _stmt(
            "By ATT&CK tactic (a finding counts under each of its rule's tactics): "
            + ", ".join(f"{t['name']} {t['total']:,}" for t in findings["tactics"])
            + ".",
            [t["rows"][0]["evidence"][0] for t in findings["tactics"]],
        )
    )
    by_rule: dict[str, list] = defaultdict(list)
    for f in stored:
        by_rule[f["rule_id"]].append(f)
    top = sorted(by_rule.items(), key=lambda item: (-len(item[1]), item[0]))
    statements.append(
        _stmt(
            "Rules: "
            + "; ".join(
                f"{rule} ({_technique(fs[0])}, {fs[0]['severity']}) {len(fs):,}, "
                f"{sum(f['evidence_count'] for f in fs):,} evidence events"
                for rule, fs in top
            )
            + ".",
            [fs[0]["event_ids"][0] for _, fs in top[:5]],
        )
    )
    if warning:
        statements.append(_anonymised_statement(warning))
    return statements


# --- output ------------------------------------------------------------------


def write_report(report: Report, out_dir: Path, redact: bool = False) -> list[Path]:
    """Write ``<kind>-<UTC time>.md``, ``.html`` and ``.json`` into ``out_dir``.

    With ``redact``, account IDs and access keys are masked in all three files
    with the same masks.
    """
    from ctinv.render import render_html, render_markdown

    stamp = report.model["generated_at"].strftime("%Y%m%dT%H%M%SZ")
    out_dir.mkdir(parents=True, exist_ok=True)
    stem, n = f"{report.kind}-{stamp}", 1
    while any((out_dir / f"{stem}{ext}").exists() for ext in (".md", ".html", ".json")):
        n += 1
        stem = f"{report.kind}-{stamp}-{n}"
    model, data = report.model, report.data
    if redact:
        redactor = Redactor()
        model, data = redactor.walk(model), redactor.walk(data)
    model = model | {"redacted": redact, "json_file": f"{stem}.json"}
    data = data | {"redacted": redact}
    paths = [out_dir / f"{stem}{ext}" for ext in (".md", ".html", ".json")]
    paths[0].write_text(render_markdown(model), encoding="utf-8")
    paths[1].write_text(render_html(model), encoding="utf-8")
    dump_json(data, paths[2])
    report.model = model  # what was written, e.g. for the console summary
    return paths
