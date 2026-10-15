"""Detection rules: YAML metadata plus a SQL query over the ``events`` table.

A rule file (``src/ctinv/rules/<id>.yml``) holds the rule's metadata (ATT&CK
mapping, severity, rationale, known false positives) next to its logic, a
DuckDB query. The query returns one row per finding with exactly three columns:

* ``principal``: who the finding is about (may be NULL)
* ``summary``: one line describing what happened
* ``evidence_event_ids``: the eventIDs the finding is derived from (VARCHAR[])

Everything else (time span, outcome, datasets, a stable finding ID) is derived
from the evidence events by the framework. A finding without evidence cannot
exist: the framework rejects empty evidence and eventIDs that are not in the
database, and the ``findings`` table enforces non-empty evidence with a CHECK.
"""

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib.resources import files
from importlib.resources.abc import Traversable
from typing import Any

import duckdb
import yaml

from ctinv import macros

SEVERITIES = ("low", "medium", "high", "critical")
# Tactic short names of MITRE ATT&CK Enterprise v20.0 (Defense Evasion no longer
# exists since v19; it was split into Stealth and Defense Impairment).
TACTICS = (
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "stealth",
    "defense-impairment",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
)
OUTPUT_COLUMNS = {"principal": "VARCHAR", "summary": "VARCHAR", "evidence_event_ids": "VARCHAR[]"}
_RULE_ID = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")
_TECHNIQUE_ID = re.compile(r"T\d{4}(\.\d{3})?")
_REQUIRED = {
    "id",
    "title",
    "severity",
    "attack",
    "description",
    "rationale",
    "false_positives",
    "query",
}
_OPTIONAL = {"known_gaps", "parameters"}


class RuleError(ValueError):
    """A rule file is invalid, or its query broke the output contract."""


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    technique_id: str
    technique_name: str
    former_technique_ids: tuple[str, ...]
    tactics: tuple[str, ...]
    description: str
    rationale: str
    false_positives: tuple[str, ...]
    known_gaps: tuple[str, ...]
    parameters: dict[str, Any]
    query: str
    sha256: str
    source: str = field(compare=False)

    @property
    def technique_label(self) -> str:
        """The ATT&CK ID as shown to readers, with any pre-v19 ID it replaced."""
        if not self.former_technique_ids:
            return self.technique_id
        return f"{self.technique_id} (formerly {', '.join(self.former_technique_ids)})"


def _text(data: dict, key: str, source: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RuleError(f"{source}: '{key}' must be a non-empty string")
    return value.strip()


def _texts(data: dict, key: str, source: str, *, required: bool) -> tuple[str, ...]:
    value = data.get(key, [] if not required else None)
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        raise RuleError(f"{source}: '{key}' must be a list of non-empty strings")
    if required and not value:
        raise RuleError(f"{source}: '{key}' must not be empty")
    return tuple(v.strip() for v in value)


def parse_rule(text: str, source: str) -> Rule:
    """Validate a rule file's content and return the rule."""
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise RuleError(f"{source}: a rule file must contain a mapping")
    missing, unknown = _REQUIRED - set(data), set(data) - _REQUIRED - _OPTIONAL
    if missing or unknown:
        raise RuleError(f"{source}: missing keys {sorted(missing)}, unknown keys {sorted(unknown)}")

    rule_id = _text(data, "id", source)
    if not _RULE_ID.fullmatch(rule_id):
        raise RuleError(f"{source}: id {rule_id!r} must be lowercase words joined by '-'")
    severity = _text(data, "severity", source)
    if severity not in SEVERITIES:
        raise RuleError(f"{source}: severity must be one of {SEVERITIES}")

    attack = data["attack"]
    if not isinstance(attack, dict) or set(attack) - {"technique", "name", "formerly", "tactics"}:
        raise RuleError(
            f"{source}: 'attack' needs technique, name, tactics and optionally formerly"
        )
    technique = _text(attack, "technique", f"{source} attack")
    formerly = _texts(attack, "formerly", f"{source} attack", required=False)
    for tid in (technique, *formerly):
        if not _TECHNIQUE_ID.fullmatch(tid):
            raise RuleError(f"{source}: {tid!r} is not an ATT&CK technique ID")
    tactics = _texts(attack, "tactics", f"{source} attack", required=True)
    if set(tactics) - set(TACTICS):
        raise RuleError(f"{source}: unknown tactics {sorted(set(tactics) - set(TACTICS))}")

    parameters = data.get("parameters", {})
    if not isinstance(parameters, dict) or not all(
        isinstance(k, str) and isinstance(v, int | float | str | bool)
        for k, v in parameters.items()
    ):
        raise RuleError(f"{source}: 'parameters' must map names to numbers, strings or booleans")

    return Rule(
        id=rule_id,
        title=_text(data, "title", source),
        severity=severity,
        technique_id=technique,
        technique_name=_text(attack, "name", f"{source} attack"),
        former_technique_ids=formerly,
        tactics=tactics,
        description=_text(data, "description", source),
        rationale=_text(data, "rationale", source),
        false_positives=_texts(data, "false_positives", source, required=True),
        known_gaps=_texts(data, "known_gaps", source, required=False),
        parameters=dict(parameters),
        query=_text(data, "query", source),
        sha256=hashlib.sha256(text.encode()).hexdigest(),
        source=source,
    )


def builtin_rules_dir() -> Traversable:
    return files("ctinv") / "rules"


def load_rules(directory: Traversable | None = None) -> list[Rule]:
    """Load every ``*.yml`` rule of a directory (default: the built-in rules), sorted by id."""
    directory = directory or builtin_rules_dir()
    rules = []
    for entry in sorted(directory.iterdir(), key=lambda e: e.name):
        if entry.name.endswith(".yml"):
            rule = parse_rule(entry.read_text(encoding="utf-8"), entry.name)
            if entry.name != f"{rule.id}.yml":
                raise RuleError(f"{entry.name}: file name must be '{rule.id}.yml'")
            rules.append(rule)
    return rules


@dataclass(frozen=True)
class RuleResult:
    rule: Rule
    findings: int
    evidence_events: int
    outcomes: dict[str, int]
    elapsed_seconds: float


def _utc_now() -> str:
    return datetime.now(UTC).replace(tzinfo=None).isoformat(sep=" ", timespec="seconds")


def run_rules(con: duckdb.DuckDBPyConnection, rules: list[Rule]) -> list[RuleResult]:
    """Run the rules in one transaction, replacing each rule's previous findings."""
    macros.register(con)
    detected_at = _utc_now()
    results = []
    con.execute("BEGIN TRANSACTION")
    try:
        for rule in rules:
            results.append(_run_rule(con, rule, detected_at))
        con.execute("COMMIT")
    except BaseException:
        con.execute("ROLLBACK")
        raise
    return results


def _run_rule(con: duckdb.DuckDBPyConnection, rule: Rule, detected_at: str) -> RuleResult:
    started = time.monotonic()
    try:
        con.execute(
            f"CREATE OR REPLACE TEMP TABLE rule_raw AS SELECT * FROM (\n{rule.query}\n) AS q",
            rule.parameters or None,
        )
    except duckdb.Error as exc:
        raise RuleError(f"{rule.id}: query failed: {exc}") from exc
    names = [row[0] for row in con.execute("DESCRIBE rule_raw").fetchall()]
    if sorted(names) != sorted(OUTPUT_COLUMNS):
        raise RuleError(
            f"{rule.id}: query must return exactly {sorted(OUTPUT_COLUMNS)}, got {names}"
        )
    try:
        # Casting here spares rules from typing e.g. a NULL principal.
        con.execute(
            "CREATE OR REPLACE TEMP TABLE rule_output AS SELECT "
            + ", ".join(
                f"CAST({name} AS {kind}) AS {name}" for name, kind in OUTPUT_COLUMNS.items()
            )
            + " FROM rule_raw"
        )
    except duckdb.Error as exc:
        raise RuleError(f"{rule.id}: output has the wrong types: {exc}") from exc
    (empty,) = con.execute(
        "SELECT count(*) FROM rule_output WHERE evidence_event_ids IS NULL "
        "OR len(list_filter(evidence_event_ids, lambda e: e IS NOT NULL)) = 0"
    ).fetchone()
    if empty:
        raise RuleError(f"{rule.id}: {empty} finding(s) without evidence")

    con.execute(
        """
        CREATE OR REPLACE TEMP TABLE rule_findings AS
        SELECT row_number() OVER () AS n, principal, summary,
               list_sort(list_distinct(evidence_event_ids)) AS evidence
        FROM rule_output
        """
    )
    con.execute(
        "CREATE OR REPLACE TEMP TABLE rule_evidence AS "
        "SELECT n, unnest(evidence) AS event_id FROM rule_findings"
    )
    (unknown,) = con.execute(
        "SELECT count(*) FROM rule_evidence r ANTI JOIN events e ON e.event_id = r.event_id"
    ).fetchone()
    if unknown:
        raise RuleError(f"{rule.id}: {unknown} evidence eventID(s) are not in the events table")
    (repeated,) = con.execute(
        "SELECT count(*) - count(DISTINCT evidence) FROM rule_findings"
    ).fetchone()
    if repeated:
        raise RuleError(f"{rule.id}: {repeated} finding(s) repeat another finding's evidence")

    con.execute("DELETE FROM findings WHERE rule_id = ?", [rule.id])
    con.execute(
        """
        INSERT INTO findings
        SELECT substr(sha256($rule_id || '|' || array_to_string(f.evidence, ',')), 1, 24),
               $rule_id, $title, $severity, $technique_id, $technique_name,
               $former::VARCHAR[], $tactics::VARCHAR[],
               f.principal, f.summary,
               min(e.event_time), max(e.event_time),
               CASE WHEN count(e.error_code) = 0 THEN 'succeeded'
                    WHEN count(e.error_code) = count(*) THEN 'failed'
                    ELSE 'partly failed' END,
               len(f.evidence), f.evidence,
               list_sort(list_distinct(list(e.dataset))),
               $detected_at::TIMESTAMP
        FROM rule_findings f
        JOIN rule_evidence r ON r.n = f.n
        JOIN events e ON e.event_id = r.event_id
        GROUP BY f.n, f.principal, f.summary, f.evidence
        """,
        {
            "rule_id": rule.id,
            "title": rule.title,
            "severity": rule.severity,
            "technique_id": rule.technique_id,
            "technique_name": rule.technique_name,
            "former": list(rule.former_technique_ids),
            "tactics": list(rule.tactics),
            "detected_at": detected_at,
        },
    )
    (findings,) = con.execute("SELECT count(*) FROM rule_findings").fetchone()
    (evidence_events,) = con.execute(
        "SELECT count(DISTINCT event_id) FROM rule_evidence"
    ).fetchone()
    outcomes = dict(
        con.execute(
            "SELECT outcome, count(*) FROM findings WHERE rule_id = ? GROUP BY 1 ORDER BY 1",
            [rule.id],
        ).fetchall()
    )
    elapsed = time.monotonic() - started
    con.execute(
        "INSERT INTO rule_runs VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            rule.id,
            rule.sha256,
            json.dumps(rule.parameters),
            detected_at,
            findings,
            evidence_events,
            elapsed,
        ],
    )
    return RuleResult(rule, findings, evidence_events, outcomes, elapsed)
