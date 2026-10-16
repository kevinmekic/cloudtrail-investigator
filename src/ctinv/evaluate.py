"""Evaluation: detection rate per attack technique against labelled data.

Two datasets, never merged into one number:

* **Test set** (held out, the primary result): Splunk attack_data scenario
  files, grouped by the ATT&CK technique Splunk states for each file
  (``labels/splunk_labels.json``, IDs normalised to ATT&CK v20.0). Which files
  count, and why others do not, comes from a review of the labels that was
  written before the rules were run on the test set
  (``evaluation/splunk_label_review.yml``); without it the test set is not
  evaluated.
* **Development set** ("optimistic": the rules were written on it): Invictus
  Sigma-AWS, per Stratus Red Team technique, scored with the event roles of
  ``labels/invictus_labels.json``.

Ground truth comes only from those files, never from rule output. The unit of
analysis is the technique: several scenario files or runs of one technique are
one result, not independent samples. Every rate carries its denominator.

Each test-set scenario file is ingested into its own in-memory database and the
rules run on it alone, so a finding can only rest on events of the scenario it
is counted for. The development set is one lab session and runs as one.

A third, separate part draws a reproducible random sample of findings from a
database (flaws.cloud) for manual review; it is a reviewed sample, not a
measured false-positive rate.
"""

import hashlib
import json
import tempfile
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any

import duckdb
import yaml

from ctinv import __version__
from ctinv.detect import Rule, run_rules
from ctinv.ingest import DatasetResolutionError, FilePlan, Ingester, plan_files
from ctinv.render import md_escape
from ctinv.schema import connect

EVALUATION_FORMAT = "ctinv-evaluation/1"
# Roles of labels/invictus_labels.json. Findings resting only on lab scaffolding
# count neither as true nor as false positives; "unresolved" (a Stratus call
# that could not be attributed to a run) is treated the same way.
ATTACK_ROLE = "attack"
BACKGROUND_ROLE = "background"
SCAFFOLDING_ROLES = frozenset(
    {"warm-up", "preflight", "revert", "clean-up", "side-effect", "unresolved"}
)
FINDING_CATEGORIES = ("attack", "lab scaffolding only", "unlabelled background")
# Statuses of a test-set file in the label review.
FILE_STATUSES = ("in-scope", "out-of-scope", "label-ambiguous", "no-label")
# Labels of the manual review of sampled findings.
REVIEW_LABELS = ("true-positive", "benign-true-positive", "false-positive", "unclear")
DEFAULT_SAMPLE_SIZE = 10
DEFAULT_SEED = "ctinv-review-1"
# Modules whose code decides which findings exist; hashed into the results.
PIPELINE_MODULES = ("reader.py", "normalize.py", "schema.py", "ingest.py", "macros.py", "detect.py")
RDS_EXTENSION = (
    "rests only on RDS snapshot sharing, which snapshot-or-image-shared covers beyond the "
    "two EC2 APIs (snapshot and image attributes) it was specified for"
)


class EvaluationError(ValueError):
    """Labels, the label review, the data or a findings database do not allow an evaluation."""


@dataclass(frozen=True)
class Event:
    event_id: str
    time: datetime
    source: str
    name: str
    source_file: str


@dataclass(frozen=True)
class Finding:
    finding_id: str
    rule_id: str
    technique_id: str
    first_seen: datetime
    last_seen: datetime
    outcome: str
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class FileStats:
    records_read: int
    events: int
    duplicates: int
    quarantined: int
    file_error: str | None
    first_event: datetime | None
    last_event: datetime | None
    error_events: int


@dataclass(frozen=True)
class Detection:
    """Findings of the rules over one isolated set of files."""

    findings: list[Finding]
    events: dict[str, Event]  # every evidence event, by eventID
    files: dict[str, FileStats]  # by source_file


# --------------------------------------------------------------------------- helpers


def _iso(value: datetime | None) -> str | None:
    return value.isoformat(sep=" ") if value else None


def parse_utc(text: str) -> datetime:
    """'2023-07-10T11:54:42Z' -> naive UTC datetime, as stored in the database."""
    value = datetime.fromisoformat(text)
    return value.astimezone(UTC).replace(tzinfo=None) if value.tzinfo else value


def technique_matches(rule_technique: str, label_technique: str) -> bool:
    """Same ATT&CK technique, or one is a sub-technique of the other (siblings do not match)."""
    return (
        rule_technique == label_technique
        or rule_technique.split(".")[0] == label_technique
        or label_technique.split(".")[0] == rule_technique
    )


def attack_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """An ATT&CK v20.0 entry of a label file with the pre-v19 ID it replaced, if any."""
    stated = (entry.get("stated") or "").split()
    former = [stated[0]] if stated and stated[0] != entry["id"] else []
    label = entry["id"] + (f" (formerly {former[0]})" if former else "")
    return {"id": entry["id"], "name": entry.get("name"), "former": former, "label": label}


def separately_reported(finding: Finding, events: dict[str, Event]) -> str | None:
    """Why a detection resting on this finding is reported separately, or None.

    The rule set was fixed before the evaluation. snapshot-or-image-shared also
    reports RDS DB and cluster snapshots made usable by other accounts, beyond
    the two EC2 APIs it was specified for; a technique detected only through
    that part is shown separately from the main rate.
    """
    if finding.rule_id == "snapshot-or-image-shared" and all(
        events[e].source == "rds.amazonaws.com" for e in finding.evidence
    ):
        return RDS_EXTENSION
    return None


def _first_finding(hits: Sequence[Finding], start: datetime) -> dict[str, Any] | None:
    """Earliest qualifying finding relative to the attack start.

    A batch run cannot tell when a rule's condition was first met, only that it
    lies between a finding's first and last evidence event. So the earliest
    alert lies between the smallest first and the smallest last evidence time
    over all qualifying findings.
    """
    if not hits:
        return None
    first = min(hits, key=lambda f: (f.first_seen, f.finding_id))
    complete = min(hits, key=lambda f: (f.last_seen, f.finding_id))
    return {
        "attack_start": _iso(start),
        "first_evidence_after_seconds": (first.first_seen - start).total_seconds(),
        "first_evidence_finding": first.finding_id,
        "finding_complete_after_seconds": (complete.last_seen - start).total_seconds(),
        "complete_finding": complete.finding_id,
    }


def _fraction(hits: int, total: int) -> dict[str, int]:
    return {"detected": hits, "of": total}


def _finding_row(finding: Finding, extra: dict[str, Any]) -> dict[str, Any]:
    return {
        "finding_id": finding.finding_id,
        "rule_id": finding.rule_id,
        "technique_id": finding.technique_id,
        "first_seen": _iso(finding.first_seen),
        "last_seen": _iso(finding.last_seen),
        "outcome": finding.outcome,
        "evidence_count": len(finding.evidence),
        **extra,
    }


# --------------------------------------------------------------------------- detection


def rule_set(rules: Sequence[Rule]) -> dict[str, Any]:
    """What produced the findings: each rule file's hash and the pipeline modules' hashes."""
    package = files("ctinv")
    return {
        "rules": [
            {
                "id": r.id,
                "sha256": r.sha256,
                "technique": r.technique_label,
                "overrides": r.overrides,
            }
            for r in rules
        ],
        "modules": {
            name: hashlib.sha256((package / name).read_bytes()).hexdigest()
            for name in PIPELINE_MODULES
        },
    }


def detect_isolated(plans: Sequence[FilePlan], rules: Sequence[Rule]) -> Detection:
    """Ingest the files into a new in-memory database and run the rules on them alone."""
    con = connect(":memory:", "1GB")
    try:
        with tempfile.TemporaryDirectory(prefix="ctinv-evaluate-") as tmp:
            ingester = Ingester(con, Path(tmp))
            results = {plan.source_file: ingester.ingest_file(plan) for plan in plans}
        run_rules(con, list(rules))
        findings = [
            Finding(*row[:6], tuple(row[6]))
            for row in con.execute(
                "SELECT finding_id, rule_id, technique_id, first_seen, last_seen, outcome, "
                "evidence_event_ids FROM findings ORDER BY first_seen, rule_id, finding_id"
            ).fetchall()
        ]
        events = {
            row[0]: Event(*row)
            for row in con.execute(
                "SELECT event_id, event_time, event_source, event_name, source_file FROM events "
                "WHERE event_id IN (SELECT unnest(evidence_event_ids) FROM findings)"
            ).fetchall()
        }
        spans = {
            row[0]: row[1:]
            for row in con.execute(
                "SELECT source_file, min(event_time), max(event_time), count(error_code) "
                "FROM events GROUP BY source_file"
            ).fetchall()
        }
    finally:
        con.close()
    stats = {}
    for name, r in results.items():
        first, last, errors = spans.get(name, (None, None, 0))
        stats[name] = FileStats(
            r.records_read,
            r.inserted,
            r.duplicates,
            r.quarantined,
            r.file_error,
            first,
            last,
            errors,
        )
    return Detection(findings, events, stats)


# --------------------------------------------------------------------------- inputs


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise EvaluationError(f"{path} not found") from None


def dataset_directory(data_dir: Path, dataset: str) -> Path:
    manifest = data_dir / "MANIFEST.json"
    if not manifest.exists():
        raise EvaluationError(f"{manifest} not found; fetch the datasets first")
    entry = load_json(manifest).get("datasets", {}).get(dataset)
    if entry is None:
        raise EvaluationError(
            f"dataset {dataset} is not in {manifest}; fetch it with "
            f"scripts/fetch_datasets.py --dataset {dataset}"
        )
    return data_dir / entry["directory"]


def _plans(paths: Sequence[Path], data_dir: Path) -> list[FilePlan]:
    """Plan files through the manifest, which also checks every file's SHA-256."""
    try:
        return plan_files(paths, data_dir, None)
    except (DatasetResolutionError, FileNotFoundError) as exc:
        raise EvaluationError(str(exc)) from None


def load_label_review(path: Path, labels: dict[str, Any]) -> dict[str, Any]:
    """Read and validate the test set's label review against the label file."""
    if not path.exists():
        raise EvaluationError(
            f"{path} not found: the test set is only evaluated after its labels were "
            "reviewed (written before the rules are run on it)"
        )
    review = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(review, dict) or not isinstance(review.get("files"), dict):
        raise EvaluationError(f"{path}: needs a 'files' mapping")
    by_path = {entry["path"]: entry for entry in labels["files"]}
    missing = sorted(set(by_path) - set(review["files"]))
    unknown = sorted(set(review["files"]) - set(by_path))
    if missing or unknown:
        raise EvaluationError(
            f"{path}: review must cover exactly the labelled files "
            f"(missing {missing[:3]}{'...' if len(missing) > 3 else ''}, unknown {unknown[:3]})"
        )
    for name, item in review["files"].items():
        where = f"{path}: {name}"
        if not isinstance(item, dict) or item.get("status") not in FILE_STATUSES:
            raise EvaluationError(f"{where}: status must be one of {', '.join(FILE_STATUSES)}")
        if not isinstance(item.get("content"), str) or not item["content"].strip():
            raise EvaluationError(f"{where}: 'content' must describe what the review saw")
        if item["status"] != "in-scope" and not (item.get("reason") or "").strip():
            raise EvaluationError(f"{where}: status {item['status']} needs a reason")
        if (item["status"] == "no-label") != (not by_path[name]["attack_v20"]):
            raise EvaluationError(f"{where}: 'no-label' is for files without a technique label")
    labelled = {a["id"] for entry in labels["files"] for a in entry["attack_v20"]}
    techniques = review.get("techniques") or {}
    if not isinstance(techniques, dict) or set(techniques) - labelled:
        raise EvaluationError(f"{path}: 'techniques' may only name labelled ATT&CK IDs")
    return review


# --------------------------------------------------------------------------- development set


def score_development(labels: dict[str, Any], detection: Detection) -> dict[str, Any]:
    """Per Stratus technique: detected / missed / out of scope, with the role rules applied."""
    roles = {e["id"]: e for e in labels["events"]}
    hits: dict[str, list[tuple[Finding, bool]]] = {}
    rows, categories, per_rule = [], Counter(), {}
    for finding in detection.findings:
        missing = [e for e in finding.evidence if e not in roles]
        if missing:
            raise EvaluationError(f"{finding.rule_id}: evidence event {missing[0]} has no label")
        evidence = [roles[e] for e in finding.evidence]
        unknown = {e["role"] for e in evidence} - {ATTACK_ROLE, BACKGROUND_ROLE} - SCAFFOLDING_ROLES
        if unknown:
            raise EvaluationError(f"unknown event role(s) {sorted(unknown)} in the labels")
        attack = sorted({e["technique"] for e in evidence if e["role"] == ATTACK_ROLE})
        documented = {
            e["technique"] for e in evidence if e["role"] == ATTACK_ROLE and e.get("documented")
        }
        if attack:
            category = "attack"
        elif any(e["role"] == BACKGROUND_ROLE for e in evidence):
            category = "unlabelled background"
        else:
            category = "lab scaffolding only"
        for technique in attack:
            hits.setdefault(technique, []).append((finding, technique in documented))
        categories[category] += 1
        per_rule.setdefault(finding.rule_id, Counter())[category] += 1
        rows.append(
            _finding_row(
                finding,
                {
                    "category": category,
                    "attack_techniques": attack,
                    "roles": dict(Counter(e["role"] for e in evidence).most_common()),
                    "separately_reported": separately_reported(finding, detection.events),
                },
            )
        )

    techniques = []
    for key, label in labels["techniques"].items():
        ids = [attack_entry(a) for a in label["attack_v20"] if a.get("id")]
        found = hits.get(key, [])
        status, reason = ("detected" if found else "missed"), None
        if label["outcome"].startswith("not detonated") or not label["attack_events"]:
            status = "out-of-scope"
            reason = f"no attack in the data: {label['outcome']}"
        in_scope = status != "out-of-scope"
        strict = [f for f, documented in found if documented]
        matched = [f for f, _ in found for a in ids if technique_matches(f.technique_id, a["id"])]
        core = [f for f, _ in found if not separately_reported(f, detection.events)]
        techniques.append(
            {
                "technique": key,
                "attack": ids,
                "stated_outside_attack": [a["stated"] for a in label["attack_v20"] if not a["id"]],
                "status": status,
                "reason": reason,
                "attack_events": label["attack_events"],
                "attempt_failed": "every attack call returned an error" in label["outcome"],
                "rules": sorted({f.rule_id for f, _ in found}),
                "detected_strict": bool(strict) if in_scope else None,
                "strict_rules": sorted({f.rule_id for f in strict}),
                "technique_matched": bool(matched) if in_scope and ids else None,
                "detected_without_separately_reported": bool(core) if in_scope else None,
                "separately_reported": sorted(
                    {r for f, _ in found if (r := separately_reported(f, detection.events))}
                ),
                "first_finding": _first_finding(
                    [f for f, _ in found], parse_utc(label["attack_window"][0])
                )
                if found
                else None,
            }
        )

    in_scope = [t for t in techniques if t["status"] != "out-of-scope"]
    with_ids = [t for t in in_scope if t["attack"]]
    failed = [t for t in in_scope if t["attempt_failed"]]

    def count(items: list[dict], key: str = "status", value: Any = "detected") -> int:
        return sum(1 for t in items if t[key] == value)

    totals = {
        "techniques": len(techniques),
        "in_scope": len(in_scope),
        "out_of_scope": len(techniques) - len(in_scope),
        "detected": _fraction(count(in_scope), len(in_scope)),
        "detected_strict": _fraction(count(in_scope, "detected_strict", True), len(in_scope)),
        "technique_matched": _fraction(count(with_ids, "technique_matched", True), len(with_ids)),
        "detected_without_separately_reported": _fraction(
            count(in_scope, "detected_without_separately_reported", True), len(in_scope)
        ),
        "attempt_failed_detected": _fraction(count(failed), len(failed)),
        "findings": {c: categories[c] for c in FINDING_CATEGORIES},
        "findings_per_rule": {
            rule: {c: n[c] for c in FINDING_CATEGORIES} for rule, n in sorted(per_rule.items())
        },
    }
    return {"techniques": techniques, "totals": totals, "findings": rows}


# --------------------------------------------------------------------------- test set


def score_test(
    labels: dict[str, Any], review: dict[str, Any], detections: dict[str, Detection]
) -> dict[str, Any]:
    """Per ATT&CK technique over the reviewed scenario files (any in-scope file detected)."""
    exposed = {
        tid: (item or {}).get("exposed_before_split")
        for tid, item in (review.get("techniques") or {}).items()
    }
    file_rows, by_technique = [], {}
    for entry in labels["files"]:
        path, item = entry["path"], review["files"][entry["path"]]
        detection = detections[path]
        (stats,) = detection.files.values()
        if stats.records_read != entry["records"]:
            raise EvaluationError(
                f"{path}: {stats.records_read} records read, the labels say {entry['records']}"
            )
        ids = [attack_entry(a) for a in entry["attack_v20"]]
        findings = detection.findings
        row = {
            "path": path,
            "scenario": entry["scenario"],
            "attack": ids,
            "technique_source": entry["technique_source"],
            "status": item["status"],
            "reason": item.get("reason"),
            "content": item["content"],
            "records": stats.records_read,
            "events": stats.events,
            "duplicates": stats.duplicates,
            "quarantined": stats.quarantined,
            "file_error": stats.file_error,
            "error_events": stats.error_events,
            "first_event": _iso(stats.first_event),
            "last_event": _iso(stats.last_event),
            "detected": bool(findings),
            "rules": sorted({f.rule_id for f in findings}),
            "first_finding": _first_finding(findings, stats.first_event) if findings else None,
            "findings": [
                _finding_row(f, {"separately_reported": separately_reported(f, detection.events)})
                for f in findings
            ],
        }
        file_rows.append(row)
        for attack in ids:
            technique = by_technique.setdefault(attack["id"], {"attack": attack, "files": []})
            technique["files"].append((row, findings))

    techniques = []
    for tid in sorted(by_technique, key=lambda t: [int(p) for p in t[1:].split(".")]):
        attack, members = by_technique[tid]["attack"], by_technique[tid]["files"]
        counted = [(row, f) for row, f in members if row["status"] == "in-scope"]
        if counted:
            detected = [(row, f) for row, f in counted if row["detected"]]
            status, reason = ("detected" if detected else "missed"), None
        else:
            statuses = {row["status"] for row, _ in members}
            status = "out-of-scope" if statuses == {"out-of-scope"} else "label-ambiguous"
            reason = "; ".join(f"{row['scenario']}: {row['reason']}" for row, _ in members)
            detected = []
        found = [f for _, fs in detected for f in fs]
        core = [row for row, fs in detected if any(not _separate(f, row, detections) for f in fs)]
        techniques.append(
            {
                "technique": tid,
                "attack": attack,
                "status": status,
                "reason": reason,
                "exposed_before_split": exposed.get(tid),
                "label_sources": sorted({row["technique_source"] for row, _ in members}),
                "files": [
                    {"path": row["path"], "status": row["status"], "detected": row["detected"]}
                    for row, _ in members
                ],
                "files_counted": len(counted),
                "files_detected": len(detected),
                "rules": sorted({f.rule_id for f in found}),
                "fired_on_excluded_files": sorted(
                    {f.rule_id for row, fs in members if row["status"] != "in-scope" for f in fs}
                ),
                "technique_matched": any(technique_matches(f.technique_id, tid) for f in found)
                if counted
                else None,
                "detected_without_separately_reported": bool(core) if counted else None,
                "separately_reported": sorted(
                    {r for row, fs in detected for f in fs if (r := _separate(f, row, detections))}
                ),
                "first_finding": _earliest([row for row, _ in detected]),
            }
        )

    in_scope = [t for t in techniques if t["status"] in ("detected", "missed")]
    unexposed = [t for t in in_scope if not t["exposed_before_split"]]

    def count(items: list[dict], key: str = "status", value: Any = "detected") -> int:
        return sum(1 for t in items if t[key] == value)

    totals = {
        "techniques": len(techniques),
        "in_scope": len(in_scope),
        "excluded": dict(Counter(t["status"] for t in techniques if t not in in_scope)),
        "detected": _fraction(count(in_scope), len(in_scope)),
        "detected_excluding_exposed": _fraction(count(unexposed), len(unexposed)),
        "detected_without_separately_reported": _fraction(
            count(in_scope, "detected_without_separately_reported", True), len(in_scope)
        ),
        "technique_matched": _fraction(count(in_scope, "technique_matched", True), len(in_scope)),
        "every_counted_file_detected": _fraction(
            sum(1 for t in in_scope if t["files_detected"] == t["files_counted"]), len(in_scope)
        ),
        "excluded_counted_as_missed": _fraction(count(in_scope), len(techniques)),
        "files": dict(Counter(row["status"] for row in file_rows)),
        "unlabelled_files_with_findings": sum(
            1 for row in file_rows if row["status"] == "no-label" and row["detected"]
        ),
    }
    return {"techniques": techniques, "totals": totals, "files": file_rows}


def _separate(
    finding: Finding, row: dict[str, Any], detections: dict[str, Detection]
) -> str | None:
    return separately_reported(finding, detections[row["path"]].events)


def _earliest(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    """A technique's first finding: the earliest over its detected scenario files.

    Each file is timed from its own first event (the scenario's start); the
    smallest offsets over the files are taken separately, each with its file.
    """
    timed = [row for row in rows if row["first_finding"]]
    if not timed:
        return None
    first = min(timed, key=lambda r: r["first_finding"]["first_evidence_after_seconds"])
    complete = min(timed, key=lambda r: r["first_finding"]["finding_complete_after_seconds"])
    return {
        "first_evidence_after_seconds": first["first_finding"]["first_evidence_after_seconds"],
        "first_evidence_file": first["path"],
        "finding_complete_after_seconds": complete["first_finding"][
            "finding_complete_after_seconds"
        ],
        "complete_file": complete["path"],
    }


# --------------------------------------------------------------------------- runs


def evaluate_development(data_dir: Path, labels_dir: Path, rules: Sequence[Rule]) -> dict[str, Any]:
    labels = load_json(labels_dir / "invictus_labels.json")
    directory = dataset_directory(data_dir, labels["dataset"])
    detection = detect_isolated(_plans([directory], data_dir), rules)
    events = sum(s.events for s in detection.files.values())
    if events != labels["data"]["events"]:
        raise EvaluationError(
            f"{labels['dataset']}: {events} events ingested, the labels cover "
            f"{labels['data']['events']}"
        )
    result = score_development(labels, detection)
    result["dataset"] = labels["dataset"]
    result["files"] = len(detection.files)
    result["events"] = events
    return result


def evaluate_test(
    data_dir: Path,
    labels_dir: Path,
    review_path: Path,
    rules: Sequence[Rule],
    on_file: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    labels = load_json(labels_dir / "splunk_labels.json")
    review = load_label_review(review_path, labels)
    directory = dataset_directory(data_dir, labels["dataset"])
    detections = {}
    for entry in labels["files"]:
        (plan,) = _plans([directory / entry["path"]], data_dir)
        if plan.sha256 != entry["sha256"]:
            raise EvaluationError(f"{entry['path']}: SHA-256 differs from the label file")
        detections[entry["path"]] = detect_isolated([plan], rules)
        if on_file:
            on_file(entry["path"])
    result = score_test(labels, review, detections)
    result["dataset"] = labels["dataset"]
    result["label_review"] = {
        "file": review_path.as_posix(),
        "sha256": hashlib.sha256(review_path.read_bytes()).hexdigest(),
        "reviewed_on": str(review.get("reviewed_on")),
        "rule_set_tag": review.get("rule_set_tag"),
    }
    return result


# --------------------------------------------------------------------------- review sample


def check_rule_runs(con: duckdb.DuckDBPyConnection, rules: Sequence[Rule]) -> None:
    """The database's findings must come from these rules, unchanged and with defaults."""
    # detected_at has one-second resolution; rule_runs is only appended to, so
    # rowid breaks ties between runs within the same second.
    latest = {
        rule_id: (sha, json.loads(overrides))
        for rule_id, sha, overrides in con.execute(
            "SELECT rule_id, rule_sha256, overrides FROM rule_runs "
            "QUALIFY row_number() OVER (PARTITION BY rule_id ORDER BY detected_at DESC, "
            "rowid DESC) = 1"
        ).fetchall()
    }
    problems = []
    for rule in rules:
        sha, overrides = latest.get(rule.id, (None, {}))
        if sha is None:
            problems.append(f"{rule.id} never ran")
        elif sha != rule.sha256:
            problems.append(f"{rule.id} ran with a different rule file")
        elif overrides:
            problems.append(f"{rule.id} ran with changed parameters {overrides}")
    if problems:
        raise EvaluationError(
            "the database's findings are not from the built-in rules with default parameters "
            "(" + "; ".join(problems) + "); run ctinv detect on it first"
        )


def _sample_key(seed: str, finding_id: str) -> str:
    return hashlib.sha256(f"{seed}:{finding_id}".encode()).hexdigest()


def draw_sample(
    con: duckdb.DuckDBPyConnection,
    rules: Sequence[Rule],
    dataset: str,
    per_rule: int,
    seed: str,
) -> dict[str, Any]:
    """Up to ``per_rule`` findings per rule, chosen by a seeded hash of their IDs.

    Sorting by ``sha256(seed:finding_id)`` is a reproducible random order that
    does not depend on Python's random module; a smaller sample is a prefix of
    a larger one.
    """
    check_rule_runs(con, rules)
    rows = con.execute(
        "SELECT finding_id, rule_id, principal, summary, first_seen, last_seen, outcome, "
        "evidence_count FROM findings WHERE datasets = ?::VARCHAR[]",
        [[dataset]],
    ).fetchall()
    by_rule: dict[str, list[tuple]] = {r.id: [] for r in rules}
    for row in rows:
        by_rule.setdefault(row[1], []).append(row)
    sample = []
    population = {}
    for rule_id, found in by_rule.items():
        population[rule_id] = len(found)
        found.sort(key=lambda row: _sample_key(seed, row[0]))
        for row in found[:per_rule]:
            sample.append(
                {
                    "finding_id": row[0],
                    "rule_id": row[1],
                    "principal": row[2],
                    "summary": row[3],
                    "first_seen": _iso(row[4]),
                    "last_seen": _iso(row[5]),
                    "outcome": row[6],
                    "evidence_count": row[7],
                }
            )
    return {
        "dataset": dataset,
        "seed": seed,
        "per_rule": per_rule,
        "population": population,
        "findings": sample,
    }


def sample_context(con: duckdb.DuckDBPyConnection, finding_id: str) -> dict[str, list]:
    """What a reviewer needs beside the summary: top APIs, sources, user agents, errors."""

    def top(column: str, limit: int = 5) -> list[list]:
        return [
            [value, n]
            for value, n in con.execute(
                f"""
                SELECT {column} AS value, count(*) AS n
                FROM (SELECT unnest(evidence_event_ids) AS event_id FROM findings
                      WHERE finding_id = ?) r
                JOIN events e ON e.event_id = r.event_id
                GROUP BY 1 ORDER BY n DESC, value LIMIT {limit}
                """,
                [finding_id],
            ).fetchall()
        ]

    return {
        "apis": top("replace(e.event_source, '.amazonaws.com', '') || ':' || e.event_name"),
        "source_ips": top("e.source_ip_address", 3),
        "user_agents": top("e.user_agent", 3),
        "errors": top("coalesce(e.error_code, '(none)')", 3),
        "regions": top("e.aws_region", 3),
    }


REVIEW_HEADER = """\
# Manual review of a random sample of findings on flaws.cloud.
#
# flaws.cloud has no ground truth, so this is a reviewed sample, not a measured
# false-positive rate. The sample is reproducible: per rule, the findings are
# ordered by sha256("<seed>:<finding_id>") and the first <per_rule> are taken
# (all of them if a rule has fewer). `ctinv evaluate --db <database>` checks
# that the database still yields exactly these findings.
#
# For each finding, set `label` to one of:
#   true-positive         the evidence shows the behaviour the rule describes, and
#                         nothing in the logs explains it as expected activity
#   benign-true-positive  the evidence shows that behaviour, but it is expected
#                         activity (e.g. the account owner's administration, a
#                         known scanner)
#   false-positive        the evidence does not show the behaviour the rule
#                         describes
#   unclear               the logs do not allow a decision
# and optionally a short `note`. Context for each finding (top APIs, source
# addresses, user agents, errors) is in the review sheet that
# `ctinv evaluate --db <database>` writes next to its results.
"""


def write_review_file(path: Path, sample: dict[str, Any]) -> None:
    if path.exists():
        raise EvaluationError(f"{path} exists; it holds review labels and is not overwritten")
    document = {
        "sample": {k: sample[k] for k in ("dataset", "seed", "per_rule", "population")},
        "findings": [
            {
                **{k: f[k] for k in ("finding_id", "rule_id", "principal", "first_seen")},
                "summary": f["summary"],
                "label": None,
                "note": None,
            }
            for f in sample["findings"]
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        REVIEW_HEADER + "\n" + yaml.safe_dump(document, sort_keys=False, width=100),
        encoding="utf-8",
    )


def read_review_file(path: Path) -> dict[str, Any]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not isinstance(document.get("findings"), list):
        raise EvaluationError(f"{path}: needs 'sample' and 'findings'")
    for item in document["findings"]:
        label = item.get("label")
        if label is not None and label not in REVIEW_LABELS:
            raise EvaluationError(
                f"{path}: {item.get('finding_id')}: label must be one of "
                f"{', '.join(REVIEW_LABELS)} (or empty)"
            )
    return document


def summarise_review(sample: dict[str, Any], document: dict[str, Any], path: Path) -> dict:
    """Combine the drawn sample with the review labels; the two must match exactly."""
    params = document.get("sample") or {}
    for key in ("dataset", "seed", "per_rule"):
        if params.get(key) != sample[key]:
            raise EvaluationError(f"{path}: sample {key} {params.get(key)!r} != {sample[key]!r}")
    reviewed = {item["finding_id"]: item for item in document["findings"]}
    drawn = {f["finding_id"] for f in sample["findings"]}
    if drawn != set(reviewed):
        raise EvaluationError(
            f"{path}: the database yields a different sample than the one reviewed "
            f"({len(drawn - set(reviewed))} new, {len(set(reviewed) - drawn)} gone); "
            "were the rules or the data changed?"
        )
    per_rule = {}
    for f in sample["findings"]:
        item = reviewed[f["finding_id"]]
        entry = per_rule.setdefault(
            f["rule_id"],
            {
                "population": sample["population"][f["rule_id"]],
                "sampled": 0,
                "reviewed": 0,
                **{label: 0 for label in REVIEW_LABELS},
            },
        )
        entry["sampled"] += 1
        if item.get("label"):
            entry["reviewed"] += 1
            entry[item["label"]] += 1
    for rule_id, n in sample["population"].items():
        per_rule.setdefault(
            rule_id,
            {"population": n, "sampled": 0, "reviewed": 0, **{lb: 0 for lb in REVIEW_LABELS}},
        )
    return {
        "kind": "manually reviewed sample (not a measured false-positive rate)",
        "file": path.as_posix(),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "dataset": sample["dataset"],
        "seed": sample["seed"],
        "per_rule": sample["per_rule"],
        "rules": dict(sorted(per_rule.items())),
        "findings": [
            {
                **f,
                "label": reviewed[f["finding_id"]].get("label"),
                "note": reviewed[f["finding_id"]].get("note"),
            }
            for f in sample["findings"]
        ],
    }


# --------------------------------------------------------------------------- output


def _seconds(value: float) -> str:
    sign, value = ("-" if value < 0 else "+"), abs(value)
    if value < 120:
        return f"{sign}{value:.0f} s"
    if value < 7200:
        return f"{sign}{value / 60:.0f} min"
    if value < 172800:
        return f"{sign}{value / 3600:.1f} h"
    return f"{sign}{value / 86400:.1f} d"


def timing(first: dict[str, Any] | None) -> str:
    if not first:
        return "-"
    start = _seconds(first["first_evidence_after_seconds"])
    end = _seconds(first["finding_complete_after_seconds"])
    return start if start == end else f"{start} to {end}"


def _rate(value: dict[str, int]) -> str:
    return f"{value['detected']} / {value['of']}"


def _yes(value: bool | None) -> str:
    return "-" if value is None else ("yes" if value else "no")


def _cell(text: Any) -> str:
    return md_escape("" if text is None else str(text))


def render_markdown(result: dict[str, Any]) -> str:
    """The Markdown summary: per-technique tables with denominators, never one merged rate."""
    lines = [
        "# Detection evaluation",
        "",
        f"Generated {_cell(result['generated_at'])} UTC by ctinv {_cell(result['ctinv_version'])}."
        " Test set and development set are separate results and are never added up.",
        "",
    ]
    test = result.get("test_set")
    if test:
        t = test["totals"]
        lines += [
            "## Test set (held out): Splunk attack_data",
            "",
            f"**Detected: {_rate(t['detected'])} in-scope ATT&CK techniques** "
            f"({t['techniques']} labelled techniques; excluded: "
            + (", ".join(f"{n} {_cell(k)}" for k, n in sorted(t["excluded"].items())) or "none")
            + ").",
            "",
            f"- Without the techniques exposed before the split: "
            f"{_rate(t['detected_excluding_exposed'])}",
            f"- Without detections that rest only on separately reported rule parts: "
            f"{_rate(t['detected_without_separately_reported'])}",
            f"- By a rule mapped to the same ATT&CK technique (or its parent/sub-technique): "
            f"{_rate(t['technique_matched'])}",
            f"- Every counted scenario file of the technique detected: "
            f"{_rate(t['every_counted_file_detected'])}",
            f"- Excluded techniques counted as missed: {_rate(t['excluded_counted_as_missed'])}",
            "",
            "| ATT&CK v20.0 | Name | Label source | Result | Rules | Files detected "
            "| First finding | Notes |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for row in test["techniques"]:
            notes = []
            if row["exposed_before_split"]:
                notes.append("exposed before the split")
            if row["reason"]:
                notes.append(row["reason"])
            if row["separately_reported"] and not row["detected_without_separately_reported"]:
                notes.append("detected only through a separately reported rule part")
            if row["fired_on_excluded_files"]:
                notes.append(
                    "fired on excluded files: " + ", ".join(row["fired_on_excluded_files"])
                )
            lines.append(
                "| "
                + " | ".join(
                    [
                        _cell(row["attack"]["label"]),
                        _cell(row["attack"]["name"]),
                        _cell("; ".join(row["label_sources"])),
                        _cell(row["status"]),
                        _cell(", ".join(row["rules"]) or "-"),
                        f"{row['files_detected']} / {row['files_counted']}"
                        if row["files_counted"]
                        else "-",
                        _cell(timing(row["first_finding"])),
                        _cell("; ".join(notes)),
                    ]
                )
                + " |"
            )
        lines.append("")
    dev = result.get("development_set")
    if dev:
        t = dev["totals"]
        lines += [
            "## Development set (optimistic): Invictus Sigma-AWS",
            "",
            "The rules were written on this dataset, so this result is optimistic.",
            "",
            f"**Detected: {_rate(t['detected'])} in-scope Stratus Red Team techniques** "
            f"({t['out_of_scope']} out of scope by design).",
            "",
            f"- Strict (only documented technique calls count): {_rate(t['detected_strict'])}",
            f"- By a rule mapped to the technique's stated ATT&CK ID (techniques with one): "
            f"{_rate(t['technique_matched'])}",
            f"- Without detections that rest only on separately reported rule parts: "
            f"{_rate(t['detected_without_separately_reported'])}",
            f"- Failed attempts (every attack call returned an error) detected: "
            f"{_rate(t['attempt_failed_detected'])}",
            "- Findings: "
            + ", ".join(f"{n} {_cell(c)}" for c, n in t["findings"].items())
            + " (scaffolding-only and background findings count neither as true nor as "
            "false positives)",
            "",
            "| Stratus technique | ATT&CK v20.0 | Result | Strict | Attempt failed | Rules "
            "| First finding | Notes |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for row in dev["techniques"]:
            notes = [row["reason"]] if row["reason"] else []
            if row["separately_reported"] and not row["detected_without_separately_reported"]:
                notes.append("detected only through a separately reported rule part")
            lines.append(
                "| "
                + " | ".join(
                    [
                        _cell(row["technique"]),
                        _cell(", ".join(a["label"] for a in row["attack"]) or "-"),
                        _cell(row["status"]),
                        _yes(row["detected_strict"]),
                        _yes(row["attempt_failed"]),
                        _cell(", ".join(row["rules"]) or "-"),
                        _cell(timing(row["first_finding"])),
                        _cell("; ".join(notes)),
                    ]
                )
                + " |"
            )
        lines.append("")
    review = result.get("review_sample")
    if review:
        lines += [
            "## Manually reviewed sample (flaws.cloud)",
            "",
            "Not a measured false-positive rate: flaws.cloud has no ground truth. Up to "
            f"{review['per_rule']} random findings per rule, labelled by hand.",
            "",
            "| Rule | Findings | Sampled | Reviewed | "
            + " | ".join(_cell(label) for label in REVIEW_LABELS)
            + " |",
            "|---|---|---|---|" + "---|" * len(REVIEW_LABELS),
        ]
        for rule_id, n in review["rules"].items():
            lines.append(
                f"| {_cell(rule_id)} | {n['population']:,} | {n['sampled']} | {n['reviewed']} | "
                + " | ".join(str(n[label]) for label in REVIEW_LABELS)
                + " |"
            )
        lines.append("")
    rules = result["rule_set"]["rules"]
    lines += [
        "## Rule set",
        "",
        "| Rule | ATT&CK v20.0 | SHA-256 |",
        "|---|---|---|",
        *(f"| {_cell(r['id'])} | {_cell(r['technique'])} | {r['sha256'][:16]}… |" for r in rules),
        "",
    ]
    return "\n".join(lines)


def review_sheet(sample: dict[str, Any], contexts: dict[str, dict]) -> str:
    """Markdown sheet with the context of every sampled finding, for the reviewer."""
    lines = [
        "# Review sheet: sampled findings",
        "",
        f"Dataset {_cell(sample['dataset'])}, seed {_cell(sample['seed'])}, up to "
        f"{sample['per_rule']} findings per rule. Labels go into the review file.",
        "",
    ]
    for f in sample["findings"]:
        ctx = contexts[f["finding_id"]]
        lines += [
            f"## {_cell(f['rule_id'])}: {_cell(f['finding_id'])}",
            "",
            f"- Principal: {_cell(f['principal'] or '-')}",
            f"- Summary: {_cell(f['summary'])}",
            f"- Time: {_cell(f['first_seen'])} to {_cell(f['last_seen'])} UTC, "
            f"outcome {_cell(f['outcome'])}, {f['evidence_count']:,} evidence events",
        ]
        for key, title in (
            ("apis", "APIs"),
            ("source_ips", "Source addresses"),
            ("user_agents", "User agents"),
            ("errors", "Errors"),
            ("regions", "Regions"),
        ):
            lines.append(f"- {title}: " + ", ".join(f"{_cell(v)} ({n:,})" for v, n in ctx[key]))
        lines.append("")
    return "\n".join(lines)


def output_stem(out_dir: Path, generated_at: datetime) -> Path:
    stamp = generated_at.strftime("%Y%m%dT%H%M%SZ")
    stem, n = f"evaluation-{stamp}", 1
    while any((out_dir / f"{stem}{ext}").exists() for ext in (".md", ".json")):
        n += 1
        stem = f"evaluation-{stamp}-{n}"
    return out_dir / stem


def new_result(rules: Sequence[Rule]) -> dict[str, Any]:
    return {
        "format": EVALUATION_FORMAT,
        "generated_at": datetime.now(UTC).replace(tzinfo=None, microsecond=0).isoformat(sep=" "),
        "ctinv_version": __version__,
        "rule_set": rule_set(rules),
    }


def print_result(console: Any, result: dict[str, Any]) -> None:
    """Console summary; the Markdown and JSON files have everything."""
    from rich.markup import escape
    from rich.table import Table

    test = result.get("test_set")
    if test:
        t = test["totals"]
        table = Table(
            title=f"Test set (held out): {_rate(t['detected'])} in-scope ATT&CK techniques "
            "detected",
            title_justify="left",
        )
        for column in ("ATT&CK v20.0", "result", "rules", "files", "first finding", "note"):
            table.add_column(column)
        for row in test["techniques"]:
            note = "exposed before the split" if row["exposed_before_split"] else ""
            table.add_row(
                escape(row["attack"]["label"]),
                row["status"],
                escape(", ".join(row["rules"]) or "-"),
                f"{row['files_detected']}/{row['files_counted']}" if row["files_counted"] else "-",
                timing(row["first_finding"]),
                note,
            )
        console.print(table)
    dev = result.get("development_set")
    if dev:
        t = dev["totals"]
        table = Table(
            title=f"Development set (optimistic): {_rate(t['detected'])} in-scope Stratus "
            f"techniques detected (strict {_rate(t['detected_strict'])})",
            title_justify="left",
        )
        for column in ("Stratus technique", "result", "strict", "failed attempt", "rules"):
            table.add_column(column)
        for row in dev["techniques"]:
            table.add_row(
                escape(row["technique"]),
                row["status"],
                _yes(row["detected_strict"]),
                _yes(row["attempt_failed"]),
                escape(", ".join(row["rules"]) or "-"),
            )
        console.print(table)
    review = result.get("review_sample")
    if review:
        table = Table(
            title="Manually reviewed sample (not a measured false-positive rate)",
            title_justify="left",
        )
        for column in ("rule", "findings", "sampled", "reviewed", *REVIEW_LABELS):
            table.add_column(column, justify="left" if column == "rule" else "right")
        for rule_id, n in review["rules"].items():
            table.add_row(
                rule_id,
                f"{n['population']:,}",
                str(n["sampled"]),
                str(n["reviewed"]),
                *(str(n[label]) for label in REVIEW_LABELS),
            )
        console.print(table)
