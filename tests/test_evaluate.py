"""Evaluation logic with synthetic labels: scoring rules, isolation, review sample, CLI."""

import hashlib
import json
from datetime import datetime
from pathlib import Path

import pytest
import yaml

from cloudtrail_events import iam_user, make_db, root
from ctinv import evaluate as ev
from ctinv.cli import main
from ctinv.detect import apply_overrides, load_rules, run_rules
from ctinv.ingest import plan_files
from ctinv.schema import connect

T0 = datetime(2023, 1, 1, 0, 0, 0)


def at(seconds: int) -> datetime:
    return datetime(2023, 1, 1, 0, seconds // 60, seconds % 60)


def finding(fid: str, rule: str, technique: str, evidence: list[str], start: int = 0, end=None):
    return ev.Finding(
        fid, rule, technique, at(start), at(end or start), "succeeded", tuple(evidence)
    )


def detection(findings: list[ev.Finding], sources: dict[str, str] | None = None, **stats):
    events = {
        e: ev.Event(e, T0, (sources or {}).get(e, "iam.amazonaws.com"), "X", "f")
        for f in findings
        for e in f.evidence
    }
    file_stats = ev.FileStats(stats.get("records", 1), 1, 0, 0, None, stats.get("first", T0), T0, 0)
    return ev.Detection(findings, events, {stats.get("name", "f"): file_stats})


# --------------------------------------------------------------------------- small helpers


def test_technique_matches_same_parent_or_sub_technique_only() -> None:
    assert ev.technique_matches("T1098.001", "T1098.001")
    assert ev.technique_matches("T1098.001", "T1098")  # rule sub-technique, label parent
    assert ev.technique_matches("T1098", "T1098.003")  # rule parent, label sub-technique
    assert not ev.technique_matches("T1098.001", "T1098.003")  # siblings
    assert not ev.technique_matches("T1580", "T1526")


def test_attack_entry_shows_the_former_id() -> None:
    changed = ev.attack_entry({"id": "T1685.002", "name": "N", "stated": "T1562.008 (revoked)"})
    assert changed["label"] == "T1685.002 (formerly T1562.008)"
    assert changed["former"] == ["T1562.008"]
    assert ev.attack_entry({"id": "T1580", "name": "N", "stated": "T1580"})["label"] == "T1580"


def test_timing_shows_the_range_between_first_evidence_and_complete_finding() -> None:
    first = ev._first_finding(
        [finding("a", "r", "T1", ["e1"], 5, 65), finding("b", "r", "T1", ["e2"], 30, 40)], at(0)
    )
    assert first["first_evidence_after_seconds"] == 5
    assert first["finding_complete_after_seconds"] == 40  # b completes first
    assert ev.timing(first) == "+5 s to +40 s"
    assert ev.timing(None) == "-"


# --------------------------------------------------------------------------- development set


def dev_labels() -> dict:
    def technique(outcome="detonated", events=1, v20=None):
        return {
            "outcome": outcome,
            "attack_events": events,
            "attack_window": ["2023-01-01T00:00:10Z", "2023-01-01T00:00:20Z"] if events else None,
            "attack_v20": v20 or [],
        }

    creds = [{"id": "T1098.001", "name": "Additional Cloud Credentials", "stated": "T1098.001"}]
    return {
        "techniques": {
            "aws.t.detected": technique(v20=creds),
            "aws.t.undocumented": technique(),
            "aws.t.missed": technique(),
            "aws.t.failed": technique("detonated, every attack call returned an error"),
            "aws.t.rds": technique(),
            "aws.t.never": technique("not detonated (warm-up only)", 0),
        },
        "events": [
            {"id": "a1", "role": "attack", "technique": "aws.t.detected", "documented": True},
            {"id": "a2", "role": "attack", "technique": "aws.t.undocumented", "documented": False},
            {"id": "a3", "role": "attack", "technique": "aws.t.missed", "documented": True},
            {"id": "a4", "role": "attack", "technique": "aws.t.failed", "documented": True},
            {"id": "a5", "role": "attack", "technique": "aws.t.rds", "documented": True},
            {"id": "w1", "role": "warm-up", "technique": "aws.t.missed", "documented": None},
            {"id": "c1", "role": "clean-up", "technique": None, "documented": None},
            {"id": "bg1", "role": "background", "technique": None, "documented": None},
        ],
    }


def test_development_scoring_applies_the_role_rules() -> None:
    findings = [
        finding("f1", "credentials-created-for-other-user", "T1098.001", ["a1", "w1"], 12, 12),
        finding("f2", "discovery-burst", "T1580", ["a2", "bg1"], 5, 15),
        finding("f3", "cloudtrail-tampering", "T1685.002", ["w1", "c1"]),  # scaffolding only
        finding("f4", "root-account-usage", "T1078.004", ["bg1"]),  # background only
        finding("f5", "cloudtrail-tampering", "T1685.002", ["a4"], 10),
        finding("f6", "snapshot-or-image-shared", "T1537", ["a5"], 11),
    ]
    result = ev.score_development(dev_labels(), detection(findings, {"a5": "rds.amazonaws.com"}))
    by = {t["technique"]: t for t in result["techniques"]}

    assert by["aws.t.detected"]["status"] == "detected"
    assert by["aws.t.detected"]["detected_strict"] is True
    assert by["aws.t.detected"]["technique_matched"] is True
    assert by["aws.t.detected"]["first_finding"]["first_evidence_after_seconds"] == 2

    # Only an undocumented attack call was flagged: detected, but not in the strict variant.
    assert by["aws.t.undocumented"]["status"] == "detected"
    assert by["aws.t.undocumented"]["detected_strict"] is False
    assert by["aws.t.undocumented"]["technique_matched"] is None  # no ATT&CK ID stated
    # The burst began 5 s before the attack (with a background event).
    assert by["aws.t.undocumented"]["first_finding"]["first_evidence_after_seconds"] == -5

    # A finding on the technique's warm-up does not detect it.
    assert by["aws.t.missed"]["status"] == "missed"
    assert by["aws.t.failed"]["status"] == "detected"
    assert by["aws.t.failed"]["attempt_failed"] is True
    assert by["aws.t.rds"]["status"] == "detected"
    assert by["aws.t.rds"]["detected_without_separately_reported"] is False
    assert by["aws.t.rds"]["separately_reported"] == [ev.RDS_EXTENSION]
    assert by["aws.t.never"]["status"] == "out-of-scope"
    assert by["aws.t.never"]["detected_strict"] is None

    totals = result["totals"]
    assert totals["in_scope"] == 5 and totals["out_of_scope"] == 1
    assert totals["detected"] == {"detected": 4, "of": 5}
    assert totals["detected_strict"] == {"detected": 3, "of": 5}
    assert totals["technique_matched"] == {"detected": 1, "of": 1}
    assert totals["detected_without_separately_reported"] == {"detected": 3, "of": 5}
    assert totals["attempt_failed_detected"] == {"detected": 1, "of": 1}
    assert totals["findings"] == {
        "attack": 4,
        "lab scaffolding only": 1,
        "unlabelled background": 1,
    }


def test_development_scoring_rejects_unlabelled_evidence() -> None:
    with pytest.raises(ev.EvaluationError, match="has no label"):
        ev.score_development(dev_labels(), detection([finding("f", "r", "T1", ["zz"])]))


# --------------------------------------------------------------------------- test set


def splunk_labels() -> dict:
    def entry(path, *ids):
        return {
            "path": path,
            "scenario": path.split("/")[0],
            "records": 1,
            "technique_source": "descriptor field mitre_technique",
            "attack_v20": [{"id": i, "name": f"name {i}", "stated": i} for i in ids],
        }

    return {
        "files": [
            entry("hit/f.json", "T1078.004"),
            entry("quiet/f.json", "T1078.004"),
            entry("data-events/f.json", "T1530"),
            entry("odd-label/f.json", "T1110.002"),
            entry("unlabelled/f.json"),
            entry("exposed/f.json", "T1201"),
        ]
    }


def label_review(**changes) -> dict:
    files = {
        "hit/f.json": {"status": "in-scope", "content": "root signs in"},
        "quiet/f.json": {"status": "in-scope", "content": "root signs in again"},
        "data-events/f.json": {
            "status": "out-of-scope",
            "content": "GetObject only",
            "reason": "data events only",
        },
        "odd-label/f.json": {
            "status": "label-ambiguous",
            "content": "ModifyDBInstance",
            "reason": "a password reset is not password cracking",
        },
        "unlabelled/f.json": {"status": "no-label", "content": "RunInstances", "reason": "none"},
        "exposed/f.json": {"status": "in-scope", "content": "DeleteAccountPasswordPolicy"},
    }
    files.update(changes)
    return {"files": files, "techniques": {"T1201": {"exposed_before_split": "seen in 2026"}}}


def test_test_set_scoring_per_technique() -> None:
    detections = {
        "hit/f.json": detection(
            [finding("h", "root-account-usage", "T1078.004", ["e1"], 30, 90)], first=at(0)
        ),
        "quiet/f.json": detection([]),
        "data-events/f.json": detection([finding("d", "discovery-burst", "T1580", ["e2"])]),
        "odd-label/f.json": detection([]),
        "unlabelled/f.json": detection([finding("u", "discovery-burst", "T1580", ["e3"])]),
        "exposed/f.json": detection([]),
    }
    result = ev.score_test(splunk_labels(), label_review(), detections)
    by = {t["technique"]: t for t in result["techniques"]}

    hit = by["T1078.004"]
    assert hit["status"] == "detected"  # any counted file detected
    assert (hit["files_detected"], hit["files_counted"]) == (1, 2)
    assert hit["technique_matched"] is True
    assert hit["rules"] == ["root-account-usage"]
    assert hit["label_sources"] == ["descriptor field mitre_technique"]
    assert hit["first_finding"]["first_evidence_after_seconds"] == 30
    assert hit["first_finding"]["finding_complete_after_seconds"] == 90

    # Out of scope stays out of the denominator even though a rule fired on it.
    assert by["T1530"]["status"] == "out-of-scope"
    assert by["T1530"]["fired_on_excluded_files"] == ["discovery-burst"]
    assert by["T1530"]["rules"] == []
    assert by["T1110.002"]["status"] == "label-ambiguous"
    assert by["T1201"]["status"] == "missed"
    assert by["T1201"]["exposed_before_split"] == "seen in 2026"

    totals = result["totals"]
    assert totals["techniques"] == 4 and totals["in_scope"] == 2
    assert totals["detected"] == {"detected": 1, "of": 2}
    assert totals["detected_excluding_exposed"] == {"detected": 1, "of": 1}
    assert totals["every_counted_file_detected"] == {"detected": 0, "of": 2}
    assert totals["excluded_counted_as_missed"] == {"detected": 1, "of": 4}
    assert totals["excluded"] == {"out-of-scope": 1, "label-ambiguous": 1}
    assert totals["unlabelled_files_with_findings"] == 1


def test_test_set_scoring_checks_record_counts() -> None:
    detections = {e["path"]: detection([]) for e in splunk_labels()["files"]}
    detections["hit/f.json"] = detection([], records=7)
    with pytest.raises(ev.EvaluationError, match="7 records read"):
        ev.score_test(splunk_labels(), label_review(), detections)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"hit/f.json": {"status": "maybe", "content": "x"}}, "status must be one of"),
        ({"hit/f.json": {"status": "out-of-scope", "content": "x"}}, "needs a reason"),
        ({"hit/f.json": {"status": "in-scope", "content": ""}}, "'content'"),
        ({"hit/f.json": {"status": "no-label", "content": "x", "reason": "y"}}, "no-label"),
        ({"extra/f.json": {"status": "in-scope", "content": "x"}}, "exactly the labelled files"),
    ],
)
def test_label_review_is_validated(tmp_path: Path, change: dict, message: str) -> None:
    path = tmp_path / "review.yml"
    path.write_text(yaml.safe_dump(label_review(**change)))
    with pytest.raises(ev.EvaluationError, match=message):
        ev.load_label_review(path, splunk_labels())


def test_test_set_needs_a_label_review(tmp_path: Path) -> None:
    with pytest.raises(ev.EvaluationError, match="only evaluated after its labels were reviewed"):
        ev.load_label_review(tmp_path / "missing.yml", splunk_labels())


# --------------------------------------------------------------------------- isolation


def test_reused_event_ids_get_their_own_ids_identical_repeats_stay(tmp_path: Path) -> None:
    first = iam_user(1)
    variant = iam_user(1, userIdentity={**first["userIdentity"], "userName": "bob"})
    source = tmp_path / "in.json"
    source.write_text("".join(json.dumps(r) + "\n" for r in [first, first, variant, iam_user(2)]))
    out = tmp_path / "out.json"
    assert ev.keep_reused_ids(source, out) == 1
    ids = [json.loads(line)["eventID"] for line in out.read_text().splitlines()]
    one, two = first["eventID"], iam_user(2)["eventID"]
    assert ids == [one, one, f"{one}-variant-1", two]


def list_calls(first: int, count: int) -> list[dict]:
    return [iam_user(first + i, eventName=f"ListThing{first + i}") for i in range(count)]


def test_each_file_is_evaluated_alone(tmp_path: Path) -> None:
    """Ten List calls per file: a burst of 20 only exists if the files are combined."""
    paths = []
    for name, first in (("a.json", 0), ("b.json", 10)):
        path = tmp_path / name
        path.write_text("".join(json.dumps(r) + "\n" for r in list_calls(first, 10)))
        paths.append(path)
    rules = [r for r in load_rules() if r.id == "discovery-burst"]
    plans = plan_files(paths, tmp_path, "test")

    separate = [ev.detect_isolated([plan], rules) for plan in plans]
    combined = ev.detect_isolated(plans, rules)

    assert [d.findings for d in separate] == [[], []]
    assert [f.rule_id for f in combined.findings] == ["discovery-burst"]
    stats = separate[0].files["a.json"]
    assert (stats.records_read, stats.events, stats.first_event) == (10, 10, at(0))


# --------------------------------------------------------------------------- review sample


def root_days(days: int) -> list[dict]:
    return [root(n, eventTime=f"2023-01-{n + 1:02d}T00:00:00Z") for n in range(days)]


def review_db(tmp_path: Path, days: int = 5) -> Path:
    db = make_db(tmp_path / "db", root_days(days), dataset="flaws_cloud")
    with connect(db) as con:
        run_rules(con, load_rules())
    return db


def test_sample_is_reproducible_and_a_smaller_one_is_a_prefix(tmp_path: Path) -> None:
    db = review_db(tmp_path)
    rules = load_rules()
    with connect(db) as con:
        three = ev.draw_sample(con, rules, "flaws_cloud", 3, "seed")
        again = ev.draw_sample(con, rules, "flaws_cloud", 3, "seed")
        two = ev.draw_sample(con, rules, "flaws_cloud", 2, "seed")
        other = ev.draw_sample(con, rules, "flaws_cloud", 3, "other seed")
    ids = [f["finding_id"] for f in three["findings"]]
    assert three == again
    assert three["population"]["root-account-usage"] == 5
    assert len(ids) == 3 and all(f["rule_id"] == "root-account-usage" for f in three["findings"])
    assert [f["finding_id"] for f in two["findings"]] == ids[:2]
    assert {f["finding_id"] for f in other["findings"]} != set(ids) or len(ids) == 5
    expected = sorted(ids, key=lambda i: hashlib.sha256(f"seed:{i}".encode()).hexdigest())
    assert ids == expected


def test_sample_needs_findings_of_the_unchanged_rules(tmp_path: Path) -> None:
    db = review_db(tmp_path)
    rules = load_rules()
    with connect(db) as con:
        run_rules(con, apply_overrides(rules, ["discovery-burst.min_apis=5"]))
        with pytest.raises(ev.EvaluationError, match="changed parameters"):
            ev.draw_sample(con, rules, "flaws_cloud", 3, "seed")


def test_review_file_round_trip_and_mismatch(tmp_path: Path) -> None:
    db = review_db(tmp_path)
    rules = load_rules()
    with connect(db) as con:
        sample = ev.draw_sample(con, rules, "flaws_cloud", 2, "seed")
        bigger = ev.draw_sample(con, rules, "flaws_cloud", 3, "seed")
    path = tmp_path / "review.yml"
    ev.write_review_file(path, sample)
    with pytest.raises(ev.EvaluationError, match="not overwritten"):
        ev.write_review_file(path, sample)

    document = ev.read_review_file(path)
    document["findings"][0]["label"] = "benign-true-positive"
    path.write_text(yaml.safe_dump(document))
    summary = ev.summarise_review(sample, ev.read_review_file(path), path)
    root_usage = summary["rules"]["root-account-usage"]
    assert (root_usage["population"], root_usage["sampled"], root_usage["reviewed"]) == (5, 2, 1)
    assert root_usage["benign-true-positive"] == 1
    assert summary["rules"]["discovery-burst"]["sampled"] == 0  # rules without findings listed

    with pytest.raises(ev.EvaluationError, match="per_rule"):
        ev.summarise_review(bigger, ev.read_review_file(path), path)
    document["findings"][0]["label"] = "probably fine"
    path.write_text(yaml.safe_dump(document))
    with pytest.raises(ev.EvaluationError, match="label must be one of"):
        ev.read_review_file(path)


# --------------------------------------------------------------------------- command line


def write_dataset(data_dir: Path, name: str, files: dict[str, list[dict]]) -> list[dict]:
    """Write files under data_dir/raw/<name>/ and list them in MANIFEST.json."""
    entries = []
    for rel, records in files.items():
        path = data_dir / "raw" / name / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(json.dumps(r) + "\n" for r in records))
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append({"path": rel, "sha256": digest, "records": len(records)})
    manifest = data_dir / "MANIFEST.json"
    data = json.loads(manifest.read_text()) if manifest.exists() else {"datasets": {}}
    data["datasets"][name] = {"directory": f"raw/{name}", "files": entries}
    manifest.write_text(json.dumps(data))
    return entries


def synthetic_project(tmp_path: Path) -> tuple[Path, Path, Path]:
    data_dir, labels_dir = tmp_path / "data", tmp_path / "labels"
    labels_dir.mkdir()
    tampering = iam_user(
        1,
        eventSource="cloudtrail.amazonaws.com",
        eventName="StopLogging",
        requestParameters={"name": "main"},
        eventTime="2023-01-01T00:00:05Z",
    )
    dev_events = [iam_user(0), tampering]
    write_dataset(data_dir, "invictus_sigma_aws", {"session.json": dev_events})
    (labels_dir / "invictus_labels.json").write_text(
        json.dumps(
            {
                "dataset": "invictus_sigma_aws",
                "data": {"events": 2},
                "techniques": {
                    "aws.defense-evasion.cloudtrail-stop": {
                        "outcome": "detonated",
                        "attack_events": 1,
                        "attack_window": ["2023-01-01T00:00:05Z", "2023-01-01T00:00:05Z"],
                        "attack_v20": [
                            {
                                "id": "T1685.002",
                                "name": "Disable or Modify Cloud Log",
                                "stated": "T1562.008 (revoked in ATT&CK)",
                            }
                        ],
                    }
                },
                "events": [
                    {"id": dev_events[0]["eventID"], "role": "background", "technique": None},
                    {
                        "id": tampering["eventID"],
                        "role": "attack",
                        "documented": True,
                        "technique": "aws.defense-evasion.cloudtrail-stop",
                    },
                ],
            }
        )
    )
    test_files = {
        "T1685.002/stop/f.json": [tampering],
        # Two different records under one eventID: ingest quarantines the second.
        "T1201/policy/f.json": [
            iam_user(2, eventName="DeleteAccountPasswordPolicy"),
            iam_user(
                2,
                eventSource="cloudtrail.amazonaws.com",
                eventName="StopLogging",
                requestParameters={"name": "main"},
            ),
        ],
    }
    entries = write_dataset(data_dir, "splunk_attack_data", test_files)
    ids = {"T1685.002/stop/f.json": "T1685.002", "T1201/policy/f.json": "T1201"}
    (labels_dir / "splunk_labels.json").write_text(
        json.dumps(
            {
                "dataset": "splunk_attack_data",
                "files": [
                    {
                        **e,
                        "scenario": e["path"].split("/")[1],
                        "technique_source": "descriptor field mitre_technique",
                        "attack_v20": [
                            {"id": ids[e["path"]], "name": "n", "stated": ids[e["path"]]}
                        ],
                    }
                    for e in entries
                ],
            }
        )
    )
    review = tmp_path / "review.yml"
    review.write_text(
        yaml.safe_dump(
            {
                "reviewed_on": "2023-01-02",
                "rule_set_tag": "test-tag",
                "techniques": {"T1201": {"exposed_before_split": "seen early"}},
                "files": {
                    "T1685.002/stop/f.json": {"status": "in-scope", "content": "StopLogging"},
                    "T1201/policy/f.json": {"status": "in-scope", "content": "policy deleted"},
                },
            }
        )
    )
    return data_dir, labels_dir, review


def test_cli_evaluates_both_sets_and_writes_results(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir, labels_dir, review = synthetic_project(tmp_path)
    out_dir = tmp_path / "results"
    args = ["evaluate", "--data-dir", str(data_dir), "--labels-dir", str(labels_dir)]
    assert main([*args, "--label-review", str(review), "--out-dir", str(out_dir)]) == 0

    (json_path,) = out_dir.glob("evaluation-*.json")
    result = json.loads(json_path.read_text())
    assert result["format"] == "ctinv-evaluation/1"
    assert result["test_set"]["totals"]["detected"] == {"detected": 1, "of": 2}
    assert result["test_set"]["totals"]["detected_excluding_exposed"] == {"detected": 1, "of": 1}
    assert result["development_set"]["totals"]["detected"] == {"detected": 1, "of": 1}
    assert {r["id"] for r in result["rule_set"]["rules"]} == {r.id for r in load_rules()}
    assert (
        result["test_set"]["label_review"]["sha256"]
        == hashlib.sha256(review.read_bytes()).hexdigest()
    )

    reused = result["test_set"]["reused_event_ids"]
    assert [
        (f["path"], f["records"], f["quarantined_as_is"], f["renamed"]) for f in reused["files"]
    ] == [("T1201/policy/f.json", 2, 1, 1)]
    assert reused["totals_every_record_kept"]["detected"] == {"detected": 2, "of": 2}
    (differs,) = reused["techniques_that_differ"]
    assert differs["technique"] == "T1201"
    assert (differs["as_is"]["status"], differs["every_record_kept"]["status"]) == (
        "missed",
        "detected",
    )

    (md_path,) = out_dir.glob("evaluation-*.md")
    markdown = md_path.read_text()
    assert "Reused eventIDs" in markdown
    assert "Detected: 1 / 2 in-scope ATT&CK techniques" in markdown
    assert "T1685.002 \\(formerly T1562.008\\)" in markdown
    assert "exposed before the split" in markdown
    assert "Development set (optimistic)" in markdown
    assert "Test set (held out)" in capsys.readouterr().out


def test_cli_refuses_the_test_set_without_a_label_review(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir, labels_dir, _ = synthetic_project(tmp_path)
    args = ["evaluate", "--data-dir", str(data_dir), "--labels-dir", str(labels_dir)]
    assert main([*args, "--label-review", str(tmp_path / "none.yml")]) == 2
    assert "labels were reviewed" in capsys.readouterr().err


def test_cli_review_sample(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = review_db(tmp_path)
    review_file = tmp_path / "evaluation" / "fp_review.yml"
    base = ["evaluate", "--only", "review", "--db", str(db), "--review-file", str(review_file)]
    out_dir = tmp_path / "results"

    assert main([*base, "--out-dir", str(out_dir)]) == 2
    assert "--init-review" in capsys.readouterr().err
    assert main([*base, "--init-review", "--sample-size", "2"]) == 0
    assert "2 findings" in capsys.readouterr().out
    assert main([*base, "--sample-size", "2", "--out-dir", str(out_dir)]) == 0
    (sheet,) = out_dir.glob("evaluation-*-review-sheet.md")
    assert "root-account-usage" in sheet.read_text()
    result = json.loads(next(out_dir.glob("evaluation-*Z.json")).read_text())
    assert result["review_sample"]["rules"]["root-account-usage"]["sampled"] == 2
    assert "test_set" not in result


def test_cli_defaults_match_the_module() -> None:
    from ctinv.cli import build_parser

    args = build_parser().parse_args(["evaluate"])
    assert args.seed == ev.DEFAULT_SEED
    assert args.sample_size == ev.DEFAULT_SAMPLE_SIZE
