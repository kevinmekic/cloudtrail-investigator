"""Tests for the detection framework: rule files, the output contract and findings."""

import json
import textwrap
import urllib.parse
from pathlib import Path

import duckdb
import pytest

from cloudtrail_events import iam_user, make_db, root
from ctinv.cli import main
from ctinv.detect import RuleError, apply_overrides, load_rules, parse_rule, run_rules
from ctinv.schema import connect

LABELS = Path(__file__).resolve().parent.parent / "labels"

RULE = """
id: test-rule
title: Test rule
severity: medium
attack:
  technique: T1078.004
  name: "Valid Accounts: Cloud Accounts"
  tactics: [initial-access]
description: A rule for tests.
rationale: Tests need one.
false_positives: [None.]
query: |
  {query}
"""
SAME_EVIDENCE_TWICE = (
    "SELECT NULL AS principal, summary, ev AS evidence_event_ids FROM (VALUES "
    "('a', [(SELECT min(event_id) FROM events)]), "
    "('b', [(SELECT min(event_id) FROM events)])) t(summary, ev)"
)
EVERY_EVENT = (
    "SELECT identity_arn AS principal, 'event ' || event_name AS summary, "
    "[event_id] AS evidence_event_ids FROM events"
)


def rule(query: str = EVERY_EVENT, **replace: str) -> str:
    text = RULE.format(query=query)
    for old, new in replace.items():
        text = text.replace(old, new)
    return text


def write_rules(directory: Path, *texts: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    for text in texts:
        name = parse_rule(text, "draft").id
        (directory / f"{name}.yml").write_text(text)
    return directory


def run(db: Path, *texts: str):
    with connect(db) as con:
        return run_rules(con, [parse_rule(t, "test") for t in texts])


def findings(db: Path, columns: str = "*") -> list[tuple]:
    with duckdb.connect(str(db), read_only=True) as con:
        return con.execute(f"SELECT {columns} FROM findings ORDER BY finding_id").fetchall()


# --------------------------------------------------------------------------- rule files


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"id: test-rule": "id: Test_Rule"}, "lowercase words"),
        ({"severity: medium": "severity: urgent"}, "severity must be one of"),
        ({"technique: T1078.004": "technique: T1078.4"}, "is not an ATT&CK technique ID"),
        ({"tactics: [initial-access]": "tactics: [defense-evasion]"}, "unknown tactics"),
        ({"false_positives: [None.]": "false_positives: []"}, "must not be empty"),
        ({"rationale: Tests need one.\n": ""}, "missing keys"),
        ({"rationale:": "notes: x\nrationale:"}, "unknown keys"),
        ({"rationale:": "parameters: {limit: [1]}\nrationale:"}, "parameters"),
    ],
)
def test_invalid_rule_files_are_rejected(change: dict[str, str], message: str) -> None:
    with pytest.raises(RuleError, match=message):
        parse_rule(rule(**change), "test.yml")


def test_rule_file_name_must_match_its_id(tmp_path: Path) -> None:
    (tmp_path / "other-name.yml").write_text(rule())
    with pytest.raises(RuleError, match="file name must be 'test-rule.yml'"):
        load_rules(tmp_path)


def test_former_ids_are_shown_with_the_technique() -> None:
    parsed = parse_rule(
        rule(**{"tactics: [initial-access]": "tactics: [initial-access]\n  formerly: [T1562.008]"}),
        "t",
    )
    assert parsed.technique_label == "T1078.004 (formerly T1562.008)"


# --------------------------------------------------------------------------- running


def test_findings_carry_evidence_and_derived_fields(tmp_path: Path) -> None:
    db = make_db(tmp_path, [iam_user(1), iam_user(2, errorCode="AccessDenied")])
    (result,) = run(db, rule())
    assert (result.findings, result.evidence_events, result.outcomes) == (
        2,
        2,
        {"failed": 1, "succeeded": 1},
    )
    rows = findings(
        db, "rule_id, technique_id, tactics, evidence_event_ids, evidence_count, outcome, datasets"
    )
    assert {r[3][0] for r in rows} == {
        "00000000-0000-0000-0000-000000000001",
        "00000000-0000-0000-0000-000000000002",
    }
    assert all(r[:3] == ("test-rule", "T1078.004", ["initial-access"]) and r[4] == 1 for r in rows)
    assert all(r[6] == ["test"] for r in rows)


def test_a_finding_spans_its_evidence_and_reports_mixed_outcomes(tmp_path: Path) -> None:
    db = make_db(tmp_path, [iam_user(1), iam_user(5, errorCode="AccessDenied")])
    grouped = (
        "SELECT 'alice' AS principal, 'all' AS summary, "
        "list(event_id) AS evidence_event_ids FROM events"
    )
    run(db, rule(grouped))
    ((first, last, outcome, count),) = findings(
        db, "first_seen::VARCHAR, last_seen::VARCHAR, outcome, evidence_count"
    )
    assert (first, last, outcome, count) == (
        "2023-01-01 00:00:01",
        "2023-01-01 00:00:05",
        "partly failed",
        2,
    )


def test_rerun_replaces_findings_with_identical_ids(tmp_path: Path) -> None:
    db = make_db(tmp_path, [iam_user(1), root(2)])
    run(db, rule())
    first = findings(db, "finding_id")
    run(db, rule())
    assert findings(db, "finding_id") == first
    with duckdb.connect(str(db), read_only=True) as con:
        runs = con.execute(
            "SELECT rule_id, findings, length(rule_sha256) FROM rule_runs"
        ).fetchall()
    assert runs == [("test-rule", 2, 64), ("test-rule", 2, 64)]


def test_parameters_are_passed_to_the_query(tmp_path: Path) -> None:
    db = make_db(tmp_path, [iam_user(1), iam_user(2, eventName="DeleteTrail")])
    text = rule(EVERY_EVENT + " WHERE event_name = $name").replace(
        "rationale:", "parameters: {name: DeleteTrail}\nrationale:"
    )
    run(db, text)
    assert findings(db, "summary") == [("event DeleteTrail",)]


PARAMETRISED = rule(EVERY_EVENT + " WHERE event_name = $name").replace(
    "rationale:",
    "parameters: {name: DeleteTrail, limit: 5, ratio: 0.5, strict: false}\nrationale:",
)


def test_overrides_are_typed_like_the_defaults() -> None:
    base = parse_rule(PARAMETRISED, "t")
    (changed,) = apply_overrides(
        [base],
        [
            "test-rule.name=StopLogging",
            "test-rule.limit=7",
            "test-rule.ratio=2",
            "test-rule.strict=TRUE",
            "test-rule.limit = 9",
        ],
    )
    assert changed.parameters == {"name": "StopLogging", "limit": 9, "ratio": 2.0, "strict": True}
    assert changed.overrides == changed.parameters
    assert base.parameters["limit"] == 5 and base.overrides == {}


@pytest.mark.parametrize(
    ("assignment", "message"),
    [
        ("test-rule.limit", "expected RULE.PARAMETER=VALUE"),
        ("limit=3", "expected RULE.PARAMETER=VALUE"),
        ("other-rule.limit=3", "rule 'other-rule' is not run"),
        ("test-rule.lmit=3", r"has no parameter 'lmit' \(parameters: limit, name, ratio, strict\)"),
        ("test-rule.limit=3.5", "expected an integer"),
        ("test-rule.ratio=high", "expected a number"),
        ("test-rule.strict=yes", "expected true or false"),
    ],
)
def test_invalid_overrides_are_rejected(assignment: str, message: str) -> None:
    with pytest.raises(RuleError, match=message):
        apply_overrides([parse_rule(PARAMETRISED, "t")], [assignment])


def test_overrides_change_the_run_and_are_recorded(tmp_path: Path) -> None:
    db = make_db(
        tmp_path,
        [iam_user(1, eventName="DeleteTrail"), iam_user(2, eventName="StopLogging")],
    )
    text = rule(EVERY_EVENT + " WHERE event_name = $name").replace(
        "rationale:", "parameters: {name: DeleteTrail}\nrationale:"
    )
    with connect(db) as con:
        run_rules(con, [parse_rule(text, "t")])
        run_rules(con, apply_overrides([parse_rule(text, "t")], ["test-rule.name=StopLogging"]))
        runs = con.execute(
            "SELECT parameters::VARCHAR, overrides::VARCHAR FROM rule_runs ORDER BY rowid"
        ).fetchall()
    assert findings(db, "summary") == [("event StopLogging",)]
    assert runs == [
        ('{"name": "DeleteTrail"}', "{}"),
        ('{"name": "StopLogging"}', '{"name": "StopLogging"}'),
    ]


def test_old_databases_get_the_overrides_column(tmp_path: Path) -> None:
    db = tmp_path / "old.duckdb"
    with duckdb.connect(str(db)) as con:
        con.execute(
            "CREATE TABLE rule_runs (rule_id VARCHAR NOT NULL, rule_sha256 VARCHAR NOT NULL, "
            "parameters JSON NOT NULL, detected_at TIMESTAMP NOT NULL, findings INTEGER NOT NULL, "
            "evidence_events INTEGER NOT NULL, elapsed_seconds DOUBLE NOT NULL)"
        )
        con.execute("INSERT INTO rule_runs VALUES ('r', 'h', '{}', now()::TIMESTAMP, 0, 0, 0)")
    with connect(db) as con:
        assert con.execute("SELECT overrides::VARCHAR FROM rule_runs").fetchall() == [("{}",)]


@pytest.mark.parametrize(
    ("query", "message"),
    [
        (
            "SELECT 'x' AS principal, [event_id] AS evidence_event_ids FROM events",
            "must return exactly",
        ),
        (
            "SELECT NULL AS principal, 's' AS summary, []::VARCHAR[] AS evidence_event_ids",
            "without evidence",
        ),
        (
            "SELECT NULL AS principal, 's' AS summary, [NULL]::VARCHAR[] AS evidence_event_ids",
            "without evidence",
        ),
        (
            "SELECT NULL AS principal, 's' AS summary, ['no-such-event'] AS evidence_event_ids",
            "not in the events table",
        ),
        (SAME_EVIDENCE_TWICE, "repeat another finding"),
        ("SELECT 'p' AS principal, 's' AS summary, 42 AS evidence_event_ids", "wrong types"),
        ("SELECT * FROM no_such_table", "query failed"),
    ],
)
def test_contract_violations_fail_and_keep_previous_findings(
    tmp_path: Path, query: str, message: str
) -> None:
    db = make_db(tmp_path, [iam_user(1)])
    run(db, rule())
    before = findings(db)
    with pytest.raises(RuleError, match=message):
        run(db, rule(query))
    assert findings(db) == before


def test_database_rejects_a_finding_without_evidence(tmp_path: Path) -> None:
    with connect(tmp_path / "x.duckdb") as con, pytest.raises(duckdb.ConstraintException):
        con.execute(
            "INSERT INTO findings VALUES ('f', 'r', 't', 'low', 'T1078', 'n', [], ['x'], "
            "NULL, 's', now()::TIMESTAMP, now()::TIMESTAMP, 'succeeded', 0, [], [], "
            "now()::TIMESTAMP)"
        )


# --------------------------------------------------------------------------- helpers


ADMIN = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        (json.dumps(ADMIN), True),
        (json.dumps(ADMIN, indent=4), True),
        (urllib.parse.quote(json.dumps(ADMIN)), True),
        (json.dumps({"Statement": {"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}}), True),
        (
            json.dumps(
                {
                    "Statement": [
                        {"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"},
                        ADMIN["Statement"][0],
                    ]
                }
            ),
            True,
        ),
        (json.dumps({"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}), False),
        (
            json.dumps({"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}),
            False,
        ),
        (
            json.dumps(
                {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::b"}]}
            ),
            False,
        ),
        ("{not json", False),
        ("{}", False),
        (None, False),
    ],
)
def test_grants_full_admin(document: str | None, expected: bool) -> None:
    from ctinv import macros

    con = duckdb.connect()
    macros.register(con)
    assert (
        con.execute("SELECT ctinv_grants_full_admin(?::VARCHAR)", [document]).fetchone()[0]
        is expected
    )


# --------------------------------------------------------------------------- CLI and built-in rules


def test_detect_needs_an_existing_database(tmp_path: Path) -> None:
    assert main(["detect", "--db", str(tmp_path / "missing.duckdb")]) == 2
    assert not (tmp_path / "missing.duckdb").exists()


def test_detect_rejects_unknown_rule_ids(tmp_path: Path) -> None:
    db = make_db(tmp_path, [iam_user(1)])
    rules = write_rules(tmp_path / "rules", rule())
    assert main(["detect", "--db", str(db), "--rules-dir", str(rules), "--rule", "nope"]) == 2
    assert main(["detect", "--db", str(db), "--rules-dir", str(rules), "--rule", "test-rule"]) == 0
    assert len(findings(db)) == 1


def test_detect_applies_and_reports_overrides(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = make_db(tmp_path, [iam_user(1, eventName="DeleteTrail")])
    text = rule(EVERY_EVENT + " WHERE event_name = $name").replace(
        "rationale:", "parameters: {name: StopLogging}\nrationale:"
    )
    rules = write_rules(tmp_path / "rules", text)
    base = ["detect", "--db", str(db), "--rules-dir", str(rules)]
    assert main([*base, "--set", "test-rule.name=DeleteTrail"]) == 0
    assert 'test-rule: name = "DeleteTrail" (default "StopLogging")' in capsys.readouterr().out
    assert findings(db, "summary") == [("event DeleteTrail",)]
    assert main([*base, "--set", "test-rule.nme=DeleteTrail"]) == 2
    assert "has no parameter 'nme'" in capsys.readouterr().err


def test_builtin_rules_match_attack_v20() -> None:
    attack = json.loads((LABELS / "sources.json").read_text())["attack"]
    assert attack["version"] == "20.0"
    techniques = attack["techniques"]
    for builtin in load_rules():
        entry = techniques[builtin.technique_id]
        assert entry["status"] == "active", builtin.id
        assert builtin.technique_name.endswith(entry["name"]), builtin.id
        assert set(builtin.tactics) <= set(entry["tactics"]), builtin.id
        for former in builtin.former_technique_ids:
            assert techniques[former].get("revoked_by") == [builtin.technique_id], builtin.id


def test_rule_text_is_dedented_yaml() -> None:
    # Guards the test template itself: YAML must parse to the expected query.
    assert parse_rule(rule(), "t").query == textwrap.dedent(EVERY_EVENT).strip()
