"""Tests for reports: structure, evidence, escaping of untrusted fields, redaction."""

import json
import re
from datetime import datetime, timedelta
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import pytest
from markdown_it import MarkdownIt

from cloudtrail_events import ACCOUNT, event, make_db
from ctinv.cli import main
from ctinv.detect import parse_rule, run_rules
from ctinv.investigate import Scope, investigate
from ctinv.render import md_escape, render_html, render_markdown
from ctinv.report import (
    ANONYMISED_FIELDS,
    BURST_EVENTS,
    BURST_SECONDS,
    DEFAULT_LIMITS,
    PERIOD_GAP_SECONDS,
    Limits,
    Report,
    ReportError,
    anonymisation_warning,
    findings_report,
    investigation_report,
    write_report,
)
from ctinv.schema import connect

KEY_A = "AKIAEXAMPLEALICE0001"
KEY_B = "ASIAEXAMPLEROLEB0001"
OTHER_ACCOUNT = "444455556666"
T0 = datetime(2023, 1, 1)
# Attacker-controlled fields: HTML, quotes, Markdown links and tables, autolinks,
# a newline and a right-to-left override.
INJECT_UA = (
    "<script>alert(\"ua\")</script> 'q' | [x](http://evil.example) www.evil.example "
    "a@evil.example `code` <img src=x onerror=alert(1)>\nnext line ‮evil"
)
INJECT_NAME = 'Describe<script>alert(1)</script>"Things|'
SECTIONS = (
    "Executive summary",
    "Timeline",
    "Findings by ATT&CK tactic",
    "Session graph",
    "Blast radius",
    "Indicators (IOCs)",
    "Limitations of the data",
    "Evidence index",
)
RULE = """
id: test-denied-run-instances
title: Denied RunInstances
severity: high
attack:
  technique: T1685.002
  name: "Disable or Modify Tools: Disable or Modify Cloud Log"
  formerly: [T1562.008]
  tactics: [defense-impairment]
description: A rule for tests.
rationale: Tests need one.
false_positives: [None.]
query: |
  SELECT identity_arn AS principal, 'denied calls: ' || count(*) AS summary,
         list(event_id) AS evidence_event_ids
  FROM events WHERE event_name = 'RunInstances' AND error_code IS NOT NULL
  GROUP BY identity_arn
"""


def at(seconds: int, identity: dict[str, Any], **fields: Any) -> dict[str, Any]:
    record = event(seconds, identity, **fields)
    record["eventTime"] = (T0 + timedelta(seconds=seconds)).isoformat() + "Z"
    record["eventID"] = f"00000000-0000-0000-0000-{seconds:012d}"
    return record


ALICE = {
    "type": "IAMUser",
    "principalId": "AIDAEXAMPLEALICE",
    "arn": f"arn:aws:iam::{ACCOUNT}:user/alice",
    "accountId": ACCOUNT,
    "accessKeyId": KEY_A,
    "userName": "alice",
}
ROLE_B = {
    "type": "AssumedRole",
    "principalId": "AROAEXAMPLEROLEB:s",
    "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/B/s",
    "accountId": ACCOUNT,
    "accessKeyId": KEY_B,
    "sessionContext": {
        "sessionIssuer": {
            "type": "Role",
            "principalId": "AROAEXAMPLEROLEB",
            "arn": f"arn:aws:iam::{ACCOUNT}:role/B",
            "accountId": ACCOUNT,
            "userName": "B",
        },
        "attributes": {"creationDate": "2023-01-01T00:00:00Z", "mfaAuthenticated": "false"},
    },
}


def records() -> list[dict[str, Any]]:
    sts = {"eventSource": "sts.amazonaws.com", "eventName": "AssumeRole"}
    run = {"eventSource": "ec2.amazonaws.com", "eventName": "RunInstances"}
    return [
        at(1, ALICE, userAgent=INJECT_UA),
        at(
            60,
            ALICE,
            **sts,
            requestParameters={"roleArn": f"arn:aws:iam::{ACCOUNT}:role/B", "roleSessionName": "s"},
            responseElements={
                "credentials": {"accessKeyId": KEY_B, "sessionToken": "x", "expiration": "x"},
                "assumedRoleUser": {"arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/B/s"},
            },
        ),
        at(
            70,
            ALICE,
            **sts,
            requestParameters={
                "roleArn": f"arn:aws:iam::{OTHER_ACCOUNT}:role/X",
                "roleSessionName": "s",
            },
            errorCode="AccessDenied",
            errorMessage=f"not authorized on arn:aws:iam::{OTHER_ACCOUNT}:role/X",
        ),
        *(at(180 + n, ALICE, **run, errorCode="Client.UnauthorizedOperation") for n in range(12)),
        at(200, ALICE, eventSource="ec2.amazonaws.com", eventName=INJECT_NAME),
        at(
            300,
            ROLE_B,
            eventSource="s3.amazonaws.com",
            eventName="ListBuckets",
            sourceIPAddress="198.51.100.7",
        ),
        *(
            at(
                400 + n,
                ROLE_B,
                eventSource="s3.amazonaws.com",
                eventName="ListBuckets",
                sourceIPAddress="198.51.100.7",
            )
            for n in range(3)
        ),
        at(
            500,
            ROLE_B,
            eventSource="s3.amazonaws.com",
            eventName="GetObject",
            requestParameters={"bucketName": f"logs-{ACCOUNT}", "key": "a"},
            sourceIPAddress="s3.amazonaws.com",
        ),
        # 40 minutes later: a new activity period of the same API and outcome.
        at(2700, ROLE_B, eventSource="s3.amazonaws.com", eventName="ListBuckets"),
    ]


def build(tmp_path: Path, dataset: str = "test", detect: bool = True) -> Path:
    db = make_db(tmp_path / "db", records(), dataset=dataset)
    if detect:
        con = connect(db)
        run_rules(con, [parse_rule(RULE, "test-denied-run-instances.yml")])
        con.close()
    return db


def investigation(db: Path, limits: Limits = DEFAULT_LIMITS) -> Report:
    con = connect(db)
    try:
        inv = investigate(con, Scope(access_key=KEY_A))
        return investigation_report(con, inv, "test.duckdb", limits)
    finally:
        con.close()


@pytest.fixture(scope="module")
def written(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    tmp = tmp_path_factory.mktemp("report")
    report = investigation(build(tmp))
    paths = write_report(report, tmp / "reports")
    return {
        "report": report,
        "paths": paths,
        "md": paths[0].read_text(),
        "html": paths[1].read_text(),
        "json": json.loads(paths[2].read_text()),
    }


# --- structure and evidence --------------------------------------------------


def test_files_are_named_by_kind_and_utc_time(written: dict) -> None:
    names = [p.name for p in written["paths"]]
    stem = names[0][: -len(".md")]
    assert re.fullmatch(r"investigation-\d{8}T\d{6}Z", stem)
    assert names == [f"{stem}.md", f"{stem}.html", f"{stem}.json"]
    assert written["report"].model["json_file"] == f"{stem}.json"


def test_sections_in_order(written: dict) -> None:
    md_headings = re.findall(r"^## (.+)$", written["md"], flags=re.M)
    assert md_headings == list(SECTIONS)
    html_headings = re.findall(r"<h2 id=\"\w+\">(.+?)</h2>", written["html"])
    assert html_headings == [s.replace("&", "&amp;") for s in SECTIONS]


def _rows_with_evidence(model: dict) -> list[tuple[str, dict]]:
    rows = [("moment", m) for m in model["moments"]["rows"]]
    rows += [("period", p) for p in model["periods"]["rows"]]
    rows += [("finding", f) for t in model["findings"]["tactics"] for f in t["rows"]]
    rows += [("session", n) for n in model["graph"]["tree"] if not n["more"]]
    rows += [("not followed", g) for g in model["graph"]["not_followed"]]
    rows += [("resource", x) for s in model["blast"]["services"] for x in s["rows"]]
    rows += [("unnamed", a) for a in model["blast"]["without_resource"]["apis"]]
    rows += [(kind, x) for kind, part in model["iocs"].items() for x in part["rows"]]
    return rows


def test_every_statement_and_row_cites_evidence(written: dict) -> None:
    model = written["report"].model
    for kind, row in _rows_with_evidence(model):
        assert row["evidence"], (kind, row)
    # Statements without evidence are about the data or the database, not events.
    for statement in model["summary"]:
        if not statement["evidence"]:
            assert "anonymised" in statement["text"] or "Detection" in statement["text"]


def test_every_cited_event_is_linked_and_indexed(written: dict) -> None:
    model, html, md = written["report"].model, written["html"], written["md"]
    index = model["evidence_index"]
    cited = {i for _, row in _rows_with_evidence(model) for i in row["evidence"]}
    cited |= {i for s in model["summary"] + model["limitations"] for i in s["evidence"]}
    assert cited == set(index)
    assert [e["n"] for e in model["evidence"]] == list(range(1, len(index) + 1))
    for event_id, n in index.items():
        assert f'<a class="ev" href="#ev-{n}">{event_id}</a>' in html
        assert f'<tr id="ev-{n}">' in html
        assert re.search(rf"^\| {n} \| {re.escape(event_id)} \|", md, flags=re.M)
    # Evidence is listed in time order with its location in the source file.
    times = [e["event_time"] for e in model["evidence"]]
    assert times == sorted(times)
    assert all(e["source_file"] == "events.json" for e in model["evidence"])


def test_summary_states_counts_with_evidence(written: dict) -> None:
    texts = [s["text"] for s in written["report"].model["summary"]]
    assert texts[0].startswith(f"Investigated the long-term key {KEY_A}")
    assert texts[1].startswith("22 events between 2023-01-01 00:00:01 and 2023-01-01 00:45:00")
    assert texts[1].endswith("9 succeeded, 13 denied, 0 failed.")
    assert any(t.startswith("It obtained and used 1 other credential") for t in texts)
    assert any("1 finding of 1 rule" in t for t in texts)


def test_key_moments(written: dict) -> None:
    moments = written["report"].model["moments"]["rows"]
    kinds = [(m["time"].isoformat(), m["kind"], m["session"]) for m in moments]
    assert kinds == [
        ("2023-01-01T00:00:01", "first use of key", "S0"),
        ("2023-01-01T00:00:01", "first success", "S0"),
        ("2023-01-01T00:01:00", "key issued", "S0"),
        ("2023-01-01T00:01:10", "credential request denied", "S0"),
        ("2023-01-01T00:03:00", "first denied burst", "S0"),
        ("2023-01-01T00:03:00", "finding", "S0"),
        ("2023-01-01T00:05:00", "first use of key", "S1"),
    ]
    burst = moments[4]
    assert burst["text"].startswith("First burst of denied calls: 12 within 60 seconds")
    assert "T1685.002 (formerly T1562.008)" in moments[5]["text"]


def test_activity_periods(written: dict) -> None:
    periods = written["report"].model["periods"]
    rows = [(p["session"], p["api"], p["outcome"], p["events"]) for p in periods["rows"]]
    # The four ListBuckets calls within 15 minutes form one period although
    # GetObject happens in between; the call 40 minutes later starts a new one.
    assert ("S1", "s3:ListBuckets", "succeeded", 4) in rows
    assert ("S1", "s3:ListBuckets", "succeeded", 1) in rows
    assert ("S0", "ec2:RunInstances", "denied", 12) in rows
    run = next(p for p in periods["rows"] if p["api"] == "ec2:RunInstances")
    assert run["error_codes"] == [{"code": "Client.UnauthorizedOperation", "events": 12}]
    assert run["evidence"] == [
        "00000000-0000-0000-0000-000000000180",
        "00000000-0000-0000-0000-000000000191",
    ]
    assert periods["total"] == len(periods["rows"])


def test_failed_sign_ins_are_failures_not_successes(tmp_path: Path) -> None:
    # Sign-in events have no errorCode: a failure is recorded in responseElements
    # and the reason in errorMessage.
    sign_in = {"eventSource": "signin.amazonaws.com", "eventName": "ConsoleLogin"}
    failed = {
        "responseElements": {"ConsoleLogin": "Failure"},
        "errorMessage": "Failed authentication",
    }
    records = [at(n, ALICE, **sign_in, **failed) for n in range(1, 13)]
    records.append(at(30, ALICE, **sign_in, responseElements={"ConsoleLogin": "Success"}))
    report = investigation(make_db(tmp_path, records))
    moments = {m["kind"]: m for m in report.model["moments"]["rows"]}
    assert moments["first success"]["evidence"] == ["00000000-0000-0000-0000-000000000030"]
    assert moments["first failed burst"]["text"] == (
        "First burst of failed calls: 12 within 60 seconds "
        "(signin:ConsoleLogin 12; Failed authentication 12)"
    )
    (period,) = [p for p in report.model["periods"]["rows"] if p["outcome"] == "failed"]
    assert (period["api"], period["events"]) == ("signin:ConsoleLogin", 12)
    assert period["error_codes"] == [{"code": "Failed authentication", "events": 12}]
    outcomes = {e["event_id"][-2:]: e["outcome"] for e in report.model["evidence"]}
    assert (outcomes["01"], outcomes["30"]) == ("failed", "succeeded")


def test_period_gap_option(tmp_path: Path) -> None:
    db = build(tmp_path)

    def run(*options: str) -> tuple[dict, str, str]:
        out = tmp_path / "out" / "-".join(options or ("default",))
        argv = ["report", "--db", str(db), "--access-key", KEY_A, "--out-dir", str(out)]
        assert main([*argv, *options]) == 0
        md, html, data = (next(out.glob(f"*{ext}")) for ext in (".md", ".html", ".json"))
        return json.loads(data.read_text()), md.read_text(), html.read_text()

    def list_buckets(data: dict) -> list[tuple[str, str, int]]:
        return [
            (p["first_seen"], p["last_seen"], p["events"])
            for p in data["report"]["activity_periods"]
            if p["api"] == "s3:ListBuckets"
        ]

    data, md, html = run()
    assert data["report"]["period_gap_seconds"] == 900
    # Default: the call 40 minutes after the others starts a new period.
    assert [n for _, _, n in list_buckets(data)] == [4, 1]
    assert "no gap between them exceeds 15 minutes (--period-gap)" in md
    assert "no gap between them exceeds 15 minutes (<code>--period-gap</code>)" in html
    for text in (md, html):
        assert "Other calls can happen in between, so periods may overlap in time" in text

    data, md, html = run("--period-gap", "3000")
    assert data["report"]["period_gap_seconds"] == 3000
    ((first, last, n),) = list_buckets(data)
    assert (first, last, n) == ("2023-01-01T00:05:00Z", "2023-01-01T00:45:00Z", 5)
    # The merged period overlaps the GetObject period inside it.
    (get_object,) = [p for p in data["report"]["activity_periods"] if p["api"] == "s3:GetObject"]
    assert first < get_object["first_seen"] <= get_object["last_seen"] < last
    assert "no gap between them exceeds 50 minutes (--period-gap)" in md

    with pytest.raises(SystemExit) as exc:
        main(["report", "--db", str(db), "--access-key", KEY_A, "--period-gap", "-1"])
    assert exc.value.code == 2


def test_findings_grouped_by_tactic_with_former_id(written: dict) -> None:
    findings = written["report"].model["findings"]
    assert [t["name"] for t in findings["tactics"]] == ["Defense Impairment"]
    row = findings["tactics"][0]["rows"][0]
    assert row["technique"] == "T1685.002 (formerly T1562.008)"
    assert "### Defense Impairment: 1 finding (test-denied-run-instances)" in written["md"]


def test_session_graph_and_blast_radius(written: dict) -> None:
    model = written["report"].model
    tree = [(n["label"], n["level"], n["id"]) for n in model["graph"]["tree"]]
    assert tree == [("S0", 0, KEY_A), ("S1", 1, KEY_B)]
    assert model["graph"]["tree"][1]["via"]["api"] == "sts:AssumeRole"
    statuses = {(g["status"], g["api"]) for g in model["graph"]["not_followed"]}
    assert statuses == {("request_failed", "sts:AssumeRole")}
    resources = {(x["type"], x["resource"]) for s in model["blast"]["services"] for x in s["rows"]}
    assert ("bucket", f"logs-{ACCOUNT}") in resources
    assert ("object", f"logs-{ACCOUNT}/a") in resources


def test_iocs(written: dict) -> None:
    iocs = written["report"].model["iocs"]
    assert [x["value"] for x in iocs["source_ips"]["rows"]] == ["203.0.113.10", "198.51.100.7"]
    assert [x["value"] for x in iocs["other_sources"]["rows"]] == ["s3.amazonaws.com"]
    assert {x["value"] for x in iocs["access_keys"]["rows"]} == {KEY_A, KEY_B}
    seen_as = {(x["value"], x["seen_as"]) for x in iocs["arns"]["rows"]}
    assert (f"arn:aws:iam::{OTHER_ACCOUNT}:role/X", "requested in a credential call") in seen_as
    assert (f"arn:aws:iam::{ACCOUNT}:role/B", "role of the caller") in seen_as
    assert INJECT_UA in {x["value"] for x in iocs["user_agents"]["rows"]}


def test_json_keeps_complete_lists_and_the_investigation(written: dict) -> None:
    data = written["json"]
    assert data["format"] == "ctinv-investigation/1"
    assert data["report"]["format"] == "ctinv-report/1"
    assert len(data["timeline"]) == data["summary"]["events"] == 22
    assert len(data["report"]["activity_periods"]) == written["report"].model["periods"]["total"]


def test_lists_are_cut_and_say_so(tmp_path: Path) -> None:
    report = investigation(build(tmp_path), Limits(periods=2, moments=3))
    model = report.model
    assert len(model["periods"]["rows"]) == 2 and model["periods"]["total"] > 2
    assert len(model["moments"]["rows"]) == 3
    paths = write_report(report, tmp_path / "out")
    md = paths[0].read_text()
    assert f"(showing the first 2 of {model['periods']['total']} periods" in md
    data = json.loads(paths[2].read_text())
    assert len(data["report"]["activity_periods"]) == model["periods"]["total"]
    # Evidence of rows that are not shown is not indexed.
    full = investigation(tmp_path / "db" / "test.duckdb").model
    assert len(model["evidence"]) < len(full["evidence"])


# --- untrusted input -----------------------------------------------------------


class _Elements(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: set[str] = set()
        self.attributes: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.add(tag)
        self.attributes.update(name for name, _ in attrs)


def test_html_escapes_untrusted_fields(written: dict) -> None:
    html = written["html"]
    parser = _Elements()
    parser.feed(html)
    assert "script" not in parser.tags and "img" not in parser.tags
    assert not any(a.startswith("on") for a in parser.attributes)
    assert "<script" not in html.lower() and "<img" not in html.lower()
    # Text: angle brackets and quotes are entities.
    assert "&lt;script&gt;alert(&#34;ua&#34;)&lt;/script&gt; &#39;q&#39;" in html
    assert "Describe&lt;script&gt;alert(1)&lt;/script&gt;&#34;Things|" in html
    # Attribute: the full user agent in title="..." cannot close the attribute.
    assert re.search(r'title="&lt;script&gt;alert\(&#34;ua&#34;\)[^"]*"', html)
    # No external resource, and scripts are forbidden by policy.
    assert "default-src 'none'" in html
    assert not re.search(r"(src|href)=\"(?!#ev-)", html)


def test_control_characters_are_shown_not_rendered(written: dict) -> None:
    for text in (written["md"], written["html"]):
        assert "‮" not in text
        assert "next line" in text
        assert "\n next line" not in text and "\nnext line" not in text
    assert "\\u000anext line \\u202eevil" in written["html"]
    assert "\\\\u000anext line \\\\u202eevil" in written["md"]


def _render_gfm(md: str) -> tuple[str, list]:
    parser = MarkdownIt("gfm-like")  # tables, strikethrough, linkify
    return parser.render(md), parser.parse(md)


def test_markdown_escapes_untrusted_fields(written: dict) -> None:
    html, tokens = _render_gfm(written["md"])
    # The report itself has no links, images or raw HTML, so any would be injected.
    assert "<a " not in html and "<img" not in html and "<script" not in html
    assert not any(
        t.type in ("html_inline", "html_block", "image", "link_open")
        for t in tokens + [c for t in tokens for c in t.children or []]
    )
    # Values appear as text, with their angle brackets as entities.
    assert "&lt;script&gt;alert(&quot;ua&quot;)&lt;/script&gt;" in html
    assert "[x](http://evil.example) www.evil.example a@evil.example `code`" in html
    assert "Describe&lt;script&gt;alert(1)&lt;/script&gt;&quot;Things|" in html


def test_markdown_values_cannot_break_table_rows(written: dict) -> None:
    _, tokens = _render_gfm(written["md"])
    columns, cells = None, 0
    for token in tokens:
        if token.type == "thead_open":
            columns, cells = 0, 0
        elif token.type == "th_open":
            columns += 1
        elif token.type == "tr_open":
            cells = 0
        elif token.type == "td_open":
            cells += 1
        elif token.type == "tr_close" and cells:
            assert cells == columns


@pytest.mark.parametrize(
    "value, expected",
    [
        ("a|b", "a\\|b"),
        ("[x](http://e.example)", "\\[x\\]\\(http\\://e\\.example\\)"),
        ("www.e.example", "www\\.e\\.example"),
        ("a@b.example", "a\\@b\\.example"),
        ("s3.amazonaws.com", "s3\\.amazonaws\\.com"),
        ("203.0.113.10 aws-cli/2.0", "203.0.113.10 aws-cli/2.0"),
        ("<b>&amp;", "\\<b\\>\\&amp;"),
        ("*_`~#+!$", "\\*\\_\\`\\~\\#\\+\\!\\$"),
        ("- item", "\\- item"),
        ("---", "\\---"),
        ("-1 x", "-1 x"),
        ("12. item", "12\\. item"),
        ("line\nbreak", "line\\\\u000abreak"),
        ("2019-08-21 07:41:19", "2019-08-21 07:41:19"),
        ("arn:aws:iam::111122223333:role/x", "arn:aws:iam::111122223333:role/x"),
    ],
)
def test_md_escape(value: str, expected: str) -> None:
    assert md_escape(value) == expected


def test_templates_escape_every_value() -> None:
    # A minimal model whose every string is hostile; StrictUndefined makes any
    # field the templates expect but the model lacks fail loudly.
    hostile = '<i x="1">|[l](http://x.example)'
    model = {
        "kind": "findings",
        "title": hostile,
        "generated_at": T0,
        "ctinv_version": hostile,
        "database": hostile,
        "scope": {"rules": hostile},
        "redacted": False,
        "json_file": hostile,
        "summary": [{"text": hostile, "evidence": ["e1"]}],
        "datasets": [],
        "anonymised": None,
        "moments": {"rows": [], "total": 0},
        "periods": None,
        "findings": {"status": "none", "total": 0, "rules": 0, "tactics": []},
        "graph": None,
        "blast": None,
        "iocs": {
            k: {"rows": [], "total": 0}
            for k in ("source_ips", "other_sources", "user_agents", "access_keys", "arns")
        },
        "limitations": [{"text": hostile, "evidence": []}],
        "evidence": [
            {
                "n": 1,
                "event_id": "e1",
                "event_time": T0,
                "session": hostile,
                "api": hostile,
                "region": hostile,
                "caller": hostile,
                "source_ip": hostile,
                "user_agent": hostile,
                "outcome": "failed",
                "error_code": hostile,
                "dataset": hostile,
                "source_file": hostile,
                "source_index": 0,
            }
        ],
        "evidence_index": {"e1": 1},
    }
    html = render_html(model)
    assert '<i x="1">' not in html and "&lt;i x=&#34;1&#34;&gt;" in html
    rendered, _ = _render_gfm(render_markdown(model))
    assert "<i" not in rendered and "<a " not in rendered


# --- datasets and anonymised IPs ---------------------------------------------------


FLAWS_LABEL = (
    "Source IPs, account IDs and access keys were anonymised by the dataset publisher - "
    "not real infrastructure, accounts or credentials. Do not block, look up or report them."
)


@pytest.mark.parametrize(
    "fields, expected",
    [
        (["access_keys", "source_ips", "account_ids"], FLAWS_LABEL),
        (
            ["source_ips"],
            "Source IPs were anonymised by the dataset publisher - not real infrastructure. "
            "Do not block, look up or report them.",
        ),
        (
            ["access_keys", "account_ids"],
            "Account IDs and access keys were anonymised by the dataset publisher - "
            "not real accounts or credentials. Do not block, look up or report them.",
        ),
    ],
)
def test_anonymisation_warning_names_every_field(fields: list[str], expected: str) -> None:
    assert anonymisation_warning(fields) == expected


def test_anonymised_fields_are_labelled(tmp_path: Path) -> None:
    report = investigation(build(tmp_path, dataset="flaws_cloud"))
    paths = write_report(report, tmp_path / "out")
    md, html = paths[0].read_text(), paths[1].read_text()
    model = report.model
    assert model["anonymised"] == {
        "text": FLAWS_LABEL,
        "fields": ["source_ips", "account_ids", "access_keys"],
        "datasets": ["flaws_cloud"],
    }
    iocs = md[md.index("## Indicators (IOCs)") : md.index("## Limitations")]
    assert f"> **{md_escape(FLAWS_LABEL)}**" in iocs
    assert "### Source IP addresses (anonymised by the dataset publisher)" in iocs
    assert "### Access keys (anonymised by the dataset publisher)" in iocs
    assert "### ARNs (account IDs anonymised by the dataset publisher)" in iocs
    html_iocs = html[html.index('<h2 id="iocs">') : html.index('<h2 id="limitations">')]
    assert f'<div class="warning" role="alert">{FLAWS_LABEL}<br>' in html_iocs
    assert "<h3>Access keys (anonymised by the dataset publisher)</h3>" in html_iocs
    assert all(x["anonymised"] for x in model["iocs"]["source_ips"]["rows"])
    assert all(x["anonymised"] for x in model["iocs"]["access_keys"]["rows"])
    # Whether a random replacement address is public says nothing; it is not shown.
    assert "| 203.0.113.10 | yes | n/a | 17 |" in iocs
    assert f"| {KEY_A} | long-term key | yes |" in iocs
    summary = [s["text"] for s in model["summary"]]
    assert (
        "Source IPs, account IDs and access keys in this data were anonymised by the dataset "
        "publisher (flaws_cloud): they are not real infrastructure, accounts or credentials."
    ) in summary
    limitations = " ".join(s["text"] for s in model["limitations"])
    assert "wernicke" in limitations


def test_undescribed_dataset_is_not_labelled_but_flagged(written: dict) -> None:
    model = written["report"].model
    assert model["anonymised"] is None
    assert "anonymised by the dataset publisher" not in written["md"]
    assert "| Access key ID | Kind | Anonymised |" in written["md"]
    assert f"| {KEY_A} | long-term key | no |" in written["md"]
    assert any("is not described" in s["text"] for s in model["limitations"])


# --- redaction -----------------------------------------------------------------


EVENT_ID = re.compile(r"[0-9a-fA-F]{1,16}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{1,16}")


def test_redaction_is_consistent_and_complete(tmp_path: Path) -> None:
    report = investigation(build(tmp_path))
    paths = write_report(report, tmp_path / "out", redact=True)
    texts = [p.read_text() for p in paths]
    for text in texts:
        without_ids = EVENT_ID.sub("", text)
        assert not re.search(r"(?<![0-9])[0-9]{12}(?![0-9])", without_ids)
        assert KEY_A not in text and KEY_B not in text
        assert not re.search(r"(AKIA|ASIA)[A-Z0-9]{16}", text)
        # Evidence survives: eventIDs ending in 12 digits are not masked.
        assert "00000000-0000-0000-0000-000000000180" in text
    md, html, data = texts[0], texts[1], json.loads(texts[2])
    # The same value has the same mask in every file and every place.
    for text in texts:
        assert "arn:aws:iam::ACCOUNT-1:user/alice" in text
        assert "logs-ACCOUNT-1" in text
        assert "arn:aws:iam::ACCOUNT-2:role/X" in text
        assert "AKIA-KEY-1" in text and "ASIA-KEY-2" in text
    assert data["scope"]["access_key"] == "AKIA-KEY-1"
    assert data["redacted"] is True
    assert "masked as ACCOUNT-n" in md and "masked as ACCOUNT-n" in html
    # Links still resolve after masking.
    assert report.model["evidence_index"]["00000000-0000-0000-0000-000000000180"]


def test_without_redact_values_stay(written: dict) -> None:
    assert f"arn:aws:iam::{ACCOUNT}:user/alice" in written["md"]
    assert KEY_A in written["html"]


# --- findings report -------------------------------------------------------------


def test_findings_report(tmp_path: Path) -> None:
    db = build(tmp_path)
    con = connect(db)
    report = findings_report(con, "test.duckdb")
    con.close()
    model = report.model
    assert model["graph"] is None and model["blast"] is None and model["periods"] is None
    assert model["findings"]["total"] == 1
    assert [m["kind"] for m in model["moments"]["rows"]] == ["finding"]
    assert model["summary"][0]["text"].startswith("1 finding of 1 rule (all rules)")
    paths = write_report(report, tmp_path / "out")
    assert paths[0].name.startswith("findings-")
    md = paths[0].read_text()
    assert "Not part of a findings report" in md
    data = json.loads(paths[2].read_text())
    assert data["format"] == "ctinv-findings/1"
    assert len(data["findings"][0]["evidence_event_ids"]) == 12


def test_findings_report_filters(tmp_path: Path) -> None:
    con = connect(build(tmp_path))
    try:
        assert findings_report(con, "x", rules=["other"]).model["findings"]["total"] == 0
        late = findings_report(con, "x", start=T0 + timedelta(hours=1)).model
        assert late["findings"]["total"] == 0
        assert late["summary"][0]["text"] == "No findings match (all rules)."
    finally:
        con.close()


def test_findings_report_needs_detection(tmp_path: Path) -> None:
    con = connect(build(tmp_path, detect=False))
    with pytest.raises(ReportError, match="ctinv detect"):
        findings_report(con, "x")
    con.close()


# --- CLI -----------------------------------------------------------------------


def test_cli_writes_reports(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = build(tmp_path)
    out = tmp_path / "reports"
    assert main(["report", "--db", str(db), "--access-key", KEY_A, "--out-dir", str(out)]) == 0
    printed = capsys.readouterr().out
    assert "Executive summary" in printed and "Report written to" in printed
    assert sorted(p.suffix for p in out.iterdir()) == [".html", ".json", ".md"]
    assert main(["report", "--db", str(db), "--findings", "--redact", "--out-dir", str(out)]) == 0
    assert len(list(out.glob("findings-*.md"))) == 1
    assert KEY_A not in capsys.readouterr().out


def test_cli_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = build(tmp_path)
    out = ["--out-dir", str(tmp_path / "r")]
    assert main(["report", "--db", str(tmp_path / "none.duckdb"), "--findings", *out]) == 2
    assert main(["report", "--db", str(db), "--access-key", KEY_A, "--rule", "x", *out]) == 2
    assert main(["report", "--db", str(db), "--findings", "--rule", "nope", *out]) == 2
    assert main(["report", "--db", str(db), "--access-key", "AKIANOTINTHEDATA0000", *out]) == 1
    assert "no events" in capsys.readouterr().err
    assert not (tmp_path / "r").exists()


def test_documented_defaults_match_the_code() -> None:
    doc = (Path(__file__).resolve().parent.parent / "docs" / "REPORTING.md").read_text()
    assert f"\n> {anonymisation_warning(list(ANONYMISED_FIELDS))}\n" in doc
    assert f"first {BURST_SECONDS}-second window with at least {BURST_EVENTS} of them" in doc
    assert f"no gap between them exceeds {PERIOD_GAP_SECONDS // 60} minutes" in doc
    assert f"| `--period-gap SECONDS` | {PERIOD_GAP_SECONDS} |" in doc
    limits = DEFAULT_LIMITS
    assert f"| `--max-rows N` | {limits.periods} |" in doc
    assert (
        f"(activity periods {limits.periods}, key moments {limits.moments}, findings "
        f"{limits.findings} per\ntactic, resources {limits.resources} per service, IOCs "
        f"{limits.iocs} per kind, sessions {limits.children} per parent)"
    ) in doc
