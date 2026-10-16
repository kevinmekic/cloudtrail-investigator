"""Tests for the investigation: session graph, pivots, timeline, blast radius, findings."""

from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from cloudtrail_events import ACCOUNT, aws_service, event, make_db
from ctinv.detect import load_rules, run_rules
from ctinv.investigate import Investigation, InvestigationError, Scope, investigate
from ctinv.schema import connect

# Clearly fake keys in the format CloudTrail logs.
KEY_A = "AKIAEXAMPLEALICE0001"  # alice's long-term key
KEY_B = "ASIAEXAMPLEROLEB0001"  # alice assumes role B
KEY_C = "ASIAEXAMPLEROLEC0001"  # B assumes role C
KEY_B2 = "ASIAEXAMPLEROLEB0002"  # C assumes role B again
KEY_E = "ASIAEXAMPLEROLEE0001"  # issued to B, never used
KEY_S = "ASIAEXAMPLESESSN0001"  # alice's GetSessionToken
KEY_BOB = "AKIAEXAMPLEBOB000001"  # created by alice for bob
KEY_CAROL = "AKIAEXAMPLECAROL0001"  # unrelated user
KEY_I = "ASIAEXAMPLEINSTN0001"  # instance role credentials issued by EC2

T0 = datetime(2023, 1, 1)


def t(n: int) -> datetime:
    return T0 + timedelta(minutes=n)


def eid(n: int) -> str:
    return f"00000000-0000-0000-0000-{n:012d}"


def at(n: int, identity: dict[str, Any], **fields: Any) -> dict[str, Any]:
    return event(n, identity, eventTime=t(n).isoformat() + "Z", **fields)


def user(name: str, key: str) -> dict[str, Any]:
    return {
        "type": "IAMUser",
        "principalId": f"AIDAEXAMPLE{name.upper()}",
        "arn": f"arn:aws:iam::{ACCOUNT}:user/{name}",
        "accountId": ACCOUNT,
        "accessKeyId": key,
        "userName": name,
    }


def role_session(role: str, key: str, session: str = "s") -> dict[str, Any]:
    return {
        "type": "AssumedRole",
        "principalId": f"AROAEXAMPLE{role.upper()}:{session}",
        "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{role}/{session}",
        "accountId": ACCOUNT,
        "accessKeyId": key,
        "sessionContext": {
            "sessionIssuer": {
                "type": "Role",
                "principalId": f"AROAEXAMPLE{role.upper()}",
                "arn": f"arn:aws:iam::{ACCOUNT}:role/{role}",
                "accountId": ACCOUNT,
                "userName": role,
            },
            "attributes": {"creationDate": "2023-01-01T00:00:00Z", "mfaAuthenticated": "false"},
        },
    }


def assume(n: int, identity: dict, role: str, key: str | None, **fields: Any) -> dict[str, Any]:
    """An AssumeRole call; ``key`` is the issued access key ID as logged."""
    response = None
    if key is not None:
        response = {
            "credentials": {
                "accessKeyId": key,
                "sessionToken": "IQoJb3JpZ2luX2VjEXAMPLE",
                "expiration": "Jan 1, 2023, 1:00:00 AM",
            },
            "assumedRoleUser": {
                "assumedRoleId": f"AROAEXAMPLE{role.upper()}:s",
                "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{role}/s",
            },
        }
    return at(
        n,
        identity,
        eventSource="sts.amazonaws.com",
        eventName="AssumeRole",
        requestParameters={
            "roleArn": f"arn:aws:iam::{ACCOUNT}:role/{role}",
            "roleSessionName": "s",
        },
        responseElements=response,
        **fields,
    )


ALICE, CAROL = user("alice", KEY_A), user("carol", KEY_CAROL)
ROLE_B, ROLE_C, ROLE_B2 = (
    role_session("B", KEY_B),
    role_session("C", KEY_C),
    role_session("B", KEY_B2, "s2"),
)


def scenario() -> list[dict[str, Any]]:
    """alice -> role B -> role C -> role B again, plus every kind of dead end.

    Records are written in reverse order: nothing may depend on file order.
    """
    records = [
        at(1, ALICE, eventName="ListUsers"),
        assume(2, ALICE, "B", KEY_B),
        assume(3, ALICE, "X", None, errorCode="AccessDenied", errorMessage="not allowed"),
        at(4, ROLE_B, eventSource="s3.amazonaws.com", eventName="GetObject"),
        assume(5, ROLE_B, "C", KEY_C),
        assume(6, ROLE_B, "D", "HIDDEN_DUE_TO_SECURITY_REASONS"),  # key not usable
        assume(7, ROLE_B, "E", KEY_E),  # never used
        at(
            8,
            ROLE_C,
            eventSource="cloudtrail.amazonaws.com",
            eventName="DeleteTrail",
            errorCode="TrailNotFoundException",
        ),
        assume(9, ROLE_C, "B", KEY_B2),  # back to role B: a new key, one level deeper
        assume(10, ROLE_C, "B", KEY_B),  # a log claiming an existing key: a key cycle
        at(11, ROLE_B2, eventSource="s3.amazonaws.com", eventName="ListBuckets"),
        at(
            12,
            ALICE,
            eventSource="sts.amazonaws.com",
            eventName="GetSessionToken",
            requestParameters={"durationSeconds": 3600},
            responseElements={"credentials": {"accessKeyId": KEY_S, "sessionToken": "x"}},
        ),
        at(13, user("alice", KEY_S), eventSource="ec2.amazonaws.com", eventName="DescribeVpcs"),
        at(
            14,
            ALICE,
            eventName="CreateAccessKey",
            requestParameters={"userName": "bob"},
            responseElements={
                "accessKey": {"accessKeyId": KEY_BOB, "status": "Active", "userName": "bob"}
            },
        ),
        at(15, user("bob", KEY_BOB), eventName="ListRoles"),
        at(16, CAROL, eventName="ListUsers"),
    ]
    return records[::-1]


@pytest.fixture(scope="module")
def db(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return make_db(tmp_path_factory.mktemp("investigate"), scenario())


def run(db: Path, **scope: Any) -> Investigation:
    with connect(db) as con:
        return investigate(con, Scope(**scope))


def statuses(inv: Investigation) -> dict[str, str]:
    return {p.event_id: p.status for p in inv.pivots}


def graph(inv: Investigation) -> list[tuple]:
    return [(s.id, s.depth, s.parent, s.via_event_id) for s in inv.sessions]


def timeline_ids(inv: Investigation) -> list[str]:
    return [e["event_id"] for e in inv.timeline]


def test_multi_hop_pivot_from_an_access_key(db: Path) -> None:
    inv = run(db, access_key=KEY_A)
    assert graph(inv) == [
        (KEY_A, 0, None, None),
        (KEY_B, 1, KEY_A, eid(2)),
        (KEY_S, 1, KEY_A, eid(12)),
        (KEY_C, 2, KEY_B, eid(5)),
        (KEY_B2, 3, KEY_C, eid(9)),
    ]
    assert statuses(inv) == {
        eid(2): "followed",
        eid(3): "request_failed",
        eid(12): "followed",
        eid(14): "created_key_not_followed",
        eid(5): "followed",
        eid(6): "key_not_logged",
        eid(7): "not_used",
        eid(9): "followed",
        eid(10): "already_in_graph",
    }
    # Every event of every session, in time order; carol and bob are not part of it.
    assert timeline_ids(inv) == [eid(n) for n in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14)]
    assert inv.summary["events"] == 14
    assert inv.summary["deepest_session"] == 3
    assert inv.summary["pivot_statuses"]["followed"] == 4


def test_pivot_details_name_role_session_and_issued_identity(db: Path) -> None:
    pivot = next(p for p in run(db, access_key=KEY_A).pivots if p.event_id == eid(2))
    assert pivot.api == "sts:AssumeRole"
    assert pivot.caller == f"arn:aws:iam::{ACCOUNT}:user/alice"
    assert pivot.target == f"arn:aws:iam::{ACCOUNT}:role/B"
    assert pivot.session_name == "s"
    assert pivot.issued_key == KEY_B
    assert pivot.issued_identity == f"arn:aws:sts::{ACCOUNT}:assumed-role/B/s"
    assert pivot.to_session == KEY_B


def test_success_and_failure_are_separated(db: Path) -> None:
    inv = run(db, access_key=KEY_A)
    outcome = {e["event_id"]: (e["outcome"], e["error_code"]) for e in inv.timeline}
    assert outcome[eid(3)] == ("denied", "AccessDenied")
    assert outcome[eid(8)] == ("failed", "TrailNotFoundException")
    assert outcome[eid(4)] == ("succeeded", None)
    assert (inv.summary["succeeded"], inv.summary["denied"], inv.summary["failed"]) == (12, 1, 1)
    by_session = {s.id: (s.events, s.succeeded, s.denied, s.failed) for s in inv.sessions}
    assert by_session[KEY_A] == (5, 4, 1, 0)
    assert by_session[KEY_C] == (3, 2, 0, 1)
    apis = {a["api"]: a for a in inv.apis}
    assert apis["sts:AssumeRole"] == {
        "api": "sts:AssumeRole",
        "succeeded": 6,
        "denied": 1,
        "failed": 0,
        "events": 7,
    }


@pytest.mark.parametrize(
    ("max_depth", "sessions", "stopped"),
    [
        (0, [KEY_A], {eid(2): "depth_limit", eid(12): "depth_limit"}),
        (1, [KEY_A, KEY_B, KEY_S], {eid(5): "depth_limit", eid(7): "depth_limit"}),
        (2, [KEY_A, KEY_B, KEY_S, KEY_C], {eid(9): "depth_limit"}),
    ],
)
def test_depth_limit(db: Path, max_depth: int, sessions: list[str], stopped: dict) -> None:
    inv = run(db, access_key=KEY_A, max_depth=max_depth)
    assert [s.id for s in inv.sessions] == sessions
    assert stopped.items() <= statuses(inv).items()
    # Failed requests and unusable keys keep their own status at the limit.
    assert statuses(inv)[eid(3)] == "request_failed"


def test_key_cycle_ends_and_is_reported(db: Path) -> None:
    # Starting at C, the forged log line at 10 leads back to B, and B's call
    # at 5 issued C: the cycle is closed by the visited check, not by depth.
    inv = run(db, access_key=KEY_C, max_depth=50)
    assert graph(inv) == [
        (KEY_C, 0, None, None),
        (KEY_B2, 1, KEY_C, eid(9)),
        (KEY_B, 1, KEY_C, eid(10)),
    ]
    assert statuses(inv)[eid(5)] == "already_in_graph"
    assert inv.summary["deepest_session"] == 1


def test_session_limit(db: Path) -> None:
    inv = run(db, access_key=KEY_A, max_sessions=1)
    assert [s.id for s in inv.sessions] == [KEY_A, KEY_B]
    assert statuses(inv)[eid(12)] == "session_limit"


def test_created_keys_are_followed_on_request(db: Path) -> None:
    inv = run(db, access_key=KEY_A, follow_created_keys=True)
    bob = next(s for s in inv.sessions if s.id == KEY_BOB)
    assert (bob.kind, bob.depth, bob.via_event_id, bob.events) == ("long-term key", 1, eid(14), 1)
    assert eid(15) in timeline_ids(inv)


def test_principal_start_includes_all_its_keys(db: Path) -> None:
    inv = run(db, principal=f"arn:aws:iam::{ACCOUNT}:user/alice")
    root = inv.sessions[0]
    assert (root.id, root.kind, root.events) == (
        f"arn:aws:iam::{ACCOUNT}:user/alice",
        "principal",
        6,
    )
    assert [k["value"] for k in root.access_keys] == [KEY_A, KEY_S]
    # GetSessionToken's key is alice's own: its events are already in the graph.
    assert statuses(inv)[eid(12)] == "already_in_graph"
    assert [s.id for s in inv.sessions[1:]] == [KEY_B, KEY_C, KEY_B2]
    assert root.issued_by == []


def test_role_principal_matches_every_session_of_the_role(db: Path) -> None:
    inv = run(db, principal=f"arn:aws:iam::{ACCOUNT}:role/B")
    assert inv.sessions[0].events == 5  # sessions s (4 events) and s2 (1 event)
    assert [s.id for s in inv.sessions[1:]] == [KEY_C]
    assert statuses(inv)[eid(9)] == "already_in_graph"  # B2's events belong to the role
    assert statuses(inv)[eid(10)] == "already_in_graph"


def test_time_range_limits_every_session(db: Path) -> None:
    inv = run(db, access_key=KEY_A, start=t(2), end=t(9))
    assert timeline_ids(inv) == [eid(n) for n in (2, 3, 4, 5, 6, 7, 8)]
    assert [s.id for s in inv.sessions] == [KEY_A, KEY_B, KEY_C]


def test_issued_key_used_only_outside_the_time_range_counts_as_not_used(db: Path) -> None:
    inv = run(db, access_key=KEY_A, end=t(4))
    assert statuses(inv)[eid(2)] == "not_used"


def test_origin_of_the_starting_key(tmp_path: Path) -> None:
    # Instance role credentials issued by EC2 and used from somewhere else.
    records = [
        aws_service(
            1,
            eventSource="sts.amazonaws.com",
            eventName="AssumeRole",
            sourceIPAddress="ec2.amazonaws.com",
            requestParameters={
                "roleArn": f"arn:aws:iam::{ACCOUNT}:role/web",
                "roleSessionName": "i-0123456789abcdef0",
            },
            responseElements={"credentials": {"accessKeyId": KEY_I, "sessionToken": "x"}},
        ),
        event(2, role_session("web", KEY_I, "i-0123456789abcdef0"), sourceIPAddress="198.51.100.7"),
    ]
    inv = run(make_db(tmp_path, records), access_key=KEY_I)
    (origin,) = inv.sessions[0].issued_by
    assert origin["event_id"] == eid(1)
    assert origin["caller"] == "ec2.amazonaws.com"
    assert origin["session_name"] == "i-0123456789abcdef0"
    assert inv.sessions[0].source_ips == [{"value": "198.51.100.7", "events": 1}]


def test_origin_of_a_created_key_is_found_without_following(db: Path) -> None:
    (origin,) = run(db, access_key=KEY_BOB).sessions[0].issued_by
    assert (origin["event_id"], origin["api"], origin["target"]) == (
        eid(14),
        "iam:CreateAccessKey",
        "bob",
    )


def test_timeline_is_capped_but_counts_are_complete(db: Path) -> None:
    inv = run(db, access_key=KEY_A, max_events=3)
    assert timeline_ids(inv) == [eid(1), eid(2), eid(3)]
    assert inv.summary["events"] == 14


def test_same_second_events_are_ordered_by_event_id(tmp_path: Path) -> None:
    same = (T0.isoformat() + "Z",) * 3
    records = [event(n, user("alice", KEY_A), eventTime=same[0]) for n in (3, 1, 2)]
    inv = run(make_db(tmp_path, records), access_key=KEY_A)
    assert timeline_ids(inv) == [eid(1), eid(2), eid(3)]


def test_unknown_starting_point_is_an_error(db: Path) -> None:
    with pytest.raises(InvestigationError, match="no events for access key AKIA"):
        run(db, access_key="AKIAEXAMPLENOSUCH001")
    with pytest.raises(InvestigationError, match="in the given time range"):
        run(db, access_key=KEY_A, start=t(100))


@pytest.mark.parametrize(
    ("scope", "message"),
    [
        ({}, "exactly one"),
        ({"access_key": KEY_A, "principal": "arn:aws:iam::111122223333:user/alice"}, "exactly one"),
        ({"access_key": KEY_A, "start": t(5), "end": t(5)}, "before its end"),
        ({"access_key": KEY_A, "max_depth": -1}, "max_depth"),
    ],
)
def test_invalid_scope(scope: dict, message: str) -> None:
    with pytest.raises(InvestigationError, match=message):
        Scope(**scope)


# ------------------------------------------------------------------------------- blast radius


def blast_records() -> list[dict[str, Any]]:
    role_arn = f"arn:aws:iam::{ACCOUNT}:role/admin"
    return [
        at(
            1,
            ALICE,
            eventSource="s3.amazonaws.com",
            eventName="GetObject",
            requestParameters={"bucketName": "data", "key": "a.txt"},
        ),
        at(
            2,
            ALICE,
            eventSource="s3.amazonaws.com",
            eventName="PutObject",
            requestParameters={"bucketName": "data", "key": "b.txt"},
            errorCode="AccessDenied",
        ),
        at(
            3,
            ALICE,
            eventSource="s3.amazonaws.com",
            eventName="GetBucketAcl",
            requestParameters={"bucketName": "data"},
            resources=[{"ARN": "arn:aws:s3:::data", "type": "AWS::S3::Bucket"}],
        ),
        at(4, ALICE, eventName="GetUser", requestParameters={"userName": "Level6"}),
        at(5, ALICE, eventName="GetRole", requestParameters={"roleName": "Level6"}),
        at(
            6,
            ALICE,
            eventSource="ec2.amazonaws.com",
            eventName="RunInstances",
            requestParameters={
                "instancesSet": {"items": [{"imageId": "ami-1"}]},
                "instanceType": "p2.8xlarge",
            },
            errorCode="Client.InstanceLimitExceeded",
        ),
        at(
            7,
            ALICE,
            eventSource="ec2.amazonaws.com",
            eventName="DescribeInstances",
            requestParameters={"filterSet": {"items": [{"name": "tag:Name"}]}},
        ),
        at(8, ALICE, eventName="ListUsers"),
        at(
            9,
            ALICE,
            eventSource="sts.amazonaws.com",
            eventName="AssumeRole",
            requestParameters={"roleArn": role_arn, "roleSessionName": "s"},
            resources=[{"ARN": role_arn, "type": "AWS::IAM::Role", "accountId": ACCOUNT}],
            errorCode="AccessDenied",
        ),
        at(
            10,
            ALICE,
            eventSource="kms.amazonaws.com",
            eventName="Decrypt",
            awsRegion="eu-west-1",
            resources=[
                {"ARN": "arn:aws:kms:eu-west-1:111122223333:key/k1", "type": "AWS::KMS::Key"},
                {"ARN": "arn:aws:ecr:eu-west-1:111122223333:repository/r"},
            ],
        ),
    ]


@pytest.fixture(scope="module")
def blast(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    db = make_db(tmp_path_factory.mktemp("blast"), blast_records())
    return run(db, access_key=KEY_A).blast_radius


def entry(blast: dict, service: str, kind: str, resource: str) -> dict[str, Any]:
    (service_entry,) = [s for s in blast["services"] if s["service"] == service]
    (found,) = [
        r for r in service_entry["listed"] if (r["type"], r["resource"]) == (kind, resource)
    ]
    return found


def test_blast_radius_splits_succeeded_denied_and_failed(blast: dict) -> None:
    bucket = entry(blast, "s3", "bucket", "data")
    assert bucket["events"] == 3
    assert bucket["succeeded"]["events"] == 2
    assert bucket["succeeded"]["apis"] == {"GetBucketAcl": 1, "GetObject": 1}
    assert bucket["succeeded"]["event_ids"] == [eid(1), eid(3)]
    assert bucket["denied"]["apis"] == {"PutObject": 1}
    assert bucket["failed"] is None
    image = entry(blast, "ec2", "image", "ami-1")
    assert (image["succeeded"], image["denied"]) == (None, None)
    assert image["failed"]["event_ids"] == [eid(6)]


def test_resources_field_and_parameters_merge(blast: dict) -> None:
    # The S3 ARN in resources[] is the bucket that bucketName names.
    assert entry(blast, "s3", "bucket", "data")["fields"] == [
        "requestParameters.bucketName",
        "resources[AWS::S3::Bucket]",
    ]
    role = entry(blast, "sts", "role", f"arn:aws:iam::{ACCOUNT}:role/admin")
    assert role["fields"] == ["requestParameters.roleArn", "resources[AWS::IAM::Role]"]
    assert role["denied"]["events"] == 1


def test_objects_and_same_named_resources_of_other_types_stay_apart(blast: dict) -> None:
    assert entry(blast, "s3", "object", "data/a.txt")["succeeded"]["events"] == 1
    assert entry(blast, "s3", "object", "data/b.txt")["denied"]["events"] == 1
    assert entry(blast, "iam", "user", "Level6")["events"] == 1
    assert entry(blast, "iam", "role", "Level6")["events"] == 1


def test_resource_types_from_the_resources_field(blast: dict) -> None:
    key = entry(blast, "kms", "key", "arn:aws:kms:eu-west-1:111122223333:key/k1")
    assert key["regions"] == ["eu-west-1"]
    # No type stated: kept, marked unknown.
    assert entry(blast, "kms", "unknown", "arn:aws:ecr:eu-west-1:111122223333:repository/r")


def test_parameters_that_are_not_resources_are_ignored(blast: dict) -> None:
    ec2 = next(s for s in blast["services"] if s["service"] == "ec2")
    assert [(r["type"], r["resource"]) for r in ec2["listed"]] == [("image", "ami-1")]
    assert blast["events_without_resource"] == {
        "events": 2,
        "apis": [
            {"api": "ec2:DescribeInstances", "events": 1},
            {"api": "iam:ListUsers", "events": 1},
        ],
    }


def test_service_totals(blast: dict) -> None:
    s3 = next(s for s in blast["services"] if s["service"] == "s3")
    assert (s3["events"], s3["resources"]) == (3, 3)
    assert (s3["succeeded_resources"], s3["denied_resources"], s3["failed_resources"]) == (2, 2, 0)
    assert blast["services"][0]["service"] == "s3"  # most events first


def test_blast_radius_lists_are_capped(tmp_path: Path) -> None:
    records = [
        at(
            n,
            ALICE,
            eventSource="s3.amazonaws.com",
            eventName="GetBucketAcl",
            requestParameters={"bucketName": f"b{n % 3}"},
        )
        for n in range(1, 10)
    ]
    with connect(make_db(tmp_path, records)) as con:
        inv = investigate(con, Scope(access_key=KEY_A, max_resources=2, max_evidence=2))
    (s3,) = inv.blast_radius["services"]
    assert s3["resources"] == 3
    assert [r["resource"] for r in s3["listed"]] == ["b0", "b1"]
    assert s3["listed"][0]["succeeded"]["events"] == 3
    assert s3["listed"][0]["succeeded"]["event_ids"] == [eid(3), eid(6)]


# ------------------------------------------------------------------------------------ findings


def test_findings_of_sessions_in_the_graph(tmp_path: Path) -> None:
    stop = {"eventSource": "cloudtrail.amazonaws.com", "eventName": "StopLogging"}
    records = [
        assume(1, ALICE, "B", KEY_B),
        at(2, ROLE_B, requestParameters={"name": "main"}, **stop),
        at(3, CAROL, requestParameters={"name": "other"}, **stop),
    ]
    db = make_db(tmp_path, records)
    assert run(db, access_key=KEY_A).findings is None  # detection never ran

    with connect(db) as con:
        run_rules(con, [r for r in load_rules() if r.id == "cloudtrail-tampering"])
    (finding,) = run(db, access_key=KEY_A).findings
    assert finding["rule_id"] == "cloudtrail-tampering"
    assert (finding["technique_id"], finding["former_technique_ids"]) == (
        "T1685.002",
        ["T1562.008"],
    )
    assert finding["sessions"] == [KEY_B]
    assert finding["event_ids"] == [eid(2)]
    assert (finding["evidence_count"], finding["evidence_in_investigation"]) == (1, 1)
    # Detection ran, but nothing of it lies in this time range.
    assert run(db, access_key=KEY_A, end=t(2)).findings == []
