"""Tests for the investigation: session graph, pivots, timeline, limits."""

from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from cloudtrail_events import ACCOUNT, aws_service, event, make_db
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
