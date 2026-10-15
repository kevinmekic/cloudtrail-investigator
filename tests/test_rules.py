"""Positive, negative and edge-case tests for each built-in detection rule."""

from pathlib import Path

from cloudtrail_events import ACCOUNT, assumed_role, iam_user, make_db, root
from ctinv.detect import load_rules, run_rules
from ctinv.schema import connect


def eid(n: int) -> str:
    return f"00000000-0000-0000-0000-{n:012d}"


def detect(tmp_path: Path, records: list[dict], rule_id: str) -> list[tuple]:
    """Run one built-in rule on the records; return (principal, summary, evidence, outcome)."""
    db = make_db(tmp_path, records)
    rules = [r for r in load_rules() if r.id == rule_id]
    assert rules, f"no built-in rule {rule_id}"
    with connect(db) as con:
        run_rules(con, rules)
        return con.execute(
            "SELECT principal, summary, evidence_event_ids, outcome FROM findings "
            "ORDER BY first_seen, finding_id"
        ).fetchall()


# --------------------------------------------------------------------------- cloudtrail-tampering


def trail_call(n: int, name: str, **fields) -> dict:
    return iam_user(n, eventSource="cloudtrail.amazonaws.com", eventName=name, **fields)


def s3_call(n: int, name: str, bucket: str, **fields) -> dict:
    return iam_user(
        n,
        eventSource="s3.amazonaws.com",
        eventName=name,
        requestParameters={"bucketName": bucket},
        **fields,
    )


def test_tampering_calls_are_detected_including_failed_attempts(tmp_path: Path) -> None:
    records = [
        trail_call(1, "StopLogging", requestParameters={"name": "main"}),
        trail_call(2, "DeleteTrail", requestParameters={"name": "main"}),
        trail_call(3, "UpdateTrail", requestParameters={"name": "main"}),
        trail_call(4, "PutEventSelectors", requestParameters={"trailName": "main"}),
        trail_call(
            5, "StopLogging", requestParameters={"name": "main"}, errorCode="TrailNotFoundException"
        ),
    ]
    found = detect(tmp_path, records, "cloudtrail-tampering")
    assert [(f[1], f[2], f[3]) for f in found] == [
        ("StopLogging on main", [eid(1)], "succeeded"),
        ("DeleteTrail on main", [eid(2)], "succeeded"),
        ("UpdateTrail on main", [eid(3)], "succeeded"),
        ("PutEventSelectors on main", [eid(4)], "succeeded"),
        ("StopLogging on main (failed: TrailNotFoundException)", [eid(5)], "failed"),
    ]


def test_other_cloudtrail_calls_are_not_tampering(tmp_path: Path) -> None:
    records = [
        trail_call(1, "StartLogging", requestParameters={"name": "main"}),
        trail_call(2, "CreateTrail", requestParameters={"name": "main", "s3BucketName": "logs"}),
        trail_call(3, "DescribeTrails"),
        trail_call(4, "GetEventSelectors", requestParameters={"trailName": "main"}),
    ]
    assert detect(tmp_path, records, "cloudtrail-tampering") == []


def test_lifecycle_rule_counts_only_on_a_trail_bucket(tmp_path: Path) -> None:
    records = [
        trail_call(
            1, "CreateTrail", requestParameters={"name": "main", "s3BucketName": "trail-logs"}
        ),
        trail_call(
            2,
            "CreateTrail",
            requestParameters={"name": "x", "s3BucketName": "never-a-trail"},
            errorCode="InsufficientS3BucketPolicyException",
        ),
        s3_call(
            3,
            "GetBucketAcl",
            "service-seen",
            userIdentity={"type": "AWSService", "invokedBy": "cloudtrail.amazonaws.com"},
        ),
        s3_call(4, "PutBucketLifecycle", "trail-logs"),
        s3_call(5, "PutBucketLifecycle", "website"),
        s3_call(6, "PutBucketLifecycle", "never-a-trail"),
        s3_call(7, "PutBucketLifecycle", "service-seen"),
        s3_call(8, "DeleteBucketLifecycle", "trail-logs"),
    ]
    found = detect(tmp_path, records, "cloudtrail-tampering")
    assert [(f[1], f[2]) for f in found] == [
        ("PutBucketLifecycle on trail-logs", [eid(4)]),
        ("PutBucketLifecycle on service-seen", [eid(7)]),
    ]


def test_tampering_target_may_be_missing_in_denied_calls(tmp_path: Path) -> None:
    found = detect(
        tmp_path, [trail_call(1, "UpdateTrail", errorCode="AccessDenied")], "cloudtrail-tampering"
    )
    assert found[0][1] == "UpdateTrail on (target not logged) (failed: AccessDenied)"


# --------------------------------------------------------------------------- root-account-usage


def test_root_activity_is_grouped_per_day(tmp_path: Path) -> None:
    records = [
        root(1, eventTime="2023-01-01T09:00:00Z"),
        root(
            2,
            eventTime="2023-01-01T17:00:00Z",
            errorCode="AccessDenied",
            sourceIPAddress="198.51.100.7",
        ),
        root(
            3,
            eventTime="2023-01-02T09:00:00Z",
            eventName="ConsoleLogin",
            eventType="AwsConsoleSignIn",
            eventSource="signin.amazonaws.com",
        ),
    ]
    found = detect(tmp_path, records, "root-account-usage")
    assert found == [
        (
            f"arn:aws:iam::{ACCOUNT}:root",
            "root used on 2023-01-01: 2 call(s) from 2 source address(es), 1 failed",
            [eid(1), eid(2)],
            "partly failed",
        ),
        (
            f"arn:aws:iam::{ACCOUNT}:root",
            "root used on 2023-01-02: 1 call(s) from 1 source address(es), 0 failed",
            [eid(3)],
            "succeeded",
        ),
    ]


def test_root_calls_made_by_aws_services_are_not_counted(tmp_path: Path) -> None:
    on_behalf = root(1)
    on_behalf["userIdentity"]["invokedBy"] = "support.amazonaws.com"
    records = [on_behalf, root(2, eventType="AwsServiceEvent"), iam_user(3)]
    assert detect(tmp_path, records, "root-account-usage") == []


# ------------------------------------------------------------------ console-login-without-mfa


def sign_in(make, n: int, mfa: str | None, outcome: str = "Success", **fields) -> dict:
    extra = {} if mfa is None else {"additionalEventData": {"MFAUsed": mfa}}
    return make(
        n,
        eventSource="signin.amazonaws.com",
        eventName="ConsoleLogin",
        eventType="AwsConsoleSignIn",
        responseElements={"ConsoleLogin": outcome},
        **extra,
        **fields,
    )


def test_successful_sign_in_without_mfa_is_detected(tmp_path: Path) -> None:
    records = [sign_in(iam_user, 1, "No"), sign_in(root, 2, "No"), sign_in(iam_user, 3, "Yes")]
    found = detect(tmp_path, records, "console-login-without-mfa")
    assert [(f[0], f[1], f[2]) for f in found] == [
        (
            f"arn:aws:iam::{ACCOUNT}:user/alice",
            "console sign-in without MFA from 203.0.113.10",
            [eid(1)],
        ),
        (f"arn:aws:iam::{ACCOUNT}:root", "console sign-in without MFA from 203.0.113.10", [eid(2)]),
    ]


def test_sign_ins_that_do_not_count(tmp_path: Path) -> None:
    records = [
        sign_in(iam_user, 1, "No", outcome="Failure", errorMessage="Failed authentication"),
        sign_in(assumed_role, 2, "No"),  # federated: MFA happens at the identity provider
        sign_in(iam_user, 3, None),  # no MFAUsed value
        assumed_role(4, mfa="false"),  # session attribute on an ordinary API call
    ]
    assert detect(tmp_path, records, "console-login-without-mfa") == []
