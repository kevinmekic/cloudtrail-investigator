"""Positive, negative and edge-case tests for each built-in detection rule."""

from pathlib import Path

from cloudtrail_events import iam_user, make_db
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
