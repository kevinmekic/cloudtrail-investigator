"""Positive, negative and edge-case tests for each built-in detection rule."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cloudtrail_events import ACCOUNT, assumed_role, aws_service, event, iam_user, make_db, root
from ctinv.detect import apply_overrides, load_rules, run_rules
from ctinv.schema import connect


def eid(n: int) -> str:
    return f"00000000-0000-0000-0000-{n:012d}"


def detect(tmp_path: Path, records: list[dict], rule_id: str, *overrides: str) -> list[tuple]:
    """Run one built-in rule on the records; return (principal, summary, evidence, outcome)."""
    db = make_db(tmp_path, records)
    rules = apply_overrides([r for r in load_rules() if r.id == rule_id], overrides)
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


def test_failed_root_sign_ins_count_as_failed(tmp_path: Path) -> None:
    failed = {"outcome": "Failure", "errorMessage": "Failed authentication"}
    records = [
        sign_in(root, 1, "No", **failed),
        root(
            2,
            eventSource="signin.amazonaws.com",
            eventName="CheckMfa",
            eventType="AwsConsoleSignIn",
            responseElements={"CheckMfa": "Failure"},
        ),
        sign_in(root, 3, "No", eventTime="2023-01-02T00:00:00Z", **failed),
        sign_in(root, 4, "Yes", eventTime="2023-01-02T00:01:00Z"),
    ]
    found = detect(tmp_path, records, "root-account-usage")
    assert [(f[1], f[3]) for f in found] == [
        ("root used on 2023-01-01: 2 call(s) from 1 source address(es), 2 failed", "failed"),
        (
            "root used on 2023-01-02: 2 call(s) from 1 source address(es), 1 failed",
            "partly failed",
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


# ------------------------------------------------------------- credentials-created-for-other-user


def iam_call(make, n: int, name: str, params: dict | None, **fields) -> dict:
    return make(
        n, eventSource="iam.amazonaws.com", eventName=name, requestParameters=params, **fields
    )


def test_credentials_for_another_user_are_detected(tmp_path: Path) -> None:
    records = [
        iam_call(iam_user, 1, "CreateAccessKey", {"userName": "bob"}),
        iam_call(root, 2, "CreateLoginProfile", {"userName": "bob"}),
        iam_call(assumed_role, 3, "CreateAccessKey", {"userName": "alice"}),
        iam_call(iam_user, 4, "CreateAccessKey", {"userName": "carol"}, errorCode="AccessDenied"),
    ]
    found = detect(tmp_path, records, "credentials-created-for-other-user")
    assert [(f[1], f[2], f[3]) for f in found] == [
        ("CreateAccessKey for user bob", [eid(1)], "succeeded"),
        ("CreateLoginProfile for user bob", [eid(2)], "succeeded"),
        ("CreateAccessKey for user alice", [eid(3)], "succeeded"),
        ("CreateAccessKey for user carol (failed: AccessDenied)", [eid(4)], "failed"),
    ]


def test_own_credentials_and_unknown_targets_are_not_reported(tmp_path: Path) -> None:
    records = [
        iam_call(iam_user, 1, "CreateAccessKey", None),  # no userName: the caller's own key
        iam_call(iam_user, 2, "CreateAccessKey", {"userName": "Alice"}),  # same user, other case
        iam_call(iam_user, 3, "CreateLoginProfile", None, errorCode="AccessDenied"),
        iam_call(iam_user, 4, "UpdateLoginProfile", {"userName": "bob"}),
    ]
    assert detect(tmp_path, records, "credentials-created-for-other-user") == []


# ------------------------------------------------------------------------- admin-policy-attached

ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
ADMIN_DOC = (
    '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}'
)
S3_DOC = ADMIN_DOC.replace('"Action": "*"', '"Action": "s3:*"')


def test_admin_grants_are_detected(tmp_path: Path) -> None:
    records = [
        iam_call(iam_user, 1, "AttachUserPolicy", {"userName": "bob", "policyArn": ADMIN_ARN}),
        iam_call(root, 2, "AttachRolePolicy", {"roleName": "ops", "policyArn": ADMIN_ARN}),
        iam_call(
            iam_user,
            3,
            "AttachGroupPolicy",
            {
                "groupName": "devs",
                "policyArn": "arn:aws-us-gov:iam::aws:policy/AdministratorAccess",
            },
        ),
        iam_call(
            iam_user,
            4,
            "PutRolePolicy",
            {"roleName": "ops", "policyName": "all", "policyDocument": ADMIN_DOC},
        ),
        iam_call(
            iam_user,
            5,
            "AttachUserPolicy",
            {"userName": "eve", "policyArn": ADMIN_ARN},
            errorCode="AccessDenied",
        ),
    ]
    found = detect(tmp_path, records, "admin-policy-attached")
    assert [(f[1], f[3]) for f in found] == [
        (f"AttachUserPolicy on user bob: {ADMIN_ARN}", "succeeded"),
        (f"AttachRolePolicy on role ops: {ADMIN_ARN}", "succeeded"),
        (
            "AttachGroupPolicy on group devs: arn:aws-us-gov:iam::aws:policy/AdministratorAccess",
            "succeeded",
        ),
        ("PutRolePolicy on role ops: inline policy all", "succeeded"),
        (f"AttachUserPolicy on user eve: {ADMIN_ARN} (failed: AccessDenied)", "failed"),
    ]


def test_limited_policies_are_not_admin_grants(tmp_path: Path) -> None:
    records = [
        iam_call(
            iam_user,
            1,
            "AttachUserPolicy",
            {"userName": "bob", "policyArn": "arn:aws:iam::aws:policy/SecurityAudit"},
        ),
        iam_call(
            iam_user,
            2,
            "AttachRolePolicy",
            {"roleName": "ops", "policyArn": f"arn:aws:iam::{ACCOUNT}:policy/AdministratorAccess"},
        ),
        iam_call(
            iam_user,
            3,
            "PutUserPolicy",
            {"userName": "bob", "policyName": "s3", "policyDocument": S3_DOC},
        ),
        iam_call(iam_user, 4, "AttachUserPolicy", None, errorCode="AccessDenied"),
        iam_call(iam_user, 5, "CreatePolicy", {"policyName": "all", "policyDocument": ADMIN_DOC}),
    ]
    assert detect(tmp_path, records, "admin-policy-attached") == []


# --------------------------------------------------------------------------------- discovery-burst


def at(seconds: int) -> str:
    """eventTime the given number of seconds after 2023-01-01T00:00:00Z."""
    return (datetime(2023, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def reads(make, first: int, count: int, seconds: Callable[[int], int], **fields) -> list[dict]:
    """count read calls to different APIs, numbered from first; call i at seconds(i)."""
    return [
        make(first + i, eventName=f"Describe{i:02d}", eventTime=at(seconds(i)), **fields)
        for i in range(count)
    ]


def ids(first: int, count: int) -> list[str]:
    return [eid(n) for n in range(first, first + count)]


def identity_in_fields(n: int, **fields) -> dict:
    """A record whose userIdentity is given in fields."""
    return event(n, None, **fields)


def test_discovery_burst_is_one_finding_per_run(tmp_path: Path) -> None:
    records = [
        *reads(iam_user, 1, 20, lambda i: i * 10),  # 20 APIs in 190 s
        *reads(iam_user, 101, 25, lambda i: 3600 + i, errorCode="AccessDenied"),
    ]
    found = detect(tmp_path, records, "discovery-burst")
    assert found == [
        (
            f"arn:aws:iam::{ACCOUNT}:user/alice",
            "20 read calls to 20 different APIs of 1 service(s) within 3 minutes, "
            "0 failed, from 1 source address(es)",
            ids(1, 20),
            "succeeded",
        ),
        (
            f"arn:aws:iam::{ACCOUNT}:user/alice",
            "25 read calls to 25 different APIs of 1 service(s) within 24 seconds, "
            "25 failed, from 1 source address(es)",
            ids(101, 25),
            "failed",
        ),
    ]


def test_overlapping_windows_merge_and_include_the_whole_window(tmp_path: Path) -> None:
    records = [
        iam_user(1, eventName="GetCallerIdentity", eventTime=at(0)),  # inside the first window
        *reads(iam_user, 2, 20, lambda i: 200 + i * 2),  # 20 APIs by 238 s
        *reads(iam_user, 30, 20, lambda i: 500 + i * 2),  # again by 538 s, windows overlap
        iam_user(60, eventName="ListUsers", eventTime=at(900)),  # after the last window
    ]
    ((_, summary, evidence, _),) = detect(tmp_path, records, "discovery-burst")
    assert evidence == [eid(1), *ids(2, 20), *ids(30, 20)]
    assert summary.startswith("41 read calls to 21 different APIs")


def test_no_burst_below_the_thresholds(tmp_path: Path) -> None:
    records = [
        *reads(iam_user, 1, 19, lambda i: i),  # 19 APIs
        *[iam_user(100 + i, eventName="ListUsers", eventTime=at(1000 + i)) for i in range(50)],
        *reads(iam_user, 200, 20, lambda i: 5000 + i * 20),  # 20 APIs, but over 380 s
        *[iam_user(300 + i, eventName=f"Create{i:02d}", eventTime=at(9000)) for i in range(30)],
    ]
    assert detect(tmp_path, records, "discovery-burst") == []


def test_burst_counts_per_identity_and_skips_calls_made_by_aws(tmp_path: Path) -> None:
    by_service = reads(iam_user, 1, 20, lambda i: i)
    for record in by_service:
        record["userIdentity"]["invokedBy"] = "config.amazonaws.com"
    anonymous = reads(
        identity_in_fields,
        100,
        20,
        lambda i: i,
        userIdentity={"type": "AWSAccount", "principalId": "", "accountId": "ANONYMOUS_PRINCIPAL"},
    )
    records = [
        *by_service,
        *anonymous,
        *reads(aws_service, 200, 20, lambda i: i),
        *reads(iam_user, 300, 10, lambda i: i),  # alice and the role: 10 APIs each
        *reads(assumed_role, 400, 10, lambda i: i),
    ]
    assert detect(tmp_path, records, "discovery-burst") == []


def test_burst_does_not_depend_on_record_order_or_access_keys(tmp_path: Path) -> None:
    # Root calls without an access key, all within one second, in reverse order.
    records = list(reversed(reads(root, 1, 20, lambda i: 42)))
    ((principal, summary, evidence, _),) = detect(tmp_path, records, "discovery-burst")
    assert principal == f"arn:aws:iam::{ACCOUNT}:root"
    assert "within 0 seconds" in summary
    assert evidence == ids(1, 20)


def test_burst_of_another_account_principal(tmp_path: Path) -> None:
    other = {"type": "AWSAccount", "principalId": "AIDAOTHERACCOUNT01", "accountId": "444455556666"}
    records = reads(identity_in_fields, 1, 20, lambda i: i, userIdentity=other)
    ((principal, *_),) = detect(tmp_path, records, "discovery-burst")
    assert principal == "444455556666:AIDAOTHERACCOUNT01"


def test_discovery_thresholds_are_parameters(tmp_path: Path) -> None:
    records = reads(iam_user, 1, 10, lambda i: i * 60)  # 10 APIs in 9 minutes
    assert detect(tmp_path / "a", records, "discovery-burst") == []
    found = detect(
        tmp_path / "b",
        records,
        "discovery-burst",
        "discovery-burst.min_apis=10",
        "discovery-burst.window_seconds=600",
    )
    assert [f[2] for f in found] == [ids(1, 10)]


# ----------------------------------------------------------------------------- access-denied-spike


def denied(make, first: int, count: int, seconds: Callable[[int], int], **fields) -> list[dict]:
    """count calls of make's identity, numbered from first, that fail with AccessDenied."""
    fields.setdefault("errorCode", "AccessDenied")
    fields.setdefault("eventName", "CreateUser")
    return [make(first + i, eventTime=at(seconds(i)), **fields) for i in range(count)]


def test_access_denied_spike_is_detected(tmp_path: Path) -> None:
    records = [
        *denied(iam_user, 1, 20, lambda i: i * 15),  # 20 in 285 s
        *denied(
            assumed_role,
            101,
            30,
            lambda i: 7200 + i // 10,
            eventSource="ec2.amazonaws.com",
            eventName="RunInstances",
            errorCode="Client.UnauthorizedOperation",
        ),
        iam_user(200, eventName="ListUsers", eventTime=at(100)),  # succeeded: not evidence
    ]
    found = detect(tmp_path, records, "access-denied-spike")
    assert found == [
        (
            f"arn:aws:iam::{ACCOUNT}:user/alice",
            "20 denied calls to 1 API(s) of 1 service(s) within 5 minutes, "
            "from 1 source address(es)",
            ids(1, 20),
            "failed",
        ),
        (
            f"arn:aws:sts::{ACCOUNT}:assumed-role/admin/session",
            "30 denied calls to 1 API(s) of 1 service(s) within 2 seconds, "
            "from 1 source address(es)",
            ids(101, 30),
            "failed",
        ),
    ]


def test_other_errors_and_slow_denials_are_not_a_spike(tmp_path: Path) -> None:
    records = [
        *denied(iam_user, 1, 19, lambda i: i),  # one short of the threshold
        *denied(iam_user, 100, 20, lambda i: 5000 + i * 20),  # 20, but over 380 s
        *denied(iam_user, 200, 30, lambda i: 9000, errorCode="Client.RequestLimitExceeded"),
        *denied(iam_user, 300, 30, lambda i: 9500, errorCode="NoSuchBucket"),
    ]
    assert detect(tmp_path, records, "access-denied-spike") == []


def test_denied_calls_made_by_aws_or_anonymous_callers_are_not_counted(tmp_path: Path) -> None:
    by_service = denied(iam_user, 1, 20, lambda i: i)
    for record in by_service:
        record["userIdentity"]["invokedBy"] = "cloudformation.amazonaws.com"
    anonymous = denied(
        identity_in_fields,
        100,
        20,
        lambda i: i,
        userIdentity={"type": "AWSAccount", "principalId": "", "accountId": "ANONYMOUS_PRINCIPAL"},
    )
    records = [*by_service, *anonymous, *denied(aws_service, 200, 20, lambda i: i)]
    assert detect(tmp_path, records, "access-denied-spike") == []


def test_spike_counts_every_permission_error_code_and_ignores_record_order(
    tmp_path: Path,
) -> None:
    codes = [
        "AccessDenied",
        "AccessDeniedException",
        "Client.UnauthorizedOperation",
        "UnauthorizedOperation",
        "AuthorizationError",
        "NotAuthorized",
    ]
    records = [
        iam_user(i + 1, eventName=f"Call{i}", errorCode=codes[i % 6], eventTime=at(60))
        for i in range(24)
    ]
    ((_, summary, evidence, _),) = detect(tmp_path, list(reversed(records)), "access-denied-spike")
    assert evidence == ids(1, 24)
    assert summary.startswith("24 denied calls to 24 API(s)")


# ------------------------------------------------------------------------ snapshot-or-image-shared

OTHER = "444455556666"


def ec2_share(n: int, name: str, params: dict | None, **fields) -> dict:
    return iam_user(
        n, eventSource="ec2.amazonaws.com", eventName=name, requestParameters=params, **fields
    )


def snapshot_permission(change: str, *items: dict) -> dict:
    return {
        "snapshotId": "snap-0123456789abcdef0",
        "createVolumePermission": {change: {"items": list(items)}},
        "attributeType": "CREATE_VOLUME_PERMISSION",
    }


def rds_share(n: int, name: str, params: dict, **fields) -> dict:
    return iam_user(
        n, eventSource="rds.amazonaws.com", eventName=name, requestParameters=params, **fields
    )


def test_shares_with_other_accounts_are_detected(tmp_path: Path) -> None:
    records = [
        ec2_share(1, "ModifySnapshotAttribute", snapshot_permission("add", {"userId": OTHER})),
        ec2_share(2, "ModifySnapshotAttribute", snapshot_permission("add", {"group": "all"})),
        ec2_share(
            3,
            "ModifyImageAttribute",
            {
                "imageId": "ami-0123456789abcdef0",
                "launchPermission": {
                    "add": {
                        "items": [
                            {"userId": OTHER},
                            {"organizationArn": "arn:aws:organizations::444455556666:o-abc"},
                        ]
                    }
                },
                "attributeType": "launchPermission",
            },
        ),
        rds_share(
            4,
            "ModifyDBSnapshotAttribute",
            {"dBSnapshotIdentifier": "db-snap", "attributeName": "restore", "valuesToAdd": [OTHER]},
        ),
        rds_share(
            5,
            "ModifyDBClusterSnapshotAttribute",
            {
                "dBClusterSnapshotIdentifier": "cluster-snap",
                "attributeName": "restore",
                "valuesToAdd": ["all"],
            },
        ),
        ec2_share(
            6,
            "ModifySnapshotAttribute",
            snapshot_permission("add", {"userId": OTHER}),
            errorCode="Client.UnauthorizedOperation",
        ),
    ]
    found = detect(tmp_path, records, "snapshot-or-image-shared")
    assert [(f[1], f[2], f[3]) for f in found] == [
        (
            f"ModifySnapshotAttribute on snap-0123456789abcdef0: shared with {OTHER}",
            [eid(1)],
            "succeeded",
        ),
        (
            "ModifySnapshotAttribute on snap-0123456789abcdef0: shared with everyone (public)",
            [eid(2)],
            "succeeded",
        ),
        (
            f"ModifyImageAttribute on ami-0123456789abcdef0: shared with {OTHER}, "
            "arn:aws:organizations::444455556666:o-abc",
            [eid(3)],
            "succeeded",
        ),
        (f"ModifyDBSnapshotAttribute on db-snap: shared with {OTHER}", [eid(4)], "succeeded"),
        (
            "ModifyDBClusterSnapshotAttribute on cluster-snap: shared with everyone (public)",
            [eid(5)],
            "succeeded",
        ),
        (
            f"ModifySnapshotAttribute on snap-0123456789abcdef0: shared with {OTHER} "
            "(failed: Client.UnauthorizedOperation)",
            [eid(6)],
            "failed",
        ),
    ]


def test_removals_own_account_and_other_attributes_are_not_shares(tmp_path: Path) -> None:
    records = [
        ec2_share(1, "ModifySnapshotAttribute", snapshot_permission("remove", {"userId": OTHER})),
        ec2_share(2, "ModifySnapshotAttribute", snapshot_permission("add", {"userId": ACCOUNT})),
        ec2_share(3, "ModifySnapshotAttribute", None, errorCode="AccessDenied"),
        ec2_share(
            4,
            "ModifyImageAttribute",
            {"imageId": "ami-0123456789abcdef0", "description": {"value": "golden image"}},
        ),
        rds_share(
            5,
            "ModifyDBSnapshotAttribute",
            {
                "dBSnapshotIdentifier": "db-snap",
                "attributeName": "restore",
                "valuesToRemove": [OTHER],
            },
        ),
        ec2_share(6, "ModifyInstanceAttribute", snapshot_permission("add", {"userId": OTHER})),
    ]
    assert detect(tmp_path, records, "snapshot-or-image-shared") == []


# ----------------------------------------------------------------------------- new-region-activity

DAY = 86400


def in_region(make, n: int, seconds: int, region: str, name: str = "RunInstances", **fields):
    return make(
        n,
        eventSource="ec2.amazonaws.com",
        eventName=name,
        awsRegion=region,
        eventTime=at(seconds),
        **fields,
    )


def test_first_activity_in_new_regions_is_one_finding_per_day(tmp_path: Path) -> None:
    records = [
        in_region(iam_user, 1, 0, "us-east-1"),
        in_region(iam_user, 2, 3 * DAY, "us-west-2"),  # new, but within the baseline
        in_region(iam_user, 3, 10 * DAY, "ap-south-1"),
        in_region(
            iam_user, 4, 10 * DAY + 60, "sa-east-1", errorCode="Client.UnauthorizedOperation"
        ),
        in_region(iam_user, 5, 10 * DAY + 120, "ap-south-1", name="CreateKeyPair"),
        in_region(iam_user, 6, 11 * DAY + 10, "ap-south-1"),  # more than 24 h after first use
        in_region(iam_user, 7, 12 * DAY, "us-east-1"),  # known region
        in_region(iam_user, 8, 20 * DAY, "eu-west-1"),
    ]
    found = detect(tmp_path, records, "new-region-activity")
    assert found == [
        (
            f"arn:aws:iam::{ACCOUNT}:user/alice",
            "first activity in 2 new region(s): ap-south-1, sa-east-1 "
            "(active since 2023-01-01 in 2 other region(s))",
            [eid(3), eid(4), eid(5)],
            "partly failed",
        ),
        (
            f"arn:aws:iam::{ACCOUNT}:user/alice",
            "first activity in 1 new region(s): eu-west-1 "
            "(active since 2023-01-01 in 4 other region(s))",
            [eid(8)],
            "succeeded",
        ),
    ]


def test_global_services_reads_and_aws_calls_do_not_count(tmp_path: Path) -> None:
    by_service = in_region(iam_user, 4, 10 * DAY, "ap-south-1")
    by_service["userIdentity"]["invokedBy"] = "cloudformation.amazonaws.com"
    records = [
        in_region(iam_user, 1, 0, "eu-west-1"),
        # IAM is global: CloudTrail logs it in us-east-1 wherever the caller works.
        iam_user(2, eventName="CreateUser", awsRegion="us-east-1", eventTime=at(10 * DAY)),
        in_region(iam_user, 3, 10 * DAY, "ap-south-1", name="DescribeInstances"),
        by_service,
        in_region(aws_service, 5, 10 * DAY, "sa-east-1"),
    ]
    assert detect(tmp_path, records, "new-region-activity") == []


def test_reads_count_when_asked_and_do_not_hide_a_later_write(tmp_path: Path) -> None:
    records = [
        in_region(iam_user, 1, 0, "eu-west-1"),
        in_region(iam_user, 2, 10 * DAY, "ap-south-1", name="DescribeRegions"),  # a sweep
        in_region(iam_user, 3, 10 * DAY + 30, "ap-south-1"),  # then a write
    ]
    assert [f[2] for f in detect(tmp_path / "a", records, "new-region-activity")] == [[eid(3)]]
    with_reads = detect(
        tmp_path / "b", records, "new-region-activity", "new-region-activity.count_read_calls=true"
    )
    assert [f[2] for f in with_reads] == [[eid(2), eid(3)]]


def test_role_sessions_share_the_role_history(tmp_path: Path) -> None:
    other_session = in_region(assumed_role, 2, 10 * DAY, "ap-south-1")
    other_session["userIdentity"]["arn"] = f"arn:aws:sts::{ACCOUNT}:assumed-role/admin/other"
    records = [in_region(assumed_role, 1, 0, "us-east-1"), other_session]
    ((principal, summary, evidence, _),) = detect(tmp_path, records, "new-region-activity")
    assert principal == f"arn:aws:iam::{ACCOUNT}:role/admin"
    assert evidence == [eid(2)]
    assert summary.endswith("(active since 2023-01-01 in 1 other region(s))")


def test_baseline_is_a_parameter_and_record_order_does_not_matter(tmp_path: Path) -> None:
    records = [
        in_region(iam_user, 2, 2 * DAY, "ap-south-1"),
        in_region(iam_user, 1, 0, "us-east-1"),
    ]
    assert detect(tmp_path / "a", records, "new-region-activity") == []
    found = detect(
        tmp_path / "b", records, "new-region-activity", "new-region-activity.baseline_days=1"
    )
    assert [f[2] for f in found] == [[eid(2)]]
