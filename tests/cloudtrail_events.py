"""Synthetic CloudTrail records for tests. All IDs and keys are clearly fake."""

from typing import Any

ACCOUNT = "111122223333"
ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"  # AWS's documented example key
SESSION_KEY = "ASIAIOSFODNN7EXAMPLE"


def event(n: int, identity: dict[str, Any] | None, **fields: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "eventVersion": "1.08",
        "eventTime": f"2023-01-01T00:00:{n % 60:02d}Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "ListUsers",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.10",
        "userAgent": "aws-cli/2.0",
        "requestParameters": None,
        "responseElements": None,
        "requestID": f"req-{n}",
        "eventID": f"00000000-0000-0000-0000-{n:012d}",
        "readOnly": True,
        "eventType": "AwsApiCall",
        "recipientAccountId": ACCOUNT,
    }
    if identity is not None:
        record["userIdentity"] = identity
    record.update(fields)
    return record


def iam_user(n: int, **fields: Any) -> dict[str, Any]:
    identity = {
        "type": "IAMUser",
        "principalId": "AIDAEXAMPLEUSERID0001",
        "arn": f"arn:aws:iam::{ACCOUNT}:user/alice",
        "accountId": ACCOUNT,
        "accessKeyId": ACCESS_KEY,
        "userName": "alice",
    }
    return event(n, identity, **fields)


def assumed_role(n: int, mfa: str = "false", **fields: Any) -> dict[str, Any]:
    identity = {
        "type": "AssumedRole",
        "principalId": "AROAEXAMPLEROLEID0001:session",
        "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/admin/session",
        "accountId": ACCOUNT,
        "accessKeyId": SESSION_KEY,
        "sessionContext": {
            "sessionIssuer": {
                "type": "Role",
                "principalId": "AROAEXAMPLEROLEID0001",
                "arn": f"arn:aws:iam::{ACCOUNT}:role/admin",
                "accountId": ACCOUNT,
                "userName": "admin",
            },
            "attributes": {"creationDate": "2023-01-01T00:00:00Z", "mfaAuthenticated": mfa},
        },
    }
    return event(n, identity, **fields)


def root(n: int, **fields: Any) -> dict[str, Any]:
    # Without an account alias, Root has no userName (AWS userIdentity documentation).
    identity = {
        "type": "Root",
        "principalId": ACCOUNT,
        "arn": f"arn:aws:iam::{ACCOUNT}:root",
        "accountId": ACCOUNT,
        "accessKeyId": "",
    }
    return event(n, identity, **fields)


def aws_service(n: int, **fields: Any) -> dict[str, Any]:
    return event(n, {"type": "AWSService", "invokedBy": "ec2.amazonaws.com"}, **fields)
