"""Tests for turning CloudTrail records into events rows."""

import pytest

from cloudtrail_events import (
    ACCESS_KEY,
    ACCOUNT,
    SESSION_KEY,
    assumed_role,
    aws_service,
    event,
    iam_user,
    root,
)
from ctinv.normalize import InvalidRecord, normalize, utc_timestamp
from ctinv.schema import EVENT_COLUMNS

# Added by ingest, not by normalize: provenance, and the hash DuckDB computes on load.
NOT_FROM_NORMALIZE = {"dataset", "source_file", "source_index", "raw_sha256"}


def test_row_has_exactly_the_event_columns() -> None:
    assert set(normalize(iam_user(1))) == {c.name for c in EVENT_COLUMNS} - NOT_FROM_NORMALIZE


def test_iam_user() -> None:
    record = iam_user(1, requestParameters={"userName": "bob"})
    row = normalize(record)
    assert row["event_id"] == "00000000-0000-0000-0000-000000000001"
    assert row["event_time"] == "2023-01-01 00:00:01"
    assert row["identity_type"] == "IAMUser"
    assert row["user_name"] == "alice"
    assert row["access_key_id"] == ACCESS_KEY
    assert row["session_issuer_arn"] is None
    assert row["mfa_authenticated"] is None
    assert row["read_only"] is True
    assert row["request_parameters"] == {"userName": "bob"}
    assert row["raw"] is record


@pytest.mark.parametrize(("mfa", "expected"), [("true", True), ("false", False)])
def test_assumed_role(mfa: str, expected: bool) -> None:
    row = normalize(assumed_role(2, mfa=mfa))
    assert row["identity_type"] == "AssumedRole"
    assert row["user_name"] is None
    assert row["access_key_id"] == SESSION_KEY
    assert row["session_issuer_arn"] == f"arn:aws:iam::{ACCOUNT}:role/admin"
    assert row["mfa_authenticated"] is expected


def test_root_without_user_name_and_with_empty_access_key() -> None:
    row = normalize(root(3))
    assert row["identity_type"] == "Root"
    assert row["identity_arn"] == f"arn:aws:iam::{ACCOUNT}:root"
    assert row["user_name"] is None
    assert row["access_key_id"] is None


def test_aws_service() -> None:
    row = normalize(aws_service(4))
    assert row["identity_type"] == "AWSService"
    assert row["invoked_by"] == "ec2.amazonaws.com"
    assert row["identity_arn"] is None


def test_missing_optional_fields_become_null() -> None:
    minimal = {
        "eventID": "e-1",
        "eventTime": "2023-01-01T00:00:00Z",
        "eventSource": "s3.amazonaws.com",
        "eventName": "GetObject",
    }
    row = normalize(minimal)
    optional = [
        k for k in row if k not in ("event_id", "event_time", "event_source", "event_name", "raw")
    ]
    assert all(row[k] is None for k in optional)


@pytest.mark.parametrize(("value", "expected"), [("true", True), ("FALSE", False), (False, False)])
def test_read_only_accepts_booleans_and_boolean_strings(value: object, expected: bool) -> None:
    assert normalize(iam_user(5, readOnly=value))["read_only"] is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2023-01-01T00:00:00Z", "2023-01-01 00:00:00"),
        ("2023-01-01T02:30:00+02:00", "2023-01-01 00:30:00"),
        ("2022-12-31T23:59:59.250-01:00", "2023-01-01 00:59:59.250000"),
    ],
)
def test_event_time_is_converted_to_utc(value: str, expected: str) -> None:
    assert utc_timestamp(value) == expected


@pytest.mark.parametrize(
    ("record", "reason"),
    [
        ([1, 2], "not a JSON object but an array"),
        ("text", "not a JSON object but a string"),
        ({k: v for k, v in iam_user(6).items() if k != "eventID"}, "missing or empty eventID"),
        (iam_user(6, eventName="  "), "missing or empty eventName"),
        (iam_user(6, eventTime="yesterday"), "is not an ISO 8601 timestamp"),
        (iam_user(6, eventTime="2023-01-01T00:00:00"), "has no time zone"),
        (iam_user(6, eventTime="9999-12-31T23:59:59-05:00"), "is out of range"),
        (iam_user(6, readOnly="maybe"), "readOnly is 'maybe', expected true or false"),
        (iam_user(6, awsRegion=42), "awsRegion is a number, expected a string"),
        (event(6, "not-an-object"), "userIdentity is a string, expected an object"),
        (assumed_role(6, mfa="sometimes"), "mfaAuthenticated is 'sometimes'"),
    ],
)
def test_invalid_records_are_rejected_with_a_reason(record: object, reason: str) -> None:
    with pytest.raises(InvalidRecord, match=reason.replace("(", r"\(").replace(")", r"\)")):
        normalize(record)
