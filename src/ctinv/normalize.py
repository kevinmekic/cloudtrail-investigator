"""Turn one CloudTrail record into a row of the ``events`` table.

Normalization is strict: a value of an unexpected type is not coerced, the
record is rejected with the reason and ends up in the quarantine. The only
cleaning is ``accessKeyId: ""`` (no key) becoming NULL.
"""

from datetime import UTC, datetime
from typing import Any

REQUIRED_FIELDS = ("eventID", "eventTime", "eventSource", "eventName")


class InvalidRecord(ValueError):
    """The record cannot become an events row; the message is the quarantine reason."""


def normalize(record: Any) -> dict[str, Any]:
    """Return the events columns of a record (without the provenance columns)."""
    if not isinstance(record, dict):
        raise InvalidRecord(f"not a JSON object but {_type_name(record)}")
    for field in REQUIRED_FIELDS:
        value = record.get(field)
        if not isinstance(value, str) or not value.strip():
            raise InvalidRecord(f"missing or empty {field}")

    identity = _object(record, "userIdentity", "userIdentity")
    session = _object(identity, "sessionContext", "userIdentity.sessionContext")
    issuer = _object(session, "sessionIssuer", "userIdentity.sessionContext.sessionIssuer")
    attributes = _object(session, "attributes", "userIdentity.sessionContext.attributes")
    return {
        "event_id": record["eventID"],
        "event_time": utc_timestamp(record["eventTime"]),
        "event_source": record["eventSource"],
        "event_name": record["eventName"],
        "aws_region": _string(record, "awsRegion", "awsRegion"),
        "source_ip_address": _string(record, "sourceIPAddress", "sourceIPAddress"),
        "user_agent": _string(record, "userAgent", "userAgent"),
        "error_code": _string(record, "errorCode", "errorCode"),
        "error_message": _string(record, "errorMessage", "errorMessage"),
        "read_only": _boolean(record, "readOnly", "readOnly"),
        "event_type": _string(record, "eventType", "eventType"),
        "recipient_account_id": _string(record, "recipientAccountId", "recipientAccountId"),
        "event_version": _string(record, "eventVersion", "eventVersion"),
        "request_id": _string(record, "requestID", "requestID"),
        "shared_event_id": _string(record, "sharedEventID", "sharedEventID"),
        "identity_type": _string(identity, "type", "userIdentity.type"),
        "identity_arn": _string(identity, "arn", "userIdentity.arn"),
        "identity_principal_id": _string(identity, "principalId", "userIdentity.principalId"),
        "identity_account_id": _string(identity, "accountId", "userIdentity.accountId"),
        "access_key_id": _string(identity, "accessKeyId", "userIdentity.accessKeyId") or None,
        "user_name": _string(identity, "userName", "userIdentity.userName"),
        "invoked_by": _string(identity, "invokedBy", "userIdentity.invokedBy"),
        "session_issuer_arn": _string(
            issuer, "arn", "userIdentity.sessionContext.sessionIssuer.arn"
        ),
        "mfa_authenticated": _boolean(
            attributes,
            "mfaAuthenticated",
            "userIdentity.sessionContext.attributes.mfaAuthenticated",
        ),
        "request_parameters": record.get("requestParameters"),
        "response_elements": record.get("responseElements"),
        "additional_event_data": record.get("additionalEventData"),
        "resources": record.get("resources"),
        "raw": record,
    }


def utc_timestamp(value: str) -> str:
    """ISO 8601 timestamp with a time zone -> naive UTC text for a DuckDB TIMESTAMP."""
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise InvalidRecord(f"eventTime {value!r} is not an ISO 8601 timestamp") from None
    if parsed.tzinfo is None:
        raise InvalidRecord(f"eventTime {value!r} has no time zone")
    try:
        utc = parsed.astimezone(UTC)
    except OverflowError:
        raise InvalidRecord(f"eventTime {value!r} is out of range") from None
    return utc.replace(tzinfo=None).isoformat(sep=" ")


def _type_name(value: Any) -> str:
    return {dict: "an object", list: "an array", str: "a string", bool: "a boolean"}.get(
        type(value), "null" if value is None else "a number"
    )


def _object(parent: dict | None, key: str, path: str) -> dict | None:
    value = None if parent is None else parent.get(key)
    if value is not None and not isinstance(value, dict):
        raise InvalidRecord(f"{path} is {_type_name(value)}, expected an object")
    return value


def _string(parent: dict | None, key: str, path: str) -> str | None:
    value = None if parent is None else parent.get(key)
    if value is not None and not isinstance(value, str):
        raise InvalidRecord(f"{path} is {_type_name(value)}, expected a string")
    return value


def _boolean(parent: dict | None, key: str, path: str) -> bool | None:
    """CloudTrail writes booleans as JSON booleans or as the strings "true"/"false"."""
    value = None if parent is None else parent.get(key)
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in ("true", "false"):
        return value.lower() == "true"
    raise InvalidRecord(f"{path} is {value!r}, expected true or false")
