"""Investigation of one identity: timeline, session graph, blast radius, findings.

The starting point is an access key or a principal ARN. Its events form the
first session of a session graph. From there the investigation follows the
credentials the identity obtained: a successful call that issues an access
key (``sts:AssumeRole``, ``sts:GetSessionToken``, ``sts:GetFederationToken``
and the other STS calls that return credentials) names the new key in
``responseElements``, and later events that use that key
(``userIdentity.accessKeyId``) become a new session one level deeper.

Every credential-issuing call of a session is recorded as a pivot with a
status, so that the analyst sees which pivots were followed and why the others
were not (request failed, key not in the log, key never used, limits reached).

The blast radius lists the resources the investigated events name, per service,
split into succeeded, denied (permission errors) and failed (other errors).
Resources come from the event's ``resources`` field and from request parameters
that name a resource (``RESOURCE_PARAMETERS``).

Findings of ``ctinv detect`` belong to the investigation when at least one of
their evidence events is an event of the session graph.

Bounded by design: ``max_depth`` caps how many pivots deep the graph goes,
``max_sessions`` caps how many sessions are followed, ``max_events`` caps how
many events the timeline lists, ``max_resources`` how many resources are listed
per service and ``max_evidence`` how many eventIDs are listed per entry (counts
are always complete). A key already in the graph is never followed again, so
cycles end.
"""

import dataclasses
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import duckdb

from ctinv import __version__, macros

# STS calls that issue temporary credentials. A call not listed here also
# counts if its response carries credentials (future STS APIs).
ISSUING_STS_CALLS = (
    "AssumeRole",
    "AssumeRoleWithSAML",
    "AssumeRoleWithWebIdentity",
    "GetFederationToken",
    "GetSessionToken",
)
# Creates a long-term key; followed only on request (see ``follow_created_keys``).
CREATE_ACCESS_KEY = ("iam.amazonaws.com", "CreateAccessKey")

# Access key IDs are 16 to 128 characters; CloudTrail logs them in upper case
# letters and digits. Anything else (missing, empty, a placeholder such as
# HIDDEN_DUE_TO_SECURITY_REASONS) cannot be linked to later events.
_ACCESS_KEY = re.compile(r"[A-Z0-9]{16,128}")
_ROLE_ARN = re.compile(r"arn:[^:]+:iam::\d{12}:role/.+")

# Request parameters that name a resource: (service, parameter, resource type).
# The service is the event source without ".amazonaws.com". Parameters are
# matched at any depth (EC2 nests them in item lists). The same parameter can
# mean different things per service ("groupName" is a security group in EC2 and
# a group in IAM; "name" is a filter name in EC2 but a trail in CloudTrail), so
# it only counts for the services listed. Chosen from the parameters seen in the
# flaws.cloud and Invictus data; other parameters are not read as resources.
RESOURCE_PARAMETERS: tuple[tuple[str, str, str], ...] = (
    ("s3", "bucketName", "bucket"),
    ("ec2", "instanceId", "instance"),
    ("ec2", "imageId", "image"),
    ("ec2", "snapshotId", "snapshot"),
    ("ec2", "sourceSnapshotId", "snapshot"),
    ("ec2", "volumeId", "volume"),
    ("ec2", "groupId", "security group"),
    ("ec2", "groupName", "security group"),
    ("ec2", "vpcId", "vpc"),
    ("ec2", "subnetId", "subnet"),
    ("ec2", "keyName", "key pair"),
    ("ec2", "allocationId", "elastic ip"),
    ("iam", "userName", "user"),
    ("iam", "roleName", "role"),
    ("iam", "groupName", "group"),
    ("iam", "policyArn", "policy"),
    ("iam", "instanceProfileName", "instance profile"),
    ("iam", "accessKeyId", "access key"),
    ("iam", "serialNumber", "mfa device"),
    ("sts", "serialNumber", "mfa device"),
    ("sts", "roleArn", "role"),
    ("lambda", "functionName", "function"),
    ("logs", "logGroupName", "log group"),
    ("apigateway", "restApiId", "rest api"),
    ("cloudtrail", "name", "trail"),
    ("cloudtrail", "trailName", "trail"),
    ("ssm", "instanceId", "instance"),
    ("ssm", "name", "parameter"),
    ("secretsmanager", "name", "secret"),
    ("secretsmanager", "secretId", "secret"),
    ("kms", "keyId", "key"),
    ("cloudformation", "stackName", "stack"),
    ("rds", "dBInstanceIdentifier", "db instance"),
    ("rds", "dBClusterIdentifier", "db cluster"),
    ("rds", "dBSnapshotIdentifier", "db snapshot"),
    ("rds", "dBClusterSnapshotIdentifier", "db cluster snapshot"),
)
# Types of the resources field that name the same kinds as parameters above, so
# both sources merge into one entry. Other types are kept as AWS states them.
RESOURCE_FIELD_TYPES = {
    "AWS::S3::Bucket": "bucket",
    "AWS::S3::Object": "object",
    "AWS::IAM::Role": "role",
    "AWS::KMS::Key": "key",
}
OUTCOMES = ("succeeded", "denied", "failed")

PIVOT_STATUSES = {
    "followed": "the issued key is used later; its events are the next session",
    "already_in_graph": "the issued key, or every event using it, is already in the graph",
    "not_used": "no event in the investigated time range uses the issued key",
    "depth_limit": "not followed: the session would be deeper than the depth limit",
    "session_limit": "not followed: the session limit was reached",
    "created_key_not_followed": "a key created with CreateAccessKey; followed only on request",
    "key_not_logged": "the call succeeded but the log does not name a usable key",
    "request_failed": "the call returned an error, so no key was issued",
}

OUTCOME_SQL = (
    "CASE WHEN e.error_code IS NULL THEN 'succeeded' "
    "WHEN ctinv_is_access_denied(e.error_code) THEN 'denied' ELSE 'failed' END"
)
# Who made a call, for display: the ARN, else the AWS service acting, else the
# account and principal ID (identities from other accounts have no ARN).
CALLER_SQL = (
    "coalesce(e.identity_arn, e.invoked_by, "
    "e.identity_account_id || ':' || e.identity_principal_id, e.identity_type)"
)
_ISSUED_KEY_SQL = (
    "CASE WHEN e.event_source = 'iam.amazonaws.com' "
    "THEN e.response_elements->>'$.accessKey.accessKeyId' "
    "ELSE e.response_elements->>'$.credentials.accessKeyId' END"
)
_ISSUING_SQL = (
    "((e.event_source = 'sts.amazonaws.com' AND (e.event_name IN ("
    + ", ".join(f"'{name}'" for name in ISSUING_STS_CALLS)
    + ") OR (e.response_elements->'$.credentials.accessKeyId') IS NOT NULL))"
    f" OR (e.event_source = '{CREATE_ACCESS_KEY[0]}' AND e.event_name = '{CREATE_ACCESS_KEY[1]}'))"
)
# What the call asked for: the role, the federated user name, or the IAM user
# that receives a new key (absent: the caller's own user).
_TARGET_SQL = (
    "coalesce(e.request_parameters->>'roleArn', e.request_parameters->>'userName', "
    "e.request_parameters->>'name')"
)
_ISSUED_IDENTITY_SQL = (
    "coalesce(e.response_elements->>'$.assumedRoleUser.arn', "
    "e.response_elements->>'$.federatedUser.arn')"
)


class InvestigationError(ValueError):
    """The investigation cannot run, e.g. no event matches the starting point."""


@dataclass(frozen=True)
class Scope:
    """What is investigated and how far.

    ``start`` is inclusive, ``end`` exclusive; both are naive UTC datetimes.
    """

    access_key: str | None = None
    principal: str | None = None
    start: datetime | None = None
    end: datetime | None = None
    max_depth: int = 3
    max_sessions: int = 1000
    max_events: int = 100_000
    max_resources: int = 1000
    max_evidence: int = 20
    follow_created_keys: bool = False

    def __post_init__(self) -> None:
        if bool(self.access_key) == bool(self.principal):
            raise InvestigationError("give exactly one non-empty access key or principal")
        if self.start and self.end and self.start >= self.end:
            raise InvestigationError("the start of the time range must be before its end")
        for name in ("max_depth", "max_sessions", "max_events", "max_resources", "max_evidence"):
            if getattr(self, name) < 0:
                raise InvestigationError(f"{name} must not be negative")

    @property
    def root(self) -> str:
        return self.access_key or self.principal  # type: ignore[return-value]


@dataclass
class Pivot:
    """A call of a session that issues (or tried to issue) an access key."""

    event_id: str
    event_time: datetime
    from_session: str
    api: str
    caller: str | None
    target: str | None
    session_name: str | None
    outcome: str
    error_code: str | None
    issued_key: str | None
    issued_identity: str | None
    status: str = ""
    to_session: str | None = None


@dataclass
class Session:
    """A node of the session graph: the starting identity or a key it obtained."""

    id: str
    kind: str
    depth: int
    parent: str | None = None
    via_event_id: str | None = None
    events: int = 0
    succeeded: int = 0
    denied: int = 0
    failed: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    identities: list[dict[str, Any]] = field(default_factory=list)
    access_keys: list[dict[str, Any]] = field(default_factory=list)
    source_ips: list[dict[str, Any]] = field(default_factory=list)
    user_agents: list[dict[str, Any]] = field(default_factory=list)
    regions: list[dict[str, Any]] = field(default_factory=list)
    distinct: dict[str, int] = field(default_factory=dict)
    issued_by: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class Investigation:
    scope: Scope
    sessions: list[Session]
    pivots: list[Pivot]
    summary: dict[str, Any]
    apis: list[dict[str, Any]]
    timeline: list[dict[str, Any]]
    blast_radius: dict[str, Any]
    # None: detection was never run on the database, so absence means nothing.
    findings: list[dict[str, Any]] | None


def key_kind(key: str) -> str:
    """Kind of an access key ID by its documented prefix."""
    if key.startswith("AKIA"):
        return "long-term key"
    if key.startswith("ASIA"):
        return "temporary key"
    return "access key"


def is_usable_key(value: str | None) -> bool:
    return value is not None and _ACCESS_KEY.fullmatch(value) is not None


def _window_sql(scope: Scope) -> str:
    parts = []
    if scope.start:
        parts.append("e.event_time >= $start")
    if scope.end:
        parts.append("e.event_time < $end")
    return " AND ".join(parts) or "true"


def _window_params(scope: Scope) -> dict[str, Any]:
    params: dict[str, Any] = {}
    if scope.start:
        params["start"] = scope.start
    if scope.end:
        params["end"] = scope.end
    return params


def investigate(con: duckdb.DuckDBPyConnection, scope: Scope) -> Investigation:
    """Investigate the starting identity and the sessions it obtained.

    Returns the session graph with every pivot, per-API counts, the timeline,
    the blast radius and the linked findings. Works in temporary tables of the
    connection (``inv_*``); the database itself is not changed.
    """
    macros.register(con)
    window = _window_sql(scope)
    params = _window_params(scope)
    con.execute(
        "CREATE OR REPLACE TEMP TABLE inv_events "
        "(event_id VARCHAR PRIMARY KEY, session VARCHAR NOT NULL, depth INTEGER NOT NULL)"
    )

    if scope.access_key:
        root = Session(scope.access_key, key_kind(scope.access_key), 0)
        match = "e.access_key_id = $root"
    else:
        root = Session(scope.principal, "principal", 0)  # type: ignore[arg-type]
        # A role never calls anything itself; its ARN stands for all its sessions.
        match = (
            "(e.identity_arn = $root OR e.session_issuer_arn = $root)"
            if _ROLE_ARN.fullmatch(scope.principal or "")
            else "e.identity_arn = $root"
        )
    con.execute(
        f"INSERT INTO inv_events SELECT e.event_id, $root, 0 FROM events e "
        f"WHERE {match} AND {window}",
        {"root": scope.root, **params},
    )
    if not con.execute("SELECT count(*) FROM inv_events").fetchone()[0]:
        what = "access key" if scope.access_key else "principal"
        raise InvestigationError(
            f"no events for {what} {scope.root}" + (" in the given time range" if params else "")
        )

    sessions = {root.id: root}
    pivots: list[Pivot] = []
    depth = 0
    while True:
        level = _pivots_at(con, depth)
        pivots.extend(level)
        candidates = _classify(level, sessions, depth, scope)
        new = _follow(con, candidates, sessions, depth + 1, scope, window, params)
        if not new:
            break
        depth += 1

    _describe_sessions(con, list(sessions.values()))
    return Investigation(
        scope=scope,
        sessions=list(sessions.values()),
        pivots=pivots,
        summary=_summary(con, sessions, pivots),
        apis=_api_counts(con),
        timeline=_timeline(con, scope.max_events),
        blast_radius=_blast_radius(con, scope),
        findings=_findings(con, scope),
    )


def _pivots_at(con: duckdb.DuckDBPyConnection, depth: int) -> list[Pivot]:
    rows = con.execute(
        f"""
        SELECT e.event_id, e.event_time, i.session,
               replace(e.event_source, '.amazonaws.com', '') || ':' || e.event_name,
               {CALLER_SQL}, {_TARGET_SQL}, e.request_parameters->>'roleSessionName',
               {OUTCOME_SQL}, e.error_code, {_ISSUED_KEY_SQL}, {_ISSUED_IDENTITY_SQL}
        FROM inv_events i JOIN events e ON e.event_id = i.event_id
        WHERE i.depth = $depth AND {_ISSUING_SQL}
        ORDER BY e.event_time, e.event_id
        """,
        {"depth": depth},
    ).fetchall()
    return [Pivot(*row) for row in rows]


def _classify(
    level: list[Pivot], sessions: dict[str, Session], depth: int, scope: Scope
) -> dict[str, Pivot]:
    """Set the status of each pivot that cannot be followed; return the rest by key."""
    candidates: dict[str, Pivot] = {}
    for pivot in level:
        if pivot.outcome != "succeeded":
            pivot.status = "request_failed"
        elif not is_usable_key(pivot.issued_key):
            pivot.status = "key_not_logged"
        elif pivot.api == "iam:CreateAccessKey" and not scope.follow_created_keys:
            pivot.status = "created_key_not_followed"
        elif pivot.issued_key in sessions or pivot.issued_key in candidates:
            pivot.status = "already_in_graph"
        elif depth + 1 > scope.max_depth:
            pivot.status = "depth_limit"
        else:
            candidates[pivot.issued_key] = pivot  # type: ignore[index]
    return candidates


def _follow(
    con: duckdb.DuckDBPyConnection,
    candidates: dict[str, Pivot],
    sessions: dict[str, Session],
    depth: int,
    scope: Scope,
    window: str,
    params: dict[str, Any],
) -> list[str]:
    """Add the used candidate keys as sessions at ``depth``; return the new keys."""
    if not candidates:
        return []
    con.execute(
        "CREATE OR REPLACE TEMP TABLE inv_keys AS SELECT unnest($keys::VARCHAR[]) AS key",
        {"keys": list(candidates)},
    )
    usage = {
        key: (total, new)
        for key, total, new in con.execute(
            f"""
            SELECT e.access_key_id, count(*), count(*) FILTER (WHERE i.event_id IS NULL)
            FROM events e LEFT JOIN inv_events i ON i.event_id = e.event_id
            WHERE e.access_key_id IN (SELECT key FROM inv_keys) AND {window}
            GROUP BY 1
            """,
            params,
        ).fetchall()
    }
    followed = []
    for key, pivot in candidates.items():
        total, new = usage.get(key, (0, 0))
        if not total:
            pivot.status = "not_used"
        elif not new:
            pivot.status = "already_in_graph"
        elif len(sessions) - 1 >= scope.max_sessions:
            pivot.status = "session_limit"
        else:
            pivot.status = "followed"
            pivot.to_session = key
            sessions[key] = Session(
                key, key_kind(key), depth, parent=pivot.from_session, via_event_id=pivot.event_id
            )
            followed.append(key)
    if followed:
        con.execute(
            "CREATE OR REPLACE TEMP TABLE inv_keys AS SELECT unnest($keys::VARCHAR[]) AS key",
            {"keys": followed},
        )
        con.execute(
            f"""
            INSERT INTO inv_events
            SELECT e.event_id, e.access_key_id, $depth FROM events e
            ANTI JOIN inv_events i ON i.event_id = e.event_id
            WHERE e.access_key_id IN (SELECT key FROM inv_keys) AND {window}
            """,
            {"depth": depth, **params},
        )
    return followed


_INV = "inv_events i JOIN events e ON e.event_id = i.event_id"


def _top(con: duckdb.DuckDBPyConnection, expression: str, limit: int) -> dict[str, list[dict]]:
    """The most frequent values of an expression per session, with event counts."""
    rows = con.execute(
        f"""
        SELECT session, value, n FROM (
            SELECT session, value, count(*) AS n,
                   row_number() OVER (PARTITION BY session ORDER BY count(*) DESC, value) AS r
            FROM (SELECT i.session, {expression} AS value FROM {_INV})
            WHERE value IS NOT NULL GROUP BY session, value)
        WHERE r <= $limit ORDER BY session, n DESC, value
        """,
        {"limit": limit},
    ).fetchall()
    top: dict[str, list[dict]] = {}
    for session, value, n in rows:
        top.setdefault(session, []).append({"value": value, "events": n})
    return top


def _describe_sessions(con: duckdb.DuckDBPyConnection, sessions: list[Session]) -> None:
    by_id = {s.id: s for s in sessions}
    for row in con.execute(
        f"""
        SELECT i.session, count(*),
               count(*) FILTER (WHERE {OUTCOME_SQL} = 'succeeded'),
               count(*) FILTER (WHERE {OUTCOME_SQL} = 'denied'),
               count(*) FILTER (WHERE {OUTCOME_SQL} = 'failed'),
               min(e.event_time), max(e.event_time),
               count(DISTINCT {CALLER_SQL}), count(DISTINCT e.access_key_id),
               count(DISTINCT e.source_ip_address), count(DISTINCT e.user_agent),
               count(DISTINCT e.aws_region)
        FROM {_INV} GROUP BY 1
        """
    ).fetchall():
        s = by_id[row[0]]
        s.events, s.succeeded, s.denied, s.failed, s.first_seen, s.last_seen = row[1:7]
        s.distinct = dict(
            zip(
                ("identities", "access_keys", "source_ips", "user_agents", "regions"),
                row[7:],
                strict=True,
            )
        )
    for attr, expression, limit in (
        ("identities", CALLER_SQL, 10),
        ("access_keys", "e.access_key_id", 10),
        ("source_ips", "e.source_ip_address", 10),
        ("user_agents", "e.user_agent", 5),
        ("regions", "e.aws_region", 20),
    ):
        for session, values in _top(con, expression, limit).items():
            setattr(by_id[session], attr, values)

    # Where each key came from, searched in the whole database (not limited to
    # the time range): the call whose response issued it.
    keys = [s.id for s in sessions if s.kind != "principal"]
    if not keys:
        return
    con.execute(
        "CREATE OR REPLACE TEMP TABLE inv_keys AS SELECT unnest($keys::VARCHAR[]) AS key",
        {"keys": keys},
    )
    for key, *origin in con.execute(
        f"""
        SELECT k.key, e.event_id, e.event_time,
               replace(e.event_source, '.amazonaws.com', '') || ':' || e.event_name,
               {CALLER_SQL}, e.access_key_id, {_TARGET_SQL},
               e.request_parameters->>'roleSessionName', e.source_ip_address
        FROM events e JOIN inv_keys k ON k.key = {_ISSUED_KEY_SQL}
        WHERE e.error_code IS NULL AND {_ISSUING_SQL}
        ORDER BY e.event_time, e.event_id
        """
    ).fetchall():
        by_id[key].issued_by.append(
            dict(
                zip(
                    (
                        "event_id",
                        "event_time",
                        "api",
                        "caller",
                        "caller_access_key",
                        "target",
                        "session_name",
                        "source_ip",
                    ),
                    origin,
                    strict=True,
                )
            )
        )


def _summary(
    con: duckdb.DuckDBPyConnection, sessions: dict[str, Session], pivots: list[Pivot]
) -> dict[str, Any]:
    events, succeeded, denied, failed, first, last, datasets = con.execute(
        f"""
        SELECT count(*),
               count(*) FILTER (WHERE {OUTCOME_SQL} = 'succeeded'),
               count(*) FILTER (WHERE {OUTCOME_SQL} = 'denied'),
               count(*) FILTER (WHERE {OUTCOME_SQL} = 'failed'),
               min(e.event_time), max(e.event_time), list_sort(list(DISTINCT e.dataset))
        FROM {_INV}
        """
    ).fetchone()
    statuses = {status: 0 for status in PIVOT_STATUSES}
    for pivot in pivots:
        statuses[pivot.status] += 1
    return {
        "events": events,
        "succeeded": succeeded,
        "denied": denied,
        "failed": failed,
        "first_seen": first,
        "last_seen": last,
        "datasets": datasets,
        "sessions": len(sessions),
        "deepest_session": max(s.depth for s in sessions.values()),
        "pivots": len(pivots),
        "pivot_statuses": statuses,
    }


def _api_counts(con: duckdb.DuckDBPyConnection) -> list[dict[str, Any]]:
    rows = con.execute(
        f"""
        SELECT replace(e.event_source, '.amazonaws.com', '') || ':' || e.event_name AS api,
               count(*) FILTER (WHERE {OUTCOME_SQL} = 'succeeded'),
               count(*) FILTER (WHERE {OUTCOME_SQL} = 'denied'),
               count(*) FILTER (WHERE {OUTCOME_SQL} = 'failed'),
               count(*) AS n
        FROM {_INV} GROUP BY 1 ORDER BY n DESC, api
        """
    ).fetchall()
    return [
        {"api": api, "succeeded": ok, "denied": denied, "failed": failed, "events": n}
        for api, ok, denied, failed, n in rows
    ]


TIMELINE_FIELDS = (
    "event_id",
    "event_time",
    "session",
    "depth",
    "api",
    "region",
    "caller",
    "source_ip",
    "user_agent",
    "outcome",
    "error_code",
    "error_message",
    "invoked_by",
    "dataset",
)


def _timeline(con: duckdb.DuckDBPyConnection, limit: int) -> list[dict[str, Any]]:
    """Events in time order (ties by eventID: CloudTrail times have one-second precision)."""
    rows = con.execute(
        f"""
        SELECT e.event_id, e.event_time, i.session, i.depth,
               replace(e.event_source, '.amazonaws.com', '') || ':' || e.event_name,
               e.aws_region, {CALLER_SQL}, e.source_ip_address, e.user_agent, {OUTCOME_SQL},
               e.error_code, e.error_message, e.invoked_by, e.dataset
        FROM {_INV} ORDER BY e.event_time, e.event_id LIMIT $limit
        """,
        {"limit": limit},
    ).fetchall()
    return [dict(zip(TIMELINE_FIELDS, row, strict=True)) for row in rows]


def _resource_refs_sql() -> str:
    """SQL: the resources an event names, as a list of (type, resource, field) structs."""
    parts = []
    for service, name, kind in RESOURCE_PARAMETERS:
        parts.append(
            f"CASE WHEN e.event_source = '{service}.amazonaws.com' THEN list_transform("
            f"list_filter(json_extract(e.request_parameters, '$..{name}'), "
            f"lambda v: json_type(v) = 'VARCHAR' AND (v->>'$') <> ''), "
            f"lambda v: {{'type': '{kind}', 'resource': (v->>'$'), "
            f"'field': 'requestParameters.{name}'}}) END"
        )
    # S3 data events name an object by bucket and key.
    parts.append(
        "CASE WHEN e.event_source = 's3.amazonaws.com' "
        "AND (e.request_parameters->>'bucketName') <> '' "
        "AND (e.request_parameters->>'key') <> '' "
        "THEN [{'type': 'object', "
        "'resource': (e.request_parameters->>'bucketName') || '/' "
        "|| (e.request_parameters->>'key'), "
        "'field': 'requestParameters.bucketName+key'}] END"
    )
    # The resources field, as AWS states it. S3 ARNs carry no account or region,
    # so they become the bucket (or bucket/key) names the parameters use.
    types = " ".join(
        f"WHEN '{aws_type}' THEN '{kind}'" for aws_type, kind in RESOURCE_FIELD_TYPES.items()
    )
    parts.append(
        "CASE WHEN json_type(e.resources) = 'ARRAY' THEN list_transform(list_filter("
        "from_json(e.resources, '[\"JSON\"]'), "
        "lambda r: json_type(r) = 'OBJECT' AND (r->>'ARN') <> ''), "
        f"lambda r: {{'type': CASE (r->>'type') {types} "
        "ELSE coalesce(r->>'type', 'unknown') END, "
        "'resource': regexp_replace(r->>'ARN', '^arn:[^:]+:s3:::', ''), "
        "'field': 'resources[' || coalesce(r->>'type', '?') || ']'}) END"
    )
    return "list_concat(" + ", ".join(parts) + ")"


def _blast_radius(con: duckdb.DuckDBPyConnection, scope: Scope) -> dict[str, Any]:
    """Resources the events name, per service, split by outcome."""
    con.execute(
        f"""
        CREATE OR REPLACE TEMP TABLE inv_refs AS
        SELECT event_id, ref.type AS type, ref.resource AS resource,
               list_sort(list(DISTINCT ref.field)) AS fields
        FROM (SELECT e.event_id, unnest({_resource_refs_sql()}) AS ref FROM {_INV})
        GROUP BY event_id, type, resource
        """
    )
    rows = con.execute(
        f"""
        SELECT replace(e.event_source, '.amazonaws.com', '') AS service, r.type, r.resource,
               {OUTCOME_SQL} AS outcome, count(*), histogram(e.event_name),
               min(e.event_time), max(e.event_time),
               list(e.event_id ORDER BY e.event_time, e.event_id)[1:$evidence],
               list_sort(list_distinct(flatten(list(r.fields)))),
               list(DISTINCT e.aws_region) FILTER (WHERE e.aws_region IS NOT NULL)
        FROM inv_refs r JOIN events e ON e.event_id = r.event_id
        GROUP BY service, r.type, r.resource, outcome
        """,
        {"evidence": scope.max_evidence},
    ).fetchall()
    resources: dict[tuple[str, str, str], dict[str, Any]] = {}
    for service, kind, resource, outcome, n, apis, first, last, ids, fields, regions in rows:
        entry = resources.setdefault(
            (service, kind, resource),
            {"type": kind, "resource": resource, "events": 0, "fields": set(), "regions": set()}
            | {name: None for name in OUTCOMES},
        )
        entry["events"] += n
        entry["fields"].update(fields)
        entry["regions"].update(regions or [])
        entry[outcome] = {
            "events": n,
            "apis": dict(sorted(apis.items(), key=lambda item: (-item[1], item[0]))),
            "first_seen": first,
            "last_seen": last,
            "event_ids": ids,
        }

    services: dict[str, list[dict[str, Any]]] = {}
    for (service, _, _), entry in resources.items():
        entry["fields"] = sorted(entry["fields"])
        entry["regions"] = sorted(entry["regions"])
        services.setdefault(service, []).append(entry)
    service_events = dict(
        con.execute(
            "SELECT replace(e.event_source, '.amazonaws.com', ''), count(DISTINCT r.event_id) "
            "FROM inv_refs r JOIN events e ON e.event_id = r.event_id GROUP BY 1"
        ).fetchall()
    )
    listed = []
    for service, entries in services.items():
        entries.sort(key=lambda entry: (-entry["events"], entry["type"], entry["resource"]))
        listed.append(
            {
                "service": service,
                "events": service_events[service],
                "resources": len(entries),
                **{
                    f"{outcome}_resources": sum(1 for entry in entries if entry[outcome])
                    for outcome in OUTCOMES
                },
                "listed": entries[: scope.max_resources],
            }
        )
    listed.sort(key=lambda service: (-service["events"], service["service"]))

    unnamed = con.execute(
        f"""
        SELECT replace(e.event_source, '.amazonaws.com', '') || ':' || e.event_name AS api,
               count(*) AS n
        FROM {_INV} ANTI JOIN (SELECT DISTINCT event_id FROM inv_refs) r
             ON r.event_id = e.event_id
        GROUP BY api ORDER BY n DESC, api
        """
    ).fetchall()
    return {
        "services": listed,
        "events_without_resource": {
            "events": sum(n for _, n in unnamed),
            "apis": [{"api": api, "events": n} for api, n in unnamed[:10]],
        },
    }


FINDING_FIELDS = (
    "finding_id",
    "rule_id",
    "rule_title",
    "severity",
    "technique_id",
    "technique_name",
    "former_technique_ids",
    "tactics",
    "principal",
    "summary",
    "outcome",
    "first_seen",
    "last_seen",
    "evidence_count",
    "evidence_in_investigation",
    "sessions",
    "event_ids",
)


def _findings(con: duckdb.DuckDBPyConnection, scope: Scope) -> list[dict[str, Any]] | None:
    """Findings with at least one evidence event in the investigation.

    ``event_ids`` lists the first of those evidence events (``max_evidence``);
    ``evidence_count`` is the finding's whole evidence, which may reach beyond
    the investigated sessions and time range.
    """
    if not con.execute("SELECT count(*) FROM rule_runs").fetchone()[0]:
        return None
    rows = con.execute(
        """
        WITH hits AS (
            SELECT u.finding_id, u.event_id, i.session, e.event_time
            FROM (SELECT finding_id, unnest(evidence_event_ids) AS event_id FROM findings) u
            JOIN inv_events i ON i.event_id = u.event_id
            JOIN events e ON e.event_id = u.event_id
        ), per_finding AS (
            SELECT finding_id, count(*) AS n, list_sort(list(DISTINCT session)) AS sessions,
                   list(event_id ORDER BY event_time, event_id)[1:$evidence] AS event_ids
            FROM hits GROUP BY finding_id
        )
        SELECT f.finding_id, f.rule_id, f.rule_title, f.severity, f.technique_id,
               f.technique_name, f.former_technique_ids, f.tactics, f.principal, f.summary,
               f.outcome, f.first_seen, f.last_seen, f.evidence_count,
               p.n, p.sessions, p.event_ids
        FROM findings f JOIN per_finding p ON p.finding_id = f.finding_id
        ORDER BY f.first_seen, f.rule_id, f.finding_id
        """,
        {"evidence": scope.max_evidence},
    ).fetchall()
    return [dict(zip(FINDING_FIELDS, row, strict=True)) for row in rows]


FORMAT = "ctinv-investigation/1"
DEFINITIONS = {
    "times": "UTC; the time range includes its start and excludes its end",
    "outcomes": {
        "succeeded": "no errorCode",
        "denied": "a permission error (AccessDenied, AccessDeniedException, "
        "UnauthorizedOperation, Client.UnauthorizedOperation, AuthorizationError, "
        "NotAuthorized)",
        "failed": "any other errorCode",
    },
    "pivot_statuses": PIVOT_STATUSES,
    "event_ids": "evidence lists hold the first eventIDs by time, up to max_evidence; "
    "the counts next to them are complete",
}


def parse_time(text: str) -> datetime:
    """An ISO 8601 date or date and time as naive UTC; without an offset it is UTC."""
    try:
        value = datetime.fromisoformat(text.strip())
    except ValueError:
        raise ValueError(f"{text!r} is not an ISO 8601 date or time") from None
    if value.tzinfo is not None:
        value = value.astimezone(UTC).replace(tzinfo=None)
    return value


def to_dict(inv: Investigation, database: str | None = None) -> dict[str, Any]:
    """The investigation as JSON-ready data (datetimes stay datetimes)."""
    scope = dataclasses.asdict(inv.scope)
    return {
        "format": FORMAT,
        "ctinv_version": __version__,
        "generated_at": datetime.now(UTC).replace(tzinfo=None, microsecond=0),
        "database": database,
        "scope": scope,
        "definitions": DEFINITIONS,
        "summary": inv.summary
        | {
            "timeline_listed": len(inv.timeline),
            "timeline_truncated": len(inv.timeline) < inv.summary["events"],
        },
        "sessions": [dataclasses.asdict(s) for s in inv.sessions],
        "pivots": [dataclasses.asdict(p) for p in inv.pivots],
        "apis": inv.apis,
        "blast_radius": inv.blast_radius,
        "findings": inv.findings,
        "timeline": inv.timeline,
    }


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat() + "Z"
    raise TypeError(f"{type(value).__name__} is not JSON serializable")


def write_json(inv: Investigation, path: Path, database: str | None = None) -> None:
    """Write the investigation as indented JSON, with one line per timeline event."""
    data = to_dict(inv, database)
    timeline = data.pop("timeline")
    head = json.dumps(data, indent=2, default=_json_default)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as out:
        out.write(head[: -len("\n}")] + ',\n  "timeline": [')
        for n, event in enumerate(timeline):
            out.write(("," if n else "") + "\n    " + json.dumps(event, default=_json_default))
        out.write("\n  ]\n}\n")
