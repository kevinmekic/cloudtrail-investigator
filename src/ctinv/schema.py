"""DuckDB schema: normalized events, quarantined records and ingested files.

Timestamps are stored as ``TIMESTAMP`` holding UTC. Python converts every
``eventTime`` to UTC before it reaches DuckDB: casting a ``...Z`` string through
``TIMESTAMPTZ`` would apply the session time zone (by default the local one),
and returning ``TIMESTAMPTZ`` values to Python needs an extra package.
"""

from dataclasses import dataclass
from pathlib import Path

import duckdb


@dataclass(frozen=True)
class Column:
    name: str
    type: str
    source: str
    required: bool = False


EVENT_COLUMNS: tuple[Column, ...] = (
    Column("event_id", "VARCHAR", "eventID", required=True),
    Column("event_time", "TIMESTAMP", "eventTime (converted to UTC)", required=True),
    Column("event_source", "VARCHAR", "eventSource", required=True),
    Column("event_name", "VARCHAR", "eventName", required=True),
    Column("aws_region", "VARCHAR", "awsRegion"),
    Column("source_ip_address", "VARCHAR", "sourceIPAddress"),
    Column("user_agent", "VARCHAR", "userAgent"),
    Column("error_code", "VARCHAR", "errorCode"),
    Column("error_message", "VARCHAR", "errorMessage"),
    Column("read_only", "BOOLEAN", "readOnly"),
    Column("event_type", "VARCHAR", "eventType"),
    Column("recipient_account_id", "VARCHAR", "recipientAccountId"),
    Column("event_version", "VARCHAR", "eventVersion"),
    Column("request_id", "VARCHAR", "requestID"),
    Column("shared_event_id", "VARCHAR", "sharedEventID"),
    Column("identity_type", "VARCHAR", "userIdentity.type"),
    Column("identity_arn", "VARCHAR", "userIdentity.arn"),
    Column("identity_principal_id", "VARCHAR", "userIdentity.principalId"),
    Column("identity_account_id", "VARCHAR", "userIdentity.accountId"),
    Column("access_key_id", "VARCHAR", "userIdentity.accessKeyId (empty string stored as NULL)"),
    Column("user_name", "VARCHAR", "userIdentity.userName"),
    Column("invoked_by", "VARCHAR", "userIdentity.invokedBy"),
    Column("session_issuer_arn", "VARCHAR", "userIdentity.sessionContext.sessionIssuer.arn"),
    Column(
        "mfa_authenticated",
        "BOOLEAN",
        "userIdentity.sessionContext.attributes.mfaAuthenticated",
    ),
    Column("request_parameters", "JSON", "requestParameters"),
    Column("response_elements", "JSON", "responseElements"),
    Column("additional_event_data", "JSON", "additionalEventData"),
    Column("resources", "JSON", "resources"),
    Column("raw", "JSON", "the whole record", required=True),
    Column(
        "raw_sha256",
        "VARCHAR",
        "SHA-256 of raw as stored: duplicate check and integrity fingerprint",
        required=True,
    ),
    Column("dataset", "VARCHAR", "provenance: dataset name", required=True),
    Column("source_file", "VARCHAR", "provenance: file the record was read from", required=True),
    Column(
        "source_index", "BIGINT", "provenance: position of the record in its file", required=True
    ),
)

QUARANTINE_COLUMNS: tuple[Column, ...] = (
    Column("dataset", "VARCHAR", "provenance", required=True),
    Column("source_file", "VARCHAR", "provenance", required=True),
    Column("source_index", "BIGINT", "position in the file; NULL for a file-level error"),
    Column("event_id", "VARCHAR", "eventID, if the record has one"),
    Column("reason", "VARCHAR", "why the record was not ingested", required=True),
    Column("record", "VARCHAR", "the record or the invalid input text"),
    Column("quarantined_at", "TIMESTAMP", "UTC", required=True),
)

INGESTED_FILES_DDL = """
CREATE TABLE IF NOT EXISTS ingested_files (
    source_file VARCHAR NOT NULL,
    dataset VARCHAR NOT NULL,
    sha256 VARCHAR NOT NULL,
    size_bytes BIGINT NOT NULL,
    started_at TIMESTAMP NOT NULL,
    finished_at TIMESTAMP NOT NULL,
    records_read BIGINT NOT NULL,
    inserted BIGINT NOT NULL,
    duplicates BIGINT NOT NULL,
    quarantined BIGINT NOT NULL,
    file_error VARCHAR
)
"""


def create_table_sql(
    table: str, columns: tuple[Column, ...], primary_key: str | None = None
) -> str:
    parts = []
    for col in columns:
        constraint = (
            " PRIMARY KEY" if col.name == primary_key else (" NOT NULL" if col.required else "")
        )
        parts.append(f"    {col.name} {col.type}{constraint}")
    return f"CREATE TABLE IF NOT EXISTS {table} (\n" + ",\n".join(parts) + "\n)"


def connect(db_path: str | Path, memory_limit: str | None = None) -> duckdb.DuckDBPyConnection:
    """Open (or create) the database and make sure all tables exist.

    ``memory_limit`` is a DuckDB size such as "1GB"; DuckDB spills to disk
    beyond it. Without it, DuckDB may use up to 80% of the machine's memory.
    """
    con = duckdb.connect(str(db_path))
    if memory_limit:
        con.execute("SET memory_limit = ?", [memory_limit])
    # Defence in depth: nothing should depend on the machine's local time zone.
    con.execute("SET TimeZone = 'UTC'")
    con.execute(create_table_sql("events", EVENT_COLUMNS, primary_key="event_id"))
    con.execute(create_table_sql("quarantine", QUARANTINE_COLUMNS))
    con.execute(INGESTED_FILES_DDL)
    return con
