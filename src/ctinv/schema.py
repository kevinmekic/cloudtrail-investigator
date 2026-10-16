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

# One row per finding of the latest run of each rule. The CHECK makes a finding
# without evidence impossible at the database level, whatever code writes it.
FINDINGS_DDL = """
CREATE TABLE IF NOT EXISTS findings (
    finding_id VARCHAR PRIMARY KEY,
    rule_id VARCHAR NOT NULL,
    rule_title VARCHAR NOT NULL,
    severity VARCHAR NOT NULL,
    technique_id VARCHAR NOT NULL,
    technique_name VARCHAR NOT NULL,
    former_technique_ids VARCHAR[] NOT NULL,
    tactics VARCHAR[] NOT NULL,
    principal VARCHAR,
    summary VARCHAR NOT NULL,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    outcome VARCHAR NOT NULL,
    evidence_count INTEGER NOT NULL,
    evidence_event_ids VARCHAR[] NOT NULL CHECK (len(evidence_event_ids) > 0),
    datasets VARCHAR[] NOT NULL,
    detected_at TIMESTAMP NOT NULL,
    CHECK (evidence_count = len(evidence_event_ids))
)
"""

# One row per rule execution, kept as history: which rule file (by hash) and
# which parameters produced the current findings. ``parameters`` holds the values
# used, ``overrides`` the ones changed at run time (empty: the rule's defaults).
RULE_RUNS_DDL = """
CREATE TABLE IF NOT EXISTS rule_runs (
    rule_id VARCHAR NOT NULL,
    rule_sha256 VARCHAR NOT NULL,
    parameters JSON NOT NULL,
    detected_at TIMESTAMP NOT NULL,
    findings INTEGER NOT NULL,
    evidence_events INTEGER NOT NULL,
    elapsed_seconds DOUBLE NOT NULL,
    overrides JSON NOT NULL DEFAULT '{}'
)
"""
# Databases created before ``overrides`` existed get the column on open.
RULE_RUNS_MIGRATION = "ALTER TABLE rule_runs ADD COLUMN IF NOT EXISTS overrides JSON DEFAULT '{}'"


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


TABLES = ("events", "quarantine", "ingested_files", "findings", "rule_runs")


class DatabaseError(Exception):
    """The database cannot be opened, or it is not a ctinv database."""


def connect(
    db_path: str | Path,
    memory_limit: str | None = None,
    *,
    create: bool = True,
    read_only: bool = False,
) -> duckdb.DuckDBPyConnection:
    """Open the database and make sure all tables exist.

    With ``create`` (ingest), a missing file is created and missing tables are
    added. Without it, the file must exist and already hold the ``events``
    table, so that no command adds tables to a foreign or empty database.
    ``read_only`` opens it without write access, for commands that only read;
    it then needs every table.

    ``memory_limit`` is a DuckDB size such as "1GB"; DuckDB spills to disk
    beyond it. Without it, DuckDB may use up to 80% of the machine's memory.
    """
    in_memory = str(db_path) == ":memory:"
    if not create and not in_memory and not Path(db_path).is_file():
        raise DatabaseError(f"database {db_path} not found; run ctinv ingest first")
    try:
        con = duckdb.connect(str(db_path), read_only=read_only)
    except duckdb.Error as exc:
        raise DatabaseError(f"cannot open database {db_path}: {exc}") from None
    try:
        _prepare(con, db_path, memory_limit, create=create, read_only=read_only)
    except BaseException:
        con.close()
        raise
    return con


def _prepare(
    con: duckdb.DuckDBPyConnection,
    db_path: str | Path,
    memory_limit: str | None,
    *,
    create: bool,
    read_only: bool,
) -> None:
    (path,) = con.execute(
        "SELECT path FROM duckdb_databases() WHERE database_name = current_database()"
    ).fetchone()
    if path is None and str(db_path) != ":memory:":
        # DuckDB opens a data file (e.g. .json or .parquet) as an in-memory
        # database with a view on it: anything written would be lost on close.
        raise DatabaseError(f"{db_path} is not a DuckDB database file")
    if memory_limit:
        con.execute("SET memory_limit = ?", [memory_limit])
    # Defence in depth: nothing should depend on the machine's local time zone.
    con.execute("SET TimeZone = 'UTC'")
    if not create:
        tables = {
            row[0]
            for row in con.execute(
                "SELECT table_name FROM duckdb_tables() "
                "WHERE database_name = current_database() AND schema_name = 'main'"
            ).fetchall()
        }
        if "events" not in tables:
            raise DatabaseError(
                f"{db_path} is not a ctinv database (it has no events table); "
                "create one with ctinv ingest"
            )
        if read_only:
            missing = [t for t in TABLES if t not in tables]
            columns = {
                row[0]
                for row in con.execute(
                    "SELECT column_name FROM duckdb_columns() WHERE database_name = "
                    "current_database() AND table_name = 'rule_runs'"
                ).fetchall()
            }
            if missing or "overrides" not in columns:
                raise DatabaseError(
                    f"{db_path} was created by an older version of ctinv; "
                    "run ctinv detect on it once to update it"
                )
            return
    con.execute(create_table_sql("events", EVENT_COLUMNS, primary_key="event_id"))
    con.execute(create_table_sql("quarantine", QUARANTINE_COLUMNS))
    con.execute(INGESTED_FILES_DDL)
    con.execute(FINDINGS_DDL)
    con.execute(RULE_RUNS_DDL)
    con.execute(RULE_RUNS_MIGRATION)
