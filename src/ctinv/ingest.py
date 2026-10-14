"""Ingest CloudTrail files into DuckDB: stream, normalize, deduplicate, quarantine.

Each file is read with ``ctinv.reader`` in recover mode and ingested in one
transaction. Valid records are bulk-loaded in batches through temporary NDJSON
files (no extra dependencies, far faster than row inserts). Deduplication is on
eventID: a record whose eventID is already stored (or appeared earlier in the
same file) is counted as a duplicate if its content is identical, and
quarantined if it differs, so no conflicting record is silently dropped.
Records that cannot be normalized go to the quarantine with the reason; a file
that becomes unreadable keeps everything read before the error.

Nothing is derived from file names: every event attribute comes from the event.
The dataset name is given explicitly or looked up in data/MANIFEST.json.
"""

import hashlib
import json
import tempfile
import time
import zlib
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import duckdb

from ctinv.normalize import InvalidRecord, normalize
from ctinv.reader import MalformedRecord, RecordFormatError, iter_records
from ctinv.schema import EVENT_COLUMNS, QUARANTINE_COLUMNS, Column, connect

DEFAULT_BATCH_SIZE = 50_000
# Quarantined text is kept whole up to this size; real CloudTrail records are far smaller.
MAX_QUARANTINE_TEXT = 1 << 20
SUFFIXES = (".json", ".json.gz")
# Errors that make the rest of a file unreadable (corrupt gzip, encoding, structure).
FILE_ERRORS = (RecordFormatError, OSError, EOFError, zlib.error, UnicodeDecodeError, RecursionError)


class DatasetResolutionError(ValueError):
    """The dataset of one or more files cannot be determined; nothing was ingested."""


@dataclass(frozen=True)
class FilePlan:
    path: Path
    source_file: str
    dataset: str
    sha256: str
    size_bytes: int


@dataclass
class FileResult:
    source_file: str
    records_read: int = 0
    inserted: int = 0
    duplicates: int = 0
    quarantined: int = 0
    file_error: str | None = None


@dataclass
class IngestStats:
    files: list[FileResult] = field(default_factory=list)
    elapsed_seconds: float = 0.0

    def total(self, name: str) -> int:
        return sum(getattr(f, name) for f in self.files)

    @property
    def file_errors(self) -> int:
        return sum(1 for f in self.files if f.file_error)


# --------------------------------------------------------------------------- planning


def collect_files(paths: Iterable[Path]) -> list[Path]:
    """Expand directories into their .json/.json.gz files (sorted), keep files, drop repeats."""
    found: list[Path] = []
    for path in paths:
        if path.is_dir():
            found += sorted(p for p in path.rglob("*") if p.is_file() and p.name.endswith(SUFFIXES))
        elif path.is_file():
            found.append(path)
        else:
            raise FileNotFoundError(f"no such file or directory: {path}")
    return list({p.resolve(): p for p in found}.values())


def source_name(path: Path, data_dir: Path) -> str:
    """The path as stored in source_file: relative to the data directory if inside it."""
    resolved = path.resolve()
    try:
        return resolved.relative_to(data_dir.resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def sha256_file(path: Path) -> str:
    with path.open("rb") as fh:
        return hashlib.file_digest(fh, "sha256").hexdigest()


def manifest_index(data_dir: Path) -> dict[str, tuple[str, str]]:
    """Map "<path relative to data dir>" -> (dataset, sha256) from data/MANIFEST.json."""
    manifest_path = data_dir / "MANIFEST.json"
    if not manifest_path.exists():
        return {}
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    index = {}
    for name, entry in manifest.get("datasets", {}).items():
        for f in entry.get("files", []):
            index[f"{entry['directory']}/{f['path']}"] = (name, f["sha256"])
    return index


def plan_files(paths: Sequence[Path], data_dir: Path, dataset: str | None) -> list[FilePlan]:
    """Resolve source names, datasets and hashes for every file before anything is written."""
    files = collect_files(paths)
    if not files:
        raise DatasetResolutionError("no .json or .json.gz files found")
    index = {} if dataset else manifest_index(data_dir)
    plans, problems = [], []
    for path in files:
        source_file = source_name(path, data_dir)
        digest = sha256_file(path)
        name = dataset
        if name is None:
            entry = index.get(source_file)
            if entry is None:
                problems.append(f"{source_file}: not listed in {data_dir / 'MANIFEST.json'}")
                continue
            if entry[1] != digest:
                problems.append(f"{source_file}: content differs from the SHA-256 in MANIFEST.json")
                continue
            name = entry[0]
        plans.append(FilePlan(path, source_file, name, digest, path.stat().st_size))
    if problems:
        raise DatasetResolutionError(
            "cannot determine the dataset (pass --dataset, or fetch the file with "
            "scripts/fetch_datasets.py):\n  " + "\n  ".join(problems)
        )
    return plans


# --------------------------------------------------------------------------- loading


def utc_now() -> str:
    return datetime.now(UTC).replace(tzinfo=None).isoformat(sep=" ", timespec="seconds")


def _columns_literal(columns: Sequence[Column]) -> str:
    return "{" + ", ".join(f"'{c.name}': '{c.type}'" for c in columns) + "}"


class _NdjsonBatch:
    """Rows written to a temporary NDJSON file, loaded into a staging table in one go."""

    def __init__(self, path: Path, table: str, columns: Sequence[Column]) -> None:
        self.path = path
        self.table = table
        self.columns = _columns_literal(columns)
        self.count = 0
        self._fh: Any = None

    def write(self, row: dict[str, Any]) -> None:
        if self._fh is None:
            self._fh = self.path.open("w", encoding="utf-8")
        self._fh.write(json.dumps(row) + "\n")
        self.count += 1

    def load(self, con: duckdb.DuckDBPyConnection) -> int:
        """Replace the staging table's content with this batch; return the row count."""
        count, self.count = self.count, 0
        con.execute(f"DELETE FROM {self.table}")
        if self._fh is None:
            return 0
        self._fh.close()
        self._fh = None
        location = str(self.path).replace("'", "''")
        con.execute(
            f"INSERT INTO {self.table} SELECT * FROM read_json('{location}', "
            f"format = 'newline_delimited', columns = {self.columns}, "
            "maximum_object_size = 268435456)"
        )
        return count


class Ingester:
    def __init__(
        self,
        con: duckdb.DuckDBPyConnection,
        work_dir: Path,
        batch_size: int = DEFAULT_BATCH_SIZE,
    ) -> None:
        self.con = con
        self.batch_size = batch_size
        con.execute("CREATE OR REPLACE TEMP TABLE staging_events AS SELECT * FROM events LIMIT 0")
        con.execute(
            "CREATE OR REPLACE TEMP TABLE staging_quarantine AS SELECT * FROM quarantine LIMIT 0"
        )
        self.events = _NdjsonBatch(work_dir / "events.ndjson", "staging_events", EVENT_COLUMNS)
        self.quarantine = _NdjsonBatch(
            work_dir / "quarantine.ndjson", "staging_quarantine", QUARANTINE_COLUMNS
        )

    def ingest_file(self, plan: FilePlan) -> FileResult:
        result = FileResult(plan.source_file)
        started_at = utc_now()
        self.con.execute("BEGIN TRANSACTION")
        try:
            try:
                for index, record in enumerate(iter_records(plan.path, recover=True)):
                    result.records_read += 1
                    self._route(plan, index, record, result)
                    if self.events.count >= self.batch_size:
                        self._flush(result)
            except FILE_ERRORS as exc:
                result.file_error = f"unreadable after {result.records_read} records: {exc}"
                self._quarantine(plan, None, None, result.file_error, None)
            self._flush(result)
            self.con.execute(
                "INSERT INTO ingested_files VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    plan.source_file,
                    plan.dataset,
                    plan.sha256,
                    plan.size_bytes,
                    started_at,
                    utc_now(),
                    result.records_read,
                    result.inserted,
                    result.duplicates,
                    result.quarantined,
                    result.file_error,
                ],
            )
            self.con.execute("COMMIT")
        except BaseException:
            self.con.execute("ROLLBACK")
            raise
        return result

    def _route(self, plan: FilePlan, index: int, record: Any, result: FileResult) -> None:
        if isinstance(record, MalformedRecord):
            self._quarantine(plan, index, None, record.reason, record.text)
            result.quarantined += 1
            return
        try:
            row = normalize(record)
        except InvalidRecord as exc:
            event_id = record.get("eventID") if isinstance(record, dict) else None
            self._quarantine(
                plan,
                index,
                event_id if isinstance(event_id, str) else None,
                str(exc),
                json.dumps(record),
            )
            result.quarantined += 1
            return
        row.update(dataset=plan.dataset, source_file=plan.source_file, source_index=index)
        self.events.write(row)

    def _quarantine(
        self, plan: FilePlan, index: int | None, event_id: str | None, reason: str, text: str | None
    ) -> None:
        if text is not None and len(text) > MAX_QUARANTINE_TEXT:
            text = text[:MAX_QUARANTINE_TEXT] + f"... [truncated, {len(text)} characters]"
        self.quarantine.write(
            {
                "dataset": plan.dataset,
                "source_file": plan.source_file,
                "source_index": index,
                "event_id": event_id,
                "reason": reason,
                "record": text,
                "quarantined_at": utc_now(),
            }
        )

    def _flush(self, result: FileResult) -> None:
        """Load the pending batches; insert new events, count duplicates, quarantine conflicts."""
        con = self.con
        if self.events.load(con):
            # `stored` must be judged before this batch is inserted.
            con.execute(
                """
                CREATE OR REPLACE TEMP TABLE judged AS
                SELECT s.*,
                       row_number() OVER (
                           PARTITION BY s.event_id ORDER BY s.source_index
                       ) AS occurrence,
                       e.event_id IS NOT NULL AS stored
                FROM staging_events s LEFT JOIN events e ON e.event_id = s.event_id
                """
            )
            names = ", ".join(c.name for c in EVENT_COLUMNS)
            (inserted,) = con.execute(
                "SELECT count(*) FROM judged WHERE NOT stored AND occurrence = 1"
            ).fetchone()
            con.execute(
                f"INSERT INTO events SELECT {names} FROM judged WHERE NOT stored AND occurrence = 1"
            )
            # Every repeat now has its first occurrence in `events` to compare against.
            con.execute(
                """
                CREATE OR REPLACE TEMP TABLE repeats AS
                SELECT d.dataset, d.source_file, d.source_index, d.event_id, d.raw,
                       d.raw::VARCHAR <> e.raw::VARCHAR AS conflicting
                FROM judged d JOIN events e ON e.event_id = d.event_id
                WHERE d.stored OR d.occurrence > 1
                """
            )
            identical, conflicting = con.execute(
                "SELECT count(*) FILTER (WHERE NOT conflicting), "
                "count(*) FILTER (WHERE conflicting) FROM repeats"
            ).fetchone()
            con.execute(
                """
                INSERT INTO quarantine
                SELECT dataset, source_file, source_index, event_id,
                       'duplicate eventID with different content than the stored event',
                       raw::VARCHAR, ?
                FROM repeats WHERE conflicting
                """,
                [utc_now()],
            )
            result.inserted += inserted
            result.duplicates += identical
            result.quarantined += conflicting
        if self.quarantine.load(con):
            con.execute("INSERT INTO quarantine SELECT * FROM staging_quarantine")


def ingest(
    db_path: Path,
    plans: Sequence[FilePlan],
    *,
    batch_size: int = DEFAULT_BATCH_SIZE,
    on_file: Callable[[FileResult], None] | None = None,
) -> IngestStats:
    started = time.monotonic()
    stats = IngestStats()
    con = connect(db_path)
    try:
        with tempfile.TemporaryDirectory(prefix="ctinv-ingest-") as tmp:
            ingester = Ingester(con, Path(tmp), batch_size)
            for plan in plans:
                result = ingester.ingest_file(plan)
                stats.files.append(result)
                if on_file:
                    on_file(result)
    finally:
        con.close()
    stats.elapsed_seconds = time.monotonic() - started
    return stats
