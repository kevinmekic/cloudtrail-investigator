"""Tests for `ctinv ingest`: formats, deduplication, quarantine and provenance."""

import gzip
import hashlib
import json
from pathlib import Path

import duckdb
import pytest

from cloudtrail_events import ACCOUNT, assumed_role, aws_service, event, iam_user, root
from ctinv.cli import main
from ctinv.ingest import DatasetResolutionError, ingest, plan_files

DATA_ROOT = Path(__file__).resolve().parent.parent / "data"


def write_envelope(path: Path, records: list, gz: bool = False) -> Path:
    text = json.dumps({"Records": records})
    if gz:
        path.write_bytes(gzip.compress(text.encode()))
    else:
        path.write_text(text)
    return path


def write_ndjson(path: Path, lines: list) -> Path:
    path.write_text(
        "".join((line if isinstance(line, str) else json.dumps(line)) + "\n" for line in lines)
    )
    return path


def run(
    db: Path,
    *paths: Path,
    dataset: str = "test",
    data_dir: Path | None = None,
    batch_size: int = 50_000,
):
    plans = plan_files(list(paths), data_dir or paths[0].parent, dataset)
    return ingest(db, plans, batch_size=batch_size)


def query(db: Path, sql: str) -> list[tuple]:
    with duckdb.connect(str(db), read_only=True) as con:
        return con.execute(sql).fetchall()


def test_reads_envelope_gzip_ndjson_and_single_object(tmp_path: Path) -> None:
    files = [
        write_envelope(tmp_path / "a.json", [iam_user(1), iam_user(2)]),
        write_envelope(tmp_path / "b.json.gz", [iam_user(3)], gz=True),
        write_ndjson(tmp_path / "c.json", [iam_user(4), iam_user(5)]),
        write_ndjson(tmp_path / "d.json", [iam_user(6)]),
    ]
    stats = run(tmp_path / "x.duckdb", *files)
    assert (stats.total("records_read"), stats.total("inserted")) == (6, 6)
    assert query(tmp_path / "x.duckdb", "SELECT count(*) FROM events") == [(6,)]


def test_directory_is_searched_recursively_for_json_files(tmp_path: Path) -> None:
    (tmp_path / "logs/sub").mkdir(parents=True)
    write_envelope(tmp_path / "logs/a.json", [iam_user(1)])
    write_envelope(tmp_path / "logs/sub/b.json.gz", [iam_user(2)], gz=True)
    (tmp_path / "logs/notes.txt").write_text("not a log")
    stats = run(tmp_path / "x.duckdb", tmp_path / "logs")
    assert sorted(f.source_file for f in stats.files) == ["logs/a.json", "logs/sub/b.json.gz"]


def test_reingesting_the_same_file_adds_nothing(tmp_path: Path) -> None:
    log = write_envelope(tmp_path / "a.json", [iam_user(1), iam_user(2)])
    db = tmp_path / "x.duckdb"
    run(db, log)
    second = run(db, log)
    assert (second.total("inserted"), second.total("duplicates")) == (0, 2)
    assert query(db, "SELECT count(*) FROM events") == [(2,)]
    assert query(db, "SELECT count(*), sum(inserted), sum(duplicates) FROM ingested_files") == [
        (2, 2, 2)
    ]


@pytest.mark.parametrize("batch_size", [1, 2, 50_000])
def test_duplicate_event_ids_within_and_across_files(tmp_path: Path, batch_size: int) -> None:
    first = write_ndjson(tmp_path / "a.json", [iam_user(1), iam_user(2), iam_user(1)])
    second = write_ndjson(tmp_path / "b.json", [iam_user(2), iam_user(3)])
    stats = run(tmp_path / "x.duckdb", first, second, batch_size=batch_size)
    assert (stats.total("inserted"), stats.total("duplicates"), stats.total("quarantined")) == (
        3,
        2,
        0,
    )
    stored = query(
        tmp_path / "x.duckdb", "SELECT source_file, source_index FROM events ORDER BY event_id"
    )
    assert stored == [("a.json", 0), ("a.json", 1), ("b.json", 1)]


def test_duplicate_event_id_with_different_content_is_quarantined(tmp_path: Path) -> None:
    original, altered = iam_user(1), iam_user(1, eventName="DeleteTrail")
    log = write_ndjson(tmp_path / "a.json", [original, altered])
    stats = run(tmp_path / "x.duckdb", log)
    assert (stats.total("inserted"), stats.total("duplicates"), stats.total("quarantined")) == (
        1,
        0,
        1,
    )
    assert query(tmp_path / "x.duckdb", "SELECT event_name FROM events") == [("ListUsers",)]
    reason, record = query(tmp_path / "x.duckdb", "SELECT reason, record FROM quarantine")[0]
    assert reason.startswith("duplicate eventID with different content")
    assert json.loads(record)["eventName"] == "DeleteTrail"


def test_bad_records_are_quarantined_and_ingest_continues(tmp_path: Path) -> None:
    no_id = {k: v for k, v in iam_user(2).items() if k != "eventID"}
    log = write_ndjson(
        tmp_path / "a.json",
        [
            iam_user(1),
            "{this is not json",
            no_id,
            [1, 2],
            iam_user(3, eventTime="noon"),
            iam_user(4),
        ],
    )
    stats = run(tmp_path / "x.duckdb", log)
    result = stats.files[0]
    assert (result.records_read, result.inserted, result.quarantined) == (6, 2, 4)
    assert result.records_read == result.inserted + result.duplicates + result.quarantined
    assert result.file_error is None
    rows = query(
        tmp_path / "x.duckdb", "SELECT source_index, event_id, reason FROM quarantine ORDER BY 1"
    )
    assert [(i, eid) for i, eid, _ in rows] == [
        (1, None),
        (2, None),
        (3, None),
        (4, "00000000-0000-0000-0000-000000000003"),
    ]
    reasons = [r for *_, r in rows]
    assert reasons[0].startswith("invalid JSON")
    assert reasons[1] == "missing or empty eventID"
    assert reasons[2] == "not a JSON object but an array"
    assert "is not an ISO 8601 timestamp" in reasons[3]


def test_truncated_gzip_keeps_earlier_records_and_reports_a_file_error(tmp_path: Path) -> None:
    good = write_envelope(tmp_path / "good.json", [iam_user(1000)])
    full = gzip.compress(json.dumps({"Records": [iam_user(n) for n in range(200)]}).encode())
    cut = tmp_path / "cut.json.gz"
    cut.write_bytes(full[: len(full) - 40])
    db = tmp_path / "x.duckdb"
    assert main(["ingest", str(cut), str(good), "--db", str(db), "--dataset", "test"]) == 1
    (error,) = query(
        db, "SELECT file_error FROM ingested_files WHERE source_file LIKE '%cut.json.gz'"
    )[0]
    assert error.startswith("unreadable after")
    inserted_from_cut = query(
        db, "SELECT count(*) FROM events WHERE source_file LIKE '%cut.json.gz'"
    )[0][0]
    assert 0 < inserted_from_cut < 200
    assert query(db, "SELECT count(*) FROM events WHERE source_file LIKE '%good.json'") == [(1,)]
    assert query(db, "SELECT source_index, reason FROM quarantine")[0][0] is None


def test_identity_types_are_flattened(tmp_path: Path) -> None:
    records = [iam_user(1), assumed_role(2, mfa="true"), root(3), aws_service(4), event(5, None)]
    run(tmp_path / "x.duckdb", write_envelope(tmp_path / "a.json", records))
    rows = query(
        tmp_path / "x.duckdb",
        "SELECT identity_type, user_name, access_key_id, session_issuer_arn, mfa_authenticated, "
        "invoked_by FROM events ORDER BY event_id",
    )
    assert rows == [
        ("IAMUser", "alice", "AKIAIOSFODNN7EXAMPLE", None, None, None),
        (
            "AssumedRole",
            None,
            "ASIAIOSFODNN7EXAMPLE",
            f"arn:aws:iam::{ACCOUNT}:role/admin",
            True,
            None,
        ),
        ("Root", None, None, None, None, None),
        ("AWSService", None, None, None, None, "ec2.amazonaws.com"),
        (None, None, None, None, None, None),
    ]


def test_missing_optional_fields_are_null_and_json_columns_keep_payloads(tmp_path: Path) -> None:
    minimal = {
        "eventID": "e-1",
        "eventTime": "2023-01-01T00:00:00Z",
        "eventSource": "s3.amazonaws.com",
        "eventName": "GetObject",
    }
    full = iam_user(2, requestParameters={"bucketName": "b"}, resources=[{"ARN": "arn:aws:s3:::b"}])
    run(tmp_path / "x.duckdb", write_ndjson(tmp_path / "a.json", [minimal, full]))
    rows = query(
        tmp_path / "x.duckdb",
        "SELECT aws_region, read_only, request_parameters->>'bucketName', resources->0->>'ARN', "
        "raw->>'eventName' FROM events ORDER BY event_id",
    )
    assert rows == [
        ("us-east-1", True, "b", "arn:aws:s3:::b", "ListUsers"),
        (None, None, None, None, "GetObject"),
    ]


def test_event_time_is_utc_regardless_of_session_time_zone(tmp_path: Path) -> None:
    db = tmp_path / "x.duckdb"
    run(db, write_ndjson(tmp_path / "a.json", [iam_user(1, eventTime="2023-01-01T02:30:00+02:00")]))
    with duckdb.connect(str(db)) as con:
        con.execute("SET TimeZone = 'America/New_York'")
        assert con.execute("SELECT event_time::VARCHAR FROM events").fetchone() == (
            "2023-01-01 00:30:00",
        )


def test_nothing_is_derived_from_file_names(tmp_path: Path) -> None:
    # The name claims another account and region; only the events count (B11).
    name = "999999999999_CloudTrail_eu-west-1_20200101T0000Z_abc.json"
    run(tmp_path / "x.duckdb", write_envelope(tmp_path / name, [iam_user(1)]))
    assert query(
        tmp_path / "x.duckdb", "SELECT recipient_account_id, aws_region, source_file FROM events"
    ) == [(ACCOUNT, "us-east-1", name)]


def make_data_dir(tmp_path: Path) -> tuple[Path, Path]:
    data = tmp_path / "data"
    (data / "raw/demo").mkdir(parents=True)
    log = write_envelope(data / "raw/demo/a.json", [iam_user(1)])
    manifest = {
        "datasets": {
            "demo": {
                "directory": "raw/demo",
                "files": [
                    {"path": "a.json", "sha256": hashlib.sha256(log.read_bytes()).hexdigest()}
                ],
            }
        }
    }
    (data / "MANIFEST.json").write_text(json.dumps(manifest))
    return data, log


def test_dataset_is_looked_up_in_the_manifest(tmp_path: Path) -> None:
    data, log = make_data_dir(tmp_path)
    db = tmp_path / "x.duckdb"
    assert main(["ingest", str(log), "--db", str(db), "--data-dir", str(data)]) == 0
    assert query(db, "SELECT dataset, source_file FROM events") == [("demo", "raw/demo/a.json")]
    sha = hashlib.sha256(log.read_bytes()).hexdigest()
    assert query(db, "SELECT dataset, sha256, records_read FROM ingested_files") == [
        ("demo", sha, 1)
    ]


def test_file_that_differs_from_the_manifest_is_refused(tmp_path: Path) -> None:
    data, log = make_data_dir(tmp_path)
    write_envelope(log, [iam_user(2)])
    with pytest.raises(DatasetResolutionError, match="differs from the SHA-256"):
        plan_files([log], data, None)


def test_unknown_file_is_refused_before_anything_is_written(tmp_path: Path, capsys) -> None:
    data, _ = make_data_dir(tmp_path)
    stray = write_envelope(tmp_path / "stray.json", [iam_user(1)])
    db = tmp_path / "x.duckdb"
    assert main(["ingest", str(stray), "--db", str(db), "--data-dir", str(data)]) == 2
    assert "not listed in" in capsys.readouterr().err
    assert not db.exists()


def test_explicit_dataset_needs_no_manifest(tmp_path: Path) -> None:
    log = write_envelope(tmp_path / "a.json", [iam_user(1)])
    db = tmp_path / "x.duckdb"
    assert (
        main(
            ["ingest", str(log), "--db", str(db), "--dataset", "adhoc", "--data-dir", str(tmp_path)]
        )
        == 0
    )
    assert query(db, "SELECT dataset FROM events") == [("adhoc",)]


@pytest.mark.datasets
def test_invictus_dataset_ingests_completely(tmp_path: Path) -> None:
    directory = DATA_ROOT / "raw/invictus_sigma_aws"
    if not (DATA_ROOT / "MANIFEST.json").exists() or not directory.is_dir():
        pytest.skip("Invictus dataset not fetched (scripts/fetch_datasets.py)")
    stats = ingest(tmp_path / "x.duckdb", plan_files([directory], DATA_ROOT, None))
    assert (stats.total("records_read"), stats.total("inserted"), stats.total("quarantined")) == (
        2900,
        2900,
        0,
    )


def test_raw_sha256_fingerprints_the_stored_record(tmp_path: Path) -> None:
    db = tmp_path / "x.duckdb"
    run(db, write_ndjson(tmp_path / "a.json", [iam_user(1), root(2)]))
    assert query(db, "SELECT count(*) FROM events WHERE raw_sha256 = sha256(raw::VARCHAR)") == [
        (2,)
    ]


def test_oversized_record_is_quarantined_not_loaded(tmp_path: Path, monkeypatch) -> None:
    import ctinv.ingest

    monkeypatch.setattr(ctinv.ingest, "MAX_ROW_BYTES", 2_000)
    big = iam_user(2, requestParameters={"blob": "x" * 5_000})
    stats = run(
        tmp_path / "x.duckdb", write_ndjson(tmp_path / "a.json", [iam_user(1), big, iam_user(3)])
    )
    assert (stats.total("inserted"), stats.total("quarantined")) == (2, 1)
    (reason,) = query(tmp_path / "x.duckdb", "SELECT reason FROM quarantine")[0]
    assert reason.startswith("record too large")


def test_memory_limit_is_applied(tmp_path: Path) -> None:
    from ctinv.schema import connect

    with connect(tmp_path / "x.duckdb", memory_limit="256MB") as con:
        assert con.execute("SELECT current_setting('memory_limit')").fetchone()[0] == "244.1 MiB"
