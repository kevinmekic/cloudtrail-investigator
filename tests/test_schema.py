"""Opening databases: what each command may open, create or change."""

import hashlib
import json
from pathlib import Path

import duckdb
import pytest

from cloudtrail_events import ACCESS_KEY, iam_user, make_db
from ctinv.cli import main
from ctinv.schema import TABLES, DatabaseError, connect


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tables(path: Path) -> set[str]:
    with duckdb.connect(str(path), read_only=True) as con:
        return {row[0] for row in con.execute("SHOW TABLES").fetchall()}


@pytest.fixture(autouse=True)
def wide_console(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COLUMNS", "1000")  # long temporary paths stay on one line


@pytest.fixture
def foreign(tmp_path: Path) -> Path:
    """A DuckDB database that ctinv did not create."""
    path = tmp_path / "foreign.duckdb"
    with duckdb.connect(str(path)) as con:
        con.execute("CREATE TABLE other (a INTEGER)")
    return path


def test_create_makes_every_table(tmp_path: Path) -> None:
    with connect(tmp_path / "new.duckdb"):
        pass
    assert tables(tmp_path / "new.duckdb") == set(TABLES)


@pytest.mark.parametrize("name", ["events.json", "events.parquet"])
def test_a_data_file_is_not_used_as_a_database(tmp_path: Path, name: str) -> None:
    # DuckDB opens a data file as an in-memory database with a view on it, so
    # everything written would be lost on close.
    path = tmp_path / name
    path.write_text('{"a": 1}\n')
    for options in ({}, {"create": False}):
        with pytest.raises(DatabaseError, match="is not a DuckDB database file"):
            connect(path, **options)
    # Read-only, DuckDB itself refuses to open it.
    with pytest.raises(DatabaseError, match="cannot open database"):
        connect(path, create=False, read_only=True)
    assert path.read_text() == '{"a": 1}\n'


def test_files_that_cannot_be_opened(tmp_path: Path) -> None:
    (tmp_path / "text.duckdb").write_text("not a database")
    with pytest.raises(DatabaseError, match="cannot open database .*not a valid DuckDB"):
        connect(tmp_path / "text.duckdb")
    with pytest.raises(DatabaseError, match="cannot open database"):
        connect(tmp_path)  # a directory


def test_without_create_the_database_must_exist(tmp_path: Path) -> None:
    for options in ({"create": False}, {"create": False, "read_only": True}):
        with pytest.raises(DatabaseError, match="not found; run ctinv ingest first"):
            connect(tmp_path / "missing.duckdb", **options)
    assert not (tmp_path / "missing.duckdb").exists()


@pytest.mark.parametrize("read_only", [False, True])
def test_foreign_databases_are_refused_and_left_alone(foreign: Path, read_only: bool) -> None:
    with pytest.raises(DatabaseError, match="not a ctinv database"):
        connect(foreign, create=False, read_only=read_only)
    assert tables(foreign) == {"other"}


def test_read_only_needs_an_up_to_date_database(tmp_path: Path) -> None:
    db = tmp_path / "old.duckdb"
    with duckdb.connect(str(db)) as con:  # events, but none of the later tables
        con.execute("CREATE TABLE events (event_id VARCHAR)")
    with pytest.raises(DatabaseError, match="older version of ctinv; run ctinv detect"):
        connect(db, create=False, read_only=True)
    with connect(db, create=False):  # detect may update it
        pass
    assert tables(db) == set(TABLES)
    with (
        connect(db, create=False, read_only=True) as con,
        pytest.raises(duckdb.Error, match="read-only"),
    ):
        con.execute("DELETE FROM events")


def test_reading_commands_do_not_change_the_database(tmp_path: Path) -> None:
    db = make_db(tmp_path, [iam_user(1), iam_user(2)])
    assert main(["detect", "--db", str(db)]) == 0
    before = digest(db)
    assert main(["investigate", "--db", str(db), "--access-key", ACCESS_KEY]) == 0
    out = tmp_path / "reports"
    assert main(["report", "--db", str(db), "--findings", "--out-dir", str(out)]) == 0
    assert digest(db) == before


@pytest.mark.parametrize(
    "command",
    [
        ["detect"],
        ["investigate", "--access-key", ACCESS_KEY],
        ["report", "--findings"],
        ["evaluate", "--only", "review"],
    ],
)
def test_commands_refuse_foreign_databases(
    foreign: Path, command: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([command[0], "--db", str(foreign), *command[1:]]) == 2
    err = capsys.readouterr().err
    assert "not a ctinv database" in err and "Traceback" not in err
    assert tables(foreign) == {"other"}


def test_ingest_refuses_a_data_file_as_database(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    log = tmp_path / "events.json"
    log.write_text(json.dumps(iam_user(1)) + "\n")
    before = log.read_text()
    assert main(["ingest", str(log), "--db", str(log), "--dataset", "test"]) == 2
    assert "is not a DuckDB database file" in capsys.readouterr().err
    assert log.read_text() == before


def test_unwritable_outputs_are_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = make_db(tmp_path, [iam_user(1)])
    assert main(["detect", "--db", str(db)]) == 0
    a_file = tmp_path / "a-file"
    a_file.write_text("")
    base = ["--db", str(db), "--access-key", ACCESS_KEY]
    assert main(["investigate", *base, "--output", str(tmp_path)]) == 2
    assert f"cannot write {tmp_path}" in capsys.readouterr().err
    assert main(["report", *base, "--out-dir", str(a_file)]) == 2
    assert f"cannot write {a_file}" in capsys.readouterr().err


def test_detect_explains_missing_rules_and_empty_databases(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "empty.duckdb"
    connect(db).close()
    assert main(["detect", "--db", str(db), "--rules-dir", str(tmp_path / "none")]) == 2
    assert "cannot read rules from" in capsys.readouterr().err
    assert main(["detect", "--db", str(db)]) == 0
    assert "holds no events, so there is nothing to detect" in capsys.readouterr().err
