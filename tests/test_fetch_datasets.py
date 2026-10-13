"""Offline tests for scripts/fetch_datasets.py: the network is replaced by a fake opener."""

import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest

import fetch_datasets as fd

EVENT = {"eventID": "e-1", "eventName": "ListUsers", "recipientAccountId": "111122223333"}
FILE_A = json.dumps({"Records": [EVENT, EVENT]}).encode()
FILE_B = (json.dumps(EVENT) + "\n").encode()


def pin(path: str, data: bytes, **extra) -> dict:
    return {"path": path, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), **extra}


class FakeWeb:
    """Serves fixed bytes per URL and records every request."""

    def __init__(self, content: dict[str, bytes]) -> None:
        self.content = content
        self.requests: list[str] = []

    def __call__(self, request, timeout: float) -> io.BytesIO:
        self.requests.append(request.full_url)
        if request.full_url not in self.content:
            raise OSError(f"404 {request.full_url}")
        return io.BytesIO(self.content[request.full_url])


def make_tar(members: dict[str, bytes], symlink: str | None = None) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        if symlink:
            info = tarfile.TarInfo(symlink)
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            tar.addfile(info)
    return buf.getvalue()


ARCHIVE = make_tar({"logs/a.json": FILE_A, "logs/b.json": FILE_B, "../evil.json": b"{}"})
LOCK = {
    "schema_version": 1,
    "datasets": {
        "listed": {
            "title": "files pinned by URL",
            "optional": False,
            "files": [
                pin("a.json", FILE_A, url="https://example.invalid/a.json"),
                pin("sub/b.json", FILE_B, url="https://example.invalid/b.json"),
            ],
        },
        "packed": {
            "title": "files inside a pinned archive",
            "optional": True,
            "archive": {"url": "https://example.invalid/logs.tar", **pin("", ARCHIVE)},
            "files": [
                pin("a.json", FILE_A, archive_member="logs/a.json"),
                pin("b.json", FILE_B, archive_member="logs/b.json"),
            ],
        },
    },
}
CONTENT = {
    "https://example.invalid/a.json": FILE_A,
    "https://example.invalid/b.json": FILE_B,
    "https://example.invalid/logs.tar": ARCHIVE,
}


@pytest.fixture
def lock_path(tmp_path: Path) -> Path:
    path = tmp_path / "datasets.lock.json"
    path.write_text(json.dumps(LOCK))
    return path


def run(lock_path: Path, data_dir: Path, web: FakeWeb, *args: str) -> int:
    return fd.main(["--data-dir", str(data_dir), *args], lock_path=lock_path, opener=web)


def test_downloads_verifies_and_writes_manifest(lock_path: Path, tmp_path: Path) -> None:
    data = tmp_path / "data"
    web = FakeWeb(CONTENT)
    assert run(lock_path, data, web, "--all") == 0

    assert (data / "raw/listed/sub/b.json").read_bytes() == FILE_B
    assert (data / "raw/packed/a.json").read_bytes() == FILE_A
    assert not (data / "raw/evil.json").exists()
    assert not (data / "downloads/logs.tar").exists(), "archive is removed after extraction"

    manifest = json.loads((data / "MANIFEST.json").read_text())
    listed = manifest["datasets"]["listed"]
    assert listed["total_records"] == 3
    assert [f["records"] for f in listed["files"]] == [2, 1]
    assert listed["files"][0]["sha256"] == hashlib.sha256(FILE_A).hexdigest()
    assert manifest["datasets"]["packed"]["files"][0]["source_url"].endswith("logs.tar#logs/a.json")


def test_rerun_is_idempotent(lock_path: Path, tmp_path: Path) -> None:
    data = tmp_path / "data"
    assert run(lock_path, data, FakeWeb(CONTENT), "--all") == 0
    first = json.loads((data / "MANIFEST.json").read_text())

    offline = FakeWeb({})
    assert run(lock_path, data, offline, "--all") == 0
    assert offline.requests == []
    second = json.loads((data / "MANIFEST.json").read_text())
    assert second["datasets"] == first["datasets"]


def test_optional_datasets_are_skipped_by_default(lock_path: Path, tmp_path: Path) -> None:
    web = FakeWeb(CONTENT)
    assert run(lock_path, tmp_path / "data", web) == 0
    assert "https://example.invalid/logs.tar" not in web.requests


def test_corrupted_local_file_is_replaced(lock_path: Path, tmp_path: Path) -> None:
    data = tmp_path / "data"
    assert run(lock_path, data, FakeWeb(CONTENT)) == 0
    (data / "raw/listed/a.json").write_bytes(b"tampered")
    web = FakeWeb(CONTENT)
    assert run(lock_path, data, web) == 0
    assert web.requests == ["https://example.invalid/a.json"]
    assert (data / "raw/listed/a.json").read_bytes() == FILE_A


def test_hash_mismatch_is_rejected_and_nothing_is_kept(lock_path: Path, tmp_path: Path) -> None:
    data = tmp_path / "data"
    tampered = dict(CONTENT, **{"https://example.invalid/a.json": FILE_A.replace(b"e-1", b"e-2")})
    assert run(lock_path, data, FakeWeb(tampered)) == 1
    assert not (data / "raw/listed/a.json").exists()
    assert not (data / "raw/listed/a.json.part").exists()
    assert "listed" not in json.loads((data / "MANIFEST.json").read_text())["datasets"]


def test_inventory_only_reports_missing_without_network(lock_path: Path, tmp_path: Path) -> None:
    web = FakeWeb(CONTENT)
    assert run(lock_path, tmp_path / "data", web, "--inventory-only") == 1
    assert web.requests == []


def test_archive_member_must_be_a_regular_file(tmp_path: Path) -> None:
    archive = tmp_path / "x.tar"
    archive.write_bytes(make_tar({}, symlink="logs/a.json"))
    member = pin("a.json", FILE_A, archive_member="logs/a.json")
    with pytest.raises(fd.FetchError, match="not a regular file"):
        fd.extract_members(archive, [member], tmp_path / "out")
    assert not (tmp_path / "out/a.json").exists()


@pytest.mark.parametrize("bad", ["../x.json", "/etc/passwd", "a/../../x", "a\\..\\x", ""])
def test_safe_join_rejects_escaping_paths(tmp_path: Path, bad: str) -> None:
    with pytest.raises(fd.FetchError, match="unsafe path"):
        fd.safe_join(tmp_path, bad)


def test_non_https_urls_are_refused(tmp_path: Path) -> None:
    with pytest.raises(fd.FetchError, match="non-HTTPS"):
        fd.download("http://example.invalid/a.json", tmp_path / "a.json", opener=FakeWeb({}))
