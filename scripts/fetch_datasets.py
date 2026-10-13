#!/usr/bin/env python3
"""Download the public CloudTrail datasets into data/raw/<dataset>/ and record provenance.

Every file is pinned in scripts/datasets.lock.json by URL, size and SHA-256. A
download that does not match its pin is rejected, so a changed or tampered
upstream file is detected instead of silently used. Re-running is idempotent:
files already present with the pinned hash are not downloaded again.

After fetching, the provenance is written to data/MANIFEST.json and a short
inventory (files, size, streamed record count) is printed.

Examples:
    python scripts/fetch_datasets.py                          # the main datasets
    python scripts/fetch_datasets.py --dataset splunk_attack_data
    python scripts/fetch_datasets.py --all --inventory-only   # no network, verify local files
"""

import argparse
import hashlib
import json
import os
import sys
import tarfile
import urllib.request
from collections import Counter
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO
from urllib.parse import urlparse

from rich.console import Console
from rich.table import Table

from ctinv.reader import RecordFormatError, iter_records

ROOT = Path(__file__).resolve().parent.parent
LOCK_PATH = Path(__file__).resolve().with_name("datasets.lock.json")
DEFAULT_DATA_DIR = ROOT / "data"
USER_AGENT = "ctinv-fetch-datasets/1"
TIMEOUT_SECONDS = 60
CHUNK_BYTES = 1 << 20
MAX_UNPINNED_BYTES = 2 << 30  # cap for downloads whose size is not known in advance

Opener = Callable[..., Any]
console = Console()


class FetchError(RuntimeError):
    """A download or verification step failed."""


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    with path.open("rb") as fh:
        return hashlib.file_digest(fh, "sha256").hexdigest()


def is_current(path: Path, pin: dict[str, Any]) -> bool:
    """True if ``path`` exists with exactly the pinned size and SHA-256."""
    return (
        path.is_file() and path.stat().st_size == pin["size"] and sha256_file(path) == pin["sha256"]
    )


def safe_join(base: Path, relative: str) -> Path:
    """Join a lock-file path onto ``base``, refusing anything that could escape it."""
    rel = PurePosixPath(relative)
    if not rel.parts or rel.is_absolute() or ".." in rel.parts or "\\" in relative:
        raise FetchError(f"unsafe path in lock file: {relative!r}")
    return base.joinpath(*rel.parts)


def copy_verified(
    src: BinaryIO,
    dest: Path,
    *,
    size: int | None,
    sha256: str | None,
    label: str,
    max_bytes: int = MAX_UNPINNED_BYTES,
) -> tuple[int, str]:
    """Stream ``src`` to ``dest`` via a ``.part`` file and move it into place only if verified.

    Returns the number of bytes written and their SHA-256.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    limit = size if size is not None else max_bytes
    digest = hashlib.sha256()
    written = 0
    try:
        with part.open("wb") as out:
            while chunk := src.read(CHUNK_BYTES):
                written += len(chunk)
                if written > limit:
                    raise FetchError(f"{label}: larger than {limit} bytes, aborted")
                digest.update(chunk)
                out.write(chunk)
        if size is not None and written != size:
            raise FetchError(f"{label}: expected {size} bytes, got {written}")
        actual = digest.hexdigest()
        if sha256 is not None and actual != sha256:
            raise FetchError(f"{label}: SHA-256 mismatch (pinned {sha256}, got {actual})")
    except BaseException:
        part.unlink(missing_ok=True)
        raise
    os.replace(part, dest)
    return written, actual


def download(
    url: str,
    dest: Path,
    *,
    size: int | None = None,
    sha256: str | None = None,
    opener: Opener = urllib.request.urlopen,
) -> tuple[int, str]:
    """Download ``url`` to ``dest``, verifying size and SHA-256 when they are pinned."""
    if not url.startswith("https://"):
        raise FetchError(f"refusing non-HTTPS URL: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with opener(request, timeout=TIMEOUT_SECONDS) as response:
            return copy_verified(response, dest, size=size, sha256=sha256, label=url)
    except OSError as exc:  # includes URLError, HTTPError and socket timeouts
        raise FetchError(f"{url}: download failed: {exc}") from exc


def fetch_listed_files(spec: dict, dataset_dir: Path, opener: Opener) -> dict[str, str]:
    """Download every file of a dataset that is pinned by its own URL."""
    actions = {}
    for pin in spec["files"]:
        dest = safe_join(dataset_dir, pin["path"])
        if is_current(dest, pin):
            actions[pin["path"]] = "present"
            continue
        download(pin["url"], dest, size=pin["size"], sha256=pin["sha256"], opener=opener)
        actions[pin["path"]] = "downloaded"
    return actions


def fetch_archive_members(
    spec: dict, dataset_dir: Path, cache_dir: Path, keep_archive: bool, opener: Opener
) -> dict[str, str]:
    """Download a pinned archive (only if needed) and extract the pinned members from it."""
    actions = {pin["path"]: "present" for pin in spec["files"]}
    pending = [p for p in spec["files"] if not is_current(safe_join(dataset_dir, p["path"]), p)]
    if not pending:
        return actions
    archive = spec["archive"]
    archive_path = cache_dir / PurePosixPath(urlparse(archive["url"]).path).name
    if not is_current(archive_path, archive):
        console.print(f"  downloading {archive['url']} ({archive['size'] / 1e6:.0f} MB)")
        download(
            archive["url"],
            archive_path,
            size=archive["size"],
            sha256=archive["sha256"],
            opener=opener,
        )
    extract_members(archive_path, pending, dataset_dir)
    actions.update({pin["path"]: "extracted" for pin in pending})
    if not keep_archive:
        archive_path.unlink()
    return actions


def extract_members(archive_path: Path, members: Sequence[dict], dest_dir: Path) -> None:
    """Extract only the pinned members, each to its pinned path, verifying every byte.

    Nothing else in the archive is written: no extractall, so no path traversal,
    links or device files can come from an archive.
    """
    wanted = {pin["archive_member"]: pin for pin in members}
    with tarfile.open(archive_path, "r:*") as tar:
        for info in tar:
            pin = wanted.pop(info.name, None)
            if pin is None:
                continue
            src = tar.extractfile(info) if info.isreg() else None
            if src is None:
                raise FetchError(f"{archive_path.name}: {info.name} is not a regular file")
            with src:
                copy_verified(
                    src,
                    safe_join(dest_dir, pin["path"]),
                    size=pin["size"],
                    sha256=pin["sha256"],
                    label=f"{archive_path.name}:{info.name}",
                )
    if wanted:
        raise FetchError(f"{archive_path.name}: pinned members not found: {sorted(wanted)}")


def verify_only(spec: dict, dataset_dir: Path) -> dict[str, str]:
    return {
        pin["path"]: "present"
        if is_current(safe_join(dataset_dir, pin["path"]), pin)
        else "missing"
        for pin in spec["files"]
    }


def count_records(path: Path) -> tuple[int | None, str | None]:
    try:
        return sum(1 for _ in iter_records(path)), None
    except (RecordFormatError, UnicodeDecodeError, OSError, EOFError) as exc:
        return None, str(exc)


def mtime_utc(path: Path) -> str:
    stamp = datetime.fromtimestamp(path.stat().st_mtime, UTC)
    return stamp.isoformat(timespec="seconds").replace("+00:00", "Z")


def manifest_entry(
    spec: dict,
    dataset_dir: Path,
    data_dir: Path,
    actions: dict[str, str],
    previous: dict,
    *,
    count: bool,
    now: str,
) -> dict:
    """Describe a fully present dataset. Record counts are reused while the hash is unchanged."""
    previous_files = {f["path"]: f for f in previous.get("files", [])}
    files = []
    with console.status("") as status:
        for pin in spec["files"]:
            path = safe_join(dataset_dir, pin["path"])
            prev = previous_files.get(pin["path"], {})
            unchanged = prev.get("sha256") == pin["sha256"]
            if actions[pin["path"]] != "present":
                downloaded_at = now
            elif unchanged and prev.get("downloaded_at"):
                downloaded_at = prev["downloaded_at"]
            else:
                downloaded_at = mtime_utc(path)
            if unchanged and prev.get("records") is not None:
                records, error = prev["records"], None
            elif count:
                status.update(f"counting records in {pin['path']}")
                records, error = count_records(path)
            else:
                records, error = None, None
            source_url = pin.get("url") or f"{spec['archive']['url']}#{pin['archive_member']}"
            entry = {
                "path": pin["path"],
                "source_url": source_url,
                "size": pin["size"],
                "sha256": pin["sha256"],
                "downloaded_at": downloaded_at,
                "records": records,
            }
            if error:
                entry["read_error"] = error
            for key in ("mitre_technique", "descriptor"):
                if key in pin:
                    entry[key] = pin[key]
            files.append(entry)

    entry = {
        key: spec[key]
        for key in ("title", "source_page", "license", "integrity", "upstream", "archive")
        if key in spec
    }
    counts = [f["records"] for f in files]
    entry.update(
        directory=dataset_dir.relative_to(data_dir).as_posix(),
        file_count=len(files),
        total_size=sum(f["size"] for f in files),
        total_records=sum(counts) if None not in counts else None,
        files=files,
    )
    return entry


def load_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json_atomic(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1000 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1000
    raise AssertionError("unreachable")


def print_inventory(rows: list[tuple[str, dict | None, Counter, str | None]]) -> None:
    table = Table(title="Dataset inventory", title_justify="left")
    table.add_column("Dataset")
    table.add_column("Files", justify="right")
    table.add_column("Size", justify="right")
    table.add_column("Records", justify="right")
    table.add_column("This run")
    for name, entry, actions, error in rows:
        run = ", ".join(f"{n} {a}" for a, n in sorted(actions.items()))
        if error:
            table.add_row(name, "-", "-", "-", f"[red]FAILED: {error}[/red]")
        elif entry is None:
            table.add_row(name, "-", "-", "-", f"[yellow]incomplete ({run})[/yellow]")
        else:
            records = entry["total_records"]
            unreadable = sum(1 for f in entry["files"] if f.get("read_error"))
            shown = "not counted" if records is None and not unreadable else f"{records or 0:,}"
            if unreadable:
                shown += f" ({unreadable} unreadable)"
            table.add_row(
                name, str(entry["file_count"]), human_size(entry["total_size"]), shown, run
            )
    console.print(table)


def parse_args(argv: Sequence[str] | None, names: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--dataset",
        action="append",
        choices=names,
        help="dataset to process (repeatable). Default: all non-optional datasets",
    )
    parser.add_argument(
        "--all", action="store_true", help="process all datasets, including optional ones"
    )
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument(
        "--inventory-only",
        action="store_true",
        help="no downloads: verify local files against the lock and print the inventory",
    )
    parser.add_argument("--no-count", action="store_true", help="skip the streamed record count")
    parser.add_argument(
        "--keep-archives",
        action="store_true",
        help="keep downloaded archives in <data-dir>/downloads/ after extraction",
    )
    return parser.parse_args(argv)


def main(
    argv: Sequence[str] | None = None,
    *,
    lock_path: Path = LOCK_PATH,
    opener: Opener = urllib.request.urlopen,
) -> int:
    lock = load_json(lock_path)
    datasets: dict[str, dict] = lock["datasets"]
    args = parse_args(argv, sorted(datasets))
    if args.all:
        selected = list(datasets)
    elif args.dataset:
        selected = list(dict.fromkeys(args.dataset))
    else:
        selected = [name for name, spec in datasets.items() if not spec.get("optional")]

    data_dir: Path = args.data_dir.resolve()
    manifest_path = data_dir / "MANIFEST.json"
    manifest = load_json(manifest_path, default={})
    manifest_datasets: dict[str, dict] = manifest.get("datasets", {})
    now = utc_now()
    rows = []
    failed = False

    for name in selected:
        spec = datasets[name]
        dataset_dir = safe_join(data_dir / "raw", name)
        console.print(f"[bold]{name}[/bold]: {spec['title']}")
        try:
            if args.inventory_only:
                actions = verify_only(spec, dataset_dir)
            elif "archive" in spec:
                actions = fetch_archive_members(
                    spec, dataset_dir, data_dir / "downloads", args.keep_archives, opener
                )
            else:
                actions = fetch_listed_files(spec, dataset_dir, opener)
        except (FetchError, tarfile.TarError) as exc:
            console.print(f"  [red]error:[/red] {exc}")
            manifest_datasets.pop(name, None)
            rows.append((name, None, Counter(), str(exc)))
            failed = True
            continue

        if "missing" in actions.values():
            # Never let the manifest claim files that are not on disk.
            manifest_datasets.pop(name, None)
            rows.append((name, None, Counter(actions.values()), None))
            failed = True
            continue
        entry = manifest_entry(
            spec,
            dataset_dir,
            data_dir,
            actions,
            manifest_datasets.get(name, {}),
            count=not args.no_count,
            now=now,
        )
        manifest_datasets[name] = entry
        rows.append((name, entry, Counter(actions.values()), None))

    write_json_atomic(
        manifest_path,
        {
            "generated_by": "scripts/fetch_datasets.py",
            "lock_file": "scripts/datasets.lock.json",
            "updated_at": now,
            "datasets": dict(sorted(manifest_datasets.items())),
        },
    )
    print_inventory(rows)
    console.print(f"Manifest: {manifest_path}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
