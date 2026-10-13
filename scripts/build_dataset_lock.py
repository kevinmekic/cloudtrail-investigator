#!/usr/bin/env python3
"""Rebuild scripts/datasets.lock.json from the upstream sources.

This is a maintenance tool, not part of the normal workflow: run it only to pin
a new upstream version. It downloads every file once, computes its SHA-256 and
cross-checks it against whatever the source itself publishes:

* flaws_cloud: no checksum is published, so the archive hash is pinned on first
  use (trust on first use). Members are hashed from the verified archive.
* invictus_sigma_aws: the file list comes from the git tree at a pinned commit,
  and every download must match its git blob SHA-1 from that tree.
* splunk_attack_data: the repository is checked out at a pinned commit without
  Git LFS content. Files are selected from the dataset descriptors (YAML), and
  every download must match the SHA-256 in its LFS pointer. Needs ``git``.

Review the diff of the lock file before committing it.

Examples:
    python scripts/build_dataset_lock.py --dataset invictus_sigma_aws
    python scripts/build_dataset_lock.py --dataset flaws_cloud --keep-archive data/downloads
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from collections.abc import Iterator, Sequence
from pathlib import Path, PurePosixPath
from urllib.parse import quote

import yaml

from ctinv.reader import RecordFormatError, iter_records
from fetch_datasets import (
    LOCK_PATH,
    USER_AGENT,
    FetchError,
    copy_verified,
    download,
    load_json,
    write_json_atomic,
)

FLAWS = {
    "title": "flaws.cloud CloudTrail logs (Summit Route, 2020)",
    "optional": False,
    "source_page": "https://summitroute.com/blog/2020/10/09/public_dataset_of_cloudtrail_logs_from_flaws_cloud/",
    "license": (
        "No license stated by the source. Published by Summit Route (Scott Piper) as a public "
        "research dataset; the site footer reads 'All Rights Reserved'. Fetch from the source, "
        "do not redistribute."
    ),
    "integrity": (
        "The source publishes no checksum. The archive SHA-256 was pinned on first download "
        "(trust on first use); members are hashed from that verified archive."
    ),
    "archive_url": "https://summitroute.com/downloads/flaws_cloudtrail_logs.tar",
}

INVICTUS = {
    "title": "Invictus IR Sigma-AWS: CloudTrail from Stratus Red Team simulations (2023)",
    "optional": False,
    "source_page": "https://github.com/invictus-ir/Sigma-AWS",
    "license": "MIT, Copyright (c) 2023 Invictus Incident Response (repository LICENSE file)",
    "integrity": (
        "Pinned to a git commit. Every file was verified against its git blob SHA-1 at that "
        "commit before its SHA-256 was recorded."
    ),
    "repository": "invictus-ir/Sigma-AWS",
    "commit": "f0d55993fb575f747cee13069adeaa999c940b14",
    "directory": "CloudTrail",
}

SPLUNK = {
    "title": "Splunk attack_data: CloudTrail samples per ATT&CK technique",
    "optional": True,
    "source_page": "https://github.com/splunk/attack_data",
    "license": "Apache-2.0 (repository LICENSE file)",
    "integrity": (
        "Pinned to a git commit. The files are Git LFS objects; every download was verified "
        "against the SHA-256 and size in its LFS pointer at that commit."
    ),
    "selection": (
        "Files whose dataset descriptor (YAML) declares sourcetype 'aws:cloudtrail' and whose "
        "every record has eventID, eventName, eventSource and eventTime. Byte-identical "
        "duplicates are kept once. Everything else is listed under 'excluded' with the reason."
    ),
    "repository": "splunk/attack_data",
    "commit": "eac2f8f675ec31a6618003399dcc53641524e673",
}
CLOUDTRAIL_CORE_FIELDS = ("eventID", "eventName", "eventSource", "eventTime")
LFS_POINTER = re.compile(
    r"version https://git-lfs\.github\.com/spec/v1\noid sha256:([0-9a-f]{64})\nsize (\d+)\n"
)
TECHNIQUE_ID = re.compile(r"T\d{4}(\.\d{3})?")


def get_json(url: str) -> dict:
    request = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def build_flaws(work_dir: Path, keep_archive: Path | None) -> dict:
    url = FLAWS["archive_url"]
    target_dir = keep_archive or work_dir
    archive_path = target_dir / PurePosixPath(url).name
    if archive_path.exists():
        print(f"  using existing archive {archive_path} (hashing it, not trusting it)")
        size = archive_path.stat().st_size
        with archive_path.open("rb") as fh:
            sha256 = hashlib.file_digest(fh, "sha256").hexdigest()
    else:
        print(f"  downloading {url}")
        size, sha256 = download(url, archive_path)

    files = []
    with tarfile.open(archive_path, "r:*") as tar:
        for info in tar:
            if not info.isreg():
                print(f"  skipping non-file archive member {info.name!r}")
                continue
            name = PurePosixPath(info.name).name
            if not name.endswith(".json.gz"):
                print(f"  skipping unexpected archive member {info.name!r}")
                continue
            src = tar.extractfile(info)
            assert src is not None
            with src:
                member_size, member_sha256 = copy_verified(
                    src, work_dir / "member.tmp", size=info.size, sha256=None, label=info.name
                )
            files.append(
                {
                    "path": name,
                    "archive_member": info.name,
                    "size": member_size,
                    "sha256": member_sha256,
                }
            )
    files.sort(key=lambda f: f["path"])
    if len({f["path"] for f in files}) != len(files):
        raise FetchError("archive contains duplicate member file names")
    spec = {k: v for k, v in FLAWS.items() if k != "archive_url"}
    spec["archive"] = {"url": url, "size": size, "sha256": sha256}
    spec["files"] = files
    return spec


def build_invictus(work_dir: Path) -> dict:
    repo, commit, directory = INVICTUS["repository"], INVICTUS["commit"], INVICTUS["directory"]
    tree = get_json(f"https://api.github.com/repos/{repo}/git/trees/{commit}?recursive=1")
    if tree.get("truncated"):
        raise FetchError("GitHub returned a truncated tree; refusing to build a partial lock")
    blobs = [
        e
        for e in tree["tree"]
        if e["type"] == "blob"
        and e["path"].startswith(f"{directory}/")
        and e["path"].endswith(".json")
    ]
    files = []
    for blob in sorted(blobs, key=lambda e: e["path"]):
        url = f"https://raw.githubusercontent.com/{repo}/{commit}/{quote(blob['path'])}"
        dest = work_dir / "blob.tmp"
        size, sha256 = download(url, dest, size=blob["size"])
        if git_blob_sha1(dest.read_bytes()) != blob["sha"]:
            raise FetchError(f"{url}: content does not match git blob {blob['sha']}")
        files.append(
            {
                "path": PurePosixPath(blob["path"]).name,
                "url": url,
                "size": size,
                "sha256": sha256,
                "git_blob_sha1": blob["sha"],
            }
        )
    print(f"  {len(files)} files verified against their git blob SHA-1")
    spec = {k: INVICTUS[k] for k in ("title", "optional", "source_page", "license", "integrity")}
    spec["upstream"] = {
        "repository": f"https://github.com/{repo}",
        "commit": commit,
        "directory": directory,
    }
    spec["files"] = files
    return spec


def checkout_without_lfs(repository: str, commit: str, dest: Path) -> None:
    """Shallow-fetch exactly one commit; LFS files stay as pointer files."""
    env = dict(os.environ, GIT_LFS_SKIP_SMUDGE="1", GIT_TERMINAL_PROMPT="0")
    url = f"https://github.com/{repository}.git"
    for args in (
        ["init", "-q", str(dest)],
        ["-C", str(dest), "fetch", "-q", "--depth", "1", url, commit],
        ["-C", str(dest), "-c", "advice.detachedHead=false", "checkout", "-q", "FETCH_HEAD"],
    ):
        subprocess.run(["git", *args], check=True, env=env)


def cloudtrail_candidates(checkout: Path) -> Iterator[tuple[str, dict, Path]]:
    """Yield (repo path, descriptor, descriptor path) for every file labelled aws:cloudtrail.

    Handles both descriptor schemas found in the repository: the current one
    (``datasets: [{path, sourcetype}]``) and the older one (``dataset: [url]``
    plus ``sourcetypes: [...]`` for all of them).
    """
    for yml in sorted(checkout.joinpath("datasets").rglob("*.yml")):
        descriptor = yaml.safe_load(yml.read_text(encoding="utf-8"))
        if not isinstance(descriptor, dict):
            continue
        for item in descriptor.get("datasets") or []:
            if isinstance(item, dict) and item.get("sourcetype") == "aws:cloudtrail":
                yield str(item.get("path", "")).lstrip("/"), descriptor, yml
        if "aws:cloudtrail" in (descriptor.get("sourcetypes") or []):
            for url in descriptor.get("dataset") or []:
                match = re.search(r"/media/splunk/attack_data/[^/]+/(datasets/.+)$", str(url))
                yield (match.group(1) if match else str(url)), descriptor, yml


def techniques_for(path: str, descriptor: dict) -> list[str]:
    declared = descriptor.get("mitre_technique")
    if declared:
        return [str(t) for t in declared]
    # Older descriptors carry no technique field; the directory name is the label.
    parts = PurePosixPath(path).parts
    if len(parts) > 2 and parts[1] == "attack_techniques" and TECHNIQUE_ID.fullmatch(parts[2]):
        return [parts[2]]
    return []


def content_problem(path: Path) -> str | None:
    """Return why a file is not raw CloudTrail, or None if every record looks like an event."""
    count = 0
    try:
        for record in iter_records(path):
            count += 1
            if not isinstance(record, dict):
                return "contains non-object JSON values"
            if set(record) >= {"preview", "result"}:
                return "Splunk search export ({preview, result} wrapper), not raw CloudTrail"
            if not all(field in record for field in CLOUDTRAIL_CORE_FIELDS):
                return "records lack CloudTrail core fields"
    except (RecordFormatError, UnicodeDecodeError) as exc:
        return f"not readable as JSON records ({exc.__class__.__name__})"
    return None if count else "no records"


def build_splunk(work_dir: Path) -> dict:
    repo, commit = SPLUNK["repository"], SPLUNK["commit"]
    checkout = work_dir / "checkout"
    print(f"  checking out {repo}@{commit[:12]} without LFS content")
    checkout_without_lfs(repo, commit, checkout)

    files, excluded, seen_paths, seen_hashes = [], [], set(), {}
    for path, descriptor, yml in cloudtrail_candidates(checkout):
        if path in seen_paths:
            continue
        seen_paths.add(path)
        rel = PurePosixPath(path)
        if rel.parts[:1] != ("datasets",) or ".." in rel.parts:
            excluded.append({"path": path, "reason": "unrecognised dataset location"})
            continue
        pointer_file = checkout.joinpath(*rel.parts)
        if not pointer_file.is_file():
            excluded.append({"path": path, "reason": "named in a descriptor but not in the repo"})
            continue
        pointer = LFS_POINTER.fullmatch(pointer_file.read_text(encoding="utf-8", errors="replace"))
        if not pointer:
            excluded.append({"path": path, "reason": "not a Git LFS object"})
            continue
        sha256, size = pointer.group(1), int(pointer.group(2))
        url = f"https://media.githubusercontent.com/media/{repo}/{commit}/{quote(path)}"
        dest = work_dir / "download.tmp"
        download(url, dest, size=size, sha256=sha256)
        problem = content_problem(dest)
        if problem is None and sha256 in seen_hashes:
            problem = f"byte-identical to {seen_hashes[sha256]}"
        if problem:
            excluded.append({"path": path, "reason": problem})
            continue
        seen_hashes[sha256] = path
        files.append(
            {
                "path": str(rel.relative_to("datasets")),
                "url": url,
                "size": size,
                "sha256": sha256,
                "mitre_technique": techniques_for(path, descriptor),
                "descriptor": yml.relative_to(checkout).as_posix(),
            }
        )
    print(f"  {len(files)} files selected, {len(excluded)} excluded")
    spec = {
        k: SPLUNK[k]
        for k in ("title", "optional", "source_page", "license", "integrity", "selection")
    }
    spec["upstream"] = {"repository": f"https://github.com/{repo}", "commit": commit}
    spec["files"] = sorted(files, key=lambda f: f["path"])
    spec["excluded"] = sorted(excluded, key=lambda f: f["path"])
    return spec


BUILDERS = {
    "flaws_cloud": build_flaws,
    "invictus_sigma_aws": build_invictus,
    "splunk_attack_data": build_splunk,
}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--dataset", action="append", choices=sorted(BUILDERS), required=True)
    parser.add_argument(
        "--keep-archive",
        type=Path,
        metavar="DIR",
        help="keep (or reuse) the flaws.cloud archive in DIR, e.g. data/downloads",
    )
    args = parser.parse_args(argv)

    lock = load_json(LOCK_PATH, default={"schema_version": 1, "datasets": {}})
    with tempfile.TemporaryDirectory() as tmp:
        for name in dict.fromkeys(args.dataset):
            print(f"{name}:")
            if name == "flaws_cloud":
                if args.keep_archive:
                    args.keep_archive.mkdir(parents=True, exist_ok=True)
                spec = build_flaws(Path(tmp), args.keep_archive)
            else:
                spec = BUILDERS[name](Path(tmp))
            lock["datasets"][name] = spec
    order = [*BUILDERS, *sorted(set(lock["datasets"]) - set(BUILDERS))]
    lock["datasets"] = {k: lock["datasets"][k] for k in order if k in lock["datasets"]}
    write_json_atomic(LOCK_PATH, lock)
    print(f"Wrote {LOCK_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
