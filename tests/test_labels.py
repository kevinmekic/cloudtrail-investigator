"""Guards for the frozen ground-truth labels (see labels/README.md)."""

import hashlib
import json
from pathlib import Path

import pytest

LABELS = Path(__file__).resolve().parent.parent / "labels"
ROLES = {
    "attack",
    "warm-up",
    "preflight",
    "revert",
    "clean-up",
    "side-effect",
    "background",
    "unresolved",
}
SPLUNK_FILE_KEYS = {
    "path",
    "sha256",
    "records",
    "scenario",
    "descriptor",
    "stated_techniques",
    "technique_source",
    "attack_v20",
}


def frozen_hashes() -> dict[str, str]:
    lines = (LABELS / "SHA256SUMS").read_text().splitlines()
    return {name: digest for digest, name in (line.split(maxsplit=1) for line in lines)}


def load(name: str) -> dict:
    return json.loads((LABELS / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", ["invictus_labels.json", "splunk_labels.json", "sources.json"])
def test_label_files_are_unchanged(name: str) -> None:
    digest = hashlib.sha256((LABELS / name).read_bytes()).hexdigest()
    assert digest == frozen_hashes()[name], (
        f"labels/{name} changed. Labels are frozen: a change needs a documented reason, "
        "then an updated labels/SHA256SUMS (see labels/README.md)."
    )


def test_every_invictus_run_is_assigned_or_explicitly_unresolved() -> None:
    runs = load("invictus_labels.json")["runs"]
    assert runs
    for run in runs:
        assert run["status"] in {"assigned", "unresolved"}
        assert run["justification"]
        if run["status"] == "assigned":
            assert run["stratus_technique"] and run["confidence"] in {"high", "medium", "low"}
        else:
            assert run["stratus_technique"] is None and run["confidence"] is None


def test_every_invictus_event_has_a_role() -> None:
    labels = load("invictus_labels.json")
    events = labels["events"]
    assert len(events) == labels["data"]["events"]
    assert len({e["id"] for e in events}) == len(events)
    for event in events:
        assert event["role"] in ROLES
        if event["role"] in {"attack", "warm-up", "revert"}:
            assert event["technique"]
        if event["role"] == "background":
            assert event["technique"] is None


def test_splunk_labels_hold_metadata_only() -> None:
    labels = load("splunk_labels.json")
    assert labels["event_content_read"] is False
    for entry in labels["files"]:
        assert set(entry) == SPLUNK_FILE_KEYS
