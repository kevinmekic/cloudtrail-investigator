"""Tests for the dataset registry that reports take dataset caveats from."""

import json
from pathlib import Path

import pytest

from ctinv.datasets import DatasetRegistryError, describe, load_registry, parse_registry

LOCK = Path(__file__).resolve().parent.parent / "scripts" / "datasets.lock.json"


def test_every_fetched_dataset_is_described() -> None:
    lock = json.loads(LOCK.read_text())["datasets"]
    registry = load_registry()
    assert set(registry) == set(lock)
    for name, entry in lock.items():
        assert registry[name].title == entry["title"], name
        assert registry[name].url == entry["source_page"], name


def test_flaws_cloud_source_ips_are_anonymised() -> None:
    # Reports on flaws.cloud must warn that its addresses are not real attacker
    # infrastructure; this property is what triggers the warning.
    flaws = load_registry()["flaws_cloud"]
    assert flaws.source_ips_anonymised
    assert set(flaws.anonymised) == {"source_ips", "account_ids", "access_keys"}
    assert "wernicke" in flaws.anonymisation


def test_describe_marks_unknown_datasets() -> None:
    known, unknown = describe(["flaws_cloud", "my_own_logs"])
    assert known["described"] and "source_ips" in known["anonymised"]
    assert unknown == {
        "name": "my_own_logs",
        "described": False,
        "title": None,
        "url": None,
        "anonymised": [],
        "anonymisation": None,
        "caveats": [],
    }


@pytest.mark.parametrize(
    "text",
    [
        "- a list",
        "x: {title: t}",
        "x: {title: t, url: u, colour: red}",
        "x: {title: t, url: u, anonymised: [names]}",
        "x: {title: t, url: u, anonymised: [source_ips]}",
        "x: {title: t, url: u, caveats: ['']}",
    ],
)
def test_malformed_registry_is_rejected(text: str) -> None:
    with pytest.raises(DatasetRegistryError):
        parse_registry(text)
