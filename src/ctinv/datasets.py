"""Known properties of the public datasets (``datasets.yml``), for reports.

A report about events of a dataset takes that dataset's caveats from here, for
example that the publisher anonymised the source IP addresses, account IDs and
access keys. A dataset that is not described (data ingested under another
name) is reported as such, so a report never implies that its values are real
or anonymised.
"""

from dataclasses import dataclass
from importlib.resources import files
from typing import Any

import yaml

ANONYMISABLE = ("source_ips", "account_ids", "access_keys")
_KEYS = {"title", "url", "anonymised", "anonymisation", "caveats"}


class DatasetRegistryError(ValueError):
    """datasets.yml is malformed."""


@dataclass(frozen=True)
class DatasetInfo:
    name: str
    title: str
    url: str
    anonymised: tuple[str, ...]
    anonymisation: str | None
    caveats: tuple[str, ...]

    @property
    def source_ips_anonymised(self) -> bool:
        return "source_ips" in self.anonymised


def parse_registry(text: str) -> dict[str, DatasetInfo]:
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise DatasetRegistryError("datasets.yml must map dataset names to descriptions")
    registry = {}
    for name, entry in data.items():
        if not isinstance(entry, dict) or set(entry) - _KEYS or not {"title", "url"} <= set(entry):
            raise DatasetRegistryError(f"{name}: needs title and url, may have {sorted(_KEYS)}")
        anonymised = entry.get("anonymised") or []
        if not isinstance(anonymised, list) or set(anonymised) - set(ANONYMISABLE):
            raise DatasetRegistryError(f"{name}: anonymised must be a list of {ANONYMISABLE}")
        if anonymised and not entry.get("anonymisation"):
            raise DatasetRegistryError(f"{name}: say how the data was anonymised")
        caveats = entry.get("caveats") or []
        if not all(isinstance(c, str) and c.strip() for c in caveats):
            raise DatasetRegistryError(f"{name}: caveats must be non-empty strings")
        registry[name] = DatasetInfo(
            name=name,
            title=entry["title"],
            url=entry["url"],
            anonymised=tuple(anonymised),
            anonymisation=entry.get("anonymisation"),
            caveats=tuple(caveats),
        )
    return registry


def load_registry() -> dict[str, DatasetInfo]:
    return parse_registry((files("ctinv") / "datasets.yml").read_text(encoding="utf-8"))


def describe(names: list[str]) -> list[dict[str, Any]]:
    """Each dataset by name with what is known about it; ``described`` is False if nothing is."""
    registry = load_registry()
    described = []
    for name in names:
        info = registry.get(name)
        described.append(
            {
                "name": name,
                "described": info is not None,
                "title": info.title if info else None,
                "url": info.url if info else None,
                "anonymised": list(info.anonymised) if info else [],
                "anonymisation": info.anonymisation if info else None,
                "caveats": list(info.caveats) if info else [],
            }
        )
    return described
