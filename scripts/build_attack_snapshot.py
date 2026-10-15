#!/usr/bin/env python3
"""Snapshot the MITRE ATT&CK entries that the built-in detection rules reference.

The rule metadata test checks each rule's technique ID, name, tactics and former
IDs against this snapshot, so a typo or an outdated mapping fails the test suite
offline. The entries come from the same hash-pinned ATT&CK Enterprise v20.0
bundle as labels/sources.json (which only covers techniques named by the dataset
labels). Re-run this script after adding a rule with a new technique:

    python scripts/build_attack_snapshot.py                # downloads the pinned bundle
    python scripts/build_attack_snapshot.py --bundle FILE  # a local copy, hash-checked
"""

import argparse
import json
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

from build_labels import ATTACK, attack_lookup
from ctinv.detect import load_rules
from fetch_datasets import download, sha256_file

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT_PATH = ROOT / "tests" / "attack_v20_rule_techniques.json"


def rule_technique_ids() -> list[str]:
    ids = set()
    for rule in load_rules():
        ids.add(rule.technique_id)
        ids.update(rule.former_technique_ids)
    return sorted(ids)


def build(bundle: Path) -> dict:
    if sha256_file(bundle) != ATTACK["sha256"]:
        raise SystemExit(f"{bundle}: SHA-256 does not match the pinned ATT&CK bundle")
    return {
        "attack": {k: v for k, v in ATTACK.items() if k != "size"},
        "techniques": attack_lookup(bundle, rule_technique_ids()),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--bundle", type=Path, help="local copy of the pinned ATT&CK bundle")
    args = parser.parse_args(argv)
    if args.bundle:
        snapshot = build(args.bundle)
    else:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "enterprise-attack.json"
            url = (
                "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
                f"{ATTACK['commit']}/{ATTACK['path']}"
            )
            download(url, bundle, size=ATTACK["size"], sha256=ATTACK["sha256"])
            snapshot = build(bundle)
    SNAPSHOT_PATH.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
    print(f"{SNAPSHOT_PATH.relative_to(ROOT)}: {len(snapshot['techniques'])} techniques")
    return 0


if __name__ == "__main__":
    sys.exit(main())
