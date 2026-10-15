#!/usr/bin/env python3
"""Freeze the ground-truth labels for the evaluation.

Labels are derived before any detection rule exists and without detection logic,
so the evaluation cannot become circular:

* Invictus Sigma-AWS (development set): every event is attributed to a Stratus
  Red Team technique and a role, using only what Stratus documents about itself
  in its source code: the API calls of each technique's detonate and revert
  functions, the names of the resources its Terraform prerequisites create, and
  how its CLI tags requests (``stratus-red-team_<uuid>`` user agent).
* Splunk attack_data (held-out test set): labels come from Splunk's dataset
  descriptors only. No Splunk event content is read: the test set stays
  unseen while detection rules are written.

Two modes:
    python scripts/build_labels.py --refresh-sources   # network: snapshot sources
    python scripts/build_labels.py                     # offline: build label files

--refresh-sources writes labels/sources.json: Stratus technique behaviour at the
release current when the data was made, Stratus' later framework mappings, the
MITRE ATT&CK Enterprise entries for every referenced technique ID, and which
Splunk labels come from a descriptor field. The default mode reads only that
snapshot, the dataset lock and the hash-verified Invictus files, and is
deterministic: rebuilding produces byte-identical label files.
"""

import argparse
import collections
import json
import re
import sys
import tarfile
import tempfile
from collections.abc import Iterable, Sequence
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from build_dataset_lock import SPLUNK, checkout_without_lfs
from ctinv.reader import iter_records
from fetch_datasets import (
    DEFAULT_DATA_DIR,
    LOCK_PATH,
    FetchError,
    download,
    is_current,
    load_json,
    safe_join,
    write_json_atomic,
)

ROOT = Path(__file__).resolve().parent.parent
LABELS_DIR = ROOT / "labels"
SOURCES_PATH = LABELS_DIR / "sources.json"
INVICTUS_OUT = LABELS_DIR / "invictus_labels.json"
SPLUNK_OUT = LABELS_DIR / "splunk_labels.json"
DERIVED_ON = "2026-10-14"

STRATUS_REPOSITORY = "DataDog/stratus-red-team"
# Latest release before the Invictus data was generated (2023-07-10); it has the
# 27 AWS techniques the Invictus README mentions.
STRATUS_BEHAVIOUR = {"version": "v2.8.0", "commit": "53140a3c689896da90d37f2785ee55aa49bb46c4"}
# Current release when the labels were frozen; v2.8.0 states only ATT&CK tactics,
# later releases add technique IDs from AWS' Threat Technique Catalog.
STRATUS_MAPPINGS = {"version": "v2.37.0", "commit": "338bc60ca82388b7b09e662795ba2e9253132546"}
ATTACK = {
    "name": "MITRE ATT&CK Enterprise",
    "version": "20.0",
    "repository": "https://github.com/mitre-attack/attack-stix-data",
    "commit": "c2494b29dd268c46a5d0ea0990553e4327cd2253",
    "path": "enterprise-attack/enterprise-attack-20.0.json",
    "size": 55271014,
    "sha256": "81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352",
}

# Facts from the Stratus source that the generic extraction below cannot see.
MANUAL_CALLS = {
    # Logs in with raw HTTP requests to the sign-in endpoint (main.go,
    # buildHttpRequest); CloudTrail records that as signin:ConsoleLogin.
    "aws.initial-access.console-login-without-mfa": {"detonate": ["signin:ConsoleLogin"]},
}
MANUAL_IDENTIFIERS = {
    # The user name is a Go variable (main.go: userName), not a Terraform resource.
    "aws.persistence.iam-create-admin-user": ["malicious-iam-user"],
}
# SDK operations that CloudTrail records under a different event name. Lambda
# event names additionally carry an API version suffix (AddPermission20150331v2).
CLOUDTRAIL_EVENT_NAMES = {"s3:PutBucketLifecycleConfiguration": "s3:PutBucketLifecycle"}

STRATUS_UA = re.compile(
    r"stratus-red-team_([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
)
RESOURCE_ID = re.compile(
    r"\b(?:vpc|subnet|sg|sgr|i|eni|snap|vol|ami|igw|rtb|acl|fl|eipalloc|eipassoc|nat)-[0-9a-f]{8,17}\b"
)
PREFLIGHT_CALL = "ec2:DescribeAccountAttributes"
PREFLIGHT_LOOKBACK_SECONDS = 30
# Text of the frozen splunk_labels.json, kept verbatim so that a rebuild reproduces
# the frozen file byte for byte. labels/README.md explains both phrases.
SPLUNK_SPLIT_TEXT = "held-out test (ground rule 10)"
SPLUNK_DUPLICATE_NOTE = (
    "attack_techniques/T1562.007/aws_delete_acl/aws_cloudtrail_events.json is "
    "byte-identical to the aws_create_acl file and was dropped as a duplicate in M2; "
    "both scenarios state T1562.007."
)


# --------------------------------------------------------------------------- sources


def github_source_files(commit: str, work_dir: Path) -> dict[str, str]:
    """Return the AWS technique files (main.go, main.tf) of a Stratus commit, by path."""
    url = f"https://codeload.github.com/{STRATUS_REPOSITORY}/tar.gz/{commit}"
    archive = work_dir / f"stratus-{commit}.tar.gz"
    download(url, archive)
    files = {}
    with tarfile.open(archive, "r:gz") as tar:
        for info in tar:
            path = PurePosixPath(*PurePosixPath(info.name).parts[1:])
            if (
                info.isreg()
                and path.parts[:4] == ("v2", "internal", "attacktechniques", "aws")
                and path.name in ("main.go", "main.tf")
            ):
                src = tar.extractfile(info)
                assert src is not None
                files[str(path)] = src.read().decode("utf-8")
    return files


def go_functions(src: str) -> dict[str, str]:
    starts = [
        (m.start(), m.group(1)) for m in re.finditer(r"^func (?:\([^)]*\)\s*)?(\w+)\(", src, re.M)
    ]
    return {
        name: src[start : starts[i + 1][0] if i + 1 < len(starts) else len(src)]
        for i, (start, name) in enumerate(starts)
    }


def reachable_calls(functions: dict[str, str], root: str | None) -> list[str]:
    """SDK operations (service:Operation) made by ``root`` and the functions it calls."""
    if root not in functions:
        return []
    seen, todo, calls = set(), [root], set()
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        body = functions[name]
        calls |= {f"{pkg}:{op}" for pkg, op in re.findall(r"&(\w+)\.(\w+?)Input\b", body)}
        todo += [other for other in functions if re.search(rf"\b{other}\(", body)]
    return sorted(calls)


def identifiers_in(src: str) -> set[str]:
    """Technique-specific resource names that Stratus puts into its requests."""
    found = set()
    for literal in re.findall(r'"([^"\n]*)"', src):
        if "github.com/" in literal:
            continue
        literal = literal.split("${")[0]
        if (
            "stratus-red-team" in literal
            and len(literal) > len("stratus-red-team") + 1
            or re.fullmatch(r"StratusRedTeam\w+", literal)
        ):
            found.add(literal)
    return found


def stratus_catalog(behaviour: dict[str, str], mappings: dict[str, str]) -> dict[str, dict]:
    catalog = {}
    for path, src in behaviour.items():
        if not path.endswith("main.go"):
            continue
        technique = re.search(r'\bID:\s*"([^"]+)"', src).group(1)
        functions = go_functions(src)
        detonate = re.search(r"\bDetonate:\s*(\w+)", src)
        revert = re.search(r"\bRevert:\s*(\w+)", src)
        tactics = re.search(r"MitreAttackTactics:\s*\[\]mitreattack\.Tactic\{([^}]*)\}", src).group(
            1
        )
        description = re.search(r"Description:\s*`(.*?)`", src, re.S)
        terraform = behaviour.get(path.replace("main.go", "main.tf"), "")
        catalog[technique] = {
            "source_path": path,
            "attack_tactics": [
                re.sub(r"(?<!^)(?=[A-Z])", "-", t).lower()
                for t in re.findall(r"mitreattack\.(\w+)", tactics)
            ],
            "description": description.group(1).strip() if description else "",
            "detonate_calls": sorted(
                set(reachable_calls(functions, detonate and detonate.group(1)))
                | set(MANUAL_CALLS.get(technique, {}).get("detonate", []))
            ),
            "revert_calls": reachable_calls(functions, revert and revert.group(1)),
            "identifiers": sorted(
                identifiers_in(terraform + src) | set(MANUAL_IDENTIFIERS.get(technique, []))
            ),
        }
    # An identifier that occurs in (or inside) another technique's identifier proves nothing.
    for technique, entry in catalog.items():
        others = [i for t, e in catalog.items() if t != technique for i in e["identifiers"]]
        entry["identifiers"] = [i for i in entry["identifiers"] if not any(i in o for o in others)]

    for path, src in mappings.items():
        technique = re.search(r'\bID:\s*"([^"]+)"', src)
        if not path.endswith("main.go") or technique is None or technique.group(1) not in catalog:
            continue
        block = (
            src.split("FrameworkMappings", 1)[1].split("Description:", 1)[0]
            if "FrameworkMappings" in src
            else ""
        )
        catalog[technique.group(1)]["stated_techniques"] = [
            {"framework": "AWS Threat Technique Catalog", "id": tid, "name": name}
            for name, tid in re.findall(r'Name:\s*"([^"]+)",\s*ID:\s*"([^"]+)"', block)
        ]
    for entry in catalog.values():
        entry.setdefault("stated_techniques", [])
    return dict(sorted(catalog.items()))


def attack_lookup(stix_path: Path, ids: Iterable[str]) -> dict[str, dict]:
    """Status, name, successors and tactics of each referenced ATT&CK technique ID."""
    stix = json.loads(stix_path.read_text(encoding="utf-8"))
    objects = {o["id"]: o for o in stix["objects"]}

    def external_id(obj: dict) -> str | None:
        refs = obj.get("external_references", [])
        return next(
            (r["external_id"] for r in refs if r.get("source_name") == "mitre-attack"), None
        )

    patterns = {external_id(o): o for o in stix["objects"] if o.get("type") == "attack-pattern"}
    revoked_by = collections.defaultdict(list)
    for rel in stix["objects"]:
        if rel.get("type") == "relationship" and rel.get("relationship_type") == "revoked-by":
            revoked_by[rel["source_ref"]].append(external_id(objects[rel["target_ref"]]))

    lookup, todo = {}, sorted(set(ids))
    while todo:
        tid = todo.pop()
        if tid in lookup:
            continue
        obj = patterns.get(tid)
        if obj is None:
            lookup[tid] = {"status": "not in ATT&CK"}
            continue
        status = (
            "revoked"
            if obj.get("revoked")
            else "deprecated"
            if obj.get("x_mitre_deprecated")
            else "active"
        )
        entry = {"status": status, "name": obj["name"]}
        if status == "active":
            entry["tactics"] = sorted({p["phase_name"] for p in obj.get("kill_chain_phases", [])})
        if obj["id"] in revoked_by:
            entry["revoked_by"] = sorted(revoked_by[obj["id"]])
            todo += entry["revoked_by"]
        lookup[tid] = entry
    return dict(sorted(lookup.items()))


def splunk_descriptor_sources(lock: dict, work_dir: Path) -> dict[str, str]:
    """Whether each Splunk label is a descriptor field or the directory name.

    Reads only the YAML descriptors of a checkout without Git LFS content, so no
    dataset file (event content) is ever present locally.
    """
    checkout = work_dir / "splunk"
    checkout_without_lfs(SPLUNK["repository"], SPLUNK["commit"], checkout)
    result = {}
    for pin in lock["datasets"]["splunk_attack_data"]["files"]:
        descriptor = yaml.safe_load(
            checkout.joinpath(pin["descriptor"]).read_text(encoding="utf-8")
        )
        result[pin["path"]] = (
            "descriptor field mitre_technique"
            if descriptor.get("mitre_technique")
            else "directory name"
        )
    return result


def refresh_sources() -> None:
    lock = load_json(LOCK_PATH)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        print(f"Stratus {STRATUS_BEHAVIOUR['version']} and {STRATUS_MAPPINGS['version']} sources")
        catalog = stratus_catalog(
            github_source_files(STRATUS_BEHAVIOUR["commit"], work),
            github_source_files(STRATUS_MAPPINGS["commit"], work),
        )
        print(f"{ATTACK['name']} {ATTACK['version']}")
        stix = work / "enterprise-attack.json"
        url = f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/{ATTACK['commit']}/{ATTACK['path']}"
        download(url, stix, size=ATTACK["size"], sha256=ATTACK["sha256"])
        splunk_ids = {
            t for f in lock["datasets"]["splunk_attack_data"]["files"] for t in f["mitre_technique"]
        }
        stratus_ids = {m["id"] for e in catalog.values() for m in e["stated_techniques"]}
        attack = attack_lookup(stix, splunk_ids | stratus_ids)
        print("Splunk descriptor metadata")
        splunk_sources = splunk_descriptor_sources(lock, work)

    write_json_atomic(
        SOURCES_PATH,
        {
            "schema_version": 1,
            "generated_by": "scripts/build_labels.py --refresh-sources",
            "stratus_red_team": {
                "repository": f"https://github.com/{STRATUS_REPOSITORY}",
                "license": "Apache-2.0",
                "behaviour": STRATUS_BEHAVIOUR,
                "mappings": STRATUS_MAPPINGS,
                "manual_additions": {"calls": MANUAL_CALLS, "identifiers": MANUAL_IDENTIFIERS},
                "cloudtrail_event_names": CLOUDTRAIL_EVENT_NAMES,
                "techniques": catalog,
            },
            "attack": {**{k: v for k, v in ATTACK.items() if k != "size"}, "techniques": attack},
            "splunk_label_sources": {
                "repository": f"https://github.com/{SPLUNK['repository']}",
                "commit": SPLUNK["commit"],
                "files": dict(sorted(splunk_sources.items())),
            },
        },
    )
    print(f"Wrote {SOURCES_PATH}")


# --------------------------------------------------------------------------- Invictus

# requestParameters keys that show whether a sharing call grants or withdraws access.
ADD_MARKERS = ('"add":', '"valuesToAdd":')
REMOVE_MARKERS = ('"remove":', '"valuesToRemove":')


def call_of(event: dict) -> str:
    return f"{event['eventSource'].split('.')[0]}:{event['eventName']}"


def documented(call: str, calls: Iterable[str]) -> bool:
    """True if a CloudTrail call is one of the documented SDK operations."""
    service, name = call.split(":", 1)
    for doc in calls:
        doc_service, doc_name = CLOUDTRAIL_EVENT_NAMES.get(doc, doc).split(":", 1)
        if service == doc_service and re.fullmatch(rf"{doc_name}(\d{{8}}v\d+)?", name):
            return True
    return False


def evidence_text(event: dict) -> str:
    keys = (
        "requestParameters",
        "responseElements",
        "resources",
        "userIdentity",
        "additionalEventData",
    )
    return json.dumps([event.get(k) for k in keys], sort_keys=True)


def counted(calls: Iterable[str]) -> str:
    return ", ".join(
        f"{c} x{n}" if n > 1 else c for c, n in sorted(collections.Counter(calls).items())
    )


def seconds(timestamp: str) -> int:
    return int(datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp())


def background_kind(event: dict) -> str:
    ua = event.get("userAgent", "")
    if ua == "AWS Internal":
        return "aws-internal"
    if (event.get("userIdentity") or {}).get("type") == "AWSService" or ua.endswith(
        ".amazonaws.com"
    ):
        return "aws-service"
    if "Console" in ua or "Mozilla/" in ua or "AWSCloudTrail" in ua:
        return "operator-console"
    if "Boto3" in ua or "aws-cli" in ua:
        return "operator-sdk"
    if "amazon-ssm-agent" in ua:
        return "ssm-agent"
    return "other"


class InvictusLabeler:
    """Attribute every Invictus event to a Stratus technique and a role."""

    def __init__(self, events: list[dict], catalog: dict[str, dict]) -> None:
        self.events = events
        self.catalog = catalog
        self.text = {e["eventID"]: evidence_text(e) for e in events}
        self.runs: dict[str, list[dict]] = collections.defaultdict(list)
        for event in events:
            match = STRATUS_UA.search(event.get("userAgent", ""))
            if match:
                self.runs[match.group(1)].append(event)
        per_call = collections.Counter(
            c for e in catalog.values() for c in set(e["detonate_calls"]) | set(e["revert_calls"])
        )
        self.shared_calls = {c for c, n in per_call.items() if n > 1}
        self.resource_ids: dict[str, set[str]] = collections.defaultdict(set)

    def label(self) -> tuple[list[dict], list[dict]]:
        ordered = sorted(self.runs.items(), key=lambda kv: (kv[1][0]["eventTime"], kv[0]))
        # Pass 1 uses documented calls and resource names. Pass 2 also uses resource
        # IDs (EC2 IDs etc.) created under runs that pass 1 attributed.
        runs = {rid: self.classify_run(rid, evs) for rid, evs in ordered}
        for rid, run in runs.items():
            if run.get("stratus_technique"):
                for event in self.runs[rid]:
                    for res in RESOURCE_ID.findall(json.dumps(event.get("responseElements"))):
                        self.resource_ids[res].add(run["stratus_technique"])
        runs = {rid: self.classify_run(rid, evs) for rid, evs in ordered}
        self.resolve_shared_calls(runs)
        self.link_preflights(runs)
        return list(runs.values()), self.label_events(runs)

    def classify_run(self, run_id: str, events: list[dict]) -> dict:
        terraform = [e for e in events if "Terraform" in e["userAgent"]]
        sdk_calls = [call_of(e) for e in events if "Terraform" not in e["userAgent"]]
        run: dict[str, Any] = {
            "run_id": run_id,
            "first_event": events[0]["eventTime"],
            "last_event": events[-1]["eventTime"],
            "events": len(events),
            "terraform_events": len(terraform),
            "sdk_calls": counted(sdk_calls),
            "error_codes": dict(
                sorted(
                    collections.Counter(
                        e["errorCode"] for e in events if e.get("errorCode")
                    ).items()
                )
            ),
        }
        if not terraform and set(sdk_calls) == {PREFLIGHT_CALL}:
            run["phase"] = "preflight"
            return run

        # Resources this run created itself are no independent evidence for it.
        own = {
            r for e in events for r in RESOURCE_ID.findall(json.dumps(e.get("responseElements")))
        }
        evidence = {}
        for technique, entry in self.catalog.items():
            calls = sorted(
                {
                    c
                    for c in sdk_calls
                    if documented(c, entry["detonate_calls"] + entry["revert_calls"])
                }
            )
            names = sorted(
                {i for e in events for i in entry["identifiers"] if i in self.text[e["eventID"]]}
            )
            resources = sorted(
                {
                    rid
                    for e in events
                    for rid in RESOURCE_ID.findall(self.text[e["eventID"]])
                    if self.resource_ids.get(rid) == {technique} and rid not in own
                }
            )
            if names or resources or [c for c in calls if c not in self.shared_calls]:
                evidence[technique] = {"calls": calls, "names": names, "resources": resources}
        # Names and resource IDs point at the technique's own resources. Calls can be
        # shared, or made by Stratus helpers outside the technique's file.
        identified = [t for t, f in evidence.items() if f["names"] or f["resources"]]
        chosen = identified or list(evidence)
        if len(chosen) != 1:
            run.update(
                phase="unknown",
                status="unresolved",
                stratus_technique=None,
                confidence=None,
                justification="no documented call or Stratus identifier"
                if not chosen
                else f"evidence for several techniques: {', '.join(sorted(chosen))}",
            )
            return run

        technique = chosen[0]
        found, entry = evidence[technique], self.catalog[technique]
        det = [c for c in found["calls"] if documented(c, entry["detonate_calls"])]
        rev = [c for c in found["calls"] if documented(c, entry["revert_calls"])]
        if not found["calls"]:
            phase = "warm-up"
        elif terraform or any(c not in rev for c in det):
            phase = "detonation"
        elif any(c not in det for c in rev):
            phase = "revert"
        else:
            phase = "shared-call"  # same call in detonate and revert, see resolve_shared_calls
        parts = []
        if found["calls"]:
            functions = "/".join(n for n, cs in (("detonate", det), ("revert", rev)) if cs)
            parts.append(
                f"{functions} call(s) in the technique source: {', '.join(found['calls'])}"
            )
        if found["names"]:
            parts.append(f"Stratus resource name(s): {', '.join(found['names'])}")
        if found["resources"]:
            parts.append(
                f"resource(s) from this technique's warm-up: {', '.join(found['resources'][:3])}"
            )
        if terraform:
            parts.append(f"{len(terraform)} Terraform warm-up event(s)")
        other_calls = [
            c
            for c in sdk_calls
            if not documented(c, entry["detonate_calls"] + entry["revert_calls"])
        ]
        if other_calls:
            parts.append(f"other calls: {counted(other_calls)}")
        if len(evidence) > 1:
            parts.append(
                "call-only evidence outweighed for "
                + ", ".join(sorted(set(evidence) - {technique}))
            )
        kinds = sum(bool(found[k]) for k in ("calls", "names", "resources"))
        run.update(
            phase=phase,
            status="assigned",
            stratus_technique=technique,
            confidence="high" if kinds >= 2 else "medium",
            justification="; ".join(parts),
        )
        return run

    def resolve_shared_calls(self, runs: dict[str, dict]) -> None:
        """Decide detonation vs. revert for calls used by both functions.

        A revert undoes an earlier detonation, so a run without warm-up after a
        detonation of the same technique is its revert. Add/remove markers in the
        request must agree, otherwise the run's confidence drops to low.
        """
        detonated = set()
        for run in runs.values():
            if run["phase"] == "detonation":
                detonated.add(run["stratus_technique"])
            if run["phase"] != "shared-call":
                continue
            text = " ".join(self.text[e["eventID"]] for e in self.runs[run["run_id"]])
            adds = any(m in text for m in ADD_MARKERS)
            removes = any(m in text for m in REMOVE_MARKERS)
            if run["stratus_technique"] in detonated:
                run["phase"], reason = (
                    "revert",
                    "after a detonation of the same technique, no warm-up",
                )
                conflict = adds and not removes
            else:
                run["phase"], reason = "detonation", "first run of the technique"
                detonated.add(run["stratus_technique"])
                conflict = removes and not adds
            if adds or removes:
                reason += f"; request {'adds' if adds else 'removes'} access"
            if conflict:
                run["confidence"] = "low"
                reason += " (contradicts the phase)"
            run["justification"] += f"; phase: {reason}"

    def link_preflights(self, runs: dict[str, dict]) -> None:
        """Attach each preflight to the CLI command it started.

        detonate, warmup and revert first call ec2:DescribeAccountAttributes under a
        fresh UUID (pkg/stratus/providers.go EnsureAuthenticated); cleanup does not
        (cmd/stratus/cleanup_cmd.go). A detonation or warm-up run is linked to the
        latest preflight at most PREFLIGHT_LOOKBACK_SECONDS before it. In the same
        second the preflight is ordered first, as it is the command's first call.
        Older preflights that were not followed by a run before the next preflight
        made no other tagged call and stay unresolved.
        """
        order = sorted(
            runs.values(), key=lambda r: (r["first_event"], r["phase"] != "preflight", r["run_id"])
        )
        pending: list[dict] = []
        for run in order:
            if run["phase"] == "preflight":
                pending.append(run)
                continue
            if run["phase"] not in ("detonation", "warm-up"):
                continue
            usable = [
                p
                for p in pending
                if seconds(run["first_event"]) - seconds(p["first_event"])
                <= PREFLIGHT_LOOKBACK_SECONDS
            ]
            if usable:
                pre, gap = (
                    usable[-1],
                    seconds(run["first_event"]) - seconds(usable[-1]["first_event"]),
                )
                alternatives = [p["run_id"][:8] for p in usable[:-1]]
                run["preflight_run_id"] = pre["run_id"]
                pre.update(
                    status="assigned",
                    stratus_technique=run["stratus_technique"],
                    confidence="low" if alternatives else "medium",
                    linked_run_id=run["run_id"],
                    justification=(
                        "Stratus credential check of the CLI command that started run "
                        f"{run['run_id'][:8]} {gap} s later"
                        + (
                            f"; other preflights in the window: {', '.join(alternatives)}"
                            if alternatives
                            else ""
                        )
                    ),
                )
            pending = []
        for run in runs.values():
            if run["phase"] == "preflight" and "status" not in run:
                run.update(
                    status="unresolved",
                    stratus_technique=None,
                    confidence=None,
                    justification="Stratus credential check not followed by a detonation or "
                    f"warm-up run within {PREFLIGHT_LOOKBACK_SECONDS} s before the next "
                    "credential check",
                )

    def label_events(self, runs: dict[str, dict]) -> list[dict]:
        run_of = {e["eventID"]: rid for rid, evs in self.runs.items() for e in evs}
        windows = collections.defaultdict(list)
        for run in runs.values():
            if run["phase"] == "detonation":
                windows[run["stratus_technique"]].append((run["first_event"], run["last_event"]))
        rows = []
        for event in self.events:
            row = {"id": event["eventID"], "time": event["eventTime"], "call": call_of(event)}
            rid = run_of.get(event["eventID"])
            if rid:
                run = runs[rid]
                if run["phase"] == "preflight":
                    role = "preflight"
                elif run["phase"] == "unknown":
                    role = "unresolved"
                elif "Terraform" in event["userAgent"]:
                    role = "warm-up"
                else:
                    role = "attack" if run["phase"] == "detonation" else "revert"
                row.update(
                    run=rid,
                    role=role,
                    technique=run.get("stratus_technique"),
                    basis=f"run {run['phase']}",
                )
                if role == "attack":
                    # Calls on the detonation path that the technique file does not name
                    # (e.g. sts:AssumeRole into its warm-up role) are kept, but marked.
                    row["documented"] = documented(
                        row["call"], self.catalog[row["technique"]]["detonate_calls"]
                    )
            else:
                row.update(self.label_untagged(event))
            if row["technique"] is None and row["role"] in ("background", "clean-up"):
                during = sorted(
                    t
                    for t, spans in windows.items()
                    if any(a <= row["time"] <= b for a, b in spans)
                )
                if during:
                    row["during_detonation_of"] = during
            rows.append(row)
        return rows

    def label_untagged(self, event: dict) -> dict:
        text = self.text[event["eventID"]]
        hits = {t for t, e in self.catalog.items() if any(i in text for i in e["identifiers"])}
        basis = "Stratus resource name"
        if not hits:
            hits = {t for rid in RESOURCE_ID.findall(text) for t in self.resource_ids.get(rid, ())}
            basis = "resource from a warm-up"
        technique = next(iter(hits)) if len(hits) == 1 else None
        principal = (event.get("userIdentity") or {}).get("arn") or ""
        if (
            technique
            and any(i in principal for i in self.catalog[technique]["identifiers"])
            and documented(call_of(event), self.catalog[technique]["detonate_calls"])
        ):
            # The detonation uses credentials of a role Stratus created (stolen from an
            # instance) through an SDK client without the Stratus user agent.
            return {
                "run": None,
                "role": "attack",
                "technique": technique,
                "documented": True,
                "basis": "documented detonate call by a Stratus-created role session",
            }
        if "Terraform" in event.get("userAgent", ""):
            # Stratus runs `terraform destroy` without its user agent (runner/terraform.go).
            return {
                "run": None,
                "role": "clean-up",
                "technique": technique,
                "basis": f"terraform destroy, {basis}"
                if technique
                else "terraform destroy, unattributed",
            }
        if technique:
            return {
                "run": None,
                "role": "side-effect",
                "technique": technique,
                "basis": f"{background_kind(event)}, {basis}",
            }
        return {
            "run": None,
            "role": "background",
            "technique": None,
            "basis": background_kind(event),
        }


def normalise(ids: Iterable[str], attack: dict[str, dict]) -> list[dict]:
    """Map stated IDs to active ATT&CK 20.0 techniques via MITRE's revoked-by links."""
    out = []
    for tid in ids:
        entry = attack.get(tid, {"status": "not in ATT&CK"})
        if entry["status"] == "active":
            out.append(
                {"id": tid, "name": entry["name"], "tactics": entry["tactics"], "stated": tid}
            )
        elif entry["status"] == "revoked" and entry.get("revoked_by"):
            for successor in entry["revoked_by"]:
                succ = attack[successor]
                out.append(
                    {
                        "id": successor,
                        "name": succ.get("name"),
                        "tactics": succ.get("tactics", []),
                        "stated": f"{tid} (revoked in ATT&CK)",
                    }
                )
        else:
            out.append({"id": None, "stated": f"{tid} ({entry['status']})"})
    return out


def technique_summary(
    catalog: dict, attack: dict, runs: list[dict], rows: list[dict], errors: dict
) -> dict:
    summary = {}
    for technique in sorted({r["stratus_technique"] for r in runs if r.get("stratus_technique")}):
        entry = catalog[technique]
        attack_rows = [r for r in rows if r["role"] == "attack" and r["technique"] == technique]
        failed = collections.Counter(errors[r["id"]] for r in attack_rows if r["id"] in errors)
        if not attack_rows:
            outcome = "not detonated (warm-up only)"
        elif sum(failed.values()) == len(attack_rows):
            outcome = "detonated, every attack call returned an error"
        else:
            outcome = "detonated"
        mine = [r for r in runs if r.get("stratus_technique") == technique]
        summary[technique] = {
            "attack_tactics_stated": entry["attack_tactics"],
            "stated_techniques": entry["stated_techniques"],
            "attack_v20": normalise([m["id"] for m in entry["stated_techniques"]], attack),
            "outcome": outcome,
            "attack_events": len(attack_rows),
            "attack_event_errors": dict(sorted(failed.items())),
            "attack_window": [attack_rows[0]["time"], attack_rows[-1]["time"]]
            if attack_rows
            else None,
            "runs": {
                p: [r["run_id"] for r in mine if r["phase"] == p]
                for p in sorted({r["phase"] for r in mine})
            },
        }
    return summary


# --------------------------------------------------------------------------- build


def load_invictus(lock: dict, data_dir: Path) -> list[dict]:
    """All Invictus events, from files that match the lock (the labels are bound to them)."""
    spec = lock["datasets"]["invictus_sigma_aws"]
    directory = data_dir / "raw" / "invictus_sigma_aws"
    events = []
    for pin in spec["files"]:
        path = safe_join(directory, pin["path"])
        if not is_current(path, pin):
            raise FetchError(
                f"{path} is missing or differs from the lock; run scripts/fetch_datasets.py"
            )
        events.extend(iter_records(path))
    return sorted(events, key=lambda e: (e["eventTime"], e["eventID"]))


def dump(path: Path, data: dict, row_keys: Sequence[str] = ()) -> None:
    """Pretty JSON, with one line per row for long row lists (readable diffs)."""
    shallow = {k: (f"@@{k}@@" if k in row_keys else v) for k, v in data.items()}
    text = json.dumps(shallow, indent=2)
    for key in row_keys:
        body = ",\n".join("    " + json.dumps(row) for row in data[key])
        text = text.replace(f'"@@{key}@@"', "[\n" + body + "\n  ]")
    path.write_text(text + "\n", encoding="utf-8")


def build(data_dir: Path) -> None:
    sources = load_json(SOURCES_PATH)
    lock = load_json(LOCK_PATH)
    catalog = sources["stratus_red_team"]["techniques"]
    attack = sources["attack"]["techniques"]
    shared_sources = {
        "stratus_red_team": {
            k: sources["stratus_red_team"][k] for k in ("repository", "behaviour", "mappings")
        },
        "attack": {k: v for k, v in sources["attack"].items() if k != "techniques"},
        "sources_file": "labels/sources.json",
    }

    events = load_invictus(lock, data_dir)
    errors = {e["eventID"]: e["errorCode"] for e in events if e.get("errorCode")}
    runs, rows = InvictusLabeler(events, catalog).label()
    techniques = technique_summary(catalog, attack, runs, rows, errors)
    invictus = lock["datasets"]["invictus_sigma_aws"]
    dump(
        INVICTUS_OUT,
        {
            "schema_version": 1,
            "dataset": "invictus_sigma_aws",
            "split": "development",
            "derived_on": DERIVED_ON,
            "derived_by": "scripts/build_labels.py (method: labels/README.md)",
            "data": {
                "upstream": invictus["upstream"],
                "files": len(invictus["files"]),
                "events": len(events),
            },
            "sources": shared_sources,
            "roles": {
                "attack": "detonation calls of a Stratus technique (what must be detected)",
                "warm-up": "Terraform creating the technique's prerequisites",
                "preflight": "Stratus credential check at the start of a CLI command",
                "revert": "Stratus undoing a detonation during clean-up",
                "clean-up": "terraform destroy of the prerequisites (not tagged by Stratus)",
                "side-effect": "AWS-side events caused by Stratus resources (KMS, SSM, ...)",
                "background": "not linked to Stratus (operators, consoles, AWS internal)",
                "unresolved": "tagged by Stratus, but the run could not be attributed",
            },
            "techniques": techniques,
            "runs": runs,
            "events": rows,
        },
        row_keys=("runs", "events"),
    )

    splunk = lock["datasets"]["splunk_attack_data"]
    label_sources = sources["splunk_label_sources"]["files"]
    manifest = load_json(data_dir / "MANIFEST.json", default={}).get("datasets", {})
    records = {
        f["path"]: f["records"] for f in manifest.get("splunk_attack_data", {}).get("files", [])
    }
    files = [
        {
            "path": pin["path"],
            "sha256": pin["sha256"],
            "records": records.get(pin["path"]),
            "scenario": PurePosixPath(pin["path"]).parts[-2],
            "descriptor": pin["descriptor"],
            "stated_techniques": pin["mitre_technique"],
            "technique_source": label_sources[pin["path"]],
            "attack_v20": normalise(pin["mitre_technique"], attack),
        }
        for pin in splunk["files"]
    ]
    by_technique = collections.defaultdict(list)
    for f in files:
        for tid in f["stated_techniques"] or ["(none)"]:
            by_technique[tid].append(f["path"])
    dump(
        SPLUNK_OUT,
        {
            "schema_version": 1,
            "dataset": "splunk_attack_data",
            "split": SPLUNK_SPLIT_TEXT,
            "derived_on": DERIVED_ON,
            "derived_by": "scripts/build_labels.py (method: labels/README.md)",
            "event_content_read": False,
            "data": {"upstream": splunk["upstream"], "files": len(files)},
            "sources": {
                "labels": "Splunk dataset descriptors (YAML), pinned in scripts/datasets.lock.json",
                "attack": shared_sources["attack"],
                "sources_file": "labels/sources.json",
            },
            "notes": [SPLUNK_DUPLICATE_NOTE],
            "by_stated_technique": dict(sorted(by_technique.items())),
            "files": files,
        },
        row_keys=("files",),
    )
    report(techniques, runs, rows, files)


def report(techniques: dict, runs: list[dict], rows: list[dict], splunk_files: list[dict]) -> None:
    print(f"Wrote {INVICTUS_OUT.relative_to(ROOT)} and {SPLUNK_OUT.relative_to(ROOT)}\n")
    print(
        "Invictus runs:",
        dict(collections.Counter(f"{r['phase']}/{r['status']}/{r['confidence']}" for r in runs)),
    )
    print("Invictus events by role:", dict(collections.Counter(r["role"] for r in rows)))
    for r in runs:
        if r["status"] == "unresolved":
            print(
                f"  unresolved {r['run_id']} {r['first_event']} {r['phase']}: {r['justification']}"
            )
    print("\nInvictus techniques:")
    for name, s in techniques.items():
        ids = (
            ", ".join(a["id"] or a["stated"] for a in s["attack_v20"]) or "(no technique ID stated)"
        )
        print(f"  {name:<58} {s['outcome']:<47} {ids}")
    detonated = [s for s in techniques.values() if s["outcome"] != "not detonated (warm-up only)"]
    inv = {a["id"] for s in detonated for a in s["attack_v20"] if a["id"]}
    spl = {a["id"] for f in splunk_files for a in f["attack_v20"] if a["id"]}

    def parents(ids: set[str]) -> set[str]:
        return {i.split(".")[0] for i in ids}

    print(
        f"\nATT&CK 20.0 techniques: Invictus {len(inv)} (detonated, stated ID), Splunk {len(spl)}"
    )
    print(f"  overlap exact:  {sorted(inv & spl)}")
    print(f"  overlap parent: {sorted(parents(inv) & parents(spl))}")
    print(f"  Invictus only:  {sorted(inv - spl)}")
    inv_tactics = sorted({t for s in detonated for t in s["attack_tactics_stated"]})
    spl_tactics = sorted(
        {t for f in splunk_files for a in f["attack_v20"] for t in a.get("tactics", [])}
    )
    print(f"  tactics Invictus (stated by Stratus in 2023): {inv_tactics}")
    print(f"  tactics Splunk (ATT&CK 20.0): {spl_tactics}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--refresh-sources", action="store_true", help="snapshot the external sources (network)"
    )
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    args = parser.parse_args(argv)
    if args.refresh_sources:
        refresh_sources()
    else:
        build(args.data_dir.resolve())
    return 0


if __name__ == "__main__":
    sys.exit(main())
