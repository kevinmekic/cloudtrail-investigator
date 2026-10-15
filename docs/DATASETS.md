# Datasets

This project uses only public CloudTrail datasets. The data itself is never
committed (`data/` is git-ignored); this page describes each dataset, its
license or terms, its known caveats, and how to fetch it reproducibly.

| Dataset | Role here | Files | Size | Records | License | Fetched by default |
|---|---|---:|---:|---:|---|---|
| `flaws_cloud` | Scale, real-world mess, exploratory hunting | 20 | 251.7 MB | 1,939,207 | not stated | yes |
| `invictus_sigma_aws` | Attack simulation (Stratus Red Team) | 55 | 3.7 MB | 2,900 | MIT | yes |
| `splunk_attack_data` | Extra attack samples per technique | 49 | 42.6 MB | 29,896 | Apache-2.0 | no (optional) |

Sizes are on disk as distributed (flaws.cloud is gzip-compressed). Record counts
were produced by `scripts/fetch_datasets.py` on 2026-10-13 and are stored in
`data/MANIFEST.json`. They count records, not unique events: flaws.cloud has
**1,225,784 unique events**, because 713,423 records are exact duplicates (see
the flaws.cloud caveats). Invictus has no duplicates.

## Fetching

```bash
python scripts/fetch_datasets.py                                # flaws_cloud + invictus_sigma_aws
python scripts/fetch_datasets.py --dataset splunk_attack_data   # optional dataset
python scripts/fetch_datasets.py --all --inventory-only         # no network: verify and list
```

Files land in `data/raw/<dataset>/`. The script:

- **Pins every file.** `scripts/datasets.lock.json` lists each file with its
  URL, size and SHA-256. A download that does not match is rejected and nothing
  is written, so a changed or tampered upstream file is noticed instead of used.
  Downloads are HTTPS only.
- **Is idempotent.** Files already present with the pinned hash are skipped; a
  re-run with complete data makes no network requests.
- **Extracts archives defensively.** Only the pinned members of the flaws.cloud
  tar are written, each to its pinned path (no `extractall`, so no path
  traversal, links or device files). The tar is deleted afterwards unless
  `--keep-archives` is given.
- **Records provenance** in `data/MANIFEST.json`: per dataset the source, license
  and pinned upstream version; per file the source URL, size, SHA-256, download
  time and record count. A dataset that is incomplete is removed from the
  manifest rather than listed with missing files.
- **Prints an inventory** (files, size, records). Records are counted by
  streaming, one at a time (`ctinv.reader`). The first full run of both main
  datasets (extracting and counting 1.94 million records, about 2 GB of
  uncompressed JSON) took 43 s with a peak memory of 44 MB. Counts are cached in
  the manifest per file hash, so later runs take about a second.

### Updating the pins

`scripts/build_dataset_lock.py` rebuilds the lock entries from upstream. It is a
maintenance tool: run it only to move to a new upstream version, and review the
lock diff before committing. How each source is verified at that point is
described per dataset below.

## flaws.cloud CloudTrail logs

- **Source:** Summit Route (Scott Piper), released 2020-10-09.
  Description: <https://summitroute.com/blog/2020/10/09/public_dataset_of_cloudtrail_logs_from_flaws_cloud/>.
  Download: <https://summitroute.com/downloads/flaws_cloudtrail_logs.tar>.
- **What it is:** CloudTrail management events from the AWS account behind the
  [flaws.cloud](http://flaws.cloud/) training challenge, 2017-02-12 to
  2020-10-07. It is largely real attack traffic from people playing the
  challenge, plus the owner's own setup work and tool testing. The source states
  1,939,207 events; the streamed count here matches exactly.
- **Format:** one tar with 20 `flaws_cloudtrail<NN>.json.gz` files in the normal
  `{"Records": [...]}` layout.
- **License / terms:** no license is stated. The data was published openly to
  support AWS security research; the site footer reads "All Rights Reserved".
  Treat it as usable for research, fetch it from the source, and do not
  redistribute it.
- **Integrity:** the source publishes no checksum (the server ETag is a
  multipart-upload ETag, not an MD5). The archive SHA-256 was pinned on first
  download on 2026-10-13 (trust on first use), and the members are hashed from
  that verified archive.
- **Caveats:**
  - **Anonymized.** IP addresses, account IDs and access keys were replaced
    consistently with random values of the same format (Latacora's `wernicke`),
    and some values were manually set to `REDACTED`. Consequences: IPs that were
    really AWS-internal look external, IPs carry no geolocation meaning, so
    **impossible travel or geo logic cannot be validated on this data**, and the
    account ID differs from the real one.
  - **No ground truth.** Nothing is labelled; the "attackers" are thousands of
    unknown players. Suitable for hunting and manual false-positive review, not
    for measured detection rates.
  - **Unusual baseline.** The only legitimate user worked mostly as root, so root
    usage is common and not by itself suspicious here.
  - **Management events only.** S3 and Lambda data events were not logged.
  - **One in three records is a duplicate.** 713,423 of the 1,939,207 records
    repeat an earlier record exactly (same eventID, identical content), leaving
    1,225,784 unique events. The repeats fall between 2019-02-11, when a second
    trail was created, and 2019-08-23, when the original trail was deleted
    (both visible in the data): each event was delivered by both trails. Count
    unique events, as `ctinv ingest` does. Details in [`SCHEMA.md`](SCHEMA.md).

## Invictus IR Sigma-AWS

- **Source:** <https://github.com/invictus-ir/Sigma-AWS>, directory `CloudTrail/`,
  pinned to commit `f0d55993fb575f747cee13069adeaa999c940b14` (2023-07-12, the
  latest commit when checked on 2026-10-13).
- **What it is:** CloudTrail logs from a lab account in which all AWS attack
  techniques of [Stratus Red Team](https://stratus-red-team.cloud/) available at
  the time were run (the README says 27 techniques). The 55 files are ordinary
  CloudTrail delivery files. All 2,900 events are in `us-east-1`, have
  `recipientAccountId` `123837392027`, and fall between 2023-07-10 11:42 and
  12:37 UTC.
- **Format:** `{"Records": [...]}` JSON, uncompressed.
- **License:** MIT, Copyright (c) 2023 Invictus Incident Response.
- **Integrity:** every file was checked against its git blob SHA-1 in the tree
  of the pinned commit before its SHA-256 was pinned.
- **Mirror:** <https://github.com/invictus-ir/aws_dataset> contains the same 55
  files (identical git blob hashes). The Sigma-AWS repository is used because it
  documents how the data was generated.
- **Caveats:**
  - **Not labelled by technique.** Neither the files nor the README map events to
    techniques. What the data offers: 1,146 of the 2,900 events (40%) carry a
    `stratus-red-team_<uuid>` token in `userAgent`, with 83 distinct UUIDs. Per
    the Stratus source, a UUID is either one CLI command's credential check or
    one technique execution (Terraform warm-up plus detonation, or a revert).
    The labels derived from that, with the method, are in
    [`labels/`](../labels/README.md).
  - **Mostly setup and background.** Of the 1,754 untagged events, 1,006 come
    from Terraform: the clean-up (`terraform destroy`), which Stratus runs
    without its user agent; the warm-up is tagged. 418 are `AWS Internal`; the
    rest are AWS service principals, console and SDK calls.
  - **Lab data.** One short session in a clean account: much cleaner and denser
    than production logs, and no benign baseline to speak of.
  - **Snapshot of 2023.** Stratus techniques added later are not covered.
  - **File names disagree with the events.** The file names carry account ID
    `218007301253`, every event says `123837392027`. The source does not explain
    this, so file names are not used as metadata; the events are authoritative.

## Splunk attack_data (optional)

- **Source:** <https://github.com/splunk/attack_data>, pinned to commit
  `eac2f8f675ec31a6618003399dcc53641524e673` (2026-10-13). Files are Git LFS
  objects, downloaded via `media.githubusercontent.com` at that commit.
- **What it is:** a large collection of attack datasets for many log sources,
  organised as `datasets/attack_techniques/<ATT&CK ID>/<scenario>/`, each scenario
  described by a YAML file. A small part of it is raw CloudTrail.
- **Selection:** a file is included if its descriptor declares sourcetype
  `aws:cloudtrail` (both descriptor schemas in the repository are handled) and
  every record has `eventID`, `eventName`, `eventSource` and `eventTime`.
  Byte-identical duplicates are kept once. Of 62 candidates, 49 files are
  included; the 13 excluded files are listed in the lock with their reason:
  7 Splunk search exports (`{"preview", "result"}` wrappers), 2 Splunk risk-event
  logs, 2 paths named in a descriptor but absent from the repository, 1 Amazon
  Security Lake (OCSF) file, and 1 duplicate (`T1562.007/aws_delete_acl` is
  byte-identical to `T1562.007/aws_create_acl`).
- **On disk:** `data/raw/splunk_attack_data/<path below datasets/>`, so the
  ATT&CK ID and scenario stay visible in the path. The manifest also records the
  technique list and the descriptor of every file.
- **Format:** **not** the CloudTrail delivery layout: 44 files are NDJSON (one
  event per line) and 5 contain a single JSON event. `ctinv.reader` reads both.
- **License:** Apache-2.0.
- **Integrity:** every download was checked against the SHA-256 and size in its
  Git LFS pointer at the pinned commit.
- **Caveats:**
  - **Labels are Splunk's.** The technique comes from the scenario's
    `mitre_technique` field, or from its directory name for older descriptors.
    They are used as given and need a review before they count as ground truth.
    One file (`suspicious_behaviour/abnormally_high_cloud_instances_launched`)
    has no technique label.
  - **Curated extracts.** Most scenarios contain only the few events of the
    attack itself (27 of the 49 files have fewer than 10 events), with no
    surrounding benign activity. Detecting them says little about false
    positives. A few files are large (up to 13,274 events). The 49 files cover
    27 distinct technique labels.
  - **Mixed origins.** 39 of the 49 files come from Splunk's Attack Range lab; the
    rest are labelled `NA`, `custom` or `aws_ec2_test_instance` in their
    descriptors.
