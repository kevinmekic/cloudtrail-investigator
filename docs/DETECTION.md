# Detection rules

`ctinv detect` runs detection rules over the `events` table of a database
created by `ctinv ingest` and writes the results to the `findings` table.

```bash
ctinv detect --db data/ctinv.duckdb                       # all built-in rules
ctinv detect --db data/ctinv.duckdb --rule root-account-usage
ctinv detect --db x.duckdb --rules-dir my-rules/          # rules from another directory
```

## Rule files

Each rule is one YAML file in `src/ctinv/rules/`, named after its `id`. It
holds the metadata next to the logic:

```yaml
id: cloudtrail-tampering            # lowercase words joined by "-"; the file name
title: CloudTrail logging stopped, deleted or reduced
severity: high                      # low | medium | high | critical
attack:
  technique: T1685.002              # MITRE ATT&CK Enterprise v20.0
  name: "Disable or Modify Tools: Disable or Modify Cloud Log"
  formerly: [T1562.008]             # pre-v19 ID(s) this technique replaced
  tactics: [defense-impairment]     # v20.0 tactic short names
description: What the rule finds.
rationale: Why it matters, and why these tactics.
false_positives: [Known benign causes.]
known_gaps: [What the rule does not see.]   # optional
parameters: {}                      # optional: values the query reads as $name
query: |
  SELECT ... AS principal, ... AS summary, [event_id] AS evidence_event_ids
  FROM events WHERE ...
```

Rules are YAML plus SQL rather than Python classes because the logic then runs
inside DuckDB over the whole table at once (the five rules below take about two
seconds on 1.2 million events), the metadata and the logic are reviewed
together in one file, and adding a rule needs no code. Checks that are awkward
in SQL are defined once as DuckDB macros in `src/ctinv/macros.py`, for example
`ctinv_grants_full_admin(policy_document)`, with their own tests.

ATT&CK IDs are those of Enterprise v20.0. Where v19 (April 2026) replaced an ID
that public content such as SigmaHQ or Stratus Red Team still uses, the rule
lists the old one under `formerly`, and output shows both, for example
"T1685.002 (formerly T1562.008)". A test checks every rule against a snapshot
of ATT&CK v20.0 (`labels/sources.json`): the technique must be active, its name
must match, the tactics must be ones ATT&CK lists for it, and each former ID
must have been revoked in favour of it.

## Findings and evidence

The query returns one row per finding with exactly three columns: `principal`
(who the finding is about, may be NULL), `summary` (one line) and
`evidence_event_ids` (the eventIDs it is derived from). The framework derives
the rest from the evidence events: `first_seen`, `last_seen`, the `outcome`
(`succeeded`, `failed` if every evidence event has an error code, otherwise
`partly failed`), the `datasets`, and a `finding_id` that stays the same as
long as rule and evidence do.

**A finding without evidence cannot exist.** The framework rejects a rule run
that returns an empty evidence list, an eventID that is not in the database, or
two findings with the same evidence. The `findings` table has a CHECK
constraint on non-empty evidence. All rules run in one transaction: if any rule
fails, nothing changes. Each run is recorded in `rule_runs` with the SHA-256 of
the rule file and its parameters.

## Built-in rules

| Rule | Severity | ATT&CK v20.0 | Tactics |
|---|---|---|---|
| `admin-policy-attached` | high | T1098.003 Account Manipulation: Additional Cloud Roles | Persistence, Privilege Escalation |
| `cloudtrail-tampering` | high | T1685.002 (formerly T1562.008) Disable or Modify Tools: Disable or Modify Cloud Log | Defense Impairment |
| `console-login-without-mfa` | medium | T1078.004 Valid Accounts: Cloud Accounts | Initial Access |
| `credentials-created-for-other-user` | medium | T1098.001 Account Manipulation: Additional Cloud Credentials | Persistence, Privilege Escalation |
| `root-account-usage` | medium | T1078.004 Valid Accounts: Cloud Accounts | Initial Access, Privilege Escalation |

What each rule matches, why, its known false positives and its gaps are in the
rule file. Points worth knowing:

- **Failed attempts count.** Tampering, credential and admin-grant rules also
  report calls that failed (outcome `failed`): trying is a signal. Denied calls
  often have no request parameters in CloudTrail, so their target may be
  unknown ("target not logged") or, for the credential and admin rules, not
  evaluable at all.
- **Root activity is grouped per account and UTC day**, so one session is one
  finding with all its calls as evidence. Calls an AWS service made for root
  (`invokedBy`, for example AWS Support) are not counted.
- **Console sign-in without MFA** reads `additionalEventData.MFAUsed` on the
  `ConsoleLogin` event. Federated sign-ins (`AssumedRole`) are excluded because
  their MFA happens at the identity provider.
- **Trail buckets** for the lifecycle check are learnt from the data: buckets
  named in successful `CreateTrail`/`UpdateTrail` calls or accessed by the
  CloudTrail service.

## Results on flaws.cloud

On the 1,225,784 unique flaws.cloud events (2017-02-12 to 2020-10-07):

| Rule | Findings | Evidence events | Outcome |
|---|---:|---:|---|
| `admin-policy-attached` | 1 | 1 | 1 succeeded |
| `cloudtrail-tampering` | 3 | 3 | 2 failed, 1 succeeded |
| `console-login-without-mfa` | 1 | 1 | 1 succeeded |
| `credentials-created-for-other-user` | 10 | 10 | 10 succeeded |
| `root-account-usage` | 69 | 9,453 | 45 partly failed, 24 succeeded |

The data has no ground truth, so the following is an interpretation of the
findings, not a measured false-positive rate. According to the dataset's
description, the account's only legitimate user worked mostly as root, and the
IAM users `backup` and `Level6` are used by the challenge levels (players obtain
their credentials).

- `cloudtrail-tampering`: the two failed calls (`UpdateTrail` in 2017,
  `StopLogging` in 2019) come from `Level6`: attempted tampering by players,
  stopped by the account's permissions. The successful `DeleteTrail`
  (2019-08-23) is root deleting the original trail, which ends the period of
  duplicated records.
- `credentials-created-for-other-user`: root creating access keys for the
  challenge users and for other IAM users, and one IAM user creating a key for
  `backup`. Everything points to account administration by the owner, the
  false-positive source the rule documents for small accounts.
- `admin-policy-attached` and `console-login-without-mfa`: root gave the IAM
  user `piper` AdministratorAccess, a console password and an access key
  within one second; the same day, `piper` signed in without MFA. That reads
  as setting up an administrator user, and the sign-in without MFA is a real
  weakness rather than an attack.
- `root-account-usage`: 69 days of root activity, 42 of them in 2017, the year
  the challenge was launched, matching the description of the owner's habit.

Running all five rules over this database (flaws.cloud and Invictus, 1,228,684
events) took 2.4 seconds with a peak memory of 0.69 GB.
