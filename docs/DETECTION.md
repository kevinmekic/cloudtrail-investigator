# Detection rules

`ctinv detect` runs detection rules over the `events` table of a database
created by `ctinv ingest` and writes the results to the `findings` table.

```bash
ctinv detect --db data/ctinv.duckdb                       # all built-in rules
ctinv detect --db data/ctinv.duckdb --rule root-account-usage
ctinv detect --db x.duckdb --rules-dir my-rules/          # rules from another directory
ctinv detect --db data/ctinv.duckdb --set discovery-burst.min_apis=30   # change a threshold
```

`--set RULE.PARAMETER=VALUE` (repeatable) changes a parameter a rule declares
for one run. The value must have the type of the rule's default (integer,
number, `true`/`false` or text); unknown rules or parameters are rejected. The
values used and the changed ones are recorded per run in `rule_runs`
(`parameters`, `overrides`), next to the SHA-256 of the rule file.

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
of the ATT&CK v20.0 entries the rules use (`tests/attack_v20_rule_techniques.json`,
written by `scripts/build_attack_snapshot.py` from the same hash-pinned bundle
as `labels/sources.json`): the technique must be active, its name must match,
the tactics must be ones ATT&CK lists for it, and each former ID must have been
revoked in favour of it. A rule with a technique that is not in the snapshot
fails the test until the script is re-run.

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
| `access-denied-spike` | medium | T1580 Cloud Infrastructure Discovery | Discovery |
| `admin-policy-attached` | high | T1098.003 Account Manipulation: Additional Cloud Roles | Persistence, Privilege Escalation |
| `cloudtrail-tampering` | high | T1685.002 (formerly T1562.008) Disable or Modify Tools: Disable or Modify Cloud Log | Defense Impairment |
| `console-login-without-mfa` | medium | T1078.004 Valid Accounts: Cloud Accounts | Initial Access |
| `credentials-created-for-other-user` | medium | T1098.001 Account Manipulation: Additional Cloud Credentials | Persistence, Privilege Escalation |
| `discovery-burst` | low | T1580 Cloud Infrastructure Discovery | Discovery |
| `new-region-activity` | medium | T1535 Unused/Unsupported Cloud Regions | Stealth |
| `root-account-usage` | medium | T1078.004 Valid Accounts: Cloud Accounts | Initial Access, Privilege Escalation |
| `snapshot-or-image-shared` | high | T1537 Transfer Data to Cloud Account | Exfiltration |

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
- **Sharing** of EBS snapshots, AMIs and RDS DB or cluster snapshots is
  reported when the call adds another account, an organization or everyone
  (public); removals and the account's own ID are ignored.

## Behavioural rules

`discovery-burst`, `access-denied-spike` and `new-region-activity` judge an
identity's behaviour over time instead of single calls. They share these
conventions.

**Who is an identity.** The macro `ctinv_actor` gives the identity's ARN, or for
callers without one (principals of other accounts) `<accountId>:<principalId>`.
It returns nothing, so the call is not counted, when AWS made the call (identity
type `AWSService`, or `invokedBy` set: a service acting for the principal, such
as CloudFormation or AWS Config), for anonymous callers (all anonymous requests
share one `ANONYMOUS_PRINCIPAL`, which would lump the whole internet together),
and when the record names no principal. Calls without an access key (root
console sessions, for example) are counted like any other. Each AssumedRole
session is its own identity, except in `new-region-activity`, which tracks the
role (`sessionIssuer`) because sessions are short-lived and have no history.

**Time.** Windows and baselines use `eventTime` only, never the order of the
records in the files (CloudTrail files are not ordered). `eventTime` has
one-second resolution; window frames include every call with the same
timestamp, so ties never depend on order. A tested case reverses the input
order and gets the same findings.

**Windows and merging.** The two burst rules look at the window of
`window_seconds` that ends at each counted call. Every window that reaches the
threshold belongs to a burst, and overlapping windows are merged, so one
enumeration run is one finding. Its evidence is every counted call of the
identity from the start of the first window to the end of the last. A higher
threshold can produce more findings than a lower one, because fewer windows
qualify and long runs split into several bursts (see the results below).

**Read calls by name.** A read (discovery) call is one whose API name starts
with `List`, `Describe` or `Get` (macro `ctinv_is_list_describe_get`). The
`readOnly` field cannot be used: it is missing in 95.8% of the flaws.cloud
events (all event versions up to 1.05 lack it in most events). Where both are
present, the prefix agrees with `readOnly` for 49,278 of 50,919 flaws.cloud
events (96.8%) and 2,607 of 2,900 Invictus events (89.9%). Known gaps:

- Read calls without these prefixes are missed: `LookupEvents` (most of the
  1,633 flaws.cloud disagreements), `Search*`, `BatchGet*`, `Head*`, `Scan`,
  `Query`, `Simulate*Policy`, `Generate*Report`, and calls that CloudTrail
  marks read-only although they use keys (`kms:Decrypt`, `kms:Encrypt`,
  `kms:GenerateDataKey`, most of the 293 Invictus disagreements).
- Some prefixed calls change state or read secrets: 8 flaws.cloud events
  marked not read-only (`securityhub:GetEnabledStandards`, `ram:List*`,
  `dynamodb:ListContributorInsights`), and calls such as `GetSessionToken`,
  `GetFederationToken`, `GetSecretValue` and `GetPasswordData`.
- `readOnly` is not reliable either: flaws.cloud has API Gateway `Delete*` and
  `Create*` calls marked read-only, and Invictus has `AssumeRole` marked
  read-only.

**Permission errors.** `access-denied-spike` counts error codes whose meaning
the AWS API references state (macro `ctinv_is_access_denied`): `AccessDenied`,
`AccessDeniedException`, `UnauthorizedOperation` (EC2, logged as
`Client.UnauthorizedOperation`), and the SNS codes `AuthorizationError` and
`NotAuthorized`. Codes seen in flaws.cloud whose meaning is not documented
(`ForbiddenException` of MediaLive, 509 events; `AuthorizationFailure` of
SimpleDB, 21 events) and the EC2 code `Client.AuthFailure`, which also means
invalid credentials, are not counted.

**Thresholds** are rule parameters and can be changed per run with `--set`:

| Rule | Parameter | Default | Why this default |
|---|---|---:|---|
| `discovery-burst` | `window_seconds` | 300 | Enumeration tools finish a pass within minutes; a short window keeps slow manual work out. |
| `discovery-burst` | `min_apis` | 20 | Different read APIs, not calls, so polling one API never counts. People rarely call 20 different read APIs in five minutes by hand; on flaws.cloud, 10 nearly triples the root console findings (30 to 84) without adding an identity. |
| `access-denied-spike` | `window_seconds` | 300 | As above. |
| `access-denied-spike` | `min_denied` | 20 | Normal software calls what it is allowed to; 20 denials in five minutes is far above a retry. The Stratus Red Team technique `ec2-get-password-data` (29 denied calls in three seconds) is found at 20 but not at 50. |
| `new-region-activity` | `baseline_days` | 7 | An identity's first week is its baseline, so weekly jobs establish their regions before anything counts as new. |
| `new-region-activity` | `count_read_calls` | false | Enumeration tools read in every region; counting reads would turn each sweep into new regions and would let a sweep hide a later write in the same region. |

**Impossible travel is not implemented.** It needs an offline GeoIP database.
The free options checked in October 2026 either need an account and licence
key (MaxMind GeoLite2, IPinfo Lite, which is also country-level only) or a
click-through licence (DB-IP Lite, CC BY 4.0, 121 MB MMDB that needs an extra
reader library, or a 661 MB CSV). None of the available data could validate the
rule: flaws.cloud IP addresses are anonymised, the Invictus data comes from one
lab session, and the held-out test set may not be used for development. A
database of today also places old IP addresses wrongly, because address blocks
move between owners over the years.

## Writing rules

Notes from writing the built-in rules in DuckDB SQL:

- Helpers that several rules need are SQL macros in `src/ctinv/macros.py`, not
  Python functions: DuckDB's Python functions require `numpy`, which the project
  does not otherwise need.
- Parenthesise JSON extractions next to operators:
  `(request_parameters->>'userName') IN (SELECT ...)` works, while the same
  expression without parentheses fails with a cast error.
- Lambdas use the Python-style syntax `lambda x: ...`; the arrow form clashes
  with the JSON `->` operator.
- An untyped `NULL AS principal` is fine: the framework casts the three output
  columns to their types.
- Every declared parameter must be used in the query (DuckDB rejects unused
  named parameters), and parameters work inside window frames, for example
  `RANGE BETWEEN to_seconds($window_seconds) PRECEDING AND CURRENT ROW`.
- Big findings are fine: the framework aggregates evidence per finding, so a
  finding with tens of thousands of evidence events costs no more than many
  small ones.

## Results on flaws.cloud

On the 1,225,784 unique flaws.cloud events (2017-02-12 to 2020-10-07), with
default parameters:

| Rule | Findings | Evidence events | Outcome |
|---|---:|---:|---|
| `access-denied-spike` | 540 | 287,297 | 540 failed |
| `admin-policy-attached` | 1 | 1 | 1 succeeded |
| `cloudtrail-tampering` | 3 | 3 | 2 failed, 1 succeeded |
| `console-login-without-mfa` | 1 | 1 | 1 succeeded |
| `credentials-created-for-other-user` | 10 | 10 | 10 succeeded |
| `discovery-burst` | 332 | 178,272 | 305 partly failed, 24 succeeded, 3 failed |
| `new-region-activity` | 15 | 3,485 | 14 failed, 1 succeeded |
| `root-account-usage` | 69 | 9,453 | 45 partly failed, 24 succeeded |
| `snapshot-or-image-shared` | 37 | 37 | 34 failed, 3 succeeded |

The data has no ground truth, so the following is an interpretation of the
findings, not a measured false-positive rate. According to the dataset's
description, the account's only legitimate user worked mostly as root, and the
IAM users `backup` and `Level6` are used by the challenge levels (players obtain
their credentials). The challenge also runs an EC2 instance
(`i-aa2d3b42e5c6e801a`) whose role credentials players can obtain; its sessions
appear as `assumed-role/flaws/i-aa2d3b42e5c6e801a` and
`assumed-role/aws:ec2-instance/i-aa2d3b42e5c6e801a`.

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
- `snapshot-or-image-shared`: the 3 successful calls are root making three EBS
  snapshots public in February 2017, which is how one challenge level works.
  The 34 failed calls come from `backup`: players trying to share a snapshot
  with their own accounts (or with everyone), denied or invalid.
- `new-region-activity`: all but one finding come from the shared challenge
  identities, mostly failed `RunInstances` and `CreateDefaultVpc` calls of
  players trying to start instances. Two of them show the "new AWS region"
  false positive: on 2019-09-30, `backup` and `Level6` reached `eu-north-1`
  (launched by AWS in December 2018) within one minute of each other, during
  runs that touched every region. The one successful finding is root creating
  and deleting CloudFormation stacks in `us-east-1` (2018-08-05), its first
  non-read activity in that region.

The two burst rules are the noisy ones. Their three identities with the most
findings:

| Rule | Identity | Findings | Evidence events |
|---|---|---:|---:|
| `discovery-burst` | `user/Level6` | 166 | 93,995 |
| `discovery-burst` | `user/backup` | 96 | 50,792 |
| `discovery-burst` | `root` | 30 | 4,305 |
| `access-denied-spike` | `user/backup` | 316 | 151,708 |
| `access-denied-spike` | `user/Level6` | 187 | 119,248 |
| `access-denied-spike` | `assumed-role/flaws/i-aa2d3b42e5c6e801a` | 27 | 13,922 |

Of the 332 discovery bursts, 281 come from the four challenge identities
(players running enumeration tools, which in this dataset is attack activity),
30 from root, each of them with console calls in its evidence (3,137 of the
4,305 evidence events have a console user agent), and 21 from security scanners
running under their own roles (Security Monkey 19, Cloudsploit 1, an audit role
1). Of the 540 permission spikes, 533 come from the challenge identities; the
rest are another account probing S3 buckets (4 and 2 findings from two
principals) and the Security Monkey set-up user retrying `sts:AssumeRole` (1).

How the counts move with the thresholds (findings on flaws.cloud, distinct
identities in brackets):

| Rule | Parameter | Values and findings |
|---|---|---|
| `discovery-burst` | `min_apis` | 10: 605 (9) · **20: 332 (9)** · 30: 240 (7) · 50: 162 (4) |
| `access-denied-spike` | `min_denied` | 10: 623 (11) · **20: 540 (7)** · 50: 340 (6) · 100: 354 (4) |
| `new-region-activity` | `baseline_days` | 1: 16 (5) · **7: 15 (5)** · 30: 11 (5) |
| `new-region-activity` | `count_read_calls` | **false: 15 (5)** · true: 28 (7) |

Raising `min_apis` removes root's console sessions and the scanners before it
removes any challenge identity, which supports reading the discovery bursts of
the challenge identities as tool runs. `access-denied-spike` is dominated by
the shared challenge users at every threshold: these identities are attacked
by many players over three and a half years, so the count reflects how often
they were probed rather than threshold noise.

Running all nine rules over this database (flaws.cloud and Invictus, 1,228,684
events) took 8.0 seconds with a peak memory of 0.83 GB.
