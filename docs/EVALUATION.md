# Evaluation

`ctinv evaluate` measures how many attack techniques the built-in detection
rules detect in labelled CloudTrail data, per technique and always with the
denominator. It reports two datasets separately and never adds them up:

| Dataset | Role | Unit | Ground truth |
|---|---|---|---|
| Splunk attack_data (49 CloudTrail files) | **held-out test set**, the primary result | ATT&CK v20.0 technique | Splunk's own technique label per scenario file (`labels/splunk_labels.json`), reviewed before the rules ran on it (`evaluation/splunk_label_review.yml`) |
| Invictus IR Sigma-AWS (2,900 events) | development set, **optimistic**: the rules were written on it | Stratus Red Team technique | technique and role of every event, derived from Stratus Red Team's source code before any rule existed (`labels/invictus_labels.json`) |

A third, separate part draws a random sample of findings on flaws.cloud for
manual review. flaws.cloud has no ground truth and the test set has almost no
benign activity, so there is **no measured false-positive rate**; the sample is
reported as a manually reviewed sample and nothing else.

```bash
# Test set and development set (the test set needs the optional Splunk download)
ctinv evaluate
ctinv evaluate --only development

# Manual review sample: the database needs a current `ctinv detect` run
ctinv evaluate --db data/ctinv.duckdb --only review --init-review   # writes evaluation/fp_review.yml
ctinv evaluate --db data/ctinv.duckdb                                 # all three parts
```

Results go to `results/evaluation-<UTC time>.md` and `.json` (git-ignored); with
`--db`, also `results/evaluation-<UTC time>-review-sheet.md`, the context of
every sampled finding for the reviewer.

## The rule set under evaluation

The rules were frozen before any test-set event content was opened: git tag
**`rules-frozen-for-eval`** on commit `85cc462`. The evaluation always runs the
built-in rules with their default parameters (there is no `--set` or
`--rules-dir`), and the results record the SHA-256 of every rule file and of
the modules that decide which findings exist (`reader.py`, `normalize.py`,
`schema.py`, `ingest.py`, `macros.py`, `detect.py`), so a result can be matched
to the code that produced it.

| Rule file | SHA-256 at the tag |
|---|---|
| `access-denied-spike.yml` | `66f4681dca9a873a…` |
| `admin-policy-attached.yml` | `19869338ffd69843…` |
| `cloudtrail-tampering.yml` | `dfe18c930919ac53…` |
| `console-login-without-mfa.yml` | `bcdc629b830d3f32…` |
| `credentials-created-for-other-user.yml` | `106f80c542e62ce0…` |
| `discovery-burst.yml` | `c58df009d5294e8f…` |
| `new-region-activity.yml` | `2da6415e31e0fd71…` |
| `root-account-usage.yml` | `8059f13f4ba94f4c…` |
| `snapshot-or-image-shared.yml` | `7691a3f64cdc8035…` |

The order of work was fixed so that no decision about the test set could be
influenced by the rules' results on it:

1. Rules frozen (the tag above).
2. Evaluation code and this method committed, before any test-set event
   content was opened.
3. Test-set labels reviewed against the event content, and every file's scope
   decided, without running any rule on the test set; the review committed,
   together with the handling of reused eventIDs found while reading the
   content (see below).
4. Only then the evaluation run.

**Changes after the freeze.** One change was made after the frozen run: a bug
fix in how a call's outcome is decided (failed sign-ins counted as succeeded).
It changes `root-account-usage.yml`, `macros.py` and `detect.py`. The results
of the frozen rule set stay the primary result; the run after the fix is
reported separately in "Post-freeze result" below.

**Separately reported rule parts.** No rule was added or materially changed
after the rule set was fixed.
`snapshot-or-image-shared` also covers RDS DB and cluster snapshots made usable
by other accounts, beyond the two EC2 APIs (snapshot and image attributes) it
was specified for. That part was decided while the rule was written, from the
AWS API surface and a Stratus Red Team technique (`rds-share-snapshot`), not
from the test set's technique list. A technique detected only through it is
marked, and every rate is also given without such detections.

## Ground truth per technique

**Test set.** Each scenario file carries the technique ID(s) Splunk states for
it: from the descriptor field `mitre_technique` (35 files) or, for older
descriptors without that field, from the directory name (14 files); which one
is recorded per file as `technique_source` in `labels/splunk_labels.json` and
shown in the results. IDs revoked in ATT&CK v19 are normalised to their v20.0
successors and shown with the former ID, e.g. "T1685.002 (formerly
T1562.008)". One file states two techniques and counts for both; one file
states none.

**Development set.** Each event has a role (`attack`, `warm-up`, `preflight`,
`revert`, `clean-up`, `side-effect`, `background`) and, where it belongs to one,
a Stratus technique. Techniques are reported by their Stratus ID (e.g.
`aws.defense-evasion.cloudtrail-stop`). ATT&CK IDs are shown only where Stratus
Red Team or the AWS Threat Technique Catalog states one and it exists in ATT&CK
v20.0; 14 of the 26 detonated techniques have none.

Ground truth never comes from rule output.

## Method

### Isolation

Each test-set scenario file is ingested into its own in-memory database, and
the rules run on that file alone. A finding can therefore only rest on events
of the scenario it is counted for, and scenarios recorded at different times
in different accounts are not mixed. Consequences: a burst split over two files is not combined, and
`new-region-activity`, which needs a seven-day history of an identity, cannot
fire on a single short scenario. The development set is one lab session and
runs as one database. Every file's SHA-256 is checked against the manifest and
the label file before it is read, and every file's record count against the
label file.

### Unit of analysis

The unit is the **technique**, not events, findings, runs or files. Several
scenario files or Stratus runs of one technique (e.g. three `cloudtrail-stop`
detonations) are not independent samples and give one result.

- **Test set:** the headline counts a technique as detected if a rule mapped
  to that ATT&CK technique (or its parent or sub-technique; siblings do not
  count) fired in at least one of its in-scope scenario files. Next to it come
  "any finding in the scenario" (any rule fired in at least one in-scope file)
  and that rate with every excluded technique counted as missed. A rule can fire
  on a scenario for an unrelated reason (e.g. root activity in a scenario about
  something else), so the technique-matched rate is the one that says whether
  the rules recognise the technique. This order was set after the first run; the
  method first named "any finding" the main result. All three numbers come from
  that same frozen run, and the headline is the lowest of them. The results
  also show how many of a technique's files were detected and how many
  techniques had every in-scope file detected.
- **Development set:** a technique is detected if at least one finding has an
  evidence event with role `attack` for that technique. Strict variant: only
  attack events marked `"documented": true` (calls the technique's source
  names) count, not the role assumptions on the detonation path.

### Findings that are neither true nor false positives (development set)

- Evidence only on lab scaffolding (`warm-up`, `preflight`, `revert`,
  `clean-up`, `side-effect`): counted neither as true nor as false positive,
  reported as a number.
- Evidence on `background` events (operators, consoles, AWS-internal calls) and
  no attack event: reported as "unlabelled background", not as false
  positives; nothing guarantees that background activity is benign.
- Failed attempts are in scope: three techniques (`cloudtrail-stop`,
  `cloudtrail-delete`, `ec2-enumerate-from-instance`) failed on every attack
  call, and "detected" and "attempt failed" are shown side by side.

### Classification

Every technique is **detected**, **missed**, **out of scope by design** or
**label ambiguous**, the last two with a reason. Only detected and missed
techniques form the denominator. The criteria were written down before the
test-set content was opened:

- **Out of scope by design** when (a) the labelled activity is recorded only as
  CloudTrail data events (`eventCategory: Data`, e.g. S3 object reads), while
  the tool covers management events; (b) detecting it needs something the
  project ruled out, i.e. geolocation of source addresses (see "Considered but
  not built" in `docs/DETECTION.md`); or (c) the data contains no attack, as in
  the development set's `ec2-user-data`, which was never detonated (its
  warm-up failed).
- **Label ambiguous** when the scenario file has no technique label, or its
  events do not contain the labelled technique's activity at all, judged
  against the technique's ATT&CK v20.0 description. A plausible but debatable
  choice of ID (e.g. a parent technique where a sub-technique would fit) is
  kept as Splunk states it, with a note.
- **Not reasons for exclusion:** that no rule targets the technique, that the
  attack failed, or that a rule could only see it across several files. These
  are misses.

A technique counts if at least one of its files is in scope; only its in-scope
files are then evaluated. Rules that fire on excluded files are listed, but
those findings do not count.

To show how much the exclusions matter, every test-set result also states the
rate with every excluded technique counted as missed.

### Label review of the test set

Done on 2026-10-16 after the content of every scenario file was read and before
any rule ran on the test set; every file's status, a description of its
content and the reason for each exclusion are in
`evaluation/splunk_label_review.yml`, and the results record that file's
SHA-256.

- 38 files in scope, 2 out of scope (S3 data events only:
  `s3_file_encryption`, `aws_exfil_high_no_getobject`), 8 with a label that
  does not match their content, 1 without a label.
- At technique level, 4 of the 27 labelled techniques have no file left and are
  marked "label ambiguous": T1087.004 (one denied `bedrock:InvokeModel`),
  T1110.002 (an RDS master password reset), T1204 (Lambda code updated through
  the API) and T1586.003 (sign-ins to the target's own root user, while
  T1586.003 is about third-party accounts used as adversary infrastructure).
  23 techniques are in scope.
- Four ambiguous files belong to techniques that stay in scope through other
  files (a Bedrock guardrail deletion under T1685.002, a bucket ACL change under
  T1530, reading image scan results under T1204.003, two syntactically invalid
  policies under T1580).
- Debatable but plausible labels are kept as Splunk states them, with a note:
  e.g. T1078 for creating access keys or login profiles (T1098.001 would fit
  better), T1110.003 for many attempts against two user names (brute force
  rather than spraying).

### Reused eventIDs in the test set

This was decided after the test-set content was read and before any rule ran
on it, because the method above did not foresee it. CloudTrail gives every
event its own ID, but 12 test files repeat eventIDs. Most repeats are identical
records, which ingest counts as duplicates. In 6 files, records that differ
share an eventID: variants made by copying a record and changing the user
name, the time or a policy document. For example, all 31 sign-ins of a
password-spraying scenario have one eventID. Ingest keeps the first record of
an eventID and quarantines differing repeats; it never drops them silently.
The tool therefore sees fewer events than such a file holds.

The main result is the tool as it is. As a comparison, every file is also
evaluated with each differing repeat given its own eventID
(`<eventID>-variant-<n>`; identical repeats stay duplicates), and every
technique whose result changes is listed.

### Exposed before the split

Before the development/test split existed, while checking whether the Splunk
data was usable, the content of two test-set scenarios was seen: T1201
(`aws_password_policy`, whose API call was visible in a non-CloudTrail sibling
file) and T1204.003 (`aws_ecr_image_scanning`, whose single event was printed).
Both are marked "exposed before the split", and the test-set rate is also given
without them. For six other test files only the top-level field names of their
first record were seen.

### Time to first finding

A batch run cannot tell when a rule's condition was first met, only that it
lies between a finding's first and last evidence event. The results therefore
give two times relative to the attack start: the earliest first evidence event
and the earliest last evidence event over all qualifying findings; the first
alert of a streaming deployment would lie between them. The attack start is
the first `attack` event of the technique (development set) or the first event
of the scenario file (test set, which has no event-level labels). Negative
values mean that a finding's evidence begins before the attack, e.g. with lab
set-up calls.

### Further variants

Each result also states the rate without separately reported rule parts. On
the development set, the rate by a rule mapped to the technique's stated
ATT&CK ID is a variant, not the headline, because only 12 of the 26 detonated
techniques have such an ID.

### Manual review sample (flaws.cloud)

Per rule, up to N findings (default 10; all of them if a rule has fewer) are
drawn from a database on which `ctinv detect` ran with the built-in rules and
default parameters (checked against `rule_runs`). The order is
`sha256("<seed>:<finding_id>")`, which is reproducible and independent of any
random number generator; a smaller sample is a prefix of a larger one.

**Labels proposed by the tool author's assistant, each reviewed and decided by
a human.** For every sampled finding, `evaluation/fp_review.yml` holds a
proposal (`proposed_label`) with a one-line reason (`proposed_reason`) based
only on CloudTrail events: the finding's evidence (API calls, errors, user
agents, whether the session was MFA-authenticated) and, where it was needed,
other events of the same identity or source address (e.g. that the address of
a root session is used by MFA-authenticated root sessions on other days). No
knowledge about the dataset from outside the logs is used. A finding is
proposed as `unsure` where the evidence does not decide it, instead of
guessing. The human decision goes into `label`, which
the proposal never fills:

| Label | Meaning |
|---|---|
| `true_positive` | the evidence shows the behaviour the rule describes, and nothing in the logs explains it as expected activity |
| `benign_true_positive` | the evidence shows that behaviour, but it is expected activity (e.g. the account owner's administration, a known scanner) |
| `false_positive` | the evidence does not show the behaviour the rule describes |
| `unsure` | the logs do not allow a decision |

`ctinv evaluate --db` reports, per rule and in total, the decided labels and how
many decisions differ from the proposal ("proposals changed"). It refuses to
summarise a review file whose findings the database no longer yields exactly.

## Results (2026-10-16)

`ctinv evaluate` with the rules at `rules-frozen-for-eval`: 28 s, peak memory
0.35 GB for both sets. A second run gave identical results apart from the
timestamp. The development set gave exactly the same 22 findings (same IDs) in
its own database as in a database shared with flaws.cloud.

### Test set (held out): 5 / 23 in-scope ATT&CK techniques detected by a rule mapped to the technique

27 techniques are labelled; 4 are excluded as label ambiguous (none as out of
scope by design). The exclusions were committed before the first run and
confirmed unchanged by the project owner afterwards.

| Measure | Detected |
|---|---|
| **By a rule mapped to the technique (or its parent or sub-technique)** | **5 / 23** |
| Any finding in the scenario | 9 / 23 |
| Any finding, excluded techniques counted as missed | 9 / 27 |
| Any finding, without the two techniques exposed before the split | 8 / 21 |
| Any finding, every in-scope file of the technique detected | 6 / 23 |
| Any finding, without separately reported rule parts | 9 / 23 |
| Any finding, every record kept (reused eventIDs made unique) | 9 / 23 |

| ATT&CK v20.0 | Name | Same-technique rule | Any finding | Rules that fired | Files detected | First finding | Note |
|---|---|---|---|---|---|---|---|
| T1021.004 | SSH | no | missed | – | 0 / 1 | – |  |
| T1021.008 | Direct Cloud VM Connections | no | missed | – | 0 / 1 | – |  |
| T1078 | Valid Accounts | yes | detected | `console-login-without-mfa`, `credentials-created-for-other-user` | 2 / 6 | +0 s |  |
| T1078.004 | Cloud Accounts | yes | detected | `console-login-without-mfa`, `root-account-usage` | 1 / 1 | +0 s |  |
| T1087.004 | Cloud Account | – | label ambiguous | – | – | – | no file with a matching label (see the label review) |
| T1098 | Account Manipulation | no | missed | – | 0 / 3 | – |  |
| T1098.003 | Additional Cloud Roles | no | missed | – | 0 / 1 | – |  |
| T1110.001 | Password Guessing | no | missed | – | 0 / 1 | – |  |
| T1110.002 | Password Cracking | – | label ambiguous | – | – | – | no file with a matching label (see the label review) |
| T1110.003 | Password Spraying | no | missed | – | 0 / 2 | – |  |
| T1119 | Automated Collection | no | missed | – | 0 / 1 | – |  |
| T1201 | Password Policy Discovery | no | detected | `root-account-usage` | 1 / 1 | +0 s to +76 min | exposed before the split |
| T1204 | User Execution | – | label ambiguous | – | – | – | no file with a matching label (see the label review) |
| T1204.003 | Malicious Image | no | missed | – | 0 / 1 | – | exposed before the split |
| T1485 | Data Destruction | no | missed | – | 0 / 1 | – |  |
| T1486 | Data Encrypted for Impact | no | missed | – | 0 / 1 | – |  |
| T1526 | Cloud Service Discovery | no | detected | `access-denied-spike`, `discovery-burst` | 1 / 1 | +0 s to +3 min |  |
| T1530 | Data from Cloud Storage | no | missed | – | 0 / 1 | – |  |
| T1537 | Transfer Data to Cloud Account | yes | detected | `snapshot-or-image-shared` | 2 / 2 | +0 s |  |
| T1552 | Unsecured Credentials | no | detected | `access-denied-spike` | 1 / 1 | +0 s to +1 s |  |
| T1555.006 | Cloud Secrets Management Stores | no | missed | – | 0 / 1 | – |  |
| T1578.005 | Modify Cloud Compute Configurations | no | missed | – | 0 / 1 | – |  |
| T1580 | Cloud Infrastructure Discovery | yes | detected | `access-denied-spike`, `discovery-burst` | 2 / 3 | +0 s to +4 min |  |
| T1586.003 | Cloud Accounts | – | label ambiguous | – | – | – | no file with a matching label (see the label review); fired on its excluded file: `console-login-without-mfa`, `root-account-usage` |
| T1621 | Multi-Factor Authentication Request Generation | no | detected | `root-account-usage` | 1 / 1 | +0 s |  |
| T1685.002 (formerly T1562.008) | Disable or Modify Cloud Log | yes | detected | `cloudtrail-tampering` | 3 / 6 | +0 s |  |
| T1686.001 (formerly T1562.007) | Cloud Firewall | no | missed | – | 0 / 1 | – |  |

How to read it (interpretation of the findings' evidence):

- **Five techniques are detected by a rule mapped to them:** T1078 and
  T1078.004 (`console-login-without-mfa`, `root-account-usage`), T1537
  (`snapshot-or-image-shared`), T1580 (the burst and permission-error rules) and
  T1685.002 (`cloudtrail-tampering`).
- **Four more count only as "any finding in the scenario".** T1201 (password
  policy) and T1621 (failed MFA) are found only because those scenarios were
  run as root (`root-account-usage`); T1526 (a security scanner) and T1552
  (`ec2:GetPasswordData`) through the burst and permission-error rules, which
  are mapped to T1580.
- **The T1621 detection rests on failed root sign-ins**, which
  `root-account-usage` counts as root activity. In this frozen result its
  findings report them as succeeded ("0 failed"): CloudTrail records a failed
  console sign-in in `responseElements.ConsoleLogin` ("Failure"), not in
  `errorCode`, and the framework derived a finding's outcome from `errorCode`
  alone. Fixed after the freeze; the post-freeze result below reports these
  findings as failed and changes no rate.
- **14 in-scope techniques are missed.** For 13 of them no rule looks for the
  behaviour in the scenario (SSH keys pushed through EC2 Instance Connect,
  deleted IAM groups and policies, failed console sign-ins, DataSync tasks,
  container images, Bedrock deletions, KMS key policies, CloudWatch Logs reads,
  batch secret retrieval, user-data changes, network ACL entries). T1098.003 has
  a rule (`admin-policy-attached`), but the scenario creates roles trusted by
  other accounts, which that rule does not cover.
- **T1685.002: 3 of 6 in-scope files.** `cloudtrail-tampering` finds the
  `StopLogging`, `DeleteTrail` and `UpdateTrail` scenarios. It misses lifecycle
  rules on buckets that the file never shows as trail buckets (a documented gap:
  a trail bucket is only known from trail calls in the same data), deleted
  GuardDuty detectors, WAF rules and a log stream, and a denied deletion of
  Bedrock model invocation logging.
- **Reused eventIDs** change no result.
- Every detected technique's first evidence is the scenario's first event
  (+0 s). Findings that span many events (bursts, a day of root activity) are
  complete between 1 s and 76 minutes later.

### Development set (optimistic): 15 / 26 in-scope Stratus techniques detected

`ec2-user-data` is out of scope by design (never detonated).

| Variant | Detected |
|---|---|
| **Main result** | **15 / 26** |
| Strict (only documented technique calls count) | 15 / 26 |
| By a rule mapped to the technique's stated ATT&CK ID (techniques with one) | 6 / 12 |
| Without separately reported rule parts (`rds-share-snapshot` is found only by the RDS part) | 14 / 26 |
| Failed attempts detected (every attack call returned an error) | 2 / 3 |

| Stratus technique | ATT&CK v20.0 | Result | Strict | Attempt failed | Rules that fired | First finding |
|---|---|---|---|---|---|---|
| `aws.credential-access.ec2-get-password-data` | – | detected | yes | no | `access-denied-spike` | +5 s to +8 s |
| `aws.credential-access.ec2-steal-instance-credentials` | T1552.005 | detected | yes | no | `discovery-burst` | −2 min to +22 min |
| `aws.credential-access.secretsmanager-retrieve-secrets` | – | detected | yes | no | `discovery-burst` | −3 min to +21 min |
| `aws.credential-access.ssm-retrieve-securestring-parameters` | – | detected | yes | no | `discovery-burst` | −4 min to +20 min |
| `aws.defense-evasion.cloudtrail-delete` | T1685.002 (formerly T1562.008) | detected | yes | yes | `cloudtrail-tampering` | +0 s |
| `aws.defense-evasion.cloudtrail-event-selectors` | T1685.002 (formerly T1562.008) | detected | yes | no | `cloudtrail-tampering` | +0 s |
| `aws.defense-evasion.cloudtrail-lifecycle-rule` | T1685.002 (formerly T1562.008) | detected | yes | no | `cloudtrail-tampering` | +0 s |
| `aws.defense-evasion.cloudtrail-stop` | T1685.002 (formerly T1562.008) | detected | yes | yes | `cloudtrail-tampering` | +0 s |
| `aws.defense-evasion.organizations-leave` | – | missed | no | no | – | – |
| `aws.defense-evasion.vpc-remove-flow-logs` | – | missed | no | no | – | – |
| `aws.discovery.ec2-download-user-data` | – | missed | no | no | – | – |
| `aws.discovery.ec2-enumerate-from-instance` | – | missed | no | yes | – | – |
| `aws.execution.ec2-launch-unusual-instances` | T1578.002 | missed | no | no | – | – |
| `aws.execution.ec2-user-data` | – | out of scope | – | no | – | – |
| `aws.exfiltration.ec2-security-group-open-port-22-ingress` | T1686.001 (formerly T1562.007) | missed | no | no | – | – |
| `aws.exfiltration.ec2-share-ami` | – | detected | yes | no | `snapshot-or-image-shared` | +0 s |
| `aws.exfiltration.ec2-share-ebs-snapshot` | T1578.001 | detected | yes | no | `snapshot-or-image-shared` | +0 s |
| `aws.exfiltration.rds-share-snapshot` | – | detected (RDS part only) | yes | no | `snapshot-or-image-shared` | +0 s |
| `aws.exfiltration.s3-backdoor-bucket-policy` | – | missed | no | no | – | – |
| `aws.initial-access.console-login-without-mfa` | – | detected | yes | no | `console-login-without-mfa` | +0 s |
| `aws.persistence.iam-backdoor-role` | T1098.003 | missed | no | no | – | – |
| `aws.persistence.iam-backdoor-user` | T1098.001 | detected | yes | no | `credentials-created-for-other-user` | +0 s |
| `aws.persistence.iam-create-admin-user` | T1136.003 | detected | yes | no | `admin-policy-attached`, `credentials-created-for-other-user` | +0 s |
| `aws.persistence.iam-create-user-login-profile` | T1098.001 | detected | yes | no | `credentials-created-for-other-user`, `discovery-burst` | −6 min to +0 s |
| `aws.persistence.lambda-backdoor-function` | – | missed | no | no | – | – |
| `aws.persistence.lambda-overwrite-code` | – | missed | no | no | – | – |
| `aws.persistence.rolesanywhere-create-trust-anchor` | – | missed | no | no | – | – |

- 22 findings: 17 rest on attack events, 5 only on lab scaffolding (2 warm-up,
  1 revert, 2 clean-up), none only on background events. The 5 count neither as
  true nor as false positives.
- **Observation after the run, not a variant fixed in advance:** three
  credential-access techniques (`ec2-steal-instance-credentials`,
  `secretsmanager-retrieve-secrets`, `ssm-retrieve-securestring-parameters`)
  count as detected only through one `discovery-burst` finding with 1,337
  evidence events: 60 attack calls, 1,225 lab set-up and clean-up events and 52
  background events. That meets the scoring rule, but the burst is mostly
  Terraform; without these three, 12 / 26.
- The test-set and development-set rates use different units (ATT&CK techniques
  vs. Stratus techniques) and different data; they are not comparable and are
  not combined.

### Manually reviewed sample (flaws.cloud)

**This sample comes from the development data the rules were built on.**
flaws.cloud was used to write the rules and to choose their thresholds, so the
absence of false positives here says little about false positives on data the
rules have not seen. It is a manually reviewed sample, not a measured
false-positive rate, and it has one reviewer.

65 findings were drawn (seed `ctinv-review-1`, up to 10 per rule): all findings
of `admin-policy-attached` (1), `cloudtrail-tampering` (3),
`console-login-without-mfa` (1) and `credentials-created-for-other-user` (10),
and 10 each of the other five rules. Labels proposed by the tool author's
assistant, each reviewed and decided by a human: all 65 are decided.

| Rule | Findings | Sampled | true_positive | benign_true_positive | false_positive | unsure | Proposals changed |
|---|---|---|---|---|---|---|---|
| `access-denied-spike` | 540 | 10 | 10 | 0 | 0 | 0 | 1 |
| `admin-policy-attached` | 1 | 1 | 0 | 1 | 0 | 0 | 0 |
| `cloudtrail-tampering` | 3 | 3 | 2 | 1 | 0 | 0 | 0 |
| `console-login-without-mfa` | 1 | 1 | 0 | 1 | 0 | 0 | 0 |
| `credentials-created-for-other-user` | 10 | 10 | 0 | 10 | 0 | 0 | 0 |
| `discovery-burst` | 332 | 10 | 7 | 3 | 0 | 0 | 1 |
| `new-region-activity` | 15 | 10 | 9 | 1 | 0 | 0 | 0 |
| `root-account-usage` | 69 | 10 | 0 | 10 | 0 | 0 | 0 |
| `snapshot-or-image-shared` | 37 | 10 | 9 | 1 | 0 | 0 | 0 |
| **Total** | | **65** | **37** | **28** | **0** | **0** | **2** |

- **The reviewer changed 2 of the 65 proposals.** Both were the only proposals
  marked `unsure`, and both were decided `true_positive`: 33 denied
  `sts:AssumeRole` calls in 47 s whose requested role is not logged, and a Scout
  Suite scan (590 of 926 calls failed). Both use the `backup` user's key, and
  the logs alone could not decide them. The reviewer used knowledge from
  outside the logs: that key belongs to the dataset's public challenge, so any
  use of it is unauthorised by design. The other 63 proposals were kept.
- **No false positives, but 28 benign true positives.** Every sampled finding
  shows the behaviour its rule describes. 28 of 65 are expected activity (the
  account owner's administration, mostly in MFA-authenticated root console
  sessions, and a monitoring tool's own role) that an analyst would still have
  to look at and close: all 10 sampled `root-account-usage` findings and all 10
  `credentials-created-for-other-user` findings are of this kind.
- flaws.cloud is mostly attack traffic against a public challenge, with little
  ordinary activity, which also limits what the sample can show about noise in
  a normal account.

## Post-freeze result (2026-10-16): failed sign-ins

The frozen result above is the primary result. This section reports one run
after a change to the rule set, next to it.

**What changed and why.** AWS sign-in events (`ConsoleLogin`, `CheckMfa`,
`GetSigninToken`) record a failed attempt as `"Failure"` under the event's own
name in `responseElements`, with an `errorMessage` but without an `errorCode`
(AWS CloudTrail User Guide, "AWS Management Console sign-in events"; IAM User
Guide, "Example sign-in failure event"). The framework derived outcomes from
`errorCode` alone, so failed sign-ins counted as succeeded, in findings,
investigations and reports. The bug was found while checking the test-set
T1621 detection after the frozen run; the fix follows the AWS record format,
not the test set's technique list, and the development data shows the same
pattern (flaws.cloud: 12 failed `ConsoleLogin` and 14 failed `CheckMfa` events,
none with an `errorCode`). A macro, `ctinv_failed`, now decides whether a call
failed, and `root-account-usage` counts failed sign-ins in its summary.

| File | SHA-256 at the tag | SHA-256 after the fix |
|---|---|---|
| `root-account-usage.yml` | `8059f13f4ba94f4c…` | `0e2885b2ff6d72a2…` |
| `macros.py` | `ba43907cf5fb1056…` | `c57c35590826d5ac…` |
| `detect.py` | `4f33699964e78d89…` | `0c2aa2c520fa2ce2…` |

All other rule files and pipeline modules are unchanged.

**Result.** Every rate is the same as in the frozen run:

| Measure | Frozen (primary) | Post-freeze |
|---|---|---|
| Test set: by a rule mapped to the technique | 5 / 23 | 5 / 23 |
| Test set: any finding in the scenario | 9 / 23 | 9 / 23 |
| Test set: any finding, excluded techniques counted as missed | 9 / 27 | 9 / 27 |
| Test set: any finding, without the techniques exposed before the split | 8 / 21 | 8 / 21 |
| Test set: any finding, every in-scope file detected | 6 / 23 | 6 / 23 |
| Test set: any finding, every record kept | 9 / 23 | 9 / 23 |
| Development set: detected | 15 / 26 | 15 / 26 |
| Development set: strict | 15 / 26 | 15 / 26 |
| Development set: by a rule mapped to the stated ATT&CK ID | 6 / 12 | 6 / 12 |
| Development set: failed attempts detected | 2 / 3 | 2 / 3 |

No finding appeared or disappeared (106 findings over both sets, same IDs). The
outcome of three test-set findings, all of `root-account-usage`, changed:

- **T1621** (`aws_failed_mfa`): both findings, with 1 and 2 evidence events,
  changed from succeeded to **failed**. T1621 still counts as "any finding in
  the scenario", and the result now shows that this rests only on failed root
  sign-in attempts.
- **T1586.003** (`aws_console_login_multiple_ips`, an excluded file): one
  finding with 4 evidence events changed from succeeded to partly failed.

On the development database (flaws.cloud and Invictus, 1,030 findings) no
finding changed: same IDs, outcomes and summaries. The manually reviewed
sample is the same 65 findings with the same decisions.

Run: `results/evaluation-20261016T211129Z.*`, 33 s, peak memory 0.33 GB.

Later changes to `schema.py` and `ingest.py` (how a database is opened, and how
ingest reports quarantined records) change no finding: a run after them gave
the same findings, outcomes and rates.

## Limitations

- **The choice of rules was not blind to the test set's techniques.** Splunk's
  file and directory names (e.g. `attack_techniques/T1562.008/...`) reveal
  which techniques the test set covers, and they were visible while the rules
  were chosen. Event content was not opened before the rules were frozen,
  apart from the two exposed scenarios above.
- The test set is small: most techniques have one scenario file, often with
  fewer than ten events. A technique's result rests on one or a few recordings
  of one way to perform it.
- Splunk's scenarios contain almost only attack activity, so they show
  detection, not false positives. The labels are Splunk's: per file, not per
  event, and the attack start is approximated by a file's first event.
- The development set is lab data from a single session and region, cleaner
  than production logs, and the rules were written on it.
- No benign baseline exists yet, so no false-positive rate is measured.
