# Ground-truth labels

Frozen on 2026-10-14, **before any detection rule existed** and without any
detection logic, so the evaluation cannot become circular.

| File | Content |
|---|---|
| `invictus_labels.json` | Invictus Sigma-AWS: every one of the 83 Stratus run IDs and every one of the 2,900 events, with technique, role and justification |
| `splunk_labels.json` | Splunk attack_data: technique labels per file, from Splunk's descriptors only |
| `sources.json` | Snapshot of the external sources the labels are derived from (Stratus technique catalog, ATT&CK lookups, Splunk label provenance) |
| `SHA256SUMS` | Hashes of the three files above; `tests/test_labels.py` fails if any of them changes |

**Frozen means:** these files must not change once detection rules are being
written. A change needs a documented reason in the project log, then an updated
`SHA256SUMS`; the test makes a silent change impossible.

## Dev/test split

Two phrases inside the frozen `splunk_labels.json` are short labels from when
the files were written, kept because the files cannot change: `"held-out test
(ground rule 10)"` means the held-out test split described in this section, and
"dropped as a duplicate in M2" refers to the dataset download step
(`scripts/fetch_datasets.py`, see `docs/DATASETS.md`).

| Dataset | Split | Labels |
|---|---|---|
| Invictus Sigma-AWS | development | derived here from Stratus Red Team's own source code |
| flaws.cloud | development | none (no ground truth exists) |
| Splunk attack_data | **held-out test** | Splunk's own descriptors; no Splunk event content was read for this |

Rules are written and tuned on development data only. While rules are written
or tuned, Splunk event content must not be opened, queried or printed. The
primary evaluation is on Splunk; Invictus results are reported separately as
"development set, optimistic".

## Source versions

| Source | Version | Why this version |
|---|---|---|
| Invictus data | `invictus-ir/Sigma-AWS` @ `f0d5599`, files pinned in `scripts/datasets.lock.json` | the labels are bound to these exact files (hash-checked before labelling) |
| Stratus Red Team, behaviour | v2.8.0 (`53140a3`) | latest release before the data was recorded (2023-07-10); has the 27 AWS techniques the Invictus README names. The data does not reveal the exact release, but the AWS technique code, the runner, the providers and the CLI commands are **identical in v2.5.7, v2.6.0, v2.7.0 and v2.8.0** (checked with `diff`), so any release in that range gives the same labels. v2.8.1 differs in 3 techniques but was released on 2023-07-25, after the data. |
| Stratus Red Team, mappings | v2.37.0 (`338bc60`) | current release; v2.8.0 states only ATT&CK *tactics*, later releases add technique IDs (see below). All 27 technique IDs still exist there. |
| MITRE ATT&CK Enterprise | 20.0 (released 2026-10-13), `mitre-attack/attack-stix-data` @ `c2494b2`, file SHA-256 `81113ba9…` | current release; used to check every stated ID and to follow `revoked-by` links |
| Splunk attack_data | `splunk/attack_data` @ `eac2f8f` | same commit as the downloaded files |

`python scripts/build_labels.py --refresh-sources` recreates `sources.json`
(network); `python scripts/build_labels.py` rebuilds both label files from it
offline. The rebuild is deterministic (byte-identical output).

## How the Invictus labels were derived

### 1. What a run ID is (from the Stratus v2.8.0 source)

Stratus sets the user agent `stratus-red-team_<uuid>` on its requests
(`internal/providers/main.go`). One UUID is created

- per CLI command for the credential check (`pkg/stratus/providers.go`,
  `EnsureAuthenticated`): a single `ec2:DescribeAccountAttributes` call. This
  **preflight** happens for `detonate`, `warmup` and `revert`, but not for
  `cleanup` (`cmd/stratus/*_cmd.go`).
- per technique execution (`pkg/stratus/runner/runner.go`): used for the
  Terraform **warm-up** (`terraform apply` with an appended user agent) and for
  the technique's own SDK calls (**detonation** or **revert**).

`terraform destroy` runs **without** the user agent
(`runner/terraform.go`, `TerraformDestroy`), so clean-up is untagged. This
matches the data: the 1,006 untagged Terraform events are reads and teardown
calls (`Delete*`, `Detach*`, `Disassociate*`, `Release*`, `Terminate*`, plus
two `ec2:ModifyInstanceAttribute`); none of them creates anything.

### 2. What each technique does (technique catalog in `sources.json`)

For each of the 27 techniques, extracted from its `main.go` / `main.tf`:

- **detonate and revert calls:** SDK operations (`&<service>.<Operation>Input`)
  in the function registered as `Detonate` / `Revert` and in every function it
  calls.
- **identifiers:** technique-specific resource names from the source, e.g.
  `stratus-red-team-ct-stop`, `/credentials/stratus-red-team/`,
  `StratusRedTeamVolume`. An identifier that also occurs in another technique's
  identifiers is dropped.
- **manual additions** (from reading the source, recorded in `sources.json`):
  `console-login-without-mfa` logs in with raw HTTP requests, which CloudTrail
  records as `signin:ConsoleLogin`; `iam-create-admin-user` names its user
  `malicious-iam-user` in Go code.
- **event-name mapping:** CloudTrail logs `s3:PutBucketLifecycleConfiguration`
  as `PutBucketLifecycle` (seen in the data) and adds an API-version suffix to
  Lambda calls (`AddPermission20150331v2`).

### 3. Attributing runs

Three kinds of evidence, each from the Stratus source:

1. **documented calls**: the run makes a call from the technique's detonate or
   revert function.
2. **identifiers**: the technique's resource names appear in the run's requests,
   responses or principals.
3. **resources from another run**: EC2 resource IDs (AMI, snapshot, security
   group, ...) that an already attributed run of the technique created.

A technique is assigned only if exactly one technique has specific evidence.
Identifiers and resources outweigh calls, because calls can be shared between
techniques or come from Stratus helpers outside the technique's file (example:
`sts:GetCallerIdentity` in the `iam-create-user-login-profile` run).
Confidence: **high** = at least two kinds of evidence agree, **medium** = one
kind, **low** = a remaining ambiguity (stated in the justification).

**Phase.** A run with documented calls is a detonation (if it has warm-up
events or detonate-only calls) or a revert (revert-only calls). Six techniques
use the same call in both functions (e.g. `ec2:ModifyImageAttribute`); there a
run without warm-up after a detonation of the same technique is its revert. The
requests confirm it in all six cases: `add` → `remove` (AMI, EBS snapshot),
`valuesToAdd` → `valuesToRemove` (RDS snapshot), event selectors and the role's
trust policy restored, and the Lambda code reloaded from the warm-up bucket
(`lambda.zip`). A run with only Terraform events is a **warm-up**.

**Preflights** are linked to the command they started: the next detonation or
warm-up run at most 30 s later (in the same second, the preflight is ordered
first, as the command's first call). Preflights superseded by a newer one
before any run followed stay unresolved.

### 4. Untagged events

1. A call from a technique's detonate function made **by a role session that
   Stratus created**: role `attack`. This covers the 2 events of
   `ec2-steal-instance-credentials` where the stolen instance credentials are
   used (`sts:GetCallerIdentity`, `ec2:DescribeInstances`) through an SDK
   client without the Stratus user agent.
2. Terraform: role `clean-up`, attributed to a technique by identifiers or
   warm-up resource IDs where possible.
3. Other events with a technique's identifiers or resource IDs: role
   `side-effect` (AWS services acting on Stratus resources: KMS for SSM
   SecureString parameters and Secrets Manager, the SSM agent on Stratus
   instances, RDS, Inspector, ...).
4. Everything else: role `background` (operators' console and SDK activity,
   `AWS Internal`, unlinked service events). Background and unattributed
   clean-up events inside a detonation run's time span carry
   `during_detonation_of`.

### 5. Result

| Runs (83) | Count | Confidence |
|---|---:|---|
| detonation | 29 | 29 high |
| revert | 17 | 16 high, 1 medium |
| warm-up only (warm-up failed) | 3 | 3 medium |
| preflight | 34 | 31 medium, 1 low, **2 unresolved** |

Unresolved: preflights `8f842891` (11:58:37) and `06e68e16` (11:58:47). Each
was superseded by a newer credential check before any technique run followed,
so the commands they started made no other tagged call. The low-confidence
preflight `d40831dd` (11:59:02) is linked to the `cloudtrail-delete` run in the
same second, but the two unresolved preflights were also within 30 s of it.
**Every technique run (detonation, revert, warm-up) is assigned.**

| Events (2,900) | Count | Notes |
|---|---:|---|
| attack | 158 | 134 are calls named in the technique source; 24 are other calls on the detonation path (`sts:AssumeRole` ×23 into the warm-up role, `sts:GetCallerIdentity` ×1), marked `"documented": false` |
| warm-up | 932 | |
| preflight | 34 | |
| revert | 24 | |
| clean-up | 1,006 | 787 attributed to a technique |
| side-effect | 343 | |
| background | 403 | 231 AWS internal, 103 operator console, 43 operator SDK, 26 AWS service; 23 fall inside a detonation run's time span |

The table below is generated from `invictus_labels.json`. "All attack calls
failed" means every attack event carries an `errorCode`: the CloudTrail stop
and delete detonations target trails that were never created inside the data
window (`TrailNotFoundException`), and the `ec2-enumerate-from-instance`
`ssm:SendCommand` failed. Some techniques are designed to produce errors:
Stratus describes `ec2-get-password-data` as running the call "from a role that
does not have permission to do so". All error codes are in
`attack_event_errors`.

| Stratus technique | Outcome in the data | Attack events | Stated by Stratus | ATT&CK 20.0 |
|---|---|---:|---|---|
| `aws.credential-access.ec2-get-password-data` | detonated | 34 | – (tactics only) | – |
| `aws.credential-access.ec2-steal-instance-credentials` | detonated | 32 | T1552.005 | T1552.005 |
| `aws.credential-access.secretsmanager-retrieve-secrets` | detonated | 21 | – (tactics only) | – |
| `aws.credential-access.ssm-retrieve-securestring-parameters` | detonated | 10 | – (tactics only) | – |
| `aws.defense-evasion.cloudtrail-delete` | detonated, all attack calls failed | 1 | T1562.008 | T1685.002 (formerly T1562.008) |
| `aws.defense-evasion.cloudtrail-event-selectors` | detonated | 1 | T1562.008 | T1685.002 (formerly T1562.008) |
| `aws.defense-evasion.cloudtrail-lifecycle-rule` | detonated | 1 | T1562.008 | T1685.002 (formerly T1562.008) |
| `aws.defense-evasion.cloudtrail-stop` | detonated, all attack calls failed | 3 | T1562.008 | T1685.002 (formerly T1562.008) |
| `aws.defense-evasion.organizations-leave` | detonated | 6 | T1666.A002 | – |
| `aws.defense-evasion.vpc-remove-flow-logs` | detonated | 1 | – (tactics only) | – |
| `aws.discovery.ec2-download-user-data` | detonated | 20 | – (tactics only) | – |
| `aws.discovery.ec2-enumerate-from-instance` | detonated, all attack calls failed | 1 | – (tactics only) | – |
| `aws.execution.ec2-launch-unusual-instances` | detonated | 10 | T1496.A008, T1578.002 | T1578.002 |
| `aws.execution.ec2-user-data` | not detonated (warm-up failed) | 0 | – (tactics only) | – |
| `aws.exfiltration.ec2-security-group-open-port-22-ingress` | detonated | 1 | T1562.007 | T1686.001 (formerly T1562.007) |
| `aws.exfiltration.ec2-share-ami` | detonated | 1 | – (tactics only) | – |
| `aws.exfiltration.ec2-share-ebs-snapshot` | detonated | 1 | T1578.001 | T1578.001 |
| `aws.exfiltration.rds-share-snapshot` | detonated | 1 | T1496.A007 | – |
| `aws.exfiltration.s3-backdoor-bucket-policy` | detonated | 1 | – (tactics only) | – |
| `aws.initial-access.console-login-without-mfa` | detonated | 1 | T1078.A001 | – |
| `aws.persistence.iam-backdoor-role` | detonated | 1 | T1098.003 | T1098.003 |
| `aws.persistence.iam-backdoor-user` | detonated | 1 | T1098.001 | T1098.001 |
| `aws.persistence.iam-create-admin-user` | detonated | 3 | T1136.003 | T1136.003 |
| `aws.persistence.iam-create-user-login-profile` | detonated | 2 | T1098.001 | T1098.001 |
| `aws.persistence.lambda-backdoor-function` | detonated | 1 | – (tactics only) | – |
| `aws.persistence.lambda-overwrite-code` | detonated | 1 | – (tactics only) | – |
| `aws.persistence.rolesanywhere-create-trust-anchor` | detonated | 2 | – (tactics only) | – |

## ATT&CK IDs: what the sources actually state

- **Stratus states no ATT&CK technique IDs.** v2.8.0 states ATT&CK *tactics*
  only. Later releases add IDs from the **AWS Threat Technique Catalog (TTC)**,
  which reuses ATT&CK IDs where they exist and adds its own (`.A00x` suffix).
  12 of the 27 techniques have no technique ID at all; 3 have only TTC-specific
  IDs that are not in ATT&CK.
- **Recorded as stated, not corrected:** `rds-share-snapshot` is mapped by
  Stratus v2.37.0 to TTC `T1496.A007` "Cloud Service Hijacking - Bedrock LLM
  Abuse", which does not describe sharing an RDS snapshot. This looks like an
  upstream mapping error.
- **ATT&CK changed with v19** (released 2026-04-28; attack.mitre.org,
  "Updates - April 2026"): the tactic *Defense Evasion* was split into
  *Stealth* and *Defense Impairment*, and `T1562` "Impair Defenses" was revoked
  in favour of `T1685` "Disable or Modify Tools". For this project:
  **`T1685.002` (formerly `T1562.008`)** "Disable or Modify Cloud Log" and
  **`T1686.001` (formerly `T1562.007`)** "Disable or Modify System Firewall:
  Cloud Firewall". The pinned v20.0 keeps that state. Stratus' tactics
  (`attack_tactics_stated`) use the pre-v19 naming. Wherever these IDs are
  shown, the former ID is shown with them, because most public content
  (SigmaHQ, Stratus) still uses the pre-v19 IDs.
- `attack_v20` fields are a mechanical normalisation: active IDs are kept,
  revoked IDs are replaced by their `revoked-by` successors, IDs that ATT&CK
  does not have map to nothing. The stated ID is always kept next to it.

## Splunk labels

- From Splunk's dataset descriptors only, via the lock file. No dataset file
  (event content) was opened: the descriptor checkout skips Git LFS content, so
  the dataset files are not even present in it. `event_content_read: false`
  is checked by `tests/test_labels.py`, as is the set of fields per file.
- 49 files, 27 distinct stated technique IDs. 35 labels come from the
  descriptor field `mitre_technique`, 14 from the directory name (older
  descriptors without that field).
- `T1562.008` and `T1562.007` are revoked since ATT&CK v19 and normalised to
  `T1685.002` and `T1686.001` as above; all other stated IDs are active.
- One file has no technique label
  (`suspicious_behaviour/abnormally_high_cloud_instances_launched/...`); one has
  two (`aws_ec2_multiple_ssh_public_keys_uploaded`: T1021.004, T1021.008).
- The labels are Splunk's and are used as given; they have not been reviewed
  yet.

## Coverage: Invictus vs. Splunk (ATT&CK 20.0)

Only techniques that were detonated and have an ID in ATT&CK can be compared.
Invictus: 26 Stratus techniques were detonated; 12 of them map to **8 distinct
ATT&CK 20.0 IDs**. Splunk: **27 distinct IDs**.

- **Exact overlap: 3** (`T1098.003`, `T1685.002` (formerly `T1562.008`),
  `T1686.001` (formerly `T1562.007`)).
- Same parent technique: `T1098`, `T1552`, `T1578`, `T1685`, `T1686` (both
  formerly under `T1562`).
- Invictus only: `T1098.001`, `T1136.003`, `T1552.005`, `T1578.001`,
  `T1578.002`.
- 14 detonated Invictus techniques have no comparable ID (11 with tactics only,
  3 with TTC-only IDs), so the overlap at technique level is a lower bound.
- Tactics are not comparable directly: Stratus states pre-v19 tactic names
  (*defense-evasion*), and ATT&CK no longer has that tactic since v19.

## How findings are scored against these labels

1. **Detection:** a technique counts as detected if at least one finding has an
   evidence event with role `attack` for that technique. A strict variant, in
   which only `"documented": true` events count, is reported as well.
2. **Lab scaffolding** (`warm-up`, `preflight`, `revert`, `clean-up`,
   `side-effect`): findings that rest only on these events are excluded from
   both true-positive and false-positive counts and reported as a separate
   number. They are setup and teardown, not attacker behaviour, but they look
   like it (e.g. Terraform's `secretsmanager:GetSecretValue` during destroy, or
   an untagged `ec2:ModifyInstanceAttribute` from Terraform).
3. **Background** (403 events): findings on them are reported separately as
   "unlabelled background", not counted as false positives. Operator activity
   is probably benign, but nothing guarantees it, and the dataset is not a
   benign baseline.
4. **Failed attempts** (`cloudtrail-stop`, `cloudtrail-delete`,
   `ec2-enumerate-from-instance`): in scope; report "detected" and "attempt
   failed" side by side, as detecting failed tampering attempts is a rule
   design choice.
5. **Not detonated** (`ec2-user-data`): out of scope by design, with the reason;
   not in the denominator.
6. Several runs of one technique (e.g. 3 `cloudtrail-stop` detonations, 2
   `ec2-launch-unusual-instances`) are one technique, not independent samples.

## Known limitations

- Preflight linking uses timing within the documented command structure; one
  link is low confidence and two preflights are unresolved. Preflights carry no
  attack behaviour, so this does not affect technique labels.
- Phases for shared detonate/revert calls are inferred from order (confirmed by
  the request parameters in all six cases).
- The `attack` role includes 24 calls on the detonation path that the technique
  file does not name (role assumption); they are marked.
- Splunk technique labels are unreviewed.
- Stratus documentation text in `sources.json` is quoted from the Stratus Red
  Team source code (Apache-2.0, Datadog).
