# Investigation mode

`ctinv investigate` answers three questions about one identity: what did it do
(timeline), which other credentials did it obtain and use (session graph), and
what did it touch (blast radius). Detection findings whose evidence lies in the
investigated events are listed with it.

```bash
ctinv investigate --db data/ctinv.duckdb --access-key AKIA3Z2XBVUDFQ9TU4MD \
    --from 2019-08-21 --to 2019-08-23 -o results/level6.json
ctinv investigate --db data/ctinv.duckdb --principal arn:aws:iam::811596193553:role/flaws
```

| Option | Default | Meaning |
|---|---|---|
| `--access-key ID` / `--principal ARN` | one is required | starting point (see below) |
| `--from TIME`, `--to TIME` | whole database | ISO 8601 date or date and time; without an offset UTC; `--from` inclusive, `--to` exclusive |
| `--max-depth N` | 3 | follow obtained credentials at most N pivots deep; 0 = no pivots |
| `--max-sessions N` | 1000 | follow at most N sessions besides the start |
| `--max-events N` | 100,000 | list at most N events in the JSON timeline |
| `--follow-created-keys` | off | also follow keys created with `iam:CreateAccessKey` |
| `-o FILE` | none | write the whole investigation as JSON |

The console shows a summary; the JSON file has everything. An unknown starting
point (no events, or none in the time range) exits with status 1, usage errors
with 2. The investigation works in temporary tables and does not change the
database.

## Starting point

- `--access-key`: every event whose `userIdentity.accessKeyId` is that key.
- `--principal`: every event whose `userIdentity.arn` is that ARN (IAM user,
  root, assumed-role session, federated user). A **role ARN**
  (`arn:aws:iam::<account>:role/...`) stands for every session of the role
  (`sessionContext.sessionIssuer.arn`), since a role never calls anything
  itself. Callers without an ARN (principals of other accounts, logged as
  `AWSAccount`) cannot be a starting point.

## Session graph and pivots

The starting point is session S0. A **pivot** is a call of a session that
issues an access key:

- STS calls that return temporary credentials: `AssumeRole`,
  `AssumeRoleWithSAML`, `AssumeRoleWithWebIdentity`, `GetFederationToken`,
  `GetSessionToken`, and any other STS call whose response carries
  `credentials.accessKeyId`. The new key is
  `responseElements.credentials.accessKeyId`.
- `iam:CreateAccessKey`, whose response names the new long-term key
  (`responseElements.accessKey.accessKeyId`). Such
  keys are often created for someone else (a new user, a service), so they are
  followed only with `--follow-created-keys`; otherwise they are listed with the
  status `created_key_not_followed`. The secret key is not in the log.

Events that use the issued key (`userIdentity.accessKeyId`) become a new
session one level deeper, and its own pivots are followed the same way.
Linking is by key, not by time: access key IDs are unique, so no clock ordering
is assumed. Every pivot keeps one of these statuses, so dead ends stay visible:

| Status | Meaning |
|---|---|
| `followed` | the issued key is used; its events are the next session |
| `already_in_graph` | the key, or every event using it, is already in the graph (cycles end here; with `--principal`, keys the principal itself uses) |
| `not_used` | no event in the investigated time range uses the key |
| `depth_limit` | not followed: the session would be deeper than `--max-depth` |
| `session_limit` | not followed: `--max-sessions` was reached |
| `created_key_not_followed` | an `iam:CreateAccessKey` key, without `--follow-created-keys` |
| `key_not_logged` | the call succeeded, but the log names no usable key (missing, empty or a placeholder; a usable key ID is 16 to 128 upper-case letters and digits) |
| `request_failed` | the call returned an error, so no key was issued |

`AssumeRoleWithSAML` and `AssumeRoleWithWebIdentity` are made without AWS
credentials, so they cannot be reached from a starting key; they matter as the
**origin** of a key. For every key in the graph, the call that issued or
created it is looked up in the whole database (not limited by the time range)
and shown as `issued_by`, for example the EC2 service assuming an instance role
for a key that was later used from somewhere else.

Each session lists its event counts by outcome, time span, identities, keys,
source IPs (top 10), user agents (top 5) and regions (top 20), with the number
of distinct values of each.

### How often pivoting is impossible in the datasets

Measured on the unique events of both development datasets (2026-10-16), with
the definitions above.

Forward (issued keys):

| | flaws.cloud | Invictus |
|---|---:|---:|
| credential-issuing calls | 72,765 | 51 |
| failed (no key issued) | 15,863 | 13 |
| succeeded | 56,902 | 38 |
| succeeded, but key not logged or unusable | **0** | **0** |
| succeeded, key used by some event in the data | 7,291 | 8 |

No issued key was redacted in either dataset, so `key_not_logged` never
occurs there; it is covered by tests. The common dead end is a key that is
never used: 48,387 of the 51,901 `AssumeRole` calls made by AWS services in
flaws.cloud issued keys that no logged event uses (39,569 issued by EC2 for
instance roles, 6,916 by AWS Config). Of the keys issued to flaws.cloud users
and roles by their own successful calls, 3,775 of 4,940 are used.

Backward (temporary keys in use, `ASIA…`, and whether their issuing call is in
the data):

| Caller type of the events | flaws.cloud: keys with origin / keys | Invictus |
|---|---:|---:|
| AssumedRole | 7,231 / 7,889 | 8 / 8 |
| IAMUser | 46 / 1,729 | 0 / 122 |
| Root | 0 / 145 | – |
| none (no `userIdentity.type`) | 0 / 1 | – |

For assumed roles the origin is almost always logged. For temporary keys of IAM
users and root it almost never is: the data does not show how these keys were
issued. Their user agents point mostly to the AWS console and to AWS services
calling with the user's credentials (for example
`ec2-frontend-api.amazonaws.com`); 150 such flaws.cloud keys were also used by
CLI or SDK clients (by user agent). Such a key can be investigated, but its `issued_by` stays
empty. All 10 long-term keys used in flaws.cloud have their `CreateAccessKey`
call in the data; the 3 Invictus keys do not.

No successful `AssumeRole` call by an assumed role exists in either dataset, so
real chains there are one pivot deep. Deeper chains, cycles and redacted keys
are tested with synthetic events (`tests/test_investigate.py`).

## Timeline and outcomes

Events of all sessions in time order; events in the same second are ordered by
eventID (CloudTrail times have one-second precision, so their real order is
unknown). Each event has the session it belongs to, its depth and an outcome:

- **succeeded**: no `errorCode`, and for sign-in events no failure (below);
- **denied**: a permission error (`AccessDenied`, `AccessDeniedException`,
  `UnauthorizedOperation`, `Client.UnauthorizedOperation`, `AuthorizationError`,
  `NotAuthorized`; the same list the detection rules use);
- **failed**: any other error code (throttling, missing resources, limits), or
  a failed sign-in.

AWS sign-in events (`signin.amazonaws.com`: `ConsoleLogin`, `CheckMfa`,
`GetSigninToken`, ...) have no `errorCode`. They record the result under their
own name in `responseElements` (`{"ConsoleLogin": "Failure"}`) and the reason
in `errorMessage` (e.g. "Failed authentication"). A sign-in event whose
`responseElements` report `Failure` counts as failed; the detection framework
uses the same test (`ctinv_failed` in `src/ctinv/macros.py`).

Counts per outcome are given for the whole investigation, per session and per
API. The JSON timeline lists at most `--max-events` events; the counts are
always complete.

## Blast radius

The resources the events name, per service, each split into succeeded, denied
and failed, with the APIs called, first and last time, regions and the first 20
eventIDs as evidence (the counts next to them are complete). Resources come
from two places:

- the event's `resources` field, as AWS states it. S3 ARNs carry no account or
  region and become the bucket (or `bucket/key`) name. The types
  `AWS::S3::Bucket`, `AWS::S3::Object`, `AWS::IAM::Role` and `AWS::KMS::Key` map
  to the types below so both sources merge; other types are kept as stated,
  `unknown` when none is given;
- request parameters that name a resource, matched at any depth (EC2 nests them
  in item lists), but only for the services listed. The same name means
  different things elsewhere: `name` is a trail in CloudTrail but a filter name
  in EC2, `groupName` a security group in EC2 but a group in IAM. S3 events
  with `bucketName` and `key` also name the object `bucket/key`.

| Service | Parameter | Type |
|---|---|---|
| s3 | `bucketName` | bucket |
| ec2 | `instanceId` | instance |
| ec2 | `imageId` | image |
| ec2 | `snapshotId` | snapshot |
| ec2 | `sourceSnapshotId` | snapshot |
| ec2 | `volumeId` | volume |
| ec2 | `groupId` | security group |
| ec2 | `groupName` | security group |
| ec2 | `vpcId` | vpc |
| ec2 | `subnetId` | subnet |
| ec2 | `keyName` | key pair |
| ec2 | `allocationId` | elastic ip |
| iam | `userName` | user |
| iam | `roleName` | role |
| iam | `groupName` | group |
| iam | `policyArn` | policy |
| iam | `instanceProfileName` | instance profile |
| iam | `accessKeyId` | access key |
| iam | `serialNumber` | mfa device |
| sts | `serialNumber` | mfa device |
| sts | `roleArn` | role |
| lambda | `functionName` | function |
| logs | `logGroupName` | log group |
| apigateway | `restApiId` | rest api |
| cloudtrail | `name` | trail |
| cloudtrail | `trailName` | trail |
| ssm | `instanceId` | instance |
| ssm | `name` | parameter |
| secretsmanager | `name` | secret |
| secretsmanager | `secretId` | secret |
| kms | `keyId` | key |
| cloudformation | `stackName` | stack |
| rds | `dBInstanceIdentifier` | db instance |
| rds | `dBClusterIdentifier` | db cluster |
| rds | `dBSnapshotIdentifier` | db snapshot |
| rds | `dBClusterSnapshotIdentifier` | db cluster snapshot |

The list was chosen from the parameters seen in the flaws.cloud and Invictus
data. Known gaps:

- Calls that name no resource (account-wide `List*`/`Describe*`, for example)
  are not dropped: they are counted per API under `events_without_resource`.
- Parameters not in the list are not read as resources (for example
  `instanceType`, filter values, tag keys, policy documents).
- One resource can appear under two names: a role by name (`roleName`) and by
  ARN (`roleArn`), a KMS key by ID and by ARN. Only identical strings of the
  same type merge.
- Resources are what a call names, not what it changed: a denied
  `RunInstances` names the image it tried to start.

## Findings

A finding of `ctinv detect` belongs to the investigation when at least one of
its evidence events is an event of the session graph within the time range.
Matching on evidence, not on the finding's principal, is exact where a rule
reports a role rather than the session that acted. Each linked finding keeps
its rule, severity, ATT&CK technique (with the former ID where it changed),
outcome, time span, how much of its evidence lies in the investigation, which
sessions it came from and the first 20 of those eventIDs. If detection has
never run on the database, findings are reported as unknown (`null`), not as
none.

## JSON output

Top-level keys: `format` (`ctinv-investigation/1`), `ctinv_version`,
`generated_at`, `database`, `scope` (starting point, time range and limits),
`definitions` (outcomes and pivot statuses), `summary`, `sessions`, `pivots`,
`apis`, `blast_radius`, `findings`, `timeline`. Times are UTC strings ending in
`Z`. The timeline is written one event per line so it stays greppable;
`summary.timeline_truncated` says whether `--max-events` cut it.

`ctinv report --access-key ...` or `--principal ...` writes the same JSON next
to its Markdown and HTML report, with one more key, `report`
(`ctinv-report/1`): all key moments, all activity periods, all indicators and
the datasets involved. See [REPORTING.md](REPORTING.md).

## Example: flaws.cloud, the Level6 key on 21–22 August 2019

The access key of the flaws.cloud challenge user `Level6` is public by design,
so the key's events are many players'. A time window around one burst of
activity makes the investigation readable:

```bash
ctinv investigate --db data/ctinv.duckdb --access-key AKIA3Z2XBVUDFQ9TU4MD \
    --from 2019-08-21 --to 2019-08-23 -o results/level6.json
```

Measured (9.9 s, peak memory 0.97 GB, after `ctinv detect` with default
parameters):

- **263,595 events**: 2,822 succeeded, 59,774 denied, 200,999 failed, between
  2019-08-21 02:44:58 and 2019-08-22 23:59:59.
- **Session graph**: S0 is the key (141,338 events, 10 source IPs, 141,156 of
  them from `5.205.62.253`). The key was created on 2017-02-26 23:11:17 by the
  account's root user (`iam:CreateAccessKey`, event
  `8b8484ec-49ad-4ec1-8ccb-d6b1c33003b4`). At 2019-08-21 07:41:19 the key
  called `sts:GetSessionToken` from `5.205.62.253` (event
  `9b12a121-6617-41de-97d6-af22c7659f33`); the issued temporary key is S1
  (122,257 events until 2019-08-22 19:41:19, all from that address). Two
  `iam:CreateAccessKey` calls within the next three seconds were denied (pivots
  with status `request_failed`).
- **What it did**: 259,024 `ec2:RunInstances` calls from `5.205.62.253` in 15
  regions with 149 different `instanceType` values, none successful: 58,071 denied,
  the rest failed (mostly `Client.RequestLimitExceeded`, also
  `Client.Unsupported`, `Server.InsufficientInstanceCapacity`,
  `Client.InstanceLimitExceeded`), plus denied `CreateKeyPair` and
  `CreateDefaultVpc` calls.
- **Blast radius**: EC2 30 resources (15 images, 15 key pairs), all only
  attempted (0 with a successful call); IAM 7 resources, all read successfully
  (the user and the role `Level6`, three policies, the instance profiles
  `SecurityMonkey` and `flaws`); one API Gateway REST API and the Lambda function
  `Level6`, read. 3,619 events name no resource (mostly
  `sts:GetCallerIdentity`, `ec2:DescribeInstances`, `ec2:CreateDefaultVpc`,
  `ec2:DescribeKeyPairs`).
- **Findings**: 32 `access-denied-spike` findings (T1580) with 59,726 evidence
  events in this investigation.

Interpretation (not measured): a script with the public key that tried to
start every instance type in every region, which looks like an attempt to run
compute (for example mining) on someone else's account; the account's limits
and the user's missing permissions stopped all of it. The same address did the
same with the key of the challenge user `backup` six seconds later, which an
investigation of that key shows; linking keys by a shared source address is not
part of the session graph.
