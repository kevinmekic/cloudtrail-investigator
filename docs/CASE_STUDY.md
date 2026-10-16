# Case study: a public challenge key used to try to start compute

A DFIR write-up of one investigation with `ctinv`, from the question to the
conclusion: the access key of the flaws.cloud challenge user `Level6` on 21–22
August 2019.

> **About the data.** This is the analysis of a public training dataset: the
> CloudTrail logs of [flaws.cloud](http://flaws.cloud/), an AWS security
> challenge, published by Summit Route in 2020 (see
> [DATASETS.md](DATASETS.md)). The challenge hands the `Level6` key to every
> player on purpose, so its use is expected and nobody's account was broken
> into. Before publishing, the publisher replaced every source IP address,
> account ID and access key with a random value of the same format. Nothing
> below identifies a real victim or attacker. The values shown are those
> replacements: **do not block, look up or report them.**

## Summary

- In 48 hours the `Level6` key made 263,595 calls. 263,413 of them came from one
  source address running a Python script (Boto3). Within twelve seconds the
  script asked for a 36-hour session key, tried to create an IAM user and
  access keys, and then tried to start EC2 instances: 259,024 `RunInstances`
  calls in 15 regions, asking for 149 instance types.
- **Nothing that would change the account succeeded.** No instance, key pair,
  VPC, user or access key was created; every `RunInstances` call was refused
  (permissions, throttling, unsupported instance types, missing capacity, an
  instance limit of 0). The keys made no call to CloudTrail or other logging
  services.
- `ctinv` reported 32 `access-denied-spike` findings (T1580). The behaviour
  itself fits **Resource Hijacking: Compute Hijacking (T1496.001)**, which no
  built-in rule covers; the attempt to create credentials shows up in the
  investigation, but no rule reports it.
- The same address ran the same script with the key of a second challenge user,
  `backup`, starting seven seconds later. The session graph does not show this
  (it links credentials, not addresses); a separate query found it.

![Executive summary of the Level6 report](report-level6.png)

## 1. The question

The `Level6` key is the start point. Over the whole dataset it made 402,480
calls from 1,839 source addresses between 2017-02-26 and 2020-10-07: many
players, over three and a half years. Its three busiest days are 21, 22 and 23
August 2019 (53,812, 87,526 and 94,630 calls). The investigation covers the
first two of them, from 2019-08-21 00:00 to 2019-08-23 00:00 UTC, and asks:

1. What did the key do, and who (which source) did it?
2. Did it obtain other credentials, and were they used?
3. What did it touch, and did anything succeed?
4. Did it try to stay (persistence) or to hide (log tampering)?

## 2. How the evidence was collected

```bash
python scripts/fetch_datasets.py                       # flaws.cloud + Invictus, hash-checked
ctinv ingest data/raw/flaws_cloud --db data/ctinv.duckdb
ctinv detect --db data/ctinv.duckdb                    # all built-in rules, default parameters
ctinv report --db data/ctinv.duckdb --access-key AKIA3Z2XBVUDFQ9TU4MD \
    --from 2019-08-21 --to 2019-08-23
```

The report command runs the investigation (session graph, timeline, blast
radius, linked findings) and writes Markdown, HTML and JSON to `reports/`:
14 seconds and about 1 GB of memory on a 2019 laptop. Every statement in the
report cites CloudTrail eventIDs, and each cited eventID is listed in an
evidence index with its source file and record number. The facts below come
from that report (`reports/investigation-20261016T220357Z.*`); the ones marked
*query* come from read-only SQL on the same database, because they go beyond
what the report shows. The eventIDs are cited so every claim can be checked
against the raw records.

## 3. Evidence

### 3.1 Where the key came from

The account's root user created the key on 2017-02-26 23:11:17 from the
console (`iam:CreateAccessKey`, `8b8484ec-49ad-4ec1-8ccb-d6b1c33003b4`), two
and a half years before the window. This is the challenge publishing its own
key, not an attacker creating one.

### 3.2 Two kinds of use

The report's indicators split the 263,595 events by source:

| Source | Events | When | User agent | What it did |
|---|---:|---|---|---|
| one address, `5.205.62.253` | 263,413 | 07:41:17 on the 21st to the end of the window | `Boto3/1.9.201 Python/2.7.12` (two Linux kernel versions) | the script described below |
| nine other addresses | 182 | spread over both days | `aws-cli` on macOS, Linux, Windows, Cygwin | read IAM policies, Lambda function policies and API Gateway stages (*query*) |

The second group reads its way from the key's own policies to a Lambda
function and the API Gateway stage in front of it, for example
`iam:ListAttachedUserPolicies` at 02:44:58 (`4c09bb57-4135-4950-9123-37ee6aec5b65`)
to `apigateway:GetStages` at 02:50:42 (`9d6f32f2-62e6-4c68-8d77-de83c0fc3621`)
from one address, and the same sequence from another between 06:09:53
(`2f910b04-4bff-47af-a698-d7fa5d683e2b`) and 06:39:41
(`99d5c60a-4d51-4f24-9528-dd05ae55459`). All 182 calls are reads (`List*`,
`Get*`, `Describe*`); 166 succeeded, the rest were denied or named something
that does not exist (*query*). *Interpretation:* players working on the
challenge level the key belongs to.

### 3.3 The first seconds of the script

| Time (21 Aug) | Session | Call | Result | eventID |
|---|---|---|---|---|
| 07:41:17 | S0 | `sts:GetCallerIdentity` | succeeded | `cf774734-7dc3-44b1-99a6-d875452feb9` |
| 07:41:19 | S0 | `sts:GetSessionToken`, `durationSeconds` 129,600 (36 hours) | succeeded, issued `ASIAZ6XVDR2PA984G89L` (S1) | `9b12a121-6617-41de-97d6-af22c7659f33` |
| 07:41:21 | S0 | `iam:ListAccessKeys` | succeeded | `97e5bc9a-1215-4de6-9588-c6cd4595e852` |
| 07:41:21 | S0 | `iam:CreateAccessKey` | denied | `aaae5f19-7c9b-4328-8a00-991ebbdd9c5b` |
| 07:41:22 | S0 | `iam:CreateAccessKey` | denied | `7e37d426-b63e-4447-923a-eb3672d5e157` |
| 07:41:22 | S0 | `iam:CreateUser` | denied | `ae3fbed3-c701-4b51-9f9f-f7e4e9714c12` |
| 07:41:22 | S0 | `iam:DeleteAccessKey` | denied | `bca1a90e-ee45-487b-bf4b-afed809613c3` |
| 07:41:24 | S1 | `sts:GetCallerIdentity`, first use of the session key | succeeded | `544c3eca-8ec7-40d5-acc5-8dc9e4abf096` |
| 07:41:24 | S1 | `ec2:CreateKeyPair` (ap-northeast-2) | denied | `a3039f5f-e52c-497c-8538-290ff9b455247` |
| 07:41:25 | S1 | `ec2:CreateDefaultVpc` (ap-northeast-2) | denied | `d6f2d9c0-b1e8-4c6e-91a7-5726c0aa0749` |
| 07:41:29 | S1 | `ec2:RunInstances` (ap-northeast-2) | failed, `Client.InstanceLimitExceeded` | `91d6e642-7d9d-4cd2-9d7d-494e352f3dc5` |
| 07:41:30 | S1 | `ec2:RunInstances` (ap-northeast-2) | denied, `Client.UnauthorizedOperation` | `b71746e-bfb3-47ad-aed8-5b40ce5cb2c5` |

S0 is the `Level6` key, S1 the session key it obtained (the only pivot; the
session graph has these two sessions). The split fits the rules of
`GetSessionToken`: it needs no permission, so any leaked user key can get a
session key, and that key cannot call IAM without MFA (AWS STS API reference),
so the script made its IAM calls with the long-term key and its EC2 calls with
the session key. The denied IAM calls carry no request parameters, as is
common for denied calls in CloudTrail, so the logs do not say which user or
key they were aimed at.

### 3.4 Thirty-six hours of launch attempts

The session key S1 made 122,257 calls from 07:41:24 until 2019-08-22 19:41:19
(`da298eeb-3b17-459a-99e6-ebb431445c157`), the exact second its 36-hour
lifetime ended (the `GetSessionToken` response gives the expiration "Aug 22,
2019 7:41:19 PM"). From the next second on, the script continued with the
long-term key: 18,777 more calls from the same address until the end of the
window, starting at 19:41:20 (`3e012a32-6195-4a72-8d21-6a7e6989a9c0`, *query*).

In each of the 15 regions the script called `DescribeKeyPairs`,
`CreateKeyPair`, `CreateDefaultVpc`, `DescribeInstances` and, above all,
`RunInstances`: 259,024 of the 263,595 calls. From the request parameters
(*query*):

- 15 regions, one machine image per region (15 images), 149 instance types,
  24,772 of the calls asking for GPU types (families p2, p3, p3dn, g2, g3, g3s);
- every call asks for up to 10 instances (`maxCount`), turns on termination
  protection (`disableApiTermination: true`) and passes user data, whose
  content CloudTrail does not log (`<sensitiveDataRemoved>`);
- 843 `CreateKeyPair` calls for 15 key pair names
  (`<account>_<region>_my_key_pair`) and 886 `CreateDefaultVpc` calls, none
  successful.

None of the 259,024 `RunInstances` calls succeeded. The errors EC2 returned:

| Error code | Calls |
|---|---:|
| `Client.RequestLimitExceeded` (throttling) | 169,186 |
| `Client.UnauthorizedOperation` (permission denied) | 58,071 |
| `Client.Unsupported` | 16,142 |
| `Server.InsufficientInstanceCapacity` | 8,541 |
| `Client.InstanceLimitExceeded` ("current instance limit of 0") | 6,617 |
| `Client.InvalidParameterValue` | 465 |
| `Server.InternalError` | 2 |

The calls continue after the window: the address's last call is a
`RunInstances` at 2019-08-24 00:49:37 (`0a916d69-a02a-4d3f-89ec-7257a6ef4bb7`,
*query*). In the whole dataset, no `RunInstances` call by `Level6` ever
succeeded (362,760 calls between July 2018 and September 2020, *query*).

### 3.5 What the calls touched (blast radius)

39 resources in 4 services, 9 of them with at least one successful call:

| Service | Resources | Succeeded | Only denied or failed |
|---|---:|---:|---:|
| EC2 | 30 (15 images, 15 key pairs) | 0 | 30 |
| IAM | 7 (the user and role `Level6`, 3 policies, 2 instance profiles) | 7 (all reads) | 0 |
| API Gateway | 1 REST API | 1 (reads) | 0 |
| Lambda | 1 function | 1 (reads) | 0 |

3,619 events name no resource (mostly `sts:GetCallerIdentity`,
`ec2:DescribeInstances`, `ec2:CreateDefaultVpc`, `ec2:DescribeKeyPairs`). Every
successful call in the window is a read or the `GetSessionToken` call
(*query*: no call outside `List*`, `Describe*` and `Get*` succeeded).

### 3.6 What the detection rules found

32 findings, all of `access-denied-spike` (T1580 Cloud Infrastructure
Discovery, medium): one per run of denied calls, 59,726 of the window's 59,774
denied events. The first one starts with the denied `CreateAccessKey` at
07:41:21 (`aaae5f19-7c9b-4328-8a00-991ebbdd9c5b`) and covers 3,072 denied calls
in 76 minutes.

No other rule produced a finding here, and the gaps are instructive:

- **Nothing for the compute attempts.** No rule looks for mass `RunInstances`
  attempts; `access-denied-spike` fires only because many of them were denied.
  The findings describe permission probing (T1580), not the goal of the calls.
- **Nothing for the credential attempts.** `credentials-created-for-other-user`
  needs to know whose key is being created. Denied calls carry no request
  parameters here, so the rule cannot evaluate them; the investigation lists
  both `CreateAccessKey` calls as key moments ("credential request denied")
  and as failed pivots.
- **No `discovery-burst`:** the script uses a handful of APIs, far below the
  rule's 20 different read APIs in five minutes.

## 4. Findings

1. **F1: The key was used by two kinds of source.** 182 calls from nine
   addresses with interactive command-line clients, reading the policies,
   Lambda function and API Gateway stage the key can see; and 263,413 calls
   from one address running a Boto3 script (3.2).
2. **F2: The script obtained a second credential.** A session key valid for
   36 hours, the longest `GetSessionToken` allows for an IAM user, used for
   122,257 calls until it expired; then the script fell back to the long-term
   key (3.3, 3.4).
3. **F3: It tried to gain lasting access and failed.** Two `CreateAccessKey`,
   one `CreateUser` and one `DeleteAccessKey` call within one second, all
   denied (3.3). ATT&CK v20.0: Account Manipulation: Additional Cloud
   Credentials (T1098.001) and Create Account: Cloud Account (T1136.003),
   attempted.
4. **F4: It tried to start compute in every region it could reach and
   failed.** 259,024 `RunInstances` calls, 15 regions, 149 instance types, up
   to 10 instances each, termination protection on; none succeeded (3.4).
   ATT&CK v20.0: Resource Hijacking: Compute Hijacking (T1496.001), attempted.
5. **F5: No impact and no anti-forensics visible.** No resource was created or
   changed, and no call went to CloudTrail, AWS Config, GuardDuty or CloudWatch
   Logs (3.5, *query*).
6. **F6: The same actor used a second key.** The same address, with the same
   user agent, started the same way with the `backup` user's key from 07:41:24
   (`2655e7ec-67ce-4637-846d-ebede1e55a7e`): a 36-hour `GetSessionToken` at
   07:41:25 (`31fa1c59-4fd2-474a-b510-9bce0bf499546`), then denied IAM calls.
   From 2019-08-21 07:41:17 to 2019-08-24 00:49:37 the address made 696,289
   calls with four keys (two users, each with its long-term and session key)
   (*query*).

## 5. Conclusion

1. **What did it do?** One source used the public `Level6` key to run a script
   that, within twelve seconds, tried to create credentials and then tried to
   start instances in 15 regions without pause for as long as the window lasts
   and beyond. The other sources only read.
2. **Other credentials?** One session key from `GetSessionToken`, used until it
   expired; no role was assumed. Outside the graph, the same source used the
   `backup` key the same way.
3. **What did it touch?** It named 30 EC2 resources (images and key pairs) in
   calls that all failed, and read 9 IAM, Lambda and API Gateway resources.
   Nothing was created or changed.
4. **Persistence or hiding?** Persistence was attempted (new user, new keys)
   and denied; there is no sign of log tampering.

*Assessment (interpretation, not provable from the logs):* an automated
attempt to run compute in someone else's account with leaked credentials,
most likely to use the computing power, for example for cryptocurrency mining
(GPU types, every region, termination protection, `maxCount` 10). It was
stopped by the key's missing permissions and by the account's limits:
throttling, an instance limit of 0 for 18 of the instance types tried, and
configurations EC2 did not support.

In a real account the next steps would be: deny all actions to both users with
an IAM policy (temporary keys stay valid until they expire, so deactivating
the access keys alone does not end the 36-hour sessions; AWS IAM User Guide,
"Disabling permissions for temporary security credentials"), deactivate the
keys, check every region for instances, key pairs and VPCs, and alert on
credential creation and mass `RunInstances` attempts. Here the key is a public
challenge key, and the account behaved as designed.

## 6. Limitations

- **Anonymised data.** Source addresses, account IDs and access keys are random
  replacements. The replacement is consistent, so addresses can be compared
  within the dataset (the basis of F6), but they say nothing about location or
  owner, and the address shown may belong to someone unrelated.
- **A shared key.** Many players use `Level6`. Separating them by source
  address assumes one address is one actor; NAT, VPNs or one person using
  several addresses would break that.
- **What the logs do not contain.** Management events only: data events
  (S3 object reads, Lambda invocations) were not logged, so whether any player
  called the API Gateway stage is not visible. The user data passed to
  `RunInstances` is removed by CloudTrail, so what the instances would have run
  is unknown; "for profit" is an inference.
- **Error order.** CloudTrail records the error EC2 returned, not the order in
  which EC2 checked permissions, limits and capacity. That many calls failed
  with limit or capacity errors rather than a permission error does not show
  that the key was allowed to start those instance types.
- **The window.** The activity starts before and continues after the 48 hours
  investigated; window totals are not campaign totals.
- **Time resolution.** CloudTrail times have one-second resolution; events in
  the same second are ordered by eventID, so their real order is unknown.
- **Interpretation by one analyst**, with no ground truth: the dataset is not
  labelled, and the assessment in section 5 is reasoned, not measured.
- **ATT&CK IDs.** T1098.001 and T1136.003 come from the project's pinned ATT&CK
  v20.0 data; T1496.001 was checked on attack.mitre.org (ATT&CK v20) on
  2026-10-17.
