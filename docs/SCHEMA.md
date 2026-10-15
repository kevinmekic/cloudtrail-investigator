# Database schema and ingest

`ctinv ingest` loads CloudTrail files into a DuckDB database with three tables:
`events` (one row per unique eventID), `quarantine` (everything that could not
become an event, with the reason) and `ingested_files` (one row per ingested
file, with its SHA-256).

```bash
ctinv ingest data/raw/flaws_cloud --db data/ctinv.duckdb       # dataset from data/MANIFEST.json
ctinv ingest some/other/logs --db x.duckdb --dataset my-sandbox # dataset given explicitly
```

## How records are read

- `.json` and `.json.gz`, single files or directories (searched recursively).
  Three layouts: the CloudTrail delivery format `{"Records": [...]}`, NDJSON
  (one event per line) and a single JSON event. Files are streamed record by
  record (`ctinv.reader`), never loaded whole.
- **Nothing is taken from file names.** Account, region, time and every other
  attribute come from the event. (The Invictus files, for example, are named
  after account `218007301253`, while every event says `123837392027`.)
- **Provenance:** `dataset` is given with `--dataset` or looked up by path in
  `data/MANIFEST.json`; the file must then match the SHA-256 recorded there.
  `source_file` is the path as read, relative to the data directory (`--data-dir`,
  default `./data`); `source_index` is the record's position in the file.
  If any file's dataset cannot be determined, nothing is written.
- **Deduplication on eventID:** a record whose eventID is already stored, or
  appeared earlier in the same file, is counted as a duplicate if its content is
  identical. If the content differs, it is quarantined
  (`duplicate eventID with different content than the stored event`), so a
  conflicting record is never silently dropped. The first occurrence wins.
- **Quarantine instead of crashing:** a record that is not valid JSON, not an
  object, lacks `eventID`/`eventTime`/`eventSource`/`eventName`, has a field of
  an unexpected type, an `eventTime` without time zone, or is larger than 16 MB
  goes to `quarantine` with the reason. Values are never coerced; the only
  cleaning is `accessKeyId: ""` becoming NULL. In NDJSON, reading continues at
  the next line that starts with `{`. A file that becomes unreadable (damaged
  gzip, broken `Records` envelope) keeps every record read before the damage
  and gets a file-level quarantine row and an `ingested_files.file_error`; the
  command then exits with status 1.
- **One transaction per file**, so a crash never leaves a half-ingested file.
  `records_read = inserted + duplicates + quarantined` holds for every file.

## Time

`event_time` is a `TIMESTAMP` holding **UTC**. Python converts `eventTime`
(ISO 8601 with a time zone) to UTC before DuckDB sees it. Two DuckDB behaviours
made this necessary, both checked while building this:

- Casting `'2017-02-12T21:25:06Z'` via `TIMESTAMPTZ` to `TIMESTAMP` applies the
  session time zone, which defaults to the machine's local zone; on the
  development machine the result was three hours off.
- Returning `TIMESTAMPTZ` values to Python requires the `pytz` package.

The connection is also set to `TimeZone = 'UTC'`, and a test reads the column
under a different session time zone to prove the value does not move.

## Tables

### `events`

| Column | Type | CloudTrail field |
|---|---|---|
| `event_id` | VARCHAR, primary key | `eventID` |
| `event_time` | TIMESTAMP (UTC) | `eventTime` |
| `event_source` | VARCHAR | `eventSource` |
| `event_name` | VARCHAR | `eventName` |
| `aws_region` | VARCHAR | `awsRegion` |
| `source_ip_address` | VARCHAR | `sourceIPAddress` |
| `user_agent` | VARCHAR | `userAgent` |
| `error_code` | VARCHAR | `errorCode` |
| `error_message` | VARCHAR | `errorMessage` |
| `read_only` | BOOLEAN | `readOnly` (JSON boolean or `"true"`/`"false"`) |
| `event_type` | VARCHAR | `eventType` |
| `recipient_account_id` | VARCHAR | `recipientAccountId` |
| `event_version` | VARCHAR | `eventVersion` |
| `request_id` | VARCHAR | `requestID` |
| `shared_event_id` | VARCHAR | `sharedEventID` |
| `identity_type` | VARCHAR | `userIdentity.type` |
| `identity_arn` | VARCHAR | `userIdentity.arn` |
| `identity_principal_id` | VARCHAR | `userIdentity.principalId` |
| `identity_account_id` | VARCHAR | `userIdentity.accountId` |
| `access_key_id` | VARCHAR | `userIdentity.accessKeyId` (`""` → NULL) |
| `user_name` | VARCHAR | `userIdentity.userName` |
| `invoked_by` | VARCHAR | `userIdentity.invokedBy` |
| `session_issuer_arn` | VARCHAR | `userIdentity.sessionContext.sessionIssuer.arn` |
| `mfa_authenticated` | BOOLEAN | `userIdentity.sessionContext.attributes.mfaAuthenticated` (`"true"`/`"false"`) |
| `request_parameters` | JSON | `requestParameters` |
| `response_elements` | JSON | `responseElements` |
| `additional_event_data` | JSON | `additionalEventData` |
| `resources` | JSON | `resources` |
| `raw` | JSON | the whole record, as parsed |
| `raw_sha256` | VARCHAR | SHA-256 of `raw` as stored: duplicate check and integrity fingerprint |
| `dataset`, `source_file`, `source_index` | VARCHAR, VARCHAR, BIGINT | provenance (see above) |

`raw` is the record as parsed and re-serialized by DuckDB (whitespace and
escaping may differ from the file). The exact original bytes are found through
`source_file`, `source_index` and the file's SHA-256 in `ingested_files`.

Beyond the core fields, five more CloudTrail fields have their own column: `invoked_by`
(an AWS service acting on someone's behalf; needed to tell service activity
from user activity), `additional_event_data` (holds `MFAUsed` for console
sign-ins), `event_version` (field availability depends on it, see `readOnly`
below), `request_id` and `shared_event_id` (correlation across services and
accounts).

### `quarantine`

`dataset`, `source_file`, `source_index` (NULL for a file-level error),
`event_id` (if the record had one), `reason`, `record` (the record or the
invalid text, cut at 1 MB), `quarantined_at` (UTC).

### `ingested_files`

`source_file`, `dataset`, `sha256`, `size_bytes`, `started_at`, `finished_at`
(UTC), `records_read`, `inserted`, `duplicates`, `quarantined`, `file_error`.
Every ingest of a file adds a row, so re-ingests are visible.

## Field names: expectation vs. documentation vs. data

The schema started from a list of fields that forensics needs most: `eventID`,
`eventTime`, `eventSource`, `eventName`, `awsRegion`, `sourceIPAddress`,
`userAgent`, `errorCode`, `errorMessage`, `readOnly`, `eventType`,
`recipientAccountId`, and from `userIdentity`: `type`, `arn`, `principalId`,
`accountId`, `accessKeyId`, `userName`, `sessionContext.sessionIssuer.arn` and
`mfaAuthenticated`. That list was checked against the AWS CloudTrail documentation ("CloudTrail record contents"
and "CloudTrail userIdentity element") and the ingested development data
(flaws.cloud, Invictus). Splunk data was not looked at. Counts are unique
events in the database: 1,225,784 for flaws.cloud, 2,900 for Invictus.

All top-level names in the list exist with exactly that spelling (note
`sourceIPAddress`, `requestID`, `sharedEventID`). Where reality differs from
the list:

1. **`mfaAuthenticated` is not a `userIdentity` field.** It is
   `userIdentity.sessionContext.attributes.mfaAuthenticated`, a *string*
   `"true"`/`"false"`, and exists only for identities with a session context:
   307,100 flaws.cloud events (IAM users' console sessions, assumed roles,
   root sessions) and 674 Invictus events.
2. **Console sign-ins carry MFA elsewhere:** `additionalEventData.MFAUsed`
   (`"Yes"`/`"No"`) on `ConsoleLogin` events. flaws.cloud: 61 Yes, 18 No,
   1 without the field; Invictus: 1 Yes, 1 No. A "console login without MFA"
   rule needs this field, not `mfaAuthenticated`.
3. **`userName` exists for IAM users only**, and for `Root` only if the account
   has an alias (AWS documentation): flaws.cloud has it in all 1,119,316 IAMUser
   events and in 3,242 of 10,841 Root events, never for AssumedRole, AWSService
   or AWSAccount. An assumed role's name is in
   `sessionContext.sessionIssuer.userName` and in the ARN.
4. **`sessionContext.sessionIssuer.arn` exists for `AssumedRole` only**
   (41,097 flaws.cloud events, 76 Invictus).
5. **`accessKeyId` can be absent or empty.** Absent for AWSService and
   AWSAccount identities and some Root events; `""` in 35 flaws.cloud events
   and 1 Invictus event (stored as NULL).
6. **`readOnly` is mostly missing in older logs:** present in only 50,919 of
   1,225,784 flaws.cloud events (4.2%). By `eventVersion`, it is present in all
   events of versions 1.06 and 1.07 but only sporadically in 1.05 and earlier.
   Read-only detection on flaws.cloud has to use the API name (`List*`,
   `Describe*`, `Get*`), not `readOnly`. Invictus (version 1.08) has it
   everywhere.
7. **`userIdentity.type` can be missing:** all 42 Invictus `AwsServiceEvent`
   records and the single flaws.cloud `AwsConsoleAction` record have no type.
8. `eventType` values seen: `AwsApiCall`, `AwsServiceEvent`,
   `AwsConsoleSignIn`, `AwsConsoleAction`.

## flaws.cloud: one in three records is a duplicate

Of 1,939,207 records, **713,423 are exact duplicates** of another record (same
eventID, identical content); the database holds **1,225,784 unique events**.
713,161 eventIDs occur exactly twice, 86 occur 3 to 8 times. 99.99% of the
repeats are in the same file, usually within 10 records of the first copy. They
are concentrated in February to August 2019, when almost exactly half of all
records are repeats; outside that period there are almost none. This pattern
fits two trails delivering the same events during that time; the source does
not say. August 2019 alone has 710,859 unique events (58% of the dataset).
Counts and thresholds must therefore be based on unique events, which the
`events` table provides.

## Performance

Full ingest of flaws.cloud (20 files, 1,939,207 records), measured with
`/usr/bin/time -l` on an Intel Core i5-8257U (4 cores), 8 GB RAM, macOS 15.8.1,
Python 3.14.7, DuckDB 1.5.6:

| Run | Wall time | Peak memory (max RSS) |
|---|---:|---:|
| DuckDB memory limit 1 GB (default of `ctinv ingest`) | 327 s | 1.40 GB |
| DuckDB default limit (80% of RAM), before bounding `read_json` buffers | 328 s | 2.6 GB |

The database file is 1.9 GB. In a profile of four files, 58% of the time was
Python (reading, normalizing, writing batches) and 42% DuckDB (loading batches,
deduplication, commits). On six files, DuckDB's default limit, 1 GB and 512 MB took 120 s,
101 s and 113 s with a peak of 1.53, 1.14 and 0.70 GB, so the limit costs no
time. Re-ingesting the 39,207-record file 19 took 4.5 s and added nothing.
