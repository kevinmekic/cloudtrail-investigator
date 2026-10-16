# Reports

`ctinv report` turns an investigation, or the findings of `ctinv detect`, into
a Markdown report and a self-contained HTML report, plus a JSON file with the
complete data behind them.

```bash
ctinv report --db data/ctinv.duckdb --access-key AKIA3Z2XBVUDFQ9TU4MD \
    --from 2019-08-21 --to 2019-08-23
ctinv report --db data/ctinv.duckdb --principal arn:aws:iam::811596193553:role/flaws --redact
ctinv report --db data/ctinv.duckdb --findings --rule access-denied-spike
```

| Option | Default | Meaning |
|---|---|---|
| `--access-key ID` / `--principal ARN` / `--findings` | one is required | report an investigation (see [INVESTIGATION.md](INVESTIGATION.md)) or the stored findings |
| `--from TIME`, `--to TIME` | whole database | time range; for `--findings`, findings whose time span overlaps it |
| `--max-depth`, `--max-sessions`, `--max-events`, `--follow-created-keys` | as for `ctinv investigate` | limits of the investigation |
| `--rule ID` | all rules | with `--findings`: only this rule's findings (repeatable; the rule must have run on the database) |
| `--redact` | off | mask account IDs and access keys in all output files (see below) |
| `--out-dir DIR` | `reports` | where the files go |
| `--max-rows N` | 500 | activity periods shown in the report (the JSON has all) |
| `--period-gap SECONDS` | 900 | the gap that ends an activity period |

Each run writes `<kind>-<UTC time>.md`, `.html` and `.json` (for example
`investigation-20261016T110908Z.md`), where kind is `investigation` or
`findings`, and prints the executive summary. `reports/` is git-ignored: reports
contain the data they describe. Usage errors exit with status 2, an unknown
starting point or a database without detection results (for `--findings`) with
1.

## Sections

1. **Executive summary**: what was investigated, event counts by outcome,
   where the starting key came from, the credentials it obtained and used,
   credential requests that failed, the most frequent calls, the blast radius
   and the findings, each as one statement with its evidence.
2. **Timeline**: key moments and activity periods (below). A findings report
   lists its findings in time order instead.
3. **Findings by ATT&CK tactic**: grouped by MITRE ATT&CK Enterprise v20.0
   tactic, in matrix order; a finding is listed under each tactic of its rule.
   Technique IDs that changed with ATT&CK v19 are shown with their former ID,
   for example "T1685.002 (formerly T1562.008)".
4. **Session graph**: the starting identity (S0) and the keys it obtained,
   with the call that issued each key, its counts, identities, source IPs, user
   agents and regions, and the credential calls that did not lead to a session.
5. **Blast radius**: resources the calls named, per service, split into
   succeeded, denied and failed, and the calls that name no resource.
6. **Indicators (IOCs)**: source IP addresses, other source addresses (AWS
   services calling on someone's behalf), user agents, access keys and ARNs
   (callers, the roles behind their sessions, roles requested in credential
   calls), each with event counts, first and last time, sessions and evidence.
7. **Limitations of the data**: the caveats of every dataset involved (from
   the dataset registry, below), keys whose origin is not in the data, limits
   that were reached, and how times and outcomes are read.
8. **Evidence index**: every eventID cited anywhere in the report, in time
   order, with its time, session, call, region, caller, source address, user
   agent, outcome, error code, dataset, and source file with the record's
   position in it, so the original record can be found.

Session graph and blast radius are part of investigation reports only.

## Evidence

Every statement and every row cites eventIDs: aggregates cite their first and
last event (and the first event of each outcome where counts are split), a
call cites itself. Statements about the dataset or the database (anonymised
addresses, detection not run) cite none. In HTML, each eventID links to its row
in the evidence index; in Markdown, the index is a table at the end. Tests
check that every cited eventID is in the index and links to it.

Long lists are cut (activity periods 500, key moments 200, findings 100 per
tactic, resources 20 per service, IOCs 50 per kind, sessions 20 per parent);
the report says where, and only shown rows are indexed. The JSON file has the
complete lists: for an investigation it is the investigation's own JSON
(`ctinv-investigation/1`, see [INVESTIGATION.md](INVESTIGATION.md)) with an
added `report` object (`ctinv-report/1`: all key moments, all activity
periods, all IOCs, the datasets); for findings it is `ctinv-findings/1` with
every finding and its complete evidence list, and the latest rule runs.

## Timeline

### Key moments

- each credential issuance: the call that issued or created each key in the
  session graph (also when it lies before the investigated time range), and
  every other credential-issuing call, including requests that failed;
- the first use of each key;
- the first successful call;
- the first burst of denied calls and the first burst of failed calls: the
  first 60-second window with at least 10 of them;
- each finding, at its first evidence event in the investigation.

### Activity periods

Calls of one session to one API (event source and name) with the same outcome
form one period as long as no gap between them exceeds 15 minutes
(`--period-gap`). Other calls can happen in between, so periods may overlap in
time; each row has the count, first and last time, regions, errors (the error
codes, or for failed sign-ins, which have none, the error messages), and its
first and last event as evidence.

Why periods and not runs of consecutive events: a script that loops over a few
APIs produces runs of one to a few events. In the flaws.cloud example below,
grouping consecutive events with the same session, API and outcome gives
79,602 rows for 263,595 events, because `RunInstances` alternates between
denied and failed calls and five other APIs come in between; the first 500 of
those rows end at 07:49:45 on the first day, eight and a half minutes into a
burst that lasts until the end of the second day. Activity periods give 498
rows covering all of it (gap 5 minutes: 1,777 rows; 60 minutes: 142).
Sporadic activity condenses less: the 16,725 events of the role `flaws` over
three and a half years make 7,415 periods.

## Untrusted input

Every CloudTrail field can be chosen by whoever wrote the log, including
`eventName` and `userAgent`. Reports therefore treat every value as text:

- **HTML**: Jinja2 with autoescaping, so values are escaped in element text
  and attributes (quotes included). The page embeds no data in scripts and
  loads nothing: styles are inline, and a Content-Security-Policy
  (`default-src 'none'; style-src 'unsafe-inline'`) forbids scripts, frames,
  forms and external resources even if escaping were ever bypassed. The only
  links point to the evidence index.
- **Markdown**: every value a template outputs passes through one escaping
  function (Jinja2's `finalize` hook, so a template cannot forget it). It
  backslash-escapes the characters that make links, images, HTML, emphasis,
  code, math and table cells (`` \ ` * _ { } [ ] < > ( ) # + ! | ~ & $ @ ``),
  the colon of `://`, and the dot in domain names (`www.` and bare domains,
  which some renderers link without `www.`), so values cannot break table rows
  or turn into links or HTML. IP addresses, times and eventIDs stay readable.
  The report's own Markdown contains no links.
- **Both**: control, format and line-separator characters (newlines, tabs,
  bidirectional overrides, zero-width characters) are shown as `\uXXXX`, so a
  value cannot break a line or display as something else.

Tests inject `<script>`, quotes, angle brackets, Markdown links, autolinks,
pipes, a newline and a right-to-left override through `userAgent` and
`eventName`, and check the HTML with an HTML parser and the Markdown with a
GitHub-flavoured Markdown parser (markdown-it-py with linkify): no element,
attribute, link or image comes from a value, and every table row keeps its
columns.

## Anonymised datasets

What is known about each public dataset is recorded as data in
[`src/ctinv/datasets.yml`](../src/ctinv/datasets.yml): which fields the
publisher anonymised (`source_ips`, `account_ids`, `access_keys`), how, and the
caveats a report must state. A report reads it for every dataset its events
come from. If any field was anonymised, the IOC section is labelled with a
warning that names those fields. flaws.cloud's publisher replaced all three
with random values of the same format, so a report on it says:

> Source IPs, account IDs and access keys were anonymised by the dataset publisher - not real infrastructure, accounts or credentials. Do not block, look up or report them.

With fewer fields the label names only those (for example "Source IPs were
anonymised by the dataset publisher - not real infrastructure."). The
executive summary says the same, the headings of the IP, access key and ARN
tables say what in them is anonymised, and every IP and access key row says
whether its value is. For an anonymised address the report does not say
whether it is public: the value was chosen at random and may belong to
unrelated people. A dataset that is not in the registry (logs ingested under
another name) is named in the limitations as not described, so a report never
implies that its values are real or anonymised.

## Redaction

`--redact` masks, in the Markdown, HTML and JSON files alike:

- account IDs: any run of exactly 12 digits, as `ACCOUNT-1`, `ACCOUNT-2`, ...
  (CloudTrail puts account IDs into ARNs, principal IDs, bucket names and
  error messages, so matching is by shape, not by field);
- access key IDs starting with AKIA, ASIA, ABIA or ACCA, as `AKIA-KEY-1`,
  `ASIA-KEY-2`, ... (the prefix stays: it tells long-term from temporary keys).

All three files go through one masker, so the same value has the same mask
everywhere in one report; masks are numbered in order of first appearance and
are not stable across reports. eventIDs are never masked, so evidence stays
usable: a UUID, or any UUID-like value of five hex groups whose middle three
have four digits (302,189 flaws.cloud eventIDs have shorter or longer outer
groups, and 4,376 of them contain a run of 12 digits).

Not masked: names (users, roles, buckets), IP addresses, user agents, IAM unique
IDs (`AIDA...`, `AROA...`) and the database path. A redacted report is
shareable, not anonymous. A 12-digit number that is not an account ID is
masked too.

## Example: flaws.cloud, the Level6 key on 21–22 August 2019

```bash
ctinv report --db data/ctinv.duckdb --access-key AKIA3Z2XBVUDFQ9TU4MD \
    --from 2019-08-21 --to 2019-08-23
```

The investigation of [INVESTIGATION.md](INVESTIGATION.md) as a report: 263,595
events in 2 sessions, 41 key moments (the key's creation by root in 2017, the
first use of both keys, the first success, the session key from
`GetSessionToken`, two denied `CreateAccessKey` calls, the first denied and
failed bursts, 32 findings), 498 activity periods, 39 resources, 10 source IP
addresses and 2 access keys (labelled as anonymised, as are the account IDs)
and 951 cited events in the evidence index. Measured: 10.7 s and 0.93 GB peak
memory including the investigation (earlier runs: 10.2 s and 13.7 s);
Markdown 0.47 MB, HTML 0.75 MB, JSON 70.6 MB (the JSON timeline lists the first
100,000 events).

A findings report over all 1,030 findings of both development datasets
(`--findings`) took 4.3 s and 0.46 GB.
