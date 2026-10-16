"""SQL helper functions that detection rules can call.

Some checks are awkward to repeat in every rule, for example deciding whether
an IAM policy document grants full administrator access. They are defined once
here as DuckDB macros and created on the connection before the rules run.
Plain SQL keeps them fast and dependency-free (Python functions registered in
DuckDB would need numpy).
"""

import duckdb

MACROS: dict[str, str] = {
    # The items of a JSON value as a list: an array's elements, or the value itself.
    "ctinv_json_items": """
        CREATE OR REPLACE TEMP MACRO ctinv_json_items(j) AS (
            CASE WHEN j IS NULL THEN []::JSON[]
                 WHEN json_type(j) = 'ARRAY' THEN from_json(j, '["JSON"]')
                 ELSE [j] END
        )
    """,
    # True if an IAM policy document (text) allows every action on every resource:
    # a statement with Effect "Allow", Action "*" and Resource "*" (each alone or in
    # a list). Conditions, NotAction and NotResource are not evaluated. Some logs
    # carry the document URL-encoded. Unparseable or missing documents give false.
    "ctinv_grants_full_admin": """
        CREATE OR REPLACE TEMP MACRO ctinv_grants_full_admin(document) AS (
            coalesce(list_bool_or(list_transform(
                ctinv_json_items(TRY_CAST(
                    CASE WHEN starts_with(document, '%7B') THEN url_decode(document)
                         ELSE document END AS JSON)->'Statement'),
                lambda s: coalesce(
                    s->>'Effect' = 'Allow'
                    AND list_contains(
                        list_transform(ctinv_json_items(s->'Action'), lambda a: a->>'$'), '*')
                    AND list_contains(
                        list_transform(ctinv_json_items(s->'Resource'), lambda r: r->>'$'), '*'),
                    false)
            )), false)
        )
    """,
    # Who made a call, as a key for per-identity behaviour: the identity's ARN, or
    # for identities without one (other accounts) "<accountId>:<principalId>".
    # NULL when AWS made the call (AWS service identities, or invokedBy: a service
    # acting for the principal), for anonymous callers (one key would lump the
    # whole internet together) and when the record names no principal at all.
    "ctinv_actor": """
        CREATE OR REPLACE TEMP MACRO ctinv_actor(
            identity_type, arn, account_id, principal_id, invoked_by
        ) AS (
            CASE WHEN invoked_by IS NOT NULL
                      OR identity_type = 'AWSService'
                      OR account_id = 'ANONYMOUS_PRINCIPAL' THEN NULL
                 WHEN arn IS NOT NULL THEN arn
                 WHEN nullif(nullif(principal_id, ''), 'null') IS NOT NULL
                     THEN coalesce(account_id, '?') || ':' || principal_id
                 ELSE NULL END
        )
    """,
    # True if the API name starts with List, Describe or Get: the classification
    # of read (discovery) calls used by the behavioural rules. The readOnly field
    # cannot be used instead: most older events lack it.
    "ctinv_is_list_describe_get": """
        CREATE OR REPLACE TEMP MACRO ctinv_is_list_describe_get(event_name) AS (
            coalesce(starts_with(event_name, 'List')
                     OR starts_with(event_name, 'Describe')
                     OR starts_with(event_name, 'Get'), false)
        )
    """,
    # True if the error code says the caller lacked permission. Only codes whose
    # meaning the AWS API references state: AccessDenied (S3, IAM, STS and other
    # query APIs), AccessDeniedException (JSON APIs), UnauthorizedOperation (EC2;
    # CloudTrail logs it as Client.UnauthorizedOperation), AuthorizationError and
    # NotAuthorized (SNS).
    "ctinv_is_access_denied": """
        CREATE OR REPLACE TEMP MACRO ctinv_is_access_denied(error_code) AS (
            coalesce(error_code IN ('AccessDenied', 'AccessDeniedException',
                                    'UnauthorizedOperation', 'Client.UnauthorizedOperation',
                                    'AuthorizationError', 'NotAuthorized'), false)
        )
    """,
    # True if the call failed: it has an errorCode, or it is an AWS sign-in event
    # (signin.amazonaws.com: ConsoleLogin, CheckMfa, GetSigninToken, ...) whose
    # responseElements report "Failure" under the event's own name. Sign-in events
    # record a failure that way, with an errorMessage but without an errorCode
    # (AWS CloudTrail and IAM documentation of sign-in events).
    "ctinv_failed": """
        CREATE OR REPLACE TEMP MACRO ctinv_failed(
            error_code, event_source, event_name, response_elements
        ) AS (
            error_code IS NOT NULL
            OR coalesce(event_source = 'signin.amazonaws.com'
                        AND json_extract_string(response_elements, event_name) = 'Failure',
                        false)
        )
    """,
}

# ctinv_failed applied to an events table aliased as ``e``.
FAILED_SQL = "ctinv_failed(e.error_code, e.event_source, e.event_name, e.response_elements)"


def register(con: duckdb.DuckDBPyConnection) -> None:
    for ddl in MACROS.values():
        con.execute(ddl)
