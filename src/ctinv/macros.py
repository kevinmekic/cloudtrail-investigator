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
}


def register(con: duckdb.DuckDBPyConnection) -> None:
    for ddl in MACROS.values():
        con.execute(ddl)
