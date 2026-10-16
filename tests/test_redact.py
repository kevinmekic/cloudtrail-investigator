"""Tests for consistent masking of account IDs and access keys."""

from datetime import datetime

from ctinv.redact import Redactor

ACCOUNT_A, ACCOUNT_B = "111122223333", "444455556666"
KEY_A, KEY_T = "AKIAIOSFODNN7EXAMPLE", "ASIAIOSFODNN7EXAMPLE"


def test_same_value_same_mask_everywhere() -> None:
    r = Redactor()
    text = (
        f"arn:aws:iam::{ACCOUNT_A}:user/alice used {KEY_A}; bucket logs-{ACCOUNT_A}; "
        f"principal {ACCOUNT_B}:AROAEXAMPLE:s; recipient {ACCOUNT_A}; {KEY_T} and {KEY_A}"
    )
    assert r.text(text) == (
        "arn:aws:iam::ACCOUNT-1:user/alice used AKIA-KEY-1; bucket logs-ACCOUNT-1; "
        "principal ACCOUNT-2:AROAEXAMPLE:s; recipient ACCOUNT-1; ASIA-KEY-2 and AKIA-KEY-1"
    )
    # The same redactor keeps its masks for later strings of the same report.
    assert r.text(f"{ACCOUNT_B} {KEY_T}") == "ACCOUNT-2 ASIA-KEY-2"


def test_event_ids_stay_intact() -> None:
    # A UUID whose last group happens to be 12 digits is evidence, not an account;
    # so are the UUID-like eventIDs of flaws.cloud with shorter or longer outer groups.
    ids = (
        "00000000-0000-0000-0000-000000000042",
        "8B8484EC-49AD-4EC1-8CCB-123456789012",
        "84129e-a3f6-4369-8dc9-123456789012",
        "285250a71-eada-41ec-b4db-1234567890123",
    )
    assert Redactor().text(" ".join(ids)) == " ".join(ids)
    # Not an eventID: the account ID next to it is still masked.
    assert Redactor().text(f"{ACCOUNT_A}-a-b-c-d") == "ACCOUNT-1-a-b-c-d"


def test_only_exact_formats_are_masked() -> None:
    r = Redactor()
    assert r.text("1234567890123 12345678901 AKIA123 xAKIAIOSFODNN7EXAMPLE") == (
        "1234567890123 12345678901 AKIA123 xAKIA-KEY-1"
    )
    assert r.text("AKIAIOSFODNN7EXAMPLE9") == "AKIA-KEY-2"  # a longer key is a key


def test_masks_are_not_masked_again() -> None:
    r = Redactor()
    once = r.text(f"{ACCOUNT_A} {KEY_A}")
    assert r.text(once) == once


def test_walk_masks_nested_strings_and_keys_only() -> None:
    r = Redactor()
    when = datetime(2023, 1, 1)
    data = {
        "count": 111122223333,
        "when": when,
        ACCOUNT_A: [KEY_A, (ACCOUNT_B, None)],
        "nested": {"arn": f"arn:aws:sts::{ACCOUNT_A}:assumed-role/r/s"},
    }
    assert r.walk(data) == {
        "count": 111122223333,
        "when": when,
        "ACCOUNT-1": ["AKIA-KEY-1", ("ACCOUNT-2", None)],
        "nested": {"arn": "arn:aws:sts::ACCOUNT-1:assumed-role/r/s"},
    }
