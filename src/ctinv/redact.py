"""Consistent masking of AWS account IDs and access key IDs for shareable reports.

Every string of a report (and of the JSON written with it) passes through one
``Redactor``, so the same account ID or key gets the same mask everywhere in
that report: ``ACCOUNT-1``, ``ACCOUNT-2`` ... and ``AKIA-KEY-1``,
``ASIA-KEY-2`` ... (the key prefix stays, because it tells long-term from
temporary keys). Masks are numbered in order of first appearance; they are not
stable across reports and cannot be reversed.

Matching is deliberately broad: any run of exactly 12 digits counts as an
account ID (CloudTrail puts account IDs into ARNs, principal IDs, bucket names
and messages), except inside UUIDs such as eventIDs, which stay intact as
evidence. Access key IDs are tokens of upper-case letters and digits starting
with AKIA, ASIA, ABIA or ACCA. Names, IP addresses, user agents and IAM unique
IDs (AIDA..., AROA...) are not masked.
"""

import re
from typing import Any

_TOKEN = re.compile(
    r"(?P<uuid>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
    r"|(?P<key>(?<![A-Z0-9])(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{12,124}(?![A-Z0-9]))"
    r"|(?P<account>(?<![0-9])[0-9]{12}(?![0-9]))"
)


class Redactor:
    def __init__(self) -> None:
        self.masks: dict[str, str] = {}
        self._counts = {"account": 0, "key": 0}

    def _mask(self, match: re.Match[str]) -> str:
        kind, value = match.lastgroup, match.group()
        if kind == "uuid":
            return value
        if value not in self.masks:
            self._counts[kind] += 1  # type: ignore[index]
            n = self._counts[kind]  # type: ignore[index]
            self.masks[value] = f"ACCOUNT-{n}" if kind == "account" else f"{value[:4]}-KEY-{n}"
        return self.masks[value]

    def text(self, value: str) -> str:
        return _TOKEN.sub(self._mask, value)

    def walk(self, value: Any) -> Any:
        """A copy of nested dicts, lists and tuples with every string (keys too) masked."""
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, dict):
            return {self.walk(k): self.walk(v) for k, v in value.items()}
        if isinstance(value, list | tuple):
            return type(value)(self.walk(v) for v in value)
        return value
