from __future__ import annotations

import base64

import pytest

from dns_answer_parser.bin.splunk_dns_answer_parser import parse_dns_message_base64


def test_parses_sample_dns_payload(sample_dns_b64: str) -> None:
    parsed = parse_dns_message_base64(sample_dns_b64)
    assert parsed.query_count == 1
    assert parsed.answer_count == 0
    assert parsed.authority_count == 1
    assert parsed.additional_count == 0
    assert len(parsed.records) == 1

    record = parsed.records[0]
    assert record.section == "authority"
    assert record.name == "google.com"
    assert record.rtype == "SOA"
    assert "ns1.google.com" in record.value
    assert "dns-admin.google.com" in record.value


def test_rejects_empty_input() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        parse_dns_message_base64("")


def test_rejects_invalid_base64() -> None:
    with pytest.raises(ValueError, match="Invalid base64"):
        parse_dns_message_base64("%%%notbase64%%%")


def test_rejects_truncated_wire_payload() -> None:
    truncated = base64.b64encode(b"\x00\x01\x81\x80").decode("ascii")
    with pytest.raises(ValueError, match="too short"):
        parse_dns_message_base64(truncated)
