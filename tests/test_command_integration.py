from __future__ import annotations

from typing import Any

from dns_answer_parser.bin.splunk_dns_answer_parser import parse_event_record


def test_parse_event_record_emits_expected_output_shape(sample_dns_b64: str) -> None:
    event: dict[str, Any] = {"response_b64": sample_dns_b64, "host": "example-host"}
    parsed_event = parse_event_record(event, "response_b64")

    assert parsed_event["host"] == "example-host"
    assert "dnsparse_error" not in parsed_event
    assert isinstance(parsed_event["dnsparse_values"], list)
    assert isinstance(parsed_event["dnsparse_records"], list)
    assert isinstance(parsed_event["dnsparse_query_count"], int)
    assert isinstance(parsed_event["dnsparse_answer_count"], int)
    assert isinstance(parsed_event["dnsparse_authority_count"], int)
    assert isinstance(parsed_event["dnsparse_additional_count"], int)
    assert parsed_event["dnsparse_query_count"] == 1
    assert parsed_event["dnsparse_authority_count"] == 1


def test_parse_event_record_sets_error_for_missing_field() -> None:
    parsed_event = parse_event_record({"some_other_field": "value"}, "response_b64")
    assert "dnsparse_error" in parsed_event
