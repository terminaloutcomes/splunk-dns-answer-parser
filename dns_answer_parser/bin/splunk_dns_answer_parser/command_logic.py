from __future__ import annotations

from typing import Any

from .parser import parse_dns_message_base64


def parse_event_record(record: dict[str, Any], field: str) -> dict[str, Any]:
    payload = record.get(field)
    if payload is None:
        record["dnsparse_error"] = f"Field '{field}' does not exist on event"
        return record

    try:
        parsed = parse_dns_message_base64(str(payload))
    except ValueError as exc:
        record["dnsparse_error"] = str(exc)
        return record

    record["dnsparse_values"] = parsed.values()
    record["dnsparse_records"] = [
        f"{r.section}:{r.name}:{r.rtype}:{r.ttl}:{r.value}" for r in parsed.records
    ]
    record["dnsparse_query_count"] = parsed.query_count
    record["dnsparse_answer_count"] = parsed.answer_count
    record["dnsparse_authority_count"] = parsed.authority_count
    record["dnsparse_additional_count"] = parsed.additional_count
    return record
