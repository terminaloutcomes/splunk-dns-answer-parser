from __future__ import annotations

from functools import lru_cache
from typing import Any

from .parser import parse_dns_message_base64


class InvocationCache:
    def __init__(self, maxsize: int = 1024 * 1024) -> None:
        self._parse_payload = lru_cache(maxsize=maxsize)(self._parse_payload_uncached)

    def parse_event_record(self, record: dict[str, Any], field: str) -> dict[str, Any]:
        payload = record.get(field)
        if payload is None or not isinstance(payload, str):
            record["dnsparse_error"] = (
                f"Field '{field}' does not exist on event or isn't a string!"
            )
            return record

        for key, value in self._parse_payload(payload).items():
            if isinstance(value, list):
                record[key] = list(value)
            else:
                record[key] = value
        return record

    def cache_info(self) -> Any:
        return self._parse_payload.cache_info()

    def _parse_payload_uncached(self, payload: str) -> dict[str, Any]:
        try:
            parsed = parse_dns_message_base64(payload)
        except ValueError as exc:
            return {"dnsparse_error": str(exc)}

        return {
            "dnsparse_values": parsed.values(),
            "dnsparse_records": [
                f"{r.section}:{r.name}:{r.rtype}:{r.ttl}:{r.value}"
                for r in parsed.records
            ],
            "dnsparse_query_count": parsed.query_count,
            "dnsparse_answer_count": parsed.answer_count,
            "dnsparse_authority_count": parsed.authority_count,
            "dnsparse_additional_count": parsed.additional_count,
        }
