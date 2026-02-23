#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
from typing import Any, Iterable


APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_PARENT = os.path.dirname(APP_ROOT)
LIB_PATH = os.path.join(APP_ROOT, "lib")
if APP_PARENT not in sys.path:
    sys.path.insert(0, APP_PARENT)
if LIB_PATH not in sys.path:
    sys.path.insert(0, LIB_PATH)

from dns_answer_parser.bin.splunk_dns_answer_parser import parse_event_record  # noqa: E402

try:
    from splunklib.searchcommands import Configuration, Option, StreamingCommand, dispatch
except ImportError as exc:
    raise SystemExit(
        "splunklib.searchcommands is required in Splunk runtime. "
        "Install Splunk Python SDK in development if needed."
    ) from exc


@Configuration()
class DNSParseCommand(StreamingCommand):
    field = Option(require=True)

    def stream(self, records: Iterable[dict[str, Any]]) -> Iterable[dict[str, Any]]:
        if getattr(self.metadata, "preview", False):
            for record in records:
                yield record
            return

        for record in records:
            try:
                yield parse_event_record(record, str(self.field))
            except Exception as exc:  # pragma: no cover - defensive for Splunk runtime safety
                record["dnsparse_error"] = f"Unexpected dnsparse failure: {exc}"
                yield record


dispatch(DNSParseCommand, sys.argv, sys.stdin, sys.stdout, __name__)
