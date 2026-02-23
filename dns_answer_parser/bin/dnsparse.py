#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
from typing import Any, Iterable


APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_PARENT = os.path.dirname(APP_ROOT)
if APP_PARENT not in sys.path:
    sys.path.insert(0, APP_PARENT)

from dns_answer_parser.bin.splunk_dns_answer_parser import parse_event_record  # noqa: E402

try:
    from splunklib.searchcommands import Option, StreamingCommand, dispatch  # ty:ignore[unresolved-import]
except ImportError as exc:
    raise SystemExit(
        "splunklib.searchcommands is required in Splunk runtime. "
        "Install Splunk Python SDK in development if needed."
    ) from exc


class DNSParseCommand(StreamingCommand):
    field = Option(require=True)

    def stream(self, records: Iterable[dict[str, Any]]) -> Iterable[dict[str, Any]]:
        for record in records:
            yield parse_event_record(record, str(self.field))


dispatch(DNSParseCommand, sys.argv, sys.stdin, sys.stdout, __name__)
