from .command_logic import parse_event_record
from .parser import DNSRecord, ParsedDNSMessage, parse_dns_message_base64

__all__ = [
    "DNSRecord",
    "ParsedDNSMessage",
    "parse_dns_message_base64",
    "parse_event_record",
]


def main():
    import sys

    if not sys.argv[1:]:
        print("Usage: splunk_dns_answer_parser <base64_dns_message>")
        sys.exit(1)

    b64_message = sys.argv[1]
    try:
        parsed = parse_dns_message_base64(b64_message)
        print(parsed)
    except ValueError as exc:
        print(f"Error parsing DNS message: {exc}")
        sys.exit(1)
