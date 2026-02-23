from __future__ import annotations

import base64
import ipaddress
import struct
from dataclasses import dataclass
from typing import Sequence


_TYPE_NAMES: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    257: "CAA",
}


@dataclass(frozen=True)
class DNSRecord:
    section: str
    name: str
    rtype: str
    ttl: int
    value: str


@dataclass(frozen=True)
class ParsedDNSMessage:
    query_count: int
    answer_count: int
    authority_count: int
    additional_count: int
    records: list[DNSRecord]

    def values(self) -> list[str]:
        return [record.value for record in self.records]


def parse_dns_message_base64(encoded: str) -> ParsedDNSMessage:
    if not encoded or not encoded.strip():
        raise ValueError("DNS payload must be a non-empty base64 string")
    try:
        wire = base64.b64decode(encoded, validate=True)
    except Exception as exc:  # pragma: no cover - exact exception varies by implementation
        raise ValueError("Invalid base64 DNS payload") from exc
    return _parse_dns_wire_message(wire)


def _parse_dns_wire_message(wire: bytes) -> ParsedDNSMessage:
    if len(wire) < 12:
        raise ValueError("DNS wire payload is too short")

    _, _, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", wire[:12])
    offset = 12

    for _ in range(qdcount):
        _, offset = _read_name(wire, offset)
        offset = _require_slice(wire, offset, 4)

    records: list[DNSRecord] = []
    offset = _parse_rr_section(wire, offset, ancount, "answer", records)
    offset = _parse_rr_section(wire, offset, nscount, "authority", records)
    _ = _parse_rr_section(wire, offset, arcount, "additional", records)

    return ParsedDNSMessage(
        query_count=qdcount,
        answer_count=ancount,
        authority_count=nscount,
        additional_count=arcount,
        records=records,
    )


def _parse_rr_section(
    wire: bytes, offset: int, count: int, section: str, target: list[DNSRecord]
) -> int:
    for _ in range(count):
        name, offset = _read_name(wire, offset)
        offset = _require_slice(wire, offset, 10)
        rtype_num, _, ttl, rdlength = struct.unpack("!HHIH", wire[offset - 10 : offset])
        rdata_start = offset
        rdata_end = _require_slice(wire, rdata_start, rdlength)
        value = _decode_rdata(wire, rtype_num, rdata_start, rdlength)
        target.append(
            DNSRecord(
                section=section,
                name=name,
                rtype=_TYPE_NAMES.get(rtype_num, f"TYPE{rtype_num}"),
                ttl=ttl,
                value=value,
            )
        )
        offset = rdata_end
    return offset


def _decode_rdata(wire: bytes, rtype_num: int, rdata_offset: int, rdlength: int) -> str:
    rdata = wire[rdata_offset : rdata_offset + rdlength]
    if rtype_num == 1 and rdlength == 4:
        return str(ipaddress.IPv4Address(rdata))
    if rtype_num == 28 and rdlength == 16:
        return str(ipaddress.IPv6Address(rdata))
    if rtype_num in {2, 5, 12}:
        domain, _ = _read_name(wire, rdata_offset)
        return domain
    if rtype_num == 15:
        if rdlength < 3:
            return _hex(rdata)
        preference = struct.unpack("!H", rdata[:2])[0]
        exchange, _ = _read_name(wire, rdata_offset + 2)
        return f"{preference} {exchange}"
    if rtype_num == 16:
        return _decode_txt_strings(rdata)
    if rtype_num == 6:
        return _decode_soa(wire, rdata_offset, rdlength)
    if rtype_num == 33:
        return _decode_srv(wire, rdata_offset, rdlength)
    if rtype_num == 257:
        return _decode_caa(rdata)
    return _hex(rdata)


def _decode_txt_strings(rdata: bytes) -> str:
    offset = 0
    parts: list[str] = []
    while offset < len(rdata):
        length = rdata[offset]
        offset += 1
        end = offset + length
        if end > len(rdata):
            break
        parts.append(rdata[offset:end].decode("utf-8", errors="replace"))
        offset = end
    return " ".join(parts)


def _decode_soa(wire: bytes, rdata_offset: int, rdlength: int) -> str:
    end = rdata_offset + rdlength
    mname, offset = _read_name(wire, rdata_offset)
    rname, offset = _read_name(wire, offset)
    if offset + 20 > end:
        return f"{mname} {rname}"
    serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", wire[offset : offset + 20])
    return f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"


def _decode_srv(wire: bytes, rdata_offset: int, rdlength: int) -> str:
    if rdlength < 7:
        return _hex(wire[rdata_offset : rdata_offset + rdlength])
    priority, weight, port = struct.unpack("!HHH", wire[rdata_offset : rdata_offset + 6])
    target, _ = _read_name(wire, rdata_offset + 6)
    return f"{priority} {weight} {port} {target}"


def _decode_caa(rdata: bytes) -> str:
    if len(rdata) < 2:
        return _hex(rdata)
    flags = rdata[0]
    tag_len = rdata[1]
    if 2 + tag_len > len(rdata):
        return _hex(rdata)
    tag = rdata[2 : 2 + tag_len].decode("ascii", errors="replace")
    value = rdata[2 + tag_len :].decode("utf-8", errors="replace")
    return f"{flags} {tag} {value}"


def _read_name(wire: bytes, start_offset: int) -> tuple[str, int]:
    labels: list[str] = []
    offset = start_offset
    consumed_offset = start_offset
    jumped = False
    jumps = 0

    while True:
        if offset >= len(wire):
            raise ValueError("DNS name exceeds payload bounds")

        length = wire[offset]
        if length == 0:
            if not jumped:
                consumed_offset = offset + 1
            break

        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(wire):
                raise ValueError("Incomplete DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | wire[offset + 1]
            if pointer >= len(wire):
                raise ValueError("DNS compression pointer out of bounds")
            if not jumped:
                consumed_offset = offset + 2
            offset = pointer
            jumped = True
            jumps += 1
            if jumps > 32:
                raise ValueError("Too many DNS compression jumps")
            continue

        offset += 1
        label_end = offset + length
        if label_end > len(wire):
            raise ValueError("DNS label exceeds payload bounds")
        labels.append(wire[offset:label_end].decode("utf-8", errors="replace"))
        offset = label_end
        if not jumped:
            consumed_offset = offset

    return ".".join(labels), consumed_offset


def _require_slice(wire: Sequence[int], start: int, length: int) -> int:
    end = start + length
    if end > len(wire):
        raise ValueError("DNS payload is truncated")
    return end


def _hex(data: bytes) -> str:
    return data.hex()
