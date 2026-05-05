'''
@ASSESSME.USERID: dh3137
@ASSESSME.AUTHOR: 
@ASSESSME.DESCRIPTION: 
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY: LOW
'''

import ipaddress
import re

from sniffer.parser import ParsedPacket
from utils.formatting import MISSING


def ip_matches(value:str, filter_text: str) -> bool:
    if value == MISSING:
        return False
    try:
        ip_value = ipaddress.ip_address(value)
        if "/" in filter_text:
            return ip_value in ipaddress.ip_network(filter_text, strict=False)
        return ip_value == ipaddress.ip_address(filter_text)
    except ValueError:
        return False
    
    
def port_matches(packet: ParsedPacket, filter_text: str) -> bool:
    if not filter_text.isdigit():
        return False
    return filter_text in {packet.src_port, packet.dst_port}


def matches_display_filter(packet: ParsedPacket, expression: str) -> bool:
    text = expression.strip()
    lower = text.lower()
    
    if lower in {"tcp", "udp", "icmp", "arp", "dns", "http", "tls"}:
        return packet.has_protocol(lower.upper())
    
    contains_match = re.fullmatch(r"([\w.]+)\s+contains\s+(.+)", lower)
    if contains_match:
        field, expected = contains_match.groups()
        expected = expected.strip().strip("\"'")
        return expected in _field_value(packet, field).lower()
    
    equals_match = re.fullmatch(r"([\w.]+)\s*==\s*(.+)", lower)
    if equals_match:
        field, expected = equals_match.groups()
        expected = expected.strip().strip("\"'")
        return _compare_field(packet, field, expected)
    
    return lower in packet.info.lower()


def _compare_field(packet: ParsedPacket, field: str, expected: str) -> bool:
    if field in {"tcp.port", "udp.port", "port"}:
        return expected in {packet.src_port, packet.dst_port}
    if field == "tcp.srcport":
        return packet.src_port == expected and packet.has_protocol("TCP")
    if field == "tcp.dstport":
        return packet.dst_port == expected and packet.has_protocol("TCP")
    if field == "udp.srcport":
        return packet.src_port == expected and packet.has_protocol("UDP")
    if field == "udp.dstport":
        return packet.dst_port == expected and packet.has_protocol("UDP")
    if field == "ip.src":
        return packet.source == expected or packet.ip_src == expected
    if field == "ip.dst":
        return packet.destination == expected or packet.ip_dst == expected
    if field == "ip.addr":
        return expected in {packet.ip_src, packet.ip_dst, packet.source, packet.destination}
    if field == "icmp.type":
        return packet.icmp_type == expected
    if field == "icmp.code":
        return packet.icmp_code == expected
    if field == "dns.qry.name":
        return packet.dns_query.lower().rstrip(".") == expected.rstrip(".")
    if field == "https.request.method":
        return packet.http_request_line.lower().startswith(expected + " ")
    if field == "tls.sni":
        return packet.tls_sni.lower() == expected
    if field == "tcp.flags.syn":
        return ("syn" in packet.tcp_flags.lower()) == (expected in {"1", "true", "yes"})
    return False


def _field_value(packet: ParsedPacket, field: str) -> str:
    values = {
        "dns.qry.name": packet.dns_query,
        "http": packet.http_request_line,
        "http.request": packet.http_request_line,
        "tls.sni": packet.tls_sni,
        "ip.src": packet.ip_src,
        "ip.dst": packet.ip_dst,
        "info": packet.info,
    }
    
    return values.get(field, packet.info)