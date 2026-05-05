'''
@ASSESSME.USERID: hh3283
@ASSESSME.AUTHOR: 
@ASSESSME.DESCRIPTION: 
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY: LOW
'''

from dataclasses import dataclass, field
from typing import Any

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw

from utils.formatting import MISSING, format_ethertype, format_timestamp, safe_decode

TCP_FLAG_NAMES = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG"
}

HTTP_METHODS = {"GET","POST","PUT","DELETE","HEAD","OPTIONS","PATCH","TRACE","CONNECT"}

# Parsed packet data used by the table, details panel, and filters
@dataclass
class ParsedPacket:
    number: int
    timestamp: float | None
    time_display: str
    source: str = MISSING
    destination: str = MISSING
    protocol: str = "Unknown"
    length: int = 0
    info: str = ""
    raw_bytes: bytes = b""

    eth_src: str = MISSING
    eth_dst: str = MISSING
    ethertype: str = MISSING

    ip_version: str = MISSING
    ip_header_length: str = MISSING
    ip_src: str = MISSING
    ip_dst: str = MISSING
    ip_ttl: str = MISSING
    ip_protocol_number: str = MISSING
    ip_flags: str = MISSING
    ip_df: str = MISSING
    ip_mf: str = MISSING
    ip_fragment_offset: str = MISSING

    src_port: str = MISSING
    dst_port: str = MISSING
    tcp_flags: str = MISSING
    tcp_seq: str = MISSING
    tcp_ack: str = MISSING
    tcp_window: str = MISSING
    udp_length: str = MISSING

    icmp_type: str = MISSING
    icmp_code: str = MISSING

    arp_operation: str = MISSING
    arp_sender_mac: str = MISSING
    arp_sender_ip: str = MISSING
    arp_target_mac: str = MISSING
    arp_target_ip: str = MISSING

    dns_query: str = MISSING
    dns_query_type: str = MISSING
    http_request_line: str = MISSING
    tls_sni: str = MISSING

    parse_error: str | None = None
    layer_details: list[tuple[str, list[tuple[str, str]]]] = field(default_factory=list)

    def has_protocol(self, protocol_name: str) -> bool:
        wanted = protocol_name.upper()
        if wanted == "ALL":
            return True
        if self.protocol.upper() == wanted:
            return True
        if wanted == "TCP" and self.tcp_flags != MISSING:
            return True
        if wanted == "UDP" and self.udp_length != MISSING:
            return True
        if wanted == "ICMP" and self.icmp_type != MISSING:
            return True
        if wanted == "ARP" and self.arp_operation != MISSING:
            return True
        if wanted == "DNS" and self.dns_query != MISSING:
            return True
        if wanted == "HTTP" and self.http_request_line != MISSING:
            return True
        if wanted == "TLS" and self.tls_sni != MISSING:
            return True
        return False
    
# Convert a Scapy packet into our simpler ParsedPacket object
def parse_packet(packet: Packet, packet_number: int = 0) -> ParsedPacket:
    try:
        return _parse_packet(packet, packet_number)
    except Exception as exc:
        raw_bytes = _safe_bytes(packet)
        return ParsedPacket(
            number=packet_number,
            timestamp=getattr(packet, "time", None),
            time_display=format_timestamp(getattr(packet, "time", None)),
            protocol="Malformed",
            length=len(raw_bytes),
            info="Parse Error",
            raw_bytes=raw_bytes,
            parse_error=str(exc)
        )

    


def _parse_packet(packet:Packet, packet_number: int) -> ParsedPacket:
    raw_bytes = _safe_bytes(packet)
    parsed = ParsedPacket(
        number=packet_number,
        timestamp=getattr(packet, "time", None),
        time_display=format_timestamp(getattr(packet, "time", None)),
        length=len(raw_bytes),
        raw_bytes=raw_bytes
    )

    if packet.haslayer(Ether):
        _parse_ethernet(packet, parsed)

    if packet.haslayer(IP):
        _parse_ipv4(packet, parsed)

    if packet.haslayer(ARP):
        _parse_arp(packet, parsed)
    
    elif packet.haslayer(TCP):
        _parse_tcp(packet, parsed)

    elif packet.haslayer(UDP):
        _parse_udp(packet, parsed)

    elif packet.haslayer(ICMP):
        _parse_icmp(packet, parsed)
    
    if packet.haslayer(DNS):
        _parse_dns(packet, parsed)

    _parse_payload_protocols(packet,parsed)
    _finalize_display_fields(parsed)
    parsed.layer_details = build_layer_details(parsed)

    return parsed

def _safe_bytes(packet:Packet) -> bytes:
    try:
        return bytes(packet)
    except Exception:
        return b""
    
def _parse_ethernet(packet: Packet, parsed: ParsedPacket) -> None:
    ether = packet[Ether]
    parsed.eth_src = ether.src or MISSING
    parsed.eth_dst = ether.dst or MISSING
    parsed.ethertype = format_ethertype(getattr(ether, "type", None))
    parsed.source = parsed.eth_src
    parsed.destination = parsed.eth_dst
    parsed.protocol = "Ethernet"
    parsed.info = f"EtherType {parsed.ethertype}"

def _parse_ipv4(packet: Packet, parsed: ParsedPacket) -> None:
    ip_layer = packet[IP]
    parsed.ip_version = str(ip_layer.version)
    parsed.ip_header_length = f"{ip_layer.ihl * 4} bytes" if ip_layer.ihl else MISSING
    parsed.ip_src = ip_layer.src or MISSING
    parsed.ip_dst = ip_layer.dst or MISSING
    parsed.ip_ttl = str(ip_layer.ttl)
    parsed.ip_protocol_number = str(ip_layer.proto)

    flag_text = str(ip_layer.flags) or "0"
    parsed.ip_flags = flag_text
    parsed.ip_df = "Yes" if "DF" in flag_text else "No"
    parsed.ip_mf = "Yes" if "MF" in flag_text else "No"
    parsed.ip_fragment_offset = str(ip_layer.frag)

    parsed.source = parsed.ip_src
    parsed.destination = parsed.ip_dst
    parsed.protocol = "IP"
    parsed.info = f"Ipv4 proto {parsed.ip_protocol_number}"

def _parse_tcp(packet: Packet, parsed: ParsedPacket) -> None:
    tcp_layer = packet[TCP]
    parsed.src_port = str(tcp_layer.sport)
    parsed.dst_port = str(tcp_layer.dport)
    parsed.tcp_flags = _format_tcp_flags(tcp_layer.flags)
    parsed.tcp_seq = str(tcp_layer.seq)
    parsed.tcp_ack = str(tcp_layer.ack)
    parsed.tcp_window = str(tcp_layer.window)
    parsed.protocol = "TCP"
    parsed.info = f"{parsed.src_port} -> {parsed.dst_port} [{parsed.tcp_flags}]"

def _parse_udp(packet: Packet, parsed: ParsedPacket) -> None:
    udp_layer = packet[UDP]
    parsed.src_port = str(udp_layer.sport)
    parsed.dst_port = str(udp_layer.dport)
    parsed.udp_length = str(udp_layer.len) if udp_layer.len is not None else MISSING
    parsed.protocol = "UDP"
    parsed.info = f"{parsed.src_port} -> {parsed.dst_port}"

def _parse_icmp(packet: Packet, parsed: ParsedPacket) -> None:
    icmp_layer = packet[ICMP]
    parsed.icmp_type = str(icmp_layer.type)
    parsed.icmp_code = str(icmp_layer.code)
    parsed.protocol = "ICMP"
    parsed.info = f"Type {parsed.icmp_type}, Code {parsed.icmp_code}"

def _parse_arp(packet: Packet, parsed: ParsedPacket) -> None:
    arp_layer = packet[ARP]
    parsed.arp_operation = _arp_operation_name(arp_layer.op)
    parsed.arp_sender_mac = arp_layer.hwsrc or MISSING
    parsed.arp_sender_ip = arp_layer.psrc or MISSING
    parsed.arp_target_mac = arp_layer.hwdst or MISSING
    parsed.arp_target_ip = arp_layer.pdst or MISSING
    parsed.source = parsed.arp_sender_ip
    parsed.destination = parsed.arp_target_ip
    parsed.protocol = "ARP"
    parsed.info = f"{parsed.arp_operation}: {parsed.arp_sender_ip} -> {parsed.arp_target_ip}"

def _parse_dns(packet: Packet, parsed: ParsedPacket) -> None:
    dns_layer = packet[DNS]
    parsed.protocol = "DNS"

    question = _first_dns_question(dns_layer)
    if question is not None:
        parsed.dns_query = safe_decode(question.qname)
        parsed.dns_query_type = str(question.qtype)
        direction = "query" if dns_layer.qr == 0 else "response"
        parsed.info = f"DNS {direction}: {parsed.dns_query}"
    else:
        parsed.info = "DNS message"

def _first_dns_question(dns_layer: DNS) -> DNSQR | None:
    if not dns_layer.qd:
        return None
    if isinstance(dns_layer.qd, DNSQR):
        return dns_layer.qd
    try:
        first_question = dns_layer.qd[0]
    except (IndexError, TypeError):
        return None
    return first_question if isinstance(first_question, DNSQR) else None

def _format_tcp_flags(flags: Any) -> str:
    flag_string = str(flags)
    names = [name for short, name in TCP_FLAG_NAMES.items() if short in flag_string]
    return ", ".join(names) if names else "None"

def _arp_operation_name(value: int) -> str:
    names = {1: "Request", 2: "Reply"}
    return names.get(int(value),str(value))

# Detect simple application-layer protocols from the raw payload
def _parse_payload_protocols(packet: Packet, parsed:ParsedPacket) -> None:
    if not packet.haslayer(Raw):
        return
    
    payload = bytes(packet[Raw].load)
    http_line = _extract_http_line(payload)
    if http_line:
        parsed.http_request_line = http_line
        parsed.protocol = "HTTP"
        parsed.info = http_line

    tls_sni = _extract_tls_sni(payload)
    if tls_sni:
        parsed.tls_sni = tls_sni
        parsed.protocol = "TLS"
        parsed.info = f"TLS ClientHello SNI: {tls_sni}"

def _extract_http_line(payload: bytes) -> str | None:
    if not payload:
        return
    
    first_line = payload.split(b"\r\n",1)[0].decode("iso-8859-1", errors="ignore").strip()
    
    if not first_line:
        return None
    
    if first_line.startswith("HTTP/"):
        return first_line
    
    method = first_line.split(" ", 1)[0]
    if method in HTTP_METHODS and "HTTP/" in first_line:
        return first_line
    
    return None

def _extract_tls_sni(payload: bytes) -> str | None:
    try:
        if len(payload) < 5 or payload[0] != 0x16:
            return None
        
        record_length = int.from_bytes(payload[3:5], "big")
        record_end = min(5 + record_length, len(payload))
        pos = 5
        if record_end - pos < 4 or payload[pos] !=0x01:
            return None
        
        handshake_length = int.from_bytes(payload[pos +1 : pos +4], "big")
        handshake_end = min(pos + 4 + handshake_length, record_end)
        pos += 4

        if handshake_end - pos <34:
            return None
        pos += 34

        session_id_length = payload[pos]
        pos += 1 + session_id_length
        if pos +2 > handshake_end:
            return None
        
        chiper_suites_length = int.from_bytes(payload[pos : pos +2], "big")
        pos += 2 + chiper_suites_length
        if pos>= handshake_end:
            return None
        
        compression_methods_length = payload[pos]
        pos += 1 + compression_methods_length
        if pos + 2 > handshake_end:
            return None
        
        extension_length = int.from_bytes(payload[pos : pos + 2], "big")
        pos += 2
        extension_end = min(pos + extension_length, handshake_end)

        while pos + 4 <= extension_end:
            ext_type = int.from_bytes(payload[pos : pos + 2], "big")
            ext_length = int.from_bytes(payload[pos + 2 : pos + 4], "big")
            ext_data_start = pos + 4
            ext_data_end = ext_data_start + ext_length
            if ext_data_end > extension_end:
                return None
            
            if ext_type == 0:
                return _extract_server_name(payload[ext_data_start:ext_data_end])
            
            pos = ext_data_end
    except (IndexError, ValueError):
        return None
    
    return None

def _extract_server_name(extension_data: bytes) -> str | None:
    if len(extension_data) < 2:
        return None
    
    list_length = int.from_bytes(extension_data[:2], "big")
    pos = 2
    list_end = min(2 + list_length, len(extension_data))
    while pos + 3 <= list_end:
        name_type = extension_data[pos]
        name_length = int.from_bytes(extension_data[pos + 1 : pos + 3], "big")
        pos += 3
        name_end = pos + name_length
        if name_end > list_end:
            return None
        if name_type == 0:
            return extension_data[pos:name_end].decode("idna", errors="ignore") 
        pos = name_end
    
    return None

def _finalize_display_fields(parsed: ParsedPacket) -> None:
    if not parsed.info:
        parsed.info = parsed.protocol
    if not parsed.source:
        parsed.source = MISSING
    if not parsed.destination:
        parsed.destination = MISSING

def build_layer_details(parsed: ParsedPacket) -> list[tuple[str, list[tuple[str, str]]]]:
    sections: list[tuple[str, list[tuple[str,str]]]] = []

    if parsed.eth_src != MISSING or parsed.eth_dst != MISSING:
        sections.append(
            (
                "Ethernet II",
                [
                    ("Source", parsed.eth_src),
                    ("Destination", parsed.eth_dst),
                    ("EtherType",parsed.ethertype)
                ]
            )
        )

    if parsed.ip_src != MISSING or parsed.ip_dst != MISSING:
        sections.append(
            (
                "Internet Protocol v4",
                [
                    ("Version", parsed.ip_version),
                    ("Header Length", parsed.ip_header_length),
                    ("Source",parsed.ip_src),
                    ("Destination",parsed.ip_dst),
                    ("TTL",parsed.ip_ttl),
                    ("Protocol Number",parsed.ip_protocol_number),
                    ("Flags",parsed.ip_flags),
                    ("Don't Fragment",parsed.ip_df),
                    ("More Fragments",parsed.ip_mf),
                    ("Fragment Offset",parsed.ip_fragment_offset)
                ]
            )
        )

    if parsed.tcp_flags != MISSING and parsed.src_port != MISSING:
        sections.append(
            (
                "Transmission Control Protocol",
                [
                    ("Source Port",parsed.src_port),
                    ("Destination Port",parsed.dst_port),
                    ("Flags",parsed.tcp_flags),
                    ("Sequence Number",parsed.tcp_seq),
                    ("Acknowledgment Number",parsed.tcp_ack),
                    ("Window Size", parsed.tcp_window)
                ]
            )
        )
    
    if parsed.protocol in {"UDP","DNS"} and parsed.udp_length != MISSING:
        sections.append(
            (
                "User datagram Protocol",
                [
                    ("Source Port", parsed.src_port),
                    ("Destination Port",parsed.dst_port),
                    ("Length",parsed.udp_length)
                ]
            )
        )

    if parsed.icmp_type != MISSING:
        sections.append(
            (
                "Internet Control Message Protocol",
                [
                    ("Type",parsed.icmp_type),
                    ("Code",parsed.icmp_code)
                ]
            )
        )
        
    if parsed.arp_operation != MISSING:
        sections.append(
            (
                "Adress Resolution Protocol",
                [
                    ("Operation", parsed.arp_operation),
                    ("Sender MAC", parsed.arp_sender_mac),
                    ("Sender IP", parsed.arp_sender_ip),
                    ("Target MAC", parsed.arp_target_mac),
                    ("Target IP", parsed.arp_target_ip),
                ]
            )
        )
    
    if parsed.dns_query != MISSING:
        sections.append(
            (
                "Domain Name System",
                [
                    ("Query Name", parsed.dns_query),
                    ("Query Type",parsed.dns_query_type)
                ]
            )
        )

    if parsed.http_request_line != MISSING:
        sections.append(
            (
                "Hypertext Transfer Protocol",
                [
                    ("Request/Status Line",parsed.http_request_line)
                ]
            )
        )

    if parsed.tls_sni != MISSING:
        sections.append(
            (
                "Transport Layer Security",
                [
                    ("Server Name Indication",parsed.tls_sni)
                ]
            )
        )
    
    return sections