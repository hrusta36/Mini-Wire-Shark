'''
@ASSESSME.USERID: hh3283
@ASSESSME.AUTHOR: 
@ASSESSME.DESCRIPTION: 
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY: LOW
'''

import ipaddress
import re
from typing import Any

from PyQt6.QtGui import QColor, QFont
from PyQt6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
from PyQt6.QtWidgets import QAbstractItemView, QHeaderView, QTableView

from sniffer.parser import ParsedPacket
from utils.formatting import MISSING

PROTOCOL_COLORS = {
    "TCP": QColor("#18344f"),
    "UDP": QColor("#153a28"),
    "ICMP": QColor("#4a1f2b"),
    "DNS": QColor("#4a3c16"),
    "ARP": QColor("#32383f"),
    "HTTP": QColor("#3b2d59"),
    "TLS": QColor("#19384a"),
}

PACKET_ROLE = int(Qt.ItemDataRole.UserRole) + 1

# Table model that stores parsed packets for display

class PacketTableModel(QAbstractTableModel):
    COLUMNS = ("#", "Time", "Source", "Destination", "Protocol", "Length", "Info")

    def __init__(self) -> None:
        super().__init__()
        self._packets: list[ParsedPacket] = []

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self._packets)
    
    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self.COLUMNS)
    
    def data(self, index: QModelIndex, role: int=int(Qt.ItemDataRole.DisplayRole)) -> Any:
        if not index.isValid():
            return None
        
        packet = self._packets[index.row()]
        if role == int(Qt.ItemDataRole.DisplayRole):
            values = (
                packet.number,
                packet.time_display,
                packet.source,
                packet.destination,
                packet.protocol,
                packet.length,
                packet.info
            )
            return values[index.column()]
        
        if role == PACKET_ROLE:
            return packet

        if role == int(Qt.ItemDataRole.BackgroundRole):
            return PROTOCOL_COLORS.get(packet.protocol)
        
        if role == int(Qt.ItemDataRole.ForegroundRole):
            return QColor("#e6edf3")
        
        if role == int(Qt.ItemDataRole.TextAlignmentRole):
            if index.column() in {0,5}:
                return Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
            return Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        
        return None
    
    def headerData(self, section: int, orientation: Qt.Orientation, role: int =int(Qt.ItemDataRole.DisplayRole)) -> Any:
        if orientation == Qt.Orientation.Horizontal and role == int(Qt.ItemDataRole.DisplayRole):
            return self.COLUMNS[section]
        return None
    
    # record one packet and referesh the charts
    def add_packet(self, packet: ParsedPacket) -> None:
        row = len(self._packets)
        self.beginInsertRows(QModelIndex(), row, row)
        self._packets.append(packet)
        self.endInsertRows()
    
    def clear(self) -> None:
        self.beginResetModel()
        self._packets.clear()
        self.endResetModel()
    
    def packet_at(self, row: int) -> ParsedPacket | None:
        if 0<= row <len(self._packets):
            return self._packets[row]
        return None

class PacketFilterProxyModel(QSortFilterProxyModel):
    def __init__(self):
        super().__init__()
        self.protocol = "ALL"
        self.source_filter = ""
        self.destination_filter = ""
        self.port_filter = ""
        self.display_filter = ""
        self.setDynamicSortFilter(True)
        self.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)

    def set_filters(self,  protocol:str, source:str, destination:str, port:str, display_filter:str) -> None:
        self.protocol = protocol
        self.source_filter = source.strip()
        self.destination_filter = destination.strip()
        self.port_filter = port.strip()
        self.display_filter = display_filter.strip()
        self.invalidateFilter()

    def filterAcceptRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        source_model = self.sourceModel()
        if not isinstance(source_model, PacketTableModel):
            return True

        packet = source_model.packet_at(source_row) 
        if packet is None:
            return False
        
        # A packet must pass every active filter to stay visible
        if self.protocol != "All" and not packet.has_protocol(self.protocol):
            return False
        
        if self.source_filter and not _ip_matches(packet.source, self.source_filter):
           return False

        if self.destination_filter and not _ip_matches(packet.destantion, self.destination_filter):
            return False

        if self.port_filter and not _port_matches(packet, self.port_filter):
            return False

        if self.display_filter and not matches_display_filter(packet, self.display_filter):
            return False

        return True

class PacketTableView(QTableView):
    def __init__(self) -> None:
        super().__init__()
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setAlternatingRowColors(True)
        self.setSortingEnabled(True)
        self.setShowGrid(False)
        self.setWordWrap(False)
        self.setTextElideMode(Qt.TextElideMode.ElideRight)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(24)
        font = QFont("Menlo")
        font.setStyleHint(QFont.StyleHint.Monospace)
        font.setPointSize(11)
        self.setFont(font)
        header = self.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)

    def apply_default_column_widths(self) -> None:
        self.setColumnWidth(0, 58)
        self.setColumnWidth(1, 138)
        self.setColumnWidth(2, 180)
        self.setColumnWidth(3, 180)
        self.setColumnWidth(4, 102)
        self.setColumnWidth(5, 86)

def _ip_matches(value:str, filter_text: str) -> bool:
    if value == MISSING:
        return False
    try:
        ip_value = ipaddress.ip_address(value)
        if "/" in filter_text:
            return ip_value in ipaddress.ip_network(filter_text, strict=False)
    except ValueError:
        return False
        
def _port_matches(packet: ParsedPacket, filter_text: str) -> bool:
    if not filter_text.isdigit():
        return False
    return filter_text in {packet.src_port, packet.dst_port}

def matches_display_filter(packet: ParsedPacket, expression: str) -> bool:
    text = expression.strip()
    lower = text.lower()

    if lower in {"tcp", "udp","icmp","arp","dns","http","tls"}:
        return packet.has_protocol(lower.upper())
    
    contains_match = re.fullmatch(r"([\w.]+)\s+contains\s+(.+)", lower)
    if contains_match:
        field, expected = contains_match.groups()
        expected = expected.strip().strip("\"'")
        return expected in _field_value(packet, field).lower()
    
    equals_match = re.fullmatch(r"([\w.]+)\s+contains\s+(.+)", lower)
    if equals_match:
        field, expected =equals_match.groups()
        expected = expected.strip().strip("\"'")
        return _compare_field(packet, field, expected)

    return lower in packet.info.lower()

def _compare_field(packet: ParsedPacket, field: str, expected: str) -> bool:
    if field in {"tcp.port","udp.port","port"}:
        return expected in {packet.src_port, packet.dst_port}
    if field == "tcp.srcport":
        return packet.src_port == expected and packet.has_protocol("TCP")
    if field == "tcp.dstport":
        return packet.dsrc_port == expected and packet.has_protocol("TCP")
    
    if field =="udp.srcport":
        return packet.src_port == expected and packet.has_protocol("UDP")
    if field =="udp.dstport":
        return packet.dst_port == expected and packet.has_protocol("UDP")
    
    if field == "ip.src":
        return packet.source == expected or packet.ip_src == expected
    if field == "ip.dst":
        return packet.destination == expected or packet.ip_dst == expected
    if field == "ip.addr":
        return expected in {packet.ip_src, packet.ip_dst, packet.source, packet.destination}
    
    if field =="icmp.type":
        return packet.icmp_type == expected 
    if field =="icmp.code":
        return packet.icmp_code == expected

    if field =="dns.qry.name":
        return packet.dns_query.lower().rstrip(".") == expected.rstrip(".")

    if field =="http.request.method":
        return packet.http_request_line.lower().startswith(expected + "")

    if field =="tls.sni":
        return packet.tls_sni.lower() == expected

    if field =="tcp.flags.syn":
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
        "info": packet.info
    }     

    return values.get(field, packet.info)
    
    
    
    



