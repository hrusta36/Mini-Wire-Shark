'''
@ASSESSME.USERID: JuricaJamic
@ASSESSME.AUTHOR: 
@ASSESSME.DESCRIPTION: 
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY: LOW
'''

from dataclasses import dataclass

from PyQt6.QtCore import QThread, pyqtSignal
from scapy.all import conf, get_if_list, rdpcap, sniff
from sniffer.parser import parse_packet

@dataclass (frozen=True)
class InterfaceInfo:
    name: str
    display_name: str

# Get the network interfaces that Scapy can capture from 
def list_interfaces() -> list[InterfaceInfo]:
    interfaces: list[InterfaceInfo] = []
    try:
        for name in get_if_list():
            label = name
            try:
                iface = conf.ifaces.get(name)
                description = getattr(iface, "description", None)
                if description and description !=name:
                    label = f"{description} ({name})"
            except Exception:
                label = name
            interfaces.append(InterfaceInfo(name=name, display_name=label))
    except Exception:
        return []
    return interfaces

# Worker Thread for live packet capture
class CaptureThread(QThread):
    packet_captured = pyqtSignal(object)
    capture_error = pyqtSignal(str)
    status_message = pyqtSignal(str)

    def __init__(self, interface: str | None, bpf_filter: str = "") -> None:
        super().__init__()
        self.interface = interface
        self.bpf_filter = bpf_filter.strip()
        self._stop_requested = False
        self._packet_number = 0

    def stop(self) -> None:

        self._stop_requested = True
    
    def run(self) -> None:
        self.status_message.emit(f"Capturing on {self.interface or 'default interface'}")
        try:
            while not self._stop_requested:
                # Sniff in short time windows so stopping the thread is responsive
                sniff_kwargs = {
                    "iface":self.interface,
                    "prn": self._handle_packet,
                    "store": False,
                    "timeout": 1,
                    "stop_filter": lambda _packet: self._stop_requested,
                }
                if self.bpf_filter:
                    sniff_kwargs["filter"] = self.bpf_filter
                sniff(**sniff_kwargs)
        except Exception as exc:
            self.capture_error.emit(str(exc))
        finally:
            self.status_message.emit("Capture stopped")

    def _handle_packet(self, packet: object) -> None:

        if self._stop_requested:
            return
        self._packet_number += 1
        parsed = parse_packet(packet, self._packet_number)
        if parsed.parse_error:
            self.capture_error.emit(f"Skipped malformed packet #{self._packet_number}: {parsed.parse_error}")
            return
        self.packet_captured.emit(parsed)

# Worker thread for loading packets from a  saved pcap file
class PcapLoaderThread(QThread):

    packet_loaded = pyqtSignal(object)
    load_error = pyqtSignal(str)
    status_message = pyqtSignal(str)

    def __init__(self, path:str) -> None:

        super().__init__()
        self.path = path
        self._stop_requested = False

    def stop(self) -> None:

        self._stop_requested = True

    def run(self) -> None:
        try:
            self.status_message.emit(f"Loading {self.path}")
            packets = rdpcap(self.path)
            for index, packet in enumerate(packets, start=1):
                if self._stop_requested:
                    break
                parsed = parse_packet(packet,index)
                if parsed.parse_error:
                    self.load_error.emit(f"Skipped malformed packet #{index}: {parsed.parse_error}")
                    continue
                self.packet_loaded.emit(parsed)
            self.status_message.emit(f"Loaded {min(len(packets), index if packets else 0)} packets")
        except Exception as exc:
            self.load_error.emit(str(exc))

