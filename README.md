# Packet Sniffer

Mini Wireshark-style packet sniffer made for NSSA-290 course.

## Features

- Live packet capture from a selectable Scapy interface.
- Offline `.pcap` and `.pcapng` loading through File > Open.
- Background `QThread` workers for live capture and offline loading.
- Parsed Ethernet, IPv4, TCP, UDP, ICMP, ARP, DNS, HTTP, and TLS SNI fields.
- Packet table with protocol row colors and non-destructive live filtering.
- Protocol, source CIDR, destination CIDR, port, and simple display filters.
- Details tree with layered protocol breakdown.
- Hex and ASCII packet bytes.
- Live statistics: total packets, protocol bar chart, packet-rate chart, and top talkers.

## Setup on macOS

Use Python 3.12 for this project.

```bash
cd /Users/danisharmandic/Desktop/networking-project/packet_sniffer
python3.12 -m venv .venv312
source .venv312/bin/activate
pip install -r requirements.txt
python src/main.py
```

If you already have the `.venv312` folder from development, run:

```bash
cd /Users/danisharmandic/Desktop/networking-project/packet_sniffer
source .venv312/bin/activate
python src/main.py
```

## Setup on Windows

1. Install Python 3.10, 3.11, or 3.12.
2. Install Npcap from <https://npcap.com/>.
3. Open PowerShell in the project folder.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python src\main.py
```

Run PowerShell as Administrator if live capture cannot access interfaces.

## Setup on Linux

```bash
cd packet_sniffer
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python src/main.py
```

Live capture usually needs privileges. Preferred non-root setup:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
```

You can also run with `sudo`, but use the virtual environment carefully.

## Live Capture Permissions

- Windows: install Npcap and run as Administrator if needed.
- macOS: run with `sudo`, or configure ChmodBPF for non-root capture.
- Linux: use `setcap` as shown above, or run with `sudo`.

Only capture traffic on networks you own or have explicit permission to monitor.
The app also shows this ethics reminder on first startup.

## How to Use

1. Pick an interface from the dropdown.
2. Click Start or press Ctrl+E.
3. Click Stop or press Ctrl+S.
4. Select a packet to inspect parsed layers and the hex/ASCII dump.
5. Use File > Open to load `tests/sample.pcap` or another capture file.
6. Use filters to narrow visible rows without deleting captured packets.

Supported display-filter examples:

```text
tcp
dns
tcp.port == 443
udp.port == 53
ip.src == 192.168.1.10
ip.addr == 10.0.0.5
dns.qry.name == rit.edu
http contains GET
tls.sni == example.com
```

Invalid IP/CIDR or port filters intentionally match no rows so mistakes are visible.
