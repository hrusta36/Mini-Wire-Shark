'''
@ASSESSME.USERID: hh3283
@ASSESSME.AUTHOR: 
@ASSESSME.DESCRIPTION: 
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY: LOW
'''

from datetime import datetime

MISSING = "\N{EM DASH}"

def format_timestamp(timestamp: float | int | None) ->str:
    if timestamp is None:
        return MISSING
    
    try:
        dt = datetime.fromtimestamp(float(timestamp))
    except (OSError,TypeError,ValueError):
        return MISSING
    
    return dt.strftime("%H:%M:%S.%f")[:-3]

def format_ethertype(value: int | None) -> str:
    if value is None:
        return MISSING
    return f"0x{value:04x}"

def format_protocol_number(value:int | None) -> str:
    if value is None:
        return MISSING
    return str(value)

def safe_decode(raw_value: bytes | str | None) -> str:
    if raw_value is None:
        return MISSING
    if isinstance(raw_value, str):
        return raw_value
    return raw_value.decode("utf-8", errors="replace").rstrip(".")

# Format packet bytes and hex plus readable ASCII
def hex_ascii_dump(packet_bytes: bytes, bytes_per_row: int = 16) -> str:
    if not packet_bytes:
        return ""
    
    lines: list[str] = []
    for offset in range(0, len(packet_bytes), bytes_per_row):
        chunk = packet_bytes[offset: offset + bytes_per_row]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        hex_part = hex_part.ljust(bytes_per_row * 3 - 1)
        ascii_part = "".join(chr(byte) if 32 <= byte <=126 else "." for byte in chunk)
        lines.append(f"{offset:08x}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)