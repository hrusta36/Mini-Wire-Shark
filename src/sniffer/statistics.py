'''
@ASSESSME.USERID: dh3137
@ASSESSME.AUTHOR: 
@ASSESSME.DESCRIPTION: 
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY: LOW
'''

from collections import Counter, deque
import time
from dataclasses import dataclass, field

from sniffer.parser import ParsedPacket
from utils.formatting import MISSING

@dataclass
class PacketStatistics:
    total_packets: int = 0
    protocol_counts: Counter[str] = field(default_factory=Counter)
    source_counts: Counter[str] = field(default_factory=Counter)
    arrival_times: deque[float] = field(default_factory=deque)
    
    def reset(self) -> None:
        self.total_packets = 0
        self.protocol_counts.clear()
        self.source_counts.clear()
        self.arrival_times.clear()
        
    def record(self, packet: ParsedPacket) -> None:
        now = time.time()
        self.total_packets += 1
        self.protocol_counts[packet.protocol] += 1
        if packet.source != MISSING:
            self.source_counts[packet.source] += 1
            
        self.arrival_times.append(now)
        self._trim_old_arrivals(now)
        
    def packets_per_second(self) -> float:
        now = time.time()
        self._trim_old_arrivals(now)
        if len(self.arrival_times) < 2:
            return float(len(self.arrival_times))
        window_seconds = max(now - self.arrival_times[0], 1.0)
        return len(self.arrival_times) / window_seconds
    
    def rate_series(self, window_seconds: int = 60) -> tuple[list[int], list[int]]:
        now = int(time.time())
        buckets = {second: 0 for second in range(now - window_seconds + 1, now + 1)}
        for arrival in self.arrival_times:
            second = int(arrival)
            if second in buckets:
                buckets[second] += 1
        
        value_for_x = list(range(-window_seconds + 1, 1))
        value_for_y = [buckets[second] for second in sorted(buckets)]
        
        return value_for_x, value_for_y
    
    def top_talkers(self, limit: int = 5) -> list[tuple[str, int]]:
        return self.source_counts.most_common(limit)
        
    def _trim_old_arrivals(self, now: float, window_seconds: int = 60) -> None:
        cutoff = now - window_seconds
        while self.arrival_times and self.arrival_times[0] < cutoff:
            self.arrival_times.popleft()