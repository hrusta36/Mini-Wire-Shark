'''
@ASSESSME.USERID: dh3137
@ASSESSME.AUTHOR: 
@ASSESSME.DESCRIPTION: 
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY: LOW
'''

import pyqtgraph as pg
from PyQt6.QtWidgets import QLabel, QListWidget, QVBoxLayout, QWidget
from sniffer.parser import ParsedPacket
from sniffer.statistics import PacketStatistics

class StatsPanel(QWidget):
    
    def __init__(self):
        super().__init__()
        self.setObjectName("StatsPanel")
        self.stats = PacketStatistics()
        
        
        self.total_label = QLabel("Total packets: 0")
        self.rate_label = QLabel("Packets/sec: 0.00")
        self.total_label.setObjectName("MetricLabel")
        self.rate_label.setObjectName("MetricLabel")
        
        self.protocol_plot = pg.PlotWidget()
        self.protocol_plot.setBackground("#0f1419")
        self.protocol_plot.setTitle("Packets per Protocol")
        self.protocol_plot.getAxis("left").setLabel("Packets")
        self.protocol_plot.getAxis("bottom").setLabel("Protocol")
        self._style_plot(self.protocol_plot, "Packets per Protocol")
        self.protocol_plot.showGrid(x=True, y=True, alpha=0.18)
        
        self.rate_plot = pg.PlotWidget()
        self.rate_plot.setBackground("#0f1419")
        self.rate_plot.setTitle("Packets per Second (last 60s)")
        self.rate_plot.getAxis("left").setLabel("Packets")
        self.rate_plot.getAxis("bottom").setLabel("Seconds")
        self._style_plot(self.rate_plot, "Packets per Second (last 60s)")
        self.rate_plot.showGrid(x=True, y=True, alpha=0.18)
        
        self.top_talkers = QListWidget()
        self.top_talkers.setMinimumHeight(90)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        layout.addWidget(self.total_label)
        layout.addWidget(self.rate_label)
        layout.addWidget(self.protocol_plot, stretch=1)
        layout.addWidget(self.rate_plot, stretch=1)
        layout.addWidget(QLabel("Top talkers"))
        layout.addWidget(self.top_talkers)
        
    def reset(self) -> None:
        self.stats.reset()
        self._refresh()
        
    def _refresh(self) -> None:
        self.total_label.setText(f"Total packets: {self.stats.total_packets}")
        self.rate_label.setText(f"Packets/sec: {self.stats.packets_per_second():.2f}")
        self._refresh_protocol_chart()
        self._refresh_rate_chart()
        self._refresh_top_talkers()
        
    def add_packet(self, packet: ParsedPacket) -> None:
        self.stats.record(packet)
        self._refresh()
    
    def _refresh_protocol_chart(self) -> None:
        self.protocol_plot.clear()
        labels = list(self.stats.protocol_counts.keys())
        values = [self.stats.protocol_counts[label] for label in labels]
        if not labels:
            return
        
        x_values = list(range(len(labels)))
        bars = pg.BarGraphItem(x=x_values, height=values, width=0.6, brush="#2563eb")
        self.protocol_plot.addItem(bars)
        axis = self.protocol_plot.getAxis("bottom")
        axis.setTicks([list(zip(x_values, labels))])
        
    def _refresh_rate_chart(self) -> None:
        self.rate_plot.clear()
        x_values, y_values = self.stats.rate_series()
        self.rate_plot.plot(x_values, y_values, pen=pg.mkPen("#16a34a", width=2))
        
    def _refresh_top_talkers(self) -> None:
        self.top_talkers.clear()
        for address, count in self.stats.top_talkers():
            self.top_talkers.addItem(f"{address}: {count}")
        
    def _style_plot(self, plot: pg.PlotWidget, title: str) -> None:
        plot.setTitle(title, color="#d7dee7")
        for axis_name in ("left", "bottom"):
            axis = plot.getAxis(axis_name)
            axis.setPen("#4b5563")
            axis.setTextPen("#cbd5e1")