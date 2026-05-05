'''
@ASSESSME.USERID: dh3137
@ASSESSME.AUTHOR: 
@ASSESSME.DESCRIPTION: 
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY: LOW
'''

from PyQt6.QtCore import QTimer, pyqtSignal
from PyQt6.QtWidgets import QComboBox, QGridLayout, QLabel, QLineEdit, QPushButton, QWidget

class FilterBar(QWidget): 
    filters_changed = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.setObjectName("FilterBar")
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["All", "TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "TLS"])
        
        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("Source IP or CIDR")
        self.destination_edit = QLineEdit()
        self.destination_edit.setPlaceholderText("Destination IP or CIDR")
        self.port_edit = QLineEdit()
        self.port_edit.setPlaceholderText("Port")
        self.display_filter_edit = QLineEdit()
        self.display_filter_edit.setObjectName("DisplayFilter")
        self.display_filter_edit.setPlaceholderText("Display Filter, e.g. tcp.port == 443)")
        
        self.apply_button = QPushButton("Apply")
        
        layout = QGridLayout(self)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setHorizontalSpacing(8)
        layout.setVerticalSpacing(3)
        layout.addWidget(QLabel("Protocol"), 0, 0)
        layout.addWidget(QLabel("Source"), 0, 1)
        layout.addWidget(QLabel("Destination"), 0, 2)
        layout.addWidget(QLabel("Port"), 0, 3)
        layout.addWidget(QLabel("Display filter"), 0, 4)
        layout.addWidget(self.protocol_combo, 1, 0)
        layout.addWidget(self.source_edit, 1, 1)
        layout.addWidget(self.destination_edit, 1, 2)
        layout.addWidget(self.port_edit, 1, 3)
        layout.addWidget(self.display_filter_edit, 1, 4)
        layout.addWidget(self.apply_button, 1, 5)
        layout.setColumnStretch(4, 1)
        
        # Delay filter updates slightly while the user is typing 
        self._debounce_timer = QTimer(self)
        self._debounce_timer.setSingleShot(True)
        self._debounce_timer.setInterval(300)
        self._debounce_timer.timeout.connect(self.emit_filters)
        
        self.protocol_combo.currentTextChanged.connect(self._schedule_emit)
        self.source_edit.textChanged.connect(self._schedule_emit)
        self.destination_edit.textChanged.connect(self._schedule_emit)
        self.port_edit.textChanged.connect(self._schedule_emit)
        self.display_filter_edit.textChanged.connect(self._schedule_emit)
        self.apply_button.clicked.connect(self.emit_filters)
        
    def emit_filters(self) -> None:
        self._debounce_timer.stop()
        self.filters_changed.emit(
            {
                "protocol": self.protocol_combo.currentText(),
                "source": self.source_edit.text(),
                "destination": self.destination_edit.text(),
                "port": self.port_edit.text(),
                "display_filter": self.display_filter_edit.text(),
            }
        )
        
    def _schedule_emit(self) -> None:
        self._debounce_timer.start()