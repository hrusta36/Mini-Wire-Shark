"""
@ASSESSME.USERID: JuricaJamic
@ASSESSME.AUTHOR:
@ASSESSME.DESCRIPTION:
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY: LOW
"""

import os

from PyQt6.QtCore import QModelIndex, QSettings, Qt
from PyQt6.QtGui import QAction, QKeySequence
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFrame,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSplitter,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from gui.details_panel import DetailsPanel
from gui.filter_bar import FilterBar
from gui.hex_view import HexView
from gui.packet_table import PacketFilterProxyModel, PacketTableModel, PacketTableView
from gui.stats_panel import StatsPanel
from gui.theme import APP_STYLESHEET
from sniffer.capture import CaptureThread, PcapLoaderThread, list_interfaces
from sniffer.parser import ParsedPacket


class MainWindow(QMainWindow):

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Packet Sniffer Pro")
        self.resize(1440, 900)
        self.setStyleSheet(APP_STYLESHEET)

        self.capture_thread: CaptureThread | None = None
        self.loader_thread: PcapLoaderThread | None = None
        self._last_warning = ""
        
    
        # Store packets in the source model and filter them through the proxy model
        self.packet_model = PacketTableModel()
        self.proxy_model = PacketFilterProxyModel()
        self.proxy_model.setSourceModel(self.packet_model)

        self.packet_table = PacketTableView()
        self.packet_table.setModel(self.proxy_model)
        self.packet_table.apply_default_column_widths()
        self.packet_table.selectionModel().currentRowChanged.connect(
            self._packet_selected
        )

        self.details_panel = DetailsPanel()
        self.hex_view = HexView()
        self.stats_panel = StatsPanel()
        self.filter_bar = FilterBar()
        self.filter_bar.filters_changed.connect(self._apply_filters)

        self.interface_combo = QComboBox()
        self.start_button = QPushButton("Start")
        self.start_button.setObjectName("PrimaryButton")
        self.stop_button = QPushButton("Stop")
        self.stop_button.setObjectName("DangerButton")
        self.stop_button.setEnabled(False)
        self.auto_scroll = QCheckBox("Auto-scroll")
        self.auto_scroll.setChecked(True)
        self.status_badge = QLabel("Ready")
        self.status_badge.setObjectName("StatusBadge")
        self.packet_count_label = QLabel("0 packets")
        self.packet_count_label.setObjectName("MetricLabel")
        self.filtered_count_label = QLabel("0 visible")
        self.filtered_count_label.setObjectName("MetricLabel")

        self._build_actions()
        self._build_layout()
        self._load_interfaces()
        self._update_capture_buttons(capturing=False)
        self.statusBar().showMessage("Ready")

    def showEvent(self, event: object) -> None:

        super().showEvent(event)
        self._show_startup_disclaimer_once()

    def closeEVent(self, event: object) -> None:

        self._stop_threads()
        super().closeEvent(event)

    def _build_actions(self) -> None:

        open_action = QAction("Open PCAP", self)
        open_action.setIcon(
            self.style().standardIcon(self.style().StandardPixmap.SP_DialogOpenButton)
        )
        open_action.setShortcut(QKeySequence.StandardKey.Open)
        open_action.triggered.connect(self.open_pcap)

        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)

        start_action = QAction("Start Capture", self)
        start_action.setIcon(
            self.style().standardIcon(self.style().StandardPixmap.SP_MediaPlay)
        )
        start_action.setShortcut(QKeySequence("Ctrl+E"))
        start_action.triggered.connect(self.start_capture)

        stop_action = QAction("Stop Capture", self)
        stop_action.setIcon(
            self.style().standardIcon(self.style().StandardPixmap.SP_MediaStop)
        )
        stop_action.setShortcut(QKeySequence("Ctrl+S"))
        stop_action.triggered.connect(self.stop_capture)

        refresh_action = QAction("Refresh Interfaces", self)
        refresh_action.setIcon(
            self.style().standardIcon(self.style().StandardPixmap.SP_BrowserReload)
        )
        refresh_action.triggered.connect(self._load_interfaces)

        file_menu = self.menuBar().addMenu("File")
        file_menu.addAction(open_action)
        file_menu.addSeparator()
        file_menu.addAction(exit_action)

        capture_menu = self.menuBar().addMenu("Capture")
        capture_menu.addAction(start_action)
        capture_menu.addAction(stop_action)
        capture_menu.addAction(refresh_action)

        toolbar = QToolBar("Capture")
        toolbar.setMovable(False)
        toolbar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        toolbar.addAction(open_action)
        toolbar.addAction(start_action)
        toolbar.addAction(stop_action)
        toolbar.addAction(refresh_action)
        self.addToolBar(toolbar)

        self.start_button.clicked.connect(self.start_capture)
        self.stop_button.clicked.connect(self.stop_capture)

    def _build_layout(self) -> None:

        root = QWidget()
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        capture_bar = QFrame()
        capture_bar.setObjectName("CaptureSourceBar")
        capture_controls = QHBoxLayout()
        capture_bar.setLayout(capture_controls)
        capture_controls.setContentsMargins(8, 6, 8, 6)
        capture_controls.setSpacing(10)
        capture_controls.addWidget(QLabel("Interface"))
        capture_controls.addWidget(self.interface_combo, stretch=1)
        capture_controls.addWidget(self.start_button)
        capture_controls.addWidget(self.stop_button)
        capture_controls.addWidget(self.auto_scroll)
        capture_controls.addWidget(self.packet_count_label)
        capture_controls.addWidget(self.filtered_count_label)
        capture_controls.addWidget(self.status_badge)
        root_layout.addWidget(capture_bar)
        root_layout.addWidget(self.filter_bar)

        details_hex_splitter = QSplitter(Qt.Orientation.Vertical)
        details_hex_splitter.addWidget(self.details_panel)
        details_hex_splitter.addWidget(self.hex_view)
        details_hex_splitter.setStretchFactor(0, 2)
        details_hex_splitter.setStretchFactor(1, 1)

        # Bottom area : packet details and hex view on the left, statistics on the right
        bottom_splitter = QSplitter(Qt.Orientation.Horizontal)
        bottom_splitter.addWidget(details_hex_splitter)
        bottom_splitter.addWidget(self.stats_panel)
        bottom_splitter.setStretchFactor(0, 3)
        bottom_splitter.setStretchFactor(1, 1)

        main_splitter = QSplitter(Qt.Orientation.Vertical)
        main_splitter.addWidget(self.packet_table)
        main_splitter.addWidget(bottom_splitter)
        main_splitter.setStretchFactor(0, 3)
        main_splitter.setStretchFactor(1, 2)

        root_layout.addWidget(main_splitter, stretch=1)
        self.setCentralWidget(root)

    def _load_interfaces(self) -> None:

        self.interface_combo.clear()
        for interface in list_interfaces():
            self.interface_combo.addItem(interface.display_name, interface.name)

        if self.interface_combo.count() == 0:
            self.interface_combo.addItem("Default interface", None)
        self.statusBar().showMessage(
            f"Loaded {self.interface_combo.count()} interfaces"
        )

    def start_capture(self) -> None:

        if self.capture_thread and self.capture_thread.isRunning():
            return

        self._stop_loader()
        self._clear_packets()

        # Run packet capture in a worker thread so the GUI stays responsive
        interface = self.interface_combo.currentData()
        self.capture_thread = CaptureThread(interface=interface)
        self.capture_thread.packet_captured.connect(self._add_packet)
        self.capture_thread.capture_error.connect(self._show_warning)
        self.capture_thread.status_message.connect(self.statusBar().showMessage)
        self.capture_thread.finished.connect(
            lambda: self._update_capture_buttons(capturing=False)
        )
        self.capture_thread.start()
        self._update_capture_buttons(capturing=True)
        self.status_badge.setText("Capturing")
        self.statusBar().showMessage(f"Capturing on {interface or 'default interface'}")

    def stop_capture(self) -> None:
        if self.capture_thread and self.capture_thread.isRunning():
            self.capture_thread.stop()
            self.status_badge.setText("Stopping ")
            self.statusBar().showMessage("Stopping capture")

    def open_pcap(self) -> None:

        path, _selected_filter = QFileDialog.getOpenFileName(
            self,
            "Open capture file",
            "",
            "Capture files (*.pcap *.pcapng);; All files (*)",
        )
        if not path:
            return

        self._stop_threads()
        self._clear_packets()
        # Load saved capture files in the background 
        self.loader_thread = PcapLoaderThread(path)
        self.loader_thread.packet_loaded.connect(self._add_packet)
        self.loader_thread.load_error.connect(self._show_warning)
        self.loader_thread.status_message.connect(self.statusBar().showMessage)
        self.loader_thread.finished.connect.connect(
            lambda: self._update_capture_buttons(capturing=False)
        )
        self.loader_thread.start()
        self._update_capture_buttons(capturing=False)
        self.status_badge.setText("Loading")

    def _add_packet(self, packet: ParsedPacket) -> None:

        # Add the parsed packet to the table and update live statistics
        self.packet_model.add_packet(packet)
        self.stats_panel.add_packet(packet)
        self._update_packet_counts()
        self.statusBar().showMessage(f"Packet: {self.packet_model.rowCount()}")
        if self.auto_scroll.isChecked():
            self.packet_table.scrollToBottom()

    def _packet_selected(self, current: QModelIndex, _previous: QModelIndex) -> None:

        if not current.isValid():
            self.details_panel.show_packet(None)
            self.hex_view.clear()
            return

        source_index = self.proxy_model.mapToSource(current)
        packet = self.packet_model.packet_at(source_index.row())
        self.details_panel.show_packet(packet)
        self.hex_view.show_bytes(packet.raw_bytes if packet else b"")

    def _apply_filters(self, filters: dict) -> None:

        self.proxy_model.set_filters(
            protocol=filters["protocol"],
            source=["source"],
            destination=filters["destination"],
            port=filters["port"],
            display_filter=filters["display_filter"],
        )
        visible = self.proxy_model.rowCount()
        total = self.packet_model.rowCount()
        self._update_packet_counts()
        self.statusBar().showMessage(f"Showing {visible} of {total} packets")

    def _clear_packets(self) -> None:

        self.packet_model.clear()
        self.details_panel.show_packet(None)
        self.hex_view.clear()
        self.stats_panel.reset()
        self._update_packet_counts()

    def _show_warning(self, message: str) -> None:
        self._last_warning = message
        self.status_badge.setText("Warning")
        self.statusBar().showMessage(f"Warning: {message}", 8000)

    def _update_capture_buttons(self, capturing: bool) -> None:

        self.start_button.setEnabled(not capturing)
        self.stop_button.setEnabled(capturing)
        if not capturing and self.status_badge.text() in {
            "Capturing",
            "Stopping",
            "Loading",
        }:
            self.status_badge.setText("Ready")

    def _update_packet_counts(self) -> None:

        total = self.packet_model.rowCount()
        visible = self.proxy_model.rowCount()
        self.packet_count_label.setText(f"{total} packets")
        self.filtered_count_label.setText(f"{visible} visible")

    def _stop_threads(self) -> None:

        self._stop_capture()
        self._stop_loader()

    def _stop_capture(self) -> None:

        if self.capture_thread and self.capture_thread.isRunning():
            self.capture_thread.stop()
            self.capture_thread.wait(1500)

    def _stop_loader(self) -> None:

        if self.loader_thread and self.loader_thread.isRunning():
            self.loader_thread.stop()
            self.loader_thread.wait(1500)

    def _show_startup_disclaimer_once(self) -> None:

        if os.environ.get("QT_QPA_PLATFORM") == "offscreen":
            return

        settings = QSettings("NSSA290", "PacketSniffer")
        if settings.value("ethics_disclaimer_seen", False, type=bool):
            return

        QMessageBox.information(
            self,
            "Ethics Notice",
            "Only capture traffic on networks you own or have explicit permission to monitor",
        )
        settings.setValue("ethics_disclaimer_seen", True)
