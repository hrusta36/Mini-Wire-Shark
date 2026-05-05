from PyQt6.QtWidgets import QTreeWidget, QTreeWidgetItem

from sniffer.parser import ParsedPacket

class DetailsPanel(QTreeWidget):
    def __init__(self) -> None:
        super().__init__()
        self.setHeaderLabels(["Field", "value"])
        self.setAlternatingRowColors(True)
        self.setUniformRowHeights(True)

    def show_packet(self, packet: ParsedPacket | None) -> None:
        self.clear()
        if packet is None:
            return
        
        for section_name, fields in packet.layer_details:
            section_item = QTreeWidgetItem([section_name, ""])
            self.addTopLevelItem(section_item)
            for field_name, value in fields:
                section_item.addChild(QTreeWidgetItem([field_name, value]))
            section_item.setExpanded(True)
        
        self.resizeColumnToContents(0)