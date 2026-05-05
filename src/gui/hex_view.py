'''
@ASSESSME.USERID: JuricaJamic
@ASSESSME.AUTHOR: 
@ASSESSME.DESCRIPTION: 
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY: LOW
'''

from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QTextEdit

from utils.formatting import hex_ascii_dump

class HexView(QTextEdit):
    def __init__(self) -> None:
        super().__init__()
        self.setReadOnly(True)
        self.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        font = QFont("Menlo")
        font.setStyleHint(QFont.StyleHint.TypeWriter)
        font.setPointSize(10)
        self.setFont(font)

    def show_bytes(self, packet_bytes: bytes) -> None:
        self.setPlainText(hex_ascii_dump(packet_bytes))