'''
@ASSESSME.USERID: dh3137
@ASSESSME.AUTHOR: 
@ASSESSME.DESCRIPTION: 
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY: LOW
'''

"""Theme for the whole application, for the packet sniffer GUI."""

APP_STYLESHEET = """
QMainWindow {
    background: #0b0d10;
}

QMenuBar, QMenu {
    background: #111418;
    color: #e6edf3;
    border-bottom: 1px solid #303a45;
}

QToolBar {
    background: #111418;
    border: 0;
    border-bottom: 1px solid #303a45;
    spacing: 4px;
    padding: 4px 6px;
}


QToolButton {
    background: transparent;
    color:  #d7dee7;
    border: 1px solid transparent;
    border-radius: 4px;
    padding: 5px 8px;
}

QToolButton:hover {
    background: #2b333d;
    border-color: #3c4654;
}

QStatusBar {
    background:  #111418;
    color: #cbd5e1;
    border-top: 1px solid #303a45;
}

QLabel#AppTitle {
    color: #e6edf3;
    font-size: 16px;
    font-weight: 700;
}

QLabel#SubtleText {
    color: #95a2b3;
    font-size: 12px;
}

QLabel#StatusBadge {
    background: #163923;
    color: #7ee787;
    border: 1px solid#2f6f45;
    border-radius: 4px;
    padding: 3px 8px;
    font-weight: 600;
}

QLabel#MetricLabel {
    background: #20262d;
    border: 1px solid #303a45;
    border-radius: 4px;
    padding: 4px 8px;
    color: #d7dee7;
    font-weight: 600;
}

QFrame#HeaderBand, QFrame#CaptureSourceBar, QWidget#FilterBar {
    background:  #111418;
    border: 0;
    border-bottom: 1px solid #303a45;
    border-radius: 0;
}

QWidget#StatsPanel {
    background: #0b0d10;
    border-left: 1px solid #303a45;
}

QGroupBox {
    background: #151a1f;
    border: 1px solid #303a45;
    border-radius: 0;
    margin-top: 16px;
    padding: 8px;
    font-weight: 700;
    color: #d7dee7;
}

QGroupBox::title {
    subcontrol-origin: margin;
    left: 8px;
    padding: 0 4px;
    color: #95a2b3;
}

QPushButton {
    background: #161a20;
    border: 1px solid #3c4654;
    border-radius: 4px;
    color: #d7dee7;
    padding: 5px 10px;
    font-weight: 600;
}

QPushButton:hover {
    background: #303a45;
    border-color: #20252d;
}

QPushButton:disabled {
    color: #6b7280;
    background: #20262d;
}

QPushButton#PrimaryButton {
    background: #1f6f43;
    border-color: #2f9e5f;
    color: #f0fff4;
}

QPushButton#PrimaryButton:hover {
    background: #23824f;
}

QPushButton#DangerButton {
    background: #7f1d1d;
    border-color: #b91c1c;
    color: #fff1f2;
}

QPushButton#DangerButton:hover {
    background: #991b1b;
}

QComboBox, QLineEdit {
    background: #0c0f13;
    border: 1px solid #3c4654;
    border-radius: 3px;
    padding: 5px 7px;
    color: #e6edf3;
    selection-background-color: #2f81f7;
}

QLineEdit#DisplayFilter {
    background: #0c1410;
    border: 1px solid #1f6f43;
    color: #d7f5dc;
    font-family: Menlo, Monaco, monospace;
}

QLineEdit:focus, QComboBox:focus {
    border-color: #2f81f7;
}

QCheckBox {
    color: #d7dee7;
}

QLabel {
    color: #d7dee7;
}

QTableView, QTreeWidget, QTextEdit, QListWidget {
    background: #090b0e;
    alternate-background-color: #151b22;
    border: 1px solid #303a45;
    border-radius: 0;
    color: #d7dee7;
    selection-background-color: #101318;
    selection-color: #ffffff;
}

QHeaderView::section {
    background: #15191f;
    color: #d7dee7;
    border: 0;
    border-right: 1px solid #303a45;
    border-bottom: 1px solid #303a45;
    padding: 5px 7px;
    font-weight: 700;
}

QSplitter::handle {
    background: #1f242b;
}

QScrollBar:vertical, QScrollBar:horizontal {
    background: #151a1f;
    border: 0;
}

QScrollBar::handle {
    background: #4b5563;
    border-radius: 4px;
    min-height: 24px;
    min-width: 24px;
}
"""