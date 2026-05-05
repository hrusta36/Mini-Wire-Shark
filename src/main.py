'''
@ASSESSME.USERID: JuricaJamic
@ASSESSME.AUTHOR: 
@ASSESSME.DESCRIPTION: 
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY: LOW
'''

# Import the main window afer the APplication is created.
import sys

from PyQt6.QtWidgets import QApplication

def main() -> int:

    app = QApplication(sys.argv)
    from gui.main_window import MainWindow

    window = MainWindow()
    window.show()
    return app.exec()

if __name__ == "__main__":
    raise SystemExit(main())