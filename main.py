import sys
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QApplication

import interface

if __name__ == '__main__':
    app = QApplication(sys.argv)
    mainwindow = interface.MainWindow()
    widget = QtWidgets.QStackedWidget()
    widget.addWidget(mainwindow)
    widget.setFixedHeight(850)
    widget.setFixedWidth(1120)
    widget.show()
    try:
        sys.exit(app.exec_())
    except:
        print("Exiting...")