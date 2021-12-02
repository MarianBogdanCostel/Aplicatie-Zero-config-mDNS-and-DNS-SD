import sys
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QApplication

import interface
import zeroconfig

if __name__ == '__main__':
    #interface
    app = QApplication(sys.argv)
    mainwindow = interface.MainWindow()
    widget = QtWidgets.QStackedWidget()
    widget.addWidget(mainwindow)
    widget.setFixedHeight(850)
    widget.setFixedWidth(1120)
    widget.show()

    #zeroconfig

    zc = zeroconfig.Zeroconfig()

    #get information from interface and create entry
    #entry = zeroconfig.DNSEntry(...)
    #zc.registerService(entry)

    #zc.unregisterService(entry)

    #quit interface
    try:
        sys.exit(app.exec_())
    except:
        print("Exiting...")