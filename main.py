import sys
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QApplication

import interface
from zeroconfig import *

if __name__ == '__main__':
    #interface
    app = QApplication(sys.argv)
    mainwindow = interface.MainWindow()
    widget = QtWidgets.QStackedWidget()
    widget.addWidget(mainwindow)
    widget.setFixedHeight(452)
    widget.setFixedWidth(882)
    widget.show()

    #zeroconfig

    dns_cache = DNSCache()
    zc = Zeroconfig(dns_cache)
    listener = Listener(dns_cache)
    listener.startListening()

    entry = DNSService("My name", "_music", "_udp", DNS_TTL, CLASS_IN, "SRV", 0, 0, MDNS_PORT, "music.example.com")
    zc.registerService(entry)
    print(listener.dns_cache.entries())
    print("Ip address of "+entry.name+" is: "+dns_cache.getIp(entry))
    zc.unregisterService(entry)
    print(listener.dns_cache.entries())

    #quit interface
    try:
        sys.exit(app.exec_())
    except:
        print("Exiting...")