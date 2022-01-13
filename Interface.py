import random
import socket

from ServiceFinder import *
from PyQt5.QtWidgets import *
from PyQt5.uic import loadUi


class Listener:
    def __init__(self):
        self.result = ""

    def add_service(self, zeroconfig, type, name):
        self.result += "Name:  %s    " % (name,)
        service = zeroconfig.get_service_info(type, name)
        if service:
            self.result += ("Target:  %s    " % service.target)
            self.result += ("IP:  %s\n" % (socket.inet_ntoa(service.address)))
        else:
            self.result += "\n"


class Interface(QMainWindow):
    def __init__(self):
        super(Interface, self).__init__()
        loadUi("user_interface.ui", self)

        self.zeroconfig = None
        self.serv_dict = {}
        self.ip_dict = {}

        self.disable_controls()
        self.add_button.clicked.connect(self.add_service)
        self.save_button.clicked.connect(self.register_service)
        self.cancel_button.clicked.connect(self.cancel)
        self.delete_button.clicked.connect(self.unregister_service)
        self.showAll_button.clicked.connect(self.show_all)
        self.filter_button.clicked.connect(self.filter_by_service)
        self.get_ip_button.clicked.connect(self.get_ip_address)

    def disable_controls(self):
        self.name_text.setPlainText("")
        self.service_text.setPlainText("")
        self.target_text.setPlainText("")

        self.name_text.setEnabled(False)
        self.service_text.setEnabled(False)
        self.target_text.setEnabled(False)
        self.protocol_comboBox.setEnabled(False)

        self.save_button.setEnabled(False)
        self.cancel_button.setEnabled(False)

    def enable_controls(self):
        self.name_text.setEnabled(True)
        self.service_text.setEnabled(True)
        self.target_text.setEnabled(True)
        self.protocol_comboBox.setEnabled(True)

        self.save_button.setEnabled(True)
        self.cancel_button.setEnabled(True)

    def add_service(self):
        self.enable_controls()
        self.add_button.setEnabled(False)

    def cancel(self):
        self.disable_controls()
        self.add_button.setEnabled(True)

    def register_service(self):
        name = self.name_text.toPlainText()
        service = self.service_text.toPlainText()
        protocol = self.protocol_comboBox.currentText().lower()
        target = self.target_text.toPlainText()

        for c in ' ._':
            name = name.replace(c, '')
            service = service.replace(c, '')

        target = target.replace(' ', '')
        if not (target.endswith('.')):
            target = target + '.'

        msg = QMessageBox()
        msg.setStyleSheet("QLabel{min-width: 150px;}")
        msg.setWindowTitle("Registering service...")
        msg.show()

        service_complete = "_" + service + "._" + protocol + ".local."
        name_complete = name + "." + service_complete

        if target in self.ip_dict.keys():
            address = self.ip_dict[target]
        else:
            address = '192.168' + '.' + str(random.randint(1, 254)) + '.' + str(random.randint(1, 254))

            while address in self.ip_dict.values():
                address = '192.168' + '.' + str(random.randint(1, 254)) + '.' + str(random.randint(1, 254))

            self.ip_dict[target] = address

        service_info = ServiceInfo(service_complete, name_complete, socket.inet_aton(address), MDNS_PORT, 0, 0, target)

        if self.zeroconfig is None:
            self.zeroconfig = Zeroconfig()

        self.zeroconfig.register_service(service_info, DNS_TTL)
        self.responder_list.addItem("Name:  " + name_complete + "    Target:  " + target)
        self.serv_dict[name_complete] = service_info

        msg.setText("Registration done.")
        msg.exec_()

        self.cancel()

    def unregister_service(self):
        current_row = self.responder_list.currentRow()

        if current_row == -1:
            msg = QMessageBox()
            msg.setStyleSheet("QLabel{min-width: 150px;}")
            msg.setWindowTitle("Error")
            msg.setText("Please select a service.")
            msg.exec_()
        else:
            msg = QMessageBox()
            msg.setStyleSheet("QLabel{min-width: 150px;}")
            msg.setWindowTitle("Unregistering service...")
            msg.show()

            service = self.responder_list.currentItem().text()
            name = service.split(" ")[2]
            self.zeroconfig.unregister_service(self.serv_dict[name])

            msg.setText("Unregistration done.")
            msg.exec_()

            self.responder_list.takeItem(current_row)

    def show_all(self):
        self.resolver_list.clear()

        msg = QMessageBox()
        msg.setStyleSheet("QLabel{min-width: 150px;}")
        msg.setWindowTitle("Browsing for services...")
        msg.show()

        if self.zeroconfig is None:
            self.zeroconfig = Zeroconfig()

        services = ServiceFinder.find(self.zeroconfig, 0.5)

        for service in services:
            listener = Listener()
            browser = Browser(self.zeroconfig, service, listener)
            time.sleep(3)
            browser.stop()

            for item in listener.result.splitlines():
                self.resolver_list.addItem(item)

        msg.setText("Browsing done.")
        msg.exec_()

    def filter_by_service(self):
        service = self.filter_text.toPlainText()

        if service == '':
            msg = QMessageBox()
            msg.setStyleSheet("QLabel{min-width: 150px;}")
            msg.setWindowTitle("Error")
            msg.setText("Please specify a service.")
            msg.exec_()
        else:
            for c in ' ._':
                service = service.replace(c, '')

            self.resolver_list.clear()
            msg = QMessageBox()
            msg.setStyleSheet("QLabel{min-width: 150px;}")
            msg.setWindowTitle("Browsing for services...")
            msg.show()

            if self.zeroconfig is None:
                self.zeroconfig = Zeroconfig()

            service_complete = "_" + service + "._udp.local."
            udp_listener = Listener()
            udp_browser = Browser(self.zeroconfig, service_complete, udp_listener)
            time.sleep(3)
            udp_browser.stop()

            for item in udp_listener.result.splitlines():
                self.resolver_list.addItem(item)

            service_complete = "_" + service + "._tcp.local."
            tcp_listener = Listener()
            tcp_browser = Browser(self.zeroconfig, service_complete, tcp_listener)
            time.sleep(3)
            tcp_browser.stop()

            for item in tcp_listener.result.splitlines():
                self.resolver_list.addItem(item)

            msg.setText("Browsing done.")
            msg.exec_()

    def get_ip_address(self):
        target = self.eqp_name_text.toPlainText()

        if target == '':
            msg = QMessageBox()
            msg.setStyleSheet("QLabel{min-width: 150px;}")
            msg.setWindowTitle("Error")
            msg.setText("Please specify a target.")
            msg.exec_()
        else:
            target = target.replace(' ', '')
            if not (target.endswith('.')):
                target = target + '.'

            if self.zeroconfig is None:
                self.zeroconfig = Zeroconfig()

            msg = QMessageBox()
            msg.setStyleSheet("QLabel{min-width: 150px;}")
            msg.setWindowTitle("Resolving Hostname...")
            msg.show()
            services = ServiceFinder.find(self.zeroconfig, 0.5)
            for service in services:
                listener = Listener()
                browser = Browser(self.zeroconfig, service, listener)
                time.sleep(3)
                browser.stop()

                for item in listener.result.splitlines():
                    eqp = '.local.'
                    ip_address = '0.0.0.0'
                    srv = ' '.join(item.split()).split(' ')
                    if len(srv) > 2:
                        eqp = srv[3]
                    if target == eqp:
                        if len(srv) > 2:
                            ip_address = srv[5]
                        self.ip_label.setText(ip_address)
                        msg.setText("IP Address found.")
                    else:
                        msg.setText("IP Address NOT found.")
            msg.exec_()
