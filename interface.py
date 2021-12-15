from PyQt5.uic import loadUi
from PyQt5.QtWidgets import QMainWindow, QTableWidgetItem


class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        loadUi("user_interface.ui", self)

        self.add_button.setToolTip( "Name: numele echipamentului.\n" +
                                    "Service: tipul serviciului.\n"
                                    "Protocol: protocolul de transport pentru serviciul dorit (TCP sau UDP).\n" +
                                    "Type: tipul intrării (SRV sau TXT).\n" +
                                    "Target: numele de gazdă al dispozitivului ce pune la dispoziție acel serviciu.\n")
        #self.button_new.clicked.connect(self._addRow)
        #self.button_copy.clicked.connect(self._copyRow)
        #self.button_delete.clicked.connect(self._deleteRow)
