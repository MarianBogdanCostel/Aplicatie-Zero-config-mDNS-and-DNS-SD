from PyQt5.uic import loadUi
from PyQt5.QtWidgets import QMainWindow, QTableWidgetItem

class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        loadUi("mainwindow.ui", self)

        self.button_new.setToolTip( "Name: numele echipamentului.\n" +
                                    "Service: tipul serviciului.\n"
                                    "Protocol: protocolul de transport pentru serviciul dorit (TCP sau UDP).\n" +
                                    "Type: tipul intrării (SRV sau TXT).\n" +
                                    "Target: numele de gazdă al dispozitivului ce pune la dispoziție acel serviciu.\n")
        self.button_new.clicked.connect(self._addRow)
        self.button_copy.clicked.connect(self._copyRow)
        self.button_delete.clicked.connect(self._deleteRow)

    def _addRow(self):
        self.tableWidget.insertRow(self.tableWidget.rowCount())

    def _deleteRow(self):
        if self.tableWidget.rowCount() > 0:
            self.tableWidget.removeRow(self.tableWidget.currentRow())

    def _copyRow(self):
        currentRow = self.tableWidget.currentRow()
        self.tableWidget.insertRow(currentRow)
        columnCount = self.tableWidget.columnCount()

        for j in range(columnCount):
            if not self.tableWidget.item(currentRow+1, j) is None:
                self.tableWidget.setItem(currentRow, j, QTableWidgetItem(self.tableWidget.item(currentRow+1, j).text()))