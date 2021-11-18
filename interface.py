from PyQt5.uic import loadUi
from PyQt5.QtWidgets import QMainWindow, QTableWidgetItem

class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        loadUi("mainwindow.ui", self)

        self.button_new.setToolTip("_service._proto.name. ttl IN SRV priority weight port target.\n\n"+
                                    "service: numele serviciului dorit.\n" +
                                    "proto: protocolul de transport pentru serviciul dorit; de obicei este TCP sau UDP.\n" +
                                    "domain name: numele de domeniu unde această intrare este validă.\n" +
                                    "ttl: câmp standard DNS time to live.\n" +
                                    "IN: câmp standard DNS class (este mereu IN).\n" +
                                    "SRV: tipul intrării (este mereu SRV).\n" +
                                    "priority: prioritatea gazdei țintă, valoare mai mică înseamnă prioritate mai ridicată.\n" +
                                    "weight: o valoare relativă pentru intrarile cu aceeași prioritate, o valoare mai mare în acest câmp reprezintă o șansă mai mare de a fi aleasă.\n" +
                                    "port: portul TCP sau UDP unde serviciul va fi găsit.\n" +
                                    "target: numele de gazdă al dispozitivului ce pune la dispoziție acel serviciu.\n")
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