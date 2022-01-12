import sys
from Interface import *
from PyQt5.QtWidgets import *

if __name__ == '__main__':
    app = QApplication(sys.argv)
    interface = Interface()
    interface.show()
    interface.raise_()
    sys.exit(app.exec_())
