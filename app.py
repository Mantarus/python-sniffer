import sys
from PyQt5.QtWidgets import *


class Window(QMainWindow):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):

        self.statusBar().showMessage('Ready')

        leftWidget = QScrollArea()
        rightWidget = QScrollArea()

        hbox = QHBoxLayout()
        hbox.addWidget(leftWidget)
        hbox.addWidget(rightWidget)

        mainArea = QWidget()
        mainArea.setLayout(hbox)

        self.setCentralWidget(mainArea)
        self.setGeometry(300, 300, 800, 400)
        self.setWindowTitle('Python Sniffer')
        self.show()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = Window()
    sys.exit(app.exec_())