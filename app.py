from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from sniffer import *
from datetime import *


def get_current_time():
    return datetime.now().strftime("%I:%M:%S %B %d, %Y\n")


class PacketReceiver(QThread):
    packet_received = pyqtSignal(object)

    def __init__(self):
        QThread.__init__(self)

    def run(self):
        conn = init_connection()
        while True:
            packet = receive_packet(conn)
            self.packet_received.emit(packet)


class MainWindow(QWidget):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.main_layout = QVBoxLayout()
        self.options_layout = QHBoxLayout()
        self.capture_screen_layout = QHBoxLayout()
        self.leftWidget = QListWidget()
        self.rightWidget = QListWidget()
        self.init_ui()

        self.threads = []

    def init_ui(self):

        self.main_layout.addLayout(self.options_layout)
        self.main_layout.addLayout(self.capture_screen_layout)

        button = QPushButton('Start capturing')
        button.clicked.connect(self.start_capturing)
        self.options_layout.addWidget(button)

        self.capture_screen_layout.addWidget(self.leftWidget)
        self.capture_screen_layout.addWidget(self.rightWidget)

        self.setLayout(self.main_layout)

        self.setGeometry(300, 300, 800, 400)
        self.setWindowTitle('Python Sniffer')
        self.show()

    def start_capturing(self):
        if len(self.threads) == 0:
            thread = PacketReceiver()
            thread.packet_received.connect(self.on_data_ready)
            self.threads.append(thread)
            thread.start()

    def on_data_ready(self, data):
        print(get_current_time())
        print(data)
        packet_repr = get_current_time()
        is_vnc = False
        for item in data:
            if isinstance(item, Ethernet):
                packet_repr += 'SRC MAC: {} DST MAC: {}\n'.format(item.src_mac, item.dest_mac)
                continue
            if isinstance(item, IPv4):
                packet_repr += 'SRC IP: {} DST IP: {}\n'.format(item.src, item.target)
                continue
            if isinstance(item, TCP):
                packet_repr += 'SRC Port: {} DST Port: {}\n'.format(item.src_port, item.dest_port)
                continue
            if isinstance(item, VNC):
                is_vnc = True
                packet_repr += item.header
                continue

        if is_vnc:
            self.leftWidget.addItem(packet_repr)
            self.leftWidget.scrollToBottom()
        else:
            self.rightWidget.addItem(packet_repr)
            self.rightWidget.scrollToBottom()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    sys.exit(app.exec_())
