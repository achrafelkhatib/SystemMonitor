import sys
import psutil
import socket
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QTreeWidget, QTreeWidgetItem, QWidget, QGroupBox, QLabel
from PyQt5.QtCore import pyqtSignal, QThread

class UpdateThread(QThread):
    updated = pyqtSignal(dict)

    def run(self):
        while True:
            # Get the initial values
            send_start = psutil.net_io_counters().bytes_sent
            recv_start = psutil.net_io_counters().bytes_recv

            # Sleep for 1 second
            self.msleep(1000)

            # Get the final values
            send_end = psutil.net_io_counters().bytes_sent
            recv_end = psutil.net_io_counters().bytes_recv

            # Calculate the network speed in kbps
            send_speed = ((send_end - send_start) * 8) / 1024
            recv_speed = ((recv_end - recv_start) * 8) / 1024

            info = {
                "CPU Usage": f"{psutil.cpu_percent()}%",
                "RAM Usage": f"{psutil.virtual_memory().percent}%",
                "Disk Usage": f"{psutil.disk_usage('/').percent}%",
                "Network Send": f"{send_speed:.2f} kbps",
                "Network Received": f"{recv_speed:.2f} kbps",
                "Cores": psutil.cpu_count(logical=False),
                "Logical Cores": psutil.cpu_count(logical=True),
                # Add more system information as needed
            }
            self.updated.emit(info)

class TrafficThread(QThread):
    updated_traffic = pyqtSignal(dict)

    def run(self):
        while True:
            # Get the network traffic information
            connections = self.get_connections()
            self.updated_traffic.emit({
                "Connections": connections
            })
            self.msleep(1000)  # Update every 1 second

    def get_connections(self):
        connections = []
        for conn in psutil.net_connections(kind='inet'):
            conn_info = {
                "Type": self.get_connection_type(conn.type),
                "Local Address": f"{conn.laddr.ip}:{conn.laddr.port}",
                "Remote Address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
            }
            connections.append(conn_info)
        return connections

    def get_connection_type(self, conn_type):
        return "TCP" if conn_type == socket.SOCK_STREAM else "UDP"

class TrafficWidget(QWidget):
    def __init__(self):
        super().__init__()

        self.label = QLabel("Network Traffic:")
        self.tree_widget = QTreeWidget()
        self.tree_widget.setHeaderLabels(["Type", "Local Address", "Remote Address"])
        self.tree_widget.setColumnWidth(0, 100)
        self.tree_widget.setColumnWidth(1, 200)
        self.tree_widget.setColumnWidth(2, 200)

        layout = QVBoxLayout(self)
        layout.addWidget(self.label)
        layout.addWidget(self.tree_widget)

    def set_traffic_info(self, connections):
        self.tree_widget.clear()

        for conn_info in connections:
            parent = QTreeWidgetItem(self.tree_widget)
            parent.setText(0, conn_info["Type"])
            parent.setText(1, conn_info["Local Address"])
            parent.setText(2, conn_info["Remote Address"])

class SystemMonitor(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("System Monitor")
        self.setGeometry(100, 100, 800, 600)

        # Create a group box for system information
        system_info_group = QGroupBox("System Information")
        system_info_layout = QVBoxLayout()

        # Add the existing InfoFrame to the layout
        self.central_widget = InfoFrame()
        system_info_layout.addWidget(self.central_widget)

        # Add more widgets if needed
        # Example: self.some_widget = SomeWidget()
        # system_info_layout.addWidget(self.some_widget)

        system_info_group.setLayout(system_info_layout)

        # Set a slightly larger fixed size for the group box
        system_info_group.setFixedWidth(400)

        # Create a group box for network information
        network_info_group = QGroupBox("Network Information")
        network_info_layout = QVBoxLayout()

        # Create a new TrafficWidget for network traffic information
        self.traffic_widget = TrafficWidget()
        network_info_layout.addWidget(self.traffic_widget)

        network_info_group.setLayout(network_info_layout)

        # Set the group boxes as the central widgets
        self.setCentralWidget(QWidget())
        layout = QVBoxLayout(self.centralWidget())
        layout.addWidget(system_info_group)
        layout.addWidget(network_info_group)

        # Create an instance of the UpdateThread
        self.update_thread = UpdateThread()
        # Connect the signal from the thread to the update_info method
        self.update_thread.updated.connect(self.update_info)
        # Start the thread
        self.update_thread.start()

        # Create an instance of the TrafficThread
        self.traffic_thread = TrafficThread()
        # Connect the signal from the thread to the update_traffic method
        self.traffic_thread.updated_traffic.connect(self.update_traffic)
        # Start the thread
        self.traffic_thread.start()

    def update_info(self, info):
        self.central_widget.set_info(info)

    def update_traffic(self, traffic_info):
        self.traffic_widget.set_traffic_info(traffic_info.get("Connections", []))

class InfoFrame(QTreeWidget):
    def __init__(self):
        super().__init__()
        self.setHeaderLabels(["Info", "Value"])
        self.setColumnWidth(0, 200)
        self.setColumnWidth(1, 100)

    def set_info(self, values):
        self.clear_info()

        for key, value in values.items():
            parent = QTreeWidgetItem(self)
            parent.setText(0, key)
            parent.setText(1, str(value))

    def clear_info(self):
        for i in reversed(range(self.topLevelItemCount())):
            self.takeTopLevelItem(i)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SystemMonitor()
    window.show()
    sys.exit(app.exec_())
