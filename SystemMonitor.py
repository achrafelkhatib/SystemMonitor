import sys
import psutil
import socket
import csv
import os
import requests
import json
import configparser
from datetime import timedelta
from PyQt5.QtCore import pyqtSignal, QThread, Qt
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QTreeWidget, QTreeWidgetItem, QWidget, QGroupBox, QLabel, QSplitter,QDialog, QPushButton

config = configparser.ConfigParser()
config.read('config.ini')

api_key = config['API']['abuseipdb_key']

def check_abuseipdb(ip_address, max_age_in_days=30, verbose=False):
    base_url = 'https://api.abuseipdb.com/api/v2/check'
    query_params = {
        'ipAddress': ip_address,
        'maxAgeInDays': max_age_in_days,
        'verbose': verbose,
    }
    headers = {
        'Accept': 'application/json',
        'Key': api_key,  # Replace with your AbuseIPDB API key
    }

    try:
        response = requests.get(base_url, params=query_params, headers=headers)
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx and 5xx status codes)

        decoded_response = response.json()
        data = decoded_response.get('data', {})
        is_whitelisted = data.get('isWhitelisted', None)
        abuse_confidence_score = data.get('abuseConfidenceScore', None)
        country_name = data.get('countryName', {})  # Assuming the API provides geolocation information
        return is_whitelisted, abuse_confidence_score, country_name

    except requests.exceptions.RequestException as e:
        print(f"Request Exception: {e}")
        # Handle the exception as needed (log, raise, etc.)
        return None, None, None
    except json.JSONDecodeError as e:
        print(f"JSON Decode Error: {e}")
        # Handle the exception as needed (log, raise, etc.)
        return None, None, None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        # Handle the exception as needed (log, raise, etc.)
        return None, None, None


class IPCheckThread(QThread):
    ip_checked = pyqtSignal(str, bool, int, str)

    def __init__(self, max_age_in_days=30, api_call_limit=100, api_call_reset_duration=timedelta(minutes=5), parent=None):
        super(IPCheckThread, self).__init__(parent)
        self.max_age_in_days = max_age_in_days
        self.api_call_limit = api_call_limit
        self.api_call_reset_duration = api_call_reset_duration
        self.last_api_call_time = None
        self._is_running = True

    def run(self):
        while self._is_running:
            self.runCheck()

    def stop(self):
        self._is_running = False
        self.wait()

    def runCheck(self):
        unique_ips_file = "uniqueIpAddress.csv"

        if os.path.exists(unique_ips_file):
            with open(unique_ips_file, 'r') as file:
                reader = csv.reader(file)
                for row in reader:
                    if row:
                        ip_address = row[0]
                        self.check_ip(ip_address)

    def check_ip(self, ip_address):
        # Check if the IP has already been checked
        if not self.is_ip_checked(ip_address):
            print(f"IP {ip_address} not checked yet. Checking AbuseIPDB.")

            # Check if the API limit is reached
            if not self.is_api_limit_reached():
                is_whitelisted, abuse_confidence_score, country_name = check_abuseipdb(ip_address, self.max_age_in_days)
                self.update_checked_ips(ip_address, is_whitelisted, abuse_confidence_score, country_name)
                self.ip_checked.emit(ip_address, is_whitelisted if is_whitelisted is not None else False,
                                     abuse_confidence_score, str(country_name))
            else:
                print("API limit reached. Skipping IP check.")

    def is_api_limit_reached(self):
        # Check if the API call limit is reached
        base_url = 'https://api.abuseipdb.com/api/v2/check'
        query_params = {
            'ipAddress': '8.8.8.8',  # Use a dummy IP address for checking API limit
            'maxAgeInDays': self.max_age_in_days,
            'verbose': False,
        }
        headers = {
            'Accept': 'application/json',
            'Key': 'a131308d736a692d4e2c48dc9f09f3b08eadb40b4b0414b6807ea40e5c6a6a5552b21c99aac1c4c4',  # Replace with your AbuseIPDB API key
        }

        try:
            response = requests.get(base_url, params=query_params, headers=headers)
            return response.status_code == 429  # Check if the status code is 429 (Too Many Requests)
        except requests.exceptions.RequestException as e:
            print(f"Request Exception: {e}")
            # Handle the exception as needed (log, raise, etc.)
            return True  # Assume the limit is reached in case of an exception

    def is_ip_checked(self, ip_address):
        # Check if the IP is in the checked IPs CSV file
        checked_ips_file = "checkedIPs.csv"

        if not os.path.exists(checked_ips_file):
            return False

        with open(checked_ips_file, 'r') as file:
            reader = csv.reader(file)
            # Check if the IP is already in the file
            for row in reader:
                if row and row[0] == ip_address:
                    return True

        return False

    def update_checked_ips(self, ip_address, is_whitelisted, abuse_confidence_score, country_name):
        # Update the checked IPs CSV file
        print(
            f"Updating checked IPs for {ip_address}. Is Whitelisted: {is_whitelisted}, Score: {abuse_confidence_score}, Country: {country_name}")
        checked_ips_file = "checkedIPs.csv"
        with open(checked_ips_file, 'a', newline='') as file:
            writer = csv.writer(file)
            # If the file is empty, write headers
            if file.tell() == 0:
                writer.writerow(["IP Address", "Is Whitelisted", "Abuse Confidence Score", "Country"])
            writer.writerow([ip_address, is_whitelisted, abuse_confidence_score, country_name])

        # If the abuse confidence score is higher than 50, also update the abusive IPs CSV file
        if abuse_confidence_score is not None and abuse_confidence_score > 1:
            abusive_ips_file = "abusiveIPs.csv"
            with open(abusive_ips_file, 'a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([ip_address, abuse_confidence_score, country_name])

        # Emit the signal with the results
        self.ip_checked.emit(ip_address, is_whitelisted if is_whitelisted is not None else False,
                             abuse_confidence_score, country_name)

class UpdateThread(QThread):
    updated = pyqtSignal(dict)

    def __init__(self):
        super(UpdateThread, self).__init__()
        self._is_running = True

    def run(self):
        while self._is_running:
            cpu_percent = psutil.cpu_percent(interval=None)

            send_start = psutil.net_io_counters().bytes_sent
            recv_start = psutil.net_io_counters().bytes_recv

            self.msleep(1000)

            send_end = psutil.net_io_counters().bytes_sent
            recv_end = psutil.net_io_counters().bytes_recv

            send_speed = ((send_end - send_start) * 8) / 1024
            recv_speed = ((recv_end - recv_start) * 8) / 1024

            info = {
                "CPU Usage": f"{cpu_percent}%",
                "RAM Usage": f"{psutil.virtual_memory().percent}%",
                "Disk Usage": f"{psutil.disk_usage('/').percent}%",
                "Network Send": f"{send_speed:.2f} kbps",
                "Network Received": f"{recv_speed:.2f} kbps",
                "Cores": psutil.cpu_count(logical=False),
                "Logical Cores": psutil.cpu_count(logical=True),
            }
            self.updated.emit(info)

    def stop(self):
        self._is_running = False
        self.wait()

class TrafficThread(QThread):
    updated = pyqtSignal(list)

    def __init__(self, csv_file, unique_ip_file):
        super().__init__()
        self.csv_file = csv_file
        self.unique_ip_file = unique_ip_file
        self.unique_ips = self.load_unique_ips()
        self._is_running = True

    def load_unique_ips(self):
        unique_ips = set()
        if os.path.exists(self.unique_ip_file):
            with open(self.unique_ip_file, 'r') as file:
                reader = csv.reader(file)
                for row in reader:
                    unique_ips.add(row[0])
        return unique_ips

    def save_unique_ips(self):
        with open(self.unique_ip_file, 'w', newline='') as file:
            writer = csv.writer(file)
            for ip in self.unique_ips:
                writer.writerow([ip])

    def run(self):
        try:
            while self._is_running:
                connections = self.get_connections()

                # Save the connections data to the CSV file
                self.save_to_csv(connections)

                # Emit the updated signal with the connections data
                self.updated.emit(connections)

                self.msleep(1000)
        except Exception as e:
            print(f"Error in TrafficThread: {e}")

    def stop(self):
        self._is_running = False
        self.wait()

    def get_connections(self):
        connections = []
        for conn in psutil.net_connections(kind='inet'):
            conn_info = {
                "Type": self.get_connection_type(conn.type),
                "Local Address": f"{conn.laddr.ip}:{conn.laddr.port}",
                "Remote Address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
            }
            connections.append(conn_info)
            self.unique_ips.add(conn.laddr.ip)
            if conn.raddr:
                self.unique_ips.add(conn.raddr.ip)
        for conn in psutil.net_connections(kind='inet6'):
            conn_info = {
                "Type": self.get_connection_type(conn.type),
                "Local Address": f"{conn.laddr.ip}:{conn.laddr.port}",
                "Remote Address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
            }
            connections.append(conn_info)
            self.unique_ips.add(conn.laddr.ip)
            if conn.raddr:
                self.unique_ips.add(conn.raddr.ip)
        self.save_unique_ips()
        return connections

    def get_connection_type(self, conn_type):
        return "TCP" if conn_type == socket.SOCK_STREAM else "UDP"

    def save_to_csv(self, data):
        with open(self.csv_file, mode='a', newline='') as file:
            writer = csv.writer(file)
            for row in data:
                writer.writerow(row.values())

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

class AbusiveIPWidget(QTreeWidget):

    def __init__(self, abusive_ips_file="abusiveIPs.csv"):
        super().__init__()

        self.setHeaderLabels(["Abusive IP Address", "Abuse Confidence Score", "Country"])
        self.setColumnWidth(0, 200)
        self.setColumnWidth(1, 200)
        self.setColumnWidth(2, 200)  # Adjust the width as needed

        self.abusive_ips_file = abusive_ips_file
        self.load_abusive_ips()

    def load_abusive_ips(self):
        if os.path.exists(self.abusive_ips_file):
            with open(self.abusive_ips_file, 'r') as file:
                reader = csv.reader(file)
                # Skip the header
                next(reader, None)
                for row in reader:
                    if row:
                        ip_address = row[0]
                        abuse_confidence_score = row[1]
                        country_name = row[2] if len(row) > 2 else "N/A"
                        self.add_abusive_ip(ip_address, abuse_confidence_score, country_name)

    def add_abusive_ip(self, ip_address, abuse_confidence_score, country_name):
        parent = QTreeWidgetItem(self)
        parent.setText(0, ip_address)
        parent.setText(1, str(abuse_confidence_score))
        parent.setText(2, country_name)

    def refresh_abusive_ips(self):
        # Clear existing items in the widget
        self.clear()

        # Load the latest abusive IPs from the CSV file
        self.load_abusive_ips()

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

class ClosingProgressDialog(QDialog):
    def __init__(self, message, parent=None):
        super(ClosingProgressDialog, self).__init__(parent)
        self.setWindowTitle("Closing Program")
        self.setWindowModality(Qt.WindowModal)

        self.message_label = QLabel(message)
        self.message_label.setAlignment(Qt.AlignCenter)

        self.setFixedSize(300, 100)


        self.cancel_button = QPushButton("Force Close")
        self.cancel_button.clicked.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(self.message_label)
        layout.addWidget(self.cancel_button)

    def set_message(self, message):
        self.message_label.setText(message)

class ClosingThread(QThread):
    closed = pyqtSignal()

    def __init__(self, update_thread, traffic_thread, ip_check_thread, parent=None):
        super(ClosingThread, self).__init__(parent)
        self.update_thread = update_thread
        self.traffic_thread = traffic_thread
        self.ip_check_thread = ip_check_thread

    def run(self):
        self.stop_threads()
        self.closed.emit()

    def stop_threads(self):
        # Stop and wait for the threads to finish
        self.update_thread.stop()
        self.traffic_thread.stop()
        self.ip_check_thread.stop()

class SystemMonitor(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("System Monitor")
        self.setGeometry(100, 100, 1920, 1080)

        splitter = QSplitter()

        system_info_group = QGroupBox("System Information")
        system_info_layout = QVBoxLayout()

        self.system_info = InfoFrame()
        system_info_layout.addWidget(self.system_info)

        system_info_group.setLayout(system_info_layout)
        system_info_group.setFixedWidth(400)

        network_info_group = QGroupBox("Network Information")
        network_info_layout = QVBoxLayout()

        self.traffic_widget = TrafficWidget()
        network_info_layout.addWidget(self.traffic_widget)

        network_info_group.setLayout(network_info_layout)

        abusive_ips_group = QGroupBox("Abusive IPs")
        abusive_ips_layout = QVBoxLayout()

        self.abusive_ip_widget = AbusiveIPWidget()
        abusive_ips_layout.addWidget(self.abusive_ip_widget)

        abusive_ips_group.setLayout(abusive_ips_layout)

        splitter.addWidget(system_info_group)
        splitter.addWidget(network_info_group)
        splitter.addWidget(abusive_ips_group)

        self.setCentralWidget(splitter)

        self.closing_progress_dialog = ClosingProgressDialog("Closing, please wait...", self)
        
        # Specify the path for the CSV file
        csv_file = "NetworkTrafficLog.csv"
        unique_ip_file = "uniqueIpAddress.csv"
        checked_ip_file = "checkedIPs.csv"
        abusive_ip_file = "abusiveIPs.csv"

        # Create the files with headers if they don't exist
        self.create_csv_file(csv_file, ["Type", "Local Address", "Remote Address"])
        self.create_csv_file(unique_ip_file, ["IP Address"])
        self.create_csv_file(checked_ip_file, ["IP Address", "Is Whitelisted", "Abuse Confidence Score"])
        self.create_csv_file(abusive_ip_file, ["IP Address", "Abuse Confidence Score", "Country"])

        # Create and start the UpdateThread
        self.update_thread = UpdateThread()
        self.update_thread.updated.connect(self.system_info.set_info)
        self.update_thread.start()

        # Create and start the TrafficThread
        self.traffic_thread = TrafficThread(csv_file, unique_ip_file)
        self.traffic_thread.updated.connect(self.traffic_widget.set_traffic_info)
        self.traffic_thread.start()

        # Create and start the IPCheckThread
        self.ip_check_thread = IPCheckThread()
        self.ip_check_thread.ip_checked.connect(self.handle_ip_checked)
        self.ip_check_thread.start()


    def handle_ip_checked(self, ip_address, is_whitelisted, abuse_confidence_score, country_name):
        if abuse_confidence_score is not None and abuse_confidence_score > 1:
            self.abusive_ip_widget.add_abusive_ip(ip_address, abuse_confidence_score, country_name)
            # Refresh the AbusiveIPWidget with the latest data
            self.abusive_ip_widget.refresh_abusive_ips()
        # You can use country_name as needed in your application
        # For example, print it:
        print(f"Country info for {ip_address}: {country_name}")

    def stop_threads(self):
        # Stop and wait for the threads to finish
        self.update_thread.stop()
        self.traffic_thread.stop()
        self.ip_check_thread.stop()

    def create_csv_file(self, file_path, headers):
        if not os.path.exists(file_path):
            with open(file_path, 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(headers)

    def closeEvent(self, event):
        # Override the close event to stop threads before exiting
        self.closing_progress_dialog = ClosingProgressDialog("Closing, please wait...", self)
        self.closing_thread = ClosingThread(self.update_thread, self.traffic_thread, self.ip_check_thread)
        self.closing_thread.closed.connect(self.closing_progress_dialog.accept)

        self.closing_thread.start()
        self.closing_progress_dialog.exec_()

        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SystemMonitor()
    window.show()
    sys.exit(app.exec_())
