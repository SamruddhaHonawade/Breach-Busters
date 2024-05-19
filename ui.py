import sys
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QLabel, QPushButton,
    QWidget, QTabWidget, QMessageBox, QLineEdit, QTextEdit, QFormLayout
)
from PyQt5.QtGui import QIcon
import platform
import subprocess
from supabase_py import create_client
import vulscanner as vs
from pas_check import AccNames
import psutil
from datetime import datetime
import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder
import time
import os
import smtplib
import socket
from scapy.all import sniff
from pygetwindow import getActiveWindow

# Initialize Supabase client
supabase_url = "https://ohkkxqszvvdqfmnoxfgz.supabase.co"
supabase_key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9oa2t4cXN6dnZkcWZtbm94Zmd6Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3MTYwNzUzNjEsImV4cCI6MjAzMTY1MTM2MX0.sz0gpro3o_MBfAvqxxhzU3qCDaQqP5F_RXf691HZL48"
supabase = create_client(supabase_url, supabase_key)


class NetworkMonitorThread(QThread):
    update_scan_results = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.running = False

    def run(self):
        model = joblib.load('DT_malacious_traffic_classifier.pkl')
        label_encoder = LabelEncoder()

        while self.running:
            network_io = self.get_system_network_io()
            if network_io and network_io['details']:
                for detail in network_io['details']:
                    df = pd.DataFrame([[
                        detail['IPV4_SRC_ADDR'],
                        detail['L4_SRC_PORT'],
                        detail['IPV4_DST_ADDR'],
                        detail['L4_DST_PORT'],
                        detail['PROTOCOL'],
                        0,
                        network_io['in_bytes'],
                        network_io['out_bytes'],
                        network_io['in_packets'],
                        network_io['out_packets'],
                        detail['TCP_FLAGS'],
                        detail['FLOW_DURATION_MILLISECONDS']
                    ]], columns=[
                        'IPV4_SRC_ADDR', 'L4_SRC_PORT', 'IPV4_DST_ADDR', 'L4_DST_PORT',
                        'PROTOCOL', 'TCP_FLAGS', 'IN_BYTES', 'OUT_BYTES',
                        'IN_PKTS', 'OUT_PKTS', 'TCP_FLAGS', 'FLOW_DURATION_MILLISECONDS'
                    ])

                    for col in df.columns:
                        if df[col].dtype == 'object':
                            df[col] = label_encoder.fit_transform(df[col])

                    pred = model.predict(df)
                    if pred[0] == 0:
                        self.update_scan_results.emit(f"Malicious traffic detected: {detail['IPV4_SRC_ADDR']} -> {detail['IPV4_DST_ADDR']}")

            time.sleep(5)

    def get_system_network_io(self):
        net_io = psutil.net_io_counters(pernic=False)
        connections = psutil.net_connections(kind='inet')

        total_in_bytes = net_io.bytes_recv
        total_out_bytes = net_io.bytes_sent
        total_in_packets = net_io.packets_recv
        total_out_packets = net_io.packets_sent

        details = []

        for conn in connections:
            if conn.status == psutil.CONN_ESTABLISHED:
                if conn.raddr:
                    details.append({
                        'IPV4_SRC_ADDR': conn.laddr.ip,
                        'L4_SRC_PORT': conn.laddr.port,
                        'IPV4_DST_ADDR': conn.raddr.ip,
                        'L4_DST_PORT': conn.raddr.port,
                        'PROTOCOL': conn.type,
                        'TCP_FLAGS': 0,
                        'FLOW_DURATION_MILLISECONDS': 0
                    })
                else:
                    details.append({
                        'IPV4_SRC_ADDR': conn.raddr.ip if conn.raddr else 'unknown',
                        'L4_SRC_PORT': conn.raddr.port if conn.raddr else 0,
                        'IPV4_DST_ADDR': conn.laddr.ip,
                        'L4_DST_PORT': conn.laddr.port,
                        'PROTOCOL': conn.type,
                        'TCP_FLAGS': 0,
                        'FLOW_DURATION_MILLISECONDS': 0
                    })

        return {
            'in_bytes': total_in_bytes,
            'out_bytes': total_out_bytes,
            'in_packets': total_in_packets,
            'out_packets': total_out_packets,
            'details': details
        }


class LogMonitoringThread(QThread):
    update_log_results = pyqtSignal(str)

    def run(self):
        last_active_window_title = None
        while True:
            try:
                active_window = getActiveWindow()
                if active_window.title != last_active_window_title:
                    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    self.update_log_results.emit(f"Active window title: {active_window.title} | Accessed at: {current_time}")
                    last_active_window_title = active_window.title

                    if "settings" in active_window.title.lower() or "user" in active_window.title.lower():
                        self.update_log_results.emit(f"Alert! User is trying to access settings or change user information at {current_time}")
            except Exception as e:
                self.update_log_results.emit(f"An error occurred: {e}")
            time.sleep(1)


class BreachDetectionThread(QThread):
    update_breach_results = pyqtSignal(str)

    def run(self):
        sniff(prn=self.monitor_packet)

    def monitor_packet(self, packet):
        if packet.haslayer('Raw'):
            payload_length = len(packet['Raw'].load)
            if payload_length > 1500:
                self.update_breach_results.emit(
                    f"Alert! Large amount of data is being uploaded or downloaded. Payload length: {payload_length}")
class LoginForm(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle('Login Form')
        self.setGeometry(100, 100, 300, 200)

        # Initialize form layout
        layout = QVBoxLayout()

        # Organization Name
        self.org_name = QLineEdit()
        layout.addWidget(QLabel('Organization Name:'))
        layout.addWidget(self.org_name)

        # Admin Name
        self.admin_name = QLineEdit()
        layout.addWidget(QLabel('Admin Name:'))
        layout.addWidget(self.admin_name)

        # Email
        self.email = QLineEdit()
        layout.addWidget(QLabel('Email:'))
        layout.addWidget(self.email)

        # Phone Number
        self.phone_no = QLineEdit()
        layout.addWidget(QLabel('Phone Number:'))
        layout.addWidget(self.phone_no)

        # Password
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        layout.addWidget(QLabel('Password:'))
        layout.addWidget(self.password)

        # Login Button
        self.login_button = QPushButton('Login')
        self.login_button.clicked.connect(self.login)
        layout.addWidget(self.login_button)

        self.setLayout(layout)

    def login(self):
        org_name = self.org_name.text()
        admin_name = self.admin_name.text()
        email = self.email.text()
        phone_no = self.phone_no.text()
        password = self.password.text()

        # Check if any field is empty
        if not org_name or not admin_name or not email or not phone_no or not password:
            QMessageBox.warning(self, 'Input Error', 'All fields are required!')
            return

        # Assuming successful login, display the MainWindow
        self.main_window = MainWindow(org_name, admin_name, email, phone_no)
        self.main_window.setWindowTitle("Continuous Attack Surface Monitoring Tool")
        self.main_window.setGeometry(100, 100, 1000, 700)
        self.main_window.show()
        self.hide()  # Hide the login form


class MainWindow(QMainWindow):
    def __init__(self, org_name, admin_name, email, phone_no):
        super().__init__()
        self.org_name = org_name
        self.admin_name = admin_name
        self.email = email
        self.phone_no = phone_no

        self.setWindowTitle("Continuous Attack Surface Monitoring Tool")
        self.setGeometry(100, 100, 1000, 700)
        try:
            self.setWindowIcon(QIcon("icon.png"))
        except Exception as e:
            print(f"Icon not found: {e}")

        self.statusBar().showMessage("Ready")
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout()
        tab_widget = QTabWidget()

        dashboard_tab = QWidget()
        dashboard_layout = QVBoxLayout()

        system_health_info = self.get_system_health_info()
        dashboard_layout.addWidget(QLabel("<h2>System Health</h2>"))
        dashboard_layout.addWidget(QLabel(system_health_info))

        weak_passwords_info = self.check_weak_passwords()
        dashboard_layout.addWidget(QLabel("<h2>Weak Passwords</h2>"))
        dashboard_layout.addWidget(QLabel(weak_passwords_info))

        open_ports_info = self.get_open_ports_info()
        dashboard_layout.addWidget(QLabel("<h2>Open Ports</h2>"))
        dashboard_layout.addWidget(QLabel(open_ports_info))

        outdated_software_info = self.check_outdated_software()
        dashboard_layout.addWidget(QLabel("<h2>Outdated Software</h2>"))
        dashboard_layout.addWidget(QLabel(outdated_software_info))

        dashboard_tab.setLayout(dashboard_layout)
        tab_widget.addTab(dashboard_tab, "Dashboard")

        scanner_tab = QWidget()
        scanner_layout = QFormLayout()

        self.url_input = QLineEdit()
        scanner_layout.addRow("URL to scan:", self.url_input)
        self.scan_results = QTextEdit()
        self.scan_results.setReadOnly(True)
        scanner_layout.addRow("Scan Results:", self.scan_results)
        scan_button = QPushButton("Scan")
        scan_button.clicked.connect(self.scan_website)
        scanner_layout.addWidget(scan_button)
        scanner_tab.setLayout(scanner_layout)
        tab_widget.addTab(scanner_tab, "Website Vulnerability Scanner")

        network_scanning_tab = QWidget()
        network_scanning_layout = QVBoxLayout()

        self.network_scan_results = QTextEdit()
        self.network_scan_results.setReadOnly(True)
        network_scanning_layout.addWidget(self.network_scan_results)

        self.start_network_monitor_button = QPushButton("Start Network Traffic Analyzer")
        self.start_network_monitor_button.clicked.connect(self.start_network_monitor)
        network_scanning_layout.addWidget(self.start_network_monitor_button)

        self.start_network_monitor_honey = QPushButton("Activate Honeypot")
        network_scanning_layout.addWidget(self.start_network_monitor_honey)
        network_scanning_tab.setLayout(network_scanning_layout)
        tab_widget.addTab(network_scanning_tab, "Network Scanning")

        behavior_analytics_tab = QWidget()
        behavior_analytics_layout = QVBoxLayout()

        self.breach_detection_results = QTextEdit()
        self.breach_detection_results.setReadOnly(True)
        self.log_monitoring_results = QTextEdit()
        self.log_monitoring_results.setReadOnly(True)

        self.breach_detection_button = QPushButton("Start Breach Detection")
        self.breach_detection_button.clicked.connect(self.start_breach_detection)
        self.log_monitoring_button = QPushButton("Start Log Monitoring")
        self.log_monitoring_button.clicked.connect(self.start_log_monitoring)

        behavior_analytics_layout.addWidget(QLabel("<h2>Breach Detection</h2>"))
        behavior_analytics_layout.addWidget(self.breach_detection_button)
        behavior_analytics_layout.addWidget(self.breach_detection_results)

        behavior_analytics_layout.addWidget(QLabel("<h2>Log Monitoring</h2>"))
        behavior_analytics_layout.addWidget(self.log_monitoring_button)
        behavior_analytics_layout.addWidget(self.log_monitoring_results)

        behavior_analytics_tab.setLayout(behavior_analytics_layout)
        tab_widget.addTab(behavior_analytics_tab, "Behavior Analytics")

        main_layout.addWidget(tab_widget)
        central_widget.setLayout(main_layout)

        self.network_monitor_thread = None
        self.breach_detection_thread = None
        self.log_monitoring_thread = None


    def get_system_health_info(self):
        system_info = []
        system_info.append("<b>Operating System Information:</b>")
        system_info.append(f"System: {platform.system()}")
        system_info.append(f"Release: {platform.release()}")
        system_info.append(f"Version: {platform.version()}")
        return "<br>".join(system_info)

    def get_open_ports_info(self):
        try:
            open_ports = self.check_open_ports()
            vulnerable_ports = self.check_vulnerable_ports(open_ports)
            open_ports_info = ["<b>Open Ports:</b>"]
            for port, service in vulnerable_ports.items():
                open_ports_info.append(f"Port {port} ({service}) - Vulnerable")
            for port in open_ports:
                if port not in vulnerable_ports:
                    open_ports_info.append(f"Port {port} - Not vulnerable")
            return "<br>".join(open_ports_info)
        except Exception as e:
            return f"Error: {e}"

    def check_open_ports(self):
        try:
            open_ports = []
            if platform.system() == "Windows":
                output = subprocess.check_output(["netstat", "-an"], text=True)
                lines = output.splitlines()
                for line in lines:
                    if "LISTENING" in line:
                        parts = line.split()
                        address = parts[1]
                        port = int(address.split(':')[-1])
                        open_ports.append(port)
            else:
                output = subprocess.check_output(["netstat", "-tuln"], text=True)
                lines = output.splitlines()
                for line in lines[2:]:  # Skip headers
                    parts = line.split()
                    address = parts[3]
                    port = int(address.split(':')[-1])
                    open_ports.append(port)
            return open_ports
        except Exception as e:
            print("An error occurred while checking open ports:", e)
            return []

    def check_vulnerable_ports(self, open_ports):
        vulnerable_ports = {
            21: "FTP",
            23: "Telnet",
            25: "SMTP",
            69: "TFTP",
            110: "POP3",
            135: "RPC",
            139: "NetBIOS",
            143: "IMAP",
            445: "SMB",
            1433: "MSSQL",
            1521: "Oracle DB",
            3306: "MySQL",
            3389: "RDP",
            5900: "VNC",
            8080: "HTTP Proxy",
        }
        vulnerable_ports_found = {}
        for port in open_ports:
            if port in vulnerable_ports:
                vulnerable_ports_found[port] = vulnerable_ports[port]
        return vulnerable_ports_found

    def check_weak_passwords(self):
        # Create an instance of AccNames
        accnames = AccNames()

        # Retrieve and format password policy information
        password_policy = ""
        try:
            password_policy = subprocess.run(["net", "accounts"], capture_output=True, text=True, check=True).stdout
        except subprocess.CalledProcessError:
            password_policy = "Error: Unable to retrieve password policy information using net accounts."
        except ModuleNotFoundError:
            password_policy = "Error: The 'subprocess' module is not available. Please ensure it's installed."

        # Format the information for display
        formatted_info = f"<br>Password Policy:<br>{password_policy.replace('\n', '<br>')}"

        return formatted_info

    def check_outdated_software(self):
        try:
            outdated_info = "<br>Outdated Software:"
            if platform.system() == "Windows":
                outdated_info += "Windows does not have a centralized package manager."
            else:
                outdated_info += f"Consider running 'apt list --upgradable' on Debian-based systems or 'yum list updates' on RPM-based systems."
            return outdated_info
        except Exception as e:
            return f"Error: {e}"

    def contains_vulnerabilities(self, results):
        # Define keywords or patterns that indicate vulnerabilities
        vulnerability_keywords = ["SQL Injection vulnerability found.", "XSS vulnerability found.", "CSRF vulnerability found."]

        for keyword in vulnerability_keywords:
            if keyword.lower() in results.lower():
                return True
        return False

    def save_results_to_db(self, results):
        try:
            if self.contains_vulnerabilities(results):
                data_to_insert = {
                    "organisation": self.org_name,
                    "username": self.admin_name,
                    "email": self.email,
                    "phone": self.phone_no,
                    "vulnerability": results
                }

                table_name = "vulnerabilities"
                response = supabase.table(table_name).insert(data_to_insert).execute()

                if response.get("status_code") == 201:
                    print("Data inserted successfully.")

                    # Send email notification
                    self.send_email_notification(results)
                else:
                    print("Failed to insert data into Supabase.")
            else:
                print("No significant vulnerabilities found. Data not inserted.")
        except Exception as e:
            print(f"Error saving results to database: {e}")

    import os
    import smtplib

    def send_email_notification(self, vulnerability_results):
        try:
            sender_email = 'breachbusters8@gmail.com'
            sender_password = 'samruddha'
            receiver_email = self.email

            if sender_email and sender_password and receiver_email:
                message = f"Subject: Vulnerability Alert\n\nDear User,\n\nThe following vulnerability was detected:\n\n{vulnerability_results}\n\nBest regards,\nYour Security Team"
                with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
                    smtp.login(sender_email, sender_password)
                    smtp.sendmail(sender_email, receiver_email, message.encode('utf-8'))
                    print("Email notification sent successfully.")
            else:
                print("Email configuration not provided. Notification not sent.")
        except Exception as e:
            print(f"Error sending email notification: {e}")

    def scan_website(self):
        url = self.url_input.text()
        if url:
            self.statusBar().showMessage(f"Scanning {url}...")
            try:
                results = vs.run_vulnerability_scan(url)
                self.scan_results.setPlainText(results)
                if self.contains_vulnerabilities(results):
                    self.save_results_to_db(url, results)
                self.statusBar().showMessage(f"Scan of {url} completed")
                QMessageBox.information(self, "Scan Complete", f"The scan of {url} is complete.")
            except Exception as e:
                self.statusBar().showMessage("Scan failed")
                QMessageBox.critical(self, "Scan Error", f"An error occurred during the scan: {e}")
                print(f"Error during scan: {e}")
        else:
            QMessageBox.warning(self, "Input Error", "Please enter a URL to scan.")

    def update_network_scan_results(self, result):
        self.network_scan_results.append(result)

    def start_network_monitor(self):
        if not self.network_monitor_thread.isRunning():
            self.network_monitor_thread.running = True
            self.network_monitor_thread.start()
            self.start_network_monitor_button.setText("Stop Network Traffic Analyzer")
        else:
            self.network_monitor_thread.running = False
            self.network_monitor_thread.wait()
            self.start_network_monitor_button.setText("Start Network Traffic Analyzer")

    def scan_open_ports(self):
        open_ports_info = self.get_open_ports_info()
        self.network_scan_results.append(open_ports_info)

    def start_breach_detection(self):
        if not self.breach_detection_thread or not self.breach_detection_thread.isRunning():
            self.breach_detection_thread = BreachDetectionThread()
            self.breach_detection_thread.update_breach_results.connect(self.update_breach_detection_results)
            self.breach_detection_thread.start()
            self.breach_detection_button.setText("Stop Breach Detection")
        else:
            self.breach_detection_thread.quit()
            self.breach_detection_thread.wait()
            self.breach_detection_thread = None
            self.breach_detection_button.setText("Start Breach Detection")

    def update_breach_detection_results(self, result):
        self.breach_detection_results.append(result)

    def start_log_monitoring(self):
        if not self.log_monitoring_thread or not self.log_monitoring_thread.isRunning():
            self.log_monitoring_thread = LogMonitoringThread()
            self.log_monitoring_thread.update_log_results.connect(self.update_log_monitoring_results)
            self.log_monitoring_thread.start()
            self.log_monitoring_button.setText("Stop Log Monitoring")
        else:
            self.log_monitoring_thread.quit()
            self.log_monitoring_thread.wait()
            self.log_monitoring_thread = None
            self.log_monitoring_button.setText("Start Log Monitoring")

    def update_log_monitoring_results(self, result):
        self.log_monitoring_results.append(result)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    form = LoginForm()
    form.show()
    sys.exit(app.exec_())
