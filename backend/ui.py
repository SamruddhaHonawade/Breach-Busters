import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QLabel, QPushButton,
    QWidget, QTabWidget, QMessageBox, QLineEdit, QTextEdit
)
from PyQt5.QtGui import QIcon
import subprocess
import platform
import wmi
# Import the vulnerability scanner module
import vulscanner as vs
from pas_check import AccNames

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
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

        # Execute and display system health information
        system_health_info = self.get_system_health_info()
        dashboard_layout.addWidget(QLabel("<h2>System Health</h2>"))
        dashboard_layout.addWidget(QLabel(system_health_info))

        # Execute and display weak passwords information
        weak_passwords_info = self.check_weak_passwords()
        dashboard_layout.addWidget(QLabel("<h2>Weak Passwords</h2>"))
        dashboard_layout.addWidget(QLabel(weak_passwords_info))

        # Execute and display open ports and vulnerable ports
        open_ports_info = self.get_open_ports_info()
        dashboard_layout.addWidget(QLabel("<h2>Open Ports</h2>"))
        dashboard_layout.addWidget(QLabel(open_ports_info))


        # Execute and display outdated software information
        outdated_software_info = self.check_outdated_software()
        dashboard_layout.addWidget(QLabel("<h2>Outdated Software</h2>"))
        dashboard_layout.addWidget(QLabel(outdated_software_info))

        dashboard_tab.setLayout(dashboard_layout)
        tab_widget.addTab(dashboard_tab, "Dashboard")

        scanner_tab = QWidget()
        scanner_layout = QVBoxLayout()
        scanner_layout.addWidget(QLabel("Enter URL to scan:"))
        self.url_input = QLineEdit()
        scanner_layout.addWidget(self.url_input)
        self.scan_results = QTextEdit()
        self.scan_results.setReadOnly(True)
        scanner_layout.addWidget(self.scan_results)
        scan_button = QPushButton("Scan")
        scan_button.clicked.connect(self.scan_website)
        scanner_layout.addWidget(scan_button)
        scanner_tab.setLayout(scanner_layout)
        tab_widget.addTab(scanner_tab, "Website Vulnerability Scanner")

        main_layout.addWidget(tab_widget)
        central_widget.setLayout(main_layout)

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
        # Check for outdated software using package manager commands or specific vulnerability databases
        try:
            outdated_info = "<br>Outdated Software:<br>"
            if platform.system() == "Windows":
                outdated_info += "Windows does not have a centralized package manager."
            else:
                outdated_info += f"Consider running 'apt list --upgradable' on Debian-based systems or 'yum list updates' on RPM-based systems."
            return outdated_info
        except Exception as e:
            return f"Error: {e}"

    def scan_website(self):
        url = self.url_input.text()
        if url:
            self.statusBar().showMessage(f"Scanning {url}...")
            try:
                results = vs.run_vulnerability_scan(url)
                self.scan_results.setPlainText(results)
                self.statusBar().showMessage(f"Scan of {url} completed")
                QMessageBox.information(self, "Scan Complete", f"The scan of {url} is complete.")
            except Exception as e:
                self.statusBar().showMessage("Scan failed")
                QMessageBox.critical(self, "Scan Error", f"An error occurred during the scan: {e}")
                print(f"Error during scan: {e}")
        else:
            QMessageBox.warning(self, "Input Error", "Please enter a URL to scan.")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec_())
