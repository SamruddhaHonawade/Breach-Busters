import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QLabel, QPushButton,
    QWidget, QTabWidget, QMessageBox
)
from PyQt5.QtGui import QIcon
import ccountinfo

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Continuous Attack Surface Monitoring Tool")
        self.setGeometry(100, 100, 1000, 700)

        # Check if icon file exists before setting
        try:
            self.setWindowIcon(QIcon("icon.png"))  # Ensure "icon.png" is in the same directory
        except Exception as e:
            print(f"Icon not found: {e}")

        # Status Bar
        self.statusBar().showMessage("Ready")

        # Central Widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Layouts
        main_layout = QVBoxLayout()
        tab_widget = QTabWidget()

        # Dashboard Tab
        dashboard_tab = QWidget()
        dashboard_layout = QVBoxLayout()
        dashboard_layout.addWidget(QLabel("<h2>System Health</h2>"))
        dashboard_layout.addWidget(QLabel("Summary of system health..."))  # Add actual content
        dashboard_layout.addWidget(QLabel("<h2>Recent Alerts</h2>"))
        dashboard_layout.addWidget(QLabel("Summary of recent alerts..."))  # Add actual content
        dashboard_layout.addWidget(QLabel("<h2>Scan Summary</h2>"))
        dashboard_layout.addWidget(QLabel("Summary of scan results..."))  # Add actual content
        dashboard_layout.addWidget(QLabel("<h2>Key Metrics</h2>"))
        dashboard_layout.addWidget(QLabel("Display key metrics here..."))  # Add actual content
        dashboard_tab.setLayout(dashboard_layout)
        tab_widget.addTab(dashboard_tab, "Dashboard")

        # Scan Management Tab
        scan_tab = QWidget()
        scan_layout = QVBoxLayout()
        scan_layout.addWidget(QLabel("<h2>Configure Scan</h2>"))
        start_scan_button = QPushButton("Start New Scan")
        start_scan_button.clicked.connect(self.start_new_scan)
        scan_layout.addWidget(start_scan_button)
        scan_tab.setLayout(scan_layout)
        tab_widget.addTab(scan_tab, "Scan Management")

        # Threat Analysis Tab
        threat_tab = QWidget()
        threat_layout = QVBoxLayout()
        threat_layout.addWidget(QLabel("<h2>Threat List</h2>"))
        threat_layout.addWidget(QLabel())  # Add actual content
        threat_layout.addWidget(QLabel("<h2>ML Analysis</h2>"))
        threat_layout.addWidget(QLabel("Results of machine learning analysis..."))  # Add actual content
        threat_layout.addWidget(QLabel("<h2>Historical Data</h2>"))
        threat_layout.addWidget(QLabel("Graphical representation of historical data..."))  # Add actual content
        threat_tab.setLayout(threat_layout)
        tab_widget.addTab(threat_tab, "Threat Analysis")

        main_layout.addWidget(tab_widget)
        central_widget.setLayout(main_layout)

    def start_new_scan(self):
        button_reply = QMessageBox.question(self, 'Start New Scan', "Are you sure you want to start a new scan?",
                                            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if button_reply == QMessageBox.Yes:
            self.statusBar().showMessage("Starting new scan...")
            # Add logic to start the scan
            self.statusBar().showMessage("Scan started")

            self.scan_layout.addWidget(QLabel("Hiiiii"))



app = QApplication(sys.argv)
app.setStyle("Fusion")

# Apply custom styles
app.setStyleSheet("""
    QMainWindow {
        background-color: #f0f0f0;
    }
    QLabel {
        font-size: 14px;
    }
    QPushButton {
        font-size: 14px;
        padding: 10px;
        margin: 5px;
    }
    QTabWidget::pane { 
        border: 1px solid #ccc;
        background: #fafafa;
    }
    QTabWidget::tab-bar {
        alignment: center;
    }
    QTabBar::tab {
        background: #e0e0e0;
        border: 1px solid #ccc;
        padding: 10px;
        margin: 1px;
    }
    QTabBar::tab:selected, QTabBar::tab:hover {
        background: #d0d0d0;
    }
""")

window = MainWindow()
window.show()
sys.exit(app.exec_())

