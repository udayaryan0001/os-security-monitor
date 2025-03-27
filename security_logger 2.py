qimport sys
import psutil
import time
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                            QHBoxLayout, QPushButton, QTextEdit, QLabel,
                            QComboBox, QFileDialog, QMessageBox)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont, QPalette, QColor
import csv
from collections import defaultdict

class SecurityLogger(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("OS Event Security Logger")
        self.setMinimumSize(800, 600)
        
        # Initialize variables
        self.logs = []
        self.process_history = defaultdict(list)
        self.anomaly_threshold = 5  # Threshold for anomaly detection
        
        # Create main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        
        # Create header
        header = QLabel("Real-Time Security Event Logger")
        header.setFont(QFont('Arial', 16, QFont.Weight.Bold))
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)
        
        # Create control panel
        control_panel = QHBoxLayout()
        
        # Filter dropdown
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All Events", "Process Events", "Resource Usage", "Security Alerts"])
        self.filter_combo.currentTextChanged.connect(self.filter_logs)
        control_panel.addWidget(QLabel("Filter:"))
        control_panel.addWidget(self.filter_combo)
        
        # Export button
        export_btn = QPushButton("Export Logs")
        export_btn.clicked.connect(self.export_logs)
        control_panel.addWidget(export_btn)
        
        # Clear button
        clear_btn = QPushButton("Clear Logs")
        clear_btn.clicked.connect(self.clear_logs)
        control_panel.addWidget(clear_btn)
        
        layout.addLayout(control_panel)
        
        # Create log display
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        layout.addWidget(self.log_display)
        
        # Create status bar
        self.statusBar().showMessage("Monitoring system events...")
        
        # Set up monitoring timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.monitor_system)
        self.timer.start(1000)  # Update every second
        
        # Set dark theme
        self.set_dark_theme()
        
    def set_dark_theme(self):
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))
        palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.Base, QColor(25, 25, 25))
        palette.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))
        palette.setColor(QPalette.ColorRole.ToolTipBase, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.ToolTipText, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
        palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
        palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
        palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
        palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.black)
        self.setPalette(palette)
        
    def monitor_system(self):
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Monitor processes
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                proc_info = proc.info()
                self.process_history[proc_info['name']].append({
                    'time': current_time,
                    'cpu': proc_info['cpu_percent'],
                    'memory': proc_info['memory_percent']
                })
                
                # Detect anomalies
                if len(self.process_history[proc_info['name']]) > self.anomaly_threshold:
                    recent_usage = [p['cpu'] for p in self.process_history[proc_info['name']][-self.anomaly_threshold:]]
                    if max(recent_usage) > 80:  # High CPU usage
                        self.log_event(f"Security Alert: High CPU usage detected for {proc_info['name']} (PID: {proc_info['pid']})")
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Monitor system resources
        cpu_percent = psutil.cpu_percent()
        memory_percent = psutil.virtual_memory().percent
        
        if cpu_percent > 80 or memory_percent > 80:
            self.log_event(f"System Alert: High resource usage detected (CPU: {cpu_percent}%, Memory: {memory_percent}%)")
    
    def log_event(self, event):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {event}"
        self.logs.append(log_entry)
        self.log_display.append(log_entry)
        self.log_display.verticalScrollBar().setValue(
            self.log_display.verticalScrollBar().maximum()
        )
    
    def filter_logs(self, filter_text):
        self.log_display.clear()
        for log in self.logs:
            if filter_text == "All Events":
                self.log_display.append(log)
            elif filter_text == "Process Events" and "Process" in log:
                self.log_display.append(log)
            elif filter_text == "Resource Usage" and "resource" in log.lower():
                self.log_display.append(log)
            elif filter_text == "Security Alerts" and "Security Alert" in log:
                self.log_display.append(log)
    
    def export_logs(self):
        file_name, _ = QFileDialog.getSaveFileName(
            self, "Export Logs", "", "CSV Files (*.csv)"
        )
        if file_name:
            try:
                with open(file_name, 'w', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(['Timestamp', 'Event'])
                    for log in self.logs:
                        timestamp = log[1:20]  # Extract timestamp
                        event = log[22:]  # Extract event message
                        writer.writerow([timestamp, event])
                QMessageBox.information(self, "Success", "Logs exported successfully!")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export logs: {str(e)}")
    
    def clear_logs(self):
        self.logs.clear()
        self.log_display.clear()
        self.process_history.clear()
        self.statusBar().showMessage("Logs cleared")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = SecurityLogger()
    window.show()
    sys.exit(app.exec())
    