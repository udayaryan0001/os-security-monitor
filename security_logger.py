import sys
import psutil
import time
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import csv
from collections import defaultdict
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib
import os
import hashlib
import socket
import subprocess
from pathlib import Path
import signal
matplotlib.use('TkAgg')

class ProcessControlDialog:
    def __init__(self, parent, process_info):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Process Control")
        self.dialog.geometry("400x300")
        self.process_info = process_info
        
        # Make dialog modal
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Configure style
        style = ttk.Style()
        self.dialog.configure(bg=style.lookup("Dark.TFrame", "background"))
        
        # Process info
        info_frame = ttk.Frame(self.dialog, style="Dark.TFrame")
        info_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(info_frame, text="Process Information", style="Dark.TLabel",
                 font=('Arial', 12, 'bold')).pack(pady=5)
        
        info_text = (
            f"Name: {process_info['name']}\n"
            f"PID: {process_info['pid']}\n"
            f"CPU: {process_info['cpu']:.1f}%\n"
            f"Memory: {process_info['memory']:.1f}%\n"
            f"Category: {process_info['category']}"
        )
        
        ttk.Label(info_frame, text=info_text, style="Dark.TLabel").pack(pady=5)
        
        # Control buttons
        button_frame = ttk.Frame(self.dialog, style="Dark.TFrame")
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(button_frame, text="Terminate (SIGTERM)",
                  command=self.terminate_process).pack(fill=tk.X, pady=2)
        
        ttk.Button(button_frame, text="Force Quit (SIGKILL)",
                  command=self.force_quit_process).pack(fill=tk.X, pady=2)
        
        ttk.Button(button_frame, text="Suspend",
                  command=self.suspend_process).pack(fill=tk.X, pady=2)
        
        ttk.Button(button_frame, text="Resume",
                  command=self.resume_process).pack(fill=tk.X, pady=2)
        
        ttk.Button(button_frame, text="Lower Priority",
                  command=self.lower_priority).pack(fill=tk.X, pady=2)
        
        ttk.Button(button_frame, text="Cancel",
                  command=self.dialog.destroy).pack(fill=tk.X, pady=2)
        
        # Center the dialog
        self.dialog.update_idletasks()
        width = self.dialog.winfo_width()
        height = self.dialog.winfo_height()
        x = (self.dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (height // 2)
        self.dialog.geometry(f'{width}x{height}+{x}+{y}')

    def terminate_process(self):
        if messagebox.askyesno("Confirm", "Are you sure you want to terminate this process?"):
            try:
                process = psutil.Process(self.process_info['pid'])
                process.terminate()
                messagebox.showinfo("Success", "Process terminated successfully")
                self.dialog.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to terminate process: {str(e)}")

    def force_quit_process(self):
        if messagebox.askyesno("Confirm", "WARNING: Force quitting may cause data loss. Continue?"):
            try:
                process = psutil.Process(self.process_info['pid'])
                process.kill()
                messagebox.showinfo("Success", "Process force quit successfully")
                self.dialog.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to force quit process: {str(e)}")

    def suspend_process(self):
        try:
            process = psutil.Process(self.process_info['pid'])
            process.suspend()
            messagebox.showinfo("Success", "Process suspended successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to suspend process: {str(e)}")

    def resume_process(self):
        try:
            process = psutil.Process(self.process_info['pid'])
            process.resume()
            messagebox.showinfo("Success", "Process resumed successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to resume process: {str(e)}")

    def lower_priority(self):
        try:
            process = psutil.Process(self.process_info['pid'])
            process.nice(19)
            messagebox.showinfo("Success", "Process priority lowered successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to lower process priority: {str(e)}")

class SecurityLogger:
    def __init__(self, root):
        self.root = root
        self.root.title("OS Security Monitor")
        self.root.geometry("1400x900")
        
        # Initialize variables
        self.logs = []
        self.process_history = defaultdict(list)
        self.anomaly_threshold = 5
        self.is_dark_theme = True
        self.auto_refresh = True
        self.cpu_history = []
        self.memory_history = []
        self.top_processes = []
        self.network_connections = set()
        self.file_hashes = {}
        self.suspicious_patterns = {
            'processes': [
                'crypto_miner', 'malware', 'backdoor', 
                'keylogger', 'exploit', 'suspicious'
            ],
            'network_ports': [
                4444,  # Metasploit
                31337, # Back Orifice
                6666,  # IRC Bot
                1080   # SOCKS proxy
            ],
            'file_extensions': [
                '.exe', '.dll', '.sh', '.bat', '.vbs', '.ps1'
            ]
        }
        
        # Security settings
        self.security_config = {
            'max_cpu_percent': 80,
            'max_memory_percent': 80,
            'max_connections_per_process': 50,
            'monitored_directories': ['/usr/bin', '/usr/local/bin', '/Applications'],
            'blocked_ips': set(),
            'blocked_ports': set(self.suspicious_patterns['network_ports']),
            'process_whitelist': set(),
            'process_blacklist': set()
        }
        
        # Process categories with security context
        self.process_categories = {
            'browsers': {
                'processes': ['chrome', 'firefox', 'safari', 'edge', 'brave'],
                'allowed_ports': [80, 443, 8080],
                'max_instances': 10
            },
            'development': {
                'processes': ['python', 'node', 'code', 'idea', 'git'],
                'allowed_ports': [3000, 8000, 8080],
                'max_instances': 20
            },
            'system': {
                'processes': ['kernel', 'system', 'finder', 'dock', 'systemui'],
                'allowed_ports': [],
                'protected': True
            },
            'media': {
                'processes': ['music', 'spotify', 'vlc', 'quicktime'],
                'allowed_ports': [80, 443],
                'max_instances': 5
            },
            'office': {
                'processes': ['word', 'excel', 'powerpoint', 'outlook'],
                'allowed_ports': [80, 443],
                'max_instances': 10
            },
            'communication': {
                'processes': ['slack', 'discord', 'teams', 'zoom', 'skype'],
                'allowed_ports': [80, 443, 3478, 3479],
                'max_instances': 5
            },
            'other': {
                'processes': [],
                'allowed_ports': [],
                'max_instances': 5
            }
        }

        # Initialize security monitoring
        self.initialize_security_monitoring()
        
        # Configure initial theme
        self.configure_theme()
        
        # Create main frame
        self.main_frame = ttk.Frame(root, style="Dark.TFrame")
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create header with gradient effect
        self.create_header()
        
        # Create top control panel
        self.create_control_panel()
        
        # Create main content area with Panedwindow
        self.create_main_content()
        
        # Start monitoring
        self.monitor_system()

    def initialize_security_monitoring(self):
        """Initialize security monitoring components"""
        # Create baseline of file hashes for monitored directories
        self.update_file_hashes()
        
        # Initialize network monitoring
        self.previous_connections = set()
        
        # Load security policies
        self.load_security_policies()

    def load_security_policies(self):
        """Load security policies from configuration"""
        try:
            # Here you would typically load from a config file
            # For now, we'll use default policies
            self.security_policies = {
                'network': {
                    'max_connections': 1000,
                    'blocked_ports': self.security_config['blocked_ports'],
                    'blocked_ips': self.security_config['blocked_ips'],
                },
                'process': {
                    'max_cpu_percent': self.security_config['max_cpu_percent'],
                    'max_memory_percent': self.security_config['max_memory_percent'],
                    'blacklist': self.security_config['process_blacklist'],
                    'whitelist': self.security_config['process_whitelist']
                },
                'filesystem': {
                    'monitored_dirs': self.security_config['monitored_directories'],
                    'protected_files': set(['/etc/hosts', '/etc/passwd'])
                }
            }
        except Exception as e:
            self.log_event(f"Critical: Failed to load security policies: {str(e)}", 'CRITICAL')

    def update_file_hashes(self):
        """Update file hashes for monitored directories"""
        for directory in self.security_config['monitored_directories']:
            if os.path.exists(directory):
                for root, _, files in os.walk(directory):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'rb') as f:
                                file_hash = hashlib.sha256(f.read()).hexdigest()
                                self.file_hashes[file_path] = file_hash
                        except Exception:
                            continue

    def check_file_integrity(self):
        """Check file integrity in monitored directories"""
        for directory in self.security_config['monitored_directories']:
            if os.path.exists(directory):
                for root, _, files in os.walk(directory):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'rb') as f:
                                current_hash = hashlib.sha256(f.read()).hexdigest()
                                if file_path in self.file_hashes:
                                    if current_hash != self.file_hashes[file_path]:
                                        self.log_event(
                                            f"Critical: File modification detected: {file_path}",
                                            'CRITICAL'
                                        )
                                        self.take_security_action('file_modified', file_path)
                        except Exception:
                            continue

    def monitor_network_activity(self):
        """Monitor network connections for suspicious activity"""
        try:
            current_connections = set()
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED':
                    current_connections.add((
                        conn.laddr.ip, conn.laddr.port,
                        conn.raddr.ip if conn.raddr else None,
                        conn.raddr.port if conn.raddr else None,
                        conn.pid if conn.pid else None
                    ))
            
            # Check for new connections
            new_connections = current_connections - self.previous_connections
            for conn in new_connections:
                local_ip, local_port, remote_ip, remote_port, pid = conn
                
                # Check if connection is suspicious
                if self.is_suspicious_connection(local_port, remote_ip, pid):
                    self.log_event(
                        f"Critical: Suspicious network connection detected - "
                        f"Process: {self.get_process_name(pid)}, "
                        f"Remote: {remote_ip}:{remote_port}",
                        'CRITICAL'
                    )
                    self.take_security_action('suspicious_connection', conn)
            
            self.previous_connections = current_connections
            
        except Exception as e:
            self.log_event(f"Critical: Network monitoring error: {str(e)}", 'CRITICAL')

    def is_suspicious_connection(self, port, remote_ip, pid):
        """Check if a network connection is suspicious"""
        if port in self.security_config['blocked_ports']:
            return True
        if remote_ip in self.security_config['blocked_ips']:
            return True
        
        # Check if process is allowed to make network connections
        if pid:
            try:
                process = psutil.Process(pid)
                category = self.get_process_category(process.name())
                if category in self.process_categories:
                    allowed_ports = self.process_categories[category]['allowed_ports']
                    if port not in allowed_ports and allowed_ports:
                        return True
            except psutil.NoSuchProcess:
                return True
        
        return False

    def monitor_system(self):
        if not self.auto_refresh:
            self.root.after(1000, self.monitor_system)
            return
            
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            # Update top processes
            self.update_top_processes()
            
            # Monitor processes for security
            self.monitor_processes()
            
            # Monitor network activity
            self.monitor_network_activity()
            
            # Check file integrity
            self.check_file_integrity()
            
            # Update statistics
            self.update_statistics()
            
        except Exception as e:
            self.log_event(f"Critical: Error monitoring system: {str(e)}", 'CRITICAL')
        
        # Schedule next update
        self.root.after(1000, self.monitor_system)

    def monitor_processes(self):
        """Monitor processes for suspicious activity"""
        for proc in self.top_processes:
            name = proc['name']
            cpu_percent = proc['cpu']
            memory_percent = proc['memory']
            pid = proc['pid']
            category = proc['category']
            
            # Check for suspicious process names
            if self.is_suspicious_process(name):
                self.log_event(
                    f"Critical: Suspicious process detected: {name} ({category}) "
                    f"(PID: {pid})",
                    'CRITICAL'
                )
                self.take_security_action('suspicious_process', pid)
            
            # Check resource usage
            if cpu_percent > self.security_config['max_cpu_percent']:
                self.log_event(
                    f"Critical: High CPU usage detected for {name} ({category}) "
                    f"(PID: {pid}, CPU: {cpu_percent:.1f}%, Memory: {memory_percent:.1f}%)",
                    'CRITICAL'
                )
                self.take_security_action('high_cpu', pid)
            
            # Check process limits per category
            if category in self.process_categories:
                max_instances = self.process_categories[category]['max_instances']
                current_instances = sum(1 for p in self.top_processes if p['category'] == category)
                if current_instances > max_instances:
                    self.log_event(
                        f"Warning: Too many {category} processes running "
                        f"({current_instances}/{max_instances})",
                        'WARNING'
                    )

    def is_suspicious_process(self, process_name):
        """Check if a process name matches suspicious patterns"""
        process_name = process_name.lower()
        
        # Check against blacklist
        if process_name in self.security_config['process_blacklist']:
            return True
        
        # Check against suspicious patterns
        return any(pattern in process_name for pattern in self.suspicious_patterns['processes'])

    def take_security_action(self, threat_type, threat_data):
        """Take appropriate security action based on the threat"""
        try:
            if threat_type == 'suspicious_process':
                pid = threat_data
                try:
                    process = psutil.Process(pid)
                    process.terminate()
                    self.log_event(f"Action: Terminated suspicious process (PID: {pid})", 'WARNING')
                except psutil.NoSuchProcess:
                    pass
            
            elif threat_type == 'suspicious_connection':
                local_ip, local_port, remote_ip, remote_port, pid = threat_data
                if remote_ip:
                    self.security_config['blocked_ips'].add(remote_ip)
                    self.log_event(f"Action: Blocked IP address {remote_ip}", 'WARNING')
            
            elif threat_type == 'file_modified':
                file_path = threat_data
                # Log file modification and potentially restore from backup
                self.log_event(f"Action: Detected unauthorized file modification: {file_path}", 'WARNING')
            
            elif threat_type == 'high_cpu':
                pid = threat_data
                try:
                    process = psutil.Process(pid)
                    process.nice(19)  # Lower the process priority
                    self.log_event(f"Action: Reduced priority of high CPU process (PID: {pid})", 'WARNING')
                except psutil.NoSuchProcess:
                    pass
        
        except Exception as e:
            self.log_event(f"Critical: Failed to take security action: {str(e)}", 'CRITICAL')

    def create_header(self):
        header_frame = tk.Frame(self.main_frame, bg=self.colors['bg'])
        header_frame.pack(fill=tk.X, pady=10)
        
        header = ttk.Label(header_frame, text="Real-Time Security Event Logger", 
                          font=('Arial', 20, 'bold'), style="Dark.TLabel")
        header.pack(pady=10)

    def create_main_content(self):
        # Main paned window (horizontal split)
        main_paned = ttk.PanedWindow(self.main_frame, orient=tk.HORIZONTAL)
        main_paned.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Left panel (for logs and process list)
        left_paned = ttk.PanedWindow(main_paned, orient=tk.VERTICAL)
        main_paned.add(left_paned, weight=2)
        
        # Top processes panel
        self.create_top_processes_panel(left_paned)
        
        # Log panel
        self.create_log_panel(left_paned)
        
        # Right panel for statistics
        right_panel = ttk.Frame(main_paned, style="Dark.TFrame")
        main_paned.add(right_panel, weight=1)
        
        # Create statistics graphs
        self.create_statistics_panel(right_panel)

    def create_top_processes_panel(self, parent):
        top_frame = ttk.Frame(parent, style="Dark.TFrame")
        parent.add(top_frame, weight=1)
        
        # Header
        header_frame = ttk.Frame(top_frame, style="Dark.TFrame")
        header_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(header_frame, text="Top Processes", 
                 font=('Arial', 12, 'bold'), style="Dark.TLabel").pack(side=tk.LEFT, padx=5)
        
        # Process category filter
        ttk.Label(header_frame, text="Category:", style="Dark.TLabel").pack(side=tk.LEFT, padx=5)
        self.category_var = tk.StringVar(value="All")
        categories = ["All"] + list(self.process_categories.keys())
        category_combo = ttk.Combobox(header_frame, textvariable=self.category_var,
                                    values=categories, state="readonly", width=15)
        category_combo.pack(side=tk.LEFT, padx=5)
        category_combo.bind('<<ComboboxSelected>>', self.filter_processes)
        
        # Kill selected process button
        kill_btn = ttk.Button(header_frame, text="Force Quit Selected",
                             command=self.force_quit_selected)
        kill_btn.pack(side=tk.RIGHT, padx=5)
        
        # Process control button
        control_btn = ttk.Button(header_frame, text="Process Control",
                               command=self.show_process_control)
        control_btn.pack(side=tk.RIGHT, padx=5)
        
        # Process list
        columns = ('Name', 'PID', 'CPU %', 'Memory %', 'Category', 'Status')
        self.process_tree = ttk.Treeview(top_frame, columns=columns, show='headings', height=8)
        
        for col in columns:
            self.process_tree.heading(col, text=col, command=lambda c=col: self.sort_processes(c))
            self.process_tree.column(col, width=100)
        
        self.process_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add double-click binding for process control
        self.process_tree.bind('<Double-1>', self.on_process_double_click)
        
        # Scrollbar for process list
        scrollbar = ttk.Scrollbar(top_frame, orient=tk.VERTICAL, command=self.process_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.process_tree.configure(yscrollcommand=scrollbar.set)

    def create_log_panel(self, parent):
        log_frame = ttk.Frame(parent, style="Dark.TFrame")
        parent.add(log_frame, weight=2)
        
        # Search frame
        search_frame = ttk.Frame(log_frame, style="Dark.TFrame")
        search_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(search_frame, text="Search:", style="Dark.TLabel").pack(side=tk.LEFT, padx=5)
        self.search_var = tk.StringVar()
        self.search_var.trace('w', self.search_logs)
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Create log display with custom tags for severity levels
        self.log_display = scrolledtext.ScrolledText(log_frame, height=20,
                                                    bg=self.colors['entry_bg'],
                                                    fg=self.colors['fg'],
                                                    font=('Consolas', 10))
        self.log_display.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.log_display.tag_configure('INFO', foreground='#4CAF50')
        self.log_display.tag_configure('WARNING', foreground='#FFA500')
        self.log_display.tag_configure('CRITICAL', foreground='#FF0000')
        
        # Status bar
        self.status_var = tk.StringVar(value="Monitoring system events...")
        status_bar = ttk.Label(log_frame, textvariable=self.status_var,
                              style="Dark.TLabel")
        status_bar.pack(fill=tk.X, pady=5)

    def get_process_category(self, process_name):
        process_name = process_name.lower()
        for category, processes in self.process_categories.items():
            if any(proc in process_name for proc in processes):
                return category.capitalize()
        return "Other"

    def update_top_processes(self):
        # Clear current items
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)
        
        # Get top processes by CPU usage
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
            try:
                info = proc.info
                category = self.get_process_category(info['name'])
                
                if self.category_var.get() != "All" and category.lower() != self.category_var.get().lower():
                    continue
                
                processes.append({
                    'name': info['name'],
                    'pid': info['pid'],
                    'cpu': info['cpu_percent'] or 0,
                    'memory': info['memory_percent'] or 0,
                    'category': category,
                    'status': info['status']
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        # Sort by CPU usage and take top 15
        processes.sort(key=lambda x: x['cpu'], reverse=True)
        self.top_processes = processes[:15]
        
        # Update treeview
        for proc in self.top_processes:
            self.process_tree.insert('', tk.END, values=(
                proc['name'],
                proc['pid'],
                f"{proc['cpu']:.1f}",
                f"{proc['memory']:.1f}",
                proc['category'],
                proc['status'].capitalize()
            ))

    def sort_processes(self, column):
        items = [(self.process_tree.set(item, column), item) for item in self.process_tree.get_children('')]
        
        # Convert to proper type for sorting
        if column in ('CPU %', 'Memory %'):
            items = [(float(value.replace('%', '')), item) for value, item in items]
        elif column == 'PID':
            items = [(int(value), item) for value, item in items]
        
        # Sort items
        items.sort(reverse=True)
        
        # Rearrange items in sorted positions
        for index, (val, item) in enumerate(items):
            self.process_tree.move(item, '', index)

    def filter_processes(self, event=None):
        self.update_top_processes()

    def configure_theme(self):
        self.colors = {
            'bg': '#2E3440' if self.is_dark_theme else '#F0F0F0',
            'fg': '#ECEFF4' if self.is_dark_theme else '#2E3440',
            'entry_bg': '#3B4252' if self.is_dark_theme else '#FFFFFF',
            'button_bg': '#4C566A' if self.is_dark_theme else '#E5E9F0',
            'accent': '#88C0D0'
        }
        
        style = ttk.Style()
        style.configure("Dark.TFrame", background=self.colors['bg'])
        style.configure("Dark.TLabel", background=self.colors['bg'], foreground=self.colors['fg'])
        style.configure("Dark.TButton", background=self.colors['button_bg'], foreground=self.colors['fg'])
        style.configure("Dark.TCombobox", background=self.colors['entry_bg'], foreground=self.colors['fg'])
        
        self.root.configure(bg=self.colors['bg'])

    def create_control_panel(self):
        control_frame = ttk.Frame(self.main_frame, style="Dark.TFrame")
        control_frame.pack(fill=tk.X, pady=5)
        
        # Left side controls
        left_controls = ttk.Frame(control_frame, style="Dark.TFrame")
        left_controls.pack(side=tk.LEFT)
        
        # Filter dropdown
        ttk.Label(left_controls, text="Filter:", style="Dark.TLabel").pack(side=tk.LEFT, padx=5)
        self.filter_var = tk.StringVar(value="All Events")
        filter_combo = ttk.Combobox(left_controls, textvariable=self.filter_var,
                                  values=["All Events", "Process Events", "Resource Usage", "Security Alerts", "Critical Only"],
                                  state="readonly", style="Dark.TCombobox", width=15)
        filter_combo.pack(side=tk.LEFT, padx=5)
        filter_combo.bind('<<ComboboxSelected>>', self.filter_logs)
        
        # Right side controls
        right_controls = ttk.Frame(control_frame, style="Dark.TFrame")
        right_controls.pack(side=tk.RIGHT)
        
        # Theme toggle
        theme_btn = ttk.Button(right_controls, text="Toggle Theme",
                              command=self.toggle_theme, style="Dark.TButton")
        theme_btn.pack(side=tk.RIGHT, padx=5)
        
        # Auto-refresh toggle
        self.refresh_btn = ttk.Button(right_controls, text="Auto-Refresh: ON",
                                    command=self.toggle_refresh, style="Dark.TButton")
        self.refresh_btn.pack(side=tk.RIGHT, padx=5)
        
        # Export button
        export_btn = ttk.Button(right_controls, text="Export Logs",
                               command=self.export_logs, style="Dark.TButton")
        export_btn.pack(side=tk.RIGHT, padx=5)
        
        # Clear button
        clear_btn = ttk.Button(right_controls, text="Clear Logs",
                              command=self.clear_logs, style="Dark.TButton")
        clear_btn.pack(side=tk.RIGHT, padx=5)

    def create_statistics_panel(self, parent):
        # Create figure for statistics
        self.fig, (self.ax1, self.ax2) = plt.subplots(2, 1, figsize=(6, 8))
        self.fig.patch.set_facecolor(self.colors['bg'])
        
        # Configure axes
        for ax in [self.ax1, self.ax2]:
            ax.set_facecolor(self.colors['entry_bg'])
            ax.tick_params(colors=self.colors['fg'])
            ax.spines['bottom'].set_color(self.colors['fg'])
            ax.spines['top'].set_color(self.colors['fg'])
            ax.spines['left'].set_color(self.colors['fg'])
            ax.spines['right'].set_color(self.colors['fg'])
        
        self.ax1.set_title('CPU Usage (%)', color=self.colors['fg'])
        self.ax2.set_title('Memory Usage (%)', color=self.colors['fg'])
        
        # Create canvas
        self.canvas = FigureCanvasTkAgg(self.fig, parent)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def update_statistics(self):
        # Update CPU and memory history
        cpu_percent = psutil.cpu_percent()
        memory_percent = psutil.virtual_memory().percent
        
        self.cpu_history.append(cpu_percent)
        self.memory_history.append(memory_percent)
        
        # Keep only last 60 readings
        if len(self.cpu_history) > 60:
            self.cpu_history.pop(0)
            self.memory_history.pop(0)
        
        # Clear and redraw plots
        self.ax1.clear()
        self.ax2.clear()
        
        self.ax1.plot(self.cpu_history, color=self.colors['accent'])
        self.ax2.plot(self.memory_history, color=self.colors['accent'])
        
        self.ax1.set_title('CPU Usage (%)', color=self.colors['fg'])
        self.ax2.set_title('Memory Usage (%)', color=self.colors['fg'])
        
        for ax in [self.ax1, self.ax2]:
            ax.set_facecolor(self.colors['entry_bg'])
            ax.tick_params(colors=self.colors['fg'])
            ax.grid(True, linestyle='--', alpha=0.7)
        
        self.canvas.draw()

    def toggle_theme(self):
        self.is_dark_theme = not self.is_dark_theme
        self.configure_theme()
        self.update_statistics()
        self.filter_logs()  # Refresh logs with new theme

    def toggle_refresh(self):
        self.auto_refresh = not self.auto_refresh
        self.refresh_btn.configure(text=f"Auto-Refresh: {'ON' if self.auto_refresh else 'OFF'}")

    def search_logs(self, *args):
        search_text = self.search_var.get().lower()
        self.log_display.delete('1.0', tk.END)
        
        for log in self.logs:
            if search_text in log.lower():
                self.display_log_entry(log)

    def display_log_entry(self, log):
        if "Critical" in log:
            self.log_display.insert(tk.END, log + '\n', 'CRITICAL')
        elif "Warning" in log:
            self.log_display.insert(tk.END, log + '\n', 'WARNING')
        else:
            self.log_display.insert(tk.END, log + '\n', 'INFO')

    def log_event(self, event, severity='INFO'):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {event}"
        self.logs.append(log_entry)
        
        if self.filter_matches(log_entry):
            self.display_log_entry(log_entry)
        self.log_display.see(tk.END)
    
    def filter_matches(self, log_entry):
        filter_text = self.filter_var.get()
        
        if filter_text == "All Events":
            return True
        elif filter_text == "Process Events" and "PID:" in log_entry:
            return True
        elif filter_text == "Resource Usage" and "resource" in log_entry.lower():
            return True
        elif filter_text == "Security Alerts" and ("Warning:" in log_entry or "Critical:" in log_entry):
            return True
        elif filter_text == "Critical Only" and "Critical:" in log_entry:
            return True
        return False
    
    def filter_logs(self, event=None):
        self.log_display.delete('1.0', tk.END)
        for log in self.logs:
            if self.filter_matches(log):
                self.display_log_entry(log)
    
    def export_logs(self):
        file_name = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("Text Files", "*.txt")],
            title="Export Logs"
        )
        if file_name:
            try:
                with open(file_name, 'w', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(['Timestamp', 'Severity', 'Event'])
                    for log in self.logs:
                        timestamp = log[1:20]
                        severity = 'CRITICAL' if 'Critical:' in log else 'WARNING' if 'Warning:' in log else 'INFO'
                        event = log[22:]
                        writer.writerow([timestamp, severity, event])
                messagebox.showinfo("Success", "Logs exported successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export logs: {str(e)}")
    
    def clear_logs(self):
        self.logs.clear()
        self.log_display.delete('1.0', tk.END)
        self.process_history.clear()
        self.cpu_history.clear()
        self.memory_history.clear()
        self.status_var.set("Logs cleared")

    def force_quit_selected(self):
        selected_items = self.process_tree.selection()
        if not selected_items:
            messagebox.showwarning("Warning", "Please select a process to force quit")
            return
        
        if messagebox.askyesno("Confirm", "Are you sure you want to force quit the selected process(es)?"):
            for item in selected_items:
                values = self.process_tree.item(item)['values']
                pid = int(values[1])  # PID is in the second column
                try:
                    process = psutil.Process(pid)
                    process.kill()  # Force kill the process
                    self.log_event(f"Action: Force quit process {values[0]} (PID: {pid})", 'WARNING')
                except Exception as e:
                    self.log_event(f"Error: Failed to force quit process {pid}: {str(e)}", 'CRITICAL')

    def show_process_control(self):
        selected_items = self.process_tree.selection()
        if not selected_items:
            messagebox.showwarning("Warning", "Please select a process to control")
            return
        
        item = selected_items[0]  # Get the first selected item
        values = self.process_tree.item(item)['values']
        process_info = {
            'name': values[0],
            'pid': int(values[1]),
            'cpu': float(values[2]),
            'memory': float(values[3]),
            'category': values[4]
        }
        
        ProcessControlDialog(self.root, process_info)

    def on_process_double_click(self, event):
        self.show_process_control()

if __name__ == '__main__':
    root = tk.Tk()
    app = SecurityLogger(root)
    root.mainloop() 