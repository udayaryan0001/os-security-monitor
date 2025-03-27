# Real-Time OS Security Event Logger

A comprehensive real-time security monitoring and process management tool for operating systems. This application provides advanced process control, resource monitoring, and security event logging capabilities.

## Features

- **Real-time Process Monitoring**: Track CPU usage, memory consumption, and process status
- **Advanced Process Control**: Terminate, suspend, resume, and manage process priorities
- **Security Event Logging**: Monitor and log suspicious activities and system events
- **Network Activity Monitoring**: Track and analyze network connections
- **File Integrity Monitoring**: Monitor critical system files for unauthorized modifications
- **Resource Usage Statistics**: Visual graphs of CPU and memory usage over time
- **Process Categorization**: Organize processes by categories with specific security policies
- **Export Capabilities**: Export logs in CSV format for further analysis

## Requirements

- Python 3.7+
- Required packages:
  - psutil
  - tkinter
  - matplotlib
  - hashlib

## Installation

1. Clone the repository:
```bash
git clone https://github.com/udayaryan0001/os-security-monitor.git
cd os-security-monitor
```

2. Install required packages:
```bash
pip install psutil matplotlib
```

## Usage

Run the application:
```bash
python security_logger.py
```

## Features

### Process Management
- View real-time process information
- Force quit processes
- Control process priorities
- Monitor process resource usage

### Security Monitoring
- Track suspicious processes
- Monitor network connections
- Check file integrity
- Log security events

### User Interface
- Dark/Light theme toggle
- Auto-refresh capability
- Export logs to CSV
- Filter and search logs
- Real-time statistics graphs

## Security Policies

The application implements various security policies:
- Process blacklisting/whitelisting
- Network port monitoring
- Resource usage thresholds
- File integrity checking
- Category-based process limits

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built with Python and tkinter
- Uses psutil for system monitoring
- Dark theme for reduced eye strain
- Detects unusual process behavior
- Logs security-relevant system events
- Provides real-time alerts for suspicious activities

## Note
Some features may require administrative privileges to access system information. 