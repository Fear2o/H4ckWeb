# H4ckWeb

**H4ckWeb** is a powerful, advanced tool designed for testing web vulnerabilities, focusing on SQL Injection and Cross-Site Scripting (XSS). It allows security professionals and ethical hackers to easily identify vulnerabilities in web applications and report them.

## Features

- **SQL Injection Testing**: Automatically tests for SQL injection vulnerabilities with a variety of payloads.
- **XSS Testing**: Injects custom XSS payloads to identify potential vulnerabilities.
- **Detailed Logging**: All test results are saved in `logs.txt` for later review.
- **Multithreading and Asynchronous Testing**: Supports both threaded and async testing for faster vulnerability detection.
- **Proxy Support**: Optionally use proxies to route traffic during testing.
- **Custom Headers**: Add custom HTTP headers for requests to simulate real-world traffic or testing conditions.

## Requirements

- 🐍 Python 3.x
- 🖥 Linux (Arch, Ubuntu, Kali)
- 📱 Termux
- 🖥 Windows
- 🖥 macOS

## Installation

### For Termux (Android)

To use **H4ckWeb** in Termux, type the following commands:

```bash
pkg install git -y
pkg install python3 -y
git clone https://github.com/Fear2o/H4ckWeb
cd h4ckweb
pip install -r requirements.txt
```

### For Debian-based GNU/Linux Distributions (Kali, Ubuntu, etc.)

To use H4ckWeb on Linux, run the following commands in the terminal:
```bash
sudo apt install git
git clone https://github.com/Fear2o/H4ckWeb
cd h4ckweb
pip install -r requirements.txt
```

### For Windows
For Windows, run the following commands in Command Prompt or PowerShell:
```bash
git clone https://github.com/yourusername/H4ckWeb.git
cd h4ckweb
pip install -r requirements.txt
```

### For macOS
On macOS, ensure you have Python 3 installed and then follow the Linux instructions above.

## Usage

To start the tool, simply run the script:

```bash
python h4ckweb.py
```

### Important Notes:
- Ethical Use Only: This tool is intended for educational and ethical testing purposes. Ensure you have explicit permission before testing any website or web application.
  
- Logging: All results are saved in logs.txt. The file is cleared each time before new data is logged to keep it clean.
  
- Privacy and Security: Be cautious when using proxies or custom headers to avoid any misuse of the tool.
