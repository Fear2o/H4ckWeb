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

- Python 3.x

## Installation

### Windows


2. **Clone the repository**:
   - Open Command Prompt (`cmd`) or PowerShell and run:
     ```bash
     git clone https://github.com/yourusername/H4ckWeb.git
     cd H4ckWeb
     ```

3. **Install dependencies**:
     ```bash
     pip install -r requirements.txt
     ```

4. **Run the tool**:
     ```bash
     python h4ckweb.py
     ```

### macOS

2. **Clone the repository**:
   - Open Terminal and run:
     ```bash
     git clone https://github.com/yourusername/H4ckWeb.git
     cd H4ckWeb
     ```

3. **Install dependencies**:
     ```bash
     pip3 install -r requirements.txt
     ```

4. **Run the tool**:
     ```bash
     python3 h4ckweb.py
     ```

### Linux (Ubuntu/Debian)

2. **Clone the repository**:
   - Open Terminal and run:
     ```bash
     git clone https://github.com/yourusername/H4ckWeb.git
     cd H4ckWeb
     ```

3. **Install dependencies**:
     ```bash
     pip3 install -r requirements.txt
     ```

4. **Run the tool**:
     ```bash
     python3 h4ckweb.py
     ```

## Usage

### Running the Tool

To start the tool, simply run the script:

```bash
python h4ckweb.py
```

### Important Notes:
- Ethical Use Only: This tool is intended for educational and ethical testing purposes. Ensure you have explicit permission before testing any website or web application.
  
- Logging: All results are saved in logs.txt. The file is cleared each time before new data is logged to keep it clean.
  
- Privacy and Security: Be cautious when using proxies or custom headers to avoid any misuse of the tool.
