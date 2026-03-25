"""
Author: Sami Alsadi
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

# Step ii: Import required modules
import socket
import threading
import sqlite3
import os
import platform
import datetime

# Step iii: Print Python version and OS name
print("Python Version:", platform.python_version())
print("Operating System:", os.name)


# Step iv: common_ports stores a mapping of well-known port numbers to service names.
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt",
}


# Step v: NetworkTool parent class
class NetworkTool:
    def __init__(self, target: str):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # They let us validate and control access to the private target value instead of changing self.__target directly.
    # This makes the class safer because invalid values (like an empty target) can be rejected in one place.
    # It also keeps the code cleaner because other parts of the program can use scanner.target like a normal attribute.
    @property
    def target(self) -> str:
        return self.__target

    @target.setter
    def target(self, value: str):
        # Reject empty string targets
        if value is None or str(value).strip() == "":
            print("Error: Target cannot be empty")
            return
        self.__target = str(value).strip()

    def __del__(self):
        print("NetworkTool instance destroyed")


# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner inherits from NetworkTool, so it reuses the target attribute logic (the private __target plus the getter/setter).
# For example, scan_port() uses self.target to connect to the target IP without re-implementing validation in PortScanner.
# This reduces duplicate code and keeps the target handling consistent across network tools.


# Step vi: PortScanner child class
class PortScanner(NetworkTool):
    def __init__(self, target: str):
        super().__init__(target)
        self.scan_results = []  # list of (port, status, service)
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port: int):
        s = None
        # Q4: What would happen without try-except here?
        # Without try-except, a connection error or timeout on an unreachable target could crash the whole program.
        # That would stop the scan early and you would lose results for the remaining ports.
        # try-except lets the scan continue and still record results for other ports.
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)

            result = s.connect_ex((self.target, int(port)))
            status = "Open" if result == 0 else "Closed"

            service_name = common_ports.get(int(port), "Unknown")

            # Thread-safe append
            self.lock.acquire()
            try:
                self.scan_results.append((int(port), status, service_name))
            finally:
                self.lock.release()

        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass

    def get_open_ports(self):
        # Use list comprehension to return only Open results
        return [r for r in self.scan_results if r[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # Threading allows multiple ports to be checked at the same time, so the scan finishes much faster.
    # A sequential scan waits for each timeout one-by-one, which is slow especially when ports are closed.
    # With threads, the program can handle many slow waits in parallel.

    def scan_range(self, start_port: int, end_port: int):
        threads = []
        for port in range(int(start_port), int(end_port) + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)

        # Start all threads
        for t in threads:
            t.start()

        # Join all threads
        for t in threads:
            t.join()


# Step vii: save_results
def save_results(target: str, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute(
            """CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                port INTEGER,
                status TEXT,
                service TEXT,
                scan_date TEXT
            )"""
        )

        scan_date = str(datetime.datetime.now())
        for port, status, service in results:
            cursor.execute(
                "INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                (target, int(port), str(status), str(service), scan_date),
            )

        conn.commit()
        conn.close()

    except sqlite3.Error as e:
        print(f"Database error while saving results: {e}")


# Step viii: load_past_scans
def load_past_scans():
    conn = None
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("SELECT id, target, port, status, service, scan_date FROM scans")
        rows = cursor.fetchall()

        if not rows:
            print("No past scans found.")
        else:
            print("\n=== PAST SCAN HISTORY ===")
            for row in rows:
                # (id, target, port, status, service, scan_date)
                print(f"[{row[5]}] {row[1]} : Port {row[2]} ({row[4]}) - {row[3]}")

    except sqlite3.Error:
        print("No past scans found.")
    except Exception:
        print("No past scans found.")
    finally:
        if conn is not None:
            conn.close()


# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":
    # Step ix: Get user input with try-except
    try:
        target_input = input("Enter target IP (default 127.0.0.1): ").strip()
        target = target_input if target_input != "" else "127.0.0.1"

        start_port = int(input("Enter start port (1-1024): "))
        end_port = int(input("Enter end port (1-1024): "))

    except ValueError:
        print("Invalid input. Please enter a valid integer.")
        raise SystemExit(1)

    # Range checks
    if start_port < 1 or start_port > 1024 or end_port < 1 or end_port > 1024:
        print("Port must be between 1 and 1024.")
        raise SystemExit(1)
    if end_port < start_port:
        print("Port must be between 1 and 1024.")
        raise SystemExit(1)

    # Step x: Run scan
    scanner = PortScanner(target)
    print(f"Scanning {target} from port {start_port} to {end_port}...")

    scanner.scan_range(start_port, end_port)

    open_ports = scanner.get_open_ports()

    print(f"\n--- Scan Results for {target} ---")
    if len(open_ports) == 0:
        print("(no open ports found)")
    else:
        for port, status, service in sorted(open_ports, key=lambda x: x[0]):
            print(f"Port {port}: {status} ({service})")
    print("------")
    print(f"Total open ports found: {len(open_ports)}")

    # Save all results (open + closed) as requested by step vii
    save_results(target, scanner.scan_results)

    view_history = input("Would you like to see past scan history? (yes/no): ").strip().lower()
    if view_history == "yes":
        load_past_scans()


# Q5: New Feature Proposal
# I would add a small feature that rates open ports as high, medium, or low risk.
# For example, ports like 21/22/23/3389 would be “HIGH” because they are common targets, and ports like 80/443 would be “MEDIUM”.
# I would use a nested if-statement to check which list the port is in, then print a short risk report after the scan.
# Diagram: See diagram_studentID.png in the repository root
