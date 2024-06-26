import socket

# Dictionary of potentially vulnerable ports with their service names
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

def check_open_ports(ip_address):
    """Check for open ports on the given IP address and return a list of open ports."""
    print(f"Checking open ports on {ip_address}...")
    open_ports = []
    try:
        for port in vulnerable_ports.keys():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # Timeout of 1 second
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                open_ports.append(port)
                print(f"Port {port} ({vulnerable_ports[port]}) is open on {ip_address}")
            else:
                print(f"Port {port} ({vulnerable_ports[port]}) is closed on {ip_address}")
            sock.close()
    except Exception as e:
        print("An error occurred while checking open ports:", e)
    return open_ports

def check_vulnerable_ports(ip_address, open_ports):
    """Check the open ports against a list of commonly vulnerable ports and print the findings."""
    for port in open_ports:
        if port in vulnerable_ports:
            print(f"Potentially vulnerable open port detected on {ip_address}: {port} ({vulnerable_ports[port]})")
        else:
            print(f"Open port detected on {ip_address}: {port} (Not in the list of commonly vulnerable ports)")

if __name__ == "__main__":
    ip_addresses = input("Enter the IP addresses to scan (separated by commas): ").split(',')
    print("Starting Open Port Scan...")
    for ip_address in ip_addresses:
        ip_address = ip_address.strip()
        if ip_address:
            print(f"\nScanning IP address: {ip_address}")
            open_ports = check_open_ports(ip_address)
            check_vulnerable_ports(ip_address, open_ports)
        else:
            print("Invalid IP address entered.")
    print("Port scan completed.")
