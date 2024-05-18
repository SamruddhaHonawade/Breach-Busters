import subprocess
import platform

def check_os_version():
    # Check OS version and release information
    print("Operating System Information:")
    print("System:", platform.system())
    print("Release:", platform.release())
    print("Version:", platform.version())

def check_weak_passwords():
    # Check for weak passwords using a password strength checker tool or library
    # This is just a placeholder, you can replace it with a more robust solution
    print("\nWeak Passwords (Placeholder):")
    print("Consider using a more advanced password strength checker tool.")

def check_outdated_software():
    # Check for outdated software using package manager commands or specific vulnerability databases
    print("\nOutdated Software:")
    if platform.system() == "Windows":
        print("Windows does not have a centralized package manager.")
    else:
        print("Consider running 'apt list --upgradable' on Debian-based systems or 'yum list updates' on RPM-based systems.")

# List of commonly vulnerable or unnecessary ports
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

def check_open_ports():
    # Check for open ports using netstat command
    print("Checking Open Ports...")
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

def check_vulnerable_ports(open_ports):
    for port in open_ports:
        if port in vulnerable_ports:
            print(f"Potentially vulnerable open port detected: {port} ({vulnerable_ports[port]})")
        else:
            print(f"Open port: {port} (Not in the list of commonly vulnerable ports)")

if __name__ == "__main__":
    print("Starting Open Port Scan...")
    open_ports = check_open_ports()
    check_vulnerable_ports(open_ports)
    check_os_version()

    check_weak_passwords()
    check_outdated_software()
