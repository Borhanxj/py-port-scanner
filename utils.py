# utils.py
import socket
import threading
from colorama import Fore, Style, init
from scapy.all import IP, TCP, sr1

init(autoreset=True)
print_lock = threading.Lock()

def grab_banner(target, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((target, port))

        try:
            banner = s.recv(1024).decode().strip()
            if not banner:
                raise Exception("Empty banner")
        except:
            s.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = s.recv(1024).decode().strip()

        s.close()
        return banner
    except:
        return None

def scan_port(target, port, output_file=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    result = s.connect_ex((target, port))

    if result == 0:
        banner = grab_banner(target, port)
        with print_lock:
            print(Fore.GREEN + f"Port {port} is OPEN" + Style.RESET_ALL)
            if banner:
                print("\tBanner:")
                for line in banner.splitlines():
                    print("\t ", line)
            else:
                print(Fore.YELLOW + "\tUnknown or empty banner" + Style.RESET_ALL)

            if output_file:
                try:
                    with open(output_file, "a") as f:
                        f.write(f"Port {port} is OPEN\n")
                        if banner:
                            f.write("Banner:\n")
                            for line in banner.splitlines():
                                f.write("  " + line + "\n")
                        else:
                            f.write("Banner: Unknown or empty\n")
                        f.write("\n")
                except:
                    pass
    s.close()

def scan_udp_port(target, port, output_file=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1)
    try:
        s.sendto(b"", (target, port))
        data, sender = s.recvfrom(1024)
        with print_lock:
            print(Fore.CYAN + f"[+] UDP Port {port} is OPEN (received response)" + Style.RESET_ALL)
            print("\t", data.decode(errors="ignore"))
            print("\tResponse from:", sender)
        if output_file:
            with open(output_file, "a") as f:
                f.write(f"UDP Port {port} is OPEN (response)\n")
                f.write("Data: " + data.decode(errors="ignore") + "\n")
                f.write("Sender: " + str(sender) + "\n\n")
    except socket.timeout:
        with print_lock:
            print(Fore.CYAN + f"[?] UDP Port {port} might be OPEN (no response)" + Style.RESET_ALL)
        if output_file:
            with open(output_file, "a") as f:
                f.write(f"UDP Port {port} might be OPEN (no response)\n\n")
    except:
        pass
    s.close()

def guess_os(ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, 80))
        ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
        s.close()

        if ttl <= 64:
            return "Linux/Unix"
        elif ttl <= 128:
            return "Windows"
        else:
            return "Networking Device or Cisco"
    except:
        return "Unknown"

def syn_scan(ip, port, output_file=None):
    pkt = IP(dst=ip)/TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=1, verbose=0)

    with print_lock:
        if resp is None:
            print(Fore.MAGENTA + f"[?] SYN Port {port} → No response (filtered or silent)" + Style.RESET_ALL)
            result = "Filtered or no response"
        elif resp.haslayer(TCP):
            if resp[TCP].flags == 0x12:
                print(Fore.MAGENTA + f"[+] SYN Port {port} is OPEN" + Style.RESET_ALL)
                result = "OPEN"
            elif resp[TCP].flags == 0x14:
                print(Fore.MAGENTA + f"[-] SYN Port {port} is CLOSED" + Style.RESET_ALL)
                result = "CLOSED"
            else:
                print(Fore.MAGENTA + f"[?] SYN Port {port} → Unknown TCP flags" + Style.RESET_ALL)
                result = "UNKNOWN"
        else:
            print(Fore.MAGENTA + f"[?] SYN Port {port} → Non-TCP response" + Style.RESET_ALL)
            result = "UNKNOWN"

    if output_file:
        try:
            with open(output_file, "a") as f:
                f.write(f"SYN Port {port}: {result}\n")
        except:
            pass


#Frontend functions for web scanning

def scan_port_for_web(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    result = s.connect_ex((ip, port))
    banner = None

    if result == 0:
        banner = grab_banner(ip, port)
        s.close()
        if banner:
            banner_lines = banner.splitlines()
            formatted_banner = "<br>".join(banner_lines)
            return "Port " + str(port) + " is OPEN Banner:<br>" + formatted_banner
        else:
            return "Port " + str(port) + " is OPEN Banner: Unknown"
    s.close()
    return None  # not open
def scan_udp_port_for_web(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    try:
        s.sendto(b"", (ip, port))
        s.recvfrom(1024)
    except socket.timeout:
        return "UDP Port " + str(port) + " might be OPEN (no response)"
    except:
        return None
    finally:
        s.close()
    return None
def get_ttl(ip):
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, 80))  # arbitrary port; must be open
        ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
        s.close()
        return ttl
    except:
        return None
def scan_stealth_port(ip, port, timeout=1):
    try:
        pkt = IP(dst=ip)/TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp is None:
            return None  # filtered or no reply
        elif resp.haslayer(TCP):
            if resp[TCP].flags == 0x12:  # SYN-ACK
                return "Port {} is OPEN (SYN scan)".format(port)
            elif resp[TCP].flags == 0x14:  # RST
                return None  # closed
    except:
        return None
