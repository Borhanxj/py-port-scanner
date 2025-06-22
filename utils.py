#lib that makes us able to connect to a port
import socket
# lib that gives us mutex functionality
import threading
# lib that gives us colored output in terminal
from colorama import Fore, Style, init
# lib that gives us the ability to send and receive packets
from scapy.all import IP, TCP, sr1

init(autoreset=True)

print_lock = threading.Lock()

def grab_banner(target, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((target, port))

        try:
            # Step 1: Try to receive without sending
            banner = s.recv(1024).decode().strip()
            if not banner:
                raise Exception("Empty banner")
        except:
            # Step 2: Try sending HTTP request
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

    if result == 0 : 
        banner = grab_banner(target, port)
        with print_lock:
            print(Fore.GREEN + "Port " + str(port) + " is open" + Style.RESET_ALL)
            if banner:
                print("\tBanner for port", port, ":")
                for line in banner.splitlines():
                    print("\t ", line)
            else: 
                print(Fore.YELLOW + "\tUnknown or empty banner" + Style.RESET_ALL)

            if output_file:
                try:
                    with open(output_file, "a") as f:
                        f.write("Port " + str(port) + " is OPEN\n")
                        if banner:
                            f.write("Banner:\n")
                            for line in banner.splitlines():
                                f.write("  " + line + "\n")
                        else:
                            f.write("Banner: Unknown or empty\n")
                        f.write("\n")
                except:
                    pass
    else:
        pass

    s.close()


def scan_udp_port(target, port, output_file=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1)
    
    try:
        s.sendto(b"", (target, port))
        data, sender = s.recvfrom(1024)
        with print_lock:
            print(Fore.CYAN + "[+] UDP Port " + str(port) + " is OPEN (received response)" + Style.RESET_ALL)
            print("\t", data.decode(errors="ignore"))
            print("\tResponse from:", sender)
        
        if output_file:
            with open(output_file, "a") as f:
                f.write("UDP Port " + str(port) + " is OPEN (response)\n")
                f.write("Data: " + data.decode(errors="ignore") + "\n\n")
                f.write("Sender: " + str(sender) + "\n")

    except socket.timeout:
        with print_lock:
            print(Fore.CYAN + "[?] UDP Port " + str(port) + " might be OPEN (no response)" + Style.RESET_ALL)
        if output_file:
            with open(output_file, "a") as f:
                f.write("UDP Port " + str(port) + " might be OPEN (no response)\n\n")

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
            print(Fore.MAGENTA + "[?] SYN Port " + str(port) + " → No response (filtered or silent)" + Style.RESET_ALL)
            result = "Filtered or no response"
        elif resp.haslayer(TCP):
            if resp[TCP].flags == 0x12:
                print(Fore.MAGENTA + "[+] SYN Port " + str(port) + " is OPEN" + Style.RESET_ALL)
                result = "OPEN"
            elif resp[TCP].flags == 0x14:
                print(Fore.MAGENTA + "[-] SYN Port " + str(port) + " is CLOSED" + Style.RESET_ALL)
                result = "CLOSED"
            else:
                print(Fore.MAGENTA + "[?] SYN Port " + str(port) + " → Unknown TCP flags" + Style.RESET_ALL)
                result = "UNKNOWN"
        else:
            print(Fore.MAGENTA + "[?] SYN Port " + str(port) + " → Non-TCP response" + Style.RESET_ALL)
            result = "UNKNOWN"

    if output_file:
        try:
            with open(output_file, "a") as f:
                f.write("SYN Port " + str(port) + ": " + result + "\n")
        except:
            pass

