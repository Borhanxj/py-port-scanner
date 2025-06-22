# scanner.py
import argparse
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style
from utils import scan_port, scan_udp_port, guess_os, syn_scan

def main():
    parser = argparse.ArgumentParser(description="Simple Python scanner")
    parser.add_argument("-t", "--target", required=True, help="Target IP or CIDR (e.g., 192.168.1.1 or 192.168.1.0/24)")
    parser.add_argument("-p", "--port", required=False, help="Port range (format: 10-80) or 'common'")
    parser.add_argument("-o", "--output", required=False, help="Output file to save results")
    parser.add_argument("-s", "--scan", choices=["tcp", "udp", "both", "syn"], default="tcp", help="Scan type: tcp, udp, both, or syn")

    args = parser.parse_args()

    # Parse target(s)
    try:
        if '/' in args.target:
            net = ipaddress.IPv4Network(args.target, strict=False)
            ip_list = [str(ip) for ip in net.hosts()]
        else:
            ipaddress.IPv4Address(args.target)  # validate IP
            ip_list = [args.target]
    except ValueError:
        print(Fore.RED + "Invalid IP or CIDR provided." + Style.RESET_ALL)
        return

    if len(ip_list) > 256:
        print(Fore.RED + f"Too many IPs to scan ({len(ip_list)}). Use a smaller subnet." + Style.RESET_ALL)
        return

    print(Fore.LIGHTBLUE_EX + "Scanning target: " + args.target + Style.RESET_ALL)
    print(Fore.LIGHTBLUE_EX + "Port(s): " + (args.port or "1-65535") + Style.RESET_ALL)

    # Parse port range
    if args.port == "common":
        with open("wordlists/common_ports.txt") as f:
            ports_to_scan = [int(line.strip()) for line in f if line.strip().isdigit()]
        start_port = min(ports_to_scan)
        end_port = max(ports_to_scan)
    elif args.port and "-" in args.port:
        start_port, end_port = map(int, args.port.split("-"))
        ports_to_scan = list(range(start_port, end_port + 1))
    elif args.port:
        ports_to_scan = [int(args.port)]
        start_port = end_port = ports_to_scan[0]
    else:
        ports_to_scan = list(range(1, 65536))
        start_port = 1
        end_port = 65535

    print(f"Scanning ports from {start_port} to {end_port}")

    with ThreadPoolExecutor(max_workers=100) as executor:
        for ip in ip_list:
            os_guess = guess_os(ip)
            print(Fore.MAGENTA + "[OS Guess] " + ip + " is likely running " + os_guess + Style.RESET_ALL)
            for port in ports_to_scan:
                if args.scan == "syn":
                    executor.submit(syn_scan, ip, port, args.output)
                if args.scan in ["tcp", "both"]:
                    executor.submit(scan_port, ip, port, args.output)
                if args.scan in ["udp", "both"]:
                    executor.submit(scan_udp_port, ip, port, args.output)

if __name__ == "__main__":
    main()
