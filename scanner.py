#Borhan Javadian

import argparse
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style
from utils import scan_port, scan_udp_port, guess_os, syn_scan

def main():

    parser = argparse.ArgumentParser(description="Simple pyhton scanner")
    parser.add_argument("-t", "--target", required=True, help="Target IP address") # Add an argument for the target IP address - required=True makes this argument mandatory
    parser.add_argument("-p", "--port", required= False, help="Port range ( format: 10-80 )" )
    parser.add_argument("-o", "--output", required=False, help="Output file to save results")
    parser.add_argument("-s", "--scan", choices=["tcp", "udp", "both", "syn"], default="tcp", help="Scan type: tcp, udp, or both")

    args = parser.parse_args()

    try:
        ip_list = []
        for ip in ipaddress.IPv4Network(args.target, strict=False):
            ip_list.append(str(ip))
    except:
        ip_list = [args.target]
    print (Fore.LIGHTBLUE_EX+"Scanning target:"+ args.target + Style.RESET_ALL)
    print (Fore.LIGHTBLUE_EX+"Port(s):"+ args.port+ Style.RESET_ALL)

    if args.port == "common":
        with open("wordlists/common_ports.txt") as f:
            ports_to_scan = []
            for line in f:
                line = line.strip()
                if line.isdigit():
                    ports_to_scan.append(int(line))
        start_port = min(ports_to_scan)
        end_port = max(ports_to_scan)
        print("Scanning ports from", start_port, "to", end_port)

    elif args.port and "-" not in args.port:
        ports_to_scan = [int(args.port)]
        start_port = int(args.port)
        print("Scanning port:", start_port)

    elif args.port:
        ports = args.port.split("-")
        start_port = int(ports[0])
        end_port = int(ports[1])
        ports_to_scan = list(range(start_port, end_port + 1))
        print("Scanning ports from", start_port, "to", end_port)

    else:
        ports_to_scan = list(range(1, 65536))
        start_port = 1
        end_port = 65535
        print("Scanning ports from", start_port, "to", end_port)

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