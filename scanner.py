#Borhan Javadian

# lib that makes us able to write bash command
import argparse

# This library is used to run functions in parallel
from concurrent.futures import ThreadPoolExecutor

# libray created by me that contains the scan_port function
from utils import scan_port

def main():
    parser = argparse.ArgumentParser(description="Simple pyhton scanner")

    # 1. Add target IP address
    parser.add_argument("-t", "--target", required=True, help="Target IP address") # Add an argument for the target IP address - required=True makes this argument mandatory

    # 2. Add port range
    parser.add_argument("-p", "--port", required= False, help="Port range ( format: 10-80 )" )

    # 3. output the results
    parser.add_argument("-o", "--output", required=False, help="Output file to save results")

    args = parser.parse_args()

    #If the user does not provide a port range, we will scan all ports
    if args.port == "common":
        # If the user specifies "common", we will read the common ports from a file
        with open("wordlists/common_ports.txt") as f:
            # Read the common ports from the file and convert them to integers
            ports_to_scan = []
            for line in f:
                line = line.strip()
                if line.isdigit():
                    ports_to_scan.append(int(line))
        start_port = min(ports_to_scan)
        end_port = max(ports_to_scan)

    else:
        if args.port:
            ports = args.port.split("-")
            start_port = int(ports[0])
            end_port = int(ports[1])
            ports_to_scan = list(range(start_port, end_port + 1))
        else:
            ports_to_scan = list(range(1, 65536))

    
    print ("Scanning target:", args.target)
    print ("Port range:", args.port)
    print("Scanning ports from ", start_port, end_port)

    # 4. Scan the ports - we will use ThreadPoolExecutor to scan ports in parallel
    with ThreadPoolExecutor(max_workers=100) as executor:
        for port in ports_to_scan:
            executor.submit(scan_port, args.target, port, args.output)


# __name__ is a special variable in Python that is set to the name of the module.
# If the module is being run directly, __name__ will be set to "__main__"./
if __name__ == "__main__":
    main()