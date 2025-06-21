#Borhan Javadian

#lib that makes us able to write bash command
import argparse
#lib that makes us able to connect to a port
import socket


def main():
    parser = argparse.ArgumentParser(description="Simple pyhton scanner")

    # 1. Add target IP address
    parser.add_argument("-t", "--target", required=True, help="Target IP address") # Add an argument for the target IP address - required=True makes this argument mandatory

    # 2. Add port range
    # -------------------------------------------------------
    parser.add_argument("-p", "--port", required= False, help="Port range ( format: 10-80 )" )

    #If the user does not provide a port range, we will scan all ports
    if args.ports:
        port_range = args.ports
    else:
        port_range = "1-65535"

    ports = port_range.split("-")
    start_port = int(ports[0])
    end_port = int(ports[1])
    # -------------------------------------------------------
    
    args = parser.parse_args()
    print ("Scanning target:", args.target)
    print ("Port range:", args.port)
    print("Scanning ports from ", start_port, end_port)


# __name__ is a special variable in Python that is set to the name of the module.
# If the module is being run directly, __name__ will be set to "__main__"./
if __name__ == "__main__":
    main()