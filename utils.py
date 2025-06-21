#lib that makes us able to connect to a port
import socket
# lib that gives us mutex functionality
import threading
# lib that gives us colored output in terminal\
from colorama import Fore, Style, init
init(autoreset=True)

print_lock = threading.Lock()

def grab_banner(target, port):
    # This function can be used to grab the banner of the service running on the open portdef grab_banner(target, port):
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
    # Create a socket object
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # socket means we are using socket library
        # second socket means we are inititating a socket object
        # AF_INET means we are using IPv4
        # SOCK_STREAM means we are using TCP protocol

    s.settimeout(1)
        # Set a timeout for the socket connection

    result = s.connect_ex((target, port))
        # connect_ex() method tries to connect to the target IP and port
        # If the connection is successful, it returns 0, otherwise it returns an error code

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
        # Close the socket connection
