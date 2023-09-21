import argparse
import socket
import threading
import json
from tqdm import tqdm
from termcolor import colored
from IPython.display import clear_output





# Define a ScanThread class that will be used to check if a port is open or not
class ScanThread(threading.Thread):
    def __init__(self, target, port, timeout, scan_type):
        super().__init__()
        self.target = target
        self.port = port
        self.timeout = timeout
        self.scan_type = scan_type
        self.result = None

    def run(self):
        try:
            # Create a socket and connect to the target host and port
            client = socket.socket(socket.AF_INET, self.scan_type)
            client.settimeout(self.timeout)
            client.connect((self.target, self.port))
            # If connection is successful, print in green
            print(colored(f"[+] Port {self.port} is open. \n", "green"))
            try:
                # Get the banner and service version of the open port
                banner = socket.get_banner(self.target, self.port)
                version = socket.get_service_version(self.target, self.port)
                print(f"Banner for port {self.port}: {banner.strip()}")
                print(f"Service version for port {self.port}: {version}")
                # Check for known vulnerabilities in FTP service version
                if "FTP" in version and "2.2" in version:
                    print(colored(f"[!] Vulnerability detected: FTP service version {version} is vulnerable to exploit XYZ.", "yellow"))
            except:
                print(f"Unable to get banner and service version for port {self.port}")
            try:
                client.send(b"GET /get_banner HTTP/1.1\r\nHost: %s\r\n\r\n")
                response = client.recv(1024).decode("utf-8")
                # print(response)
                if "FTP" in response:
                    print(f"Service running on port {self.port}: FTP")
                    # Check for known vulnerabilities in FTP response
                    if "vsftpd 2.3.4" in response:
                        print(colored(f"[!] Vulnerability detected: FTP response from port {self.port} indicates that the service is vulnerable to exploit ABC.", "yellow"))
                elif "SSH" in response:
                    print(f"Service running on port {self.port}: SSH")
                elif "SMTP" in response:
                    print(f"Service running on port {self.port}: SMTP")
                elif "HTTP" in response:
                    print(f"Service running on port {self.port}: HTTP")    
                elif "POP3" in response:
                    print(f"Service running on port {self.port}: POP3")
                elif "DNS" in response:
                    print(f"Service running on port {self.port}: DNS")
                elif "IMAP" in response:
                    print(f"Service running on port {self.port}: IMAP")
                elif "HTTPS" in response:
                    print(f"Service running on port {self.port}: HTTPS")    
                elif "SNMP" in response:
                    print(f"Service running on port {self.port}: SNMP")
                elif "Telnet" in response:
                    print(f"Service running on port {self.port}: Telnet")
                elif "NetBIOS" in response:
                    print(f"Service running on port {self.port}: NetBIOS")
                elif "SMB" in response:
                    print(f"Service running on port {self.port}: SMB")    
                elif "RDP" in response:
                    print(f"Service running on port {self.port}: RDP")
                elif "SMTPS" in response:
                    print(f"Service running on port {self.port}: SMTPS")
                elif "POP3S" in response:
                    print(f"Service running on port {self.port}: POP3S")
                elif "IMAPS" in response:
                    print(f"Service running on port {self.port}: IMAPS")
                elif "SQL" in response:
                    print("Vulnerability found on port {}: SQL injection".format(self.port))
                elif "XSS" in response:
                    print("Vulnerability found on port {}: Cross-site scripting (XSS)".format(self.port))
                elif "Directory listing" in response:
                    print("Vulnerability found on port {}: Directory listing enabled".format(self.port))
    
                # Add more service signatures here
                else:
                    print(f"Service running on port {self.port}: {response.strip()}")
                if "SQL" in response:
                    print("Vulnerability found on port {}: SQL injection".format(self.port))
                elif "XSS" in response:
                    print("Vulnerability found on port {}: Cross-site scripting (XSS)".format(self.port))
                elif "Directory listing" in response:
                    print("Vulnerability found on port {}: Directory listing enabled".format(self.port))    
            except:
                print(f"Unable to determine service running on port {self.port}")    
            
            # Save the open port number in self.result
            self.result = self.port
            
           
        except:
            # If connection is unsuccessful, print in red
            print(colored(f"[-] Port {self.port} is closed.\n", "red"))
            
        
        client.close()        

# Define a function that will be used to scan the target(s) for open ports
def scan_targets(targets, port_range, timeout, num_threads, output_file):
    for target in targets:
        all_open_ports = []
        clear_output(wait=False)
        # Print the target being scanned in yellow
        print(colored(f"\n[+] Scanning {target}...", "yellow"))
        if target.startswith('http'):
            target = target.split('//')[1]
        if ':' in target:
            target = target.split(':')[0]
        # Parse the port range
        start_port, end_port = parse_port_range(port_range)
        threads = []
        # Create ScanThread objects for each port in the port range
        for port in range(start_port, end_port+1):
            thread = ScanThread(target, port, timeout, socket.SOCK_STREAM)
            threads.append(thread)
        # Run the ScanThread objects in batches using multiple threads
        for i in tqdm(range(0, len(threads), num_threads), desc="Scanning ports"):
            batch = threads[i:i+num_threads]
            for thread in batch:
                thread.start()
            for thread in batch:
                thread.join()
                if thread.result is not None:
                    all_open_ports.append(thread.result)
        # Save the results in a JSON file if output_file is specified
        # 
        
    # Return the list of open ports
    return all_open_ports

# Define a function to parse port range
def parse_port_range(port_range):
    if port_range.lower() == 'all':
        # If port_range is 'all', scan all ports
        start_port = 1
        end_port = 65535
    else:
        # Otherwise, parse the start and end port numbers from port_range string
        start_port, end_port = port_range.split('-')
        start_port = int(start_port)
        end_port = int(end_port)
    return start_port, end_port

def main():
    # set up command line arguments
    parser = argparse.ArgumentParser(description='TCP port scanner')
    parser.add_argument('-t', '--targets', required=True, nargs='+', help='target IP addresses or domain names')
    parser.add_argument('-p', '--port-range', default='1-100', help='range of ports to scan (e.g. 1-100 or all)')
    parser.add_argument('-T', '--timeout', default=1.0, type=float, help='timeout value in seconds (default: 1.0)')
    parser.add_argument('-n', '--num-threads', default=10, type=int, help='number of threads to use for scanning (default: 10)')
    parser.add_argument('-o', '--output', help='output file to save results to (e.g. output.txt)')
    parser.add_argument('-v', '--verbose', action='store_true', help='verbose output')
    args = parser.parse_args()

    # run port scan for specified targets
    for target in args.targets:
        all_open_ports = scan_targets([target], args.port_range, args.timeout, socket.SOCK_STREAM, args.output)

        # print or save results
        if len(all_open_ports) > 0:
            # if there are open ports, print them in green
            open_ports_str = ', '.join([str(port) for port in all_open_ports])
            print(colored(f"\n[+] Found open ports on {target}: {open_ports_str}", "green"))
            if args.output:
                # if an output file is specified, write the results to the file
                with open(args.output, 'a') as f:
                    output = {
                        'target': target,
                        'open_ports': all_open_ports
                    }
                    json.dump(output, f)
        else:
            # if no open ports are found, print a message in red
            print(colored(f"\n[-] No open ports found on {target}.", "red"))
            if args.output:
                # if an output file is specified, write the results to the file
                with open(args.output, 'a') as f:
                    output = {
                        'target': target,
                        'open_ports': []
                    }
                    json.dump(output, f)

    if args.output:
        # if an output file is specified, print a message indicating where the results were saved
        print(colored(f"\n[+] Results saved to {args.output}", "green"))
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("Scanning interrupted by user")
    except:
        print("An error occurred while scanning ports")