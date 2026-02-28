import socket
import json
import threading
from queue import Queue
from tqdm import tqdm
from datetime import datetime
from colorama import init, Fore, Style

# initialize coloroma for windows colour support
init(autoreset=True)

# function to  if port is open on the target host
def check_port(host, port, timeout=1):
    try:
        # create socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # try to connect to the target host and port
        result = sock.connect_ex((host, port))
        sock.close()

        # if result is 0, port is open
        return result == 0
    
    except socket.gaierror:  # hostname couldn't be resolved
        return False
    except socket.error:  # hostname couldn't connect to server
        return False
    
# function to grab banner information from open ports
def grab_banner(host, port, timeout=2):
    try:
        # create socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # receive banner information
        try:
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner
        except:
            sock.close()
            return ""
    except:
        return ""

# function to get service name from port number
def get_service_name(port):
    try:
        with open('common_ports.json', 'r') as f:
            common_ports = json.load(f)
        return common_ports.get(str(port), "Unknown")
    except:
        return "Unknown"
    
# function to process ports from queue and check if they are open (worker thread function)
def scan_worker(host, port_queue, open_ports, progress_bar):
    while not port_queue.empty():
        try:
            port = port_queue.get_nowait()

            if check_port(host, port):
                service = get_service_name(port)
                banner = grab_banner(host, port)

                port_info = {
                    "port": port,
                    "service": service,
                    "banner": banner
                }

                open_ports.append(port_info)

            progress_bar.update(1)
            port_queue.task_done()

        except:
            break

# function to perform scanning of ports on target host (main scan function)
def scan_ports(host, start_port=1, end_port=1024, num_threads=100):  # scan a range of ports on target hosts
    print(f"\n{Fore.CYAN}[*] Starting port scan on {host}")
    print(f"[*] Scanning ports {start_port}-{end_port}")
    print(f"[*] Using {num_threads} threads\n")

    # create queue and result list
    port_queue = Queue()
    open_ports = []

    # fill queue with ports to scan
    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    # create progress bar
    total_ports = end_port - start_port + 1
    progress_bar = tqdm(total=total_ports, desc="Scanning", unit="port")

    # create and start worker thread
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=scan_worker, args=(host, port_queue, open_ports, progress_bar))
        thread.daemon = True
        thread.start()
        threads.append(thread)

    # wait for all threads to finish/ complete scanning
    for thread in threads:
        thread.join()

    progress_bar.close()

    return sorted(open_ports, key=lambda x: x['port'])

# function to display scan results in a formatted table
def display_results(host, open_ports, vuln_db):
    print(f"\n{Fore.GREEN}{'='*70}")
    print(f"SCAN RESULTS FOR {host}")
    print(f"{'='*70}\n")
    
    if not open_ports:
        print(f"{Fore.YELLOW}No open ports found.\n")
        return
    
    print(f"{Fore.CYAN}{'PORT':<10}{'SERVICE':<20}{'RISK':<15}{'BANNER'}")
    print(f"{'-'*70}")
    
    critical_count = 0
    high_count = 0
    medium_count = 0
    
    for port_info in open_ports:
        port = port_info['port']
        service = port_info['service']
        banner = port_info['banner'][:30] if port_info['banner'] else "No banner"
        
        # Check for vulnerabilities
        vuln_info = check_vulnerabilities(port, vuln_db)
        
        if vuln_info:
            risk = vuln_info['risk']
            
            # Count by risk level
            if risk == 'CRITICAL':
                critical_count += 1
                risk_color = Fore.RED
            elif risk == 'HIGH':
                high_count += 1
                risk_color = Fore.RED
            elif risk == 'MEDIUM':
                medium_count += 1
                risk_color = Fore.YELLOW
            else:
                risk_color = Fore.GREEN
            
            print(f"{Fore.GREEN}{port:<10}{service:<20}{risk_color}{risk:<15}{Fore.WHITE}{banner}")
        else:
            print(f"{Fore.GREEN}{port:<10}{service:<20}{Fore.WHITE}{'LOW':<15}{banner}")
    
    print(f"\n{Fore.GREEN}Total open ports: {len(open_ports)}")
    
    # Show vulnerability summary
    if critical_count > 0 or high_count > 0 or medium_count > 0:
        print(f"\n{Fore.RED} SECURITY WARNINGS:")
        if critical_count > 0:
            print(f"{Fore.RED} • {critical_count} CRITICAL risk port(s)")
        if high_count > 0:
            print(f"{Fore.RED} • {high_count} HIGH risk port(s)")
        if medium_count > 0:
            print(f"{Fore.YELLOW} • {medium_count} MEDIUM risk port(s)")
    
    print()

# function to load vulnerability database from JSON file
def load_vulnerability_database():
    try:
        with open('vulns.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"{Fore.YELLOW}Warning: vulns.json not found. Vulnerability checking disabled.{Style.RESET_ALL}")
        return {}
    except json.JSONDecodeError:
        print(f"{Fore.YELLOW}Warning: vulns.json is invalid. Vulnerability checking disabled.{Style.RESET_ALL}")
        return {}
    
# function to check for vulnerabilitys based on open ports and vulnerability database
def check_vulnerabilities(port, vuln_db):
    port_str = str(port)
    if port_str in vuln_db:
        return vuln_db[port_str]
    return None
    
# function main
def main():
    print(f"{Fore.CYAN}{'=' * 70}")      
    print(f"{Fore.CYAN}NETWORK PORT SCANNER")
    print(f"{Fore.CYAN}{'=' * 70}\n")

    # get target from user input
    host = input(f"{Fore.YELLOW}Enter target host (IP or hostname): {Style.RESET_ALL}").strip()

    if not host:
        print(f"{Fore.RED}Error: No target host provided.{Style.RESET_ALL}")
        return
    
    # get port range from user input
    print(f"\n{Fore.CYAN}Port range options:")
    print(f" 1. Quick scan (Top 20 common ports)")
    print(f" 2. Common ports (1-1024)")
    print(f" 3. Extended scan (1-5000)")
    print(f" 4. Full scan (1-65535)")
    print(f" 5. Custom range")

    choice = input(f"\n{Fore.YELLOW}Choose from options (1-5): {Style.RESET_ALL}").strip()

    # define port ranges based on choice
    if choice == '1':
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1723, 3306, 3389, 5900, 8080, 8443]
        start_port =  min(common_ports)
        end_port = max(common_ports)
    elif choice == '2':
        start_port, end_port = 1, 1024
    elif choice == '3':
        start_port, end_port = 1, 5000
    elif choice == '4':
        start_port, end_port = 1, 65535
        confirm = input(f"{Fore.YELLOW}Full scan can take a while (10-15 minutes).Continue? (y/n): {Style.RESET_ALL}").lower() 
        if confirm != 'y':
            print(f"{Fore.RED}Scan cancelled.")
            return
    elif choice == '5':
        try:
            start_port = int(input(f"{Fore.YELLOW}Enter starting port: {Style.RESET_ALL}").strip())
            end_port = int(input(f"{Fore.YELLOW}Enter ending port: {Style.RESET_ALL}").strip())
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                print(f"{Fore.RED}Invalid port range. Exiting.")
                return
        except ValueError:
            print(f"{Fore.RED}Invalid input. Exiting. {Style.RESET_ALL}")
            return
    else:
        print(f"{Fore.RED}Invalid choice. Exiting. {Style.RESET_ALL}")
        return
    
    # perform port scan
    print(f"\n{Fore.CYAN}Starting scan...{Style.RESET_ALL}\n")
    start_time = datetime.now()

    open_ports = scan_ports(host, start_port, end_port)

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    # load vulnerability database
    vuln_db = load_vulnerability_database()

    # display results
    display_results(host, open_ports, vuln_db)

    print(f"{Fore.CYAN}Scan completed in {duration:.2f} seconds. {Style.RESET_ALL}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}Scan cancelled{Style.RESET_ALL}")  
    except Exception as e:
        print(f"\n{Fore.RED}Error: {e}{Style.RESET_ALL}")
