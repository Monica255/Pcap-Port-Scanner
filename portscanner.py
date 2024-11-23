import socket
import sys
from scapy.layers.l2 import ARP, Ether 
from scapy.sendrecv import srp
from threading import Thread, Lock
import nmap

print_lock=Lock()
# import psutil
# def force_close_port(port, process_name=None):
#     """Terminate a process that is bound to a port.
    
#     The process name can be set (eg. python), which will
#     ignore any other process that doesn't start with it.
#     """
#     print("closing ports")
#     for proc in psutil.process_iter():
#         for conn in proc.connections():
#             if conn.laddr[1] == port:
#                 #Don't close if it belongs to SYSTEM
#                 #On windows using .username() results in AccessDenied
#                 #TODO: Needs testing on other operating systems
#                 try:
#                     proc.username()
#                 except psutil.AccessDenied:
#                     pass
#                 else:
#                     if process_name is None or proc.name().startswith(process_name):
#                         try:
#                             proc.kill()
#                         except (psutil.NoSuchProcess, psutil.AccessDenied):
#                             pass 
# def close_port(port):
#     for conn in psutil.net_connections(kind='inet'):
#         if conn.laddr.port == port:
#             print(f"Closing port {port} by terminating PID {conn.pid}")
#             process = psutil.Process(conn.pid)
#             process.terminate()


import nmap

import nmap

#scan IP
def scanHost(ip, startPort, endPort):
    """Starts a TCP scan on a given IP address and returns scan results with protocol and service info for open ports only."""
    print('[*] Starting TCP port scan on host %s' % ip)

    # Initialize the nmap scanner
    scanner = nmap.PortScanner()

    # Perform the TCP scan on the specified port range
    scanner.scan(ip, f"{startPort}-{endPort}")

    # Prepare the scan result dictionary
    open_ports = []
    for port in range(startPort, endPort + 1):
        if scanner[ip].has_tcp(port):
            port_info = scanner[ip]['tcp'][port]
            if port_info['state'] == 'open':  # Only include ports that are open
                open_ports.append({
                    "port": port,
                    "state": port_info['state'],
                    "name": port_info['name'],
                    "reason": port_info['reason'],
                    "product": port_info.get('product', 'unknown'),
                    "version": port_info.get('version', 'unknown'),
                    "extrainfo": port_info.get('extrainfo', 'unknown'),
                    "conf": port_info['conf'],
                })

    scan_result = {
        "type": "Scan Host",
        "ip_address": ip,
        "start_port": startPort,
        "end_port": endPort,
        "open_ports": open_ports
    }

    print('[+] TCP scan on host %s complete' % ip)
    return scan_result



# def scanRange(network, startPort, endPort):
#     """ Starts a TCP scan on a given IP address range """

#     print('[*] Starting TCP port scan on network %s.0' % network)

#     # Iterate over a range of host IP addresses and scan each target
#     for host in range(1, 255):
#         ip = network + '.' + str(host)
#         print(f"Scanning IP: {ip}")
#         tcp_scan(ip, startPort, endPort)

#     print('[+] TCP scan on network %s.0 complete' % network)

def tcp_scan(ip, startPort, endPort):
    """ Creates a TCP socket and attempts to connect via supplied ports. """
    open_ports = []
    for port in range(startPort, endPort + 1):
        try:
            # Create a new socket
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp.settimeout(1)  # Set a timeout for the connection attempt

            # Attempt to connect to the port
            if tcp.connect_ex((ip, port)) == 0:  # Port is open
                open_ports.append(port)
                print(f'[+] {ip}:{port}/TCP Open')
                
                # Attempt to "close" the port by disconnecting immediately
                # tcp.shutdown(socket.SHUT_RDWR)
            # tcp.close()  # Always close the socket to free up the port locally

        except Exception as e:
            print(f"Error scanning port {port} on {ip}: {e}")
    return open_ports

from scapy.all import ARP, Ether, srp

#scan network 
def network_scan(target_ip):
    # Create an ARP request packet and an Ethernet broadcast packet
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    
    # Send the packet and receive the response
    result = srp(packet, timeout=3, verbose=0)[0]

    # List to store available devices (IP and MAC pairs)
    available_devices = [(received.psrc, received.hwsrc) for sent, received in result]

    # Prepare the scan result in the required dictionary format
    scan_result = {
        "type": "Scan Network",
        "network": target_ip,
        "available_devices": available_devices
    }

    print(scan_result)

    return scan_result

# import module 
# import subprocess 
# from subprocess import PIPE, run
# import psutil
# def get_info():
#     # # Traverse the ipconfig information 
#     # data = subprocess.check_output(['ifconfig','/all']).decode('utf-8').split('\n') 
    
#     # # Arrange the bytes data 
#     # for item in data: 
#     #     print(item.split('\r')[:-1])
#     # addrs = psutil.net_if_addrs()
#     # print(addrs.keys())
#     # First we import required functions from subprocess module
   
#     # our_command - variable which contains the CMD command we want to run
#     our_command = "ifconfig /all"
#     # calling the subprocess module to execute our command
#     result = run (our_command, stdout=PIPE, stderr=PIPE, universal_newlines=True)
#     print (result.stdout, result.stderr)

if __name__ == '__main__':
    # Set default timeout for socket connections
    socket.setdefaulttimeout(0.01)

    if len(sys.argv) < 4:
        print('Usage: ./portscanner.py <IP address> <start port> <end port>')
        print('Example: ./portscanner.py 192.168.1.10 1 65535\n')
        print('Usage: ./portscanner.py <network> <start port> <end port> -n')
        print('Example: ./portscanner.py 192.168.1 1 65535 -n')
        sys.exit(1)

    network   = sys.argv[1]
    startPort = int(sys.argv[2])
    endPort   = int(sys.argv[3])

    # Determine whether to scan a host or a network range
    if len(sys.argv) == 4:
        result = scanHost(network, startPort, endPort)
        # close_port(5000)
        # force_close_port(5000)
        print(result)

    elif len(sys.argv) == 5 and sys.argv[4] == '-n':
        # scanRange(network, startPort, endPort)
        result = network_scan(network)
        # get_info()
        print(result)

