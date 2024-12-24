import socket
import sys
from scapy.layers.l2 import ARP, Ether 
from scapy.sendrecv import srp
from threading import Thread, Lock
import nmap

print_lock=Lock()
import nmap

vulnerability_messages = {
        21: "Port 21 terbuka (FTP - File Transfer Protocol). Data ditransfer dalam teks biasa, memungkinkan sniffing kredensial. FTP tidak aman jika tidak dilengkapi dengan FTPS atau SFTP.",
        22: "Port 22 terbuka (SSH - Secure Shell). Rentan terhadap serangan brute force jika password lemah. Periksa kekuatan password dan aktifkan key-based authentication.",
        23: "Port 23 terbuka (Telnet). Semua data ditransfer tanpa enkripsi sehingga rentan sniffing dan serangan man-in-the-middle. Telnet sangat tidak disarankan digunakan.",
        25: "Port 25 terbuka (SMTP - Simple Mail Transfer Protocol). Rentan terhadap abuse seperti spam relaying dan dapat digunakan untuk serangan phishing jika server tidak dikonfigurasi dengan benar.",
        53: "Port 53 terbuka (DNS - Domain Name System). Rentan terhadap serangan DNS amplification yang dapat digunakan dalam DDoS dan cache poisoning.",
        80: "Port 80 terbuka (HTTP - HyperText Transfer Protocol). Komunikasi tidak terenkripsi, memungkinkan sniffing data sensitif. Sebaiknya gunakan HTTPS di port 443.",
        110: "Port 110 terbuka (POP3 - Post Office Protocol v3). Rentan terhadap sniffing karena data dikirim dalam teks biasa. Gunakan POP3S untuk enkripsi.",
        143: "Port 143 terbuka (IMAP - Internet Message Access Protocol). Data tidak terenkripsi dan rentan terhadap sniffing. Gunakan IMAPS untuk meningkatkan keamanan.",
        3306: "Port 3306 terbuka (MySQL Database). Rentan terhadap brute force dan ekspos data sensitif jika tidak diamankan dengan firewall atau enkripsi.",
        3389: "Port 3389 terbuka (RDP - Remote Desktop Protocol). Rentan terhadap serangan brute force dan exploit jika tidak dikonfigurasi dengan benar. Sebaiknya gunakan VPN untuk akses.",
        445: "Port 445 terbuka (SMB - Server Message Block). Rentan terhadap serangan seperti EternalBlue yang digunakan oleh ransomware seperti WannaCry.",
        5900: "Port 5900 terbuka (VNC - Virtual Network Computing). Rentan terhadap brute force dan sniffing data. Gunakan enkripsi tambahan untuk melindungi akses remote.",
        8080: "Port 8080 terbuka (HTTP Alternate). Rentan terhadap sniffing karena komunikasi tidak terenkripsi. Pastikan hanya digunakan untuk aplikasi non-sensitif."
    }

#scan IP
def scanHost(ip, startPort, endPort):
    """Starts a TCP scan on a given IP address and returns scan results with protocol and service info for open ports only."""
    print('[*] Starting TCP port scan on host %s' % ip)

    scanner = nmap.PortScanner()

    scanner.scan(ip, f"{startPort}-{endPort}")

    open_ports = []
    for port in range(startPort, endPort + 1):
        if scanner[ip].has_tcp(port):
            port_info = scanner[ip]['tcp'][port]
            if port_info['state'] == 'open':  # Only include ports that are open
                message = vulnerability_messages.get(port, "")
                open_ports.append({
                    "port": port,
                    "state": port_info['state'],
                    "name": port_info['name'],
                    "reason": port_info['reason'],
                    "product": port_info.get('product', 'unknown'),
                    "version": port_info.get('version', 'unknown'),
                    "extrainfo": port_info.get('extrainfo', 'unknown'),
                    "conf": port_info['conf'],
                    "message": message
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

# def tcp_scan(ip, startPort, endPort):
#     """ Creates a TCP socket and attempts to connect via supplied ports. """
#     open_ports = []
#     for port in range(startPort, endPort + 1):
#         try:
#             tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#             tcp.settimeout(1)  

#             if tcp.connect_ex((ip, port)) == 0:  
#                 open_ports.append(port)
#                 print(f'[+] {ip}:{port}/TCP Open')

#         except Exception as e:
#             print(f"Error scanning port {port} on {ip}: {e}")
#     return open_ports

from scapy.all import ARP, Ether, srp

#scan network 
# def network_scan(target_ip):
#     arp = ARP(pdst=target_ip)
#     ether = Ether(dst="ff:ff:ff:ff:ff:ff")
#     packet = ether/arp
    
#     result = srp(packet, timeout=3, verbose=0)[0]

#     available_devices = [(received.psrc, received.hwsrc) for sent, received in result]

#     scan_result = {
#         "type": "Scan Network",
#         "network": target_ip,
#         "available_devices": available_devices
#     }

#     print(scan_result)
#     return scan_result

from scapy.all import ARP, Ether, srp
import nmap

def scanPort(ip, startPort, endPort):
    """
    Scans the specified IP address for open TCP ports in the given range.
    """
    print(f"[*] Starting TCP port scan on host {ip}")

    scanner = nmap.PortScanner()

    try:
        scanner.scan(ip, f"{startPort}-{endPort}")
    except Exception as e:
        print(f"[!] Error during scan: {e}")
        return []
    # {
    #         "type": "Scan Host",
    #         "ip_address": ip,
    #         "open_ports": [],
    #         "error": str(e)
    #     }

    if ip not in scanner.all_hosts():
        print(f"[!] Host {ip} not found in scan results. It may be offline or unreachable.")
        return []

    open_ports = []

    for port in range(startPort, endPort + 1):
        try:
            if scanner[ip].has_tcp(port):
                port_info = scanner[ip]['tcp'][port]
                if port_info['state'] == 'open':
                    message = vulnerability_messages.get(port, "")
                    open_ports.append({
                        "port": port,
                        "state": port_info['state'],
                        "name": port_info['name'],
                        "reason": port_info['reason'],
                        "product": port_info.get('product', 'unknown'),
                        "version": port_info.get('version', 'unknown'),
                        "extrainfo": port_info.get('extrainfo', 'unknown'),
                        "conf": port_info['conf'],
                        "message": message
                    })
        except KeyError:
            print(f"[!] Port {port} data not found in scan results.")
        except Exception as e:
            print(f"[!] Unexpected error for port {port}: {e}")

    print(f"[+] TCP scan on host {ip} complete")
    return open_ports

def network_scan_and_port_scan(subnet, startPort=20, endPort=100):
    """
    Scans the specified subnet for devices and optionally scans each device for open ports.
    """
    print(f"[*] Scanning subnet {subnet} for active devices... {startPort} - {endPort}")
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    try:
        result = srp(packet, timeout=3, verbose=0)[0]
    except Exception as e:
        print(f"[!] Error during ARP scan: {e}")
        return {
            "type": "Subnet Scan and Port Scan",
            "subnet": subnet,
            "number_of_devices":len(available_devices),
            "start_port": startPort,
            "end_port": endPort,
            "available_devices": [],
            "error": str(e)
        }

    available_devices = []
    for sent, received in result:
        available_devices.append((received.psrc, received.hwsrc))
        print(f"[+] Found device: IP={received.psrc}, MAC={received.hwsrc}")

    print(f"[*] Subnet scan complete. {len(available_devices)} device(s) found.")

    scanned_results = []
    for ip, mac in available_devices:
        print(f"[*] Scanning {ip} for open ports...")
        open_ports = scanPort(ip, startPort, endPort)
        scanned_results.append({
            "ip": ip,
            "mac": mac,
            "open_ports": open_ports
        })

    # Organize results into a JSON-like dictionary
    scan_result = {
        "type": "Subnet Scan and Port Scan",
        "subnet": subnet,
        "number_of_devices":len(available_devices),
        "start_port": startPort,
        "end_port": endPort,
        "available_devices": scanned_results
    }

    print("[+] Full scan complete.")
    return scan_result



# Example Usage
if __name__ == "__main__":
    # Replace '192.168.1.0/24' with your desired subnet
    subnet = "192.168.1.1/24"
    result = network_scan_and_port_scan(subnet, startPort=80, endPort=100)
    # result = scanHost("192.168.1.31",4999,5010)
    print(result)

# if __name__ == '__main__':
#     socket.setdefaulttimeout(0.01)

#     if len(sys.argv) < 4:
#         print('Usage: ./portscanner.py <IP address> <start port> <end port>')
#         print('Example: ./portscanner.py 192.168.1.10 1 65535\n')
#         print('Usage: ./portscanner.py <network> <start port> <end port> -n')
#         print('Example: ./portscanner.py 192.168.1 1 65535 -n')
#         sys.exit(1)

#     network   = sys.argv[1]
#     startPort = int(sys.argv[2])
#     endPort   = int(sys.argv[3])

#     # Determine whether to scan a host or a network range
#     if len(sys.argv) == 4:
#         result = scanHost(network, startPort, endPort)
#         print(result)

#     elif len(sys.argv) == 5 and sys.argv[4] == '-n':
#         # scanRange(network, startPort, endPort)
#         result = network_scan(network)
#         # get_info()
#         print(result)

