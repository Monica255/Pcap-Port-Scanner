from scapy.all import rdpcap, TCP, IP

# Load the pcap file
def detect_brute_force(pcap_file):
    packets = rdpcap(pcap_file)
    # Dictionary to store connection attempts
    attempts = {}

    # Loop through each packet
    for pkt in packets:
        if pkt.haslayer(TCP):
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport

            # Using (src_ip, dst_ip, dst_port) as key to count attempts
            key = (ip_src, ip_dst, dport)

            # Initialize the count if key doesn't exist
            if key not in attempts:
                attempts[key] = []

            # Append each attempt with its timestamp and source port
            attempts[key].append({
                'timestamp': pkt.time,
                'source_port': sport
            })

    # Threshold to define brute force (e.g., more than 10 attempts)
    threshold = 10

    # List to store details of potential brute-force attempts
    detected_brute_force = []

    # Populate the detected_brute_force list
    for key, logs in attempts.items():
        if len(logs) > threshold:
            detected_brute_force.append({
                'source_ip': key[0],
                'destination_ip': key[1],
                'destination_port': key[2],
                'number_of_attempts': len(logs),
                # 'attempts': logs
            })

    # Create the result dictionary
    result = {
        'vulnerability_type': 'Brute Force Attack',
        'message': 'Potential Brute Force Attack Detected',
        'number_of_detected': len(detected_brute_force),
        'details': detected_brute_force
    }

    return result

# Output the result
# print(detect_brute_force('bruteforce.pcap'))

def calculate_cvss3_score(av, ac, pr, ui, s, c, i, a):
    # Weight mappings for CVSS
    weights_av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    weights_ac = {"L": 0.77, "H": 0.44}
    weights_pr = {"N": 0.85, "L": 0.62, "H": 0.27}
    weights_ui = {"N": 0.85, "R": 0.62}
    weights_s = {"U": 1, "C": 1.08}
    weights_cia = {"H": 0.56, "L": 0.22, "N": 0}

    # Calculate the impact based on CIA
    impact = 1 - ((1 - weights_cia[c]) * (1 - weights_cia[i]) * (1 - weights_cia[a]))

    if s == "U":  # If scope is Unchanged
        impact = weights_s[s] * impact
    else:  # If scope is Changed
        impact = weights_s[s] * (impact - 0.029) - 3.25 * (impact - 0.02) ** 15

    # Calculate exploitability
    exploitability = weights_av[av] * weights_ac[ac] * weights_pr[pr] * weights_ui[ui]

    # Calculate the base score
    if impact <= 0:
        base_score = 0
    elif s == "U":
        base_score = min(impact + exploitability, 10)
    else:
        base_score = min(weights_s[s] * (impact + exploitability), 10)

    return round(base_score, 1)

# Port Scanning Attack Example
# cvss_score = calculate_cvss3_score("N", "L", "N", "N", "U", "N", "N", "L")
# print(cvss_score)  # Expected output: 5.3


import re
import unicodedata
from scapy.all import rdpcap, DNSQR, IP, TCP

def has_hidden_characters(domain_name):
    hidden_character_patterns = [
        r'[^\x00-\x7F]',            # Non-ASCII characters (e.g., Unicode characters)
        r'\u200B',                  # Zero-width space
        r'\u200C',                  # Zero-width non-joiner
        r'\u200D',                  # Zero-width joiner
        r'\uFEFF',                  # Zero-width no-break space (BOM)
        r'\u00A0',                  # Non-breaking space
        r'\u202E',                  # Right-to-left override (used to disguise file extensions)
        r'\u202D',                  # Left-to-right override (used to disguise file extensions)
        r'\u202C',                  # Pop directional formatting
        r'\u202A',                  # Left-to-right embedding
        r'\u202B',                  # Right-to-left embedding
        r'\u034F',                  # Combining grapheme joiner
        r'\u2060',                  # Word joiner
        r'\u2061',                  # Function application
        r'\u2062',                  # Invisible times
        r'\u2063',                  # Invisible separator
        r'\u2064',                  # Invisible plus
        r'\u00AD',                  # Soft hyphen (may be invisible in certain contexts)
        r'\u180E',                  # Mongolian vowel separator
        # Homoglyphs: Characters that look like ASCII characters but are different
        r'\u0430',                  # Cyrillic 'a' (looks like Latin 'a')
        r'\u03C1',                  # Greek 'ρ' (looks like Latin 'p')
        r'\u0456',                  # Cyrillic 'і' (looks like Latin 'i')
        r'\u043E',                  # Cyrillic 'o' (looks like Latin 'o')
        r'\u03C0',                  # Greek 'π' (looks like Latin 'n')
        r'\uFF21-\uFF3A',           # Full-width Latin capital letters
        r'\uFF41-\uFF5A',           # Full-width Latin small letters
        # Add more patterns as needed for specific phishing cases
    ]

    for pattern in hidden_character_patterns:
        if re.search(pattern, domain_name):
            return True
    return False

def detect_hidden_characters_in_domains(pcap_file):
    packets = rdpcap(pcap_file)

    detected_hidden_characters = []

    for packet in packets:
        # Check for DNS query requests
        if packet.haslayer(DNSQR):
            domain_name = packet[DNSQR].qname.decode('utf-8')
            if has_hidden_characters(domain_name):
                detected_hidden_characters.append({
                    'nama_domain': domain_name,
                    'ip_sumber': packet[IP].src,
                    'ip_tujuan': packet[IP].dst,
                    'protokol': 'DNS'
                })

        # Check for HTTP/HTTPS traffic containing domain names in the payload
        if packet.haslayer(TCP):
            if packet[TCP].dport in [80, 443] or packet[TCP].sport in [80, 443]:
                raw_data = bytes(packet[TCP].payload)
                try:
                    # Attempt to decode the payload as a UTF-8 string
                    data = raw_data.decode('utf-8')
                    # Extract domain names from the payload (typically in Host header)
                    host_matches = re.findall(r'Host: ([^\s]+)', data)
                    for host in host_matches:
                        if has_hidden_characters(host):
                            detected_hidden_characters.append({
                                'nama_domain': host,
                                'ip_sumber': packet[IP].src,
                                'ip_tujuan': packet[IP].dst,
                                'protokol': 'HTTP/HTTPS'
                            })
                except UnicodeDecodeError:
                    pass

    result = {
        'vulnerability_type': 'Hidden Characters in Domain',
        'message': 'Potensi domain phishing dengan karakter tersembunyi terdeteksi',
        'number_of_detected': len(detected_hidden_characters),
        'details': detected_hidden_characters
    }

    return result

# result = detect_hidden_characters_in_domains('sql pcap.pcapng')
# print(result)



from scapy.all import rdpcap, DNS, DNSRR
from decimal import Decimal

def detect_nxdomain(pcap_file):
    packets = rdpcap(pcap_file)
    nxdomain_info = []

    # Analyze each packet
    for packet in packets:
        if packet.haslayer(DNS) and packet[DNS].qr == 1:
            dns_layer = packet[DNS]
            if dns_layer.rcode == 3:
                query_name = dns_layer.qd.qname.decode() if dns_layer.qdcount > 0 else 'Unknown'
                nxdomain_info.append({
                    'nama_kueri': query_name,
                    'kode_respon': dns_layer.rcode,
                    'timestamp': packet.time
                })

    result = {
        'vulnerability_type': 'NXDOMAIN',
        'message': 'NXDOMAIN (Non-Existent Domain) adalah respons dari server DNS yang menunjukkan bahwa domain yang diminta tidak ada atau tidak dapat ditemukan. Hal ini dapat dimanfaatkan oleh penyerang dalam serangan seperti NXDOMAIN Flood, di mana banyak permintaan DNS untuk domain tidak valid dikirim untuk membanjiri server DNS.',
        'number_of_detected': len(nxdomain_info),
        'details': nxdomain_info
    }
    return result

# pcap_file = 'formbook.pcap'  
# nxdomain_result = detect_nxdomain(pcap_file)
# print(nxdomain_result)


from scapy.all import rdpcap, IP, TCP

def detect_weak_credentials(pcap_file):
    packets = rdpcap(pcap_file)
    weak_credentials = {
        'admin': 'admin',
        'root': 'root',
        'user': 'user',
        'guest': 'guest',
        'test': 'test',
        'administrator': 'administrator',
        'admin': 'password',
        'root': 'password',
        'admin': '12345',
        'root': '12345',
        'admin': '123456',
        'root': '123456',
        'user': '1234',
        'guest': '1234',
        'test': '1234',
        'user': 'password',
        # 'guest': 'guest',
        # 'support': 'support',
        'webadmin': 'webadmin',
        # 'ftp': 'ftp',
        # 'manager': 'manager',
        # 'backup': 'backup',
        'sysadmin': 'sysadmin',
        # 'postgres': 'postgres',
        # 'mysql': 'mysql',
        # 'oracle': 'oracle',
        'default': 'default',
        'admin': 'letmein',
        'admin': 'qwerty',
        'root': 'qwerty',
        'admin': '123',
        'root': '123',
        'user': '123',
        'admin': '123123',
        'admin': 'pass',
        'root': 'pass',
        'user': 'letmein',
        'admin': 'welcome',
        'user': 'welcome',
        'admin': 'admin123',
        'root': 'root123'
    }

    detected_credentials = []

    for packet in packets:
        payload = str(packet.payload)
        for username, password in weak_credentials.items():
            if username in payload and password in payload:
                detected_credentials.append({
                    'username': username,
                    'password': password,
                    'payload':payload,
                    'ringkasan_paket': packet.summary()
                })

    result = {
        'vulnerability_type': 'Weak Credentials',
        'message': 'Potensi kredensial lemah terdeteksi pada jaringan',
        'number_of_detected': len(detected_credentials),
        'details': detected_credentials
    }

    return result


# pcap_file = 'SYN.pcap'
# print(detect_weak_credentials(pcap_file))

def detect_unencrypted_traffic(pcap_file):
    packets = rdpcap(pcap_file)
    unencrypted_protocols_ports = {80: 'HTTP', 21: 'FTP'}
    detected_packets = []
    n=0
    for packet in packets:
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            ip_layer = packet[IP] if packet.haslayer(IP) else None
            src_ip = ip_layer.src if ip_layer else "Unknown Source IP"
            dst_ip = ip_layer.dst if ip_layer else "Unknown Destination IP"
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport

            if dst_port in unencrypted_protocols_ports or src_port in unencrypted_protocols_ports:
                protocol = unencrypted_protocols_ports.get(dst_port, unencrypted_protocols_ports.get(src_port, "Unknown Protocol"))
                packet_info = {
                    'ip_sumber': src_ip,
                    'ip_tujuan': dst_ip,
                    'port_sumber': src_port,
                    'port_tujuan': dst_port,
                    'protokol': protocol,
                    'ukuran_payload': len(tcp_layer.payload),
                    'timestamp': packet.time,
                    'ringkasan_paket': packet.summary(),
                    'ukuran_paket': len(packet),
                    'tcp_flags': tcp_layer.flags
                }
                detected_packets.append(packet_info)

    result = {
        'vulnerability_type':'Unencrypted Traffic',
        'message':'Unencrypted Traffic adalah data jaringan yang dikirim tanpa enkripsi, sehingga tetap dalam bentuk teks yang dapat dibaca dan rentan disadap, dianalisis, atau dicuri oleh pihak yang tidak berwenang.',
        'number_of_detected': len(detected_packets),
        # 'details': detected_packets
    }

    return result


from scapy.all import rdpcap, TCP, IP
import time
from cvss_calc import get_cvss_base_score


def detect_ssh_brute_force_attack(pcap_file):
    packets = rdpcap(pcap_file)
    brute_force_threshold = 100  
    
    cve="CVE-2018-15473"
    cvss_score = get_cvss_base_score(cve)
    failed_attempts = {}

    for packet in packets:
        if packet.haslayer(TCP) and packet.haslayer(IP):
            ip_layer = packet[IP]
            tcp_layer = packet[TCP]
            
            if tcp_layer.dport == 22 or tcp_layer.sport == 22:
                src_ip = ip_layer.src
                
                if src_ip not in failed_attempts:
                    failed_attempts[src_ip] = 0
                if packet.haslayer(TCP) and packet[TCP].flags == 0x14:  
                    failed_attempts[src_ip] += 1

    detected_brute_force = []
    for src_ip, attempts in failed_attempts.items():
        if attempts >= brute_force_threshold:
            detected_brute_force.append({
                'src_ip': src_ip,
                'failed_attempts': attempts
            })

    result = {
        'vulnerability_type': 'SSH Brute Force Attack',
        'message': 'Serangan brute force pada SSH terjadi ketika seorang penyerang mencoba banyak kombinasi username dan password untuk mendapatkan akses ke server SSH. Banyaknya percakapan gagal dalam waktu singkat bisa menunjukkan upaya brute force. Serangan ini berisiko tinggi karena dapat memberikan akses tidak sah ke server, yang dapat digunakan untuk berbagai tujuan berbahaya.',
        'number_of_detected': len(detected_brute_force),
        'cvss_score': cvss_score,
        'details': detected_brute_force
    }

    return result


# Example usage
# pcap_file = "ssh.pcap"
# result = detect_ssh_brute_force_attack(pcap_file)
# print(result)


