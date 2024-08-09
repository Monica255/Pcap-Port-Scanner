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
print(detect_brute_force('bruteforce.pcap'))
