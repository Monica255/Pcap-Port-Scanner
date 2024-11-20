from scapy.all import *

from vulnerability_scanner import *

def filter_packets(packets):
    tcp_packets = [p for p in packets if TCP in p]
    udp_packets = [p for p in packets if UDP in p]
    icmp_packets = [p for p in packets if ICMP in p]
    other_packets = [p for p in packets if not (TCP in p or UDP in p or ICMP in p)]
    return tcp_packets, udp_packets, icmp_packets, other_packets

def filter_packets_by_source_ip(packets, source_ip):
    return [p for p in packets if IP in p and p[IP].src == source_ip]

def filter_packets_by_destination_port(packets, dest_port):
    return [p for p in packets if TCP in p and p[TCP].dport == dest_port]

def filter_packets_by_mac_address(packets, mac_address):
    return [p for p in packets if Ether in p and (p.src == mac_address or p.dst == mac_address)]

def filter_packets_by_ip_range(packets, start_ip, end_ip):
    return [p for p in packets if IP in p and start_ip <= p[IP].src <= end_ip]

def filter_packets_by_protocol(packets, protocol):
    return [p for p in packets if p.haslayer(protocol)]

def parse_dns_packets(packets):
    dns_packets = [p for p in packets if DNS in p]
    return [p[DNS].qd.qname.decode('utf-8') for p in dns_packets]

def filter_suspicious_packets(packets, max_payload_size):
    return [p for p in packets if TCP in p and len(p[TCP].payload) > max_payload_size]

def filter_packets_by_tcp_flags(packets, flags):
    return [p for p in packets if TCP in p and p[TCP].flags & flags]

def get_time(packets):
    if packets:
        first_packet_time = packets[0].time
        last_packet_time = packets[-1].time
        start_time = datetime.fromtimestamp(float(first_packet_time))
        end_time = datetime.fromtimestamp(float(last_packet_time))
        duration_seconds = end_time - start_time

        total_seconds = int(duration_seconds.total_seconds())

        # Calculate hours, minutes, and seconds
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)

        # Format as HH:MM:SS
        formatted_duration = f"{hours:02}:{minutes:02}:{seconds:02}"
        # duration = str(datetime.utcfromtimestamp(duration_seconds).strftime('%H:%M:%S'))
        return start_time.isoformat(),end_time.isoformat(),formatted_duration
    

def analyze_pcap(pcap_file):
    packets = rdpcap(pcap_file)
    time = get_time(packets)
    tcp_packets, udp_packets, icmp_packets, other_packets = filter_packets(packets)
    source_ip_packets = filter_packets_by_source_ip(packets, "192.168.0.1")
    dest_port_packets = filter_packets_by_destination_port(packets, 80)
    mac_address_packets = filter_packets_by_mac_address(packets, "00:11:22:33:44:55")
    ip_range_packets = filter_packets_by_ip_range(packets, "192.168.0.1", "192.168.0.100")
    http_packets = filter_packets_by_protocol(packets, TCP)
    domain_info = parse_dns_packets(packets)
    suspicious_packets = filter_suspicious_packets(packets, 1024)
    syn_packets = filter_packets_by_tcp_flags(packets, 0x02)  # SYN flag

    # Scan vulnerabilities
    # - DDoS
    # - Unencrypted packets
    # - SQL injection
    # - weak credential
    # - NXDomain
    # - phishing
    vulnerabilities = []
    ddos = detect_ddos(pcap_file)
    UP = detect_unencrypted_traffic(pcap_file)
    SQL = detect_sql_injection(pcap_file)
    WC = detect_weak_credentials(pcap_file)
    NXD = detect_nxdomain(pcap_file)
    phishing = detect_hidden_characters_in_domains(pcap_file)
    bf = detect_brute_force(pcap_file)
    arp = detect_arp_spoofing(pcap_file)
    port_scan = detect_port_scanning(pcap_file)

    vulnerabilities.append(ddos)
    vulnerabilities.append(UP)
    vulnerabilities.append(SQL)
    vulnerabilities.append(WC)
    vulnerabilities.append(NXD)
    vulnerabilities.append(phishing)
    vulnerabilities.append(bf)
    vulnerabilities.append(arp)
    vulnerabilities.append(port_scan)

    my_list = [item for item in vulnerabilities if item['number_of_detected'] != 0]

    # Build results dictionary
    result = {
        'file_name':pcap_file,
        'start_time':time[0],
        'end_time':time[1],
        'duration':time[2],
        'tcp_packets_count': len(tcp_packets),
        'udp_packets_count': len(udp_packets),
        'icmp_packets_count': len(icmp_packets),
        'other_packets_count': len(other_packets),
        # 'source_ip_packets_count': len(source_ip_packets),
        # 'destination_port_packets_count': len(dest_port_packets),
        # 'mac_address_packets_count': len(mac_address_packets),
        # 'ip_range_packets_count': len(ip_range_packets),
        'http_packets_count': len(http_packets),
        'suspicious_packets_count': len(suspicious_packets),
        'syn_packets_count': len(syn_packets),
        'dns_domains': domain_info,
        'total_vulnerabilities_detected':len(my_list),
        'vulnerabilities': my_list
    }

    return result

# Example usage
result = analyze_pcap('formbook.pcap')
# print(result)


