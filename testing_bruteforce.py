import unittest
from unittest.mock import patch
from vulnerability_scanner import detect_brute_force
from scapy.all import IP, TCP

def create_mock_tcp_packets(packet_data):
    packets = []
    for data in packet_data:
        packet = IP(src=data['ip_sumber'], dst=data['ip_tujuan']) / TCP(
            sport=data['port_sumber'], dport=data['port_tujuan']
        )
        packets.append(packet)
    return packets

class TestNetworkAnalysis(unittest.TestCase):
    @patch('vulnerability_scanner.rdpcap')
    def test_brute_force_detected(self, mock_rdpcap):

        mock_packets = create_mock_tcp_packets([
            {'ip_sumber': '10.0.0.1', 'port_sumber': 12345, 'ip_tujuan': '192.168.1.1', 'port_tujuan': 22},
        ] * 120) 
        mock_rdpcap.return_value = mock_packets

        result = detect_brute_force('mock_file.pcap')
        self.assertEqual(result['number_of_detected'], 1)
        self.assertEqual(len(result['details']), 1)
        self.assertEqual(result['details'][0]['jumlah_percobaan'], 120)

    @patch('vulnerability_scanner.rdpcap')
    def test_no_brute_force_detected(self, mock_rdpcap):

        mock_packets = create_mock_tcp_packets([
            {'ip_sumber': '10.0.0.1', 'port_sumber': 12345, 'ip_tujuan': '192.168.1.1', 'port_tujuan': 22}
        ] * 80)  
        mock_rdpcap.return_value = mock_packets

        result = detect_brute_force('mock_file.pcap')
        self.assertEqual(result['number_of_detected'], 0)

if __name__ == '__main__':
    unittest.main()
