import unittest
from unittest.mock import patch
from vulnerability_scanner import detect_port_scanning
from scapy.all import TCP, IP

def create_mock_port_scanning_packets(packet_data):
    packets = []
    for data in packet_data:
        packet = IP(src=data['src_ip'], dst=data['dst_ip'])/TCP(sport=data['sport'], dport=data['dport'])
        packets.append(packet)
    return packets

class TestNetworkAnalysis(unittest.TestCase):
    @patch('vulnerability_scanner.rdpcap')
    def test_port_scanning_detected(self, mock_rdpcap):

        mock_packets = create_mock_port_scanning_packets([
            {'src_ip': '10.0.0.1', 'dst_ip': '192.168.1.1', 'sport': 12345, 'dport': 80},
            {'src_ip': '10.0.0.1', 'dst_ip': '192.168.1.1', 'sport': 12345, 'dport': 443},
            {'src_ip': '10.0.0.1', 'dst_ip': '192.168.1.1', 'sport': 12345, 'dport': 8080},
            {'src_ip': '10.0.0.1', 'dst_ip': '192.168.1.1', 'sport': 12345, 'dport': 21},
            {'src_ip': '10.0.0.1', 'dst_ip': '192.168.1.1', 'sport': 12345, 'dport': 22},
            {'src_ip': '10.0.0.1', 'dst_ip': '192.168.1.1', 'sport': 12345, 'dport': 25},
        ])  
        mock_rdpcap.return_value = mock_packets

        result = detect_port_scanning('mock_file.pcap')
        self.assertEqual(result['number_of_detected'], 1)
        self.assertEqual(len(result['details']), 1)
        self.assertEqual(result['details'][0]['ip_sumber'], '10.0.0.1')
        self.assertEqual(result['details'][0]['total_port_discan'], 6)
        self.assertEqual(sorted(result['details'][0]['port']), [21, 22, 25, 80, 443, 8080])

    @patch('vulnerability_scanner.rdpcap')
    def test_no_port_scanning_detected(self, mock_rdpcap):

        mock_packets = create_mock_port_scanning_packets([
            {'src_ip': '10.0.0.1', 'dst_ip': '192.168.1.1', 'sport': 12345, 'dport': 80},
            {'src_ip': '10.0.0.1', 'dst_ip': '192.168.1.1', 'sport': 12345, 'dport': 443},
            {'src_ip': '10.0.0.1', 'dst_ip': '192.168.1.1', 'sport': 12345, 'dport': 8080},
        ]) 
        mock_rdpcap.return_value = mock_packets

        result = detect_port_scanning('mock_file.pcap')
        self.assertEqual(result['number_of_detected'], 0)
        self.assertEqual(len(result['details']), 0)

if __name__ == '__main__':
    unittest.main()
