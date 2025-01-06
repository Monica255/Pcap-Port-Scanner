import unittest
from unittest.mock import patch
from scapy.all import IP, TCP, rdpcap
import re
from vulnerability_scanner import detect_sql_injection

def create_mock_tcp_packets(packet_data):
    packets = []
    for data in packet_data:
        packet = IP(src=data['ip_sumber'], dst=data['ip_tujuan']) / TCP(
            sport=data['port_sumber'], dport=data['port_tujuan']
        )
        packet[TCP].payload = data['payload'].encode('utf-8')
        packets.append(packet)
    return packets

class TestDetectSQLInjection(unittest.TestCase):
    @patch('vulnerability_scanner.rdpcap')  
    def test_sql_injection_detected(self, mock_rdpcap):

        packet_data = [
            {
                'ip_sumber': '192.168.1.10',
                'port_sumber': 12345,
                'ip_tujuan': '192.168.1.20',
                'port_tujuan': 80,
                'payload': "SELECT * FROM users WHERE username = 'admin' OR '1'='1';"
            }
        ]
        mock_packets = create_mock_tcp_packets(packet_data)
        mock_rdpcap.return_value = mock_packets

        result = detect_sql_injection('mock_file.pcap')

        self.assertEqual(result['number_of_detected'], 1)
        self.assertEqual(len(result['details']), 1)
        self.assertEqual(result['details'][0]['ip_sumber'], '192.168.1.10')
        self.assertEqual(result['details'][0]['ip_tujuan'], '192.168.1.20')

    @patch('vulnerability_scanner.rdpcap') 
    def test_no_sql_injection_detected(self, mock_rdpcap):

        packet_data = [
            {
                'ip_sumber': '192.168.1.10',
                'port_sumber': 12345,
                'ip_tujuan': '192.168.1.20',
                'port_tujuan': 80,
                'payload': "GET /index.html HTTP/1.1"
            }
        ]
        mock_packets = create_mock_tcp_packets(packet_data)
        mock_rdpcap.return_value = mock_packets

        result = detect_sql_injection('mock_file.pcap')

        self.assertEqual(result['number_of_detected'], 0)
        self.assertEqual(len(result['details']), 0)

if __name__ == '__main__':
    unittest.main()
