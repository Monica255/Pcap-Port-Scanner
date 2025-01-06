import unittest
from unittest.mock import patch
from scapy.all import IP, rdpcap
from collections import defaultdict
from vulnerability_scanner import detect_ddos

def create_mock_packets(dest_ip_counts, src_ips_per_dest):
    packets = []
    for dest_ip, count in dest_ip_counts.items():
        for i in range(count):
            packet = IP(dst=dest_ip, src=src_ips_per_dest[dest_ip][i % len(src_ips_per_dest[dest_ip])])
            packets.append(packet)
    return packets

class TestDetectDDOS(unittest.TestCase):
    @patch('vulnerability_scanner.rdpcap') 
    def test_ddos_detected(self, mock_rdpcap):

        dest_ip_counts = {'192.168.1.1': 1200}
        src_ips_per_dest = {'192.168.1.1': ['10.0.0.1', '10.0.0.2', '10.0.0.3']}
        mock_packets = create_mock_packets(dest_ip_counts, src_ips_per_dest)
        mock_rdpcap.return_value = mock_packets

        result = detect_ddos('mock_file.pcap')

        self.assertEqual(result['number_of_detected'], 1)
        self.assertEqual(len(result['details']), 1)
        self.assertEqual(result['details'][0]['ip_tujuan'], '192.168.1.1')
        self.assertEqual(result['details'][0]['jumlah_paket'], 1200)
        self.assertEqual(result['details'][0]['sumber_unik'], 3)

    @patch('vulnerability_scanner.rdpcap')
    def test_no_ddos_detected(self, mock_rdpcap):

        dest_ip_counts = {'192.168.1.1': 800, '192.168.1.2': 900}
        src_ips_per_dest = {'192.168.1.1': ['10.0.0.1'], '192.168.1.2': ['10.0.0.2']}
        mock_packets = create_mock_packets(dest_ip_counts, src_ips_per_dest)
        mock_rdpcap.return_value = mock_packets

        result = detect_ddos('mock_file.pcap')

        self.assertEqual(result['number_of_detected'], 0)
        self.assertEqual(len(result['details']), 0)

if __name__ == '__main__':
    unittest.main()
