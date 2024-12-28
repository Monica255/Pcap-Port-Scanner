import unittest
from unittest.mock import patch
from vulnerability_scanner import detect_arp_spoofing
from scapy.all import ARP, IP

def create_mock_arp_packets(packet_data):
    packets = []
    for data in packet_data:
        packet = ARP(op=2, psrc=data['ip_sumber'], hwsrc=data['mac_sumber'], pdst=data['ip_tujuan'], hwdst=data['mac_tujuan'])
        packets.append(packet)
    return packets

class TestNetworkAnalysis(unittest.TestCase):
    @patch('vulnerability_scanner.rdpcap')
    def test_arp_spoofing_detected(self, mock_rdpcap):
        
        mock_packets = create_mock_arp_packets([
            {'ip_sumber': '10.0.0.1', 'mac_sumber': '00:11:22:33:44:55', 'ip_tujuan': '192.168.1.1', 'mac_tujuan': '66:77:88:99:AA:BB'},
            {'ip_sumber': '10.0.0.1', 'mac_sumber': '00:11:22:33:44:66', 'ip_tujuan': '192.168.1.1', 'mac_tujuan': '66:77:88:99:AA:BB'},
        ])  
        mock_rdpcap.return_value = mock_packets

        result = detect_arp_spoofing('mock_file.pcap')
        self.assertEqual(result['number_of_detected'], 1)
        self.assertEqual(len(result['details']), 1) 
        self.assertEqual(result['details'][0]['ip_sumber'], '10.0.0.1')
        self.assertEqual(result['details'][0]['mac_sumber'], '00:11:22:33:44:66')
        self.assertEqual(result['details'][0]['mac_lainnya'], '00:11:22:33:44:55')

    @patch('vulnerability_scanner.rdpcap')
    def test_no_arp_spoofing_detected(self, mock_rdpcap):
        
        mock_packets = create_mock_arp_packets([
            {'ip_sumber': '10.0.0.1', 'mac_sumber': '00:11:22:33:44:55', 'ip_tujuan': '192.168.1.1', 'mac_tujuan': '66:77:88:99:AA:BB'},
            {'ip_sumber': '10.0.0.2', 'mac_sumber': '00:11:22:33:44:66', 'ip_tujuan': '192.168.1.2', 'mac_tujuan': '66:77:88:99:AA:BB'},
        ])  
        mock_rdpcap.return_value = mock_packets

        result = detect_arp_spoofing('mock_file.pcap')
        self.assertEqual(result['number_of_detected'], 0)
        self.assertEqual(len(result['details']), 0)

if __name__ == '__main__':
    unittest.main()
