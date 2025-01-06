import unittest
from scapy.all import rdpcap
from vulnerability_scanner import detect_arp_spoofing

class TestNetworkAnalysis(unittest.TestCase):
    def test_arp_spoofing_detected(self):
        # file PCAP yang mengandung paket ARP spoofing
        test_file = 'sample/(sample) arpspoof.pcap'
        result = detect_arp_spoofing(test_file)
        
        # Verifikasi hasilnya
        self.assertGreaterEqual(result['number_of_detected'], 1)
        self.assertGreaterEqual(len(result['details']), 1)

    def test_no_arp_spoofing_detected(self):
        # file PCAP yang tidak mengandung ARP spoofing
        test_file = 'sample/(exported) sikuel.pcapng'
        result = detect_arp_spoofing(test_file)
        
        # Verifikasi hasilnya
        self.assertEqual(result['number_of_detected'], 0)
        self.assertEqual(len(result['details']), 0)

if __name__ == '__main__':
    unittest.main()
