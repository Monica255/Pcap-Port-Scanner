import unittest
from vulnerability_scanner import detect_brute_force

class TestNetworkAnalysis(unittest.TestCase):
    def test_brute_force_detected(self):
        # file PCAP Anda yang mengandung aktivitas brute force
        test_file = 'sample/(sample) bruteforce.pcap'
        result = detect_brute_force(test_file)
        
        # Verifikasi hasilnya
        self.assertGreaterEqual(result['number_of_detected'], 1)
        self.assertGreaterEqual(len(result['details']), 1)
        self.assertGreaterEqual(result['details'][0]['jumlah_percobaan'], 120)

    def test_no_brute_force_detected(self):
        # file PCAP yang tidak mengandung aktivitas brute force
        test_file = 'sample/(exported) no action.pcapng'
        result = detect_brute_force(test_file)
        
        # Verifikasi hasilnya
        self.assertEqual(result['number_of_detected'], 0)

if __name__ == '__main__':
    unittest.main()
