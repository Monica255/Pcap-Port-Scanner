import unittest
from vulnerability_scanner import detect_ssh_brute_force_attack

class TestNetworkAnalysis(unittest.TestCase):
    def test_ssh_brute_force_detected(self):
        # file PCAP Anda yang mengandung aktivitas brute force
        test_file = 'sample/(exported) ssh bruteforce.pcapng'
        result = detect_ssh_brute_force_attack(test_file)
        
        # Verifikasi hasilnya
        self.assertGreaterEqual(result['number_of_detected'], 1)
        self.assertGreaterEqual(len(result['details']), 1)

    def test_no_ssh_brute_force_detected(self):
        # file PCAP yang tidak mengandung aktivitas brute force
        test_file = 'sample/(exported) no action.pcapng'
        result = detect_ssh_brute_force_attack(test_file)
        
        # Verifikasi hasilnya
        self.assertEqual(result['number_of_detected'], 0)

if __name__ == '__main__':
    unittest.main()
