import unittest
from vulnerability_scanner import detect_port_scanning

class TestDetectPortScanning(unittest.TestCase):
    def test_port_scanning_detected(self):
        # File PCAP yang mengandung aktivitas port scanning
        test_file = 'sample/(exported) port scan.pcapng'
        result = detect_port_scanning(test_file)

        # Verifikasi hasilnya
        self.assertGreaterEqual(result['number_of_detected'], 1)
        self.assertGreaterEqual(len(result['details']), 1)
        self.assertGreaterEqual(result['details'][0]['total_port_discan'], 100)

    def test_no_port_scanning_detected(self):
        # File PCAP tanpa aktivitas port scanning
        test_file = 'sample/(exported) no action.pcapng'
        result = detect_port_scanning(test_file)

        # Verifikasi hasilnya
        self.assertEqual(result['number_of_detected'], 0)
        self.assertEqual(len(result['details']), 0)

if __name__ == '__main__':
    unittest.main()
