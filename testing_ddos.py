import unittest
from vulnerability_scanner import detect_ddos

class TestDetectDDOS(unittest.TestCase):
    def test_ddos_detected(self):
        # File PCAP yang mengandung aktivitas DDoS
        test_file = 'sample/(sample) ddos.pcap'

        # Panggil fungsi untuk mendeteksi DDoS
        result = detect_ddos(test_file)

        # Verifikasi hasilnya
        self.assertGreaterEqual(result['number_of_detected'], 1)
        self.assertGreaterEqual(len(result['details']), 1)
        self.assertGreaterEqual(result['details'][0]['jumlah_paket'], 1000)
        self.assertGreaterEqual(result['details'][0]['sumber_unik'], 10)

    def test_no_ddos_detected(self):
        # File PCAP tanpa aktivitas DDoS
        test_file = 'sample/(exported) no action.pcapng'
        
        result = detect_ddos(test_file)

        # Verifikasi hasilnya
        self.assertEqual(result['number_of_detected'], 0)
        self.assertEqual(len(result['details']), 0)

if __name__ == '__main__':
    unittest.main()
