import unittest
from vulnerability_scanner import detect_sql_injection

class TestDetectSQLInjection(unittest.TestCase):
    def test_sql_injection_detected(self):
        # File PCAP dengan payload SQL injection
        test_file = 'sample/(exported) sql.pcapng'
        result = detect_sql_injection(test_file)

        # Verifikasi hasilnya
        self.assertGreaterEqual(result['number_of_detected'], 1)
        self.assertGreaterEqual(len(result['details']), 1)

    def test_no_sql_injection_detected(self):
        # File PCAP tanpa payload SQL injection
        test_file = 'sample/(exported) no action.pcapng'
        result = detect_sql_injection(test_file)

        # Verifikasi hasilnya
        self.assertEqual(result['number_of_detected'], 0)
        self.assertEqual(len(result['details']), 0)

if __name__ == '__main__':
    unittest.main()
