import unittest
from unittest.mock import patch, MagicMock
from portscanner import scanHost, network_scan, vulnerability_messages

class TestNetworkScan(unittest.TestCase):
    
    @patch('nmap.PortScanner')
    def test_scanHost_open_ports(self, MockPortScanner):
        mock_scanner = MagicMock()
        MockPortScanner.return_value = mock_scanner
        
        mock_scanner.scan.return_value = None
        mock_scanner.__getitem__.return_value = {
            'tcp': {
                80: {'state': 'open', 'name': 'http', 'reason': 'syn-ack', 'product': 'Apache', 'version': '2.4.29', 'extrainfo': 'unix', 'conf': 10}
            }
        }

        result = scanHost('192.168.1.1', 80, 80)

        self.assertEqual(result['type'], "Scan Host")
        self.assertEqual(result['ip_address'], '192.168.1.1')
        self.assertEqual(len(result['open_ports']), 1)
        self.assertEqual(result['open_ports'][0]['port'], 80)
        self.assertEqual(result['open_ports'][0]['state'], 'open')
        self.assertEqual(result['open_ports'][0]['name'], 'http')
        self.assertEqual(result['open_ports'][0]['message'], vulnerability_messages[80])

    @patch('nmap.PortScanner')
    def test_scanHost_no_open_ports(self, MockPortScanner):

        mock_scanner = MagicMock()
        MockPortScanner.return_value = mock_scanner
        
        mock_scanner.scan.return_value = None
        mock_scanner.__getitem__.return_value = {
            'tcp': {}
        }

        result = scanHost('192.168.1.1', 80, 80)

        self.assertEqual(result['type'], "Scan Host")
        self.assertEqual(result['ip_address'], '192.168.1.1')
        self.assertEqual(len(result['open_ports']), 0)


    # @patch('scapy.sendrecv.srp')
    # def test_network_scan_two_devices(self, mock_srp):
    #     # Mock the srp function to simulate two devices
    #     mock_srp.return_value = [
    #         (
    #             MagicMock(),  # Sent packet (mocked, not used in function)
    #             MagicMock(psrc="192.168.1.2", hwsrc="00:11:22:33:44:55")
    #         ),
    #         (
    #             MagicMock(),  # Sent packet (mocked, not used in function)
    #             MagicMock(psrc="192.168.1.3", hwsrc="66:77:88:99:AA:BB")
    #         )
    #     ], None  # srp returns a tuple (results, unanswered_packets)

    #     # Call the function
    #     result = network_scan('192.168.1.0/24')

    #     # Assertions
    #     self.assertEqual(result['type'], "Pemindaian Subnet")
    #     self.assertEqual(result['subnet'], '192.168.1.0/24')
    #     self.assertEqual(result['number_of_devices'], 2)
    #     self.assertEqual(len(result['available_devices']), 2)

    #     # Check the returned devices
    #     self.assertIn(('192.168.1.2', '00:11:22:33:44:55'), result['available_devices'])
    #     self.assertIn(('192.168.1.3', '66:77:88:99:AA:BB'), result['available_devices'])



    # @patch('scapy.sendrecv.srp')
    # def test_network_scan_no_devices(self, mock_srp):
    #     mock_result = []
    #     mock_srp.return_value = mock_result
        
    #     result = network_scan('192.168.1.0/24')

    #     self.assertEqual(result['type'], "Pemindaian Subnet")
    #     self.assertEqual(result['subnet'], '192.168.1.0/24')
    #     self.assertEqual(result['number_of_devices'], 0)
    #     self.assertEqual(len(result['available_devices']), 0)

if __name__ == '__main__':
    unittest.main()
