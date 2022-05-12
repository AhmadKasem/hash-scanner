import unittest
import hash_scan




class HashTestCase(unittest.TestCase):

    def test_scanner1(self):
        hashCode = 'c83a64d493d248897d5292634571f0a3'
        result = hash_scan.VirusTotal().scanHash(hashCode)
        self.assertEqual(result, 200)

    def test_scanner2(self):
        hashCode = 'd87d19d1daf83936b8f6ebfa92f867d0'
        result = hash_scan.VirusTotal().scanHash(hashCode)
        self.assertEqual(result, 200)

    def test_scanner3(self):
        hashCode = 'c83a81111849ebb3043d8043319e440e'
        result = hash_scan.VirusTotal().scanHash(hashCode)
        self.assertEqual(result, 200)

    def test_scanner4(self):
        hashCode = 'd87d68407f8fc68b203456077d72d0dd'
        result = hash_scan.VirusTotal().scanHash(hashCode)
        self.assertEqual(result, 200)

    def test_scanner5(self):
        hashCode = '1422230751dfdd430ed89bfcd788db53'
        result = hash_scan.VirusTotal().scanHash(hashCode)
        self.assertEqual(result, 200)

    def test_scanner6(self):
        hashCode = '2128b91592655aeafcc9dd13acc262e0'
        result = hash_scan.VirusTotal().scanHash(hashCode)
        self.assertEqual(result, 200)
        

    