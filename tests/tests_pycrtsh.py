import unittest
from pycrtsh import Crtsh, CrtshInvalidRequestType, CrtshCertificateNotFound

class TestUtils(unittest.TestCase):
    def test_get_id(self):
        crt = Crtsh()
        cert = crt.get('8186392', type='id')
        self.assertEqual(cert['id'], '8186392')
        self.assertEqual(cert['sha1'], 'B387B1F38800844F5E8FBA0F4442BFB3892BE2A9')
        self.assertEqual(cert['sha256'], 'E9AB36315DC9DEBC718086BA341E3F9332A1AE98C5554B71A14E6E39F755BCC4')
        self.assertEqual(cert['serial'], '00d3fc2747513084672c3739cce9a212c0')

    def test_get_parsing(self):
        crt = Crtsh()
        cert = crt.get('253073880', type='id')
        self.assertEqual(cert['subject']['commonName'], 'citizenlab.ca')
        self.assertTrue('alternative_names' in cert['extensions'])
        self.assertEqual(len(cert['extensions']['alternative_names']), 2)

    def test_get_unknown_id(self):
        crt = Crtsh()
        try:
            cert = crt.get('81863923950', type='id')
            self.assertTrue(False)
        except CrtshCertificateNotFound:
            pass

    def test_get_sha1(self):
        crt = Crtsh()
        cert = crt.get('B387B1F38800844F5E8FBA0F4442BFB3892BE2A9', type='sha1')
        self.assertEqual(cert['id'], '8186392')
        self.assertEqual(cert['sha1'], 'B387B1F38800844F5E8FBA0F4442BFB3892BE2A9')
        self.assertEqual(cert['sha256'], 'E9AB36315DC9DEBC718086BA341E3F9332A1AE98C5554B71A14E6E39F755BCC4')
        self.assertEqual(cert['serial'], '00d3fc2747513084672c3739cce9a212c0')

    def test_search_not_found(self):
        crt = Crtsh()
        res = crt.search('domaindoesnotexist.cco')
        self.assertEqual(len(res), 0)

    def test_get_serial_bug(self):
        crt = Crtsh()
        cert = crt.get('146290136')
        self.assertEqual(cert['serial'], '24d427be1877104b4eef1a85')

    def test_search(self):
        crt = Crtsh()
        res = crt.search("okta.com")
        self.assertTrue(len(res) > 0)


if __name__ == '__main__':
    unittest.main()

