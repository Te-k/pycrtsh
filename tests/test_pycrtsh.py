# pycrtsh
# Copyright (c) 2017-2023 Etienne Tek Maynier
# This software is released under the MIT license
# See https://opensource.org/license/mit/
from pycrtsh import Crtsh, CrtshCertificateNotFound


class TestUtils:
    def test_get_id(self):
        crt = Crtsh()
        cert = crt.get("8186392", type="id")
        assert cert["id"] == "8186392"
        assert cert["sha1"] == "B387B1F38800844F5E8FBA0F4442BFB3892BE2A9"
        assert (
            cert["sha256"]
            == "E9AB36315DC9DEBC718086BA341E3F9332A1AE98C5554B71A14E6E39F755BCC4"
        )
        assert cert["serial"] == "00d3fc2747513084672c3739cce9a212c0"

    def test_get_sha1(self):
        crt = Crtsh()
        cert = crt.get("28F97816197AFF182518AA44FEC1A0CE5CB64C8A", type="sha1")
        assert cert["id"] == "52590901"
        assert cert["sha1"] == "28F97816197AFF182518AA44FEC1A0CE5CB64C8A"
        assert (
            cert["sha256"]
            == "9BEA11C976FE014764C1BE56A6F914B5A560317ABD9988393382E5161AA0493C"
        )
        assert cert["serial"] == "5ddfb1da5aa3ed5dbe5a6520650390ef"

    def test_get_sha1_2(self):
        crt = Crtsh()
        cert = crt.get("B387B1F38800844F5E8FBA0F4442BFB3892BE2A9", type="sha1")
        assert cert["id"] == "8186392"
        assert cert["sha1"] == "B387B1F38800844F5E8FBA0F4442BFB3892BE2A9"
        assert (
            cert["sha256"]
            == "E9AB36315DC9DEBC718086BA341E3F9332A1AE98C5554B71A14E6E39F755BCC4"
        )
        assert cert["serial"] == "00d3fc2747513084672c3739cce9a212c0"

    def test_get_parsing_change(self):
        crt = Crtsh()
        cert = crt.get("2380562261", type="id")
        assert cert["id"] == "2380562261"
        assert cert["sha1"] == "AB6165D9DBC24CDED0E20473517E3BC9BD0B6413"
        assert (
            cert["sha256"]
            == "BB79316B4CA1C00AF01B0A201B25417782FB418E284AEC5EF4F0C169D703B2F5"
        )
        assert cert["serial"] == "436071a2"

    def test_get_sha256(self):
        crt = Crtsh()
        cert = crt.get(
            "9BEA11C976FE014764C1BE56A6F914B5A560317ABD9988393382E5161AA0493C",
            type="sha256",
        )
        assert cert["id"] == "52590901"
        assert cert["sha1"] == "28F97816197AFF182518AA44FEC1A0CE5CB64C8A"
        assert (
            cert["sha256"]
            == "9BEA11C976FE014764C1BE56A6F914B5A560317ABD9988393382E5161AA0493C"
        )
        assert cert["serial"] == "5ddfb1da5aa3ed5dbe5a6520650390ef"

    def test_get_parsing(self):
        crt = Crtsh()
        cert = crt.get("253073880", type="id")
        assert cert["subject"]["commonName"] == "citizenlab.ca"
        assert "alternative_names" in cert["extensions"]
        assert len(cert["extensions"]["alternative_names"]) == 2

    def test_get_unknown_id(self):
        crt = Crtsh()
        try:
            crt.get("81863923950", type="id")
            assert False
        except CrtshCertificateNotFound:
            pass

    def test_search_not_found(self):
        crt = Crtsh()
        res = crt.search("domaindoesnotexist.cco")
        assert len(res) == 0

    def test_get_serial_bug(self):
        crt = Crtsh()
        cert = crt.get("146290136")
        assert cert["serial"] == "24d427be1877104b4eef1a85"

    def test_search(self):
        crt = Crtsh()
        res = crt.search("okta.com")
        assert len(res) > 0
