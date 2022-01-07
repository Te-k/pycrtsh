# Pycrtsh

![PyPI](https://img.shields.io/pypi/v/pycrtsh)
![PyPI - Downloads](https://img.shields.io/pypi/dm/pycrtsh)
![GitHub](https://img.shields.io/github/license/te-k/pycrtsh)

Python 3 library to request https://crt.sh/

## Install

To install, either download the code and install it manually :
```bash
git clone git@github.com:Te-k/pycrtsh.git
cd pycrtsh
pip install .
```

Or install it directly from [PyPi](https://pypi.org/project/pycrtsh/) : `pip install pycrtsh`

## CLI

```
$ certsh domain github.com
157394275       2017-06-19T00:00:00     2017-06-19T00:00:00     C=US, O=DigiCert Inc, CN=DigiCert ECC Secure Server CA
157394064       2017-06-19T00:00:00     2017-06-19T00:00:00     C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 High Assurance Server CA
146290136       2017-05-30T00:00:00     2017-05-25T00:00:00     C=BE, O=GlobalSign nv-sa, CN=GlobalSign Organization Validation CA - SHA256 - G2
110799854       2017-03-31T00:00:00     2017-03-23T00:00:00     C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 High Assurance Server CA
110109609       2017-03-29T00:00:00     2017-03-20T00:00:00     C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 High Assurance Server CA
108108576       2017-03-23T00:00:00     2017-03-23T00:00:00     C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 High Assurance Server CA
107288158       2017-03-21T00:00:00     2017-03-20T00:00:00     C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 High Assurance Server CA
[SNIP]

$ certsh cert 1357978
{
    "cert": {
        "extensions": {
            "alternative_names": [
                "*.github.com",
                "github.com"
            ],
            "authority_information_access": {
                "CA Issuers": "URI:http://cacerts.digicert.com/DigiCertHighAssuranceCA-3.crt",
                "OCSP": "URI:http://ocsp.digicert.com"
            },
            "authority_key_identifier": "50EA7389DB29FB108F9EE50120D4DE79994883F7",
            "basic_constraints": false,
            "crl_distribution": {
                "url": "http://crl3.digicert.com/ca3-g18.crl"
            },
            "extended_key_usage": {
                "usage": [
                    "TLS Web Server Authentication",
                    "TLS Web Client Authentication"
                ]
            },
            "key_usage": {
                "critical": true,
                "usage": [
                    "Digital Signature",
                    "Key Encipherment"
                ]
            },
            "subject_key_identifier": "BD0E3B9747B4967C3769706F79EB34B215293F5F"
        },
        "id": "1357978",
        "issuer": {
            "commonName": "DigiCert High Assurance CA-3",
            "countryName": "US",
            "id": "29",
            "organizationName": "DigiCert Inc",
            "organizationalUnitName": "www.digicert.com"
        },
        "not_after": "2014-02-05T12:00:00+00:00",
        "not_before": "2013-01-28T00:00:00+00:00",
        "publickey": {
            "algorithm": "rsaEncryption",
            "exponent": "65537",
            "modulus": "00d1f7c403dd3f82cd4e80c6f53c3ac79d694d10fd2dd166487a7f01e049f310336915b00fae14d75f40a62d671be136498509efaff270d27511dcee830b87207ecdf3fc3bb56efc5c3633aa7b7588cc67f3b6c28cf551700958d2ed52a46a4636c78d92aef0b85388a9ecf517b04b09fcb57c0c5d5eec59c86ed6983302b6832c258dff8ef2eb4f43f01bc7dde659a043cd95182d3a0906f1bf9dbbe93adc82b2f01204157352d0f4d44ddae38f7393f5a2d75f235ba0d4152a8e45150345ba0ba58914ff93461352c773662c1a99c12eaf540c6a77fbe989d949397ec3f39705717372190b0eac9e502f3df7e1f03fe08d06857e1e920847c053887e0a6417a7",
            "sha256": "664972c80a1624ee99d0b6bdcf4e8624abda3ecc49dcaf283a3b958daf28eac7",
            "size": 2048
        },
        "serial": "0eada97535df71387222e9cc45b026da",
        "sha1": "0792C0A4E7123A199BAD31BB0A93A2328146C24A",
        "sha256": "8216887A031C3A28FF7A9ECF18815CEA5016A0FF09F72D4EBECFDF3AA4CCD3B1",
        "signature": "a6afbb63af12d1d0777c7708593395798b8972b8f522f3fd8e86cd877fd6f5221ae1f0a33b0d08c0d3113f62b013a0603079d299b3d8bb1ad76af03fb005f1562123a0146e6b9817c1ce297b603aa7d6edfbabf32665c52e5a43bd8d3c534cbf13ad4a461389e0ffbbcc32cb586bb412fe0cf8a29a49663472123e9d2225576779f8b888a9c0abc55e44d86cf1be6cc5e5a91abc3d0be11bc1cfdcb8cb49b9484c955c7e6927ae9afa92d3f9c312442f75e61a10ce0e860f3a06344386d2869ae6e8424b724201c1493fc15fbdd1b59e6789fb1bcd7a502701e5f6837a473342c9ca021245d74ed5551d46ca7d9da55c3c233e7d6dd30486e02e847423ac9017",
        "signature_algorithm": "sha1WithRSAEncryption",
        "subject": {
            "commonName": "*.github.com",
            "countryName": "US",
            "localityName": "San Francisco",
            "organizationName": "Github, Inc.",
            "stateOrProvinceName": "California"
        },
        "version": "3"
    },
    "found": true
}
```

## Library

```python
from pycrtsh import Crtsh
c = Crtsh()
certs = c.search("github.com")
details = c.get(certs[0]["id"], type="id")
```

## Tests

You can run tests in teh test folder with `python -m unittest`

## Licence

This code is published under MIT license
