#!/usr/bin/env python
# pycrtsh
# Copyright (c) 2017-2023 Etienne Tek Maynier
# This software is released under the MIT license
# See https://opensource.org/license/mit/
import re
from typing import Any, Dict, List, Optional

import requests
from bs4 import BeautifulSoup, Tag
from dateutil.parser import parse


class PycrtshException(Exception):
    """
    Main Pycrtsh exception.
    Any exception from the library will raise a subclass of this class.
    """

    pass


class CrtshInvalidRequestType(PycrtshException):
    """This exception is raised if the request is invalid"""

    def __init__(self):
        Exception.__init__(self, "Invalid request type")


class CrtshCertificateNotFound(PycrtshException):
    """Exception raised if a certificate is not found"""

    def __init__(self):
        Exception.__init__(self, "Certificate not found")


class DependenciesNeeded(PycrtshException):
    """Exception raised if dependencies are missing"""

    def __init__(self):
        Exception.__init__(self, "Missing dependencies, please install psycopg2")


class CrtshPlatformDown(PycrtshException):
    """This exception is raised when the platform is down"""

    def __init__(self):
        Exception.__init__(self, "The crt.sh platform is down")


class Crtsh(object):
    """
    Main Crtsh object
    """

    def search(self, query: str, timeout: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Search crt.sh with the given query.
        The query can be a domain or any identity indexed by crt.sh.
        Searching by sha1/sha256 is not supported here as crt.sh returns
        the certificate page directly, use get() for that.

        Args:
            query (str): the crt.sh query
            timeout (int) : optional timeout (default is None)

        Returns:
            list: list of certificates as dictionaries
        """
        certs: List[Dict[str, Any]] = []

        r = requests.get("https://crt.sh/", params={"q": query}, timeout=timeout)
        if not r.ok:
            if r.status_code == 502:
                raise CrtshPlatformDown()
            else:
                raise PycrtshException("Invalid HTTP response {}".format(r.status_code))

        soup = BeautifulSoup(r.text, "lxml")
        table = soup.find("table", {"class": "identities"})
        if table is None:
            return certs

        if not isinstance(table, Tag):
            return certs

        lines = table.find_all("tr", recursive=False)
        if not lines:
            return certs

        # crt.sh reuses the "identities" class for other tables: a query for a
        # sha1/sha256 returns the certificate page, whose first "identities"
        # table lists CT log entries (Timestamp/Entry #/Log Operator/Log URL).
        # Make sure we are looking at the search result table before indexing
        # into the columns.
        headers = [th.get_text(strip=True) for th in lines[0].find_all("th")]
        if not headers or not headers[0].startswith("crt.sh ID"):
            return certs

        nameparser = re.compile('([a-zA-Z]+)=("[^"]+"|[^,]+)')
        for entry in lines[1:]:
            tds = entry.find_all("td")
            if len(tds) < 6:
                continue
            issuer = tds[5].text
            certs.append(
                {
                    "id": int(tds[0].text),
                    "logged_at": None,  # Kept for compatibility with previous versions
                    "not_before": parse(tds[1].text),
                    "not_after": parse(tds[2].text),
                    "name": tds[3].get_text("\n"),
                    "matching_identities": tds[4].get_text("\n").split("\n"),
                    "ca": {
                        "caid": None,  # kept for compatibility with previous versions
                        "name": issuer,
                        "parsed_name": dict(nameparser.findall(issuer)),
                    },
                }
            )

        return certs

    def get(self, query: str, type: str = "sha1") -> Dict[str, Any]:
        """
        Search for a certificate with the given value of the given type

        Args:
            query (str): value of the query, can be either a crtsh id, sha1 or sha256
            type (str): type of the quer, can be ['id', 'sha1', 'sha256']

        Returns:
            Dictionnary with the details of the certificate information

        Raises:
            CrtshInvalidRequestType: if the query type in invalid
            CrtshCertificateNotFound: if the certificate can't be found
        """
        if type not in ["sha1", "sha256", "id"]:
            raise CrtshInvalidRequestType()
        if type == "id":
            r = requests.get("https://crt.sh/", params={"id": query})
        else:
            r = requests.get("https://crt.sh/", params={"q": query})

        if "<BR><BR>Certificate not found </BODY>" in r.text:
            raise CrtshCertificateNotFound()
        if "<BR><BR>Invalid value:" in r.text:
            raise CrtshCertificateNotFound()

        soup = BeautifulSoup(r.text, "lxml")
        table = soup.find_all("table")[1]
        cert = {}
        lines1 = table.find_all("tr", recursive=False)
        if len(lines1) < 6:
            # It means that we are in a research not in a certificate description
            # ie https://crt.sh/?q=sha1
            raise CrtshCertificateNotFound()

        cert["id"] = lines1[0].td.text
        for i in range(3):
            try:
                cert["sha256"] = (
                    lines1[i + 4]
                    .find("th", string="SHA-256")
                    .find_next_sibling("td")
                    .text
                )
                cert["sha1"] = (
                    lines1[i + 4]
                    .find("th", string="SHA-1")
                    .find_next_sibling("td")
                    .text
                )
                break
            except AttributeError:
                pass
        certinfo = str(lines1[i + 5].td)[60:-6].split("<br/>")
        i = 0
        while i < len(certinfo):
            if "Version:" in certinfo[i]:
                cert["version"] = certinfo[i].strip().split("\xa0")[1]
            if "Serial\xa0Number:" in certinfo[i]:
                # Size of serial may change
                ends = certinfo[i][25:].find('"')
                cert["serial"] = certinfo[i][25 : 25 + ends]
            if "Signature\xa0Algorithm:" in certinfo[i]:
                if "signature_algorithm" in cert.keys():
                    signature = ""
                    i += 1
                    while certinfo[i].startswith(
                        "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0"
                    ):
                        signature += certinfo[i][9:]
                        i += 1
                    i -= 1
                    cert["signature"] = signature.replace(":", "")
                else:
                    cert["signature_algorithm"] = certinfo[i].split(":")[1].strip()
            if ">Issuer:</a>" in certinfo[i]:
                cert["issuer"] = {"id": certinfo[i].split('"')[1][6:]}
                i += 1
                while certinfo[i].startswith(
                    "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0"
                ):
                    split = certinfo[i].split("=")
                    cert["issuer"][split[0].strip()] = (
                        split[1].strip().replace("\xa0", " ")
                    )
                    i += 1
                i -= 1

            if "\xa0Not\xa0Before:" in certinfo[i] and "Not\xa0After" in certinfo[i]:
                for param in certinfo[i].split(","):
                    param = param.strip()
                    if "Not\xa0Before:" in param:
                        cert["not_before"] = parse(param[11:].strip())
                    if "Not\xa0After:" in param:
                        cert["not_after"] = parse(param[10:].strip())
            else:
                if "\xa0Not\xa0Before:" in certinfo[i]:
                    cert["not_before"] = parse(certinfo[i][24:])
                if "\xa0Not\xa0After\xa0:" in certinfo[i]:
                    cert["not_after"] = parse(certinfo[i][24:])
            if "\xa0Subject:" in certinfo[i]:
                cert["subject"] = {}
                i += 1
                while certinfo[i].startswith(
                    "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0"
                ):
                    split = certinfo[i].split("=")
                    if len(split) > 1:
                        cert["subject"][split[0].strip()] = (
                            split[1].strip().replace("\xa0", " ")
                        )
                    i += 1
                i -= 1
            if "Subject\xa0Public\xa0Key\xa0Info:</a>" in certinfo[i]:
                cert["publickey"] = {"sha256": certinfo[i].split("=")[2][:64]}
            if "Public\xa0Key\xa0Algorithm" in certinfo[i]:
                cert["publickey"]["algorithm"] = certinfo[i].split(":")[1].strip()
            if "\xa0Public-Key:\xa0(" in certinfo[i]:
                cert["publickey"]["size"] = int(
                    certinfo[i].split("(")[1].split("\xa0")[0]
                )
            if "\xa0Modulus:" in certinfo[i]:
                modulus = ""
                i += 1
                while certinfo[i].startswith(
                    "\xa0\xa0\xa0\xa0\xa0\xa0\xa0"
                    + "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0"
                ):
                    modulus += certinfo[i][20:]
                    i += 1
                cert["publickey"]["modulus"] = modulus.replace(":", "")
                i -= 1
            if "Exponent:" in certinfo[i]:
                cert["publickey"]["exponent"] = certinfo[i][26:].split("\xa0")[0]
            if "X509v3\xa0extensions:" in certinfo[i]:
                cert["extensions"] = {}
            if "\xa0Subject\xa0Alternative\xa0Name:" in certinfo[i]:
                cert["extensions"]["alternative_names"] = []
                i += 1
                while certinfo[i].startswith(
                    "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0DNS:"
                ):
                    cert["extensions"]["alternative_names"].append(
                        certinfo[i][20:].strip()
                    )
                    i += 1
                i -= 1
            if "X509v3\xa0Certificate\xa0Policies:\xa0" in certinfo[i]:
                cert["extensions"]["certificate_policies"] = []
                i += 1
                while certinfo[i].startswith(
                    "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Policy:"
                ):
                    cert["extensions"]["certificate_policies"].append(
                        certinfo[i][23:].strip()
                    )
                    i += 1
                    if certinfo[i].startswith(
                        "\xa0\xa0\xa0\xa0\xa0\xa0\xa0"
                        + "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0CPS:"
                    ):
                        i += 1
                i -= 1
            if "X509v3\xa0Basic\xa0Constraints:\xa0" in certinfo[i]:
                i += 1
                cert["extensions"]["basic_constraints"] = "CA:FALSE" not in certinfo[i]
            if "X509v3\xa0Key\xa0Usage:" in certinfo[i]:
                cert["extensions"]["key_usage"] = {
                    "critical": ("Usage:\xa0critical" in certinfo[i])
                }
                i += 1
                cert["extensions"]["key_usage"]["usage"] = [
                    a.strip().replace("\xa0", " ") for a in certinfo[i].split(",")
                ]
            if (
                "X509v3\xa0CRL\xa0Distribution\xa0Points:" in certinfo[i]
                and "URI:" in certinfo[i]
            ):
                i += 3
                cert["extensions"]["crl_distribution"] = {
                    "url": certinfo[i].split("URI:")[1].strip()
                }
            if "X509v3\xa0Extended\xa0Key\xa0Usage:" in certinfo[i]:
                i += 1
                cert["extensions"]["extended_key_usage"] = {
                    "usage": [
                        a.strip().replace("\xa0", " ") for a in certinfo[i].split(",")
                    ]
                }
            if "X509v3\xa0Authority\xa0Key\xa0Identifier:" in certinfo[i]:
                i += 1
                cert["extensions"]["authority_key_identifier"] = certinfo[i][
                    22:
                ].replace(":", "")
            if "X509v3\xa0Subject\xa0Key\xa0Identifier:" in certinfo[i]:
                i += 1
                cert["extensions"]["subject_key_identifier"] = certinfo[i][16:].replace(
                    ":", ""
                )
            if "Authority\xa0Information\xa0Access:" in certinfo[i]:
                cert["extensions"]["authority_information_access"] = {}
                i += 1
                while certinfo[i].startswith(
                    "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0"
                ):
                    split = certinfo[i].split("\xa0-\xa0")
                    cert["extensions"]["authority_information_access"][
                        split[0].strip().replace("\xa0", " ")
                    ] = split[1].strip()
                    i += 1
                i -= 1
            # Warning : does not parse all the X509 extensions
            i += 1
        return cert

    def psql_query(self, query: str) -> List[Any]:
        """
        PSQL query in crt.sh database

        Args:
            query (str): PSQL query

        Returns:
            list: a list of tupes from the query

        Raises:
            DependenciesNeeded: if psycopg2 isn't installed
        """
        try:
            import psycopg2
        except ImportError:
            raise DependenciesNeeded()

        conn = psycopg2.connect("dbname=certwatch user=guest host=crt.sh")
        conn.set_session(autocommit=True)
        cur = conn.cursor()
        cur.execute(query)
        return cur.fetchall()

    def subdomains(self, domain: str) -> List[str]:
        """
        Get a list of subdomains for a domain based on existing certificates

        Args:
            domain (str): domain name

        Returns:
            list: list of subdomains as strings

        Raises:
            DependenciesNeeded: if psycopg2 isn't installed
        """
        subdomains: List[str] = []
        for entry in self.psql_query(
            """
            select distinct(lower(name_value))
            FROM certificate_and_identities cai
            WHERE plainto_tsquery('{}') @@ identities(cai.CERTIFICATE) AND
                lower(cai.NAME_VALUE) LIKE ('%.{}')
        """.format(domain, domain)
        ):
            if entry[0] not in subdomains and not entry[0].startswith("*."):
                subdomains.append(entry[0])
        return subdomains
