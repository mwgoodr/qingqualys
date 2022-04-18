#!/usr/bin/python3

##################################################
#
#   Qualys scan list query / result download utility
#     following the Extract, Transform, Load
#     methodology to populate a local DB
#
##################################################

import requests
import getpass
import sys
import xml.etree.ElementTree as ET
from requests.auth import HTTPBasicAuth

base_url = 'qualysguard.qg4.apps.qualys.com'

def connectivity_check():
    uri = f'https://{base_url}/msp/user_list.php'
    headers = {
        'Content-Type': 'text/xml',
        'Accept': 'text/xml'
        }
    r = requests.post(uri, headers=headers, auth=auth)
    print(r)

# connectivity_check()

def fetch_scan_list(targets=[], state='Finished', type='Scheduled', show_last=0):
    """Fetches scans matching filters defined by input"""

    uri = f'https://{base_url}/api/2.0/fo/scan/'
    payload = {
        "action": "list",
        "state": state,
        "target": targets,
        "show_last": 0
        # "type": type
    }
    headers = {
        "X-Requested-With": "qingqualys v0.0.1"
    }

    r = requests.post(uri, data=payload, headers=headers, auth=auth)

    try:
        r.status_code == 200
    except BaseException:
        print(f'Scan List request failed with status code {r.status_code}')

    # Parse response content into an ElementTree Element
    tree = ET.fromstring(r.content)

    scan_refs = {}
    for scan in list(tree.iter('SCAN')):
        # Iterate through SCAN objects, dumping REF and TITLE into key/value
        # pairs. Should this instead instantiate a class? Who knows.
        scan_refs[scan[0].text] = scan[2].text

    return scan_refs

def fetch_scan_results(scan_ref, outfile):
    """Accepts REF value from scan list query, fetches results in CSV format"""

    uri = f'https://{base_url}/api/2.0/fo/scan/'
    payload = {
        "action": "fetch",
        "scan_ref": scan_ref,
    }
    headers = {
        "X-Requested-With": "qingqualys v0.0.1"
    }

    try:
        with open(outfile, 'a', newline='') as f, \
                requests.post(uri, data=payload, headers = headers, auth=auth,
                              stream=True) as r:
                f.write(r.text)
    except BaseException as err:
        print(f'Error received while fetching results. The error returned was {err}')


def main():
    opts = [opt for opt in sys.argv[1:] if opt.startswith("-")]
    args = [arg for arg in sys.argv[1:] if not arg.startswith("-")]

    if "-t" in opts:
        # fetch_scan_list(targets=whatever follows -t)
        # Valid options: One or more IPs/ranges, comma separated.
        # Ranges take form: '192.168.1.-192.168.1.254'
        targets = args[0]
        outfile = args[1]
    else:
        targets = []
        outfile = args[0]

    print(f'Querying scan history for {targets}, writing to {outfile}...')
    scan_refs = fetch_scan_list(targets=targets)

    try:
        print(f'Fetched {len(scan_refs)} scans.')
        print(list(scan_refs))
        print(f'Pulling results for {list(scan_refs)[0]}...')

        # Grab a single scan while testing.
        fetch_scan_results(list(scan_refs)[0], outfile)

    except IndexError:
        print(f'No results returned for provided filters')

    # for scan_ref in scan_refs:
    #     print(f'Pulling scan data for {scan_ref}...')
    #     fetch_scan_results(scan_ref)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} [-t] [192.168.1.1 | 192.168.1.1-192.168.1.254] out-file.csv')
        print(f'Target selection can be IP, IP range, or comma-separated list of multiple IPs/ranges')
        exit()

    username = getpass.getpass("Username: ")
    password = getpass.getpass("Password: ")
    auth = HTTPBasicAuth(username, password)

    main()
