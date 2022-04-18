#!/usr/bin/python3

##################################################
#
#   Qualys Knowledgebase query / import utility
#     following the Extract, Transform, Load
#     methodology to populate a local DB
#
##################################################

import requests
from requests.auth import HTTPBasicAuth
import qingqonf

base_url = qingqonf.base_url
auth = HTTPBasicAuth(qingqonf.username, qingqonf.password)

def connectivity_check():
    uri = f'https://{base_url}/msp/user_list.php'
    headers = {
        'Content-Type': 'text/xml',
        'Accept': 'text/xml'
        }
    r = requests.post(uri, headers=headers, auth=auth)
    print(r)

connectivity_check()
