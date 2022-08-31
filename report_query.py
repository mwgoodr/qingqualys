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
import getpass
import re

base_url = 'qualysguard.qg4.apps.qualys.com'

class QualysSession:
    def __init__(self, endpoint, auth):
        self.endpoint = endpoint
        self.auth = auth
        self.session_token = ""

    def open(self, url, auth, stream='False'):
        with requests.get(url=url, auth=auth, stream=stream) as r:
            session_token = re.split('=|;',r.headers['Set-Cookie'])[1]
        auth = []
        self.session_token = session_token
        return self.session_token


class QualysScanList(QualysSession):
    def __init__(self, session_token, endpoint):
        super().__init__(session_token, endpoint)
        self.session_token = session_token
        self.endpoint = f'{super().endpoint}scan/'
        self.payload = {"action": "list"}


def create_session():
    """Maybe this should return a QualysSession class"""

    username = getpass.getpass("Username: ")
    password = getpass.getpass("Password: ")
    auth = HTTPBasicAuth(username, password)
    url = f'https://{base_url}/api/2.0/fo/session/'
    global session

    session = QualysSession(url, auth)
    session.open(url, auth)

    return session

    # Here's the non-forced-class-object method that works just fine:
    # global session_token
    # url = f'https://{base_url}/api/2.0/fo/session/'
    # with requests.get(url=url, auth=auth) as r:
    #     session_token = re.split('=|;',r.headers['Set-Cookie'])[1]

    # # Clear creds from memory
    # auth = ''
    # # Return session_token for future requests
    # return session_token

def connectivity_check():
    uri = f'https://{base_url}/msp/user_list.php'
    headers = {
        'Content-Type': 'text/xml',
        'Accept': 'text/xml'
        }
    r = requests.post(uri, headers=headers, auth=auth)
    print(r)

create_session()
print(f'Session Token: {session.session_token}')
# connectivity_check()
