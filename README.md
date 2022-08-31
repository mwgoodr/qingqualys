oops I didn't write a readme for this. Do that. 

But first! I finally (again) get it. Classes store objects or expose functions.
Leave it at that. Don't try to blend them. If it's an object with multiple
methods unrelated to changing the properties *of that object* then you're doing
it wrong. Examples:  

```py
from dataclasses import dataclass

@dataclass
def qualys_conf:
    vmdr_root_uri: str = 'https://qualysguard.gq4.apps.qualys.com/api/2.0/fo'
    vmdr_asset_uri: str
    vmdr_scan_uri: str 
    base_header: dict(?) = {
        'Content-Type': 'text/xml',
        'Accept': 'text/xml'
        'X-Requested-By': 'qualyteeVM v0.0.1'
    }
    session: str
    ...

    def __post_init__(self):
        ...
        self.vmdr_asset_uri = f"{vmdr_root_uri}/asset"
        self.vmdr_scan_uri = f"{vmdr_root_uri}/scan"
        self.creds = HTTPBasicAuth(username,password) # guess I need to figure
        out how to store these in a way accessible to the class
        ...

    def create_session(self, uri=self.uri, auth=self.creds, stream='False'):
        with requests.get(url=self.uri, auth=auth, stream=stream) as r:
            session = re.split('=|;',r.headers['Set-Cookie'])[1]
        auth = [] # clear auth. look into clearstr() to improve this
        self.session = session
        return self.session
        
def risk_calc(risk_score, criticality):
    return risk_score + criticality * 100 % 10

@dataclass
class VMDR_Asset:
    """the dataclass decorator automatically generates __init__"""
    hostid: str
    name: str
    ip: str
    vuln_sev5: int
    vuln_sev4: int
    auth_success: bool
    how_much_do_you_love_it: int = 5 # scale of 1-10, obv. default to 5.
    risk_score: int = 0

    def __post_init__(self): # see if @dataclass can handle this better
    """ assigns attributes dependent on other attributes on instantiation """
        self.risk_score = risk_calc(self.vuln_sev5,self.how_much_...) 

class vmdr_searcher:
    __init__(self,conf):
    """
    Not sure if it works like this but what I'm aiming for is to pass an
    object of type qualys_conf through upon instantiation. If no object is
    passed, a new one will be created.
    """
        self._conf: qualys_conf = qualys_conf # I think _ makes it immutableish
        self.result_count = 0 # to be updated by search functions

    def hostname(self, fqdn):
    """ 
    Writing this function out makes passing an object in at instantiation is
    probably not possible. Likely need to pass in each attribute, as I doubt I
    can get away with this self._config.xxx thing... but I'll google it later.
    """
        uri = self._conf.uri 
        headers = self._conf.base_headers 
        session = self._config.session
        payload = {
            action: 'list',
            dns_hostname: fqdn 
            other_stuff: 'whatever'
        }
        cookie = {'X-Whatever-This-Should-Be': session}

        # not sure if this 'cookie=' thing is right but I'm not googling it for
        # this """PSEUDOCODE"""
        r = requests.post(uri, data=payload, headers=headers, cookie=cookie)
        try:
            r.status_code == 200
        except BaseException:
            print(f'Scan List request failed with status code {r.status_code}')

        assets = do_something_with(r.content)
        self.result_count = len(assets)
        return assets

# Instantiate our base object and then build a session
Qualys = qualys_conf()
Qualys.create_session()

# Instantiate a searcher object
searcher = vmdr_searcher(Qualys.session)

# Search for an asset by hostname
searcher.hostname('OWNER-PC')
```

whoops didn't mean to write that much. 
