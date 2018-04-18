"""
This is the (unofficial) Python API for dnsdumpster.com Website.
Using this code, you can retrieve subdomains

"""
import requests
import re
from bs4 import BeautifulSoup


class DNSDumpsterAPI(object):

    """
        DNSDumpsterAPI Main Handler
    """

    _instance = None
    _verbose = False

    def __init__(self, arg=None):
        pass

    def __new__(cls, *args, **kwargs):
        """
            __new__ builtin
        """
        if not cls._instance:
            cls._instance = super(DNSDumpsterAPI, cls).__new__(
                cls, *args, **kwargs)
            if (args and args[0] and args[0]['verbose']):
                cls._verbose = True
        return cls._instance

    def display_message(self, s):
        if (self._verbose):
            print '[verbose] %s' % s

    def search(self, domain):
        url = "https://dnsdumpster.com/"
        s = requests.session()

        req = s.get(url)
        soup = BeautifulSoup(req.content)
        csrf_middleware = soup.findAll('input', attrs={'name': 'csrfmiddlewaretoken'})[0]['value']
        self.display_message('Retrieved token: %s' % csrf_middleware)

        cookies = {'csrftoken': csrf_middleware}
        headers = {'Referer': 'https://dnsdumpster.com/'}
        data = {'csrfmiddlewaretoken': csrf_middleware, 'targetip': domain}
        req = s.post(url, cookies=cookies, data=data, headers=headers)
        #pattern = r'([a-z1-9\.\-]+)\.%s' % (domain.replace('.', '\.'))
        #print pattern
        pattern = r'([\w\-][\w\-\.]+)\.%s' % (domain.replace('.', '\.'))
        
        self.display_message('Retrieving all subdomains')
        res = re.findall(pattern, req.content)
        return list(set(res))