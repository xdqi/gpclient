#!/usr/bin/env python3
import logging
import requests
from lxml import etree
from client import GlobalProtectException

class Portal(object):
    L = logging.getLogger('GlobalProtectClient')

    def __init__(self, server: str):
        self.headers = {'User-Agent': 'PAN GlobalProtect'}
        self.verify = False

        if server.startswith('https://'):
            self.server = server
        else:
            self.server = 'https://' + server

        self.auth_cookie = None
        self.username = None
        self.password = None

    def pre_login(self):
        req = requests.post(url=self.server + '/global-protect/prelogin.esp',
                            headers=self.headers,
                            verify=self.verify)
        if req.status_code == 200:
            pass
        else:
            raise GlobalProtectException('Cannot process pre-login to %s'
                                         % self.server)
        self.L.debug(req.text)

    def get_config(self, username: str, password: str):
        self.username = username
        self.password = password
        data = {
            'inputStr': '',
            'clientos': 'Windows\x00',
            'ok': 'Login',
            'portal-prelogonuserauthcookie': 'empty',
            'portal-userauthcookie': 'empty',
            'clientVer': '4100',
            'user': self.username,
            'passwd': self.password,
        }
        req = requests.post(url=self.server + '/global-protect/getconfig.esp',
                            headers=self.headers,
                            data=data,
                            verify=self.verify)
        result = etree.fromstring(req.content)
        self.L.debug(repr(req.text))
        auth_cookies = result.xpath('/policy/userauthcookie')
        if auth_cookies:
            self.auth_cookie = auth_cookies[0]
        else:
            raise GlobalProtectException("User not authorized")
        users = []
        for i in result.xpath('/policy/gateways/external/list/entry'):
            users.append(Gateway(i, self))
        return users
