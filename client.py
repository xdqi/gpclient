# GlobalProtect Client
# Copyright (C) 2015 Xiaodong Qi
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import requests
import requests.exceptions
from lxml import etree
import socket

import logging
logging.basicConfig(format='%(asctime)s %(levelno)s\t%(funcName)s: %(message)s')
logger = logging.getLogger('GlobalProtectClient')
logger.setLevel(logging.DEBUG)


class GlobalProtectException(Exception):
    pass


class Portal(object):
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
        logger.debug(req.text)

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
        logger.debug(repr(req.text))
        auth_cookies = result.xpath('/policy/userauthcookie')
        if auth_cookies:
            self.auth_cookie = auth_cookies[0]
        else:
            raise GlobalProtectException("User not authorized")
        users = []
        for i in result.xpath('/policy/gateways/external/list/entry'):
            users.append(Gateway(i, self))
        return users


class Gateway(object):
    def __init__(self, gateway_element, portal: Portal):
        self.headers = {'User-Agent': 'PAN GlobalProtect'}
        self.verify = False

        self.portal = portal
        self.description = gateway_element.xpath('./description')[0].text
        self.server_name = gateway_element.attrib['name']
        self.server = 'https://' + self.server_name

        self.portal_name = None
        self.auth_cookie = None

    def __repr__(self):
        return 'Gateway: %s at %s' % (self.description, hex(id(self)))

    def pre_login(self):
        req = requests.post(url=self.server + '/ssl-vpn/prelogin.esp',
                            headers=self.headers,
                            verify=self.verify)
        if req.status_code == 200:
            pass
        else:
            raise GlobalProtectException('Cannot process pre-login to %s'
                                         % self.server)
        logger.debug(repr(req.text))

    def login(self):
        data = {
            'prot': 'https:',
            'server': self.server_name,
            'inputStr': '',
            'jnlpReady': 'jnlpReady',
            'user': self.portal.username,
            'passwd': self.portal.password,
            'computer': socket.gethostname(),
            'ok': 'Login',
            'direct': 'yes',
            'userauthcookie': self.portal.auth_cookie,
            'clientVer': '4100\x00'
        }
        req = requests.post(url=self.server + '/ssl-vpn/login.esp',
                            headers=self.headers,
                            data=data,
                            verify=self.verify)
        logger.debug(repr(req.text))
        result = etree.fromstring(req.content)
        misc_arguments = result.xpath('/jnlp/application-desc/argument')
        self.auth_cookie = misc_arguments[1].text
        self.portal_name = misc_arguments[3].text

    def get_config(self):
        data = {
            'user': self.portal.username,
            'addr1': '192.168.1.100/24',  # TODO: get all addr/subnet on all eth
            # 'preferred-ip': '10.0.0.1' TODO: save used ip
            'portal': self.portal_name,
            'authcookie': self.auth_cookie,
            'client-type': '1',
            'os-version': 'Microsoft Windows XP Professional Service Pack 3',
            'app-version': '2.1.1-25',
            'protocol-version': 'p1\x00'
        }
        req = requests.post(url=self.server + '/ssl-vpn/getconfig.esp',
                            headers=self.headers,
                            data=data,
                            verify=self.verify)
        logger.debug(repr(req.text))
        print(req.text)
        # TODO: deal with XML

    def start_tunnel(self):
        params = {
            'user': self.portal.username,
            'authcookie': self.auth_cookie
        }
        # TODO: Connect address may change
        try:
            req = requests.get(url=self.server + '/ssl-tunnel-connect.sslvpn',
                               params=params,
                               headers={},
                               verify=self.verify)
        except requests.exceptions.ConnectionError as e:
            print(e)  # TODO: get inner exception

    def logout(self):
        data = {
            'user': self.portal.username,
            'portal': self.portal_name,
            'authcookie': self.auth_cookie,
            'domain': '',
            'computer': socket.gethostname()
        }
        req = requests.post(url=self.server + '/ssl-vpn/logout.esp',
                            headers=self.headers,
                            data=data,
                            verify=self.verify)
        logger.debug(repr(req.text))

if __name__ == '__main__':
    pass
