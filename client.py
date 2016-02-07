#!/usr/bin/env python3
#
# GlobalProtect Client
# Copyright (C) 2015-2016 Xiaodong Qi
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
import ssl
import binascii

import logging
logging.basicConfig(format='%(asctime)s %(levelno)s\t%(funcName)s: %(message)s')
logger = logging.getLogger('GlobalProtectClient')
# logger.setLevel(logging.DEBUG)


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
            'clientVer': '4100'
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
            'app-version': '2.3.2-7',
            'protocol-version': 'p1',
            'clientos': 'Windows',
            'enc-algo': 'aes-256-gcm,aes-128-gcm,aes-128-cbc,',
            'hmac-algo': 'sha1,'
        }
        req = requests.post(url=self.server + '/ssl-vpn/getconfig.esp',
                            headers=self.headers,
                            data=data,
                            verify=self.verify)
        logger.debug(repr(req.text))
        result = etree.fromstring(req.content)
        return Connection(
            gw_address=result.xpath('/response/gw-address')[0].text,
            udp_port=int(result.xpath('/response/ipsec/udp-port')[0].text),
            ip_address=result.xpath('/response/ip-address')[0].text,
            netmask=result.xpath('/response/netmask')[0].text,
            default_gateway=result.xpath('/response/default-gateway')[0].text,
            dns=[item.text for item in result.xpath('/response/dns/member')],
            access_routes=[item.text for item in result.xpath('/response/access-routes/member')],
            enc_algo=result.xpath('/response/ipsec/enc-algo')[0].text,
            hmac_algo=result.xpath('/response/ipsec/hmac-algo')[0].text,
            c2s_spi=result.xpath('/response/ipsec/c2s-spi')[0].text,
            akey_c2s=binascii.unhexlify(result.xpath('/response/ipsec/akey-c2s/val')[0].text),
            ekey_c2s=binascii.unhexlify(result.xpath('/response/ipsec/ekey-c2s/val')[0].text),
            s2c_spi=result.xpath('/response/ipsec/s2c-spi')[0].text,
            akey_s2c=binascii.unhexlify(result.xpath('/response/ipsec/akey-s2c/val')[0].text),
            ekey_s2c=binascii.unhexlify(result.xpath('/response/ipsec/ekey-s2c/val')[0].text),
        )

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

        c = 'GET /ssl-tunnel-connect.sslvpn?user=%s&authcookie=%s HTTP/1.1\r\n\r\n' % (
            self.portal.username, self.auth_cookie)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = ssl.wrap_socket(sock)
        ssl_sock.connect((self.server_name, 443))
        ssl_sock.send(c.encode('utf-8'))
        result = ssl_sock.recv(1024)
        logger.debug(result.decode('utf-8'))
        ssl_sock.close()

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


class Connection(object):
    def __init__(self,
                 gw_address: str,
                 udp_port: int,
                 ip_address: str,
                 netmask: str,
                 default_gateway: str,
                 dns: list,
                 access_routes: list,
                 enc_algo: str,
                 hmac_algo: str,
                 c2s_spi: int,
                 s2c_spi: int,
                 akey_s2c: bytes,
                 ekey_s2c: bytes,
                 akey_c2s: bytes,
                 ekey_c2s: bytes
                 ):
        self.algorithms_list = {
            'aes128': 'AES-128-CBC (RFC 3602)',
            'sha1': 'HMAC-SHA-1-96 (RFC 2404)'
        }
        self.algorithms = dict(
            encryption=self.algorithms_list[enc_algo],
            authentication=self.algorithms_list[hmac_algo]
        )
        self.client = dict(
            encryption_key=ekey_c2s,
            authentication_key=akey_c2s,
            spi=c2s_spi
        )
        self.server = dict(
            encryption_key=ekey_s2c,
            authentication_key=akey_s2c,
            spi=s2c_spi
        )
        self.gateway_ip = gw_address
        self.port = udp_port
        self.network = dict(
            ip=ip_address,
            netmask=netmask,
            gateway=default_gateway,
            dns=dns.copy(),
            routes=access_routes.copy()
        )

    def show_info(self):
        print('Please connect to server via ESP (RFC 4303) tunnel mode: ')
        print('Server address: UDP %s:%s' % (self.gateway_ip, self.port))
        print('Algorithms used in connection:')
        print('Encryption:', self.algorithms['encryption'])
        print('Authentication:', self.algorithms['authentication'])
        print()
        print('Keys used in connection:')
        print('Client:')
        print('Encryption:', binascii.hexlify(self.client['encryption_key']))
        print('Authentication:', binascii.hexlify(self.client['authentication_key']))
        print('Server:')
        print('Encryption:', binascii.hexlify(self.server['encryption_key']))
        print('Authentication:', binascii.hexlify(self.server['authentication_key']))
        print()
        print('Network information of new network card:')
        print('IP address:', self.network['ip'])
        print('Network mask:', self.network['netmask'])
        print('Default gateway:', self.network['gateway'])
        print('DNS:', ', '.join(self.network['dns']))
        print('Routes:', ', '.join(self.network['routes']), 'via default gateway')

if __name__ == '__main__':
    USER = ''
    PASS = ''
    SERVER = 'vpn.xxxx.edu'

    # Connect to center portal
    p = Portal(SERVER)
    gateways = p.get_config(USER, PASS)
    # Select one of gateways
    preferred_gateway = gateways[0]

    # Login onto the gateway
    preferred_gateway.login()

    # Get config from gateway
    conn = preferred_gateway.get_config()
    conn.show_info()

    # Log out from gateway
    preferred_gateway.logout()
