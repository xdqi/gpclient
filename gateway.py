import logging
import socket
import requests
import binascii
import ssl
from lxml import etree
from client import GlobalProtectException
from portal import Portal
from portal import Connection


class Gateway(object):
    L = logging.getLogger('Gateway')

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
        self.L.debug(repr(req.text))

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
        self.L.debug(repr(req.text))
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
        self.L.debug(repr(req.text))
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
        c = 'GET /ssl-tunnel-connect.sslvpn?user=%s&authcookie=%s HTTP/1.1\r\n\r\n' % (
            self.portal.username, self.auth_cookie)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = ssl.wrap_socket(sock)
        ssl_sock.connect((self.server_name, 443))
        ssl_sock.send(c.encode('utf-8'))
        result = ssl_sock.recv(1024)
        self.L.debug(repr(result))
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
        self.L.debug(repr(req.text))
