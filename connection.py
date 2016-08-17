import binascii

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
