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

import logging
import portal
from portal import *


class GlobalProtectException(Exception):
    pass


    USER = ''
    PASS = ''
    SERVER = 'vpn.xxxx.edu'
def main():
    logging.basicConfig(format='%(asctime)s %(levelno)s\t%(funcName)s: %(message)s')

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


if __name__ == '__main__':
    main()
