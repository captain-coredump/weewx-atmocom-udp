# installer for the atmocom-udp driver
# Copyright 2017-2019 Arthur Emerson, vreihen@yahoo.com
# Distributed under the terms of the GNU Public License (GPLv3)

from setup import ExtensionInstaller

def loader():
    return AtmocomUDPInstaller()

class AtmocomUDPInstaller(ExtensionInstaller):
    def __init__(self):
        super(AtmocomUDPInstaller, self).__init__(
            version="1.0",
            name='atmocomudp',
            description='Capture data from Atmocom interceptor via UDP broadcast packets of Weather Underground updates',
            author="Arthur Emerson",
            author_email="vreihen@yahoo.com",
            files=[('bin/user', ['bin/user/atmocomudp.py'])]
            )

