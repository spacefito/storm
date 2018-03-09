# Copyright 2018 Adolfo Duarte
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import socket

# constants:


ENCODING = 'little'

# frame types
EMPTY = 0
REQUEST = 1
FILEINFO = 2
DATA = 3

# header
FRAMETYPELENGTH = 1
UUIDLENGTH = 16
FILESIZELENGTH = 8
OFFSETLENGTH = 8
PORTLENGTH = 2

HEADERLENGTH = FRAMETYPELENGTH + UUIDLENGTH + FILESIZELENGTH

# frame topology
FTSTART = 0
FTEND = FTSTART + FRAMETYPELENGTH
FRAMETYPE = slice(FTSTART, FTEND)

UUIDEND = FTEND + UUIDLENGTH
UUID = slice(FTEND, UUIDEND)

FSEND = UUIDEND + FILESIZELENGTH
FILESIZE = slice(UUIDEND, FSEND)

OFFSETEND = HEADERLENGTH + OFFSETLENGTH
OFFSET = slice(HEADERLENGTH, OFFSETEND)

FILENAME = slice(HEADERLENGTH, None, None)

PAYLOAD = slice(OFFSETEND, None, None)

PORT = slice(HEADERLENGTH, PORTLENGTH)


class Frame(object):

    def __init__(self, frame_type, file_uid=None, file_size=0, payload=None):

        self.frame_type = frame_type.to_bytes(FRAMETYPELENGTH, ENCODING)
        if file_uid:
            self.file_uid = file_uid.bytes
        else:
            self.file_uid = bytearray(UUIDLENGTH)

        self.file_size = file_size.to_bytes(FILESIZELENGTH, ENCODING)
        if payload:
            self.payload = payload
        else:
            self.payload = bytearray()

    @property
    def header(self):
        return self.frame_type + self.file_uid + self.file_size

    def serialize(self):
        return self.header + self.payload

    def sendto(self, ip_address, udp_port):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        message = self.serialize()
        s.sendto(message, (ip_address, udp_port))
        s.close()
