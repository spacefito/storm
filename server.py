#!/usr/bin/env python3
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

import _thread
import socket
import sys
import time
import uuid

import os

from protocol import DATA
from protocol import ENCODING
from protocol import FILEINFO
from protocol import FRAMETYPE
from protocol import FRAMETYPELENGTH
from protocol import Frame
from protocol import OFFSETLENGTH
from protocol import PORT
from protocol import REQUEST


class FileSender(object):

    def __init__(self, filename, ip_address, udp_port, chunk_size=1400):
        self.filename = filename
        self.udp_port = udp_port
        self.ip_address = ip_address
        self.chunk_size = chunk_size
        self.file_uid = uuid.uuid1()
        self.file_size = os.path.getsize(self.filename)

    def file_chunks(self):
        with open(self.filename, 'rb') as f:
            _offset = f.tell()
            _bytes = f.read(self.chunk_size)
            while _bytes:
                yield _offset, _bytes
                _bytes = f.read(self.chunk_size)
                _offset = f.tell()

    def run(self):
        packet = Frame(FILEINFO,
                       file_size=self.file_size,
                       file_uid=self.file_uid,
                       payload=self.filename.encode(encoding='utf_8'))
        packet.sendto(self.ip_address, self.udp_port)

        for offset, chunk in self.file_chunks():
            packet.frame_type = DATA.to_bytes(FRAMETYPELENGTH, ENCODING)
            packet.payload = offset.to_bytes(OFFSETLENGTH, ENCODING) + chunk
            packet.sendto(self.ip_address, self.udp_port)
            print("sent {} bytes to {} port {} of type {} offset {}".format(
                len(packet.payload),
                self.ip_address,
                self.udp_port,
                int.from_bytes(packet.frame_type, ENCODING),
                offset
            )
            )
        print("DONE")


class Server(object):
    def __init__(self, filename, udp_port, lifetime):
        self.filename = filename
        self.udp_port = udp_port
        self.lifetime = lifetime

    def handle_request(self, packet, ip_address):
        packet_type = int.from_bytes(packet[FRAMETYPE], ENCODING)
        if packet_type == REQUEST:
            udp_port = packet[PORT]
            chunk_size = self.get_chunk_size_for(ip_address)
            file_sender = FileSender(self.filename, ip_address,
                                     udp_port, chunk_size=chunk_size)
            file_sender.run()

    @staticmethod
    def get_chunk_size_for(ip_address):
        # To optimize performance, we should calculate the optimal
        # chunk size we should use for a particular client.
        return 1400

    def start_serving_file(self):
        start_time = time.time()

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self.lifetime)
        s.bind(('127.0.0.1', self.udp_port))
        there_is_time_left = True
        while there_is_time_left:
            try:
                data, address = s.recvfrom(4096)
                elapsed_time = time.time() - start_time
                time_left = self.lifetime - elapsed_time
                _thread.start_new_thread(self.handle_request, (data, address))
            except socket.timeout:
                there_is_time_left = False
                continue
            if time_left < 0:
                there_is_time_left = False


def main():
    server = Server(sys.argv[2], 3000, sys.argv[1])
    server.start_serving_file()


if __name__ == "__main__":
    main()
