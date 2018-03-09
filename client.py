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

import socket
import sys

import _thread

from protocol import DATA
from protocol import ENCODING
from protocol import FILEINFO
from protocol import FILENAME
from protocol import FILESIZE
from protocol import Frame
from protocol import FRAMETYPE
from protocol import OFFSET
from protocol import PAYLOAD
from protocol import PORTLENGTH
from protocol import REQUEST
from protocol import UUID


class FileReceiver(object):
    def __init__(self, ip_address, udp_port, timeout, sender_address):
        self.ip_address = ip_address
        self.udp_port = udp_port
        self.timeout = timeout
        self.file_transfer_complete = False
        self.total_bytes_received = 0
        self.file_uid = None
        self.file_name = None
        self.file_size = 0
        self.sender_address = sender_address

    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((self.ip_address, self.udp_port))
        s.settimeout(self.timeout)
        while True:
            try:
                packet, sender_addr = s.recvfrom(4096)
                self.process_packet(packet, sender_addr)
            except socket.timeout:
                break
            if self.file_transfer_complete:
                break

        if self.file_transfer_complete:
            print("Received {} bytes for file {}"
                  .format(self.total_bytes_received, self.file_name))
            return

        print("Timed out waiting for file packets. "
              "File transfered not complete.")

    def process_fileinfo(self, packet):
        _filename = packet[FILENAME]
        self.file_name = str(_filename, 'utf_8')
        self.file_uid = packet[UUID]
        self.file_size = int.from_bytes(packet[FILESIZE], ENCODING)
        with open(self.file_name, 'wb') as f:
            f.seek(self.file_size - 1)
            f.write(bytes(1))

    def process_data(self, packet):
        if packet[UUID] == self.file_uid:
            offset = int.from_bytes(packet[OFFSET], ENCODING)
            payload = packet[PAYLOAD]
            with open(self.file_name, 'wb') as f:
                f.seek(offset)
                f.write(payload)
            self.total_bytes_received += len(payload)
            if self.total_bytes_received >= self.file_size:
                self.file_transfer_complete = True

    def process_packet(self, packet, sender_address):
        packet_type = int.from_bytes(packet[FRAMETYPE], ENCODING)
        if sender_address is not self.sender_address:
            return
        if packet_type == FILEINFO and not self.file_uid:
            self.process_fileinfo(packet)
        elif packet_type == DATA:
            self.process_data(packet)


class Client(object):
    def __init__(self, server_ip, server_udp_port, receive_udp_port, timeout):
        self.server_ip = server_ip
        self.server_udp_port = server_udp_port
        self.receive_udp_port = receive_udp_port
        self.timeout = timeout

    def start_receiving_packets(self):
        file_receiver = FileReceiver('127.0.0.1', self.receive_udp_port,
                                     self.timeout, self.server_ip)
        file_receiver.run()

    def send_request(self):
        packet = Frame(REQUEST,
                       payload=self.server_udp_port.to_bytes(PORTLENGTH,
                                                             ENCODING)
                       )
        packet.sendto(self.server_ip, self.server_udp_port)


def main():
    client = Client(sys.argv[1], sys.argv[2], sys.argv[2], 60)
    _thread.start_new_thread(client.start_receiving_packets, ())
    client.send_request()


if __name__ == "__main__":
    main()
