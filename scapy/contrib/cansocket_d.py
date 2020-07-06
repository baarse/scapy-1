# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Sebastian Baar <sebastian.baar@gmx.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = Socketcand
# scapy.contrib.status = loads


import socket
from scapy.supersocket import StreamSocket
from scapy.error import Scapy_Exception
from scapy.data import MTU
from scapy.layers.can import *
import re

"""
Socketcand socket
"""

# #########################Socketcand Socket###################################

class Socketcand_Socket(StreamSocket):
    def __init__(self, ip='127.0.0.1', port=6801, liface="vcan0", riface="vcan1"):
        self.ip = ip
        self.port = port
        self.liface = liface
        self.riface = riface

        s = socket.socket()
        s.connect((self.ip, self.port))
        StreamSocket.__init__(self, s)
        start_msg = self.recv(start_msg=True)
        if str(start_msg) != str(b'< hi >'):
            print("Error while starting connection")
        self.start_rawmode()

    def start_rawmode(self):
        super().send("< open vcan0 >".encode(encoding="ascii"))
        msg = self.recv(start_msg=True)
        if str(msg) != str(b'< ok >'):
            print("Error opening vcan0")

        super().send("< rawmode >".encode(encoding="ascii"))
        msg = self.recv(start_msg=True)
        if str(msg) != str(b'< ok >'):
            print("Error starting rawmode")

    def can_to_socketcand(self, p):
        data = (p.data).decode("ascii")
        data_tpl = re.findall('..', data)
        data = ""
        for i in data_tpl:
            data = data + " " + i
        identifier = str(hex(p.identifier))
        length = str(int(len(p.data)/2))

        m = "< send " + identifier + " " + length + " " + data + " >"

        return m.encode(encoding="ascii")

    def socketcand_to_can(self, m):
        m = str(m)
        m = re.split("[<>]", m)
        for i in m:
            if not "frame" in i:
                m.remove(i)
        pkts = []
        for i in m:
            id = i.split()[1]
            id = "0x" + id
            data = i.split()[3].encode(encoding='ascii')
            pkts.append(CAN(identifier=id, data=data))

        return pkts

    def send(self, x):
        if not isinstance(x, CAN):
            raise Scapy_Exception("Please provide a packet class based on "
                                      "CAN")
        super().send(self.can_to_socketcand(x))

    def recv(self, x=MTU, start_msg=False):
        if start_msg:
            return super(Socketcand_Socket, self).recv(x)
        else:
            pkt = super(Socketcand_Socket, self).recv(x)
            return self.socketcand_to_can(pkt)
