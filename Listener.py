import socket

from DNSResponse import *
from DNSClasses import *


class Listener:
    def __init__(self, zeroconfig):
        self.zeroconfig = zeroconfig
        self.data = None

    def read_data(self, s):
        try:
            data, (addr, port) = s.recvfrom(8972)
        except socket.error as err:
            if err.errno == socket.EBADF:
                return
            else:
                raise err
        self.data = data
        message = DNSResponse(data)
        if message.is_query():
            if port == MDNS_PORT:
                self.zeroconfig.read_query(message, MDNS_ADDR4, MDNS_PORT)
        else:
            self.zeroconfig.read_response(message)
