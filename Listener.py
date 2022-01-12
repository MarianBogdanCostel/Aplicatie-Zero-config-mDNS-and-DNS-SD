from DNSResponse import *
from queryTypes import *


class Listener:
    def __init__(self, zeroconfig):
        self.zeroconfig = zeroconfig
        self.data = None

    def handle_read(self, socket_):
        try:
            data, (addr, port) = socket_.recvfrom(8972)
        except socket.error as err:
            if err.errno == socket.EBADF:
                return
            else:
                raise err
        self.data = data
        message = DNSResponse(data)
        if message.is_query():
            if port == MDNS_PORT:
                self.zeroconfig.handle_query(message, MDNS_ADDR, MDNS_PORT)
        else:
            self.zeroconfig.handle_response(message)
