from DNSclasses import *
from DNScache import *
import struct
import socket
import threading


class Listener(object):
    def __init__(self, dns_cache):
        self.dns_cache = dns_cache
        self.thread = threading.Thread(target=self.listening_thread)

    def startListening(self):
        try:
            self.thread.start()
        except:
            print("Eroare la pornirea thread-ului")

    def listening_thread(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('', MDNS_PORT))

        while 1:
            data, addr = s.recvfrom(1024)
            magic_key, name_length, target_length = struct.unpack("!7sHH", data)
            if magic_key.decode() == "fnf327h":
                data, addr = s.recvfrom(1024)
                entry = unpackData(data, name_length, target_length)
                self.dns_cache.add(entry)


def packData(entry: DNSService):
    """Packing data"""
    print("Data packed: ")
    print(entry.name + '.' + entry.service + '.' + entry.protocol + '.local')
    print(str(entry.ttl) + " " + entry.clazz + " " + entry.type + " 0 0 " + str(entry.port) + " " + entry.target)
    b_name = bytes(entry.name + '.' + entry.service + '.' + entry.protocol + '.local', 'utf-8')
    b_class = bytes(entry.clazz, 'utf-8')
    b_type = bytes(entry.type, 'utf-8')
    b_target = bytes(entry.target, 'utf-8')

    data = struct.pack("%dsH2s3sHHH%ds" % (len(b_name), len(b_target)),
                       b_name, entry.ttl, b_class, b_type, 0, 0, entry.port, b_target)

    return data, len(b_name), len(b_target)


def unpackData(data, name_length, target_length):
    """Unpacking data"""
    size = struct.calcsize("%dsH2s3sHHH%ds" % (name_length, target_length))

    (name, ttl, clazz, type, priority, weight, port, target,) = struct.unpack(
        "%dsH2s3sHHH%ds" % (name_length, target_length), data[:size])

    print("\nData unpacked:")
    print(name.decode())
    print(str(ttl) + " " + clazz.decode() + " " + type.decode() + " " + str(priority) + " " + str(weight) + " " +
          str(port) + " " + target.decode())

    array = name.decode().split(".")
    name = array[0]
    service = array[1]
    protocol = array[2]
    clazz = clazz.decode()
    type = type.decode()
    target = target.decode()
    entry = DNSService(name, service, protocol, ttl, clazz, type, priority, weight, port, target)
    return entry


class Zeroconfig(object):
    def __init__(self, dns_cache):
        self.dns_cache = dns_cache

    def registerService(self, entry):
        if isinstance(entry, DNSText):
            pass
        if isinstance(entry, DNSService):
            data, name_length, target_length = packData(entry)
            if entry.protocol == "_udp":
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('', 0))
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

                magic_key = bytes("fnf327h", 'utf-8')
                data_length = struct.pack("!7sHH", magic_key, name_length, target_length)
                s.sendto(data_length, ('<broadcast>', MDNS_PORT))
                s.sendto(data, ('<broadcast>', MDNS_PORT))
                print("\nsent service announcement")

            elif entry.protocol == "_tcp":
                pass

    def unregisterService(self, entry):
        if isinstance(entry, DNSText):
            pass
        if isinstance(entry, DNSService):
            print(entry)
            self.dns_cache.remove(entry)

    def checkService(self, service):
        pass
