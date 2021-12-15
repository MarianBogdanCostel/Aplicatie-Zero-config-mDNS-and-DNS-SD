import struct
import socket
import threading

MDNS_ADDR = '127.0.0.1'
MDNS_PORT = 5353
DNS_TTL = 3600

CLASS_IN = "IN"

TYPE_TXT = "TXT"
TYPE_SRV = "SRV"


class UnknownProtocolException(Exception):
    pass


class DNSEntry(object):
    def __init__(self, name, protocol, ttl, clazz, type, priority, weight, port, target):
        self.name = name
        self.protocol = protocol
        self.ttl = ttl
        self.clazz = clazz
        self.type = type
        self.priority = priority
        self.weight = weight
        self.port = port
        self.target = target

    def __eq__(self, other):
        if isinstance(other, DNSEntry):
            #return self.name == other.name and self.type == other.type and self.protocol == other.protocol
            pass
        return 0

    def __ne__(self, other):
        return not self.__eq__(other)


class DNSText(DNSEntry):
    def __init__(self, name, protocol, ttl, clazz, type, priority, weight, port, target, text):
        DNSEntry.__init__(self, name, protocol, ttl, clazz, type, priority, weight, port, target)
        self.text = text

    def __eq__(self, other):
        if isinstance(other, DNSText):
            return self.text == other.text
        return 0


class DNSService(DNSEntry):
    def __init__(self, name, service, protocol, ttl, clazz, type, priority, weight, port, target):
        DNSEntry.__init__(self, name, protocol, ttl, clazz, type, priority, weight, port, target)
        self.service = service

    def __eq__(self, other):
        if isinstance(other, DNSService):
            return self.service == other.service
        return 0


class DNSCache(object):
    def __init__(self):
        self.cache = []

    def add(self, entry):
        self.cache.append(entry)

    def remove(self, entry):
        self.cache.remove(entry)

    def entries(self):
        return self.cache


class DNSQuery(DNSEntry):

    def __init__(self, name, type, protocol, target):
        pass

    def answeredBy(self, record):
        return self.type == record.type and self.name == record.name


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
    print(entry.name + '._' + entry.service + '._' + entry.protocol + '.local')
    print(str(entry.ttl) + " " + entry.clazz + " " + entry.type + " 0 0 " + str(entry.port) + " " + entry.target)
    b_name = bytes(entry.name + '._' + entry.service + '._' + entry.protocol + '.local', 'utf-8')
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
    entry = DNSService("My name", "music", "udp", DNS_TTL, CLASS_IN, "SRV", 0, 0, MDNS_PORT, "music.example.com")
    return entry



class Zeroconfig(object):
    def __init__(self):
        pass

    def registerService(self, entry):
        if isinstance(entry, DNSText):
            pass
        if isinstance(entry, DNSService):
            data, name_length, target_length = packData(entry)
            if entry.protocol == "udp":
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('', 0))
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                my_ip = socket.gethostbyname(socket.gethostname())

                magic_key = bytes("fnf327h", 'utf-8')
                data_length = struct.pack("!7sHH", magic_key, name_length, target_length)
                s.sendto(data_length, ('<broadcast>', MDNS_PORT))
                s.sendto(data, ('<broadcast>', MDNS_PORT))
                print("\nsent service announcement")

            elif entry.protocol == "tcp":
                pass
            else:
                raise UnknownProtocolException

    def unregisterService(self, entry):
        if isinstance(entry, DNSText):
            pass
        if isinstance(entry, DNSService):
            pass

    def checkService(self, service):
        pass
