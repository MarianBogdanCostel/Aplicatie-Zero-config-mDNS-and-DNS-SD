import string
import time
import socket
import threading


MDNS_ADDR = '192.168.0.1'
MDNS_PORT = 5353
DNS_PORT = 53
DNS_TTL = 3600

CLASS_IN = "in"

TYPE_TXT = "txt"
TYPE_SRV = "srv"


class DNSEntry(object):
    """DNS entry"""

    def __init__(self, name, type, protocol):
        self.key = name.lower()
        self.name = name
        self.type = type
        self.protocol = protocol
        self.clazz = CLASS_IN

    def __eq__(self, other):
        if isinstance(other, DNSEntry):
            return self.name == other.name and self.type == other.type and self.protocol == other.protocol
        return 0

    def __ne__(self, other):
        return not self.__eq__(other)

    def getName(self):
        return self.name

    def getType(self):
        return self.type

    def getProtocol(self):
        return self.protocol


class DNSText(DNSEntry):
    """DNS text record"""

    def __init__(self, name, type, protocol, text):
        DNSEntry.__init__(self, name, type, protocol)
        self.ttl = DNS_TTL
        self.text = text

    def write(self, out):
        out.writeString(self.text, len(self.text))

    def __eq__(self, other):
        if isinstance(other, DNSText):
            return self.text == other.text
        return 0


class DNSService(DNSEntry):
    """DNS service record"""

    def __init__(self, name, type, protocol, target):
        DNSEntry.__init__(self, name, type, protocol)
        self.ttl = DNS_TTL
        self.target = target
        self.port = MDNS_PORT

    def write(self, out):
        out.writeShort(self.port)
        out.writeName(self.target)

    def __eq__(self, other):
        if isinstance(other, DNSService):
            return self.target == other.target
        return 0


class DNSCache(object):
    """A cache of DNS entries"""

    def __init__(self):
        self.cache = {}

    def add(self, entry):
        try:
            list = self.cache[entry.key]
        except:
            list = self.cache[entry.key] = []
        list.append(entry)

    def remove(self, entry):
        try:
            list = self.cache[entry.key]
            list.remove(entry)
        except:
            pass

    def get(self, entry):
        try:
            list = self.cache[entry.key]
            return list[list.index(entry)]
        except:
            return None

    def getByDetails(self, name, type):
        entry = DNSEntry(name, type)
        return self.get(entry)

    def entriesWithName(self, name):
        try:
            return self.cache[name]
        except:
            return []

    def entries(self):
        return self.cache


class DNSQuery(DNSEntry):

    def __init__(self, name, type, protocol):
        DNSEntry.__init__(self, name, type, protocol)

    def answeredBy(self, record):
        return  self.type == record.type and self.name == record.name


class Zeroconfig(object):
    """Implementation of Zeroconf Multicast DNS Service Discovery
    Supports registration, unregistration, queries and browsing.
    """
    def __init__(self):
        pass

    def registerService(self, entry):
        if isinstance(entry, DNSText):
            pass
        if isinstance(entry, DNSService):
            pass

    def unregisterService(self, entry):
        if isinstance(entry, DNSText):
            pass
        if isinstance(entry, DNSService):
            pass

    def checkService(self, service):
        pass