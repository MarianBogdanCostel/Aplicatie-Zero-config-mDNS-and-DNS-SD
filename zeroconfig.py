import string
import time
import socket
import threading

_CLASS_IN = "IN"
_TYPE_SRV = "SRV"


class DNSEntry(object):
    """DNS entry"""

    def __init__(self, name, clazz, type):
        self.key = name.lower()
        self.name = name
        self.clazz = clazz
        self.type = type

    def __eq__(self, other):
        if isinstance(other, DNSEntry):
            return self.name == other.name and self.type == other.type
        return 0

    def __ne__(self, other):
        return not self.__eq__(other)

    def getClass(self):
        return self.clazz

    def getType(self):
        return self.type


class DNSService(DNSEntry):
    """DNS service record"""

    def __init__(self, name, protocol, ttl, clazz, type, priority, weight, port, target):
        DNSEntry.__init__(self, name, clazz, type)
        self.protocol = protocol
        self.ttl = ttl
        self.priority = priority
        self.weight = weight
        self.port = port
        self.target = target

    def __eq__(self, other):
        if isinstance(other, DNSService):
            return self.priority == other.priority and self.weight == other.weight and self.port == other.port and self.target == other.target and DNSEntry.__eq__(self, other)
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

    def getByDetails(self, name, type, clazz):
        entry = DNSEntry(name, type, clazz)
        return self.get(entry)

    def entriesWithName(self, name):
        try:
            return self.cache[name]
        except:
            return []

    def entries(self):
        return self.cache