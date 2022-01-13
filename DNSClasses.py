import time
from DNSQuery import *
import abc

GLOBAL_DONE = False

MDNS_ADDR4 = '224.0.0.251'
MDNS_ADDR6 = 'ff02::fb'
MDNS_PORT = 5353

DNS_TTL = 3600
CLASS_IN = 1

TYPE_A = 1
TYPE_PTR = 12
TYPE_AAAA = 28
TYPE_SRV = 33
TYPE_ANY = 255

FLAG_QUERY = 0x0000
FLAG_RESPONSE = 0x8000
FLAG_AA = 0x0400


class DNSEntry:
    def __init__(self, name, type_, clazz):
        self.key = name.lower()
        self.name = name
        self.type_ = type_
        self.clazz = clazz

    def __eq__(self, other):
        return (isinstance(other, DNSEntry) and
                self.name == other.name and
                self.type_ == other.type_ and
                self.clazz == other.clazz)

    def __ne__(self, other):
        return not self.__eq__(other)


class DNSQuestion(DNSEntry):
    def __init__(self, name, type_, clazz):
        super().__init__(name, type_, clazz)

    def answered_by(self, record):
        return (self.clazz == record.clazz and
                (self.type_ == record.type_ or
                 self.type_ == TYPE_ANY) and
                self.name == record.name)


class DNSRecord(DNSEntry):
    __metaclass__ = abc.ABCMeta

    def __init__(self, name, type_, clazz, ttl):
        super().__init__(name, type_, clazz)
        self.ttl = ttl
        self.moment = time.time() * 1000

    def __eq__(self, other):
        return isinstance(other, DNSRecord) and DNSEntry.__eq__(self, other)

    def suppressed(self, msg):
        for record in msg.answers:
            if self == record and record.ttl > (self.ttl / 2):
                return True
        return False

    def get_expiration_time(self, percent):
        return self.moment + (percent * self.ttl * 10)

    def get_remaining_ttl(self, now):
        return max(0, (self.get_expiration_time(100) - now) / 1000)

    def is_expired(self, now):
        return self.get_expiration_time(100) <= now

    def reset_ttl(self, other):
        self.moment = other.moment
        self.ttl = other.ttl

    @abc.abstractmethod
    def write(self, query):
        pass


class DNSAddress(DNSRecord):
    def __init__(self, name, type_, clazz, ttl, address):
        super().__init__(name, type_, clazz, ttl)
        self.address = address

    def write(self, query):
        query.write_string(self.address)

    def __eq__(self, other):
        return isinstance(other, DNSAddress) and self.address == other.address


class DNSPointer(DNSRecord):
    def __init__(self, name, type_, clazz, ttl, alias):
        super().__init__(name, type_, clazz, ttl)
        self.alias = alias

    def write(self, query):
        query.write_domain_name(self.alias)

    def __eq__(self, other):
        return isinstance(other, DNSPointer) and self.alias == other.alias


class DNSService(DNSRecord):
    def __init__(self, name, type_, clazz, ttl, priority, weight, port, target):
        super().__init__(name, type_, clazz, ttl)
        self.priority = priority
        self.weight = weight
        self.port = port
        self.target = target

    def write(self, query):
        query.write_short(self.priority)
        query.write_short(self.weight)
        query.write_short(self.port)
        query.write_domain_name(self.target)

    def __eq__(self, other):
        return (isinstance(other, DNSService) and
                self.priority == other.priority and
                self.weight == other.weight and
                self.port == other.port and
                self.target == other.target)
