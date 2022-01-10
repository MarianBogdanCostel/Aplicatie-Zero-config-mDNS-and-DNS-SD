import abc
import time

GLOBAL_DONE = False

BROWSER_TIME = 500
CHECK_TIME = 175
REGISTER_TIME = 225

DNS_PORT = 53
MDNS_PORT = 5353

MDNS_ADDR = '224.0.0.251'
MAX_MSG_ABSOLUTE = 8972
DNS_TTL = 3600

CLASS_IN = 1
CLASS_ANY = 255
CLASS_MASK = 0x7FFF
CLASS_UNIQUE = 0X8000

TYPE_A = 1
TYPE_PTR = 12
TYPE_TXT = 16
TYPE_SRV = 33
TYPE_ANY = 255

FLAGS_QR_QUERY = 0x0000
FLAGS_QR_RESPONSE = 0x8000
FLAGS_QR_MASK = 0x8000

FLAGS_AA = 0x0400

CLASSES = {CLASS_IN: "in",
           CLASS_ANY: "any"}
TYPES = {TYPE_TXT: "txt",
         TYPE_PTR: "ptr",
         TYPE_SRV: "srv",
         TYPE_ANY: "any"}


class DNSEntry:
    def __init__(self, name, type_, class_):
        self.key = name.lower()
        self.name = name
        self.type_ = type_
        self.class_ = class_ & CLASS_MASK
        self.unique = (class_ & CLASS_UNIQUE) != 0

    def __eq__(self, other):
        return (isinstance(other, DNSEntry) and
                self.name == other.name and
                self.type_ == other.type_ and
                self.class_ == other.class_)

    def __ne__(self, other):
        return not self.__eq__(other)

    @staticmethod
    def get_type(type_):
        return TYPES.get(type_, "NotRecognisedType(%s)" % type_)


class DNSRecord(DNSEntry):
    __metaclass__ = abc.ABCMeta

    def __init__(self, name, type_, class_, ttl):
        super().__init__(name, type_, class_)
        self.ttl = ttl
        self.moment = time.time() * 1000

    def __eq__(self, other):
        return isinstance(other, DNSRecord) and DNSEntry.__eq__(self, other)

    def get_expiration_time(self, percent):
        return self.moment + (percent * self.ttl * 10)

    def get_remaining_ttl(self, now):
        return max(0, (self.get_expiration_time(100) - now) / 1000)

    def is_expired(self, now) -> bool:
        return self.get_expiration_time(100) <= now

    def reset_ttl(self, other):
        self.moment = other.moment
        self.ttl = other.ttl

    @abc.abstractmethod
    def write(self, out_):
        pass


class DNSPointer(DNSRecord):
    def __init__(self, name, type_, class_, ttl, alias):
        super().__init__(name, type_, class_, ttl)
        self.alias = alias

    def write(self, out_):
        out_.write_domain_name(self.alias)

    def __eq__(self, other):
        return isinstance(other, DNSPointer) and self.alias == other.alias


class DNSText(DNSRecord):
    def __init__(self, name, type_, class_, ttl, text):
        assert isinstance(text, (bytes, type(None)))
        super().__init__(name, type_, class_, ttl)
        self.text = text

    def write(self, out_):
        out_.write_string(self.text)

    def __eq__(self, other):
        return isinstance(other, DNSText) and self.text == other.text


class DNSService(DNSRecord):
    def __init__(self, name, type_, class_, ttl, priority, weight, port, server):
        super().__init__(name, type_, class_, ttl)
        self.priority = priority
        self.weight = weight
        self.port = port
        self.server = server

    def write(self, out_):
        out_.write_short(self.priority)
        out_.write_short(self.weight)
        out_.write_short(self.port)
        out_.write_domain_name(self.server)

    def __eq__(self, other):
        return (isinstance(other, DNSService) and
                self.priority == other.priority and
                self.weight == other.weight and
                self.port == other.port and
                self.server == other.server)


class DNSQuestion(DNSEntry):
    def __init__(self, name, type_, class_):
        super().__init__(name, type_, class_)

    def answered_by(self, record):
        return (self.class_ == record.class_ and
                (self.type_ == record.type_ or
                 self.type_ == TYPE_ANY) and
                self.name == record.name)


class DNSAddress(DNSRecord):
    def __init__(self, name, type_, class_, ttl, address):
        super().__init__(name, type_, class_, ttl)
        self.address = address

    def write(self, out_):
        out_.write_string(self.address)

    def __eq__(self, other):
        return isinstance(other, DNSAddress) and self.address == other.address
