from Browser import Browser
from DNSQuery import DNSQuery
from DNSclasses import *
from DNScache import *
from DNSclasses import *
from DNSResponse import *
import struct
import socket
import threading


class Listener:
    def __init__(self, zeroconf):
        self.zeroconf = zeroconf
        self.data = None

    def handle_read(self, socket_):
        try:
            data, (addr, port) = socket_.recvfrom(MAX_MSG_ABSOLUTE)
        except socket.error as err:
            if err.errno == socket.EBADF:
                return
            else:
                raise err
        self.data = data
        msg = DNSResponse(data)
        if msg.is_query():
            if port == MDNS_PORT:
                self.zeroconf.handle_query(msg, MDNS_ADDR, MDNS_PORT)
        else:
            self.zeroconf.handle_response(msg)


class Reaper(threading.Thread):
    def __init__(self, zeroconf):
        super().__init__()
        self.daemon = True
        self.zeroconf = zeroconf
        self.start()

    def run(self):
        while True:
            self.zeroconf.wait(10 * 1000)
            if GLOBAL_DONE:
                return
            now = time.time() * 1000
            for record in self.zeroconf.cache.entries():
                if record.is_expired(now):
                    self.zeroconf.update_record(now, record)
                    self.zeroconf.cache.remove(record)


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
    entry = DNSService(name, service, protocol, ttl, clazz, type, priority, weight)
    return entry


def new_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ttl = struct.pack(b'B', 255)
    loop = struct.pack(b'B', 1)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, loop)
    s.bind(('', DNSclasses.MDNS_PORT))
    return s


class Zeroconfig(object):
    def __init__(self):
        DNSclasses.GLOBAL_DONE = False
        self._listen_socket = new_socket()

        self._respond_sockets = []

        self.listeners = []
        self.browsers = []
        self.services = {}
        self.servicetypes = {}
        self.condition = threading.Condition()

        self.cache = DNSCache()
        self.listener = Listener(self)
        self.reaper = Reaper(self)

    def wait(self, timeout):
        with self.condition:
            self.condition.wait(timeout / 1000)

    def notify_all(self):
        with self.condition:
            self.condition.notify_all()

    def remove_service_listener(self, listener):
        for browser in self.browsers:
            if browser.listener == listener:
                browser.cancel()
                del browser

    def add_service_listener(self, type_, listener):
        self.remove_service_listener(listener)
        self.browsers.append(Browser(self, type_, listener))

    def send(self, out_, addr=DNSclasses.MDNS_ADDR, port=DNSclasses.MDNS_PORT):
        packet = out_.packet()
        for socket_ in self._respond_sockets:
            if DNSclasses.GLOBAL_DONE:
                return
            if addr is None:
                real_addr = DNSclasses.MDNS_ADDR
            else:
                real_addr = addr
            bytes_sent = socket_.sendto(packet, 0, (real_addr, port))
            if bytes_sent != len(packet):
                raise Exception('S-au trimis cu succes %d din %d octeti.' % (bytes_sent, len(packet)))

    def check_service(self, info, allow_name_change=True):
        next_instance_number = 2
        instance_name = info.name[:-len(info.type_) - 1]
        now = time.time() * 1000
        next_time = now
        j = 0
        while j < 3:
            for record in self.cache.entries_with_name(info.type_):
                if record.type_ == DNSclasses.TYPE_PTR and not record.is_expired(now) and record.alias == info.name:

                    if not allow_name_change:
                        raise Exception("NonUniqueNameException")
                    info.name = '%s-%s.%s' % (instance_name, next_instance_number, info.type_)
                    next_instance_number += 1
                    self.check_service(info)
                    return

            if now < next_time:
                self.wait(next_time - now)
                now = time.time() * 1000
                continue

            out = DNSQuery(DNSclasses.FLAGS_QR_QUERY | DNSclasses.FLAGS_AA)
            self.debug = out
            out.add_question(DNSQuestion(info.type_, DNSclasses.TYPE_PTR, DNSclasses.CLASS_IN))
            out.add_authoritative_answer(DNSPointer(info.type_, DNSclasses.TYPE_PTR, DNSclasses.CLASS_IN,
                                                    DNSclasses.DNS_TTL, info.name))
            self.send(out)
            j += 1
            next_time += DNSclasses.CHECK_TIME

    def register_service(self, info, ttl=DNSclasses.DNS_TTL):
        self.check_service(info)
        self.services[info.name.lower()] = info
        if info.type_ in self.servicetypes:
            self.servicetypes[info.type_] += 1
        else:
            self.servicetypes[info.type_] = 1
        now = time.time() * 1000
        next_time = now
        j = 0
        while j < 3:
            if now < next_time:
                self.wait(next_time - now)
                now = time.time() * 1000
                continue
            out_ = DNSQuery(DNSclasses.FLAGS_QR_RESPONSE | DNSclasses.FLAGS_AA)
            out_.add_answer_at_time(DNSPointer(info.type_, DNSclasses.TYPE_PTR, DNSclasses.CLASS_IN, ttl, info.name),
                                    0)
            out_.add_answer_at_time(
                DNSService(info.name, DNSclasses.TYPE_SRV, DNSclasses.CLASS_IN, ttl, info.priority,
                           info.weight, info.port, info.server), 0)
            out_.add_answer_at_time(DNSText(info.name, DNSclasses.TYPE_TXT, DNSclasses.CLASS_IN, ttl, info.text), 0)
            if info.address:
                out_.add_answer_at_time(
                    DNSAddress(info.server, DNSclasses.TYPE_A, DNSclasses.CLASS_IN, ttl, info.address), 0)

            self.send(out_)
            j += 1
            next_time += DNSclasses.REGISTER_TIME
