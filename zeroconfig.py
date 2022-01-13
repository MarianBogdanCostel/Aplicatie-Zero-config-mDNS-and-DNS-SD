import ipaddress
import DNSClasses
from Listener import *
from DNSCache import *
from Cleaner import *
from Engine import *
from ServiceInfo import *
from Browser import *
from DNSClasses import *


def get_current_time():
    return time.time() * 1000


class Zeroconfig:
    def __init__(self):
        DNSClasses.GLOBAL_DONE = False
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ttl = struct.pack(b'B', 255)
        loop = struct.pack(b'B', 1)
        self.listen_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
        self.listen_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, loop)
        self.listen_socket.bind(('', MDNS_PORT))
        self.listen_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                                      socket.inet_aton(MDNS_ADDR4) + socket.inet_aton('0.0.0.0'))

        self.respond_sockets = []
        respond_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        respond_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ttl = struct.pack(b'B', 255)
        loop = struct.pack(b'B', 1)
        respond_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
        respond_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, loop)
        respond_socket.bind(('', MDNS_PORT))

        respond_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton('0.0.0.0'))
        self.respond_sockets.append(respond_socket)

        self.listeners = []
        self.browsers = []
        self.services = {}
        self.servicetypes = {}
        self.condition = threading.Condition()

        self.cache = DNSCache()
        self.engine = Engine(self)
        self.listener = Listener(self)
        self.engine.add_listener(self.listener, self.listen_socket)
        self.cleaner = Cleaner(self)

    def wait(self, timeout):
        with self.condition:
            self.condition.wait(timeout / 1000)

    def notify_all(self):
        with self.condition:
            self.condition.notify_all()

    def get_service_info(self, type, name, timeout=3000):
        info = ServiceInfo(type, name)
        if info.request(self, timeout):
            return info
        return None

    def send(self, query, address=MDNS_ADDR4, port=MDNS_PORT):
        packet = query.packet()
        for s in self.respond_sockets:
            if GLOBAL_DONE:
                return
            if address is None:
                real_addr = MDNS_ADDR4
            else:
                real_addr = address
            bytes_sent = s.sendto(packet, 0, (real_addr, port))
            if bytes_sent != len(packet):
                raise Exception('Sent %d out of %d bytes!' % (bytes_sent, len(packet)))

    def register_service(self, info, ttl=DNS_TTL):
        self.services[info.name.lower()] = info

        if info.type_ in self.servicetypes:
            self.servicetypes[info.type_] += 1
        else:
            self.servicetypes[info.type_] = 1
        now = get_current_time()
        next_time = now
        j = 0
        while j < 3:
            if now < next_time:
                self.wait(next_time - now)
                now = get_current_time()
                continue
            query = DNSQuery(FLAG_RESPONSE | FLAG_AA)
            query.add_answer_at_time(DNSPointer(info.type_, TYPE_PTR, CLASS_IN, ttl, info.name), 0)
            query.add_answer_at_time(DNSService(info.name, TYPE_SRV, CLASS_IN, ttl, info.priority,
                                                info.weight, info.port, info.target), 0)

            if info.address:
                query.add_answer_at_time(
                    DNSAddress(info.target, TYPE_A, CLASS_IN, ttl, info.address), 0)
            self.send(query)
            j += 1
            next_time += 250

    def unregister_service(self, info):
        try:
            del self.services[info.name.lower()]
            if self.servicetypes[info.type_] > 1:
                self.servicetypes[info.type_] -= 1
            else:
                del self.servicetypes[info.type_]
        except Exception:
            pass
        now = get_current_time()
        next_time = now
        j = 0
        while j < 3:
            if now < next_time:
                self.wait(next_time - now)
                now = get_current_time()
                continue
            query = DNSQuery(FLAG_RESPONSE | FLAG_AA)
            query.add_answer_at_time(DNSPointer(info.type_, TYPE_PTR, CLASS_IN, 0, info.name), 0)
            query.add_answer_at_time(DNSService(info.name, TYPE_SRV, CLASS_IN, 0, info.priority,
                                                info.weight, info.port, info.target), 0)
            if info.address:
                query.add_answer_at_time(
                    DNSAddress(info.target, TYPE_A, CLASS_IN, 0, info.address), 0)
            self.send(query)
            j += 1
            next_time += 150

    def update_record(self, now, record):
        for listener in self.listeners:
            listener.update_record(self, now, record)
        self.notify_all()

    def add_listener(self, listener, question):
        now = get_current_time()
        self.listeners.append(listener)
        if question is not None:
            for record in self.cache.get_item_with_name(question.name):
                if question.answered_by(record) and not record.is_expired(now):
                    listener.update_record(self, now, record)
        self.notify_all()

    def remove_listener(self, listener):
        try:
            self.listeners.remove(listener)
            self.notify_all()
        except Exception:
            pass

    def read_response(self, msg):
        now = get_current_time()
        for record in msg.answers:
            expired = record.is_expired(now)
            if record in self.cache.get_items():
                if expired:
                    self.cache.remove_item(record)
                else:
                    entry = self.cache.get_item(record)
                    if entry is not None:
                        entry.reset_ttl(record)
                        record = entry
            else:
                self.cache.add_item(record)
            self.update_record(now, record)

    def read_query(self, msg, address, port):
        query = None
        if port != MDNS_PORT:
            query = DNSQuery(FLAG_RESPONSE | FLAG_AA, False)
            for question in msg.questions:
                query.add_question(question)

        for question in msg.questions:
            if question.type_ == TYPE_PTR:
                if question.name == "_services._dns-sd._udp.local.":
                    for service_type in self.servicetypes.keys():
                        if query is None:
                            query = DNSQuery(FLAG_RESPONSE | FLAG_AA)
                        query.add_answer(msg, DNSPointer("_services._dns-sd._udp.local.", TYPE_PTR, CLASS_IN, DNS_TTL, service_type))

                for service in self.services.values():
                    if question.name == service.type_:
                        if query is None:
                            query = DNSQuery(FLAG_RESPONSE | FLAG_AA)
                        query.add_answer(msg, DNSPointer(service.type_, TYPE_PTR, CLASS_IN, DNS_TTL, service.name))
            else:
                try:
                    if query is None:
                        query = DNSQuery(FLAG_RESPONSE | FLAG_AA)
                    if question.type_ in (TYPE_A, TYPE_ANY):
                        for service in self.services.values():
                            if service.target == question.name.lower():
                                query.add_answer(msg, DNSAddress(question.name, TYPE_A, CLASS_IN, DNS_TTL, service.address))
                    service = self.services.get(question.name.lower(), None)
                    if not service:
                        continue

                    if question.type_ in (TYPE_SRV, TYPE_ANY):
                        query.add_answer(msg, DNSService(question.name, TYPE_SRV, CLASS_IN, DNS_TTL, service.priority, service.weight, service.port, service.server))
                    if question.type_ == TYPE_SRV:
                        query.add_additional_answer(DNSAddress(service.server, TYPE_A, CLASS_IN, DNS_TTL, service.address))

                except Exception:
                    pass
        if query is not None and query.answers:
            query.id = msg.id
            self.send(query, address, port)

    def close(self):
        if not DNSClasses.GLOBAL_DONE:
            DNSClasses.GLOBAL_DONE = True
            self.notify_all()
            self.engine.notify()
            self.listen_socket.close()
            for s in self.respond_sockets:
                s.close()
