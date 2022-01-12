import ipaddress
from typing import cast

import queryTypes
from Listener import *
from DNSCache import *
from Cleaner import *
from wrapper import *
from serviceInfo import *
from Browser import *
from queryTypes import *


def can_send_to(sock: socket.socket, address: str) -> bool:
    addr = ipaddress.ip_address(address)
    return cast(bool, addr.version == 6 if sock.family == socket.AF_INET6 else addr.version == 4)


class Zeroconfig:
    def __init__(self, interfaces=InterfaceChoice.Default):
        queryTypes.GLOBAL_DONE = False
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ttl = struct.pack(b'B', 255)
        loop = struct.pack(b'B', 1)
        self.listen_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
        self.listen_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, loop)
        self.listen_socket.bind(('', MDNS_PORT))

        self.respond_sockets = []

        self.listen_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                                      socket.inet_aton(MDNS_ADDR) + socket.inet_aton('0.0.0.0'))

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
        self.engine.add_reader(self.listener, self.listen_socket)
        self.cleaner = Cleaner(self)

    def wait(self, timeout):
        with self.condition:
            self.condition.wait(timeout / 1000)

    def notify_all(self):
        with self.condition:
            self.condition.notify_all()

    def get_service_info(self, type_, name, timeout=3000):
        info = ServiceInfo(type_, name)
        if info.request(self, timeout):
            return info
        return None

    def remove_service_listener(self, listener):
        for browser in self.browsers:
            if browser.listener == listener:
                browser.cancel()
                del browser

    def add_service_listener(self, type_, listener):
        self.remove_service_listener(listener)
        self.browsers.append(Browser(self, type_, listener))

    def send(self, out_, addr=MDNS_ADDR, port=MDNS_PORT):
        packet = out_.packet()
        for s in self.respond_sockets:
            if GLOBAL_DONE:
                return
            if addr is None:
                real_addr = MDNS_ADDR
            elif not can_send_to(s, addr):
                continue
            else:
                real_addr = addr
            bytes_sent = s.sendto(packet, 0, (real_addr, port))
            if bytes_sent != len(packet):
                raise Exception(
                    'Sent %d out of %d bytes!' % (bytes_sent, len(packet)))

    def check_service(self, info, allow_name_change=True):
        next_instance_number = 2
        instance_name = info.name[:-len(info.type_) - 1]
        now = current_time_millis()
        next_time = now
        j = 0
        while j < 3:
            for record in self.cache.get_items_with_name(info.type_):
                if record.type_ == TYPE_PTR and not record.is_expired(now) and record.alias == info.name:

                    if not allow_name_change:
                        raise Exception("NonUniqueNameException")
                    info.name = '%s-%s.%s' % (instance_name, next_instance_number, info.type_)
                    next_instance_number += 1
                    self.check_service(info)
                    return

            if now < next_time:
                self.wait(next_time - now)
                now = current_time_millis()
                continue

            out = DNSQuery(FLAGS_QR_QUERY | FLAGS_AA)
            self.debug = out
            out.add_question(DNSQuestion(info.type_, TYPE_PTR, CLASS_IN))
            out.add_authoritative_answer(DNSPointer(info.type_, TYPE_PTR,CLASS_IN,
                                                    DNS_TTL, info.name))
            self.send(out)
            j += 1
            next_time += CHECK_TIME

    def register_service(self, info, ttl=DNS_TTL):
        self.check_service(info)
        self.services[info.name.lower()] = info
        if info.type_ in self.servicetypes:
            self.servicetypes[info.type_] += 1
        else:
            self.servicetypes[info.type_] = 1
        now = current_time_millis()
        next_time = now
        j = 0
        while j < 3:
            if now < next_time:
                self.wait(next_time - now)
                now = current_time_millis()
                continue
            out_ = DNSQuery(FLAGS_QR_RESPONSE | FLAGS_AA)
            out_.add_answer_at_time(DNSPointer(info.type_, TYPE_PTR, CLASS_IN, ttl, info.name),
                                    0)
            out_.add_answer_at_time(
                DNSService(info.name, TYPE_SRV, CLASS_IN, ttl, info.priority,
                           info.weight, info.port, info.server), 0)
            out_.add_answer_at_time(DNSText(info.name, TYPE_TXT, CLASS_IN, ttl, info.text), 0)
            if info.address:
                out_.add_answer_at_time(
                    DNSAddress(info.server, TYPE_A, CLASS_IN, ttl, info.address), 0)

            self.send(out_)
            j += 1
            next_time += REGISTER_TIME

    def unregister_service(self, info):
        try:
            del self.services[info.name.lower()]
            if self.servicetypes[info.type_] > 1:
                self.servicetypes[info.type_] -= 1
            else:
                del self.servicetypes[info.type_]
        except Exception as e:
            pass
        now = current_time_millis()
        next_time = now
        j = 0
        while j < 3:
            if now < next_time:
                self.wait(next_time - now)
                now = current_time_millis()
                continue
            out_ = DNSQuery(FLAGS_QR_RESPONSE | FLAGS_AA)
            out_.add_answer_at_time(DNSPointer(info.type_, TYPE_PTR, CLASS_IN, 0, info.name), 0)
            out_.add_answer_at_time(DNSService(info.name, TYPE_SRV, CLASS_IN, 0, info.priority,
                                               info.weight, info.port, info.server), 0)
            out_.add_answer_at_time(DNSText(info.name, TYPE_TXT, CLASS_IN, 0, info.text), 0)
            if info.address:
                out_.add_answer_at_time(
                    DNSAddress(info.server, TYPE_A, CLASS_IN, 0, info.address), 0)
            self.send(out_)
            j += 1
            next_time += UNREGISTER_TIME

    def unregister_all_services(self):
        if len(self.services) > 0:
            now = current_time_millis()
            next_time = now
            j = 0
            while j < 3:
                if now < next_time:
                    self.wait(next_time - now)
                    now = current_time_millis()
                    continue
                out_ = DNSQuery(FLAGS_QR_RESPONSE | FLAGS_AA)
                for info in self.services.values():
                    out_.add_answer_at_time(
                        DNSPointer(info.type_, TYPE_PTR, CLASS_IN, 0, info.name), 0)
                    out_.add_answer_at_time(
                        DNSService(info.name, TYPE_SRV, CLASS_IN, 0, info.priority,
                                   info.weight, info.port, info.server), 0)
                    out_.add_answer_at_time(
                        DNSText(info.name, TYPE_TXT, CLASS_IN, 0, info.text), 0)
                    if info.address:
                        out_.add_answer_at_time(
                            DNSAddress(info.server, TYPE_A, CLASS_IN, 0, info.address), 0)
                self.send(out_)
                j += 1
                next_time += UNREGISTER_TIME

    def update_record(self, now, record):
        for listener in self.listeners:
            listener.update_record(self, now, record)
        self.notify_all()

    def add_listener(self, listener, question):
        now = current_time_millis()
        self.listeners.append(listener)
        if question is not None:
            for record in self.cache.get_items_with_name(question.name):
                if question.answered_by(record) and not record.is_expired(now):
                    listener.update_record(self, now, record)
        self.notify_all()

    def remove_listener(self, listener):
        try:
            self.listeners.remove(listener)
            self.notify_all()
        except Exception as e:
            pass

    def handle_response(self, msg):
        now = current_time_millis()
        for record in msg.answers:
            expired = record.is_expired(now)
            if record in self.cache.get_items():
                if expired:
                    self.cache.remove_item(record)
                else:
                    entry = self.cache.get_item(record)
                    if entry is not None:
                        entry.reset_TTL(record)
                        record = entry
            else:
                self.cache.add_item(record)
            self.update_record(now, record)

    def handle_query(self, msg, addr, port):
        out_ = None
        if port != MDNS_PORT:
            out_ = DNSQuery(FLAGS_QR_RESPONSE | FLAGS_AA, False)
            for question in msg.questions:
                out_.add_question(question)

        for question in msg.questions:
            if question.type_ == TYPE_PTR:
                if question.name == "_services._dns-sd._udp.local.":
                    for serv_type in self.servicetypes.keys():
                        if out_ is None:
                            out_ = DNSQuery(FLAGS_QR_RESPONSE | FLAGS_AA)
                        out_.add_answer(msg,
                                        DNSPointer("_services._dns-sd._udp.local.",
                                                   TYPE_PTR, CLASS_IN, DNS_TTL,
                                                   serv_type))

                for service in self.services.values():
                    if question.name == service.type_:
                        if out_ is None:
                            out_ = DNSQuery(FLAGS_QR_RESPONSE | FLAGS_AA)
                        out_.add_answer(msg,
                                        DNSPointer(service.type_,
                                                   TYPE_PTR, CLASS_IN, DNS_TTL,
                                                   service.name))
            else:
                try:
                    if out_ is None:
                        out_ = DNSQuery(FLAGS_QR_RESPONSE | FLAGS_AA)
                    if question.type_ in (TYPE_A, TYPE_ANY):
                        for service in self.services.values():
                            if service.server == question.name.lower():
                                out_.add_answer(msg, DNSAddress(question.name,TYPE_A, CLASS_IN | CLASS_UNIQUE,DNS_TTL, service.address))
                    service = self.services.get(question.name.lower(), None)
                    if not service:
                        continue

                    if question.type_ in (TYPE_SRV, TYPE_ANY):
                        out_.add_answer(msg, DNSService(question.name,
                                                        TYPE_SRV,
                                                        CLASS_IN | CLASS_UNIQUE,
                                                        DNS_TTL, service.priority, service.weight,
                                                        service.port, service.server))
                    if question.type_ in (TYPE_TXT, TYPE_ANY):
                        out_.add_answer(msg, DNSText(question.name,
                                                     TYPE_TXT,
                                                     CLASS_IN | CLASS_UNIQUE,
                                                     DNS_TTL, service.text))
                    if question.type_ == TYPE_SRV:
                        out_.add_additional_answer(DNSAddress(service.server,
                                                              TYPE_A,
                                                              CLASS_IN | CLASS_UNIQUE,
                                                              DNS_TTL, service.address))

                except Exception as e:
                    pass
        if out_ is not None and out_.answers:
            out_.id = msg.id
            self.send(out_, addr, port)

    def close(self):
        if not queryTypes.GLOBAL_DONE:
            queryTypes.GLOBAL_DONE = True
            self.notify_all()
            self.engine.notify()
            self.unregister_all_services()
            for socket_ in [self._listen_socket] + self._respond_sockets:
                socket_.close()
