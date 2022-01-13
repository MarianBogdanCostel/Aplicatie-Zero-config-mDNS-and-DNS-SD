from DNSClasses import *


class ServiceInfo:
    def __init__(self, type_, name: str, address=None, port=None, weight=0, priority=0, target=None):
        self.type_ = type_
        self.name = name
        self.address = address
        self.port = port
        self.weight = weight
        self.priority = priority
        if target:
            self.target = target
        else:
            self.target = name

    def get_name(self):
        if self.type_ is not None and self.name.endswith("." + self.type_):
            return self.name[:len(self.name) - len(self.type_) - 1]
        return self.name

    def update_record(self, zeroconfig, now, record):
        if record is not None and not record.is_expired(now):

            if record.type_ == TYPE_A:
                if record.name == self.target:
                    self.address = record.address
            elif record.type_ == TYPE_SRV:
                if record.name == self.name:
                    self.target = record.target
                    self.port = record.port
                    self.weight = record.weight
                    self.priority = record.priority
                    self.update_record(zeroconfig, now, zeroconfig.cache.get_item_by_details(self.target, TYPE_A, CLASS_IN))

    def request(self, zeroconfig, timeout):
        now = time.time() * 1000
        delay = 200
        next = now + delay
        last = now + timeout

        try:
            zeroconfig.add_listener(self, DNSQuestion(self.name, TYPE_ANY, CLASS_IN))
            while self.target is None or self.address is None:
                if last <= now:
                    return False
                if next <= now:

                    query = DNSQuery(FLAG_QUERY)
                    cached_entry = zeroconfig.cache.get_item_by_details(self.name, TYPE_SRV, CLASS_IN)
                    if not cached_entry:
                        query.add_question(DNSQuestion(self.name, TYPE_SRV, CLASS_IN))
                        query.add_answer_at_time(cached_entry, now)
                    if self.target is not None:
                        cached_entry = zeroconfig.cache.get_item_by_details(self.target, TYPE_A, CLASS_IN)
                        if not cached_entry:
                            query.add_question(DNSQuestion(self.target, TYPE_A, CLASS_IN))
                            query.add_answer_at_time(cached_entry, now)
                        cached_entry = zeroconfig.cache.get_item_by_details(self.target, TYPE_AAAA, CLASS_IN)
                        if not cached_entry:
                            query.add_question(DNSQuestion(self.target, TYPE_AAAA, CLASS_IN))
                            query.add_answer_at_time(cached_entry, now)

                    zeroconfig.send(query)
                    next = now + delay
                    delay *= 2
                zeroconfig.wait(min(next, last) - now)
                now = time.time() * 1000

        finally:
            zeroconfig.remove_listener(self)
        return True

    def __eq__(self, other):
        if isinstance(other, ServiceInfo):
            return other.name == self.name
        return False

    def __ne__(self, other):
        return not self.__eq__(other)
