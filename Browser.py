import threading

from DNSClasses import *


class Browser(threading.Thread):
    def __init__(self, zeroconfig, type, listener):
        super().__init__()
        self.zeroconfig = zeroconfig
        self.type = type
        self.listener = listener

        self.done = False
        self.services = {}
        self.next_time = time.time() * 1000
        self.delay = 500
        self.list = []
        self.zeroconfig.add_listener(self, DNSQuestion(self.type, TYPE_PTR, CLASS_IN))
        self.start()

    def update_record(self, zeroconfig, now, record):
        if record.type_ == TYPE_PTR and record.name == self.type:
            expired = record.is_expired(now)
            try:
                oldrecord = self.services[record.alias.lower()]
                if not expired:
                    oldrecord.reset_ttl(record)
                else:
                    del (self.services[record.alias.lower()])
                    return
            except Exception:
                if not expired:
                    self.services[record.alias.lower()] = record
                    callback = lambda x: self.listener.add_service(x, self.type, record.alias)
                    self.list.append(callback)
            expires = record.get_expiration_time(75)
            if expires < self.next_time:
                self.next_time = expires

    def run(self):
        while True:
            event = None
            now = time.time() * 1000
            if len(self.list) == 0 and self.next_time > now:
                self.zeroconfig.wait(self.next_time - now)
            if GLOBAL_DONE or self.done:
                return
            now = time.time() * 1000
            if self.next_time <= now:
                query = DNSQuery(FLAG_QUERY)
                query.add_question(DNSQuestion(self.type, TYPE_PTR, CLASS_IN))
                for record in self.services.values():
                    if not record.is_expired(now):
                        query.add_answer_at_time(record, now)
                self.zeroconfig.send(query)
                self.next_time = now + self.delay
                self.delay = min(20 * 1000, self.delay * 2)
            if len(self.list) > 0:
                event = self.list.pop(0)
            if event is not None:
                event(self.zeroconfig)

    def stop(self):
        self.done = True
        self.zeroconfig.notify_all()
