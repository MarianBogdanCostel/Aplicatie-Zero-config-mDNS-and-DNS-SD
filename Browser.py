import threading
from queryTypes import *


class Browser(threading.Thread):
    def __init__(self, zeroconfig, type_, listener):
        super().__init__()
        self.daemon = True
        self.zeroconfig = zeroconfig
        self.type_ = type_
        self.listener = listener
        self.services = {}
        self.next_time = current_time_millis()
        self.delay = BROWSER_TIME
        self.list = []
        self.done = False
        self.zeroconfig.add_listener(self, DNSQuestion(self.type_, TYPE_PTR, CLASS_IN))
        self.start()

    def update_record(self, zeroconfig, now, record):
        if record.type_ == TYPE_PTR and record.name == self.type_:
            expired = record.is_expired(now)
            try:
                oldrecord = self.services[record.alias.lower()]
                if not expired:
                    oldrecord.reset_TTL(record)
                else:
                    del (self.services[record.alias.lower()])
                    return
            except Exception as e:
                if not expired:
                    self.services[record.alias.lower()] = record
                    callback = lambda x: self.listener.add_service(x, self.type_, record.alias)
                    self.list.append(callback)
            expires = record.get_expiration_time(75)
            if expires < self.next_time:
                self.next_time = expires

    def cancel(self):
        self.done = True
        self.zeroconfig.notify_all()

    def run(self):
        while True:
            event = None
            now = current_time_millis()
            if len(self.list) == 0 and self.next_time > now:
                self.zeroconfig.wait(self.next_time - now)
            if GLOBAL_DONE or self.done:
                return
            now = current_time_millis()
            if self.next_time <= now:
                out = DNSQuery(FLAGS_QR_QUERY)
                out.add_question(DNSQuestion(self.type_, TYPE_PTR, CLASS_IN))
                for record in self.services.values():
                    if not record.is_expired(now):
                        out.add_answer_at_time(record, now)
                self.zeroconfig.send(out)
                self.next_time = now + self.delay
                self.delay = min(20 * 1000, self.delay * 2)
            if len(self.list) > 0:
                event = self.list.pop(0)
            if event is not None:
                event(self.zeroconfig)
