from six import text_type, indexbytes
from queryTypes import *


class ServiceInfo:
    def __init__(self, type_, name: str, address=None, port=None, weight=0, priority=0, properties=None, server=None):
        if not name.endswith(type_):
            raise Exception("Bad type name!")
        self.type_ = type_
        self.name = name
        self.address = address
        self.port = port
        self.weight = weight
        self.priority = priority
        if server:
            self.server = server
        else:
            self.server = name
        self._properties = None
        self._set_properties(properties)

    @property
    def properties(self):
        return self._properties

    def _set_properties(self, properties):
        if isinstance(properties, dict):
            self._properties = properties
            list_ = []
            result = b''
            for key in properties:
                value = properties[key]
                if isinstance(key, text_type):
                    key = key.encode('utf-8')
                if value is not None:
                    if not isinstance(value, bytes):
                        value = str(value).encode('utf-8')
                list_.append(b'='.join((key, value)))
            for item in list_:
                result = b''.join((result, int2byte(len(item)), item))
            self.text = result
        else:
            self.text = properties

    def _set_text(self, text):
        self.text = text
        try:
            result = {}
            end = len(text)
            index = 0
            values = []
            while index < end:
                length = indexbytes(text, index)
                index += 1
                values.append(text[index:index + length])
                index += length

            for v in values:
                try:
                    key, value = v.split(b'=', 1)
                except Exception as e:
                    key = v
                    value = False
                if key and result.get(key) is None:
                    result[key] = value
            self._properties = result
        except Exception as e:
            self._properties = None

    def get_name(self):
        if self.type_ is not None and self.name.endswith("." + self.type_):
            return self.name[:len(self.name) - len(self.type_) - 1]
        return self.name

    def update_record(self, zerocfg, now, record):
        if record is not None and not record.is_expired(now):

            if record.type_ == TYPE_A:
                if record.name == self.server:
                    self.address = record.address
            elif record.type_ == TYPE_SRV:
                if record.name == self.name:
                    self.server = record.server
                    self.port = record.port
                    self.weight = record.weight
                    self.priority = record.priority
                    self.update_record(zerocfg, now, zerocfg.cache.get_item_by_details(self.server, TYPE_A, CLASS_IN))
            elif record.type_ == TYPE_TXT:

                if record.name == self.name:
                    self._set_text(record.text)

    def request(self, zerocfg, timeout):
        now = current_time_millis()
        delay = LISTENER_TIME
        next = now + delay
        last = now + timeout

        try:

            zerocfg.add_listener(self, DNSQuestion(self.name, TYPE_ANY, CLASS_IN))

            while self.server is None or self.address is None or self.text is None:
                if last <= now:
                    return False
                if next <= now:

                    out = DNSQuery(FLAGS_QR_QUERY)
                    cached_entry = zerocfg.cache.get_item_by_details(self.name, TYPE_SRV, CLASS_IN)
                    if not cached_entry:
                        out.add_question(DNSQuestion(self.name, TYPE_SRV, CLASS_IN))
                        out.add_answer_at_time(cached_entry, now)
                    cached_entry = zerocfg.cache.get_item_by_details(self.name, TYPE_TXT, CLASS_IN)
                    if not cached_entry:
                        out.add_question(DNSQuestion(self.name, TYPE_TXT, CLASS_IN))
                        out.add_answer_at_time(cached_entry, now)
                    if self.server is not None:
                        cached_entry = zerocfg.cache.get_item_by_details(self.server, TYPE_A, CLASS_IN)
                        if not cached_entry:
                            out.add_question(DNSQuestion(self.server, TYPE_A, CLASS_IN))
                            out.add_answer_at_time(cached_entry, now)
                        cached_entry = zerocfg.cache.get_item_by_details(self.server, TYPE_AAAA, CLASS_IN)
                        if not cached_entry:
                            out.add_question(DNSQuestion(self.server, TYPE_AAAA, CLASS_IN))
                            out.add_answer_at_time(cached_entry, now)

                    zerocfg.send(out)
                    next = now + delay
                    delay *= 2
                zerocfg.wait(min(next, last) - now)
                now = current_time_millis()

        finally:
            zerocfg.remove_listener(self)
        return True

    def __eq__(self, other):
        if isinstance(other, ServiceInfo):
            return other.name == self.name
        return False

    def __ne__(self, other):
        return not self.__eq__(other)
