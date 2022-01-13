from six import int2byte
import DNSClasses
import struct


class DNSQuery:
    def __init__(self, flags, multicast=True):
        self.is_packed = False
        self.id = 0
        self.is_multicast = multicast
        self.flags = flags
        self.domain_names = {}
        self.data = []
        self.size = 12

        self.questions = []
        self.answers = []
        self.authorities = []
        self.additionals = []

    def add_question(self, record):
        self.questions.append(record)

    def add_answer(self, msg, record):
        if not record.suppressed(msg):
            self.add_answer_at_time(record, 0)

    def add_authoritative_answer(self, record):
        self.authorities.append(record)

    def add_additional_answer(self, record):
        self.additionals.append(record)

    def add_answer_at_time(self, record, now):
        if record is not None:
            if now == 0 or not record.is_expired(now):
                self.answers.append((record, now))

    def pack(self, format, value):
        self.data.append(struct.pack(format, value))
        self.size += struct.calcsize(format)

    def write_byte(self, value):
        self.pack(b'!c', int2byte(value))

    def insert_short(self, index, value):
        self.data.insert(index, struct.pack(b'!H', value))
        self.size += 2

    def write_short(self, value):
        self.pack(b'!H', value)

    def write_int(self, value):
        self.pack(b'!I', int(value))

    def write_string(self, value):
        assert isinstance(value, bytes)
        self.data.append(value)
        self.size += len(value)

    def write_utf8(self, string):
        utf_string = string.encode('utf-8')
        length = len(utf_string)
        if length > 64:
            raise Exception("String too long!")
        self.write_byte(length)
        self.write_string(utf_string)

    def write_domain_name(self, domain_name):
        if domain_name in self.domain_names:
            index = self.domain_names[domain_name]
            self.write_byte((index >> 8) | 0xC0)
            self.write_byte(index & 0xFF)
        else:
            self.domain_names[domain_name] = self.size
            dnn = domain_name.split('.')
            if dnn[-1] == '':
                dnn = dnn[:-1]
            for i in dnn:
                self.write_utf8(i)
            self.write_byte(0)

    def write_question(self, question):
        self.write_domain_name(question.name)
        self.write_short(question.type_)
        self.write_short(question.clazz)

    def write_record(self, record, now):
        self.write_domain_name(record.name)
        self.write_short(record.type_)
        if self.is_multicast:
            self.write_short(record.clazz)
        else:
            self.write_short(record.clazz)
        if now == 0:
            self.write_int(record.ttl)
        else:
            self.write_int(record.get_remaining_ttl(now))
        index = len(self.data)
        self.size += 2
        record.write(self)
        self.size -= 2
        length = len(b''.join(self.data[index:]))
        self.insert_short(index, length)

    def packet(self):
        if not self.is_packed:
            self.is_packed = True
            for question in self.questions:
                self.write_question(question)
            for answer, time_ in self.answers:
                self.write_record(answer, time_)

            for authority in self.authorities:
                self.write_record(authority, 0)
            for additional in self.additionals:
                self.write_record(additional, 0)

            self.insert_short(0, len(self.additionals))
            self.insert_short(0, len(self.authorities))
            self.insert_short(0, len(self.answers))
            self.insert_short(0, len(self.questions))
            self.insert_short(0, self.flags)
            if self.is_multicast:
                self.insert_short(0, 0)
            else:
                self.insert_short(0, self.id)
        return b''.join(self.data)
