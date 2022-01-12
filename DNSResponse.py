from six import indexbytes
from queryTypes import *


class DNSResponse:
    def __init__(self, data):
        self.offset = 0
        self.data = data
        self.questions = []
        self.answers = []
        self.id = 0
        self.flags = 0
        self.nr_questions = 0
        self.nr_answers = 0
        self.nr_authorities = 0
        self.nr_additionals = 0

        self.read_header()
        self.read_questions()
        self.read_other_data()

    def unpack(self, format_):
        length = struct.calcsize(format_)
        info = struct.unpack(format_, self.data[self.offset:self.offset + length])
        self.offset += length
        return info

    def read_header(self):
        (
            self.id,
            self.flags,
            self.nr_questions,
            self.nr_answers,
            self.nr_authorities,
            self.nr_additionals,
        ) = self.unpack(b'!6H')

    def read_int(self):
        return self.unpack(b'!I')[0]

    def read_unsigned_short(self):
        return self.unpack(b'!H')[0]

    def read_string(self, length):
        info = self.data[self.offset:self.offset + length]
        self.offset += length
        return info

    def read_character_string(self):
        length = indexbytes(self.data, self.offset)
        self.offset += 1
        return self.read_string(length)

    def is_query(self):
        return (self.flags & FLAGS_QR_MASK) == FLAGS_QR_QUERY

    def is_response(self):
        return (self.flags & FLAGS_QR_MASK) == FLAGS_QR_RESPONSE

    def read_utf8(self, offset, length):
        return str(self.data[offset: offset + length], encoding='utf-8', errors='replace')

    def read_domain_name(self):
        result = ''
        offset = self.offset
        next_off = -1
        first = offset
        while True:
            length = indexbytes(self.data, offset)
            offset += 1
            if length == 0:
                break
            t = length & 0xC0
            if t == 0x00:
                result = ''.join((result, self.read_utf8(offset, length) + '.'))
                offset += length
            elif t == 0xC0:
                if next_off < 0:
                    next_off = offset + 1
                offset = ((length & 0x3F) << 8) | indexbytes(self.data, offset)  # Turn back to the domain name
                if offset >= first:
                    raise Exception("Bad domain name (circular) at %s!" % offset)
                first = offset
            else:
                raise Exception("Bad domain name at %s" % offset)
        if next_off >= 0:
            self.offset = next_off
        else:
            self.offset = offset
        return result

    def read_questions(self):
        for j in range(self.nr_questions):
            name = self.read_domain_name()
            type_, class_ = self.unpack(b'!HH')
            question = DNSQuestion(name, type_, class_)
            self.questions.append(question)

    def read_other_data(self):
        nr = self.nr_answers + self.nr_authorities + self.nr_additionals
        for j in range(nr):
            domain = self.read_domain_name()
            type_, class_, ttl, length = self.unpack(b'!HHiH')
            record = None
            if type_ == TYPE_A:
                record = DNSAddress(domain, type_, class_, ttl, self.read_string(4))
            elif type_ == TYPE_CNAME or type_ == TYPE_PTR:
                record = DNSPointer(domain, type_, class_, ttl, self.read_domain_name())
            elif type_ == TYPE_TXT:
                record = DNSText(domain, type_, class_, ttl, self.read_string(length))
            elif type_ == TYPE_SRV:
                record = DNSService(domain, type_, class_, ttl, self.read_unsigned_short()
                                    , self.read_unsigned_short(), self.read_unsigned_short(), self.read_domain_name())
            elif type_ == TYPE_AAAA:
                record = DNSAddress(domain, type_, class_, ttl, self.read_string(16))
            else:
                self.offset += length
            if record is not None:
                self.answers.append(record)