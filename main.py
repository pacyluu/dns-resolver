import random
import dataclasses
from dataclasses import dataclass
import struct
from typing import List
from io import BytesIO
import socket

random.seed(1)

TYPE_A = 1
TYPE_NS = 2
CLASS_IN = 1


@dataclass
class DNSHeader:
    id: int
    flags: int
    num_questions: int = 0
    num_answers: int = 0
    num_authorities: int = 0
    num_additionals: int = 0


@dataclass
class DNSQuestion:
    name: bytes
    type_: int
    class_: int


@dataclass
class DNSRecord:
    name: bytes             
    type_: int              #2 bytes
    class_: int             #2 bytes
    ttl: int                #4 bytes
    data: object            #2 bytes ***

# When receive a dns record, there is 2 bytes indicating length and then the data afterwords
#
# When we create a dns record, we just put the actual data in there.

@dataclass
class DNSPacket:
    header: DNSHeader
    questions: List[DNSQuestion]
    answers: List[DNSRecord]
    authorities: List[DNSRecord]
    additionals: List[DNSRecord]


def header_to_bytes(header: DNSHeader) -> bytes:
    fields = dataclasses.astuple(header)
    return struct.pack("!HHHHHH", *fields)


def question_to_bytes(question: DNSQuestion) -> bytes:
    return question.name + struct.pack("!HH", question.type_, question.class_)


def encode_dns_name(domain_name: str) -> bytes:
    encoded = []
    for part in domain_name.encode("ascii").split(b"."):
        encoded.append(bytes([len(part)]))
        encoded.append(part)
    encoded.append(b"\x00")
    return b"".join(encoded)


def build_query(domain_name: str, record_type: int) -> bytes:
    name = encode_dns_name(domain_name)
    query_id = random.randint(0, 65535)
    header = DNSHeader(id=query_id, num_questions=1, flags=0)
    question = DNSQuestion(name=name, type_=record_type, class_=CLASS_IN)
    return header_to_bytes(header) + question_to_bytes(question)


def send_query(ip_address: str, domain_name: str, record_type: int) -> DNSPacket:
    query = build_query(domain_name, record_type)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    try:
        sock.sendto(query, (ip_address, 53))
        data, _ = sock.recvfrom(1024)
        return parse_dns_packet(data)
    finally:
        sock.close()


def parse_header(reader: BytesIO) -> DNSHeader:
    data = reader.read(12)
    items = struct.unpack("!HHHHHH", data)
    return DNSHeader(*items)


def parse_question(reader: BytesIO) -> DNSQuestion:
    name = decode_name(reader)
    data = reader.read(4)
    type_, class_ = struct.unpack("!HH", data)
    return DNSQuestion(name, type_, class_)


def decode_name(reader: BytesIO) -> bytes:
    parts = []

    while True:
        length = reader.read(1)[0]

        if length == 0:
            break

        if (length & 0b11000000) == 0b11000000:
            parts.append(decode_compressed_name(length, reader))
            break
        else:
            parts.append(reader.read(length))

    return b".".join(parts)


def decode_compressed_name(length: int, reader: BytesIO) -> bytes:
    second_byte = reader.read(1)[0]
    pointer = ((length & 0b0011_1111) << 8) | second_byte
    current_pos = reader.tell()
    reader.seek(pointer)
    result = decode_name(reader)
    reader.seek(current_pos)
    return result


def ip_to_string(ip: bytes) -> str:
    return ".".join(str(x) for x in ip)


def parse_record(reader: BytesIO) -> DNSRecord:
    name = decode_name(reader)
    values = reader.read(10)
    type_, class_, ttl, data_len = struct.unpack("!HHIH", values)

    if type_ == TYPE_NS:
        data = decode_name(reader).decode("utf-8")
    elif type_ == TYPE_A:
        data = ip_to_string(reader.read(data_len))
    else:
        data = reader.read(data_len)

    return DNSRecord(name, type_, class_, ttl, data)


def parse_dns_packet(data: bytes) -> DNSPacket:
    reader = BytesIO(data)
    header = parse_header(reader)
    questions = [parse_question(reader) for _ in range(header.num_questions)]
    answers = [parse_record(reader) for _ in range(header.num_answers)]
    authorities = [parse_record(reader) for _ in range(header.num_authorities)]
    additionals = [parse_record(reader) for _ in range(header.num_additionals)]
    return DNSPacket(header, questions, answers, authorities, additionals)


def get_answer(packet: DNSPacket):
    for record in packet.answers:
        if record.type_ == TYPE_A:
            # print(record.type_)
            return record.data


def get_nameserver_ip(packet: DNSPacket):
    for record in packet.additionals:
        if record.type_ == TYPE_A:
            # print(packet.authorities[0].type_)
            return record.data


def get_nameserver(packet: DNSPacket):
    for record in packet.authorities:
        if record.type_ == TYPE_NS:
            return record.data


def resolve(domain_name: str, record_type: int):
    nameserver = "198.41.0.4"  # a.root-servers.net

    while True:
        print(f"Querying {nameserver} for {domain_name}")
        response = send_query(nameserver, domain_name, record_type)

        if ip := get_answer(response):
            return ip
        elif ns_ip := get_nameserver_ip(response):
            nameserver = ns_ip
        elif ns_domain := get_nameserver(response):
            # print(3)
            nameserver = resolve(ns_domain, TYPE_A)
        else:
            raise Exception("something went wrong")


def main():
    query = input("Enter a domain: ")
    print(resolve(query, TYPE_A))


if __name__ == "__main__":
    main()