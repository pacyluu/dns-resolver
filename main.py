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
    num_questions: int = 0              #All of these are 2 byte integers
    num_answers: int = 0
    num_authorities: int = 0
    num_additionals: int = 0

@dataclass
class DNSQuestion:
    name: bytes
    type_: int                # 2 byte integers
    class_: int

@dataclass
class DNSRecord:
    name: bytes         
    type_: int                  # 2 byte
    class_: int                 # 2 byte
    ttl: int                    # 4 byte
    data: bytes                 

@dataclass
class DNSPacket:
    header: DNSHeader
    questions: List[DNSQuestion]
    answers: List[DNSRecord]
    authorities: List[DNSRecord]
    additionals: List[DNSRecord]

def header_to_bytes(header: DNSHeader) -> bytes:
    fields = dataclasses.astuple(header)
    return struct.pack("!hhhhhh", *fields)

def question_to_bytes(question: DNSQuestion) -> bytes:
    return question.name + struct.pack("!HH", question.type_, question.class_)

def encode_dns_name(domain_name: str) -> bytes:
    encoded = []
    for part in domain_name.encode("ascii").split(b"."):
        encoded.append(bytes([len(part)]))
        encoded.append(part)
    encoded.append(b"\x00")
    return b"".join(encoded)
    
#Test one query
def build_query(domain_name, record_type):
    name = encode_dns_name(domain_name)
    id = random.randint(0, 65535)
    RECURSION_DESIRED = 1 << 8
    header = DNSHeader(id=id, num_questions=1, flags=RECURSION_DESIRED)
    question = DNSQuestion(name=name, type_=record_type, class_=CLASS_IN)
    return header_to_bytes(header) + question_to_bytes(question)

def send_query(ip_address, domain_name, record_type):
    query = build_query(domain_name, record_type)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, (ip_address, 53))

    data, _ = sock.recvfrom(1024)
    return parse_dns_packet(data)

def parse_header(reader):
    data = reader.read(12)
    items = struct.unpack("!HHHHHH", data)
    return DNSHeader(*items)

def parse_question(reader):
    name = decode_name(reader)
    data = reader.read(4)
    type_, class_ = struct.unpack("!HH", data)
    return DNSQuestion(name, type_, class_)

def decode_name(reader):
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

def decode_compressed_name(length, reader):
    second_byte = reader.read(1)[0]
    pointer = ((length & 0b0011_1111) << 8) | second_byte     ## get rid of the 2 left bits and add the next 8 in
    current_pos = reader.tell()
    reader.seek(pointer)
    result = decode_name(reader)
    reader.seek(current_pos)
    return result

def parse_record(reader):
    name = decode_name(reader)
    values = reader.read(10)
    type_, class_, ttl, data_len = struct.unpack("!HHIH", values)       # Data len is the 2 byte value of the length of the string 
    data = reader.read(data_len)                                        # Once we know the length of the string, we can read it
    return DNSRecord(name, type_, class_, ttl, data)                    # Example in decimal: 11 192.168.1.2  11 chars, so 11 is prepended

def parse_dns_packet(data) -> DNSPacket:
    reader = BytesIO(data)
    header = parse_header(reader)
    questions = [parse_question(reader) for _ in range(header.num_questions)]
    answers = [parse_record(reader) for _ in range(header.num_answers)]
    authorities = [parse_record(reader) for _ in range(header.num_authorities)]
    additionals = [parse_record(reader) for _ in range(header.num_additionals)]

    return DNSPacket(header, questions, answers, authorities, additionals)

def ip_to_string(ip) -> str:
    return ".".join([str(x) for x in ip])
        
def get_answer(packet):
    # return the first A record in the Answer section
    for x in packet.answers:
        if x.type_ == TYPE_A:
            return x.data
        
def get_nameserver_ip(packet):
    # return the first A record in the Additional section
    for x in packet.additionals:
        if x.type_ == TYPE_A:
            return x.data
        
def get_nameserver(packet):
    # return the first NS record in the Authority section
    for x in packet.authorities:
        if x.type_ == TYPE_NS:
            return x.data.decode('utf-8')
        
def resolve(domain_name, record_type):
    nameserver = "198.41.0.4"
    while True:
        print(f"Querying {nameserver} for {domain_name}")
        response = send_query(nameserver, domain_name, record_type)
        if ip := get_answer(response):
            return ip
        elif nsIP := get_nameserver_ip(response):
            nameserver = nsIP
        elif ns_domain := get_nameserver(response):
            nameserver = resolve(ns_domain, TYPE_A)
        else:
            raise Exception("something went wrong")