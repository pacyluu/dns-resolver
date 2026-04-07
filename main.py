import random
import dataclasses
from dataclasses import dataclass
import struct
from typing import List
from io import BytesIO

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
    data: bytes                 # 2 byte

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
    

random.seed(1)

TYPE_A = 1
CLASS_IN = 1

#Test one query
def build_query(domain_name, record_type):
    name = encode_dns_name(domain_name)
    id = random.randint(0, 65535)
    RECURSION_DESIRED = 1 << 8
    header = DNSHeader(id=id, num_questions=1, flags=RECURSION_DESIRED)
    question = DNSQuestion(name=name, type_=record_type, class_=CLASS_IN)
    return header_to_bytes(header) + question_to_bytes(question)


# bit 0 end

# bit 5	AA	Authoritative Answer	[RFC1035]
# bit 6	TC	Truncated Response	[RFC1035]
# bit 7	RD	Recursion Desired	[RFC1035]
# bit 8	RA	Recursion Available	[RFC1035]
# bit 9		Reserved	
# bit 10	AD	Authentic Data	[RFC4035][RFC6840][RFC Errata 4924]
# bit 11	CD	Checking Disabled


#bit 15 start

import socket

query = build_query("www.example.com", 1)


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sock.sendto(query, ("8.8.8.8", 53))
response, addr = sock.recvfrom(1024)

print(f"Received {response} from {addr}")

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
