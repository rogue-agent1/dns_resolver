#!/usr/bin/env python3
"""dns_resolver — DNS packet builder/parser and stub resolver. Zero deps."""
import struct, socket, random

def build_query(domain, qtype=1):
    tid = random.randint(0, 65535)
    header = struct.pack('>HHHHHH', tid, 0x0100, 1, 0, 0, 0)
    question = b''
    for label in domain.split('.'):
        question += bytes([len(label)]) + label.encode()
    question += b'\x00' + struct.pack('>HH', qtype, 1)
    return header + question, tid

def parse_name(data, offset):
    labels, jumped = [], False
    orig = offset
    while True:
        length = data[offset]
        if length == 0:
            offset += 1; break
        if (length & 0xC0) == 0xC0:
            if not jumped: orig = offset + 2
            offset = struct.unpack('>H', data[offset:offset+2])[0] & 0x3FFF
            jumped = True
        else:
            offset += 1
            labels.append(data[offset:offset+length].decode())
            offset += length
    return '.'.join(labels), orig if jumped else offset

def parse_response(data):
    tid, flags, qcount, acount = struct.unpack('>HHHH', data[:8])
    offset = 12
    for _ in range(qcount):
        _, offset = parse_name(data, offset)
        offset += 4
    records = []
    for _ in range(acount + struct.unpack('>H', data[8:10])[0]):
        name, offset = parse_name(data, offset)
        rtype, rclass, ttl, rdlen = struct.unpack('>HHIH', data[offset:offset+10])
        offset += 10
        rdata = data[offset:offset+rdlen]
        if rtype == 1 and rdlen == 4:
            rdata = '.'.join(str(b) for b in rdata)
        elif rtype == 28 and rdlen == 16:
            rdata = ':'.join(f'{rdata[i]:02x}{rdata[i+1]:02x}' for i in range(0, 16, 2))
        elif rtype == 5:
            rdata, _ = parse_name(data, offset - rdlen + (offset - offset))
        offset += rdlen
        records.append({'name': name, 'type': rtype, 'ttl': ttl, 'data': rdata})
    return records

def resolve(domain, server='8.8.8.8', qtype=1):
    query, tid = build_query(domain, qtype)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    sock.sendto(query, (server, 53))
    data, _ = sock.recvfrom(512)
    sock.close()
    return parse_response(data)

TYPE_NAMES = {1:'A', 5:'CNAME', 28:'AAAA', 15:'MX', 2:'NS', 6:'SOA'}

def main():
    import sys
    domains = sys.argv[1:] or ['example.com', 'google.com']
    for domain in domains:
        print(f"\n{domain}:")
        try:
            records = resolve(domain)
            for r in records:
                tname = TYPE_NAMES.get(r['type'], str(r['type']))
                print(f"  {tname:>6} {r['data']} (TTL={r['ttl']})")
        except Exception as e:
            print(f"  Error: {e}")

if __name__ == "__main__":
    main()
