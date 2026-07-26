#!/usr/bin/env python3

from dnslib.server import DNSServer, BaseResolver
from dnslib import RR, QTYPE, A
#since h2 is our webserver i used h6 as its domain system 
class SimpleResolver(BaseResolver):

    def resolve(self, request, handler):

        reply = request.reply()

        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]

        print(f"DNS query received: {qname} ({qtype})")

        if qtype == "A":
            reply.add_answer(
                RR(
                    rname=qname,
                    rtype=QTYPE.A,
                    ttl=60,
                    rdata=A("10.0.0.2")      # h2 ip adress
                )
            )

        return reply


resolver = SimpleResolver()

server = DNSServer(
    resolver,
    port=2026,
    address="0.0.0.0"
)

print("DNS server listening on UDP port 2026")

server.start()