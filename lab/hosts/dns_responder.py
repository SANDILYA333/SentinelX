#!/usr/bin/env python3
"""Lightweight DNS responder for enterprise lab network simulation."""
import socket

DNS_RECORDS = {
    b"filesrv.corp": b"\x0a\x0a\x01\x14",       # 10.10.1.20
    b"dbprod.corp": b"\x0a\x0a\x01\x1e",        # 10.10.1.30
    b"jumphost.corp": b"\x0a\x0a\x01\x0a",      # 10.10.1.10
    b"engws.corp": b"\x0a\x0a\x01\x28",         # 10.10.1.40
    b"backup-srv-02.dmz": b"\x0a\x0a\x02\x14",  # 10.10.2.20
    b"db-prod-02.dmz": b"\x0a\x0a\x02\x1e",     # 10.10.2.30
}
DEFAULT_IP = b"\x0a\x0a\x01\x14"


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 53))
    while True:
        try:
            data, addr = s.recvfrom(512)
            if len(data) < 12:
                continue
            # Extract queried domain
            idx = 12
            domain_parts = []
            while idx < len(data) and data[idx] != 0:
                length = data[idx]
                idx += 1
                domain_parts.append(data[idx:idx + length])
                idx += length
            domain = b".".join(domain_parts).lower()

            ip_bytes = DNS_RECORDS.get(domain, DEFAULT_IP)

            # Build DNS response (1 answer, A record)
            resp = (
                data[:2]
                + b"\x81\x80"
                + data[4:6]
                + b"\x00\x01\x00\x00\x00\x00"
                + data[12:idx + 5]
                + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"
                + ip_bytes
            )
            s.sendto(resp, addr)
        except Exception:
            pass


if __name__ == "__main__":
    main()

