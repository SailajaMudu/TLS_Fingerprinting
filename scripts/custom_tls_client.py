"""A hand-crafted TLS client: writes a ClientHello byte-by-byte, reads the ServerHello.

Profiles
  handcrafted (default) - an unusual TLS 1.2 cipher/extension set, like a bespoke
                          implant or scanner would produce
  --ja3  "<ja3_full>"   - replay an arbitrary JA3 string on the wire (spoofing demo)
  --ja4r "<ja4_r>"      - replay an arbitrary JA4_r string on the wire (spoofing demo)

Example
  python scripts/custom_tls_client.py www.wikipedia.org
  python scripts/custom_tls_client.py www.wikipedia.org --ja3 "771,4865-4866-...,0-23-...,29-23-24,0"
"""
from __future__ import annotations

import argparse
import os
import socket
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tlsfp.builder import (HelloSpec, build_client_hello, spec_from_ja3,  # noqa: E402
                           spec_from_ja4_r)
from tlsfp.fingerprints import client_fingerprint, server_fingerprint  # noqa: E402
from tlsfp.tls_parser import (HS_SERVER_HELLO, TLSParseError,  # noqa: E402
                              extract_first_handshake, parse_client_hello,
                              parse_server_hello)

HANDCRAFTED = dict(
    version=0x0303,
    ciphers=[0xC030, 0xC02F, 0x009F, 0x009E, 0xC028, 0xC027, 0x003D, 0x003C, 0x0035, 0x002F],
    extensions=[0x0000, 0x000B, 0x000A, 0x000D, 0x0017, 0xFF01],
    groups=[0x0017, 0x0018, 0x001D],
    point_formats=[0],
)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("--port", type=int, default=443)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--ja3", help="JA3 full string to impersonate")
    g.add_argument("--ja4r", help="JA4_r string to impersonate")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if args.ja3:
        spec = spec_from_ja3(args.ja3, sni=args.host)
    elif args.ja4r:
        spec = spec_from_ja4_r(args.ja4r, sni=args.host)
    else:
        spec = HelloSpec(sni=args.host, **HANDCRAFTED)
    record = build_client_hello(spec)

    sent = client_fingerprint(parse_client_hello(record[9:]))
    if not args.quiet:
        print(f"sent ClientHello  JA3={sent.ja3}  JA4={sent.ja4}")
        print(f"                  ja3_full={sent.ja3_full}")

    with socket.create_connection((args.host, args.port), timeout=10) as s:
        s.sendall(record)
        buf = b""
        while True:
            try:
                chunk = s.recv(16384)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            if buf[:1] == b"\x15":
                print(f"server sent alert {buf[5:7].hex()} (expected for spoofed/fake key shares)")
                return
            try:
                res = extract_first_handshake(buf)
            except TLSParseError:
                print("server reply is not TLS")
                return
            if res:
                t, body = res
                if t == HS_SERVER_HELLO:
                    fp = server_fingerprint(parse_server_hello(body))
                    if not args.quiet:
                        print(f"got ServerHello   JA3S={fp.ja3s}  JA4S={fp.ja4s}")
                return


if __name__ == "__main__":
    main()
