import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tlsfp.builder import (HelloSpec, build_client_hello, build_server_hello,  # noqa: E402
                           spec_from_ja3, spec_from_ja4_r)
from tlsfp.fingerprints import (client_fingerprint, ja4, ja4_parts,  # noqa: E402
                                server_fingerprint)
from tlsfp.flows import FlowTracker, SessionTable  # noqa: E402
from tlsfp.tls_parser import (extract_first_handshake, is_grease,  # noqa: E402
                              parse_client_hello, parse_server_hello)


def _parse_record(record: bytes):
    t, body = extract_first_handshake(record)
    return parse_client_hello(body) if t == 1 else parse_server_hello(body)


# ---------------------------------------------------------------- published vectors

def test_ja3_salesforce_reference_vector():
    # Example from https://github.com/salesforce/ja3 README
    ja3_full = "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
    ch = _parse_record(build_client_hello(spec_from_ja3(ja3_full, sni="example.com")))
    fp = client_fingerprint(ch)
    assert fp.ja3_full == ja3_full
    assert fp.ja3 == "ada70206e40642a3e4461f35503241d5"


def test_ja4_foxio_reference_vector():
    # Example from FoxIO JA4 technical details (Chrome-like hello)
    ja4_r = ("t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,"
             "cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,"
             "ff01_0403,0804,0401,0503,0805,0501,0806,0601")
    ch = _parse_record(build_client_hello(spec_from_ja4_r(ja4_r, sni="example.com")))
    j4, j4r = ja4(ch)
    assert j4r == ja4_r
    assert j4 == "t13d1516h2_8daaf6152771_e5627efa2ab1"


# ---------------------------------------------------------------- spec details

def test_grease_values():
    assert all(is_grease(v) for v in (0x0A0A, 0x1A1A, 0xFAFA))
    assert not any(is_grease(v) for v in (0x0A1A, 0x002F, 0xC02F, 0x0000))


def test_grease_and_randomised_order():
    base = dict(ciphers=[0x1301, 0x1302, 0xC02F], groups=[0x001D, 0x0017], point_formats=[0],
                alpn=[b"h2", b"http/1.1"], supported_versions=[0x0304, 0x0303], sni="a.com")
    a = HelloSpec(extensions=[0x0A0A, 0x0000, 0x0010, 0x000A, 0x000B, 0x000D, 0x002B], **base)
    b = HelloSpec(extensions=[0x2A2A,0x000D, 0x002B, 0x000B, 0x0000, 0x000A, 0x0010], **base)
    a.ciphers = [0x3A3A] + a.ciphers
    fa = client_fingerprint(_parse_record(build_client_hello(a)))
    fb = client_fingerprint(_parse_record(build_client_hello(b)))
    assert "2570" not in fa.ja3_full.split(",")[1]          # GREASE cipher removed
    assert fa.ja3 != fb.ja3                                  # JA3 depends on extension order
    assert fa.ja4 == fb.ja4                                  # JA4 sorts -> stable
    assert fa.ja4.startswith("t13d0306h2_")                  # 3 ciphers, 6 exts (no GREASE)


def test_ja4_no_sni_no_alpn_and_empty_hashes():
    spec = HelloSpec(ciphers=[0x002F], extensions=[], sni="")
    a, c_str, e_str = ja4_parts(_parse_record(build_client_hello(spec)))
    assert a == "t12i010000"
    j4, _ = ja4(_parse_record(build_client_hello(spec)))
    assert j4.endswith("_000000000000")


def test_ja3s_and_ja4s():
    rec = build_server_hello(0x0303, 0x1301, [(0x002B, b"\x03\x04"), (0x0033, b"\x00\x1d\x00\x00")])
    fp = server_fingerprint(_parse_record(rec))
    assert fp.ja3s_full == "771,4865,43-51"
    assert fp.ja4s.startswith("t130200_1301_")


# ---------------------------------------------------------------- reassembly

def test_reassembly_out_of_order_multi_segment():
    spec = HelloSpec(ciphers=list(range(1, 200)), extensions=[0x0000, 0x0015], sni="big.example")
    record = build_client_hello(spec)
    expected = client_fingerprint(_parse_record(record)).ja3
    flow = ("10.0.0.1", 50000, "10.0.0.2", 443)
    isn = 0xFFFFFF00                         # forces sequence-number wrap-around
    tr = FlowTracker()
    assert tr.feed(0.0, flow, isn, True, False, b"") is None
    segs = [(i, record[i:i + 100]) for i in range(0, len(record), 100)]
    order = segs[1:] + segs[:1]              # first segment arrives last
    events = [tr.feed(1.0, flow, (isn + 1 + off) & 0xFFFFFFFF, False, False, d) for off, d in order]
    got = [e for e in events if e]
    assert len(got) == 1 and got[0].fp.ja3 == expected


def test_session_pairing():
    tr, st = FlowTracker(), SessionTable()
    c = ("10.0.0.1", 50000, "10.0.0.2", 443)
    s = ("10.0.0.2", 443, "10.0.0.1", 50000)
    ev1 = tr.feed(0, c, 1000, False, False, build_client_hello(HelloSpec(ciphers=[0x2F], extensions=[0])))
    ev2 = tr.feed(0, s, 5000, False, False, build_server_hello(0x0303, 0x2F, []))
    sess, new = st.add(ev1)
    assert new
    sess2, new2 = st.add(ev2)
    assert sess2 is sess and not new2 and sess.server.fp.ja3s_full == "771,47,"


def test_non_tls_ignored():
    tr = FlowTracker()
    assert tr.feed(0, ("a", 1, "b", 80), 1, False, False, b"GET / HTTP/1.1\r\n\r\n") is None
