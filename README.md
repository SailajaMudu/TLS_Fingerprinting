# tlsfp — Passive TLS Fingerprinting (JA3 / JA3S / JA4 / JA4S)

`tlsfp` passively captures TLS **ClientHello** and **ServerHello** messages, computes
**JA3/JA3S** (Salesforce) and **JA4/JA4S** (FoxIO) fingerprints, and identifies the
client application or TLS library from a curated reference database, **without decrypting
anything**.

```
packets ──► TCP reassembly ──► TLS hello parser ──► JA3 / JA3S / JA4 / JA4S ──► reference DB ──► verdict
(Npcap/libpcap,   (multi-segment,     (pure Python,           (spec-exact,            (SQLite, optional    (+ SQLite history
 pcap / pcapng)    out-of-order,       GREASE-aware)           validated)              Redis/Valkey KV)     for reports)
                   any port)
```

## Features

| Requirement | Implementation |
|---|---|
| Passive capture | Scapy over Npcap/libpcap: live (`live`) or offline pcap/pcapng (`analyze`) |
| JA3 / JA3S | `tlsfp/fingerprints.py`. Matches Wireshark on **100%** of 276 ClientHellos and 241 ServerHellos |
| JA4 / JA4S (stretch goal) | Implemented per the FoxIO spec, including `ja4_r` raw strings |
| Real-world parsing | TCP reassembly (Chrome's post-quantum ClientHello spans 2+ segments), out-of-order segments, seq wrap-around, IPv4/IPv6, TLS on **any port** (detected by content, not port 443) |
| Reference DB | SQLite (`fingerprints` + `observations`), JSON export/import, abuse.ch SSLBL malware JA3 import, FoxIO `ja4plus-mapping.csv` import, Redis/Valkey mirror |
| Ground truth | `--resolve-process` maps each local connection to its owning process (psutil); `--auto-learn` labels from it |
| Evaluation | `learn` / `evaluate` / `stability` from labelled captures (`scripts/gen_traffic.py` writes the manifest) |
| Validation | `validate` cross-checks every hello against Wireshark/tshark's independent implementation |
| Evasion demo | `scripts/custom_tls_client.py --ja3 / --ja4r` replays any fingerprint on the wire |

## Install

```bash
pip install -r requirements.txt
# Windows: Npcap (comes with Wireshark). Linux/macOS: libpcap, and run captures with sudo.
# Optional: Wireshark >= 4.2 for `validate`; Redis/Valkey + `pip install redis` for --redis.
python -m pytest -q tests        # 9 tests, including the published JA3 and JA4 reference vectors
```

## Quick start

```bash
python -m tlsfp ifaces                                    # find your interface name
python -m tlsfp live -i "Wi-Fi" --resolve-process -v      # live fingerprints + owning process
python -m tlsfp analyze some.pcap --show-server           # offline
python -m tlsfp report                                    # historical report from the DB
```

Real live output (`proc=` is the OS ground truth, `=>` is the fingerprint verdict). Note
Chrome's three connections within one second: **three different JA3s, one JA4**:
```
22:22:23.059 CH 10.7.37.4:58027 -> 103.102.166.224:443 sni=www.wikipedia.org  proc=curl.exe
    JA3 fae0e5d973c96ae1888b99538efa0363   JA4 t13d2013h1_2b729b4bf6f3_e24568c0d440
    => curl (Windows/Schannel) via ja4+ja3
22:22:25.777 CH 10.7.37.4:58035 -> 103.102.166.224:443 sni=www.wikipedia.org  proc=python.exe
    JA3 331a436afb23d4e31134c11b301bdcb5   JA4 t13d1813h1_85036bcba153_d339722ba4af
    => Python urllib (OpenSSL) via ja4+ja3
22:22:28.243 CH 10.7.37.4:58040 -> 103.102.166.224:443 sni=www.wikipedia.org  proc=python.exe
    JA3 c486fa9f911d4de497fa6c84b456789c   JA4 t12d100600_ef2f9671594d_bb157cc35868
    => Handcrafted raw TLS client via ja4+ja3
22:22:31.431 CH 10.7.37.4:56424 -> 103.102.166.224:443 sni=www.wikipedia.org  proc=chrome.exe
    JA3 fbd6bc2fb817dc35778cc4d5ccb2970a   JA4 t13d1517h2_8daaf6152771_cb7bf5808d99
    => Google Chrome via ja4
22:22:31.466 CH 10.7.37.4:52544 -> 103.102.166.224:443 sni=www.wikipedia.org  proc=chrome.exe
    JA3 a72bbc955ab709ed435b6c157ca77e74   JA4 t13d1517h2_8daaf6152771_cb7bf5808d99
    => Google Chrome via ja4
22:22:32.200 CH 10.7.37.4:62034 -> 103.102.166.224:443 sni=en.wikipedia.org  proc=chrome.exe
    JA3 66aba877588de8c54c0988ae6fe6ac47   JA4 t13d1517h2_8daaf6152771_cb7bf5808d99
    => Google Chrome via ja4
```

The curated reference set ships as `data/reference_db.json`. Load it with
`python -m tlsfp db import data/reference_db.json`. Fingerprints depend on client
versions, so re-learn them on your own machine for a live demo.

## Reproducing the experiment

```bash
# 1. Training capture: start the sniffer, then drive 8 real clients (3 runs each)
python -m tlsfp live -i "Wi-Fi" -f "tcp port 443" -w captures/train.pcap -t 110 --no-record
python scripts/gen_traffic.py --wait 6 --repeat 3 -o captures/train_manifest.json   # 2nd terminal

# 2. Build the reference DB from the labelled capture and check fingerprint stability
python -m tlsfp learn captures/train.pcap --manifest captures/train_manifest.json

# 3. Validate the extractor against Wireshark's independent implementation
python -m tlsfp validate captures/train.pcap

# 4. Held-out test capture, including two spoofing clients impersonating Chrome
python -m tlsfp live -i "Wi-Fi" -f "tcp port 443" -w captures/test.pcap -t 100 --no-record
python scripts/gen_traffic.py --wait 6 --repeat 2 -o captures/test_manifest.json \
       --spoof-ja3 "<Chrome ja3_full from DB>" --spoof-ja4r "<Chrome ja4_r from DB>" \
       --spoof-label "SPOOF: raw client impersonating Chrome"
python -m tlsfp evaluate captures/test.pcap --manifest captures/test_manifest.json            # JA4 then JA3
python -m tlsfp evaluate captures/test.pcap --manifest captures/test_manifest.json --ja3-only
```

`gen_traffic.py` runs each client as a separate process, in sequence, and records the
`[start, end]` window and target SNI. `learn` and `evaluate` attach labels to ClientHellos
with those windows. Browsers run headless with a fresh profile and `--disable-quic` so that
they use TCP; HTTP/3 over QUIC is not captured.

## Results (Windows 11, Chrome, Edge, curl 8.21/Schannel, Python 3.13/OpenSSL 3.0)

### 1. Extractor validation

| Check | Result |
|---|---|
| Salesforce README vector `769,47-53-5-…,0` → `ada70206e40642a3e4461f35503241d5` | pass (unit test) |
| FoxIO spec vector → `t13d1516h2_8daaf6152771_e5627efa2ab1` | pass (unit test) |
| JA3 vs Wireshark 4.6.7 (train + test, 276 ClientHellos) | **276/276 (100%)** |
| JA3S vs Wireshark 4.6.7 (241 ServerHellos) | **241/241 (100%)** |
| JA4 vs Wireshark 4.6.7 | 64 exact + 212 identical after removing tshark's GREASE sigalg, **0 real mismatches** |

**Finding:** current Chrome and Edge put a **GREASE value inside `signature_algorithms`**
(for example `aaaa`). The JA4 spec says GREASE is ignored, and `tlsfp` does that.
Wireshark 4.6.7 keeps it, so Wireshark's JA4 for Chrome changes on every connection
while ours stays stable. `validate` detects and reports this case separately.

### 2. Reference database (learned): 8 distinct clients

| Client | TLS stack | JA4 |
|---|---|---|
| Google Chrome | BoringSSL | `t13d1517h2_8daaf6152771_cb7bf5808d99` |
| Microsoft Edge | BoringSSL | `t13d1516h2_8daaf6152771_806a8c22fdea`, `t13d1517h2_8daaf6152771_a87ad97598a9` |
| curl 8.21 (Windows) | Schannel | `t13d2013h1_2b729b4bf6f3_e24568c0d440` |
| PowerShell Invoke-WebRequest | .NET → Schannel | `t13d201100_2b729b4bf6f3_36bf25f296df` |
| Python urllib | OpenSSL 3.0 | `t13d1813h1_85036bcba153_d339722ba4af` |
| Python requests | OpenSSL 3.0 | `t13d1812h1_85036bcba153_b26ce05bbdd6` |
| Custom Python script (TLS 1.2, 3 ciphers) | OpenSSL 3.0 | `t12d040700_1905ac1fb84a_e7e480e5a997` |
| Handcrafted raw TLS client | none (hand-built bytes) | `t12d100600_ef2f9671594d_bb157cc35868` |

How to read these: the **cipher hash** (middle part) identifies the TLS *library*. Chrome
and Edge share `8daaf6152771` (BoringSSL), curl and PowerShell share `2b729b4bf6f3`
(Schannel), and urllib and requests share `85036bcba153` (OpenSSL). The **ALPN, counts and
extension hash** separate the *applications* built on the same library.

### 3. Held-out identification (`evaluate`, 24 ClientHellos)

| Ground truth | JA4 → JA3 fallback | JA3 only |
|---|---|---|
| Chrome (4) | Chrome ×4 | **UNKNOWN ×4** |
| Edge (4) | Edge ×4 | **UNKNOWN ×4** |
| curl, PowerShell, urllib, requests, custom script, handcrafted (2 each) | all correct | all correct |
| SPOOF: raw client replaying Chrome's JA3 (2) | Chrome ×2 (**fooled**) | Chrome ×2 (**fooled**) |
| SPOOF: raw client replaying Chrome's JA4_r (2) | Chrome ×2 (**fooled**) | UNKNOWN ×2 |
| **Legitimate clients** | **20/20 = 100%** | 12/20 = 60% |

### 4. Fingerprint stability (`stability`)

| Client | Connections | Distinct JA3 | Distinct JA4 |
|---|---|---|---|
| Chrome (train) | 6 | **6** | 1 |
| Chrome (test) | 4 | **4** | 1 |
| Edge (train) | 9 | **9** | 2 (with or without a session-resumption extension) |
| Every non-browser client | n | 1 | 1 |

Since 2023, Chrome **randomizes the order of its TLS extensions** on every connection
(Chrome 110+). JA3 hashes extensions in wire order, so every Chrome connection gets a new
JA3 and exact-match JA3 lists stop working for browsers. JA4 **sorts** ciphers and
extensions before hashing, which removes the randomization.

## Security monitoring: what fingerprinting is good for

* **Malware/C2 detection.** Implants often use a TLS stack their host OS wouldn't use, or
  hard-coded cipher lists (Cobalt Strike, Metasploit, Trickbot and others have
  published JA3/JA4 fingerprints). Load the abuse.ch list with
  `python -m tlsfp db import-sslbl ja3_fingerprints.csv` and any match is flagged red.
  Because detection works on any port, C2 on unusual ports is also covered.
* **User-Agent mismatch.** A request claiming `User-Agent: Chrome` whose handshake is
  Python/OpenSSL is a bot or scraper. This works without decryption, at the network edge.
* **Asset inventory and policy.** Find unmanaged clients, old TLS 1.0/1.2-only libraries,
  or a `curl.exe` running on servers that should never use it.
* **JA3S/JA4S** fingerprint the *server's* response to a given client. Together with the
  client fingerprint, a (JA4, JA4S) pair identifies specific C2 frameworks more precisely
  than either alone.

## Limitations and evasion

1. **Fingerprints identify the TLS library, not the application.** Anything built on
   Schannel looks like Windows. Chrome and Edge share BoringSSL; here they only separate by one extension.
2. **Extension-order randomization** (Chrome 110+) breaks JA3 for browsers (shown
   above). JA4 fixes this specific problem.
3. **Spoofing is easy.** `custom_tls_client.py` reproduced Chrome's JA3 and JA4 exactly
   from a 150-line script. Real tools such as uTLS, curl-impersonate and tls-client do this
   for real connections. Fingerprints are evidence, not proof of identity.
4. **Collisions.** Popular libraries are shared by benign and malicious software. A
   Python-based implant has the same fingerprint as `requests`, so malware lists have false
   positives.
5. **Drift.** Browsers change their fingerprint with each release (new extensions, for example
   post-quantum `X25519MLKEM768` = group `4588`, ECH = `fe0d`), so the DB needs maintenance.
   Edge already shows two JA4s depending on whether it resumes a session.
6. **Visibility.** QUIC/HTTP3 (UDP) isn't covered here. The hello is inside QUIC Initial
   packets, which must be decrypted with keys derived from the connection ID. ECH hides the
   inner hello's SNI, but the outer hello is still fingerprintable.

## Commands

```
python -m tlsfp [--db tlsfp.db] <command>
  ifaces                                  list capture interfaces
  live      [-i IF] [-f BPF] [-w out.pcap] [--resolve-process] [--auto-learn] [--json] [--redis URL]
  analyze   PCAP [--show-server] [--record] [--json] [-v]
  learn     PCAP (--manifest M | --label L [--sni S] [--category C])
  evaluate  PCAP --manifest M [--ja3-only | --ja4-only]
  stability PCAP --manifest M
  validate  PCAP                          compare with tshark
  report    [--hours N]                   history: verdict counts, top unknowns, malware hits
  db list | add | remove | export | import | import-sslbl | import-csv | sync-redis
```

## Layout

```
tlsfp/tls_parser.py      ClientHello/ServerHello parser, GREASE detection
tlsfp/fingerprints.py    JA3, JA3S, JA4, JA4S
tlsfp/flows.py           TCP reassembly + ClientHello/ServerHello session pairing
tlsfp/capture.py         Scapy live/pcap sources, psutil process attribution
tlsfp/db.py              SQLite reference DB + observations, importers, Redis mirror
tlsfp/validate.py        tshark cross-check
tlsfp/builder.py         ClientHello builder (custom client, spoofing, tests)
tlsfp/cli.py             CLI
scripts/gen_traffic.py   labelled traffic from 8 real clients + manifest
scripts/custom_tls_client.py   handcrafted client / JA3 & JA4 impersonation
tests/                   unit tests (reference vectors, GREASE, reassembly, pairing)
```

## Possible extensions

* **eBPF/XDP capture** on Linux: an XDP or TC program that copies only TCP payloads starting with
  `16 03 0x 01/02` to a ring buffer, so user space never sees bulk traffic. This
  scales to line rate; the parser and fingerprint code here are reused unchanged.
* **TRex / flow generators**: replay the captured hellos at high rates to benchmark throughput.
* **Redis/Valkey**: `db sync-redis redis://host:6379` and `live --redis ...` let many sensors
  share one reference set.
* **JA4 for QUIC** (`q` prefix): decrypt QUIC Initial packets and reuse the same parser.

JA4 (client) is BSD-3 licensed. JA4S and the other JA4+ methods are under the FoxIO License 1.1,
which allows academic and non-commercial use.
