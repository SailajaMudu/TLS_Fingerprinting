"""Generate labelled TLS traffic from many real clients and write a ground-truth manifest.

Run a capture at the same time (python -m tlsfp live -w capture.pcap, or Wireshark),
then:  python -m tlsfp learn capture.pcap --manifest manifest.json

Each client is run --repeat times, one at a time; the manifest records the label and
the [start, end] window so the learner can attach labels to the ClientHellos.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable

CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
FIREFOX = r"C:\Program Files\Mozilla Firefox\firefox.exe"


def _browser(exe: str):
    def cmd(url: str) -> list[str]:
        profile = tempfile.mkdtemp(prefix="tlsfp_profile_")
        return [exe, "--headless=new", "--disable-quic", "--no-first-run",
                "--no-default-browser-check", "--disable-extensions",
                f"--user-data-dir={profile}", "--dump-dom", url]
    return cmd


def clients() -> dict[str, dict]:
    py_urllib = "import urllib.request,sys; urllib.request.urlopen(sys.argv[1], timeout=15).read(100)"
    py_requests = "import requests,sys; requests.get(sys.argv[1], timeout=15)"
    py_custom = (
        "import ssl,socket,sys,urllib.parse as u; h=u.urlparse(sys.argv[1]).hostname;"
        "c=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); c.maximum_version=ssl.TLSVersion.TLSv1_2;"
        "c.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:AES256-SHA');"
        "c.check_hostname=False; c.verify_mode=ssl.CERT_NONE;"
        "s=c.wrap_socket(socket.create_connection((h,443),timeout=10),server_hostname=h); s.close()")
    c = {
        "curl": dict(label="curl (Windows/Schannel)", category="cli",
                     cmd=lambda url: ["curl.exe", "-s", "-o", os.devnull, url]),
        "powershell": dict(label="PowerShell Invoke-WebRequest (.NET)", category="cli",
                           cmd=lambda url: ["powershell", "-NoProfile", "-Command",
                                            f"Invoke-WebRequest -UseBasicParsing '{url}' | Out-Null"]),
        "python-urllib": dict(label="Python urllib (OpenSSL)", category="library",
                              cmd=lambda url: [PY, "-c", py_urllib, url]),
        "python-requests": dict(label="Python requests (OpenSSL)", category="library",
                                cmd=lambda url: [PY, "-c", py_requests, url]),
        "python-custom": dict(label="Custom Python script (TLS1.2, 3 ciphers)", category="custom",
                              cmd=lambda url: [PY, "-c", py_custom, url]),
        "handcrafted": dict(label="Handcrafted raw TLS client", category="custom",
                            cmd=lambda url: [PY, os.path.join(HERE, "custom_tls_client.py"),
                                             url.split("/")[2], "--quiet"]),
    }
    if os.path.exists(CHROME):
        c["chrome"] = dict(label="Google Chrome", category="browser", cmd=_browser(CHROME))
    if os.path.exists(EDGE):
        c["edge"] = dict(label="Microsoft Edge", category="browser", cmd=_browser(EDGE))
    if os.path.exists(FIREFOX):
        c["firefox"] = dict(label="Mozilla Firefox", category="browser",
                            cmd=lambda url: [FIREFOX, "--headless", "--screenshot",
                                             os.path.join(tempfile.gettempdir(), "ff.png"), url])
    if not shutil.which("curl.exe") and shutil.which("curl"):
        c["curl"]["cmd"] = lambda url: ["curl", "-s", "-o", os.devnull, url]
        c["curl"]["label"] = "curl"
    return c


def main() -> None:
    all_clients = clients()
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="www.wikipedia.org")
    ap.add_argument("--repeat", type=int, default=3)
    ap.add_argument("--clients", default=",".join(all_clients),
                    help=f"comma list from: {','.join(all_clients)}")
    ap.add_argument("--spoof-ja3", help="also run the raw client impersonating this JA3 string")
    ap.add_argument("--spoof-ja4r", help="also run the raw client impersonating this JA4_r")
    ap.add_argument("--spoof-label", default="SPOOFED client")
    ap.add_argument("--gap", type=float, default=2.0, help="pause between runs (s)")
    ap.add_argument("-o", "--manifest", default="manifest.json")
    ap.add_argument("--wait", type=float, default=0.0,
                    help="seconds to wait before starting (lets a capture start up)")
    args = ap.parse_args()
    time.sleep(args.wait)

    url = f"https://{args.host}/"
    chosen = {k: all_clients[k] for k in args.clients.split(",") if k in all_clients}
    custom_script = os.path.join(HERE, "custom_tls_client.py")
    if args.spoof_ja3:
        chosen["spoof-ja3"] = dict(label=args.spoof_label, category="spoof",
                                   cmd=lambda u: [PY, custom_script, args.host, "--quiet",
                                                  "--ja3", args.spoof_ja3])
    if args.spoof_ja4r:
        chosen["spoof-ja4r"] = dict(label=args.spoof_label, category="spoof",
                                    cmd=lambda u: [PY, custom_script, args.host, "--quiet",
                                                   "--ja4r", args.spoof_ja4r])

    runs = []
    for name, c in chosen.items():
        for i in range(args.repeat):
            cmd = c["cmd"](url)
            start = time.time()
            try:
                subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=40)
                status = "ok"
            except subprocess.TimeoutExpired:
                status = "timeout"
            except FileNotFoundError:
                status = "missing"
            end = time.time()
            runs.append(dict(client=name, label=c["label"], category=c["category"],
                             sni=args.host, start=start, end=end, status=status))
            print(f"[{status:7}] {c['label']:45} run {i + 1}/{args.repeat} ({end - start:.1f}s)")
            time.sleep(args.gap)

    with open(args.manifest, "w", encoding="utf-8") as f:
        json.dump({"host": args.host, "runs": runs}, f, indent=2)
    print(f"manifest -> {args.manifest}")


if __name__ == "__main__":
    main()
