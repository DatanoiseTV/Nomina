#!/usr/bin/env python3
"""Minimal DHCPv4 test client for exercising a local Nomina DHCP server.

Sends a DISCOVER, waits for the OFFER, sends a REQUEST, and prints the ACK
(assigned address, lease, next-server/bootfile for PXE, and all options).

DHCP uses privileged UDP ports (67/68), so this must run as root:

    # terminal 1 — run the server with DHCP enabled (see nomina.toml [dhcp])
    sudo ./target/release/nomina --config nomina.toml

    # terminal 2 — probe it
    sudo python3 scripts/dhcp_probe.py            # broadcast on the LAN
    sudo python3 scripts/dhcp_probe.py 127.0.0.1  # unicast to a loopback server

The server broadcasts its replies to 255.255.255.255:68, so this binds
0.0.0.0:68 to catch them. On a single host this works on Linux and usually on
macOS; if you see no OFFER, run it from another device on the same L2 segment
instead. No third-party dependencies.
"""

import random
import socket
import struct
import sys
import time

MAGIC = bytes([99, 130, 83, 99])
SERVER = sys.argv[1] if len(sys.argv) > 1 else "255.255.255.255"
XID = random.randint(0, 0xFFFFFFFF)
MAC = bytes([0x02, 0x00, 0x00, random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)])


def build(msg_type, opts):
    pkt = struct.pack(
        "!BBBBIHHIIII16s64s128s",
        1, 1, 6, 0, XID, 0, 0x8000,  # op, htype, hlen, hops, xid, secs, flags=broadcast
        0, 0, 0, 0,                  # ciaddr, yiaddr, siaddr, giaddr
        MAC + b"\x00" * 10, b"", b"",
    )
    pkt += MAGIC
    pkt += bytes([53, 1, msg_type])
    for code, val in opts:
        pkt += bytes([code, len(val)]) + val
    pkt += bytes([255])
    return pkt


def parse_opts(data):
    i = 240
    out = {}
    while i < len(data):
        c = data[i]
        if c == 255:
            break
        if c == 0:
            i += 1
            continue
        ln = data[i + 1]
        out[c] = data[i + 2 : i + 2 + ln]
        i += 2 + ln
    return out


def show(label, data):
    yi = socket.inet_ntoa(data[16:20])
    si = socket.inet_ntoa(data[20:24])
    fname = data[108:236].split(b"\x00", 1)[0].decode(errors="replace")
    opts = parse_opts(data)
    print(f"\n=== {label} ===")
    print(f"  your address (yiaddr): {yi}")
    print(f"  next-server (siaddr):  {si}")
    if fname:
        print(f"  bootfile (file):       {fname}")
    if 51 in opts:
        print(f"  lease time:            {struct.unpack('!I', opts[51])[0]}s")
    if 1 in opts:
        print(f"  subnet mask:           {socket.inet_ntoa(opts[1])}")
    if 3 in opts:
        print(f"  routers:               {socket.inet_ntoa(opts[3][:4])}")
    if 6 in opts:
        print(f"  dns:                   {socket.inet_ntoa(opts[6][:4])}")
    if 67 in opts:
        print(f"  bootfile (opt 67):     {opts[67].decode(errors='replace')}")
    if 60 in opts:
        print(f"  vendor class (opt 60): {opts[60].decode(errors='replace')}")
    other = sorted(k for k in opts if k not in (1, 3, 6, 51, 53, 54, 60, 67))
    if other:
        print(f"  other options:         {other}")
    return yi, opts


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind(("", 68))
    s.settimeout(5)

    print(f"DISCOVER -> {SERVER}:67  (mac {MAC.hex(':')}, xid {XID:#x})")
    s.sendto(build(1, []), (SERVER, 67))
    try:
        data, _ = s.recvfrom(2048)
    except socket.timeout:
        print("no OFFER received (timeout). See the note in this script's header.")
        return 1
    yi, opts = show("OFFER", data)

    sid = opts.get(54, socket.inet_aton(SERVER) if SERVER != "255.255.255.255" else b"\0\0\0\0")
    req_opts = [(50, socket.inet_aton(yi)), (54, sid)]
    time.sleep(0.2)
    print(f"\nREQUEST {yi} -> {SERVER}:67")
    s.sendto(build(3, req_opts), (SERVER, 67))
    try:
        data, _ = s.recvfrom(2048)
        show("ACK", data)
        print("\nLease acquired. Check the DHCP page / leases table in the UI.")
    except socket.timeout:
        print("no ACK received (timeout).")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
