from scapy.all import *
import struct

# ============================================================
# TCP Options Length Mismatch — Full Matrix PoC (FIXED)
# Raw TCP header construction — bypasses Scapy options parser
# IP() / Raw(manual_tcp_bytes) method
# ============================================================

TARGET = "192.31.242.65"

# ── Destination Port Array ────────────────────────────────────
DPORT_LIST = [80, 443, 8080, 8443, 22, 21, 25, 53]

# ── TTL Array ─────────────────────────────────────────────────
TTL_LIST = [10,11]

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
        # ── dataofs=5 → 0 bytes ──────────────────────────────────
    5: [
        ("No options (bare)",            b''),
    ],

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

    # ── dataofs=7 → 8 bytes ──────────────────────────────────
    7: [
        ("NOP×8",                        b'\x01'*8),
        ("MSS+SACK-OK+NOP×2",            b'\x02\x04\x05\xb4\x04\x02\x01\x01'),
        ("MSS+WinScale+NOP×1",           b'\x02\x04\x05\xb4\x03\x03\x06\x01'),
        ("MSS+MSS malformed",            b'\x02\x04\x05\xb4\x02\x04\xff\xff'),
        ("TS Kind=8 Len=10 MISMATCH+NOP×2", b'\x08\x0a\x00\x00\x01\x01\x01\x01'),
        ("SACK+TS MISMATCH chain",       b'\x05\x0a\x08\x0a\x00\x00\x01\x01'),
        ("WinScale×2 chain",             b'\x03\x03\x0e\x01\x03\x03\xff\x01'),
        ("Unknown Kind=255 Len=8 exact", b'\xff\x08\x00\x00\x00\x00\x00\x00'),
        ("RFC-Exp-253 ×2",               b'\xfd\x04\x00\x00\xfd\x04\x00\x00'),
        ("EOL early exit+NOP×7",         b'\x00\x01\x01\x01\x01\x01\x01\x01'),
        ("Obsolete Echo Kind=6 MISMATCH",b'\x06\x06\x00\x00\x00\x00\x01\x01'),
    ],

    # ── dataofs=8 → 12 bytes ─────────────────────────────────
    8: [
        ("NOP×12",                       b'\x01'*12),
        ("MSS+SACK-OK+WinScale+NOP×3",   b'\x02\x04\x05\xb4\x04\x02\x03\x03\x06\x01\x01\x01'),
        ("TS full valid 10B+NOP×2",      b'\x08\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01'),
        ("TS Kind=8 Len=10 MISMATCH+NOP×6", b'\x08\x0a\x00\x00\x00\x00\x01\x01\x01\x01\x01\x01'),
        ("MSS+TS MISMATCH chain+NOP×2",  b'\x02\x04\x05\xb4\x08\x0a\x00\x00\x01\x01\x01\x01'),
        ("SACK Len=10 MISMATCH+NOP×6",   b'\x05\x0a\x00\x00\x00\x00\x01\x01\x01\x01\x01\x01'),
        ("WinScale+SACK+TS MISMATCH",    b'\x03\x03\x06\x01\x04\x02\x08\x0a\x00\x00\x01\x01'),
        ("Unknown×3 MISMATCH chain",     b'\xff\x08\x00\x00\xfd\x04\x00\x00\xfe\x04\x00\x00'),
        ("EOL early+NOP×11",             b'\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01'),
        ("Obsolete EchoReply chain",     b'\x07\x06\x00\x00\x06\x06\x00\x00\x01\x01\x01\x01'),
    ],

    # ── dataofs=9 → 16 bytes ─────────────────────────────────
    9: [
        ("NOP×16",                       b'\x01'*16),
        ("MSS+SACK-OK+WinScale+TS full", b'\x02\x04\x05\xb4\x04\x02\x03\x03'
                                         b'\x06\x01\x08\x0a\x00\x00\x00\x00'),
        ("TS MISMATCH+NOP×10",           b'\x08\x0a\x00\x00\x00\x00\x01\x01'
                                         b'\x01\x01\x01\x01\x01\x01\x01\x01'),
        ("SACK blocks Len=18 MISMATCH",  b'\x05\x12\x00\x00\x00\x00\x00\x00'
                                         b'\x00\x00\x00\x00\x01\x01\x01\x01'),
        ("MSS×4 chain malformed",        b'\x02\x04\xff\xff\x02\x04\x00\x00'
                                         b'\x02\x04\x05\xb4\x02\x04\x05\xdc'),
        ("Unknown Kind=255 Len=16 exact",b'\xff\x10\x00\x00\x00\x00\x00\x00'
                                         b'\x00\x00\x00\x00\x00\x00\x00\x00'),
        ("EOL early+NOP×15",             b'\x00\x01\x01\x01\x01\x01\x01\x01'
                                         b'\x01\x01\x01\x01\x01\x01\x01\x01'),
    ],

    # ── dataofs=10 → 20 bytes ────────────────────────────────
    10: [
        ("NOP×20",                       b'\x01'*20),
        ("MSS+SACK+WinScale+TS+NOP×6",   b'\x02\x04\x05\xb4\x04\x02\x03\x03'
                                         b'\x06\x01\x08\x0a\x00\x00\x00\x00'
                                         b'\x00\x00\x01\x01'),
        ("TS MISMATCH Len=10+NOP×14",    b'\x08\x0a\x00\x00\x00\x00\x01\x01'
                                         b'\x01\x01\x01\x01\x01\x01\x01\x01'
                                         b'\x01\x01\x01\x01'),
        ("SACK Len=18+8B data+NOP×6",    b'\x05\x12\x00\x00\x00\x00\x00\x00'
                                         b'\x00\x00\x00\x00\x00\x00\x00\x00'
                                         b'\x01\x01\x01\x01'),
        ("Unknown×5 MISMATCH chain",     b'\xff\x08\x00\x00\xfd\x04\x00\x00'
                                         b'\xfe\x04\x00\x00\xff\x08\x00\x00'
                                         b'\xfd\x04\x00\x00'),
        ("EOL early+NOP×19",             b'\x00\x01\x01\x01\x01\x01\x01\x01'
                                         b'\x01\x01\x01\x01\x01\x01\x01\x01'
                                         b'\x01\x01\x01\x01'),
    ],

    # ── dataofs=11 → 24 bytes ────────────────────────────────
    11: [
        ("NOP×24",                       b'\x01'*24),
        ("TS full+SACK+WinScale+MSS+NOP×8",
                                         b'\x08\x0a\x00\x00\x00\x00\x00\x00'
                                         b'\x00\x00\x04\x02\x03\x03\x06\x01'
                                         b'\x02\x04\x05\xb4\x01\x01\x01\x01'),
        ("TS MISMATCH Len=10+NOP×18",    b'\x08\x0a\x00\x00\x00\x00\x01\x01'
                                         b'\x01\x01\x01\x01\x01\x01\x01\x01'
                                         b'\x01\x01\x01\x01\x01\x01\x01\x01'),
        ("Unknown Kind=255 Len=24 exact",b'\xff\x18' + b'\x00'*22),
        ("EOL early+NOP×23",             b'\x00' + b'\x01'*23),
    ],

    # ── dataofs=12 → 28 bytes ────────────────────────────────
    12: [
        ("NOP×28",                       b'\x01'*28),
        ("TS+SACK+WinScale+MSS+TS2+NOP", b'\x08\x0a\x00\x00\x00\x00\x00\x00'
                                         b'\x00\x00\x04\x02\x03\x03\x06\x01'
                                         b'\x02\x04\x05\xb4\x08\x0a\xff\xff'
                                         b'\xff\xff\x01\x01'),
        ("TS MISMATCH Len=10+NOP×22",    b'\x08\x0a\x00\x00\x00\x00\x01\x01'
                                         b'\x01'*20),
        ("Unknown Kind=255 Len=28 exact",b'\xff\x1c' + b'\x00'*26),
        ("EOL early+NOP×27",             b'\x00' + b'\x01'*27),
    ],

    # ── dataofs=13 → 32 bytes ────────────────────────────────
    13: [
        ("NOP×32",                       b'\x01'*32),
        ("TS MISMATCH+NOP×26",           b'\x08\x0a\x00\x00\x00\x00\x01\x01'
                                         b'\x01'*24),
        ("Unknown Kind=255 Len=32 exact",b'\xff\x20' + b'\x00'*30),
        ("MSS×8 chain",                  b'\x02\x04\x05\xb4' * 8),
        ("EOL early+NOP×31",             b'\x00' + b'\x01'*31),
    ],

    # ── dataofs=14 → 36 bytes ────────────────────────────────
    14: [
        ("NOP×36",                       b'\x01'*36),
        ("TS MISMATCH+NOP×30",           b'\x08\x0a\x00\x00\x00\x00\x01\x01'
                                         b'\x01'*28),
        ("Unknown Kind=255 Len=36 exact",b'\xff\x24' + b'\x00'*34),
        ("MSS×9 chain",                  b'\x02\x04\x05\xb4' * 9),
        ("EOL early+NOP×35",             b'\x00' + b'\x01'*35),
    ],

    # ── dataofs=15 → 40 bytes (MAX) ──────────────────────────
    15: [
        ("NOP×40 (max)",                 b'\x01'*40),
        ("TS MISMATCH+NOP×34",           b'\x08\x0a\x00\x00\x00\x00\x01\x01'
                                         b'\x01'*32),
        ("Unknown Kind=255 Len=40 exact",b'\xff\x28' + b'\x00'*38),
        ("MSS×10 chain (max)",           b'\x02\x04\x05\xb4' * 10),
        ("EOL early+NOP×39",             b'\x00' + b'\x01'*39),
        ("Full MISMATCH storm",          b'\x08\x0a\x05\x12\xff\x28\x08\x0a'
                                         b'\x05\x12\xff\x28\x08\x0a\x05\x12'
                                         b'\xff\x28\x08\x0a\x05\x12\xff\x28'
                                         b'\xff\x28\x08\x0a\x05\x12\xff\x28'
                                         b'\xff\x28\x08\x0a\x05\x12\xff\x28'),
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
                        send(pkt, verbose=0)

print("=" * 72)
print(f"[✓] Matrix complete — {pkt_count} packets sent to {TARGET}")
print("[i] Wireshark : tcp.options || tcp.hdr_len >= 20")
print(f"[i] tcpdump   : tcpdump -i eth0 'tcp and host {TARGET}'")
