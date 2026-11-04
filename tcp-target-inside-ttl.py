from scapy.all import *
import struct
import random
import string

# ============================================================
# TCP Options Length Mismatch — Full Matrix PoC v4
# Changes from v3:
#   - TLS_METHODS_LIST removed completely
#   - TLS flow is now version-driven automatically:
#       TLS 1.0 / 1.1 / 1.2 → ClientHello → ClientKeyExchange → Finished
#       TLS 1.3             → ClientHello (key_share + supported_versions)
#                                        → Finished  (no ClientKeyExchange)
#   - Each version entry in TLS_VERSIONS_LIST triggers its correct flow
#   - All other behaviour from v3 preserved
# ============================================================

#

TARGET = "192.31.242.45"

# ── Destination Port Array ────────────────────────────────────
DPORT_LIST = [443]

# ── SYN TTL — Fixed Single Value ─────────────────────────────
SYN_TTL = 17

# ── ACK TTL Array — Applied to ACK packets ───────────────────
TTL_LIST = [17,18,19,20]

# ── IP Protocol Array ─────────────────────────────────────────
IP_PROTO_LIST = [6]

# ── TCP Probe Flags ───────────────────────────────────────────
TCP_PROBE_FLAGS_LIST = ["S"]

# ── ACK Payload Config ────────────────────────────────────────
ACK_PAYLOAD_MIN_LEN = 8
ACK_PAYLOAD_MAX_LEN = 64

# ── ACK Packet Count ──────────────────────────────────────────
# How many ACK packets to send per TTL value
# Matrix: ACK_PACKET_COUNT × len(TTL_LIST) ACKs per session
# e.g. ACK_PACKET_COUNT=4, TTL_LIST=[10,11,12] → 12 ACKs/session
#        TTL=10: 4 ACKs | TTL=11: 4 ACKs | TTL=12: 4 ACKs
ACK_PACKET_COUNT = 1

# ============================================================
# TLS CONFIG
# ── TLS On/Off Toggle ────────────────────────────────────────
# True  → TLS handshake flow runs after each ACK phase
# False → TLS phase skipped entirely; only SYN + ACK sent
TLS_ENABLED = True

# ── SNI Name ─────────────────────────────────────────────────
SNI_NAME = "adfs.spacex.com"           # ← user sets this

# ── TLS Versions Array ───────────────────────────────────────
# Format : (label, major, minor)
# Flow is selected automatically per version — no method list needed
#
#   TLS 1.0 (3,1) → ClientHello → ClientKeyExchange → Finished
#   TLS 1.1 (3,2) → ClientHello → ClientKeyExchange → Finished
#   TLS 1.2 (3,3) → ClientHello → ClientKeyExchange → Finished
#   TLS 1.3 (3,4) → ClientHello (key_share ext)     → Finished
#
# Comment/uncomment versions to include or exclude
TLS_VERSIONS_LIST = [
    #("TLS1.0", 0x03, 0x01),
    #("TLS1.1", 0x03, 0x02),
    ("TLS1.2", 0x03, 0x03),
    # ("TLS1.3", 0x03, 0x04),
]

#============================================================
# DATAOFS → OPTIONS MAPPING  ← user config — top of script
# options_window = (dataofs × 4) - 20
# All option bytes must match window size exactly
# Common for ALL packets: SYN + ACK + TLS
#
# ── Empty map {} behaviour ───────────────────────────────────
# If DATAOFS_OPTIONS_MAP = {} (nothing set) → default fallback:
#   dataofs=5, opt_bytes=b'' → plain 20B TCP header, no options
# ============================================================
DATAOFS_OPTIONS_MAP = {
   8: [
        ("MSS + SACK-PERM",             b'\x02\x04\x05\xb4'   # MSS=1460
                                         b'\x01\x01'           # NOP NOP
                                         b'\x04\x02'           # SACK Permitted
                                         b'\x00\x00\x00\x00'), # pad to 12
        ("MSS + WScale",                b'\x02\x04\x05\xb4'   # MSS=1460
                                         b'\x01'               # NOP
                                         b'\x03\x03\x06'       # WScale=6
                                         b'\x00\x00\x00'),     # pad to 12
    ]
   

}

# ============================================================
# FLAG STRING → INT CONVERTER
# ============================================================
FLAG_MAP = {
    'F': 0x01,
    'S': 0x02,
    'R': 0x04,
    'P': 0x08,
    'A': 0x10,
    'U': 0x20,
}

def flags_to_int(flags_str):
    val = 0
    for c in flags_str:
        val |= FLAG_MAP.get(c, 0)
    return val

# ============================================================
# RANDOM ALPHANUMERIC PAYLOAD GENERATOR
# charset: a-z A-Z 0-9 — fresh per call
# ============================================================
_ALNUM = (string.ascii_letters + string.digits).encode()

def random_payload():
    length  = random.randint(ACK_PAYLOAD_MIN_LEN, ACK_PAYLOAD_MAX_LEN)
    return bytes(random.choice(_ALNUM) for _ in range(length))

# ============================================================
# RAW TCP HEADER BUILDER
# Bypasses Scapy TCP options parser — struct.pack exact bytes
# TCP Header (20B base) + opt_bytes + payload
# ============================================================
def build_tcp_raw(sport, dport, flags_str, dataofs, opt_bytes,
                  seq=1000, ack_seq=0, payload=b''):
    fval        = flags_to_int(flags_str)
    offset_rsvd = (dataofs << 4) & 0xFF
    tcp_hdr = struct.pack('!HHIIBBHHH',
        sport, dport, seq, ack_seq,
        offset_rsvd, fval,
        8192,       # window
        0xabc0,     # checksum placeholder
        0           # urgptr
    )
    return tcp_hdr + opt_bytes + payload

# ============================================================
# TLS RECORD BUILDERS
# ============================================================

# ── Helper: wrap handshake body into TLS record ──────────────
def _tls_record(hs_type_byte, hs_body, tls_maj, tls_min):
    # Handshake header: type(1) + length(3)
    hs_hdr    = bytes([hs_type_byte]) + struct.pack('!I', len(hs_body))[1:]
    handshake = hs_hdr + hs_body
    # TLS Record: ContentType(1)=0x16 + version(2) + length(2) + handshake
    return (b'\x16'
            + struct.pack('!BB', tls_maj, tls_min)
            + struct.pack('!H', len(handshake))
            + handshake)

# ── ClientHello — TLS 1.0 / 1.1 / 1.2 ───────────────────────
# Extensions: SNI only
# Ciphersuites: TLS_RSA_WITH_AES_128_CBC_SHA (0x002F)
def build_client_hello_12(tls_maj, tls_min, sni_name):
    sni_b   = sni_name.encode()
    sni_ext = (b'\x00\x00'                           # ext type: server_name
               + struct.pack('!H',
                   2 + 1 + 2 + len(sni_b))           # ext data len
               + struct.pack('!H',
                   1 + 2 + len(sni_b))                # list len
               + b'\x00'                              # name type: host_name
               + struct.pack('!H', len(sni_b))
               + sni_b)
    exts    = sni_ext
    hs_body = (struct.pack('!BB', tls_maj, tls_min)      # client_version
               + bytes(random.randint(0,255) for _ in range(32))  # random
               + b'\x00'                                  # session_id len
               + b'\x00\x02\x00\x2f'                     # cipher_suites
               + b'\x01\x00'                              # compression
               + struct.pack('!H', len(exts)) + exts)    # extensions
    return _tls_record(0x01, hs_body, tls_maj, tls_min)

# ── ClientHello — TLS 1.3 ─────────────────────────────────────
# Outer version stays 0x0303 (TLS 1.2 compat)
# Extensions: supported_versions(0x002b)=0x0304
#             key_share(0x0033) with X25519 placeholder
#             SNI
def build_client_hello_13(sni_name):
    tls_maj, tls_min = 0x03, 0x03   # outer record version fixed for 1.3

    sni_b   = sni_name.encode()
    sni_ext = (b'\x00\x00'
               + struct.pack('!H', 2 + 1 + 2 + len(sni_b))
               + struct.pack('!H', 1 + 2 + len(sni_b))
               + b'\x00'
               + struct.pack('!H', len(sni_b))
               + sni_b)

    # supported_versions ext → TLS 1.3 (0x0304)
    sv_ext  = (b'\x00\x2b'          # ext type
               + b'\x00\x03'        # ext data len
               + b'\x02'            # versions list len
               + b'\x03\x04')       # TLS 1.3

    # key_share ext → X25519 (0x001d) with 32-byte random public key
    ks_key  = bytes(random.randint(0,255) for _ in range(32))
    ks_entry= b'\x00\x1d' + struct.pack('!H', 32) + ks_key   # group + key
    ks_ext  = (b'\x00\x33'
               + struct.pack('!H', 2 + len(ks_entry))
               + struct.pack('!H', len(ks_entry))
               + ks_entry)

    exts    = sni_ext + sv_ext + ks_ext

    hs_body = (struct.pack('!BB', tls_maj, tls_min)
               + bytes(random.randint(0,255) for _ in range(32))
               + b'\x00'
               + b'\x00\x02\x13\x01'   # TLS_AES_128_GCM_SHA256
               + b'\x01\x00'
               + struct.pack('!H', len(exts)) + exts)
    return _tls_record(0x01, hs_body, tls_maj, tls_min)

# ── ClientKeyExchange — TLS 1.0 / 1.1 / 1.2 only ────────────
# RSA: encrypted_pms_len(2) + 48 random bytes
def build_client_key_exchange(tls_maj, tls_min):
    pms     = bytes(random.randint(0,255) for _ in range(48))
    hs_body = struct.pack('!H', 48) + pms
    return _tls_record(0x10, hs_body, tls_maj, tls_min)

# ── Finished — both TLS 1.2 and 1.3 ─────────────────────────
# verify_data: 12 random bytes (simulates HMAC-SHA256 output)
def build_finished(tls_maj, tls_min):
    verify_data = bytes(random.randint(0,255) for _ in range(12))
    return _tls_record(0x14, verify_data, tls_maj, tls_min)

# ============================================================
# VERSION-DRIVEN TLS FLOW DISPATCHER
# Returns ordered list of (step_label, raw_bytes) for the version
#
#   TLS 1.0/1.1/1.2 → [ClientHello, ClientKeyExchange, Finished]
#   TLS 1.3         → [ClientHello(+key_share), Finished]
# ============================================================
def tls_flow_for_version(label, tls_maj, tls_min, sni_name):
    is_13 = (tls_maj == 0x03 and tls_min == 0x04)

    if is_13:
        return [
            (f"{label}/ClientHello(key_share)",  build_client_hello_13(sni_name)),
            (f"{label}/Finished",                build_finished(tls_maj, tls_min)),
        ]
    else:
        return [
            (f"{label}/ClientHello",             build_client_hello_12(tls_maj, tls_min, sni_name)),
            (f"{label}/ClientKeyExchange",       build_client_key_exchange(tls_maj, tls_min)),
            (f"{label}/Finished",                build_finished(tls_maj, tls_min)),
        ]

# ============================================================
# DATAOFS RESOLUTION
# DATAOFS_OPTIONS_MAP = {} → default: dataofs=5, no options
#   dataofs=5 → 20B TCP header, opt_bytes=b'' (standard, no opts)
# ============================================================
_RESOLVED_MAP = (
    DATAOFS_OPTIONS_MAP
    if DATAOFS_OPTIONS_MAP
    else {5: [("default(no-opts)", b'')]}
)

# ── Byte Verification ─────────────────────────────────────────
print("=" * 80)
print("  DATAOFS × OPTIONS BYTE VERIFICATION")
print("=" * 80)
all_ok = True
for dataofs, opt_list in sorted(_RESOLVED_MAP.items()):
    window = (dataofs * 4) - 20
    print(f"\n  dataofs={dataofs} → header={dataofs*4}B → options_window={window}B")
    for desc, raw in opt_list:
        ok     = len(raw) == window
        status = "✓" if ok else "✗ FAIL"
        if not ok:
            all_ok = False
        print(f"    [{status}] {len(raw):>2}B  {raw.hex() if raw else 'empty':20}  {desc}")

print("\n" + "=" * 80)
print(f"  Verification: {'ALL PASS ✓' if all_ok else 'FAILURES FOUND ✗'}")
print("=" * 80)

# ── Version → flow steps count ───────────────────────────────
def _flow_steps(tls_maj, tls_min):
    return 2 if (tls_maj == 0x03 and tls_min == 0x04) else 3

# ── Matrix Stats ──────────────────────────────────────────────
total_opts  = sum(len(v) for v in _RESOLVED_MAP.values())
total_syn   = (len(DPORT_LIST) * len(IP_PROTO_LIST)
               * len(TCP_PROBE_FLAGS_LIST) * total_opts)
total_ack   = total_syn * len(TTL_LIST) * ACK_PACKET_COUNT
total_tls   = (sum(
    total_syn * _flow_steps(maj, minn)
    for _, maj, minn in TLS_VERSIONS_LIST
) if TLS_ENABLED else 0)

print(f"  Target            : {TARGET}")
print(f"  Dport             : {DPORT_LIST}  ({len(DPORT_LIST)})")
print(f"  SYN TTL           : {SYN_TTL}  (fixed)")
print(f"  ACK TTL Array     : {TTL_LIST}  ({len(TTL_LIST)} values)")
print(f"  DataOfs           : {list(_RESOLVED_MAP.keys())}"
      f"{'  (default: no options)' if not DATAOFS_OPTIONS_MAP else ''}")
print(f"  Options           : {total_opts} variants")
print(f"  ACK Payload       : random alphanumeric {ACK_PAYLOAD_MIN_LEN}–{ACK_PAYLOAD_MAX_LEN}B/pkt")
print(f"  ACK Packet Count  : {ACK_PACKET_COUNT}/TTL  →  "
      f"{ACK_PACKET_COUNT} × {len(TTL_LIST)} TTLs = "
      f"{ACK_PACKET_COUNT * len(TTL_LIST)} ACKs/session")
print(f"  TLS Handshake     : {'ENABLED' if TLS_ENABLED else 'DISABLED'}")
if TLS_ENABLED:
    print(f"  SNI Name          : {SNI_NAME}")
    print()
    for lbl, maj, minn in TLS_VERSIONS_LIST:
        steps = [s for s,_ in tls_flow_for_version(lbl, maj, minn, "x")]
        print(f"  {lbl} flow          : {' → '.join(s.split('/')[1] for s in steps)}")
print()
print(f"  SYN Pkts          : {total_syn}")
print(f"  ACK Pkts          : {total_ack}  "
      f"({total_opts} opts × {len(TTL_LIST)} TTLs × {len(DPORT_LIST)} dports)")
print(f"  TLS Pkts (est)    : {total_tls if TLS_ENABLED else 'N/A (disabled)'}")
print(f"  Build method      : IP() / Raw(struct.pack TCP + payload)")
print("=" * 80)

# ============================================================
# MAIN LOOP
# Flow per session (proto × dport × flags × dataofs × opt_variant):
#
#   Step 1 — SYN          : fixed SYN_TTL
#   Step 2 — recv SYN-ACK : sr1()
#   Step 3 — ACK × TTL_LIST : random alnum payload per ACK
#   Step 4 — TLS flow     : version-driven sequence (PSH+ACK)
# ============================================================

syn_count  = 0
ack_count  = 0
tls_count  = 0
ack_payload_total_bytes = 0

print("\n[→] Starting three-way handshake + TLS matrix...\n")

for proto in IP_PROTO_LIST:
    for dport in DPORT_LIST:
        for flags in TCP_PROBE_FLAGS_LIST:
            for dataofs, opt_list in sorted(_RESOLVED_MAP.items()):
                for opt_desc, opt_bytes in opt_list:

                    sport   = random.randint(1024, 65535)

                    # ── Step 1 : SYN ─────────────────────────────────────
                    syn_seq = random.randint(0, 0xFFFFFFFF)
                    syn_raw = build_tcp_raw(
                                  sport, dport, flags,
                                  dataofs, opt_bytes,
                                  seq=syn_seq, ack_seq=0, payload=b'')
                    syn_pkt = IP(dst=TARGET, ttl=SYN_TTL, proto=proto) / Raw(syn_raw)

                    syn_count += 1
                    print(f"[SYN  {syn_count:>5}] "
                          f"TTL={SYN_TTL:>3}(fixed) | "
                          f"→{dport:<5} | "
                          f"Flags={flags:<4} | "
                          f"Ofs={dataofs}({(dataofs*4)-20:>2}B) | "
                          f"{opt_bytes[:4].hex():8}  {opt_desc}")

                    # ── Step 2 : recv SYN-ACK ────────────────────────────
                    synack = sr1(syn_pkt, timeout=1, retry=3, verbose=0)

                    if synack is None:
                        print(f"         [!] No SYN-ACK — skipping ACK+TLS phase")
                        continue

                    raw_sa = bytes(synack[Raw]) if synack.haslayer(Raw) else b''
                    if len(raw_sa) >= 12:
                        server_seq = struct.unpack('!I', raw_sa[4:8])[0]
                    else:
                        server_seq = synack[TCP].seq if synack.haslayer(TCP) else 0

                    ack_seq_val = server_seq + 1
                    cur_seq     = syn_seq + 1

                    # ── Step 3 : ACK matrix — TTL_LIST × ACK_PACKET_COUNT ─
                    # For each TTL → send ACK_PACKET_COUNT ACKs
                    # Each ACK → fresh random alphanumeric payload
                    for ack_ttl in TTL_LIST:
                        for ack_n in range(1, ACK_PACKET_COUNT + 1):
                            pload     = random_payload()
                            pload_len = len(pload)
                            ack_payload_total_bytes += pload_len

                            ack_raw = build_tcp_raw(
                                          sport, dport, "A",
                                          dataofs, opt_bytes,
                                          seq=cur_seq, ack_seq=ack_seq_val,
                                          payload=pload)
                            ack_pkt = IP(dst=TARGET, ttl=ack_ttl, proto=proto) / Raw(ack_raw)

                            ack_count += 1
                            print(f"[ACK  {ack_count:>5}] "
                                  f"TTL={ack_ttl:>3}(arr[{TTL_LIST.index(ack_ttl)}]) "
                                  f"#{ack_n}/{ACK_PACKET_COUNT} | "
                                  f"→{dport:<5} | "
                                  f"Flags=A    | "
                                  f"Ofs={dataofs}({(dataofs*4)-20:>2}B) | "
                                  f"Payload={pload_len:>2}B [{pload[:8].decode()}…] | "
                                  f"{opt_bytes[:4].hex():8}  {opt_desc}")

                            send(ack_pkt, verbose=0)
                            cur_seq += pload_len

                    # ── Step 4 : TLS — version-driven flow ───────────────
                    if not TLS_ENABLED:
                        continue

                    for ver_label, tls_maj, tls_min in TLS_VERSIONS_LIST:

                        flow = tls_flow_for_version(
                                   ver_label, tls_maj, tls_min, SNI_NAME)

                        for step_label, tls_payload in flow:

                            tls_raw = build_tcp_raw(
                                          sport, dport, "PA",
                                          dataofs, opt_bytes,
                                          seq=cur_seq, ack_seq=ack_seq_val,
                                          payload=tls_payload)
                            tls_pkt = IP(dst=TARGET, ttl=SYN_TTL, proto=proto) / Raw(tls_raw)

                            tls_count += 1
                            print(f"[TLS  {tls_count:>5}] "
                                  f"TTL={SYN_TTL:>3}(fixed) | "
                                  f"→{dport:<5} | "
                                  f"Flags=PA   | "
                                  f"Ofs={dataofs}({(dataofs*4)-20:>2}B) | "
                                  f"Step={step_label:<35} | "
                                  f"SNI={SNI_NAME} | "
                                  f"Payload={len(tls_payload)}B")

                            send(tls_pkt, verbose=0)
                            cur_seq += len(tls_payload)

# ── Final Summary ─────────────────────────────────────────────
print("\n" + "=" * 80)
print(f"[✓] Matrix complete")
print(f"    SYN packets sent        : {syn_count}")
print(f"    ACK packets sent        : {ack_count}  "
      f"({ACK_PACKET_COUNT}/TTL × {len(TTL_LIST)} TTLs {TTL_LIST})")
print(f"    ACK payload total       : {ack_payload_total_bytes}B  "
      f"(random alnum {ACK_PAYLOAD_MIN_LEN}–{ACK_PAYLOAD_MAX_LEN}B/pkt)")
if TLS_ENABLED:
    print(f"    TLS packets sent        : {tls_count}  (version-driven flows)")
    print(f"    SNI name used           : {SNI_NAME}")
    for lbl, maj, minn in TLS_VERSIONS_LIST:
        steps = [s.split('/')[1] for s,_ in tls_flow_for_version(lbl,maj,minn,"x")]
        print(f"      {lbl:<8}: {' → '.join(steps)}")
else:
    print(f"    TLS handshake           : DISABLED — skipped")
print(f"    Total                   : {syn_count + ack_count + tls_count}")
print(f"[i] Wireshark : tcp.options || tls || tcp.hdr_len >= 20")
print(f"[i] tcpdump   : tcpdump -i eth0 'tcp and host {TARGET}'")
print(f"[i] TLS filter: tshark -Y 'tls.handshake' -i eth0")
print("=" * 80)
