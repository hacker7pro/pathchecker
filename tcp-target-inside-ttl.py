from scapy.all import *
import struct
import random
import string
import time
from threading import Thread

# ============================================================
# TCP Options Length Mismatch — Full Matrix PoC v4.7
#
# TCP OPTIONS SCOPE — important:
#   3WHS only  : SYN + clean ACK use DATAOFS_OPTIONS_MAP options
#   TLS packets: dataofs=5, opt_bytes=b''  (plain 20B header)
#   ACK+TTL    : dataofs=5, opt_bytes=b''  (plain 20B header)
#
# TLS flow (matches real browser — Image 2):
#   → ClientHello                 (dataofs=5, no options)
#   ← ServerHello                 [wait]
#   ← Certificate                 [wait — may be separate segment]
#   ← ServerKeyExchange           [wait — ECDHE only]
#   ← ServerHelloDone             [wait — stop condition]
#   → CKE + CCS + EncHandshake    (one packet, dataofs=5)
#         CKE  = ClientKeyExchange  (ECDHE or RSA, chosen after ServerHello)
#         CCS  = ChangeCipherSpec   (0x14)
#         EHM  = Encrypted Handshake Message (0x16, simulated random)
#   ← CCS + EncHandshake          [wait]
#   ← ApplicationData             [wait — stop condition]
#
# ACK+TTL matrix (after TLS):
#   → ACK(payload, TTL=N)         (dataofs=5, no options)
#   ← any reply                   [wait — log flags+seq+ack+TLS type]
#
# v4.6 fix — ack_seq_val tracking:
#   do_client_hello() and do_cke_ccs_ehm() now compute the correct
#   ack from collected server segments (max seq+len across all received
#   packets) and return it alongside cur_seq.  The main loop propagates
#   the updated ack_seq_val so every subsequent packet (CKE+CCS+EHM,
#   ACK matrix) carries the right ACK field — stopping the server
#   retransmitting its TLS handshake data indefinitely.
#
# v4.7 fix — ECDHE ClientKeyExchange:
#   v4.6 always built an RSA-style CKE (2B len + 256B random encrypted
#   PMS).  When the server negotiates an ECDHE cipher suite (e.g.
#   0xC030 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) it expects an
#   ECDH public key point, not an RSA ciphertext.  Parsing a 2B prefix
#   as a 1B EC-point length (= 0x01, 1 byte) is structurally invalid
#   and causes an immediate RST.
#
#   Fix:
#     • ECDHE_CIPHER_SUITES  — set of all ECDHE suite IDs offered in CH
#     • EC_POINT_LEN         — named-curve → uncompressed point byte size
#     • parse_negotiated_kex()  — walks collected server pkts, extracts
#                                 negotiated cipher (ServerHello 0x02) and
#                                 named curve (ServerKeyExchange 0x0c),
#                                 returns (kex_type, ec_point_len)
#     • _build_client_key_exchange() — ECDHE branch: 1B len + 0x04 +
#                                      random X||Y (not on curve →
#                                      Alert illegal_parameter, NOT RST)
#                                      RSA branch: unchanged
#     • do_client_hello() now returns (cur_seq, new_ack, ok,
#                                       kex_type, ec_point_len)
#     • tls_flow_for_version() no longer pre-builds CKE; CKE_CCS_EHM
#       entry carries None — CKE is assembled in do_cke_ccs_ehm()
#     • do_cke_ccs_ehm() accepts (maj, minn, kex_type, ec_point_len),
#       builds CKE fresh from the actual negotiated type
# ============================================================

TARGET               = "192.31.242.45"
DPORT_LIST           = [443]
SYN_TTL              = 17
TTL_LIST             = [17, 18, 19, 20]
IP_PROTO_LIST        = [6]
TCP_PROBE_FLAGS_LIST = ["S"]
ACK_PAYLOAD_MIN_LEN  = 8
ACK_PAYLOAD_MAX_LEN  = 64
ACK_PACKET_COUNT     = 1

TLS_ENABLED          = True
SNI_NAME             = "adfs.spacex.com"
TLS_VERSIONS_LIST    = [
    ("TLS1.2", 0x03, 0x03),
    # ("TLS1.3", 0x03, 0x04),
]

# ── ECDHE cipher suite detection ─────────────────────────────
# All ECDHE suites offered in the ClientHello above.
# Used by parse_negotiated_kex() to decide CKE format.
ECDHE_CIPHER_SUITES = frozenset({
    0xC02C, 0xC030,   # ECDHE_ECDSA / ECDHE_RSA AES-256-GCM-SHA384
    0xC02B, 0xC02F,   # ECDHE_ECDSA / ECDHE_RSA AES-128-GCM-SHA256
    0xC024, 0xC028,   # ECDHE_ECDSA / ECDHE_RSA AES-256-CBC-SHA384
    0xC023, 0xC027,   # ECDHE_ECDSA / ECDHE_RSA AES-128-CBC-SHA256
    0xC00A, 0xC014,   # ECDHE_ECDSA / ECDHE_RSA AES-256-CBC-SHA
    0xC009, 0xC013,   # ECDHE_ECDSA / ECDHE_RSA AES-128-CBC-SHA
})

# named_curve value → uncompressed EC point byte length
# uncompressed = 0x04 + X (coord_bytes) + Y (coord_bytes)
EC_POINT_LEN = {
    0x0017:  65,   # secp256r1  — 0x04 + 32B + 32B
    0x0018:  97,   # secp384r1  — 0x04 + 48B + 48B
    0x0019: 133,   # secp521r1  — 0x04 + 66B + 66B
}

# ── TCP Options — used for 3WHS only ─────────────────────────
# TLS packets and ACK+TTL always use dataofs=5, opt_bytes=b''
DATAOFS_OPTIONS_MAP  = {
    8: [
        ("MSS + SACK-PERM",  b'\x02\x04\x05\xb4'   # MSS=1460
                              b'\x01\x01'            # NOP NOP
                              b'\x04\x02'            # SACK Permitted
                              b'\x00\x00\x00\x00'),  # pad → 12B
       
    ]
}

# ── Plain header constants (TLS + ACK+TTL packets) ───────────
PLAIN_DATAOFS = 5
PLAIN_OPTS    = b''

# ── Timeouts ──────────────────────────────────────────────────
TIMEOUT_SYNACK  = 3
TIMEOUT_TLS     = 5
TIMEOUT_ACK     = 2

# ============================================================
# FLAG MAP
# ============================================================
FLAG_MAP = {
    'F': 0x01, 'S': 0x02, 'R': 0x04,
    'P': 0x08, 'A': 0x10, 'U': 0x20,
}

def flags_to_int(flags_str):
    val = 0
    for c in flags_str:
        val |= FLAG_MAP.get(c, 0)
    return val

# ============================================================
# RANDOM ALPHANUMERIC PAYLOAD
# ============================================================
_ALNUM = (string.ascii_letters + string.digits).encode()

def random_payload():
    length = random.randint(ACK_PAYLOAD_MIN_LEN, ACK_PAYLOAD_MAX_LEN)
    return bytes(random.choice(_ALNUM) for _ in range(length))

# ============================================================
# RAW TCP BUILDER
# dataofs and opt_bytes are explicit — caller controls options
# ============================================================
def build_tcp_raw(sport, dport, flags_str, dataofs, opt_bytes,
                  seq=1000, ack_seq=0, payload=b''):
    fval        = flags_to_int(flags_str)
    offset_rsvd = (dataofs << 4) & 0xFF
    tcp_hdr = struct.pack('!HHIIBBHHH',
        sport, dport, seq, ack_seq,
        offset_rsvd, fval,
        8192, 0xabc0, 0
    )
    return tcp_hdr + opt_bytes + payload

# ============================================================
# SESSION BPF
# ============================================================
def session_bpf(sport, dport):
    return (f"tcp and src host {TARGET} "
            f"and src port {dport} "
            f"and dst port {sport}")

# ============================================================
# TCP / TLS FIELD EXTRACTORS
# ============================================================
def _tcp_raw_bytes(pkt):
    if pkt.haslayer(IP):
        ip_raw = bytes(pkt[IP])
        ihl    = (ip_raw[0] & 0x0F) * 4
        return ip_raw[ihl:]
    if pkt.haslayer(Raw):
        return bytes(pkt[Raw])
    return b''

def get_tcp_flags(pkt):
    if pkt.haslayer(TCP):
        return int(pkt[TCP].flags)
    raw = _tcp_raw_bytes(pkt)
    if len(raw) >= 14:
        return raw[13]
    return None

def get_server_seq(pkt):
    if pkt.haslayer(TCP):
        return pkt[TCP].seq
    raw = _tcp_raw_bytes(pkt)
    if len(raw) >= 8:
        return struct.unpack('!I', raw[4:8])[0]
    return 0

def get_server_ack(pkt):
    if pkt.haslayer(TCP):
        return pkt[TCP].ack
    raw = _tcp_raw_bytes(pkt)
    if len(raw) >= 12:
        return struct.unpack('!I', raw[8:12])[0]
    return 0

def _tls_payload_bytes(pkt):
    """Bytes after TCP header — where TLS record starts."""
    raw = _tcp_raw_bytes(pkt)
    if len(raw) < 20:
        return b''
    tcp_dataofs = (raw[12] >> 4) * 4
    return raw[tcp_dataofs:]

def get_tls_content_type(pkt):
    tls = _tls_payload_bytes(pkt)
    return tls[0] if len(tls) >= 1 else None

def get_tls_handshake_type(pkt):
    tls = _tls_payload_bytes(pkt)
    # TLS record: type(1) ver(2) len(2) hs_type(1)...
    if len(tls) >= 6 and tls[0] == 0x16:
        return tls[5]
    return None

def tls_ct_name(ct):
    return {0x14: 'ChangeCipherSpec',
            0x15: 'Alert',
            0x16: 'Handshake',
            0x17: 'ApplicationData'}.get(ct, f'0x{ct:02x}' if ct is not None else '?')

def tls_ht_name(ht):
    return {0x01: 'ClientHello',
            0x02: 'ServerHello',
            0x0b: 'Certificate',
            0x0c: 'ServerKeyExchange',
            0x0e: 'ServerHelloDone',
            0x10: 'ClientKeyExchange',
            0x14: 'Finished'}.get(ht, f'0x{ht:02x}' if ht is not None else '')

# ============================================================
# SNIFF HELPER
# Thread starts sniff, main sleeps 50ms, sends pkt, joins.
# store_fn(pkt, collected) — caller decides what to keep
# stop_fn(pkt) → True     — stop sniffing
# ============================================================
def send_then_sniff(pkt, bpf, store_fn, stop_fn, timeout):
    collected = []

    def _filter(p):
        store_fn(p, collected)
        return stop_fn(p)

    def _sniff():
        sniff(filter=bpf, stop_filter=_filter,
              timeout=timeout, store=False)

    t = Thread(target=_sniff, daemon=True)
    t.start()
    time.sleep(0.05)
    send(pkt, verbose=0)
    t.join(timeout + 1)
    return collected

# ============================================================
# ACK TRACKER
# Scans a list of collected server packets and returns the
# highest (seq + payload_len) seen — the correct next ACK.
# Falls back to ack_seq_val if no data packets were collected.
# ============================================================
def compute_new_ack(collected, ack_seq_val):
    """
    Walk every collected server packet and find the furthest
    byte the server has sent.  Returns max(seq + data_len)
    across all segments, or the existing ack_seq_val when the
    server sent no data (bare ACKs, empty packets).
    """
    new_ack = ack_seq_val
    for p in collected:
        if not p.haslayer(TCP):
            continue
        srv_data = len(bytes(p[TCP].payload))
        if srv_data > 0:
            candidate = p[TCP].seq + srv_data
            # seq arithmetic is mod-2^32 — handle wrap-around
            # by treating candidate as "ahead" only when the
            # forward distance is less than 2^31
            diff = (candidate - new_ack) & 0xFFFFFFFF
            if diff < 0x80000000:
                new_ack = candidate
    return new_ack

# ============================================================
# KEX TYPE PARSER
# Walk collected server packets, find ServerHello (cipher suite)
# and ServerKeyExchange (named curve).
# Returns (kex_type, ec_point_len):
#   kex_type     : 'ECDHE' or 'RSA'
#   ec_point_len : uncompressed EC point size in bytes (0 for RSA)
# ============================================================
def parse_negotiated_kex(collected):
    kex_type     = 'RSA'
    ec_point_len = 0

    for p in collected:
        raw = _tls_payload_bytes(p)
        off = 0
        while off + 5 <= len(raw):
            ct   = raw[off]
            rlen = struct.unpack('!H', raw[off+3:off+5])[0]
            body = raw[off+5:off+5+rlen]
            off += 5 + rlen
            if len(body) < rlen or ct != 0x16 or len(body) < 4:
                continue

            ht      = body[0]
            hs_body = body[4:]  # skip hs_type(1) + hs_length(3)

            if ht == 0x02:  # ServerHello — extract negotiated cipher suite
                # layout: version(2) + random(32) + sid_len(1) + sid + cipher(2)
                if len(hs_body) >= 35:
                    sid_len = hs_body[34]
                    cs_off  = 35 + sid_len
                    if len(hs_body) >= cs_off + 2:
                        cs = struct.unpack('!H', hs_body[cs_off:cs_off+2])[0]
                        if cs in ECDHE_CIPHER_SUITES:
                            kex_type = 'ECDHE'

            elif ht == 0x0c:  # ServerKeyExchange — extract named curve
                # ECDHE layout: curve_type(1)=0x03 + named_curve(2) + pubkey_len(1) + pubkey
                if len(hs_body) >= 3 and hs_body[0] == 0x03:
                    named_curve  = struct.unpack('!H', hs_body[1:3])[0]
                    ec_point_len = EC_POINT_LEN.get(named_curve, 65)
                    kex_type     = 'ECDHE'

    return kex_type, ec_point_len

# ============================================================
# TLS RECORD BUILDERS
# ============================================================
def _tls_rec(hs_type, hs_body, maj, minn):
    """Wrap handshake body into a TLS Handshake record (0x16)."""
    hdr = bytes([hs_type]) + struct.pack('!I', len(hs_body))[1:]
    hs  = hdr + hs_body
    return b'\x16' + struct.pack('!BB', maj, minn) + struct.pack('!H', len(hs)) + hs

def _build_client_hello(maj, minn, sni_name):
    sni_b   = sni_name.encode()
    sni_ext = (b'\x00\x00'
               + struct.pack('!H', 2 + 1 + 2 + len(sni_b))
               + struct.pack('!H', 1 + 2 + len(sni_b))
               + b'\x00'
               + struct.pack('!H', len(sni_b))
               + sni_b)

    cipher_suites = (
        b'\xc0\x2c'   # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        b'\xc0\x30'   # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        b'\xc0\x2b'   # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        b'\xc0\x2f'   # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        b'\xc0\x24'   # TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
        b'\xc0\x28'   # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
        b'\xc0\x23'   # TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
        b'\xc0\x27'   # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
        b'\xc0\x0a'   # TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
        b'\xc0\x14'   # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        b'\xc0\x09'   # TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
        b'\xc0\x13'   # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        b'\x00\x9d'   # TLS_RSA_WITH_AES_256_GCM_SHA384
        b'\x00\x9c'   # TLS_RSA_WITH_AES_128_GCM_SHA256
        b'\x00\x3d'   # TLS_RSA_WITH_AES_256_CBC_SHA256
        b'\x00\x3c'   # TLS_RSA_WITH_AES_128_CBC_SHA256
        b'\x00\x35'   # TLS_RSA_WITH_AES_256_CBC_SHA
        b'\x00\x2f'   # TLS_RSA_WITH_AES_128_CBC_SHA
    )
    cs_field = struct.pack('!H', len(cipher_suites)) + cipher_suites

    groups  = (b'\x00\x17'   # secp256r1
               b'\x00\x18'   # secp384r1
               b'\x00\x19')  # secp521r1
    grp_ext = (b'\x00\x0a'
               + struct.pack('!H', 2 + len(groups))
               + struct.pack('!H', len(groups))
               + groups)

    pt_ext  = b'\x00\x0b\x00\x02\x01\x00'

    sig_algs = (b'\x04\x01'   # RSA_PKCS1_SHA256
                b'\x05\x01'   # RSA_PKCS1_SHA384
                b'\x06\x01'   # RSA_PKCS1_SHA512
                b'\x04\x03'   # ECDSA_SECP256R1_SHA256
                b'\x05\x03'   # ECDSA_SECP384R1_SHA384
                b'\x06\x03')  # ECDSA_SECP521R1_SHA512
    sa_ext  = (b'\x00\x0d'
               + struct.pack('!H', 2 + len(sig_algs))
               + struct.pack('!H', len(sig_algs))
               + sig_algs)

    exts    = sni_ext + grp_ext + pt_ext + sa_ext
    ch_body = (struct.pack('!BB', maj, minn)
               + bytes(random.randint(0, 255) for _ in range(32))
               + b'\x00'
               + cs_field
               + b'\x01\x00'
               + struct.pack('!H', len(exts)) + exts)
    return _tls_rec(0x01, ch_body, maj, minn)

def _build_client_key_exchange(maj, minn, kex_type='RSA', ec_point_len=65):
    if kex_type == 'ECDHE':
        # Uncompressed EC point: 0x04 + random X + random Y
        # Coordinates are random — not a valid curve point.
        # Server parses structure OK (1B length + point bytes), then
        # validates the point → not on curve →
        #   Alert(illegal_parameter 0x2f)   NOT RST
        # (RST happened before because the RSA 2B length prefix was
        #  read as a 1B EC point length = 0x01, which is an immediate
        #  TLS record parse failure → server RSTs.)
        point    = bytes([0x04]) + bytes(random.randint(0, 255)
                                         for _ in range(ec_point_len - 1))
        cke_body = bytes([ec_point_len]) + point   # 1B len + point
    else:
        # RSA-2048: 2B length + 256B random ciphertext
        # Server: RSA-2048 PKCS#1 decrypt → random → decrypt_error Alert
        encrypted_pms = bytes(random.randint(0, 255) for _ in range(256))
        cke_body      = struct.pack('!H', 256) + encrypted_pms
    return _tls_rec(0x10, cke_body, maj, minn)

def _build_change_cipher_spec(maj, minn):
    return b'\x14' + struct.pack('!BB', maj, minn) + b'\x00\x01' + b'\x01'

def _build_encrypted_handshake_msg(maj, minn):
    # AES-128-CBC + HMAC-SHA1: IV(16) + CT(16) + MAC(20) = 52B
    iv         = bytes(random.randint(0, 255) for _ in range(16))
    ciphertext = bytes(random.randint(0, 255) for _ in range(16))
    mac        = bytes(random.randint(0, 255) for _ in range(20))
    body       = iv + ciphertext + mac
    return (b'\x16'
            + struct.pack('!BB', maj, minn)
            + struct.pack('!H', len(body))
            + body)

# ============================================================
# TLS FLOW BUILDER
# ============================================================
def tls_flow_for_version(label, tls_maj, tls_min, sni_name):
    # Only ClientHello is pre-built here — it does not depend on the
    # server's response.  CKE+CCS+EHM is assembled in do_cke_ccs_ehm()
    # after do_client_hello() has parsed the negotiated cipher suite and
    # named curve from ServerHello / ServerKeyExchange, so the CKE can
    # be built with the correct key-exchange format (ECDHE or RSA).
    ch = _build_client_hello(tls_maj, tls_min, sni_name)
    return [
        (f"{label}/ClientHello",           ch,   "ClientHello"),
        (f"{label}/CKE+CCS+EncHandshake",  None, "CKE_CCS_EHM"),
    ]

# ============================================================
# STEP 1 : SYN  — uses 3WHS dataofs/opt_bytes
# ============================================================
def do_syn(sport, dport, proto, dataofs, opt_bytes, syn_seq, syn_count):
    syn_raw = build_tcp_raw(sport, dport, "S",
                             dataofs, opt_bytes,
                             seq=syn_seq, ack_seq=0, payload=b'')
    syn_pkt = IP(dst=TARGET, ttl=SYN_TTL, proto=proto) / Raw(syn_raw)

    print(f"[SYN  {syn_count:>5}] "
          f"TTL={SYN_TTL:>3}(fixed) | "
          f"→{dport:<5} | Flags=S    | "
          f"Ofs={dataofs}({(dataofs*4)-20:>2}B opts) | "
          f"{opt_bytes[:4].hex():8} | seq={syn_seq}")
    return syn_pkt

# ============================================================
# STEP 2 : wait SYN-ACK
# ============================================================
def do_wait_synack(syn_pkt, sport, dport):
    bpf = session_bpf(sport, dport)

    def _store(p, col): col.append(p)
    def _stop(p):
        f = get_tcp_flags(p)
        return f is not None and (f & 0x12) == 0x12

    collected = send_then_sniff(syn_pkt, bpf, _store, _stop, TIMEOUT_SYNACK)

    if not collected:
        print(f"         [!] No SYN-ACK — aborting session")
        return None, None

    pkt        = collected[0]
    server_seq = get_server_seq(pkt)
    server_ack = get_server_ack(pkt)
    print(f"         [←SYN-ACK ] server_seq={server_seq} "
          f"server_ack={server_ack}")
    return server_seq, server_ack

# ============================================================
# STEP 3 : clean ACK — completes 3WHS
# ============================================================
def do_3whs_ack(sport, dport, proto, dataofs, opt_bytes,
                cur_seq, ack_seq_val):
    ack_raw = build_tcp_raw(sport, dport, "A",
                             dataofs, opt_bytes,
                             seq=cur_seq, ack_seq=ack_seq_val,
                             payload=b'')
    ack_pkt = IP(dst=TARGET, ttl=SYN_TTL, proto=proto) / Raw(ack_raw)
    send(ack_pkt, verbose=0)
    print(f"[3WHS      ] "
          f"TTL={SYN_TTL:>3}(fixed) | "
          f"→{dport:<5} | Flags=A    | "
          f"Ofs={dataofs}({(dataofs*4)-20:>2}B opts) | "
          f"clean ACK | seq={cur_seq} ack={ack_seq_val}")
    return cur_seq

# ============================================================
# STEP 4a : ClientHello → wait ServerHello + Cert + SHDone
#
# Returns (cur_seq, new_ack_seq_val, ok)
#
# new_ack_seq_val is computed from the highest (seq + len) seen
# across all collected server segments so that the subsequent
# CKE+CCS+EHM and ACK-matrix packets carry the correct ACK —
# preventing the server from retransmitting its TLS handshake.
# ============================================================
def do_client_hello(sport, dport, proto,
                    cur_seq, ack_seq_val,
                    tls_payload, step_label, tls_count):
    tls_raw = build_tcp_raw(sport, dport, "PA",
                             PLAIN_DATAOFS, PLAIN_OPTS,
                             seq=cur_seq, ack_seq=ack_seq_val,
                             payload=tls_payload)
    tls_pkt = IP(dst=TARGET, ttl=SYN_TTL, proto=proto) / Raw(tls_raw)
    bpf     = session_bpf(sport, dport)

    print(f"[TLS  {tls_count:>5}] "
          f"TTL={SYN_TTL:>3}(fixed) | "
          f"→{dport:<5} | Flags=PA   | "
          f"Ofs={PLAIN_DATAOFS}( 0B opts) | "
          f"Step={step_label:<35} | "
          f"Payload={len(tls_payload)}B | seq={cur_seq} ack={ack_seq_val}")

    def _store(p, col):
        ct = get_tls_content_type(p)
        if ct in (0x15, 0x16, 0x17):
            col.append(p)

    def _stop(p):
        ct = get_tls_content_type(p)
        ht = get_tls_handshake_type(p)
        if ct == 0x15:    return True   # Alert
        if ht == 0x0e:    return True   # ServerHelloDone
        return False

    collected = send_then_sniff(tls_pkt, bpf, _store, _stop, TIMEOUT_TLS)
    cur_seq  += len(tls_payload)

    if not collected:
        print(f"         [!] No ServerHello received")
        return cur_seq, ack_seq_val, False, 'RSA', 0

    # ── v4.6: advance ack_seq_val past all received server data ──────
    new_ack = compute_new_ack(collected, ack_seq_val)
    if new_ack != ack_seq_val:
        print(f"         [ack update ] {ack_seq_val} → {new_ack} "
              f"(+{(new_ack - ack_seq_val) & 0xFFFFFFFF}B server data ACKed)")

    # ── v4.7: parse negotiated kex type from ServerHello + SKE ───────
    kex_type, ec_point_len = parse_negotiated_kex(collected)
    kex_tag = (f"ec_point_len={ec_point_len}" if kex_type == 'ECDHE'
               else "rsa-2048")
    print(f"         [kex parsed ] kex={kex_type}  {kex_tag}")

    for p in collected:
        ct  = get_tls_content_type(p)
        ht  = get_tls_handshake_type(p)
        tag = tls_ct_name(ct)
        if ht is not None:
            tag += f"/{tls_ht_name(ht)}"
        print(f"         [←TLS     ] {tag}")

    return cur_seq, new_ack, True, kex_type, ec_point_len

# ============================================================
# STEP 4b : CKE+CCS+EncHandshake (combined) →
#           wait CCS + EncHandshake + ApplicationData
#
# Returns (cur_seq, new_ack_seq_val)
#
# v4.7: accepts (maj, minn, kex_type, ec_point_len) from
# do_client_hello() and builds the CKE fresh here using the
# actual negotiated key-exchange type, so the server receives
# a structurally correct record (ECDHE or RSA) and responds
# with an Alert instead of an immediate RST.
#
# v4.6: advances ack_seq_val past the server's reply so the
# ACK-matrix step opens with the right ACK field.
# ============================================================
def do_cke_ccs_ehm(sport, dport, proto,
                   cur_seq, ack_seq_val,
                   maj, minn, kex_type, ec_point_len,
                   step_label, tls_count):
    # ── v4.7: build CKE with the negotiated kex type ─────────────────
    cke         = _build_client_key_exchange(maj, minn, kex_type, ec_point_len)
    ccs         = _build_change_cipher_spec(maj, minn)
    ehm         = _build_encrypted_handshake_msg(maj, minn)
    tls_payload = cke + ccs + ehm

    tls_raw = build_tcp_raw(sport, dport, "PA",
                             PLAIN_DATAOFS, PLAIN_OPTS,
                             seq=cur_seq, ack_seq=ack_seq_val,
                             payload=tls_payload)
    tls_pkt = IP(dst=TARGET, ttl=SYN_TTL, proto=proto) / Raw(tls_raw)
    bpf     = session_bpf(sport, dport)

    kex_tag = (f"ec_pt={ec_point_len}B" if kex_type == 'ECDHE' else "rsa-2048")
    print(f"[TLS  {tls_count:>5}] "
          f"TTL={SYN_TTL:>3}(fixed) | "
          f"→{dport:<5} | Flags=PA   | "
          f"Ofs={PLAIN_DATAOFS}( 0B opts) | "
          f"Step={step_label:<35} | "
          f"kex={kex_type}({kex_tag}) | "
          f"Payload={len(tls_payload)}B | seq={cur_seq} ack={ack_seq_val}")

    def _store(p, col):
        ct = get_tls_content_type(p)
        if ct in (0x14, 0x15, 0x16, 0x17):
            col.append(p)

    def _stop(p):
        ct = get_tls_content_type(p)
        if ct == 0x17:    return True   # ApplicationData — TLS up
        if ct == 0x15:    return True   # Alert — rejected
        return False

    collected = send_then_sniff(tls_pkt, bpf, _store, _stop, TIMEOUT_TLS)
    cur_seq  += len(tls_payload)

    if not collected:
        print(f"         [!] No server response to CKE+CCS+EHM")
    else:
        # ── v4.6: advance ack_seq_val past server's reply ────────────
        new_ack = compute_new_ack(collected, ack_seq_val)
        if new_ack != ack_seq_val:
            print(f"         [ack update ] {ack_seq_val} → {new_ack} "
                  f"(+{(new_ack - ack_seq_val) & 0xFFFFFFFF}B server data ACKed)")
        ack_seq_val = new_ack

        for p in collected:
            ct  = get_tls_content_type(p)
            ht  = get_tls_handshake_type(p)
            tag = tls_ct_name(ct)
            if ht is not None:
                tag += f"/{tls_ht_name(ht)}"
            print(f"         [←TLS     ] {tag}")

    return cur_seq, ack_seq_val

# ============================================================
# STEP 5 : ACK matrix — TTL_LIST × ACK_PACKET_COUNT
# ============================================================
def do_ack_matrix(sport, dport, proto,
                  cur_seq, ack_seq_val,
                  opt_desc, ack_count_ref):
    bpf = session_bpf(sport, dport)

    for ack_ttl in TTL_LIST:
        for ack_n in range(1, ACK_PACKET_COUNT + 1):

            pload     = random_payload()
            pload_len = len(pload)

            ack_raw = build_tcp_raw(sport, dport, "A",
                                     PLAIN_DATAOFS, PLAIN_OPTS,
                                     seq=cur_seq,
                                     ack_seq=ack_seq_val,
                                     payload=pload)
            ack_pkt = IP(dst=TARGET, ttl=ack_ttl, proto=proto) / Raw(ack_raw)

            ack_count_ref[0] += 1
            print(f"[ACK  {ack_count_ref[0]:>5}] "
                  f"TTL={ack_ttl:>3}(arr[{TTL_LIST.index(ack_ttl)}]) "
                  f"#{ack_n}/{ACK_PACKET_COUNT} | "
                  f"→{dport:<5} | Flags=A    | "
                  f"Ofs={PLAIN_DATAOFS}( 0B opts) | "
                  f"Payload={pload_len:>2}B [{pload[:8].decode()}…] | "
                  f"seq={cur_seq} ack={ack_seq_val}")

            def _store(p, col):
                f = get_tcp_flags(p)
                if f is not None and (f & 0x14):
                    col.append(p)

            def _stop(p):
                f = get_tcp_flags(p)
                return f is not None and bool(f & 0x14)

            collected = send_then_sniff(ack_pkt, bpf,
                                        _store, _stop, TIMEOUT_ACK)

            if collected:
                for p in collected:
                    f     = get_tcp_flags(p)
                    s_seq = get_server_seq(p)
                    s_ack = get_server_ack(p)

                    f_parts = []
                    if f & 0x10: f_parts.append("ACK")
                    if f & 0x08: f_parts.append("PSH")
                    if f & 0x01: f_parts.append("FIN")
                    if f & 0x04: f_parts.append("RST")
                    flag_str = "+".join(f_parts) if f_parts else f"0x{f:02x}"

                    ct     = get_tls_content_type(p)
                    ct_tag = ""
                    if ct == 0x17: ct_tag = " [ApplicationData]"
                    elif ct == 0x15: ct_tag = " [Alert]"
                    elif ct == 0x16: ct_tag = " [Handshake]"
                    elif ct == 0x14: ct_tag = " [ChangeCipherSpec]"

                    tls_bytes = _tls_payload_bytes(p)
                    pay_len   = len(tls_bytes)

                    print(f"         [←{flag_str:<12}] "
                          f"server_seq={s_seq} "
                          f"server_ack={s_ack} "
                          f"payload={pay_len}B"
                          f"{ct_tag}")
            else:
                print(f"         [  no-reply ] "
                      f"TTL={ack_ttl} timeout — "
                      f"dropped by middlebox or firewall")

            cur_seq += pload_len

    return cur_seq

# ============================================================
# DATAOFS RESOLUTION + BYTE VERIFICATION  (3WHS options only)
# ============================================================
_RESOLVED_MAP = (
    DATAOFS_OPTIONS_MAP if DATAOFS_OPTIONS_MAP
    else {5: [("default(no-opts)", b'')]}
)

print("=" * 80)
print("  DATAOFS × OPTIONS BYTE VERIFICATION  (3WHS packets only)")
print("=" * 80)
all_ok = True
for dataofs, opt_list in sorted(_RESOLVED_MAP.items()):
    window = (dataofs * 4) - 20
    print(f"\n  dataofs={dataofs} → header={dataofs*4}B → "
          f"options_window={window}B")
    for desc, raw in opt_list:
        ok     = len(raw) == window
        status = "✓" if ok else "✗ FAIL"
        if not ok:
            all_ok = False
        print(f"    [{status}] {len(raw):>2}B  "
              f"{raw.hex() if raw else 'empty':20}  {desc}")

print("\n" + "=" * 80)
print(f"  Verification: {'ALL PASS ✓' if all_ok else 'FAILURES FOUND ✗'}")
print("=" * 80)

total_opts = sum(len(v) for v in _RESOLVED_MAP.values())
total_syn  = (len(DPORT_LIST) * len(IP_PROTO_LIST)
              * len(TCP_PROBE_FLAGS_LIST) * total_opts)
total_ack  = total_syn * len(TTL_LIST) * ACK_PACKET_COUNT

print(f"\n  Session flow per combination:")
print(f"    SYN (opts)                 → send  [dataofs from map]")
print(f"    SYN-ACK                    ← wait  [sniff BPF]")
print(f"    ACK clean (opts)           → send  [dataofs from map, 3WHS done]")
print(f"    ClientHello                → send  [dataofs=5, NO opts]")
print(f"    ServerHello+Cert+SHDone    ← wait  [stop on SHDone, ack updated]")
print(f"    CKE+CCS+EncHandshake       → send  [dataofs=5, NO opts, correct ack]")
print(f"    CCS+EncHandshake+AppData   ← wait  [stop on AppData, ack updated]")
print(f"    ACK(payload,TTL=N)         → send  [dataofs=5, NO opts, correct ack]")
print(f"    reply                      ← wait  [every TTL, every count]")
print(f"\n  Target      : {TARGET}")
print(f"  SYN TTL     : {SYN_TTL}  (fixed)")
print(f"  ACK TTL arr : {TTL_LIST}")
print(f"  Opts (3WHS) : {total_opts} variants")
print(f"  TLS         : {'ENABLED' if TLS_ENABLED else 'DISABLED'}")
print(f"  SNI         : {SNI_NAME}")
print(f"  SYN total   : {total_syn}")
print(f"  ACK total   : {total_ack}")
print("=" * 80)

# ============================================================
# MAIN LOOP
# ============================================================
syn_count             = 0
ack_count_ref         = [0]
tls_count             = 0

print("\n[→] Starting listen-based session matrix...\n")

for proto in IP_PROTO_LIST:
    for dport in DPORT_LIST:
        for flags in TCP_PROBE_FLAGS_LIST:
            for dataofs, opt_list in sorted(_RESOLVED_MAP.items()):
                for opt_desc, opt_bytes in opt_list:

                    sport   = random.randint(1024, 65535)
                    syn_seq = random.randint(0, 0xFFFFFFFF)
                    syn_count += 1

                    print(f"\n{'─'*78}")
                    print(f"  Session {syn_count} | "
                          f"sport={sport} | "
                          f"opt={opt_desc}")
                    print(f"{'─'*78}")

                    # ── Step 1 : SYN  (with 3WHS options) ───────────────
                    syn_pkt = do_syn(sport, dport, proto,
                                     dataofs, opt_bytes,
                                     syn_seq, syn_count)

                    # ── Step 2 : wait SYN-ACK ───────────────────────────
                    server_seq, server_ack = do_wait_synack(
                        syn_pkt, sport, dport)

                    if server_seq is None:
                        continue

                    ack_seq_val = server_seq + 1
                    cur_seq     = syn_seq + 1

                    # ── Step 3 : clean ACK  (with 3WHS options) ─────────
                    cur_seq = do_3whs_ack(
                        sport, dport, proto,
                        dataofs, opt_bytes,
                        cur_seq, ack_seq_val)

                    # ── Step 4 : TLS flow  (NO options) ─────────────────
                    if TLS_ENABLED:
                        for ver_label, tls_maj, tls_min in TLS_VERSIONS_LIST:
                            flow = tls_flow_for_version(
                                       ver_label, tls_maj, tls_min, SNI_NAME)

                            # v4.7: kex defaults — overwritten after ClientHello
                            kex_type     = 'RSA'
                            ec_point_len = 0

                            for step_label, tls_payload, step_type in flow:
                                tls_count += 1

                                if step_type == "ClientHello":
                                    # → ClientHello
                                    # ← ServerHello + Cert + SKE + SHDone
                                    # v4.6: ack_seq_val updated from reply
                                    # v4.7: kex_type + ec_point_len parsed from reply
                                    cur_seq, ack_seq_val, ok, kex_type, ec_point_len = \
                                        do_client_hello(
                                            sport, dport, proto,
                                            cur_seq, ack_seq_val,
                                            tls_payload, step_label, tls_count)

                                elif step_type == "CKE_CCS_EHM":
                                    # → CKE (ECDHE or RSA) + CCS + EncHandshakeMsg
                                    # ← CCS + EncHandshake + AppData (or Alert)
                                    # v4.6: ack_seq_val updated from reply
                                    # v4.7: CKE built from kex_type/ec_point_len
                                    cur_seq, ack_seq_val = do_cke_ccs_ehm(
                                        sport, dport, proto,
                                        cur_seq, ack_seq_val,
                                        tls_maj, tls_min,
                                        kex_type, ec_point_len,
                                        step_label, tls_count)

                    # ── Step 5 : ACK matrix  (NO options) ───────────────
                    cur_seq = do_ack_matrix(
                        sport, dport, proto,
                        cur_seq, ack_seq_val,
                        opt_desc, ack_count_ref)

# ── Final Summary ──────────────────────────────────────────────
print("\n" + "=" * 80)
print(f"[✓] Matrix complete")
print(f"    SYN sent              : {syn_count}")
print(f"    Clean ACK (3WHS)      : {syn_count}  (1 per session)")
print(f"    TLS steps sent        : {tls_count}")
print(f"    ACK matrix sent       : {ack_count_ref[0]}  "
      f"({ACK_PACKET_COUNT}/TTL × {len(TTL_LIST)} TTLs {TTL_LIST})")
print(f"    Total packets sent    : "
      f"{syn_count * 2 + tls_count + ack_count_ref[0]}")
print(f"[i] tcpdump : tcpdump -i eth0 'tcp and host {TARGET}'")
print(f"[i] tshark  : tshark -Y 'tls.handshake' -i eth0")
print(f"[i] Wireshark: tcp.port==443 && ip.addr=={TARGET}")
print("=" * 80)
