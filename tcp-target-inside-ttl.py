from scapy.all import *
import struct
import random
import string
import time
from threading import Thread

# ============================================================
# TCP Options Length Mismatch — Full Matrix PoC v4.5
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
#   ← ServerHelloDone             [wait — stop condition]
#   → CKE + CCS + EncHandshake    (one packet, dataofs=5)
#         CKE  = ClientKeyExchange  (0x16 / 0x10)
#         CCS  = ChangeCipherSpec   (0x14)
#         EHM  = Encrypted Handshake Message (0x16, simulated random)
#   ← CCS + EncHandshake          [wait]
#   ← ApplicationData             [wait — stop condition]
#
# ACK+TTL matrix (after TLS):
#   → ACK(payload, TTL=N)         (dataofs=5, no options)
#   ← any reply                   [wait — log flags+seq+ack+TLS type]
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
# TLS RECORD BUILDERS
# ============================================================
def _tls_rec(hs_type, hs_body, maj, minn):
    """Wrap handshake body into a TLS Handshake record (0x16)."""
    hdr = bytes([hs_type]) + struct.pack('!I', len(hs_body))[1:]
    hs  = hdr + hs_body
    return b'\x16' + struct.pack('!BB', maj, minn) + struct.pack('!H', len(hs)) + hs

def _build_client_hello(maj, minn, sni_name):
    # ── FIX 4: expanded cipher suite list + required extensions ──────
    # Previous: only 0x002F (RSA) → server had no ECDHE choice
    # Fixed: 18 ciphers covering ECDHE-RSA, ECDHE-ECDSA, RSA variants
    # Extensions: SNI + supported_groups + ec_point_formats + sig_algs
    # Required for server to negotiate ECDHE correctly
    sni_b   = sni_name.encode()
    sni_ext = (b'\x00\x00'
               + struct.pack('!H', 2 + 1 + 2 + len(sni_b))
               + struct.pack('!H', 1 + 2 + len(sni_b))
               + b'\x00'
               + struct.pack('!H', len(sni_b))
               + sni_b)

    # Cipher suites — ECDHE first (server preference), RSA fallback
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

    # Supported groups (required for ECDHE key exchange)
    groups  = (b'\x00\x17'   # secp256r1
               b'\x00\x18'   # secp384r1
               b'\x00\x19')  # secp521r1
    grp_ext = (b'\x00\x0a'
               + struct.pack('!H', 2 + len(groups))
               + struct.pack('!H', len(groups))
               + groups)

    # EC point formats (uncompressed = 0x00)
    pt_ext  = b'\x00\x0b\x00\x02\x01\x00'

    # Signature algorithms (required for TLS 1.2)
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

def _build_client_key_exchange(maj, minn):
    # ── FIX 1: RSA-2048 correct encrypted PMS size ───────────────────
    # Previous: 2B + 48B = 50B body → server parse fail (expected 256B)
    # Fixed:    2B length + 256B random ciphertext = 258B body
    # Server: attempts RSA-2048 PKCS#1 decrypt → random → decrypt_error Alert
    # NOT RST — record is structurally valid, server processes it ✓
    encrypted_pms = bytes(random.randint(0, 255) for _ in range(256))
    cke_body      = struct.pack('!H', 256) + encrypted_pms
    return _tls_rec(0x10, cke_body, maj, minn)

def _build_change_cipher_spec(maj, minn):
    # ContentType=0x14, body=0x01 (single byte) — unchanged, was correct
    return b'\x14' + struct.pack('!BB', maj, minn) + b'\x00\x01' + b'\x01'

def _build_encrypted_handshake_msg(maj, minn):
    # ── FIX 3: correct CBC-SHA Finished record structure ─────────────
    # Previous: _tls_rec(0x14, 64B_random) → exposed hs_type byte
    #           server saw unknown HS type → RST during parse
    # Fixed:    raw ContentType=0x16 record, body = IV+CT+MAC
    #
    # AES-128-CBC + HMAC-SHA1 structure (matches 0x002F and CBC ciphers):
    #   IV         = 16B  random (AES block size)
    #   ciphertext = 16B  random (1 AES block covering padded Finished)
    #   MAC        = 20B  random (HMAC-SHA1 output size)
    #   Total body = 52B
    #
    # Server: AES-CBC decrypt with IV → random plaintext
    #         HMAC-SHA1 verify → fails → Alert(bad_record_mac 0x14)
    #         NOT RST — record structure is valid, server parses it ✓
    iv         = bytes(random.randint(0, 255) for _ in range(16))
    ciphertext = bytes(random.randint(0, 255) for _ in range(16))
    mac        = bytes(random.randint(0, 255) for _ in range(20))
    body       = iv + ciphertext + mac   # 52B
    return (b'\x16'
            + struct.pack('!BB', maj, minn)
            + struct.pack('!H', len(body))
            + body)

# ============================================================
# TLS FLOW BUILDER
#
# Packet 1 : ClientHello                   (separate, dataofs=5)
# Packet 2 : CKE + CCS + EncHandshake     (combined, dataofs=5)
#            ↑ matches browser Wireshark exactly
# ============================================================
def tls_flow_for_version(label, tls_maj, tls_min, sni_name):
    maj, minn = tls_maj, tls_min

    ch       = _build_client_hello(maj, minn, sni_name)

    # Combined: ClientKeyExchange + ChangeCipherSpec + EncHandshakeMsg
    cke      = _build_client_key_exchange(maj, minn)
    ccs      = _build_change_cipher_spec(maj, minn)
    ehm      = _build_encrypted_handshake_msg(maj, minn)
    combined = cke + ccs + ehm   # ONE TCP payload

    return [
        (f"{label}/ClientHello",            ch,       "ClientHello"),
        (f"{label}/CKE+CCS+EncHandshake",   combined, "CKE_CCS_EHM"),
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
# Uses same dataofs/opt_bytes as SYN (3WHS options)
# Server sends nothing after bare ACK — no wait needed
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
    return cur_seq   # unchanged — empty ACK does not advance seq

# ============================================================
# STEP 4a : ClientHello → wait ServerHello + Cert + SHDone
#
# Uses PLAIN_DATAOFS=5, PLAIN_OPTS=b'' — no TCP options
# Collects until ServerHelloDone (ht=0x0e) or Alert or timeout
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
          f"Payload={len(tls_payload)}B | seq={cur_seq}")

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
        return cur_seq, False

    for p in collected:
        ct  = get_tls_content_type(p)
        ht  = get_tls_handshake_type(p)
        tag = tls_ct_name(ct)
        if ht is not None:
            tag += f"/{tls_ht_name(ht)}"
        print(f"         [←TLS     ] {tag}")

    return cur_seq, True

# ============================================================
# STEP 4b : CKE+CCS+EncHandshake (combined) →
#           wait CCS + EncHandshake + ApplicationData
#
# Uses PLAIN_DATAOFS=5, PLAIN_OPTS=b'' — no TCP options
# Stop on ApplicationData (0x17) — TLS session fully up
# ============================================================
def do_cke_ccs_ehm(sport, dport, proto,
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
          f"Payload={len(tls_payload)}B | seq={cur_seq}")

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
        for p in collected:
            ct  = get_tls_content_type(p)
            ht  = get_tls_handshake_type(p)
            tag = tls_ct_name(ct)
            if ht is not None:
                tag += f"/{tls_ht_name(ht)}"
            print(f"         [←TLS     ] {tag}")

    return cur_seq

# ============================================================
# STEP 5 : ACK matrix — TTL_LIST × ACK_PACKET_COUNT
#
# Uses PLAIN_DATAOFS=5, PLAIN_OPTS=b'' — no TCP options
# Every single packet: send → wait reply → log reply
# ============================================================
def do_ack_matrix(sport, dport, proto,
                  cur_seq, ack_seq_val,
                  opt_desc, ack_count_ref):
    bpf = session_bpf(sport, dport)

    for ack_ttl in TTL_LIST:
        for ack_n in range(1, ACK_PACKET_COUNT + 1):

            pload     = random_payload()
            pload_len = len(pload)

            # No TCP options — PLAIN_DATAOFS=5, PLAIN_OPTS=b''
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
                  f"seq={cur_seq}")

            # ── wait for any reply ────────────────────────────
            def _store(p, col):
                f = get_tcp_flags(p)
                if f is not None and (f & 0x14):   # ACK or RST
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
print(f"    ServerHello+Cert+SHDone    ← wait  [stop on SHDone]")
print(f"    CKE+CCS+EncHandshake       → send  [dataofs=5, NO opts, one packet]")
print(f"    CCS+EncHandshake+AppData   ← wait  [stop on AppData]")
print(f"    ACK(payload,TTL=N)         → send  [dataofs=5, NO opts]")
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

                            for step_label, tls_payload, step_type in flow:
                                tls_count += 1

                                if step_type == "ClientHello":
                                    # → ClientHello
                                    # ← ServerHello + Cert + SHDone
                                    cur_seq, ok = do_client_hello(
                                        sport, dport, proto,
                                        cur_seq, ack_seq_val,
                                        tls_payload, step_label, tls_count)

                                elif step_type == "CKE_CCS_EHM":
                                    # → CKE + CCS + EncHandshakeMsg
                                    # ← CCS + EncHandshake + AppData
                                    cur_seq = do_cke_ccs_ehm(
                                        sport, dport, proto,
                                        cur_seq, ack_seq_val,
                                        tls_payload, step_label, tls_count)

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
