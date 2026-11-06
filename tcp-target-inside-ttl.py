from scapy.all import *
import struct
import random
import string
import time
import hashlib
import hmac
import os
from threading import Thread
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

# ============================================================
# TCP Options Length Mismatch — Full Matrix PoC v13
# TTL Matrix with TLS TTL Toggle
# ============================================================

TARGET               = "192.31.242.45"
DPORT_LIST           = [443]
IP_PROTO_LIST        = [6]
TCP_PROBE_FLAGS_LIST = ["S"]

# 🚨 3-WAY HANDSHAKE TTL (Fixed Default)
SYN_TTL              = 64 

# 🚨 ACK & TLS TTL ARRAY
TTL_LIST             = [18,19,20,21]  

# 🚨 TLS TTL TOGGLE
# True  = TLS Handshake uses the TTL from TTL_LIST array
# False = TLS Handshake uses the fixed SYN_TTL (17)
TLS_USE_ARRAY_TTL    = True  

# ACK MATRIX CONFIG
ACK_PAYLOAD_MIN_LEN  = 8
ACK_PAYLOAD_MAX_LEN  = 64
ACK_PACKET_COUNT     = 10  # 10 packets per TTL

# TLS MASTER SWITCH
TLS_ENABLED          = True
SNI_NAME             = "spacex"

# ============================================================
# TCP OPTIONS CONFIG
# ============================================================
THREE_WAY_HANDSHAKE_OPTS_ENABLED = True
THREE_WAY_HANDSHAKE_OPTS_MAP = {
    7: [
       
          ("RFC-Exp-253 ×2",               b'\xfd\x04\x00\x00\xfd\x04\x00\x00'),
    ],
}

# 🚨 TLS OPTIONS TOGGLE
TLS_OPTS_ENABLED = True
TLS_OPTS_MAP = {
      6: [
        ("MSS=0 malformed",              b'\x02\x04\x00\x00'),
        
       
    ],
}

# 🚨 ACK MATRIX OPTIONS TOGGLE
ACK_OPTS_ENABLED = True
ACK_OPTS_MAP = {
    6: [
        ("NOPx4", b'\x01\x01\x01\x01', [("NOP",None),("NOP",None),("NOP",None),("NOP",None)]),
    ]
}

TIMEOUT_SYNACK  = 3
TIMEOUT_TLS     = 5
TIMEOUT_ACK     = 2

# ============================================================
# FLAG MAP / UTILS
# ============================================================
FLAG_MAP = {'F': 0x01, 'S': 0x02, 'R': 0x04, 'P': 0x08, 'A': 0x10, 'U': 0x20}

def flags_to_int(flags_str):
    val = 0
    for c in flags_str:
        val |= FLAG_MAP.get(c, 0)
    return val

_ALNUM = (string.ascii_letters + string.digits).encode()
def random_payload():
    length = random.randint(ACK_PAYLOAD_MIN_LEN, ACK_PAYLOAD_MAX_LEN)
    return bytes(random.choice(_ALNUM) for _ in range(length))

def resolve_opts_map(enabled, raw_map):
    if not enabled or not raw_map:
        return {5: [("plain(no-opts)", b'', None)]}
    normalised = {}
    for dataofs, opt_list in raw_map.items():
        normalised[dataofs] = []
        for entry in opt_list:
            if len(entry) == 2:
                normalised[dataofs].append((entry[0], entry[1], None))
            else:
                normalised[dataofs].append(entry)
    return normalised

def first_opt_entry(resolved_map):
    dataofs, opt_list        = sorted(resolved_map.items())[0]
    desc, opt_bytes, scapy_o = opt_list[0]
    return dataofs, desc, opt_bytes, scapy_o

_3WHS_MAP = resolve_opts_map(THREE_WAY_HANDSHAKE_OPTS_ENABLED, THREE_WAY_HANDSHAKE_OPTS_MAP)
_TLS_MAP  = resolve_opts_map(TLS_OPTS_ENABLED,  TLS_OPTS_MAP)
_ACK_MAP  = resolve_opts_map(ACK_OPTS_ENABLED,  ACK_OPTS_MAP)

_TLS_DATAOFS, _TLS_OPT_DESC, _TLS_OPT_BYTES, _TLS_SCAPY_OPTS = first_opt_entry(_TLS_MAP)
_ACK_DATAOFS, _ACK_OPT_DESC, _ACK_OPT_BYTES, _ACK_SCAPY_OPTS = first_opt_entry(_ACK_MAP)

# ============================================================
# TCP CHECKSUM / RAW BUILDER
# ============================================================
import socket as _socket

def _tcp_checksum(src_ip, dst_ip, tcp_segment):
    src  = _socket.inet_aton(src_ip)
    dst  = _socket.inet_aton(dst_ip)
    pseudo = struct.pack('!4s4sBBH', src, dst, 0, 6, len(tcp_segment))
    data = pseudo + tcp_segment
    if len(data) % 2: data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    while s >> 16: s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

try:
    _s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    _s.connect((TARGET, 80))
    SRC_IP = _s.getsockname()[0]
    _s.close()
except Exception:
    SRC_IP = "0.0.0.0"

def build_tcp_raw(sport, dport, flags_str, dataofs, opt_bytes, seq=1000, ack_seq=0, payload=b''):
    fval        = flags_to_int(flags_str)
    offset_rsvd = (dataofs << 4) & 0xFF
    tcp_seg = (struct.pack('!HHIIBBHHH', sport, dport, seq, ack_seq, offset_rsvd, fval, 65535, 0, 0) + opt_bytes + payload)
    chk = _tcp_checksum(SRC_IP, TARGET, tcp_seg)
    tcp_seg = (struct.pack('!HHIIBBHHH', sport, dport, seq, ack_seq, offset_rsvd, fval, 65535, chk, 0) + opt_bytes + payload)
    return tcp_seg

def build_scapy_pkt(sport, dport, flags_str, seq, ack_seq, payload=b'', ttl=64, window=511):
    ip  = IP(src=SRC_IP, dst=TARGET, ttl=ttl, flags="DF")
    tcp = TCP(sport=sport, dport=dport, flags=flags_str, seq=seq, ack=ack_seq, window=window)
    if payload: return ip / tcp / Raw(payload)
    return ip / tcp

def build_pkt_for_entry(sport, dport, flags_str, dataofs, opt_bytes, scapy_opts, seq, ack_seq, payload=b'', ttl=64, window=511):
    if scapy_opts is not None:
        ip  = IP(src=SRC_IP, dst=TARGET, ttl=ttl, flags="DF")
        tcp = TCP(sport=sport, dport=dport, flags=flags_str, seq=seq, ack=ack_seq, window=window, options=scapy_opts)
        if payload: return ip / tcp / Raw(payload)
        return ip / tcp
    else:
        raw = build_tcp_raw(sport, dport, flags_str, dataofs, opt_bytes, seq=seq, ack_seq=ack_seq, payload=payload)
        return IP(src=SRC_IP, dst=TARGET, ttl=ttl, proto=6, flags="DF") / Raw(raw)

# ============================================================
# SNIFF HELPERS & EXTRACTORS
# ============================================================
def session_bpf(sport, dport):
    return f"tcp and src host {TARGET} and src port {dport} and dst port {sport}"

def _tcp_raw_bytes(pkt):
    if pkt.haslayer(IP):
        ip_raw = bytes(pkt[IP])
        ihl    = (ip_raw[0] & 0x0F) * 4
        return ip_raw[ihl:]
    if pkt.haslayer(Raw): return bytes(pkt[Raw])
    return b''

def get_tcp_flags(pkt):
    if pkt.haslayer(TCP): return int(pkt[TCP].flags)
    raw = _tcp_raw_bytes(pkt)
    return raw[13] if len(raw) >= 14 else None

def get_server_seq(pkt):
    if pkt.haslayer(TCP): return pkt[TCP].seq
    raw = _tcp_raw_bytes(pkt)
    return struct.unpack('!I', raw[4:8])[0] if len(raw) >= 8 else 0

def _tls_payload_bytes(pkt):
    raw = _tcp_raw_bytes(pkt)
    if len(raw) < 20: return b''
    tcp_dataofs = (raw[12] >> 4) * 4
    return raw[tcp_dataofs:]

def get_tls_content_type(pkt):
    tls = _tls_payload_bytes(pkt)
    return tls[0] if len(tls) >= 1 else None

def send_then_sniff(pkt, bpf, store_fn, stop_fn, timeout):
    collected = []
    def _filter(p):
        store_fn(p, collected)
        return stop_fn(p)
    def _sniff():
        sniff(filter=bpf, stop_filter=_filter, timeout=timeout, store=False)
    t = Thread(target=_sniff, daemon=True)
    t.start()
    time.sleep(0.05)
    send(pkt, verbose=0)
    t.join(timeout + 1)
    return collected

def decode_flags(f):
    parts = []
    if f & 0x02: parts.append("SYN")
    if f & 0x10: parts.append("ACK")
    if f & 0x08: parts.append("PSH")
    if f & 0x01: parts.append("FIN")
    if f & 0x04: parts.append("RST")
    return "+".join(parts) if parts else f"0x{f:02x}"

def is_rst(pkt):
    f = get_tcp_flags(pkt)
    return f is not None and bool(f & 0x04)

def is_synack(pkt):
    f = get_tcp_flags(pkt)
    return f is not None and (f & 0x12) == 0x12

# ============================================================
# TLS CRYPTO ENGINE (TLS 1.2 ECDHE_RSA_AES_128_GCM_SHA256)
# ============================================================
def prf_tls12(secret, label, seed, length):
    seed = label + seed
    A = seed
    result = b''
    while len(result) < length:
        A = hmac.new(secret, A, hashlib.sha256).digest()
        result += hmac.new(secret, A + seed, hashlib.sha256).digest()
    return result[:length]

def parse_tls_server_hello(payload):
    s_rand = payload[6:38]
    sid_len = payload[38]
    cipher_suite = struct.unpack('!H', payload[39+sid_len:41+sid_len])[0]
    return s_rand, cipher_suite

def parse_tls_server_key_exchange(payload):
    pubkey_len = payload[7]
    server_pubkey = payload[8:8+pubkey_len]
    return server_pubkey

def build_tls_client_hello():
    ciphers = b'\x00\x04\xc0\x2f\x00\x9c'
    rand = os.urandom(32)
    sni_b = SNI_NAME.encode()
    sni_ext = b'\x00\x00' + struct.pack('!H', 2+1+2+len(sni_b)) + struct.pack('!H', 1+2+len(sni_b)) + b'\x00' + struct.pack('!H', len(sni_b)) + sni_b
    ec_ext = b'\x00\x0a\x00\x04\x00\x02\x00\x17'
    
    exts = sni_ext + ec_ext
    ch_body = (b'\x03\x03' + rand + b'\x00' + ciphers + b'\x01\x00' + struct.pack('!H', len(exts)) + exts)
    hs_hdr = b'\x01' + struct.pack('!I', len(ch_body))[1:]
    ch_hs = hs_hdr + ch_body
    ch_rec = b'\x16\x03\x01' + struct.pack('!H', len(ch_hs)) + ch_hs
    return ch_rec, ch_hs, rand

def build_tls_crypto_payloads(server_hello_payload, server_kex_payload, client_random, handshake_messages):
    server_random, _ = parse_tls_server_hello(server_hello_payload)
    server_pub_bytes = parse_tls_server_key_exchange(server_kex_payload)

    client_priv = ec.generate_private_key(ec.SECP256R1())
    client_pub_bytes = client_priv.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    cke_body = bytes([len(client_pub_bytes)]) + client_pub_bytes
    cke_hs = b'\x10' + struct.pack('!I', len(cke_body))[1:] + cke_body
    cke_rec = b'\x16\x03\x03' + struct.pack('!H', len(cke_hs)) + cke_hs

    server_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), server_pub_bytes)
    shared_secret = client_priv.exchange(ec.ECDH(), server_pub_key)

    master_secret = prf_tls12(shared_secret, b"master secret", client_random + server_random, 48)
    handshake_messages += cke_hs
    hmac_hash = hashlib.sha256(handshake_messages).digest()
    verify_data = prf_tls12(master_secret, b"client finished", hmac_hash, 12)

    key_block = prf_tls12(master_secret, b"key expansion", server_random + client_random, 40)
    client_write_key = key_block[0:16]
    client_write_iv  = key_block[16:20]

    explicit_nonce = b'\x00\x00\x00\x00\x00\x00\x00\x01'
    nonce = client_write_iv + explicit_nonce
    aesgcm = AESGCM(client_write_key)
    
    finished_hs = b'\x14' + struct.pack('!I', 12)[1:] + verify_data
    aad = struct.pack('!Q', 0) + b'\x16\x03\x03' + struct.pack('!H', len(finished_hs))
    ciphertext = aesgcm.encrypt(nonce, finished_hs, aad)
    
    enc_fin_rec = b'\x16\x03\x03' + struct.pack('!H', len(explicit_nonce) + len(ciphertext)) + explicit_nonce + ciphertext
    ccs_rec = b'\x14\x03\x03\x00\x01\x01'

    return cke_rec + ccs_rec + enc_fin_rec

# ============================================================
# STEP FUNCTIONS
# ============================================================
def do_syn(sport, dport, proto, dataofs, opt_bytes, scapy_opts, syn_seq, syn_count, ttl):
    syn_pkt = build_pkt_for_entry(sport, dport, "S", dataofs, opt_bytes, scapy_opts, seq=syn_seq, ack_seq=0, ttl=ttl, window=65535)
    print(f"[SYN  {syn_count:>5}] TTL={ttl} →{dport} seq={syn_seq}")
    return syn_pkt

def do_wait_synack(syn_pkt, sport, dport):
    bpf = session_bpf(sport, dport)
    collected = send_then_sniff(syn_pkt, bpf, lambda p, c: c.append(p), is_synack, TIMEOUT_SYNACK)
    if not collected:
        print(f"         [!STOP] SYN timeout")
        return None, None
    pkt = collected[0]
    if not is_synack(pkt):
        print(f"         [!STOP] SYN unexpected")
        return None, None
    return get_server_seq(pkt), get_server_seq(pkt) + 1

def do_3whs_ack(sport, dport, proto, cur_seq, ack_seq_val, ttl):
    ack_pkt = build_scapy_pkt(sport, dport, "A", seq=cur_seq, ack_seq=ack_seq_val, ttl=ttl, window=65535)
    bpf = session_bpf(sport, dport)
    print(f"[3WHS ACK  ] TTL={ttl} →{dport} Ack={ack_seq_val} (No Options)")
    collected = send_then_sniff(ack_pkt, bpf, lambda p, c: c.append(p), is_rst, timeout=0.5)
    if collected and is_rst(collected[0]):
        print(f"         [!STOP] 3WHS RST received")
        return cur_seq, False
    return cur_seq, True

def do_tls_handshake(sport, dport, proto, cur_seq, ack_seq_val, ttl, tls_dataofs, tls_opt_bytes, tls_scapy_opts):
    ch_rec, ch_hs, client_random = build_tls_client_hello()
    
    # TLS uses the TTL passed to it
    ch_pkt = build_pkt_for_entry(sport, dport, "PA", tls_dataofs, tls_opt_bytes, tls_scapy_opts, seq=cur_seq, ack_seq=ack_seq_val, payload=ch_rec, ttl=ttl)
    bpf = session_bpf(sport, dport)
    
    print(f"[TLS        ] TTL={ttl} →{dport} ClientHello (len={len(ch_rec)}, Ofs={tls_dataofs})")
    
    collected = []
    transcript = ch_hs
    current_ack = ack_seq_val
    got_shdone = False
    got_alert = False
    next_client_seq = cur_seq + len(ch_rec)

    def process_tcp_packet(p):
        nonlocal current_ack, transcript, got_shdone, got_alert
        f = get_tcp_flags(p)
        if f is None or not (f & 0x10): return

        s_seq = get_server_seq(p)
        tls_b = _tls_payload_bytes(p)
        pay_len = len(tls_b)

        if pay_len > 0:
            new_ack = (s_seq + pay_len) & 0xFFFFFFFF
            if new_ack > current_ack:
                current_ack = new_ack
            
            # Internal TCP ACKs use the same TTL
            ack_pkt = build_scapy_pkt(sport, dport, "A", seq=next_client_seq, ack_seq=current_ack, ttl=ttl)
            send(ack_pkt, verbose=0)
            print(f"         [→TCP ACK  ] TTL={ttl} seq={next_client_seq} ack={current_ack}")

            offset = 0
            while offset < len(tls_b):
                if offset + 5 > len(tls_b): break
                ct = tls_b[offset]
                rec_len = struct.unpack('!H', tls_b[offset+3:offset+5])[0]
                if offset + 5 + rec_len > len(tls_b): break

                if ct == 0x16:
                    transcript += tls_b[offset+5 : offset+5+rec_len]
                    hs_type = tls_b[offset+5]
                    if hs_type == 0x0e: got_shdone = True
                elif ct == 0x15:
                    got_alert = True
                offset += 5 + rec_len
            
            collected.append(p)

    def _sniff():
        sniff(filter=bpf, prn=process_tcp_packet, stop_filter=lambda p: got_shdone or got_alert, timeout=TIMEOUT_TLS)

    t = Thread(target=_sniff, daemon=True)
    t.start()
    time.sleep(0.05)
    send(ch_pkt, verbose=0)
    t.join(TIMEOUT_TLS + 1)

    if got_alert:
        print(f"         [!STOP] Server sent TLS Alert")
        return next_client_seq, current_ack, False
    if not got_shdone:
        print(f"         [!STOP] Missing ServerHelloDone")
        return next_client_seq, current_ack, False

    server_hello_payload = None
    server_kex_payload = None
    for p in collected:
        tls_b = _tls_payload_bytes(p)
        offset = 0
        while offset < len(tls_b):
            if offset + 5 > len(tls_b): break
            ct = tls_b[offset]
            rec_len = struct.unpack('!H', tls_b[offset+3:offset+5])[0]
            if offset + 5 + rec_len > len(tls_b): break
            if ct == 0x16 and rec_len > 0:
                hs_type = tls_b[offset+5]
                hs_payload = tls_b[offset+5 : offset+5+rec_len]
                if hs_type == 0x02: server_hello_payload = hs_payload
                elif hs_type == 0x0c: server_kex_payload = hs_payload
            offset += 5 + rec_len

    if not server_hello_payload or not server_kex_payload:
        print(f"         [!STOP] Missing ServerHello or ServerKeyExchange")
        return next_client_seq, current_ack, False

    crypto_payload = build_tls_crypto_payloads(server_hello_payload, server_kex_payload, client_random, transcript)
    
    # Finished packet uses the same TTL
    fin_pkt = build_pkt_for_entry(sport, dport, "PA", tls_dataofs, tls_opt_bytes, tls_scapy_opts, seq=next_client_seq, ack_seq=current_ack, payload=crypto_payload, ttl=ttl)
    print(f"[TLS        ] TTL={ttl} →{dport} CKE+CCS+Finished (len={len(crypto_payload)})")

    next_client_seq += len(crypto_payload)

    def store_fin(p, c):
        if get_tls_content_type(p) in (0x14, 0x16, 0x17, 0x15):
            c.append(p)
        f = get_tcp_flags(p)
        if f and (f & 0x10):
            s_seq = get_server_seq(p)
            pay_len = len(_tls_payload_bytes(p))
            if pay_len > 0:
                nonlocal current_ack
                new_ack = (s_seq + pay_len) & 0xFFFFFFFF
                if new_ack > current_ack:
                    current_ack = new_ack
                ack_pkt = build_scapy_pkt(sport, dport, "A", seq=next_client_seq, ack_seq=current_ack, ttl=ttl)
                send(ack_pkt, verbose=0)

    collected_fin = send_then_sniff(fin_pkt, bpf, store_fin, lambda p: get_tls_content_type(p) in (0x17, 0x15), TIMEOUT_TLS)

    if any(get_tls_content_type(p) == 0x17 for p in collected_fin):
        print(f"         [✓ TLS OK ] TTL={ttl} Handshake Complete!")
        return next_client_seq, current_ack, True
    else:
        print(f"         [!STOP] Handshake failed (No ApplicationData)")
        return next_client_seq, current_ack, False

def do_ack_matrix(sport, dport, proto, cur_seq, ack_seq_val, ack_dataofs, ack_opt_bytes, ack_scapy_opts, ack_count_ref, ack_ttl_list):
    bpf = session_bpf(sport, dport)
    # Loops over the provided TTL list
    for ack_ttl in ack_ttl_list:
        for ack_n in range(1, ACK_PACKET_COUNT + 1):
            pload = random_payload()
            pload_len = len(pload)
            
            ack_pkt = build_pkt_for_entry(sport, dport, "PA", ack_dataofs, ack_opt_bytes, ack_scapy_opts, seq=cur_seq, ack_seq=ack_seq_val, payload=pload, ttl=ack_ttl, window=511)
            
            ack_count_ref[0] += 1
            print(f"[ACK-MATRIX {ack_count_ref[0]:>3}] TTL={ack_ttl} →{dport} | Flags=PA | Ofs={ack_dataofs} | Payload={pload_len}B")

            def store_ack_reply(p, c):
                f = get_tcp_flags(p)
                if f is not None and (f & 0x14): c.append(p)
            def stop_ack_reply(p):
                f = get_tcp_flags(p)
                return f is not None and bool(f & 0x14)

            collected = send_then_sniff(ack_pkt, bpf, store_ack_reply, stop_ack_reply, TIMEOUT_ACK)
            if not collected:
                print(f"         [  no-reply ] TTL={ack_ttl} → dropped")
                cur_seq += pload_len
                continue

            for p in collected:
                f = get_tcp_flags(p)
                if is_rst(p):
                    print(f"         [!STOP] step=ACK_PAYLOAD | RST received at TTL={ack_ttl}")
                    return cur_seq
                else:
                    print(f"         [←Reply     ] flags={decode_flags(f)}")
            cur_seq += pload_len
    return cur_seq

# ============================================================
# MAIN LOOP
# ============================================================
syn_count = 0
ack_count_ref = [0]
print("\n[→] Starting session matrix...\n")

# 🚨 Determine the Outer Loop based on TLS_USE_ARRAY_TTL
if TLS_USE_ARRAY_TTL:
    ttl_iterator = TTL_LIST
else:
    # If False, only run the handshake once using SYN_TTL
    ttl_iterator = [SYN_TTL]

for session_ttl in ttl_iterator:
    for proto in IP_PROTO_LIST:
        for dport in DPORT_LIST:
            for flags in TCP_PROBE_FLAGS_LIST:
                for hs_dataofs, hs_opt_list in sorted(_3WHS_MAP.items()):
                    for hs_opt_desc, hs_opt_bytes, hs_scapy_opts in hs_opt_list:

                        sport   = random.randint(1024, 65535)
                        syn_seq = random.randint(0, 0xFFFFFFFF)
                        syn_count += 1

                        print(f"\n{'─'*78}")
                        print(f"  Session {syn_count} | Handshake TTL={SYN_TTL} | TLS/ACK Session TTL={session_ttl} | sport={sport}")
                        print(f"{'─'*78}")

                        # Step 1: SYN (Fixed SYN_TTL)
                        syn_pkt = do_syn(sport, dport, proto, hs_dataofs, hs_opt_bytes, hs_scapy_opts, syn_seq, syn_count, SYN_TTL)
                        server_seq, server_ack = do_wait_synack(syn_pkt, sport, dport)
                        if server_seq is None: continue

                        ack_seq_val = server_seq + 1
                        cur_seq     = syn_seq + 1

                        # Step 2: 3WHS ACK (Fixed SYN_TTL)
                        cur_seq, ok = do_3whs_ack(sport, dport, proto, cur_seq, ack_seq_val, SYN_TTL)
                        if not ok: continue

                        # Step 3: TLS Handshake
                        tls_ok = False
                        if TLS_ENABLED:
                            # If TLS_USE_ARRAY_TTL is True, uses session_ttl from array.
                            # If False, session_ttl is SYN_TTL (from the iterator logic above)
                            cur_seq, ack_seq_val, tls_ok = do_tls_handshake(
                                sport, dport, proto, 
                                cur_seq, ack_seq_val, 
                                session_ttl, 
                                _TLS_DATAOFS, _TLS_OPT_BYTES, _TLS_SCAPY_OPTS
                            )
                            if not tls_ok:
                                print(f"  [!] TLS handshake failed. Proceeding to ACK Matrix anyway.")

                        # Step 4: ACK Matrix
                        # If TLS_USE_ARRAY_TTL is True, it only uses the current session_ttl (so we get 10 packets).
                        # If TLS_USE_ARRAY_TTL is False, it loops over the entire TTL_LIST (so we get 40 packets).
                        ack_ttls = [session_ttl] if TLS_USE_ARRAY_TTL else TTL_LIST
                        
                        cur_seq = do_ack_matrix(
                            sport, dport, proto,
                            cur_seq, ack_seq_val,
                            _ACK_DATAOFS, _ACK_OPT_BYTES, _ACK_SCAPY_OPTS,
                            ack_count_ref, ack_ttls
                        )

print("\n" + "=" * 80)
print(f"[✓] Matrix complete")
print(f"    SYN sent           : {syn_count}")
print(f"    ACK matrix sent    : {ack_count_ref[0]}")
print("=" * 80)
