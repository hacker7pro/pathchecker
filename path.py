from scapy.all import *

target = "8.8.8.8"

# ===== SCAN PARAMETERS — EDIT HERE =====
tos_list          = [0x00, 0xB8, 0x88, 0xC0, 0xE0]
ttl_list          = [1, 2, 3, 5, 8, 10, 15, 32, 64, 128, 255]
payload_size_list = [0, 8, 16, 32, 64, 128, 256, 512, 1024]

ip_options_list = {
    "NoOption":  [],
    "RR":        [IPOption_RR()],
    "NOP":       [IPOption_NOP()],
    "Timestamp": [IPOption_Timestamp()],
    "LSRR":      [IPOption_LSRR(routers=["8.8.8.8"])],
    "SSRR":      [IPOption_SSRR(routers=["8.8.8.8"])],
}

protocols = {
    1:   "ICMP",
    6:   "TCP",
    17:  "UDP",
    41:  "IPv6-in-IPv4",
    47:  "GRE",
    50:  "ESP (IPSec)",
    51:  "AH (IPSec)",
    89:  "OSPF",
    132: "SCTP",
    253: "Experimental-1",
    254: "Experimental-2",
}
# ========================================

print("=" * 85)
print(f"  Full Matrix Scan — IP Options + TTL + ToS + Protocol + Payload | Target: {target}")
print("=" * 85)

for opt_name, opt_value in ip_options_list.items():
    print(f"\n{'#'*85}")
    print(f"  [IP Option: {opt_name}]")
    print(f"{'#'*85}")

    for tos in tos_list:
        dscp = tos >> 2
        print(f"\n{'='*85}")
        print(f"  [IP Option={opt_name} | ToS=0x{tos:02X} | DSCP={dscp}]")
        print(f"{'='*85}")

        for ttl in ttl_list:
            print(f"\n  --- TTL={ttl} ---")
            print(f"  {'Proto':>5} | {'Name':<18} | {'PSize':>6} | {'Reply From':<16} | {'Status':<12} | {'RR/TS Info'}")
            print(f"  {'-'*5}-+-{'-'*18}-+-{'-'*6}-+-{'-'*16}-+-{'-'*12}-+-{'-'*30}")

            for proto_num, proto_name in protocols.items():
                for psize in payload_size_list:
                    try:
                        payload = Raw(load=b"\x00" * psize) if psize > 0 else b""

                        pkt = IP(
                            dst=target,
                            ttl=ttl,
                            tos=tos,
                            proto=proto_num,
                            options=opt_value
                        ) / payload

                        reply = sr1(pkt, timeout=2, verbose=False)

                        if reply:
                            src = reply[IP].src

                            # Status detect
                            if reply.haslayer(ICMP):
                                icmp_type = reply[ICMP].type
                                if icmp_type == 11:
                                    status = "TTL-EXPIRED"
                                elif icmp_type == 0:
                                    status = "REACHED"
                                elif icmp_type == 3:
                                    status = "UNREACHABLE"
                                else:
                                    status = f"ICMP-{icmp_type}"
                            else:
                                status = "REPLY"

                            # RR / Timestamp extract
                            extra_info = []
                            for opt in reply[IP].options:
                                if hasattr(opt, 'routers'):
                                    ips = [str(i) for i in opt.routers if str(i) != '0.0.0.0']
                                    if ips:
                                        extra_info.append("RR: " + " → ".join(ips))
                                if hasattr(opt, 'timestamps'):
                                    ts = opt.timestamps
                                    if ts:
                                        extra_info.append(f"TS: {ts}")

                            info_str = " | ".join(extra_info) if extra_info else "No extra data"
                            print(f"  {proto_num:>5} | {proto_name:<18} | {psize:>5}B | {src:<16} | {status:<12} | {info_str}")

                        else:
                            print(f"  {proto_num:>5} | {proto_name:<18} | {psize:>5}B | {'BLOCKED/DROP':<16} | {'—':<12} | —")

                    except Exception as e:
                        print(f"  {proto_num:>5} | {proto_name:<18} | {psize:>5}B | {'ERROR':<16} | {'—':<12} | {str(e)[:30]}")
