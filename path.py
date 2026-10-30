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

# ===== FULL ICMP TYPE + CODE MAP =====
icmp_type_map = {
    # Type : (Name, {Code: Code_Name})
    0:  ("Echo Reply",            {0: "Echo Reply"}),
    3:  ("Destination Unreachable", {
            0: "Net Unreachable",
            1: "Host Unreachable",
            2: "Protocol Unreachable",
            3: "Port Unreachable",
            4: "Fragmentation Needed",
            5: "Source Route Failed",
            6: "Dest Network Unknown",
            7: "Dest Host Unknown",
            8: "Src Host Isolated",
            9: "Network Admin Prohibited",
            10:"Host Admin Prohibited",
            11:"Network Unreachable for TOS",
            12:"Host Unreachable for TOS",
            13:"Communication Admin Prohibited",
            14:"Host Precedence Violation",
            15:"Precedence Cutoff",
        }),
    4:  ("Source Quench",         {0: "Source Quench"}),
    5:  ("Redirect",              {
            0: "Redirect for Network",
            1: "Redirect for Host",
            2: "Redirect for TOS & Network",
            3: "Redirect for TOS & Host",
        }),
    8:  ("Echo Request",          {0: "Echo Request"}),
    9:  ("Router Advertisement",  {0: "Router Advertisement"}),
    10: ("Router Solicitation",   {0: "Router Solicitation"}),
    11: ("Time Exceeded",         {
            0: "TTL Exceeded in Transit",
            1: "Fragment Reassembly Time Exceeded",
        }),
    12: ("Parameter Problem",     {
            0: "Pointer Indicates Error",
            1: "Missing Required Option",
            2: "Bad Length",
        }),
    13: ("Timestamp Request",     {0: "Timestamp Request"}),
    14: ("Timestamp Reply",       {0: "Timestamp Reply"}),
    15: ("Information Request",   {0: "Information Request"}),
    16: ("Information Reply",     {0: "Information Reply"}),
    17: ("Address Mask Request",  {0: "Address Mask Request"}),
    18: ("Address Mask Reply",    {0: "Address Mask Reply"}),
    30: ("Traceroute",            {0: "Traceroute"}),
    40: ("Photuris",              {
            0: "Bad SPI",
            1: "Auth Failed",
            2: "Decompress Failed",
            3: "Decrypt Failed",
            4: "Need Authentication",
            5: "Need Authorization",
        }),
}
# ======================================

def decode_icmp(icmp_type, icmp_code):
    if icmp_type in icmp_type_map:
        type_name  = icmp_type_map[icmp_type][0]
        code_map   = icmp_type_map[icmp_type][1]
        code_name  = code_map.get(icmp_code, f"Code-{icmp_code}")
        return f"{type_name} | {code_name}"
    return f"ICMP-Type={icmp_type} Code={icmp_code}"

print("=" * 90)
print(f"  Full Matrix Scan — IP Options + TTL + ToS + Protocol + Payload | Target: {target}")
print("=" * 90)

for opt_name, opt_value in ip_options_list.items():
    print(f"\n{'#'*90}")
    print(f"  [IP Option: {opt_name}]")
    print(f"{'#'*90}")

    for tos in tos_list:
        dscp = tos >> 2
        print(f"\n{'='*90}")
        print(f"  [IP Option={opt_name} | ToS=0x{tos:02X} | DSCP={dscp}]")
        print(f"{'='*90}")

        for ttl in ttl_list:
            print(f"\n  --- TTL={ttl} ---")
            print(f"  {'Proto':>5} | {'Name':<18} | {'PSize':>6} | {'Reply From':<16} | {'ICMP Response':<40} | {'RR/TS Info'}")
            print(f"  {'-'*5}-+-{'-'*18}-+-{'-'*6}-+-{'-'*16}-+-{'-'*40}-+-{'-'*30}")

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

                            # Full ICMP decode
                            if reply.haslayer(ICMP):
                                itype = reply[ICMP].type
                                icode = reply[ICMP].code
                                icmp_str = decode_icmp(itype, icode)
                            else:
                                icmp_str = "Non-ICMP Reply"

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

                            info_str = " | ".join(extra_info) if extra_info else "—"
                            print(f"  {proto_num:>5} | {proto_name:<18} | {psize:>5}B | {src:<16} | {icmp_str:<40} | {info_str}")

                        else:
                            print(f"  {proto_num:>5} | {proto_name:<18} | {psize:>5}B | {'BLOCKED/DROP':<16} | {'—':<40} | —")

                    except Exception as e:
                        print(f"  {proto_num:>5} | {proto_name:<18} | {psize:>5}B | {'ERROR':<16} | {str(e)[:40]:<40} | —")
