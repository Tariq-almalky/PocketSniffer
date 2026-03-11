#!/usr/bin/env python3
“””
╔══════════════════════════════════════════════════╗
║          PACKET SNIFFER  v1.0.0                  ║
║     Network Traffic Analyzer · Python 3          ║
║       Developed by Tariq H. Almlaki              ║
╚══════════════════════════════════════════════════╝

Requirements:
pip install scapy
Run with: sudo python packet_sniffer.py
“””

import sys
import time
import argparse
import signal
import os
from datetime import datetime
from collections import defaultdict

# ─── Check scapy ──────────────────────────────────────────

try:
from scapy.all import (
sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR,
get_if_list, conf, Raw, Ether, IPv6
)
except ImportError:
print(”\n  [!] scapy not installed. Run:\n”)
print(”      pip install scapy\n”)
sys.exit(1)

# ─── ANSI Colors ───────────────────────────────────────────

class C:
RESET   = “\033[0m”
BOLD    = “\033[1m”
DIM     = “\033[2m”
GREEN   = “\033[92m”
RED     = “\033[91m”
YELLOW  = “\033[93m”
CYAN    = “\033[96m”
BLUE    = “\033[94m”
GRAY    = “\033[90m”
WHITE   = “\033[97m”
MAGENTA = “\033[95m”
ORANGE  = “\033[38;5;214m”

# ─── Globals ───────────────────────────────────────────────

stats = {
“total”:   0,
“tcp”:     0,
“udp”:     0,
“icmp”:    0,
“arp”:     0,
“dns”:     0,
“other”:   0,
“bytes”:   0,
}
ip_counter   = defaultdict(int)
port_counter = defaultdict(int)
start_time   = None
packet_log   = []
running      = True

# ─── Banner ────────────────────────────────────────────────

def print_banner():
print(f”””
{C.BLUE}{C.BOLD}
███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗
██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
{C.RESET}  {C.CYAN}P A C K E T   S N I F F E R{C.RESET}  {C.GRAY}v1.0.0{C.RESET}
{C.GRAY}Developed by {C.RESET}{C.BOLD}{C.WHITE}Tariq H. Almlaki{C.RESET}
“””)

# ─── Protocol color/label ──────────────────────────────────

def proto_tag(name):
colors = {
“TCP”:   C.GREEN,
“UDP”:   C.CYAN,
“ICMP”:  C.YELLOW,
“ARP”:   C.MAGENTA,
“DNS”:   C.ORANGE,
“IPv6”:  C.BLUE,
“OTHER”: C.GRAY,
}
col = colors.get(name, C.GRAY)
return f”{col}{C.BOLD}{name:<5}{C.RESET}”

# ─── Known ports ──────────────────────────────────────────

KNOWN_PORTS = {
20: “FTP-data”, 21: “FTP”, 22: “SSH”, 23: “Telnet”,
25: “SMTP”, 53: “DNS”, 67: “DHCP”, 68: “DHCP”,
80: “HTTP”, 110: “POP3”, 143: “IMAP”, 443: “HTTPS”,
445: “SMB”, 3306: “MySQL”, 3389: “RDP”, 5432: “PostgreSQL”,
6379: “Redis”, 8080: “HTTP-Alt”, 8443: “HTTPS-Alt”,
27017: “MongoDB”, 1194: “OpenVPN”, 1723: “PPTP”,
}

def port_label(port):
return KNOWN_PORTS.get(port, str(port))

# ─── Packet size bar ──────────────────────────────────────

def size_bar(size):
width = min(12, max(1, size // 50))
return f”{C.GRAY}{‘▪’ * width}{C.RESET}”

# ─── Packet Handler ───────────────────────────────────────

def handle_packet(pkt):
global stats, packet_log

```
stats["total"] += 1
size = len(pkt)
stats["bytes"] += size
ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

proto = "OTHER"
src = dst = "?"
sport = dport = None
info = ""

try:
    # ── ARP ──────────────────────────────────────────
    if pkt.haslayer(ARP):
        proto = "ARP"
        stats["arp"] += 1
        src = pkt[ARP].psrc
        dst = pkt[ARP].pdst
        op  = "who-has" if pkt[ARP].op == 1 else "is-at"
        info = f"{C.MAGENTA}{op}{C.RESET}"

    # ── IP-based ─────────────────────────────────────
    elif pkt.haslayer(IP):
        src = pkt[IP].src
        dst = pkt[IP].dst
        ip_counter[src] += 1

        # DNS
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            proto = "DNS"
            stats["dns"] += 1
            qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
            info = f"{C.ORANGE}query {C.WHITE}{qname}{C.RESET}"

        elif pkt.haslayer(TCP):
            proto = "TCP"
            stats["tcp"] += 1
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            port_counter[dport] += 1
            flags = pkt[TCP].flags
            flag_str = ""
            if flags & 0x02: flag_str += f"{C.GREEN}SYN{C.RESET} "
            if flags & 0x10: flag_str += f"{C.CYAN}ACK{C.RESET} "
            if flags & 0x01: flag_str += f"{C.RED}FIN{C.RESET} "
            if flags & 0x04: flag_str += f"{C.RED}RST{C.RESET} "
            if flags & 0x08: flag_str += f"{C.YELLOW}PSH{C.RESET} "
            svc = KNOWN_PORTS.get(dport) or KNOWN_PORTS.get(sport, "")
            svc_str = f" {C.GRAY}[{svc}]{C.RESET}" if svc else ""
            info = f"{flag_str.strip()}{svc_str}"

        elif pkt.haslayer(UDP):
            proto = "UDP"
            stats["udp"] += 1
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            port_counter[dport] += 1
            svc = KNOWN_PORTS.get(dport) or KNOWN_PORTS.get(sport, "")
            info = f"{C.GRAY}[{svc}]{C.RESET}" if svc else ""

        elif pkt.haslayer(ICMP):
            proto = "ICMP"
            stats["icmp"] += 1
            icmp_types = {0: "reply", 8: "echo", 3: "unreachable", 11: "TTL-exceeded"}
            t = icmp_types.get(pkt[ICMP].type, f"type={pkt[ICMP].type}")
            info = f"{C.YELLOW}{t}{C.RESET}"

        else:
            stats["other"] += 1

    elif pkt.haslayer(IPv6):
        proto = "IPv6"
        stats["other"] += 1
        src = str(pkt[IPv6].src)
        dst = str(pkt[IPv6].dst)

    else:
        stats["other"] += 1

except Exception:
    stats["other"] += 1

# ── Format port string ────────────────────────────────
port_str = ""
if sport and dport:
    port_str = f"{C.GRAY}{port_label(sport)}{C.RESET}{C.GRAY}→{C.RESET}{C.WHITE}{port_label(dport)}{C.RESET}"

# ── Print packet line ─────────────────────────────────
num_str  = f"{C.GRAY}#{stats['total']:<5}{C.RESET}"
ts_str   = f"{C.GRAY}{ts}{C.RESET}"
src_str  = f"{C.CYAN}{src:<15}{C.RESET}"
dst_str  = f"{C.WHITE}{dst:<15}{C.RESET}"
size_str = f"{C.GRAY}{size:>5}B{C.RESET} {size_bar(size)}"

line = f"  {num_str}  {ts_str}  {proto_tag(proto)}  {src_str} → {dst_str}"
if port_str:
    line += f"  {port_str}"
if info:
    line += f"  {info}"
line += f"  {size_str}"

print(line)
packet_log.append({
    "time": ts, "proto": proto,
    "src": src, "dst": dst,
    "sport": sport, "dport": dport,
    "size": size, "info": info
})
```

# ─── Live Stats ───────────────────────────────────────────

def print_stats():
elapsed = time.time() - start_time if start_time else 1
pps     = stats[“total”] / elapsed
mbps    = (stats[“bytes”] * 8) / (elapsed * 1_000_000)

```
print(f"\n  {C.BOLD}{C.WHITE}── STATISTICS ──────────────────────────────────────{C.RESET}")
print(f"  Duration   : {C.YELLOW}{elapsed:.1f}s{C.RESET}   "
      f"Rate: {C.GREEN}{pps:.1f} pkt/s{C.RESET}   "
      f"Bandwidth: {C.CYAN}{mbps:.3f} Mbps{C.RESET}")
print(f"  Total      : {C.WHITE}{stats['total']:,}{C.RESET} packets  "
      f"({C.GRAY}{stats['bytes']:,} bytes{C.RESET})")
print(f"  Breakdown  : "
      f"{C.GREEN}TCP {stats['tcp']}{C.RESET}  "
      f"{C.CYAN}UDP {stats['udp']}{C.RESET}  "
      f"{C.YELLOW}ICMP {stats['icmp']}{C.RESET}  "
      f"{C.MAGENTA}ARP {stats['arp']}{C.RESET}  "
      f"{C.ORANGE}DNS {stats['dns']}{C.RESET}  "
      f"{C.GRAY}Other {stats['other']}{C.RESET}")

if ip_counter:
    top_ips = sorted(ip_counter.items(), key=lambda x: -x[1])[:5]
    print(f"  Top IPs    : ", end="")
    print("  ".join(f"{C.CYAN}{ip}{C.RESET}{C.GRAY}({n}){C.RESET}" for ip, n in top_ips))

if port_counter:
    top_ports = sorted(port_counter.items(), key=lambda x: -x[1])[:5]
    print(f"  Top Ports  : ", end="")
    print("  ".join(f"{C.WHITE}{port_label(p)}{C.RESET}{C.GRAY}({n}){C.RESET}" for p, n in top_ports))

print(f"  {C.GRAY}{'─' * 56}{C.RESET}\n")
```

# ─── Save capture ─────────────────────────────────────────

def save_log(filename=“capture.txt”):
with open(filename, “w”) as f:
f.write(f”Packet Capture — {datetime.now()}\n”)
f.write(f”{‘─’*60}\n”)
f.write(f”{’#’:<6} {‘TIME’:<14} {‘PROTO’:<6} {‘SRC’:<16} {‘DST’:<16} {‘SIZE’}\n”)
f.write(f”{‘─’*60}\n”)
for i, p in enumerate(packet_log, 1):
f.write(f”{i:<6} {p[‘time’]:<14} {p[‘proto’]:<6} “
f”{p[‘src’]:<16} {p[‘dst’]:<16} {p[‘size’]}B\n”)
f.write(f”\nTotal: {stats[‘total’]} packets, {stats[‘bytes’]} bytes\n”)
print(f”  {C.GREEN}✓ Saved {len(packet_log)} packets to {C.BOLD}{filename}{C.RESET}”)

# ─── Signal handler ───────────────────────────────────────

def on_exit(sig, frame):
global running
running = False
print(f”\n\n  {C.YELLOW}Stopping capture…{C.RESET}”)
print_stats()

```
if packet_log:
    try:
        ans = input(f"  Save capture to file? [{C.GRAY}Y/n{C.RESET}]: ").strip().lower()
        if ans != "n":
            save_log()
    except Exception:
        pass

print(f"\n  {C.GREEN}✓ Done. Stay curious.{C.RESET}\n")
sys.exit(0)
```

# ─── List interfaces ──────────────────────────────────────

def list_interfaces():
print(f”\n  {C.BOLD}Available network interfaces:{C.RESET}\n”)
for i, iface in enumerate(get_if_list(), 1):
marker = f”{C.GREEN}*{C.RESET}” if iface == conf.iface else “ “
print(f”  {marker} {C.WHITE}{i}.{C.RESET} {C.CYAN}{iface}{C.RESET}”)
print()

# ─── Check root ───────────────────────────────────────────

def check_root():
if os.geteuid() != 0:
print(f”\n  {C.RED}{C.BOLD}[!] Root privileges required.{C.RESET}”)
print(f”  {C.YELLOW}Run with: sudo python {sys.argv[0]}{C.RESET}\n”)
sys.exit(1)

# ─── Header row ───────────────────────────────────────────

def print_header():
print(f”  {C.GRAY}{’#’:<7} {‘TIME’:<14} {‘PROTO’:<6} {‘SRC’:<16} {‘→’} {‘DST’:<15}  {‘PORTS / INFO’}{C.RESET}”)
print(f”  {C.GRAY}{‘─’ * 78}{C.RESET}”)

# ─── Main ──────────────────────────────────────────────────

def main():
parser = argparse.ArgumentParser(
description=“Packet Sniffer — Human-Friendly Network Analyzer”,
formatter_class=argparse.RawDescriptionHelpFormatter,
epilog=”””
Examples:
sudo python packet_sniffer.py                    # interactive
sudo python packet_sniffer.py -i eth0            # specific interface
sudo python packet_sniffer.py -i eth0 -n 100     # capture 100 packets
sudo python packet_sniffer.py -f “tcp port 80”   # BPF filter
sudo python packet_sniffer.py –list             # list interfaces
sudo python packet_sniffer.py -i eth0 -f “udp” –save
“””
)
parser.add_argument(”-i”, “–interface”, help=“Network interface (default: auto)”)
parser.add_argument(”-n”, “–count”,     type=int, default=0,
help=“Packets to capture (0 = unlimited)”)
parser.add_argument(”-f”, “–filter”,    default=””,
help=“BPF filter e.g. ‘tcp port 80’”)
parser.add_argument(”–list”,            action=“store_true”,
help=“List available interfaces and exit”)
parser.add_argument(”–save”,            action=“store_true”,
help=“Auto-save capture on exit”)
parser.add_argument(”–no-banner”,       action=“store_true”,
help=“Skip banner”)
args = parser.parse_args()

```
if not args.no_banner:
    print_banner()

check_root()

if args.list:
    list_interfaces()
    return

# Interactive interface selection
iface = args.interface
if not iface:
    list_interfaces()
    try:
        choice = input(f"  {C.CYAN}Interface{C.RESET} (press Enter for default [{C.GRAY}{conf.iface}{C.RESET}]): ").strip()
        iface = choice if choice else conf.iface
    except (KeyboardInterrupt, EOFError):
        print()
        sys.exit(0)

# Interactive filter
bpf = args.filter
if not bpf and not args.interface:
    try:
        bpf = input(f"  {C.CYAN}BPF Filter{C.RESET} (e.g. tcp, udp, port 80) [{C.GRAY}none{C.RESET}]: ").strip()
    except (KeyboardInterrupt, EOFError):
        print()
        sys.exit(0)

# Interactive count
count = args.count
if count == 0 and not args.interface:
    try:
        c = input(f"  {C.CYAN}Packet limit{C.RESET} (0 = unlimited) [{C.GRAY}0{C.RESET}]: ").strip()
        count = int(c) if c.isdigit() else 0
    except (KeyboardInterrupt, EOFError):
        print()
        sys.exit(0)

global start_time
start_time = time.time()

signal.signal(signal.SIGINT, on_exit)

print(f"\n  {C.GRAY}{'─' * 78}{C.RESET}")
print(f"  {C.BOLD}Sniffing on {C.CYAN}{iface}{C.RESET}"
      + (f"  filter: {C.YELLOW}{bpf}{C.RESET}" if bpf else "")
      + (f"  limit: {C.WHITE}{count}{C.RESET}" if count else "  {C.GRAY}unlimited{C.RESET}"))
print(f"  {C.GRAY}Press Ctrl+C to stop{C.RESET}")
print(f"  {C.GRAY}{'─' * 78}{C.RESET}\n")
print_header()

try:
    sniff(
        iface=iface,
        filter=bpf if bpf else None,
        prn=handle_packet,
        count=count if count > 0 else 0,
        store=False,
    )
except PermissionError:
    print(f"\n  {C.RED}Permission denied. Run with sudo.{C.RESET}\n")
    sys.exit(1)
except Exception as e:
    print(f"\n  {C.RED}Error: {e}{C.RESET}\n")
    sys.exit(1)

# Finished (count reached)
print_stats()
if args.save and packet_log:
    save_log()
```

if **name** == “**main**”:
main()