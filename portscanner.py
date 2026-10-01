from scapy.all import *
from scapy.layers.http import *

ports = [21, 22, 53, 80, 110, 143, 443, 445, 502, 3306, 8080, 20000]

def SynScan(host: str) -> None:
    """Scans host by sending a TCP SYN (half-open) request"""
    ans, _ = sr(IP(dst=host)/TCP(sport=5555, dport=ports, flags="S"), timeout=2, verbose=2)
    for (s,r) in ans:
        if (p := s[TCP].dport) == r[TCP].sport:
            print(f"Port open on {host} at {p}!")

def DNSScan(host: str) -> None:
    """Scans host by sending a DNS query"""
    ans, _ = sr(IP(dst=host)/TCP(sport=5555, dport=53)/DNS(rd=1, qd=DNSQR(qname='www.google.com')), timeout=2, verbose=2)
    if ans:
        print(f"DNS Server found at {host}!")

def HTTPScan(host: str) -> None:
    """Scans host by sending requests to well-known HTTP/WS ports"""
    ws_ports = [80, 443, 8080]
    ans, _ = sr(IP(dst=host)/TCP(sport=5555, dport=ws_ports)/HTTP(), timeout=2, verbose=2)
    for (s, r) in ans:
        if (p := s[TCP].dport) == r[TCP].sport:
            print(f"Web Server found at {host} at {p}!")


host: str = '8.8.8.8'