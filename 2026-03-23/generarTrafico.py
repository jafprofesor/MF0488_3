from scapy.all import *

packets = []

# 1. SYN scan (Nmap) — debe disparar regla de escaneo
for port in [21, 22, 23, 80, 443, 3389, 8080, 3306, 5432, 139]:
    packets.append(IP(src="203.0.113.10", dst="192.168.1.50") /
                   TCP(sport=54321, dport=port, flags="S"))

# 2. Brute force SSH — debe disparar regla de threshold
for i in range(20):
    packets.append(IP(src="203.0.113.10", dst="192.168.1.50") /
                   TCP(sport=54322+i, dport=22, flags="PA") /
                   Raw(load=b"Invalid user admin\n"))

# 3. ICMP flood — debe disparar regla de flood
for i in range(50):
    packets.append(IP(src="203.0.113.99", dst="192.168.1.50") /
                   ICMP())

# 4. Tráfico HTTP con patrón de SQL injection
packets.append(IP(src="203.0.113.20", dst="192.168.1.50") /
               TCP(sport=45678, dport=80, flags="PA") /
               Raw(load=b"GET /index.php?id=1' OR '1'='1 HTTP/1.1\r\nHost: victim.local\r\n\r\n"))

wrpcap("./malware-traffic.pcap", packets)
print(f"PCAP generado: {len(packets)} paquetes")