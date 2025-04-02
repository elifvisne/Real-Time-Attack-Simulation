from scapy.all import IP, TCP, send
import time

# Hedef IP ve port aralığı
target_ip = "192.168.1.1"  # Hedef IP adresini buraya girin, genelde router
start_port = 1
end_port = 1024  # 1 ile 1024 arasındaki portları tarayacağız

# Port tarama fonksiyonu
def port_scan(target_ip, start_port, end_port):
    for port in range(start_port, end_port + 1):
        # TCP SYN paketi oluştur
        packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
        
        # Paketi gönder
        send(packet, verbose=False)
        print(f"Port {port} tarandı...")

        # Arada bir kısa duraklama yaparak saldırıyı simüle et
        time.sleep(0.1)  # 0.1 saniye arayla gönderiliyor

# Port taraması başlat
port_scan(target_ip, start_port, end_port)
