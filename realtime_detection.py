import pandas as pd
import joblib
from scapy.all import sniff, TCP
import numpy as np
import csv
import os
from collections import defaultdict
import time

# Model ve scaler'ı yükleyin
kmeans = joblib.load("outputs/kmeans_model.pkl")
scaler = joblib.load("outputs/scaler.pkl")

# Özellikler
features = ["src_bytes", "dst_bytes", "count", "same_srv_rate", "diff_srv_rate"]

# Gerçek zamanlı çıktı dosyasının adı
output_file = "real_time_anomalies.csv"

# Eğer dosya yoksa, başlıkları yazın
if not os.path.exists(output_file):
    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Source Port", "Destination Port", "Packet Length", "Cluster", "Distance", "Is Anomaly", "Anomaly Type"])

# IP bağlantılarını takip etmek için bir sözlük
ip_connections = {}
# Port tarama için belirli bir zaman aralığı ve eşik belirleyelim
port_scan_threshold = 10  # 10 farklı port/ tane
time_window = 10  # 10 saniye içinde yapılan talepler

# Zaman penceresinde bağlantı taleplerini izlemek için bir sözlük
ip_ports = defaultdict(lambda: defaultdict(int))
ip_first_seen = {}

# Paket işleme fonksiyonu
def process_packet(packet):
    try:
        # Sadece TCP paketlerini işleme alıyoruz
        if packet.haslayer(TCP):
            # Paket özelliklerini çıkarma
            src_ip = packet[1].src  # IP katmanındaki kaynak IP
            dst_ip = packet[1].dst  # IP katmanındaki hedef IP
            src_port = packet.sport
            dst_port = packet.dport
            packet_len = len(packet)

            # Yeni veri oluştur
            new_data = pd.DataFrame([[src_port, dst_port, packet_len, 0, 0]], columns=features)
            
            # Veriyi normalleştir
            new_data_scaled = scaler.transform(new_data)

            # Küme tahmini ve mesafe hesaplama
            cluster = kmeans.predict(new_data_scaled)[0]
            distance = kmeans.transform(new_data_scaled).min(axis=1)[0]

            # Anomali tespiti: Mesafe eşik değerini aşarsa anomali olarak işaretlenir
            threshold = np.percentile(kmeans.transform(new_data_scaled).min(axis=1), 95)
            is_anomaly = distance > threshold

            # Port Tarama Saldırısı tespiti
            if src_ip not in ip_first_seen:
                ip_first_seen[src_ip] = time.time()  # İlk görüldüğü zamanı kaydet

            # Aynı IP'den gelen port tarama saldırısını tespit et
            current_time = time.time()
            time_diff = current_time - ip_first_seen[src_ip]

            if time_diff < time_window:  # 10 saniye içinde
                ip_ports[src_ip][dst_port] += 1  # Hedef portu say

                # Eğer bir IP 10 farklı portu hedef almışsa, bu port tarama saldırısıdır
                if len(ip_ports[src_ip]) >= port_scan_threshold:
                    anomaly_type = "Port Scan"
                    is_anomaly = True
                else:
                    anomaly_type = "Normal"
            else:
                ip_ports[src_ip] = defaultdict(int)  # Zaman penceresi geçti, yeniden başlat
                ip_first_seen[src_ip] = current_time

            # SYN Flood saldırısı tespiti
            if packet[TCP].flags == "S":  # SYN bayrağı
                if src_ip not in ip_connections:
                    ip_connections[src_ip] = 0
                ip_connections[src_ip] += 1

                # SYN Flood saldırısı için eşiği kontrol et (100 paket)
                if ip_connections[src_ip] > 100:
                    anomaly_type = "SYN Flood"
                    is_anomaly = True

            # Sonuçları CSV dosyasına kaydetme
            with open(output_file, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([src_port, dst_port, packet_len, cluster, distance, is_anomaly, anomaly_type])

            # Anomali durumu
            print(f"Paket: Source Port={src_port}, Dest Port={dst_port}, Length={packet_len}")
            if is_anomaly:
                print(f">>> ANOMALİ: Mesafe={distance:.2f}, Eşik={threshold:.2f}, Tür={anomaly_type}")
            else:
                print(f"Normal: Mesafe={distance:.2f}")

    except Exception as e:
        print("Hata oluştu:", e)

# Gerçek zamanlı TCP trafiğini dinleme (veya UDP/ICMP trafiği eklemek için filtreyi değiştirebilirsiniz)
print("TCP trafiğini dinliyorum. Çıkmak için Ctrl+C yapabilirsiniz.")
sniff(prn=process_packet, filter="tcp", count=0)
