import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.decomposition import PCA
import matplotlib.pyplot as plt
import os
import joblib

# Çıktıların kaydedileceği klasör
output_dir = "outputs"
os.makedirs(output_dir, exist_ok=True)

# 1. Veri Setini Yükleme
columns = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", 
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", 
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations", 
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", 
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate", 
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", 
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", 
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", 
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate", 
    "dst_host_srv_rerror_rate", "label", "extra"
]

# Veri setini yükle
df = pd.read_csv(r'C:\Users\elifv\Desktop\BGTProje\bitmisbgt\bgt\KDDTrain+.txt', header=None, names=columns)

# 2. Özellik Seçimi ve Kategorik Veriyi Dönüştürme
df = pd.get_dummies(df, columns=["protocol_type", "service", "flag"], drop_first=True)
features = ["src_bytes", "dst_bytes", "count", "same_srv_rate", "diff_srv_rate"]
X = df[features]

# 3. Sınıf Etiketi Eklenmesi
df["anomaly"] = df["label"].apply(lambda x: 0 if "normal" in x else 1)
y = df["anomaly"]

# 4. Veri Temizleme: Eksik Veri Kontrolü
print("Eksik Veri Kontrolü:")
print(df.isnull().sum())  # Eksik verileri kontrol et

# Sayısal sütunlar için eksik veriyi ortalama ile doldur
numerical_columns = df.select_dtypes(include=[np.number]).columns
df[numerical_columns] = df[numerical_columns].fillna(df[numerical_columns].mean())

# Kategorik sütunlar için eksik veriyi mod ile doldur
categorical_columns = df.select_dtypes(include=[object]).columns
for col in categorical_columns:
    df[col] = df[col].fillna(df[col].mode()[0])

# 5. Normalizasyon
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# 6. K-Means Modeli ile Kümeleme
# Optimum k değerini belirlemek için Elbow Method
inertia = []   #hata karesi
k_values = range(1, 10)
for k in k_values:
    kmeans = KMeans(n_clusters=k, random_state=42)
    kmeans.fit(X_scaled)
    inertia.append(kmeans.inertia_)

# Elbow Method grafiğini kaydet
plt.figure(figsize=(8, 5))
plt.plot(k_values, inertia, marker='o')
plt.title("Elbow Method for Optimal k")
plt.xlabel("Number of Clusters (k)")
plt.ylabel("Inertia")
plt.savefig(os.path.join(output_dir, "elbow_method.png"))
plt.close()

# K-Means Modeli (k=2)
kmeans = KMeans(n_clusters=2, random_state=42)
kmeans.fit(X_scaled)
df["cluster"] = kmeans.labels_

# 7. Anomali Tespiti
distances = kmeans.transform(X_scaled).min(axis=1)
threshold = np.percentile(distances, 90)
df["is_anomaly"] = distances > threshold

# Anomali sayısını bir dosyaya yazdır
anomaly_count = df["is_anomaly"].sum()
# normal_count = len(df) - anomaly_count  # Normal veri sayısı
with open(os.path.join(output_dir, "anomaly_count.txt"), "w") as f:
    f.write(f"Toplam Anomali Sayisi: {anomaly_count}\n")
    # f.write(f"Toplam Normal Veri Sayisi: {normal_count}\n")


# 8. Model Performansı Değerlendirmesi
print("\nModel Performansı Değerlendirmesi:")
print(classification_report(y, df["is_anomaly"]))
print(confusion_matrix(y, df["is_anomaly"]))

# 9. Precision, Recall, F1-Score Görselleştirmesi
from sklearn.metrics import precision_recall_fscore_support

# Her sınıf için Precision, Recall, F1-Score hesapla
precision, recall, f1, _ = precision_recall_fscore_support(y, df["is_anomaly"], average=None)

# Saldırı türleri ve metrikler
metrics_df = pd.DataFrame({
    "Precision": precision,
    "Recall": recall,
    "F1-Score": f1
}, index=["Normal", "Anomaly"])

# Görselleştirme
metrics_df.plot(kind="bar", figsize=(10, 6))
plt.title("Precision, Recall, F1-Score for Each Class")
plt.ylabel("Score")
plt.xlabel("Metrics")
plt.savefig(os.path.join(output_dir, "precision_recall_f1.png"))
plt.close()

# 10. PCA ile Görselleştirme
pca = PCA(n_components=2)
X_pca = pca.fit_transform(X_scaled)

plt.figure(figsize=(10, 7))
plt.scatter(X_pca[:, 0], X_pca[:, 1], c=df["cluster"], cmap="viridis", label="Normal Veri")
plt.scatter(X_pca[df["is_anomaly"]][:, 0], X_pca[df["is_anomaly"]][:, 1], c="red", label="Anomaliler", marker="X")
plt.title("PCA ile K-Means Kümeleme ve Anomali Tespiti")
plt.xlabel("PCA1")
plt.ylabel("PCA2")
plt.legend()
plt.savefig(os.path.join(output_dir, "pca_clustering.png"))
plt.close()

# 11. Anomali Detaylarını CSV olarak kaydet
anomalies = df[df["is_anomaly"]]
anomalies[["src_bytes", "dst_bytes", "count", "label"]].to_csv(
    os.path.join(output_dir, "anomaly_details.csv"), index=False
)

# 12. Modeli Kaydetme
joblib.dump(kmeans, os.path.join(output_dir, "kmeans_model.pkl"))
joblib.dump(scaler, os.path.join(output_dir, "scaler.pkl"))

print(f"Çıktılar '{output_dir}' klasörüne kaydedildi.")
