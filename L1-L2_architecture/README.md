# L1-L2 Architecture: Dual-Brain NIPS 🧠

Sistemin kalbini oluşturan **"İki Beyinli Anayasal Denetim"** ve Otonom Tehdit Avcılığı mimarisidir. Geleneksel sistemlerin en büyük sorunu olan "Alarm Yorgunluğu" ve makine öğrenmesi sistemlerinin "Kara Kutu (Black-Box)" olmasını çözen bir mühendislik yaklaşımıdır.

## 🏗️ Mimari Tasarım

Sistem birbirine paralel çalışan iki mikroservise bölünmüştür:

### 1. L1 Motoru (Sezgisel Beyin - Random Forest / AI Brain)
Ağdaki trafiği milisaniyeler içinde paket bazında inceler ve anomali tespiti yapar. Trafiğin türüne karar verir (Örn: "Bu bir Ağ Taramasıdır" veya "Bu bir Web Exploit'tir"). Yapay Zeka kısmı Python (FastAPI) ile yazılmıştır.

### 2. L2 Motoru (Mantıksal Denetçi - Veto Engine)
L1'in verdiği engelleme (DROP) kararlarını, **Şirket Anayasasına** (Whitelist / JSON Kuralları) göre denetler. Örneğin, Kurum içi bir Sızma Testi uzmanının (Red Team) trafiği L1 tarafından "Saldırı" algılansa bile, L2 "VETO" kararı verir ve iş sürekliliğini sağlar.

### 3. Honeypot Simülasyonu (Aldatma)
L2'nin süzgecinden geçen ve "Saldırgan" olduğu kesinleşen IP adreslerine, gerçeğiyle birebir aynı sahte bir veritabanı veya sahte bir sunucu yanıtı (Mock) döndürerek saldırganı oyalar.

## 🛠️ Klasör Yapısı (WBS)

```text
cyberverify/
├── nips_agent_go/               # (ANA SÜREÇ) Go-Lang NIPS Kalkanı (Ağ paketlerini yakalar)
│   ├── main.go                  # CLI, gopacket dinleyicisi
│   └── api_client.go            # L1/L2 ile haberleşen API Köprüsü (Fail-Open Korumalı)
├── ai_brain_python/             # (ÇOCUK SÜREÇ) Yapay Zeka ve Karar Merkezi (FastAPI)
│   ├── api.py                   # Tahmin Uç Noktası
│   ├── core/                    # L1, L2 ve Honeypot sınıfları (OOP)
│   └── models/                  # Eğitilmiş AI Ağırlıkları (.pkl)
├── sirket_politikasi.json       # L2 Motoru için Veto / İstisna kuralları
├── test_pcap_senaryolari/       # Demostrasyon için hazırlanan ağ kayıtları (.pcap)
└── logs/                        # SOC Sistem Denetim Logları
```

## 🚀 Çalıştırma (MVP Demo)

Canlı ortamı kesintiye uğratmamak adına sistemi `.pcap` senaryo dosyaları üzerinden çalıştırabilirsiniz.

1. **Önce AI Karar Merkezini Başlatın (Terminal 1):**
   ```bash
   cd ai_brain_python
   pip install -r requirements.txt
   uvicorn api:app --host 127.0.0.1 --port 8000
   ```

2. **Go Ajanı Üzerinden Senaryoları Oynatın (Terminal 2):**
   ```bash
   cd nips_agent_go
   go mod tidy
   
   # Senaryo 1: Masum Trafik
   go run *.go -pcap ../test_pcap_senaryolari/senaryo1_masum_kullanici.pcap
   
   # Senaryo 3: Web İstismarı (Honeypot tetiklenir)
   go run *.go -pcap ../test_pcap_senaryolari/senaryo3_sql_injection.pcap
   
   # Senaryo 4: CEO Veto Testi (L2 müdahalesi)
   go run *.go -pcap ../test_pcap_senaryolari/senaryo4_ceo_veto_istisnasi.pcap
   ```

> **🛡️ Fail-Open Güvenlik Koruması:**
> Go-Lang ajanı (nips_agent_go), eğer Python AI servisine ulaşamazsa veya AI çökerse ağı kilitlemez. Tüm trafiği varsayılan olarak geçirerek (Return 0) iş sürekliliğini güvence altına alır.
