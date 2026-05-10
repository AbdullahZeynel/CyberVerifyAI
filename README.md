# CyberVerify — AI-Powered Cyber Threat Detection 🛡️

Makine öğrenmesi tabanlı, otonom ve anayasal denetimli siber tehdit tespit ve engelleme sistemi (NIDS/IPS). Bu proje, üç farklı saldırı vektörü (Ağ trafiği, SQL Injection, XSS) için eğitilmiş bağımsız modelleri ve bu modellerin kararlarını şirket politikalarına göre denetleyen "İki Beyinli (Dual-Brain)" bir mimariyi içerir.

> **Not:** Veri setlerinin toplam boyutu 100 GB'ı aştığı için bu depoya eklenmemiştir. Sadece eğitilmiş modeller (`.joblib` & `.pkl`), görselleştirme raporları, test senaryoları ve kaynak kodlar yer almaktadır. Veri setlerine kendi orijinal kaynaklarından ulaşabilirsiniz.

---

## 📁 Proje Mimarisini Oluşturan Modüller

Proje 4 ana klasörden oluşmaktadır:

### 1. [RECON (Network Traffic Anomaly Detection)](./RECON/README.md)
Sayısal ağ trafiği verilerinden (paket boyutu, süre, bayraklar vb.) saldırı türlerini milisaniyeler içinde tespit eden model.
- **En İyi Model:** Random Forest (F1: 0.9399)
- **Tespit Edilen Sınıflar:** DDoS, DoS, Recon, Benign, Mirai, Spoofing, Web-based

### 2. [SQLI (SQL Injection Detection)](./SQLI/README.md)
Metin tabanlı HTTP isteklerini ve SQL sorgularını analiz ederek karmaşık injection saldırılarını tespit eden metin tabanlı NLP/ML pipeline'ı.
- **En İyi Model:** LightGBM (F1: 0.9956)
- **Tespit Edilen Sınıflar:** Boolean Blind, Error-based, Time Blind, Stacked Queries, Inline Query, Benign

### 3. [XSS (Cross-Site Scripting Detection)](./XSS/README.md)
HTML ve JavaScript girdilerini analiz ederek XSS (Cross-Site Scripting) zafiyeti sömürülerini engelleyen yapı.
- **En İyi Model:** XGBoost (F1: 0.9989)
- **Tespit Edilen Sınıflar:** XSS, Benign

### 4. [L1-L2 Architecture (Dual-Brain NIPS)](./L1-L2_architecture/README.md)
Sistemin beynini oluşturan, Go tabanlı ağ ajanı (NIPS) ve Python tabanlı karar motorundan (AI Brain) oluşan mimari. L1 (Sezgisel Motor) saldırıları tespit eder, L2 (Mantıksal Denetçi) ise şirket anayasası/whitelist kurallarına göre nihai kararı (Veto/Drop/Honeypot) verir.

---

## 📊 Kullanılan Veri Setleri ve Linkleri

Depoda yer almayan veri setlerini kendi ortamınızda çoğaltmak isterseniz aşağıdaki linkleri kullanabilirsiniz:

1. **CICIoT2023 (RECON Modülü için):** Çeşitli IoT cihazlarına yapılan saldırıların PCAP ve CSV dökümleri.
   - [Kaggle Linki](https://www.kaggle.com/datasets/madhavmalhotra/unb-cic-iot-dataset) / [UNB Orijinal Kaynak](https://www.unb.ca/cic/datasets/iotdataset-2023.html)
2. **CICIoMT2024 (RECON Modülü için):** IoT Medikal cihazların (MQTT & WiFi) ağ trafiği ve anomali kayıtları.
   - [UNB Orijinal Kaynak](https://www.unb.ca/cic/datasets/iomt-dataset-2024.html)
3. **Web Attacks Dataset (XSS Modülü için):** HuggingFace üzerinde bulunan geniş çaplı web saldırı kayıtları.
   - [HuggingFace: shengqin/web-attacks](https://huggingface.co/datasets/shengqin/web-attacks)
4. **PayloadBox XSS & SQLi Payloads (XSS ve SQLI Modülleri için):** 
   - [GitHub: payloadbox/xss-payload-list](https://github.com/payloadbox/xss-payload-list)
   - [GitHub: payloadbox/sql-injection-payload-list](https://github.com/payloadbox/sql-injection-payload-list)
5. **SQLMap XML Şablonları (SQLI Modülü için):** Veri artırımı (data augmentation) için kullanılmıştır.
   - [GitHub: sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap)

---

## 🚀 Hızlı Başlangıç

Bu repo, her modülün kendi içerisinde bağımsız çalışabilmesi için tasarlanmıştır. Modelleri incelemek ve kendi tahminlerinizi yapmak için her klasörün altındaki `.py` scriptlerini veya eğitilmiş `.joblib` ağırlıklarını kullanabilirsiniz. L1-L2 mimarisinin demo kurulumu için `L1-L2_architecture/README.md` dosyasını inceleyin.

## 📄 Lisans
Bu proje akademik araştırma ve siber güvenlik eğitimleri amacıyla MVP ölçeğinde geliştirilmiştir. Açık kaynak kodludur.
