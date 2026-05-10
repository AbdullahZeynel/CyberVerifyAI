# RECON — Network Traffic Anomaly Detection

Bu modül, IoT (Nesnelerin İnterneti) ve IoMT (Medikal Nesnelerin İnterneti) cihazlarının ağ trafiği özelliklerini analiz ederek anomali tespiti yapan, Random Forest tabanlı bir makine öğrenmesi motorudur. 

## 📊 Modül Özeti

Ağ trafiği paketlerinden elde edilen `rst_count`, `IAT` (Inter-Arrival Time), `Protocol Type`, `Packet Length` gibi sayısal özellikleri kullanarak gelen trafiğin masum bir kullanıcıya mı yoksa bir saldırgana mı ait olduğunu saptar.

- **Kullanılan Modeller:** Random Forest (En iyi), XGBoost, LightGBM, CatBoost, ExtraTrees, MLP
- **En İyi Model Başarımı:** **Random Forest** (F1 Macro Skoru: **0.9399**)
- **Test Edilen Sınıflar:** 
  - `Benign` (Normal Trafik)
  - `Mirai` (Mirai Botnet Saldırıları - %100 Tespit Oranı)
  - `Recon` (Ağ/Port Taraması - Reconnaissance)
  - `ARP_Spoofing` (Ortadaki Adam / ARP Zehirlenmesi)

## 🗃️ Veri Seti (Dataset) Bilgisi

Bu modül iki büyük siber güvenlik veri setinin **43 ortak özelliği** üzerinden birleştirilmesiyle (toplam ~1.1 Milyon satır) eğitilmiştir. *Dosya boyutları (100+ GB) nedeniyle veri setleri bu repoya dahil edilmemiştir.*

1. **CICIoT2023:** 
   - Kapsamlı IoT anomali tespiti. [UNB Dataset Linki](https://www.unb.ca/cic/datasets/iotdataset-2023.html)
2. **CICIoMT2024:** 
   - MQTT ve WiFi protokollerini kullanan medikal IoT cihazlarının trafiği. [UNB Dataset Linki](https://www.unb.ca/cic/datasets/iomt-dataset-2024.html)

## 📂 Klasör İçeriği

- `train_models.py`: Ortak veri seti üzerinden modellerin eğitildiği ve `.joblib` olarak dışa aktarıldığı script.
- `merge_datasets.py`: CICIoT2023 ve CICIoMT2024 veri setlerini 43 ortak özellik bazında birleştiren script.
- `generate_analysis.py`: Modellerin başarım, overfitting (aşırı öğrenme) riskleri ve confusion matrix değerlerini görselleştiren analiz aracı.
- `results/`: Eğitilmiş AI modelleri (`model_random_forest.joblib` vb.) ve scaler dosyaları.
- `visuals/`: Veri seti dağılımı, Overfitting analizi ve F1 skor heatmap'lerini içeren görsel raporlar.
