# XSS — Cross-Site Scripting Detection

Bu modül, kullanıcı girdilerindeki (Form alanları, URL parametreleri, yorum satırları) HTML ve JavaScript tabanlı zararlı kalıpları analiz ederek Web Uygulama Güvenliğini sarsan XSS (Cross-Site Scripting) saldırılarını tespit eder.

## 📊 Modül Özeti

XSS saldırıları çok belirgin yapısal kalıplar (`<script>`, `onerror=`, `javascript:`, `eval(`) barındırdığı için, model **43 farklı el yapımı özellik (handcrafted features)** kullanır. Model, WAF (Web Application Firewall) atlatma (bypass) taktiklerini ve obfuscation (karmaşıklaştırma) tekniklerini algılayabilecek şekilde eğitilmiştir.

- **Kullanılan Modeller:** XGBoost (En iyi), LightGBM, Random Forest, MLP, CatBoost, ExtraTrees
- **En İyi Model Başarımı:** **XGBoost & LightGBM** (F1 Macro Skoru: **0.9989**)
- **Test Edilen Sınıflar:** 
  - `XSS` (Zararlı Payload)
  - `Benign` (Temiz Metin)

> **Not:** XGBoost ve LightGBM aynı skorları üretmesine rağmen, LightGBM 3.2 saniyede eğitilirken XGBoost 45.2 saniye sürmüştür. Modeller normal trafiği engelleme (False Positive) konusunda %0 hata payıyla çalışmaktadır.

## 🗃️ Veri Seti (Dataset) Bilgisi

Model ~11.800 satırlık dengeli bir XSS ve Benign veri seti harmanıyla eğitilmiştir.

1. **HuggingFace (Web-Attacks Dataset):** 
   - 8.985 satırlık XSS ve Benign veri içeren kapsamlı HuggingFace seti. [Link: shengqin/web-attacks](https://huggingface.co/datasets/shengqin/web-attacks)
2. **PayloadBox XSS Collection:** 
   - Çoklu bağlam payload'ları, Burp Intruder fuzzer listeleri ve WAF bypass şablonlarından oluşan koleksiyon. [Link: payloadbox/xss-payload-list](https://github.com/payloadbox/xss-payload-list)
3. **Sentetik HTML/JS:**
   - Normal sayfaların kaynak kodları, masum `<form>` elementleri ve zararsız JSON çıktıları.

## 📂 Klasör İçeriği

- `train_models.py`: 43 boyutlu XSS özel feature'larını çıkarıp, TF-IDF ile birleştiren ve eğitimi sağlayan ana script.
- `collect_datasets.py`: HuggingFace, PayloadBox ve yerel metinleri birleştiren ETL scripti.
- `xss_model_analysis.md`: Overfitting analizi ve model kıyaslamalarını içeren kapsamlı inceleme.
- `results/`: Eğitilmiş ağırlıklar (`model_xgboost.joblib`), scaler'lar ve görselleştirme çıktıları.
- `xss_payloadbox/`: Fuzzing için kullanılan ham XSS zararlı metin kütüphanesi.
