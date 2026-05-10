# SQLI — SQL Injection Detection

Bu modül, HTTP isteklerini ve URL parametrelerini Natural Language Processing (NLP) teknikleriyle inceleyerek sistemdeki veritabanı açıklarını sömürmeye çalışan SQL Injection (SQLi) payloadlarını yakalar.

## 📊 Modül Özeti

Bu model, sadece kelimeleri okumakla kalmaz, SQL injection saldırılarına has noktalama işareti yoğunluğunu, `SELECT`, `UNION`, `SLEEP` gibi anahtar kelimelerin sayısını ve entropi oranlarını içeren **28 El Yapımı (Handcrafted) Özellik** ve **TF-IDF (Term Frequency-Inverse Document Frequency)** matrisi kullanarak eğitilmiştir.

- **Kullanılan Modeller:** LightGBM (En iyi), Random Forest, ExtraTrees, XGBoost, CatBoost, MLP
- **En İyi Model Başarımı:** **LightGBM** (F1 Macro Skoru: **0.9956**, Eğitim Süresi: 18 saniye)
- **Test Edilen Sınıflar:** 
  - `Benign` (Temiz Trafik - 0 False Positive oranı)
  - `boolean_blind`
  - `error_based`
  - `time_blind`
  - `stacked_queries`
  - `inline_query`

## 🗃️ Veri Seti (Dataset) Bilgisi

Eğitim için gerçek dünya zararlı payload'ları ve dinamik veri artırımı (data augmentation) teknikleri kullanılmıştır. 

1. **SQLMap Payload Templates:** 
   - Açık kaynaklı SQLMap projesindeki XML şablonları çekilmiş ve içerisine rastgele sayılar ve tablolar eklenerek zenginleştirilmiştir. [SQLMap Projesi](https://github.com/sqlmapproject/sqlmap)
2. **PayloadBox SQLi Collection:** 
   - Gerçek hayatta WAF atlatmak için kullanılan binlerce zararlı payload. [PayloadBox Repo](https://github.com/payloadbox/sql-injection-payload-list)
3. **Üretilmiş (Synthetic) Benign Data:**
   - Modelin temiz istekleri engellememesi için, içerisinde masum SQL sorguları ve parametreler barındıran temiz veriler üretilmiştir.

## 📂 Klasör İçeriği

- `train_models.py`: TF-IDF ve handcrafted özellikleri çıkaran ve 6 ayrı modeli eğiten ana script.
- `collect_datasets.py`: XML şablonlarını ayrıştıran ve sentetik veri ekleyerek nihai `train/test/val` setlerini oluşturan script.
- `sqli_model_analysis.md`: Hangi saldırı tipinin ne kadar başarılı yakalandığını gösteren detaylı performans analizi raporu.
- `results/`: Eğitilmiş model (`model_lightgbm.joblib`), TF-IDF vectorizer ağırlıkları, confusion matrix ve feature importance grafikleri.
- `sqlmap_payloads/`: Model eğitimi için kullanılan kaynak XML payload şablonları.
