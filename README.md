# WardenIDS

WardenIDS, **basit imza tabanlı bir Python ağ izleme ve saldırı tespit sistemi (IDS)**dir.  
Ağ trafiğinizi gerçek zamanlı olarak izler, önceden tanımlanmış imzalara (anahtar kelimelere) göre şüpheli aktiviteleri tespit eder ve bu aktiviteleri hem terminalde gösterir hem de log dosyasına kaydeder.

---

## Özellikler

- TCP paketlerinin içeriğini analiz eder.
- İmza tabanlı tespit (imza dosyasındaki anahtar kelimelerle karşılaştırma).
- Şüpheli paketler tespit edildiğinde kullanıcıyı uyarır.
- Log dosyasına uyarı detaylarını kaydeder.
- Kolayca imza dosyası güncellenebilir.
- Açık kaynak ve kolayca geliştirilebilir.

---

## Kurulum
git clone https://github.com/forwellsh/WardenIDS


cd WardenIDS


# Sanal ortam oluştur ve aktif et
python3 -m venv venv


source venv/bin/activate

# Bağımlılıkları yükle
pip install -r requirements.txt

# Kullanım
sudo ./venv/bin/python3 WardenIDS.py
