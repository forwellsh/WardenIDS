import os
import sys
import argparse
from scapy.all import sniff, TCP, Raw

def load_signatures(file_path):
    try:
        with open(file_path, "r") as f:
            return [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]
    except Exception as e:
        print(f"[HATA] İmza dosyası okunamadı: {e}")
        sys.exit(1)

def log_alert(log_file, packet_summary, payload):
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    with open(log_file, "a") as f:
        f.write(f"[ALERT] Şüpheli trafik tespit edildi: {packet_summary}\n")
        f.write(f"İçerik: {payload}\n\n")

def packet_callback(packet, signatures, log_file):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode(errors='ignore').lower()
        except Exception:
            return  # decode edilemeyen paketleri atla

        for signature in signatures:
            if signature in payload:
                alert_msg = packet.summary()
                print(f"[ALERT] Şüpheli trafik tespit edildi: {alert_msg}")
                print(f"İçerik: {payload}\n")
                log_alert(log_file, alert_msg, payload)
                break

def main():
    parser = argparse.ArgumentParser(description="Basit imza tabanlı IDS")
    parser.add_argument("-s", "--signatures", default="signatures.txt", help="İmza dosyası yolu")
    parser.add_argument("-l", "--logfile", default="logs/alerts.log", help="Log dosyası yolu")
    args = parser.parse_args()

    print("İmzalar yükleniyor...")
    signatures = load_signatures(args.signatures)
    print(f"{len(signatures)} imza yüklendi.")
    print("Ağ trafiği izleniyor... (Çıkmak için CTRL+C)")

    sniff(prn=lambda pkt: packet_callback(pkt, signatures, args.logfile), store=0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nİzleme sonlandırıldı.")
