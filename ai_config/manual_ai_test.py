import os
import sys
import pandas as pd
import numpy as np

# 1. Setup Environment (Agar bisa import detector)
# Pastikan folder dataset ada __init__.py nya
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from dataset.IntrusionDetection.detector import predict_intrusion
    print("✅ Berhasil memuat AI Model!")
except ImportError as e:
    print(f"❌ Gagal import detector. Pastikan struktur folder benar.\nError: {e}")
    sys.exit(1)

def test_scenario(name, features):
    print(f"\n--- Testing Scenario: {name} ---")
    print(f"Input Features: {features}")
    
    # Panggil fungsi AI langsung
    try:
        result = predict_intrusion(features)
        print(f"👉 HASIL PREDIKSI AI: {result}")
        
        if result.upper() != "BENIGN":
            print("✅ AI BERHASIL MENDETEKSI SERANGAN!")
        else:
            print("⚠️ AI menganggap ini AMAN (Benign).")
            
    except Exception as e:
        print(f"❌ Error saat memproses: {e}")

# ==========================================
# DEFINISI 13 FITUR (Sesuai urutan real_time.py)
# 0: Duration, 1: Pkts_To_Srv, 2: Pkts_To_Cli, 
# 3: Bytes_Srv, 4: Bytes_Cli, 5: TCP(1)/UDP(0), 
# 6: App_Len, 7: Payload(1/0), 8: Dir, 
# 9: FIN, 10: SYN, 11: RST, 12: ACK
# ==========================================

# SKENARIO 1: TRAFFIC NORMAL (Web Browsing)
# Durasi 2 detik, paket balas-balasan imbang, ada flag ACK dan PUSH
normal_traffic = [2.5, 12, 14, 500, 2000, 1.0, 0, 1.0, 1.0, 0, 1, 0, 12]

# SKENARIO 2: SYN FLOOD ATTACK (Brutal)
# Durasi cepat, 5000 paket ke server, 0 balasan, 5000 flag SYN
syn_flood = [0.2, 5000, 0, 200000, 0, 1.0, 0, 0, 1.0, 0, 5000, 0, 0]

# SKENARIO 3: NMAP PORT SCAN
# Durasi sangat kilat, 1 paket SYN, 0 balasan (port closed/filtered)
port_scan = [0.001, 1, 0, 60, 0, 1.0, 0, 0, 1.0, 0, 1, 0, 0]

# SKENARIO 4: SLOWLORIS (Low and Slow)
# Durasi lama (15 detik), paket dikit, tapi koneksi nahan
slowloris = [15.0, 8, 2, 300, 100, 1.0, 0, 0, 1.0, 0, 8, 0, 2]

# --- JALANKAN TEST ---
if __name__ == "__main__":
    test_scenario("Normal Web Traffic", normal_traffic)
    test_scenario("SYN Flood Attack", syn_flood)
    test_scenario("Nmap Port Scan", port_scan)
    test_scenario("Slowloris Attack", slowloris)