# import pandas as pd
# from scapy.all import sniff, IP, TCP, UDP, Raw
# from sklearn.ensemble import RandomForestClassifier
# from sklearn.preprocessing import MinMaxScaler
# import joblib
# import numpy as np

# # Load the trained model and scaler
# model = joblib.load("model.pkl")  # Ensure this file exists
# scaler = joblib.load("scaler.pkl")  # Ensure this file exists

# # Expected feature order (must match training data)
# expected_columns = [
#     "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
#     "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
#     "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
#     "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
#     "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
#     "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
#     "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
#     "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
#     "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
# ]

# # Function to preprocess the packet data
# def preprocess_packet(packet):
#     features = {
#         "duration": 0,
#         "protocol_type": packet.proto if packet.haslayer(IP) else 0,
#         "service": 0,
#         "flag": 0,
#         "src_bytes": len(packet.payload),
#         "dst_bytes": len(packet.getlayer(Raw).load) if packet.haslayer(Raw) else 0,
#         "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0,
#         "num_failed_logins": 0, "logged_in": 0, "num_compromised": 0,
#         "root_shell": 0, "su_attempted": 0, "num_root": 0,
#         "num_file_creations": 0, "num_shells": 0, "num_access_files": 0,
#         "num_outbound_cmds": 0, "is_host_login": 0, "is_guest_login": 0,
#         "count": 0, "srv_count": 0, "serror_rate": 0, "srv_serror_rate": 0,
#         "rerror_rate": 0, "srv_rerror_rate": 0, "same_srv_rate": 0,
#         "diff_srv_rate": 0, "srv_diff_host_rate": 0, "dst_host_count": 0,
#         "dst_host_srv_count": 0, "dst_host_same_srv_rate": 0, "dst_host_diff_srv_rate": 0,
#         "dst_host_same_src_port_rate": 0, "dst_host_srv_diff_host_rate": 0,
#         "dst_host_serror_rate": 0, "dst_host_srv_serror_rate": 0,
#         "dst_host_rerror_rate": 0, "dst_host_srv_rerror_rate": 0
#     }

#     df = pd.DataFrame([features])

#     # Ensure correct column order
#     df = df.reindex(columns=expected_columns, fill_value=0)

#     # Scale the features
#     df_scaled = scaler.transform(df)

#     return df_scaled

# # Function to handle each packet
# def packet_callback(packet):
#     try:
#         processed_packet = preprocess_packet(packet)
#         prediction = model.predict(processed_packet)
#         print("Attack detected!" if prediction else "Normal traffic")
#     except Exception as e:
#         print(f"Error processing packet: {e}")

# # Start sniffing packets
# sniff(prn=packet_callback, count=100, store=False)  # Capture 100 packets

import pyshark
import joblib
import pandas as pd

# Memuat model yang sudah disimpan
model = joblib.load("random_forest_nsl_kdd.pkl")

# Daftar fitur yang digunakan saat pelatihan
feature_columns = [
    'duration', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot', 
    'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 
    'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds', 
    'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 
    'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 
    'protocol_type_icmp', 'protocol_type_tcp', 'protocol_type_udp', 'service_IRC', 'service_X11', 
    'service_Z39_50', 'service_aol', 'service_auth', 'service_bgp', 'service_courier', 
    'service_csnet_ns', 'service_ctf', 'service_daytime', 'service_discard', 'service_domain', 
    'service_domain_u', 'service_echo', 'service_eco_i', 'service_ecr_i', 'service_efs', 
    'service_exec', 'service_finger', 'service_ftp', 'service_ftp_data', 'service_gopher', 
    'service_harvest', 'service_hostnames', 'service_http', 'service_http_2784', 'service_http_443', 
    'service_http_8001', 'service_imap4', 'service_iso_tsap', 'service_klogin', 'service_kshell', 
    'service_ldap', 'service_link', 'service_login', 'service_mtp', 'service_name', 
    'service_netbios_dgm', 'service_netbios_ns', 'service_netbios_ssn', 'service_netstat', 
    'service_nnsp', 'service_nntp', 'service_ntp_u', 'service_other', 'service_pm_dump', 
    'service_pop_2', 'service_pop_3', 'service_printer', 'service_private', 'service_red_i', 
    'service_remote_job', 'service_rje', 'service_shell', 'service_smtp', 'service_sql_net', 
    'service_ssh', 'service_sunrpc', 'service_supdup', 'service_systat', 'service_telnet', 
    'service_tftp_u', 'service_tim_i', 'service_time', 'service_urh_i', 'service_urp_i', 
    'service_uucp', 'service_uucp_path', 'service_vmnet', 'service_whois', 'flag_OTH', 
    'flag_REJ', 'flag_RSTO', 'flag_RSTOS0', 'flag_RSTR', 'flag_S0', 'flag_S1', 'flag_S2', 
    'flag_S3', 'flag_SF', 'flag_SH'
]

# Fungsi untuk memproses paket
def process_packet(packet):
    # Ekstrak fitur yang tersedia dari paket
    features = {col: 0 for col in feature_columns}  # Isi semua fitur dengan nilai default

    # Fitur dasar
    features["duration"] = float(packet.frame_info.time_delta)
    features["src_bytes"] = int(packet.length)
    features["dst_bytes"] = int(packet.length)

    # Fitur protocol_type
    if hasattr(packet, 'ip'):
        if hasattr(packet, 'tcp'):
            features["protocol_type_tcp"] = 1
        elif hasattr(packet, 'udp'):
            features["protocol_type_udp"] = 1
        else:
            features["protocol_type_icmp"] = 1

    # Fitur service
    if hasattr(packet, 'http'):
        features["service_http"] = 1
    elif hasattr(packet, 'ftp'):
        features["service_ftp"] = 1
    # Tambahkan layanan lainnya sesuai kebutuhan

    # Fitur flag
    if hasattr(packet, 'tcp'):
        flags = packet.tcp.flags
        features["flag_SF"] = 1 if "SF" in flags else 0
        features["flag_S0"] = 1 if "S0" in flags else 0
        # Tambahkan flag lainnya sesuai kebutuhan

    # Konversi ke DataFrame
    df = pd.DataFrame([features])
    df = df[feature_columns]

    # Cetak data yang digunakan untuk prediksi
    print("Data untuk Prediksi:")
    print(df)

    # Cetak probabilitas prediksi
    proba = model.predict_proba(df)
    print("Probabilitas Prediksi:", proba)

    # Lakukan prediksi
    prediction = model.predict(df)
    df["prediction"] = model.predict(df.drop(columns=["label", "encoded_label"], errors="ignore"))

# Cek hasil prediksi
    print(df[["prediction"]].head())  
    # print("Prediction:", prediction)

# Mulai menangkap paket secara real-time
capture = pyshark.LiveCapture(interface='wlp0s20f3')  # Ganti dengan interface yang sesuai
capture.apply_on_packets(process_packet, packet_count=10)  # Menangkap 10 paket