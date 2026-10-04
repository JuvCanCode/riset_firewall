#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

def generate_visual_report():
    csv_file = 'report_traffic_epoch.csv'
    
    # Cek apakah file data mentah eksperimen tersedia
    if not os.path.exists(csv_file):
        print(f"[ERROR] Berkas {csv_file} tidak ditemukan!")
        print("Silakan jalankan eksperimen Mininet terlebih dahulu hingga menghasilkan file CSV.")
        return

    print(f"[REPORT] Membaca data eksperimen dari {csv_file}...")
    df = pd.DataFrame(csv_file)
    
    # Set tema grafik agar terlihat profesional untuk jurnal/skripsi
    sns.set_theme(style="whitegrid")
    plt.rcParams.update({'font.size': 11})
    #test test

    # =========================================================================
    # GRAFIK 1: Tren Penurunan Loss per Node sepanjang Epoch dan Round
    # =========================================================================
    print("[REPORT] Membuat Grafik 1: Tren Nilai Loss Per-Epoch...")
    plt.figure(figsize=(10, 5))
    
    # Membuat kolom gabungan Round-Epoch untuk sumbu X agar terlihat linier
    df['Round_Epoch'] = df.apply(lambda row: f"R{int(row['Round'])}E{int(row['Epoch'])}", axis=1)
    
    sns.lineplot(data=df, x='Round_Epoch', y='Loss', hue='Host', marker='o', linewidth=2)
    plt.title('Karakteristik Penurunan Nilai Loss pada Tiap Node Jaringan')
    plt.xlabel('Siklus Pelatihan (R = Round, E = Epoch)')
    plt.ylabel('Nilai Loss (BCE Loss)')
    plt.xticks(rotation=45)
    plt.tight_layout()
    
    grafik_loss_path = 'grafik_loss_epoch.png'
    plt.savefig(grafik_loss_path, dpi=300)
    plt.close()
    print(f" -> [SUKSES] Grafik Loss disimpan sebagai: {grafik_loss_path}")

    # =========================================================================
    # GRAFIK 2: Analisis Volume Trafik Paket yang Diterima Tiap Node
    # =========================================================================
    print("[REPORT] Membuat Grafik 2: Perbandingan Volume Trafik Paket Jaringan...")
    plt.figure(figsize=(8, 5))
    
    # Mengambil total paket unik per Host di setiap putaran
    df_traffic = df.groupby(['Round', 'Host'])['Traffic_Packets'].first().reset_index()
    
    sns.barplot(data=df_traffic, x='Round', y='Traffic_Packets', hue='Host', palette='viridis')
    plt.title('Perbandingan Volume Paket Trafik yang Teranalisis per Ronde')
    plt.xlabel('Ronde Federated Learning')
    plt.ylabel('Jumlah Paket Data (Ditangkap Scapy)')
    plt.tight_layout()
    
    grafik_traffic_path = 'grafik_volume_trafik.png'
    plt.savefig(grafik_traffic_path, dpi=300)
    plt.close()
    print(f" -> [SUKSES] Grafik Volume Trafik disimpan sebagai: {grafik_traffic_path}")

    # =========================================================================
    # RINGKASAN TEKS STATISTIK
    # =========================================================================
    print("\n=======================================================")
    print("           RINGKASAN EKSEKUSI DATA EKSPERIMEN          ")
    print("=======================================================")
    for host in df['Host'].unique():
        host_df = df[df['Host'] == host]
        max_acc = host_df['Local_Accuracy'].max() * 100
        total_pockets = host_df['Traffic_Packets'].sum()
        print(f"Node Jaringan [{host}]:")
        print(f"  - Akurasi Deteksi Tertinggi : {max_acc:.2f}%")
        print(f"  - Total Akumulasi Paket Trafik: {total_pockets} paket")
    print("=======================================================")
    print("[SELESAI] Seluruh laporan visual telah sukses diterbitkan!")

if __name__ == '__main__':
    generate_visual_report()
