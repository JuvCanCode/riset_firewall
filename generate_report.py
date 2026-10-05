#!/usr/bin/env python3
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import os

def generate_visual_report():
    csv_file = 'hasil_riset_per_ronde.csv'
    
    # Cek apakah file data mentah eksperimen tersedia
    if not os.path.exists(csv_file):
        print(f"[ERROR] Berkas {csv_file} tidak ditemukan!")
        print("Silakan jalankan eksperimen Mininet terlebih dahulu hingga menghasilkan file CSV.")
        return

    print(f"[REPORT] Membaca data eksperimen dari {csv_file}...")
    # PERBAIKAN: Gunakan pd.read_csv() alih-alih pd.DataFrame()
    df = pd.read_csv(csv_file)
    
    # Set tema grafik agar terlihat profesional untuk jurnal/skripsi
    sns.set_theme(style="whitegrid")
    plt.rcParams.update({'font.size': 11})

    # =========================================================================
    # GRAFIK 1: Tren Performa (Metrik) per Ronde
    # =========================================================================
    print("[REPORT] Membuat Grafik 1: Tren Metrik Evaluasi Per Ronde...")
    plt.figure(figsize=(10, 6))
    
    sns.lineplot(data=df, x='Ronde', y='accuracy', label='Accuracy', marker='o', linewidth=2)
    sns.lineplot(data=df, x='Ronde', y='precision', label='Precision', marker='s', linewidth=2)
    sns.lineplot(data=df, x='Ronde', y='recall', label='Recall', marker='^', linewidth=2)
    sns.lineplot(data=df, x='Ronde', y='f1_score', label='F1-Score', marker='d', linewidth=2)
    
    plt.title('Perkembangan Metrik Evaluasi Sepanjang Siklus Federated Learning')
    plt.xlabel('Ronde (Round)')
    plt.ylabel('Nilai (0.0 - 1.0)')
    plt.ylim(-0.05, 1.05)
    plt.xticks(df['Ronde'].unique())
    plt.legend()
    plt.tight_layout()
    
    grafik_loss_path = 'grafik_metrik_ronde.png'
    plt.savefig(grafik_loss_path, dpi=300)
    plt.close()
    print(f" -> [SUKSES] Grafik Metrik disimpan sebagai: {grafik_loss_path}")

    # =========================================================================
    # GRAFIK 2: Analisis Volume TP, FP, TN, FN per Fase
    # =========================================================================
    print("[REPORT] Membuat Grafik 2: Performa Deteksi Riil per Fase...")
    plt.figure(figsize=(10, 6))
    
    # Group data riil berdasarkan fase eksperimen
    df_fase = df.groupby('Fase')[['real_tp', 'real_tn', 'real_fp', 'real_fn']].sum().reset_index()
    
    # Melts data agar mudah di-plot oleh seaborn dengan format batang
    df_melt = pd.melt(df_fase, id_vars=['Fase'], value_vars=['real_tp', 'real_tn', 'real_fp', 'real_fn'], 
                      var_name='Jenis Evaluasi', value_name='Jumlah Paket Riil')
    
    sns.barplot(data=df_melt, x='Fase', y='Jumlah Paket Riil', hue='Jenis Evaluasi', palette='viridis')
    plt.title('Jumlah Tangkapan Paket Trafik (Confusion Matrix Riil) per Fase Jaringan')
    plt.xlabel('Fase Eksperimen')
    plt.ylabel('Total Paket Terproses (Agent Data)')
    plt.xticks(rotation=15)
    plt.tight_layout()
    
    grafik_traffic_path = 'grafik_volume_trafik_fase.png'
    plt.savefig(grafik_traffic_path, dpi=300)
    plt.close()
    print(f" -> [SUKSES] Grafik Volume Deteksi disimpan sebagai: {grafik_traffic_path}")

    # =========================================================================
    # RINGKASAN TEKS STATISTIK
    # =========================================================================
    print("\n=======================================================")
    print("           RINGKASAN EKSEKUSI DATA EKSPERIMEN          ")
    print("=======================================================")
    print(f"Total Ronde Terekam            : {len(df)}")
    if len(df) > 0:
        print(f"Akurasi Keseluruhan (Rata-rata): {df['accuracy'].mean() * 100:.2f}%")
        print(f"Total Serangan Dikenali (TP)   : {df['real_tp'].sum():.0f} paket")
        print(f"Total Serangan Lolos (FN)      : {df['real_fn'].sum():.0f} paket")
        print(f"Total Normal Dikenali (TN)     : {df['real_tn'].sum():.0f} paket")
        print(f"Total Normal Diblokir (FP)     : {df['real_fp'].sum():.0f} paket")
    print("=======================================================")
    print("[SELESAI] Seluruh laporan visual telah sukses diterbitkan!")

if __name__ == '__main__':
    generate_visual_report()
