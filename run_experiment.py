#!/usr/bin/env python3
import time
import json
import requests
import pandas as pd
from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch
from mininet.log import setLogLevel

def load_config():
    with open('config.json', 'r') as f:
        return json.load(f)

def run_automated_experiment():
    config = load_config()
    topo_config = config['topology']
    backend_url = config['federated_learning']['backend_url']
    
    net = Mininet(topo=None, build=False, ipBase='10.0.0.0/8')
    
    # SOLUSI PERBAIKAN FATAL: Menggunakan Kontroler Standar bawaan Mininet.
    # Ini menghentikan switch mengirim data biner OpenFlow mentah ke Port 5000 milik Flask.
    print("\n[CONFIG-AUTOMATION] Menambahkan Jaringan Kontroler Standar Bawaan...")
    c0 = net.addController(name='c0', controller=Controller)
    
    print(f"[CONFIG-AUTOMATION] Mengonstruksi OVS Switch: {topo_config['switch_name']}")
    s1 = net.addSwitch(topo_config['switch_name'], cls=OVSKernelSwitch, protocols=topo_config['openflow_protocol'])

    # 1. Membuat daftar 4 Host Jaringan secara Dinamis
    print("[CONFIG-AUTOMATION] Membuat daftar 4 Host Jaringan...")
    mininet_hosts = {}
    for host_data in topo_config['hosts']:
        print(f" -> Membuat Node Virtual: {host_data['name']} (IP Target: {host_data['ip']})")
        h = net.addHost(host_data['name'], ip=host_data['ip'], mac=host_data['mac'])
        mininet_hosts[host_data['name']] = h
        net.addLink(h, s1)

    print("[CONFIG-AUTOMATION] Mengaktifkan Topologi Jaringan Mininet...")
    net.start()
    
    # 2. Loop Otomatis Mengaktifkan 4 Local Agents (Solusi Path Venv Absolut Terintegrasi)
    print("[CONFIG-AUTOMATION] Menginjeksi dan Menyalakan Local Agents pada 4 Host...")
    
    # Mengarah langsung ke lingkungan virtual python user danielagra tempat PyTorch terinstal
    path_ke_venv = "/home/danielagra/Federated-Firewall/riset_firewall/venv"
    
    for host_name, host_obj in mininet_hosts.items():
        ip_addr = host_obj.IP()
        # Memaksa eksekusi menggunakan binary python milik venv proyek Anda
        cmd_string = f'{path_ke_venv}/bin/python3 local_agent.py --host {host_name} --ip {ip_addr} > {host_name}_agent.log 2>&1 &'
        host_obj.cmd(cmd_string)

    print("[CONFIG-AUTOMATION] Menunggu stabilisasi siklus awal FL Jaringan (15 detik)...")
    time.sleep(15)

    # Menarik referensi objek 4 host secara terpisah
    h1 = mininet_hosts['h1']
    h2 = mininet_hosts['h2']
    h3 = mininet_hosts['h3']
    h4 = mininet_hosts['h4']

    # 3. Skenario Trafik Otomatis 1: 2 Host Mengirim Trafik Normal Secara Silang
    print("\n[SKENARIO 1] Memulai Pengiriman Trafik Jaringan Normal (2 Senders -> 2 Targets)...")
    # Nyalakan netcat listener pada kedua host target
    h2.cmd('nc -l -p 8888 > /dev/null &')
    h1.cmd('nc -l -p 8889 > /dev/null &')
    time.sleep(2)

    for i in range(2):
        print(f" -> [Iterasi {i+1}] h1 ping h2 & h2 ping h1...")
        net.ping([h1, h2])
        
        # h1 mengirim traffic biasa ke h2
        h1.cmd('echo "Trafik normal dari h1 ke h2" | nc 10.0.0.2 8888')
        # h2 mengirim traffic biasa ke h1
        h2.cmd('echo "Trafik normal dari h2 ke h1" | nc 10.0.0.1 8889')
        time.sleep(5)

    # 4. Skenario Trafik Otomatis 2: 2 Host Menyerang Secara Bersamaan
    print("\n[SKENARIO 2] Memulai Simulasi Serangan Siber Simultan (2 Attackers -> 2 Targets)...")
    ports_to_scan = ",".join(map(str, config['security_policy']['blocked_ports']))
    
    # Attacker 1: h3 melancarkan Port Scanning ke Target h1
    print(f" -> [ATTACK 1] Attacker h3 melancarkan Port Scanning ke Target h1 ({h1.IP()})")
    h3.cmd(f'nmap -sS -p {ports_to_scan} {h1.IP()} &')
    
    # Attacker 2: h4 melancarkan Flood Attack ke Target h2
    print(f" -> [ATTACK 2] Attacker h4 melancarkan ICMP Flood Attack ke Target h2 ({h2.IP()})")
    h4.cmd(f'ping -f -c 500 {h2.IP()} &')
    
    print("\n[CONFIG-AUTOMATION] Mengunci jaringan untuk proses adaptasi Model Global (30 detik)...")
    time.sleep(30)

    # 5. Menarik Hasil Metrik Evaluasi Riil dari Server
    print("\n[CONFIG-AUTOMATION] Menarik laporan hasil evaluasi metrik performa riil dari Server...")
    try:
        response = requests.get(f"{backend_url}/get_evaluation_metrics")
        if response.status_code == 200:
            real_metrics = response.json()
            df = pd.DataFrame({
                'Metric': ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'False Positive Rate'],
                'Score': [
                    round(real_metrics['accuracy'], 4),
                    round(real_metrics['precision'], 4),
                    round(real_metrics['recall'], 4),
                    round(real_metrics['f1_score'], 4),
                    round(real_metrics['fpr'], 4)
                ]
            })
            df.to_csv('hasil_riset.csv', index=False)
            print("\n[SUKSES] Seluruh metrik kalkulasi riil 4-Host berhasil direkam di 'hasil_riset.csv'!")
        else:
            print("[ERROR] Server merespon namun gagal mengembalikan data metrik.")
    except Exception as e:
        print(f"[ERROR] Masalah komunikasi jaringan: {e}")

    print("\n[CONFIG-AUTOMATION] Seluruh Skenario Eksperimen Selesai. Mematikan Infrastruktur Mininet...")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_automated_experiment()
