#!/usr/bin/env python3
import os
import sys
import time
import json
import requests
import pandas as pd
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch
from mininet.log import setLogLevel

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def load_config():
    with open(os.path.join(BASE_DIR, 'config.json'), 'r') as f:
        return json.load(f)

def resolve_agent_python():
    """Cari interpreter Python yang punya torch + scapy untuk local agent.
    Urutan: env AGENT_PYTHON -> venv proyek -> interpreter yang sedang dipakai."""
    candidates = [
        os.environ.get('AGENT_PYTHON'),
        os.path.join(BASE_DIR, 'venv', 'bin', 'python3'),
        os.path.join(BASE_DIR, '..', 'venv', 'bin', 'python3'),
        sys.executable,
    ]
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            ok = os.system(f'"{c}" -c "import torch, scapy, requests, numpy" >/dev/null 2>&1') == 0
            if ok:
                return c
            print(f"[WARN] {c} ada, tapi modul torch/scapy/requests/numpy tidak lengkap.")
    return None

def wait_backend(backend_url, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if requests.get(f"{backend_url}/get_evaluation_metrics", timeout=2).status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(1)
    return False

def run_automated_experiment():
    os.chdir(BASE_DIR)
    config = load_config()
    topo_config = config['topology']
    backend_url = config['federated_learning']['backend_url']

    # Pre-flight check: backend & interpreter agent harus siap SEBELUM Mininet dibangun
    if not wait_backend(backend_url):
        print(f"[FATAL] Backend {backend_url} tidak merespon. Jalankan dulu: python3 backend_controller.py")
        return
    # Kosongkan state server agar ronde dari run sebelumnya tidak ikut terhitung
    requests.post(f"{backend_url}/reset", timeout=5)
    agent_python = resolve_agent_python()
    if agent_python is None:
        print("[FATAL] Tidak ada interpreter Python dengan torch+scapy. Buat venv atau set AGENT_PYTHON=/path/python3")
        return
    print(f"[CONFIG-AUTOMATION] Interpreter agent: {agent_python}")
    
    # PERBAIKAN: Tanpa controller eksternal. Class Controller bawaan butuh binary
    # 'controller' yang sering tidak terpasang -> OVS mode 'secure' tanpa flow -> ping 100% drop.
    # failMode='standalone' membuat OVS bertindak sebagai L2 learning switch (action NORMAL).
    net = Mininet(topo=None, build=False, ipBase='10.0.0.0/8', controller=None)
    
    print(f"[CONFIG-AUTOMATION] Mengonstruksi OVS Switch: {topo_config['switch_name']} (standalone)")
    s1 = net.addSwitch(topo_config['switch_name'], cls=OVSKernelSwitch, failMode='standalone')

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
    print("[CONFIG-AUTOMATION] Membuka jalur komunikasi Mininet ke Flask Server...")
    sw = topo_config['switch_name']
    os.system(f'ip addr flush dev {sw}; ip addr add 10.0.0.254/8 dev {sw}; ip link set {sw} up')

    # Verifikasi konektivitas data-plane sebelum eksperimen dimulai
    loss = net.pingAll(timeout=1)
    if loss > 0:
        print(f"[WARN] Packet loss awal {loss}% - cek konfigurasi OVS (ovs-vsctl show).")
    
    # 2. Loop Otomatis Mengaktifkan 4 Local Agents
    print("[CONFIG-AUTOMATION] Menginjeksi dan Menyalakan Local Agents pada 4 Host...")
    agent_script = os.path.join(BASE_DIR, 'local_agent.py')
    for host_name, host_obj in mininet_hosts.items():
        ip_addr = host_obj.IP()
        log_file = os.path.join(BASE_DIR, f'{host_name}_agent.log')
        cmd_string = f'"{agent_python}" -u "{agent_script}" --host {host_name} --ip {ip_addr} > "{log_file}" 2>&1 &'
        host_obj.cmd(cmd_string)

    print("[CONFIG-AUTOMATION] Menunggu stabilisasi siklus awal FL Jaringan (15 detik)...")
    time.sleep(15)
    for host_name in mininet_hosts:
        with open(os.path.join(BASE_DIR, f'{host_name}_agent.log')) as f:
            content = f.read()
        if 'Traceback' in content or 'No such file' in content:
            print(f"[FATAL] Agent {host_name} crash:\n{content}")
            net.stop()
            return

    # Menarik referensi objek 4 host secara terpisah
    h1 = mininet_hosts['h1']
    h2 = mininet_hosts['h2']
    h3 = mininet_hosts['h3']
    h4 = mininet_hosts['h4']

    sc = config.get('scenario', {})
    d_benign1 = int(sc.get('benign_1_duration', 45))
    d_ddos = int(sc.get('ddos_duration', 45))
    d_benign2 = int(sc.get('benign_2_duration', 45))
    victim = mininet_hosts[sc.get('ddos_target', 'h2')]
    attackers = [mininet_hosts[n] for n in sc.get('ddos_attackers', ['h3', 'h4'])]
    payload = int(sc.get('ddos_payload_size', 1200))
    total_duration = d_benign1 + d_ddos + d_benign2 + 30

    # Listener TCP benign (hidup sepanjang eksperimen, restart otomatis tiap koneksi selesai)
    h1.cmd(f"timeout {total_duration} sh -c 'while true; do nc -l -p 8889 > /dev/null 2>&1; done' > /dev/null 2>&1 &")
    h2.cmd(f"timeout {total_duration} sh -c 'while true; do nc -l -p 8888 > /dev/null 2>&1; done' > /dev/null 2>&1 &")
    time.sleep(1)

    def start_benign(pairs, duration):
        """Trafik normal: ping 1 paket/detik (ukuran default) + pesan TCP kecil via netcat."""
        for src, dst, port in pairs:
            loop = (f"while true; do ping -c 1 -W 1 {dst.IP()} > /dev/null 2>&1; "
                    f"echo \"benign {src.name}->{dst.name} $(date +%s)\" | nc -w 1 {dst.IP()} {port} > /dev/null 2>&1; "
                    f"sleep 1; done")
            src.cmd(f"timeout {duration} sh -c '{loop}' > /dev/null 2>&1 &")

    # Semua host berperilaku normal di fase benign
    benign_all = [(h1, h2, 8888), (h2, h1, 8889), (h3, h1, 8889), (h4, h2, 8888)]
    # Saat DDoS, host non-attacker tetap mengirim trafik normal (realistis: serangan bercampur trafik sah)
    benign_bg = [p for p in benign_all if p[0] not in attackers]

    phases = []  # (nama_fase, waktu_mulai)

    # ================= FASE 1: BENIGN =================
    print(f"\n[FASE 1 - BENIGN] Trafik normal seluruh host selama {d_benign1} detik...")
    phases.append(('Fase1_Benign', time.time()))
    start_benign(benign_all, d_benign1)
    net.ping([h1, h2])
    time.sleep(d_benign1)

    # ================= FASE 2: DDoS =================
    names = ", ".join(a.name for a in attackers)
    print(f"\n[FASE 2 - DDoS] {names} melancarkan ICMP Flood (payload {payload} B) ke {victim.name} "
          f"({victim.IP()}) selama {d_ddos} detik + trafik normal latar...")
    phases.append(('Fase2_DDoS', time.time()))
    start_benign(benign_bg, d_ddos)
    for a in attackers:
        # payload besar agar sesuai definisi label serangan di local_agent (ICMP len > 1000)
        a.cmd(f'ping -f -s {payload} -w {d_ddos} {victim.IP()} > /dev/null 2>&1 &')
    time.sleep(d_ddos)
    for a in attackers:
        a.cmd('pkill -f "ping -f"')

    # ================= FASE 3: BENIGN (RECOVERY) =================
    print(f"\n[FASE 3 - BENIGN] Serangan berhenti, kembali trafik normal selama {d_benign2} detik...")
    phases.append(('Fase3_Benign', time.time()))
    start_benign(benign_all, d_benign2)
    print(" -> Uji konektivitas pasca-serangan:")
    net.ping([h1, h2])
    time.sleep(d_benign2)

    print("\n[CONFIG-AUTOMATION] Menunggu ronde FL terakhir selesai (15 detik)...")
    time.sleep(15)

    # 5. Menarik Hasil Metrik Evaluasi Riil dari Server, dipetakan per fase
    print("\n[CONFIG-AUTOMATION] Menarik riwayat metrik evaluasi dari Server...")
    try:
        hist = requests.get(f"{backend_url}/get_history", timeout=5).json()
        n_rounds = len(hist['accuracy'])
        if n_rounds == 0:
            print("[ERROR] Tidak ada ronde agregasi selesai. Cek h*_agent.log dan log backend. CSV tidak ditimpa.")
        else:
            metric_keys = ['accuracy', 'precision', 'recall', 'f1_score', 'fpr']
            t0 = phases[0][1]

            # Tentukan fase tiap ronde berdasarkan timestamp selesainya agregasi
            def phase_of(ts):
                label = phases[0][0]
                for name, start in phases:
                    if ts >= start:
                        label = name
                return label

            rows = []
            for i in range(n_rounds):
                ts = hist['timestamp'][i]
                row = {'Ronde': i + 1, 'Detik': round(ts - t0, 1), 'Fase': phase_of(ts)}
                row.update({k: round(hist[k][i], 4) for k in metric_keys})
                for k in ('tp', 'fp', 'tn', 'fn'):
                    row[f'real_{k}'] = int(hist.get(f'real_{k}', [0] * n_rounds)[i])
                rows.append(row)
            df_round = pd.DataFrame(rows)
            df_round.to_csv(os.path.join(BASE_DIR, 'hasil_riset_per_ronde.csv'), index=False)

            def from_counts(tp, fp, tn, fn):
                """Metrik dari confusion matrix; None jika tidak terdefinisi (mis. tidak ada serangan)."""
                tot = tp + fp + tn + fn
                prec = tp / (tp + fp) if (tp + fp) else None
                rec = tp / (tp + fn) if (tp + fn) else None
                f1 = (2 * prec * rec / (prec + rec)) if (prec is not None and rec is not None and (prec + rec)) else None
                return {'accuracy': (tp + tn) / tot if tot else None, 'precision': prec,
                        'recall': rec, 'f1_score': f1, 'fpr': fp / (fp + tn) if (fp + tn) else None}

            def r4(v):
                return None if v is None else round(v, 4)

            label_map = {'accuracy': 'Accuracy', 'precision': 'Precision', 'recall': 'Recall',
                         'f1_score': 'F1-Score', 'fpr': 'False Positive Rate'}
            groups = [('Keseluruhan', df_round)] + [(n, df_round[df_round['Fase'] == n]) for n, _ in phases]

            # Bagian A: model global diuji pada data uji server (rata-rata per ronde)
            summary = {'Evaluasi': [], 'Metric': []}
            for g, _ in groups:
                summary[g] = []
            for k in metric_keys:
                summary['Evaluasi'].append('Server (data uji)')
                summary['Metric'].append(label_map[k])
                for g, sub in groups:
                    summary[g].append(r4(sub[k].mean()) if len(sub) else None)

            # Bagian B: model global diuji pada TRAFIK RIIL tiap fase (test-then-train, total confusion matrix)
            real = {g: from_counts(*(int(sub[f'real_{c}'].sum()) for c in ('tp', 'fp', 'tn', 'fn')))
                    for g, sub in groups}
            for k in metric_keys:
                summary['Evaluasi'].append('Trafik Riil (federated)')
                summary['Metric'].append(label_map[k])
                for g, _ in groups:
                    summary[g].append(r4(real[g][k]))
            for c in ('tp', 'fp', 'tn', 'fn'):
                summary['Evaluasi'].append('Trafik Riil (federated)')
                summary['Metric'].append(c.upper())
                for g, sub in groups:
                    summary[g].append(int(sub[f'real_{c}'].sum()))

            df = pd.DataFrame(summary)
            df.to_csv(os.path.join(BASE_DIR, 'hasil_riset.csv'), index=False)

            print(f" -> {n_rounds} ronde agregasi: " +
                  ", ".join(f"{n}={int((df_round['Fase'] == n).sum())}" for n, _ in phases))
            print(df.to_string(index=False))
            print("\n[SUKSES] Ringkasan per fase -> 'hasil_riset.csv', detail per ronde -> 'hasil_riset_per_ronde.csv'")
    except Exception as e:
        print(f"[ERROR] Masalah komunikasi jaringan: {e}")

    print("\n[CONFIG-AUTOMATION] Seluruh Skenario Eksperimen Selesai. Mematikan Infrastruktur Mininet...")
    for host_obj in mininet_hosts.values():
        host_obj.cmd('pkill -f local_agent.py; pkill -f "nc -l"; pkill -f "ping -f"')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_automated_experiment()
