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
BLOCKED_PROBE_PORT = 4444   # termasuk security_policy.blocked_ports

def load_config():
    with open(os.path.join(BASE_DIR, 'config.json'), 'r') as f:
        return json.load(f)

def resolve_agent_python():
    """Gunakan interpreter yang sama dengan yang menjalankan skrip ini."""
    return sys.executable

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

    if not wait_backend(backend_url):
        print(f"[FATAL] Backend {backend_url} tidak merespon. Jalankan dulu: python3 backend_controller.py")
        return
    requests.post(f"{backend_url}/reset", timeout=5)   # reset juga mengembalikan mode ke 'train'
    agent_python = resolve_agent_python()
    print(f"[CONFIG-AUTOMATION] Interpreter agent: {agent_python}")

    net = Mininet(topo=None, build=False, ipBase='10.0.0.0/8', controller=None)

    print(f"[CONFIG-AUTOMATION] Mengonstruksi OVS Switch: {topo_config['switch_name']} (standalone)")
    s1 = net.addSwitch(topo_config['switch_name'], cls=OVSKernelSwitch, failMode='standalone')

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
    os.system(f'ovs-ofctl add-flow {sw} actions=NORMAL')

    loss = net.pingAll(timeout=1)
    if loss > 0:
        print(f"[WARN] Packet loss awal {loss}% - cek konfigurasi OVS (ovs-vsctl show).")

    print("[CONFIG-AUTOMATION] Menginjeksi dan Menyalakan Local Agents pada 4 Host...")
    agent_script = os.path.join(BASE_DIR, 'local_agent.py')
    ppath = os.environ.get('PYTHONPATH', '')
    for host_name, host_obj in mininet_hosts.items():
        ip_addr = host_obj.IP()
        log_file = os.path.join(BASE_DIR, f'{host_name}_agent.log')
        cmd_string = f'PYTHONPATH="{ppath}" "{agent_python}" -u "{agent_script}" --host {host_name} --ip {ip_addr} > "{log_file}" 2>&1 &'
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

    h1 = mininet_hosts['h1']
    h2 = mininet_hosts['h2']
    h3 = mininet_hosts['h3']
    h4 = mininet_hosts['h4']

    sc = config.get('scenario', {})
    # Fase learning (model dilatih; berisi benign + burst serangan)
    learn_cycles = int(sc.get('learn_cycles', 4))
    learn_idle = int(sc.get('learn_idle', 20))      # detik benign sebelum tiap burst
    learn_burst = int(sc.get('learn_burst', 10))    # detik durasi tiap burst serangan
    port_probe = bool(sc.get('port_probe', True))   # sertakan akses ke port terlarang
    # Fase test (model dibekukan)
    d_benign1 = int(sc.get('benign_1_duration', 45))
    d_ddos = int(sc.get('ddos_duration', 45))
    d_benign2 = int(sc.get('benign_2_duration', 45))
    victim = mininet_hosts[sc.get('ddos_target', 'h2')]
    attackers = [mininet_hosts[n] for n in sc.get('ddos_attackers', ['h3', 'h4'])]
    payload = int(sc.get('ddos_payload_size', 1200))
    d_learn = learn_cycles * (learn_idle + learn_burst + 1)
    total_duration = d_learn + d_benign1 + d_ddos + d_benign2 + 60

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

    def start_flood(duration):
        for a in attackers:
            a.cmd(f'ping -f -s {payload} -w {duration} {victim.IP()} > /dev/null 2>&1 &')

    def stop_flood():
        for a in attackers:
            a.cmd('pkill -f "ping -f"')

    def start_port_probe(duration):
        """Akses TCP ke port terlarang (label serangan kelas 'port scan')."""
        for a in attackers:
            loop = f"while true; do nc -w 1 -z {victim.IP()} {BLOCKED_PROBE_PORT} > /dev/null 2>&1; sleep 0.5; done"
            a.cmd(f"timeout {duration} sh -c '{loop}' > /dev/null 2>&1 &")

    benign_all = [(h1, h2, 8888), (h2, h1, 8889), (h3, h1, 8889), (h4, h2, 8888)]
    benign_bg = [p for p in benign_all if p[0] not in attackers]

    phases = []  # (nama_fase, waktu_mulai)

    # ================= FASE 1: LEARNING (benign + burst serangan, model dilatih) =================
    requests.post(f"{backend_url}/set_mode", json={"mode": "train"}, timeout=5)
    print(f"\n[FASE 1 - LEARNING] {learn_cycles} siklus: {learn_idle}s benign + {learn_burst}s burst serangan "
          f"(total {d_learn}s). Model DILATIH.")
    phases.append(('Fase1_Learning', time.time()))
    start_benign(benign_all, d_learn)
    for c in range(learn_cycles):
        time.sleep(learn_idle)
        print(f" -> Burst serangan {c + 1}/{learn_cycles}")
        start_flood(learn_burst)
        if port_probe:
            start_port_probe(learn_burst)
        time.sleep(learn_burst + 1)
        stop_flood()

    # ================= FASE TEST: model dibekukan =================
    requests.post(f"{backend_url}/set_mode", json={"mode": "test"}, timeout=5)

    print(f"\n[FASE 2 - TEST/BENIGN] Model DIBEKUKAN. Trafik normal selama {d_benign1} detik...")
    phases.append(('Fase2_Test_Benign', time.time()))
    start_benign(benign_all, d_benign1)
    net.ping([h1, h2])
    time.sleep(d_benign1)

    names = ", ".join(a.name for a in attackers)
    print(f"\n[FASE 3 - TEST/DDoS] {names} ICMP Flood (payload {payload} B) ke {victim.name} "
          f"({victim.IP()}) selama {d_ddos} detik + trafik normal latar...")
    phases.append(('Fase3_Test_DDoS', time.time()))
    start_benign(benign_bg, d_ddos)
    start_flood(d_ddos)
    if port_probe:
        start_port_probe(d_ddos)
    time.sleep(d_ddos)
    stop_flood()

    print(f"\n[FASE 4 - TEST/BENIGN] Serangan berhenti, kembali trafik normal selama {d_benign2} detik...")
    phases.append(('Fase4_Test_Benign', time.time()))
    start_benign(benign_all, d_benign2)
    print(" -> Uji konektivitas pasca-serangan:")
    net.ping([h1, h2])
    time.sleep(d_benign2)

    print("\n[CONFIG-AUTOMATION] Menunggu ronde FL terakhir selesai (25 detik)...")
    time.sleep(25)

    print("\n[CONFIG-AUTOMATION] Menarik riwayat metrik evaluasi dari Server...")
    try:
        hist = requests.get(f"{backend_url}/get_history", timeout=5).json()
        n_rounds = len(hist['accuracy'])
        if n_rounds == 0:
            print("[ERROR] Tidak ada ronde agregasi selesai. Cek h*_agent.log dan log backend. CSV tidak ditimpa.")
        else:
            metric_keys = ['accuracy', 'precision', 'recall', 'f1_score', 'fpr']
            t0 = phases[0][1]

            def phase_of(ts):
                label = phases[0][0]
                for name, start in phases:
                    if ts >= start:
                        label = name
                return label

            rows = []
            for i in range(n_rounds):
                ts = hist['timestamp'][i]
                row = {'Ronde': i + 1, 'Detik': round(ts - t0, 1), 'Fase': phase_of(ts),
                       'Mode': 'test' if hist.get('is_test', [0] * n_rounds)[i] else 'train'}
                row.update({k: round(hist[k][i], 4) for k in metric_keys})
                for k in ('tp', 'fp', 'tn', 'fn'):
                    row[f'real_{k}'] = int(hist.get(f'real_{k}', [0] * n_rounds)[i])
                rows.append(row)
            df_round = pd.DataFrame(rows)
            df_round.to_csv(os.path.join(BASE_DIR, 'hasil_riset_per_ronde.csv'), index=False)

            def from_counts(tp, fp, tn, fn):
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
            # 'Test_Gabungan' = seluruh ronde fase test (model dibekukan) -> angka utama untuk skripsi
            test_df = df_round[df_round['Fase'] != 'Fase1_Learning']
            groups = [('Keseluruhan', df_round), ('Test_Gabungan', test_df)] + \
                     [(n, df_round[df_round['Fase'] == n]) for n, _ in phases]

            summary = {'Evaluasi': [], 'Metric': []}
            for g, _ in groups:
                summary[g] = []
            for k in metric_keys:
                summary['Evaluasi'].append('Server (data uji)')
                summary['Metric'].append(label_map[k])
                for g, sub in groups:
                    summary[g].append(r4(sub[k].mean()) if len(sub) else None)

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
            
            # --- TAMBAHAN: Laporan Rata-rata Akhir ---
            avg_report = []
            for i, metric in enumerate(summary['Metric']):
                if metric in ['Accuracy', 'Precision', 'Recall', 'F1-Score']:
                    avg_report.append({
                        'Evaluasi': summary['Evaluasi'][i],
                        'Metric': metric,
                        'Rata_Rata_Akhir': summary['Test_Gabungan'][i]
                    })
            df_avg = pd.DataFrame(avg_report)
            df_avg.to_csv(os.path.join(BASE_DIR, 'hasil_rata_rata_akhir.csv'), index=False)
            
            print("\n=== Laporan Rata-Rata Akhir ===")
            print(df_avg.to_string(index=False))
            # -----------------------------------------

            print("\n[SUKSES] Ringkasan -> 'hasil_riset.csv' (pakai kolom Test_Gabungan), "
                  "detail per ronde -> 'hasil_riset_per_ronde.csv', rata-rata akhir -> 'hasil_rata_rata_akhir.csv'")
    except Exception as e:
        print(f"[ERROR] Masalah komunikasi jaringan: {e}")

    print("\n[CONFIG-AUTOMATION] Seluruh Skenario Eksperimen Selesai. Mematikan Infrastruktur Mininet...")
    for host_obj in mininet_hosts.values():
        host_obj.cmd('pkill -f local_agent.py; pkill -f "nc -l"; pkill -f "ping -f"')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_automated_experiment()