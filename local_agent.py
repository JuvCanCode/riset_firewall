#!/usr/bin/env python3
import argparse
import random
import time
import requests
import torch
import torch.nn as nn
import torch.optim as optim
from scapy.all import sniff

from features import FeatureExtractor, baseline_benign

class FirewallNN(nn.Module):
    def __init__(self):
        super(FirewallNN, self).__init__()
        self.fc1 = nn.Linear(10, 128)
        self.dropout = nn.Dropout(0.2)
        self.fc2 = nn.Linear(128, 64)
        self.fc3 = nn.Linear(64, 1)

    def forward(self, x):
        x = torch.relu(self.fc1(x))
        x = self.dropout(x)
        x = torch.relu(self.fc2(x))
        return torch.sigmoid(self.fc3(x))

# --- Hyperparameter ---
SERVER_URL = "http://10.0.0.254:5000"
SNIFF_TIMEOUT = 10         # detik per ronde (maksimum)
SNIFF_PACKET_CAP = 4000    # hentikan sniff lebih awal saat flood agar ronde tidak berlarut-larut
MAX_ROUND_SAMPLES = 3000   # batasi sampel per ronde
REPLAY_PER_CLASS = 2000    # memori replay per kelas
LOCAL_EPOCHS = 5
BATCH_SIZE = 32
LR = 0.005
SYNC_TIMEOUT = 180         # detik menunggu agregasi ronde selesai (barrier)

extractor = FeatureExtractor()
captured_flows = []

def process_packet(packet):
    item = extractor.extract(packet)
    if item is not None:
        captured_flows.append(item)

def confusion(model, samples):
    """Evaluasi model menggunakan threat score sesuai paper."""
    if not samples:
        return 0, 0, 0, 0
    X = torch.tensor([s[0] for s in samples], dtype=torch.float32)
    y = torch.tensor([s[1] for s in samples], dtype=torch.float32)
    model.eval()
    with torch.no_grad():
        p = model(X)

    suspicious = X[:, 8:9]
    confidence = torch.abs(p - 0.5) * 2.0
    threat_score = 0.6 * p + 0.3 * suspicious + 0.1 * confidence

    pred = (threat_score > 0.6).float()   # flag > 0.6 (paper: 0.6 flag, 0.75 block)

    tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
    tn = int(((pred == 0) & (y == 0)).sum()); fn = int(((pred == 0) & (y == 1)).sum())
    return tp, fp, tn, fn

def balanced_accuracy(tp, fp, tn, fn):
    """Kelas yang tidak ada dinilai netral (0.5) agar host satu-kelas tidak mendapat bobot palsu 1.0."""
    tpr = tp / (tp + fn) if (tp + fn) else 0.5
    tnr = tn / (tn + fp) if (tn + fp) else 0.5
    return (tpr + tnr) / 2

def reservoir_add(buffer, items, seen, cap):
    for it in items:
        seen += 1
        if len(buffer) < cap:
            buffer.append(it)
        else:
            j = random.randrange(seen)
            if j < cap:
                buffer[j] = it
    return seen

def fetch_global():
    r = requests.get(f"{SERVER_URL}/get_global_model", timeout=30).json()
    sd = {k: torch.tensor(v) for k, v in r['state_dict'].items()}
    return sd, int(r['round']), r.get('mode', 'train')

def get_mode():
    try:
        return requests.get(f"{SERVER_URL}/get_mode", timeout=5).json().get('mode', 'train')
    except Exception:
        return 'train'

def main():
    global captured_flows
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', type=str, required=True)
    parser.add_argument('--ip', type=str, required=True)
    args = parser.parse_args()

    local_model = FirewallNN()
    optimizer = optim.Adam(local_model.parameters(), lr=LR)

    print(f"[{args.host}] Agen Jaringan Aktif di IP {args.ip}.")

    # Inisialisasi BERSAMA: semua agent memulai dari model global yang sama
    last_round = 0
    while True:
        try:
            sd, last_round, _ = fetch_global()
            local_model.load_state_dict(sd)
            print(f"[{args.host}] Model awal disinkronkan dari server (ronde {last_round}).")
            break
        except Exception as e:
            print(f"[{args.host}] Menunggu server: {e}")
            time.sleep(1)

    iface_name = f"{args.host}-eth0"
    replay = {0: [], 1: []}
    seen = {0: 0, 1: 0}
    round_idx = 1

    while True:
        print(f"\n[{args.host} - RONDE {round_idx}] Mengendus trafik via Scapy...")

        t_a = time.time()
        sniff(iface=iface_name, prn=process_packet, filter="ip",
              timeout=SNIFF_TIMEOUT, count=SNIFF_PACKET_CAP, store=0)
        t_b = time.time()
        t_mid = (t_a + t_b) / 2   # dipakai server untuk memetakan ronde ke fase skenario

        new_samples = list(captured_flows)   # trafik kontrol FL sudah dibuang di FeatureExtractor
        n_raw = len(new_samples)
        if len(new_samples) > MAX_ROUND_SAMPLES:
            new_samples = random.sample(new_samples, MAX_ROUND_SAMPLES)
        n_att = sum(1 for s in new_samples if s[1][0] == 1.0)

        # ---- 1) Evaluasi PREQUENTIAL: model global ronde sebelumnya diuji pada trafik riil BARU ----
        tp, fp, tn, fn = confusion(local_model, new_samples)
        print(f"[{args.host}] Sniff {t_b - t_a:.1f}s | Trafik riil: {n_raw} paket (sampel {len(new_samples)}, "
              f"serangan {n_att}) | Eval global model -> TP={tp} FP={fp} TN={tn} FN={fn}")

        mode = get_mode()

        if mode == 'test':
            # ---- MODE TEST: model dibekukan, tidak ada training ----
            local_accuracy = balanced_accuracy(tp, fp, tn, fn)
            sample_size = max(len(new_samples), 1)
            print(f"[{args.host}] MODE TEST: tanpa training. Akurasi (balanced) {local_accuracy:.3f}")
        else:
            # ---- 2) Susun data latih: data baru + replay seimbang ----
            for cls in (0, 1):
                seen[cls] = reservoir_add(replay[cls], [s for s in new_samples if int(s[1][0]) == cls],
                                          seen[cls], REPLAY_PER_CLASS)
            train = list(new_samples)
            for cls in (0, 1):
                if replay[cls]:
                    k = min(len(replay[cls]), max(200, len(new_samples) // 2))
                    train += random.sample(replay[cls], k)
            if len(train) < 5:
                print(f"[{args.host}] Trafik riil minim ({len(train)}). Menggunakan baseline telemetry...")
                train += baseline_benign(10)

            X = torch.tensor([s[0] for s in train], dtype=torch.float32)
            y = torch.tensor([s[1] for s in train], dtype=torch.float32)

            n_pos = float(y.sum()); n_neg = float(len(y) - n_pos)
            w_pos = (len(y) / (2 * n_pos)) if n_pos > 0 else 1.0
            w_neg = (len(y) / (2 * n_neg)) if n_neg > 0 else 1.0

            t_train = time.time()
            local_model.train()
            for epoch in range(LOCAL_EPOCHS):
                perm = torch.randperm(len(X))
                for b in range(0, len(X), BATCH_SIZE):
                    idx = perm[b:b + BATCH_SIZE]
                    xb, yb = X[idx], y[idx]
                    weights = torch.where(yb == 1, torch.tensor(w_pos), torch.tensor(w_neg))
                    optimizer.zero_grad()
                    loss = nn.functional.binary_cross_entropy(local_model(xb), yb, weight=weights)
                    loss.backward()
                    optimizer.step()

            ltp, lfp, ltn, lfn = confusion(local_model, train)
            local_accuracy = balanced_accuracy(ltp, lfp, ltn, lfn)
            sample_size = len(train)
            print(f"[{args.host}] Training {time.time() - t_train:.1f}s | Akurasi Lokal (balanced): "
                  f"{local_accuracy:.3f} | data latih {len(train)} (serangan {int(n_pos)})")

        state_dict_serializable = {k: v.numpy().tolist() for k, v in local_model.state_dict().items()}
        payload = {
            "host_id": args.host,
            "state_dict": state_dict_serializable,
            "accuracy": float(local_accuracy),
            "sample_size": int(sample_size),
            "t_mid": float(t_mid),
            "eval": {"tp": tp, "fp": fp, "tn": tn, "fn": fn}
        }

        try:
            response = requests.post(f"{SERVER_URL}/upload_weights", json=payload, timeout=60)
            if response.status_code == 200:
                # BARRIER: tunggu sampai agregasi ronde ini selesai (nomor ronde server naik)
                deadline = time.time() + SYNC_TIMEOUT
                synced = False
                while time.time() < deadline:
                    sd, rnd, _ = fetch_global()
                    if rnd > last_round:
                        local_model.load_state_dict(sd)
                        last_round = rnd
                        synced = True
                        break
                    time.sleep(0.5)
                if synced:
                    print(f"[{args.host}] Sinkronisasi Model Global Ronde {last_round} Sukses.")
                else:
                    print(f"[{args.host}] PERINGATAN: agregasi tidak selesai dalam {SYNC_TIMEOUT}s.")
        except Exception as e:
            print(f"[{args.host}] Kendala API Aggregator: {e}")

        captured_flows.clear()
        round_idx += 1

if __name__ == '__main__':
    main()