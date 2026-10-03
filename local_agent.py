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

# --- Hyperparameter pelatihan lokal ---
SNIFF_TIMEOUT = 10        # detik per ronde
MAX_ROUND_SAMPLES = 3000  # batasi sampel per ronde (ICMP flood bisa menghasilkan puluhan ribu paket)
REPLAY_PER_CLASS = 2000   # memori replay per kelas -> mencegah model "lupa" kelas yang sedang tidak muncul
LOCAL_EPOCHS = 5
BATCH_SIZE = 128
LR = 0.005

extractor = FeatureExtractor()
captured_flows = []

def process_packet(packet):
    item = extractor.extract(packet)
    if item is not None:
        captured_flows.append(item)

def confusion(model, samples):
    """Evaluasi model pada sampel: kembalikan (tp, fp, tn, fn)."""
    if not samples:
        return 0, 0, 0, 0
    X = torch.tensor([s[0] for s in samples], dtype=torch.float32)
    y = torch.tensor([s[1] for s in samples], dtype=torch.float32)
    model.eval()
    with torch.no_grad():
        p = (model(X) > 0.5).float()
    tp = int(((p == 1) & (y == 1)).sum()); fp = int(((p == 1) & (y == 0)).sum())
    tn = int(((p == 0) & (y == 0)).sum()); fn = int(((p == 0) & (y == 1)).sum())
    return tp, fp, tn, fn

def reservoir_add(buffer, items, seen, cap):
    """Reservoir sampling: memori replay tetap representatif dari seluruh riwayat."""
    for it in items:
        seen += 1
        if len(buffer) < cap:
            buffer.append(it)
        else:
            j = random.randrange(seen)
            if j < cap:
                buffer[j] = it
    return seen

def main():
    global captured_flows
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', type=str, required=True)
    parser.add_argument('--ip', type=str, required=True)
    args = parser.parse_args()
    
    server_url = "http://10.0.0.254:5000"
    local_model = FirewallNN()
    optimizer = optim.Adam(local_model.parameters(), lr=LR)
    
    print(f"[{args.host}] Agen Jaringan Aktif di IP {args.ip}. Memulai Sniffing...")
    iface_name = f"{args.host}-eth0"

    replay = {0: [], 1: []}
    seen = {0: 0, 1: 0}
    
    round_idx = 1
    while True:
        print(f"\n[{args.host} - RONDE {round_idx}] Mengendus trafik via Scapy...")
        
        # store=0 agar memori RAM tidak bengkak
        sniff(iface=iface_name, prn=process_packet, filter="ip", timeout=SNIFF_TIMEOUT, store=0)

        # Abaikan trafik kontrol FL (agent <-> server 10.0.0.254) agar tidak mencemari dataset
        new_samples = [s for s in captured_flows if abs(s[0][3] - 254 / 255.0) > 1e-6 and abs(s[0][4] - 254 / 255.0) > 1e-6]
        n_raw = len(new_samples)
        if len(new_samples) > MAX_ROUND_SAMPLES:
            new_samples = random.sample(new_samples, MAX_ROUND_SAMPLES)
        n_att = sum(1 for s in new_samples if s[1][0] == 1.0)

        # ---- 1) Evaluasi PREQUENTIAL (test-then-train) ----
        # Model global ronde sebelumnya diuji pada trafik riil BARU sebelum dipakai melatih.
        tp, fp, tn, fn = confusion(local_model, new_samples)
        print(f"[{args.host}] Trafik riil: {n_raw} paket (sampel {len(new_samples)}, serangan {n_att}) | "
              f"Eval global model -> TP={tp} FP={fp} TN={tn} FN={fn}")

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
            print(f"[{args.host}] Trafik riil minim ({len(train)}). Menggunakan baseline telemetry untuk kestabilan FL...")
            train += baseline_benign(10)

        X = torch.tensor([s[0] for s in train], dtype=torch.float32)
        y = torch.tensor([s[1] for s in train], dtype=torch.float32)

        # Class weighting: kelas minoritas diberi bobot lebih besar agar model tidak menebak 1 kelas saja
        n_pos = float(y.sum()); n_neg = float(len(y) - n_pos)
        w_pos = (len(y) / (2 * n_pos)) if n_pos > 0 else 1.0
        w_neg = (len(y) / (2 * n_neg)) if n_neg > 0 else 1.0

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

        # Akurasi seimbang (balanced accuracy) -> dipakai sebagai skor kualitas agregasi di server
        ltp, lfp, ltn, lfn = confusion(local_model, train)
        tpr = ltp / (ltp + lfn) if (ltp + lfn) else None
        tnr = ltn / (ltn + lfp) if (ltn + lfp) else None
        parts = [v for v in (tpr, tnr) if v is not None]
        local_accuracy = sum(parts) / len(parts) if parts else 0.0
        print(f"[{args.host}] Akurasi Lokal (balanced): {local_accuracy:.3f} | data latih {len(train)} (serangan {int(n_pos)})")
        
        state_dict_serializable = {k: v.numpy().tolist() for k, v in local_model.state_dict().items()}
        
        payload = {
            "host_id": args.host,
            "state_dict": state_dict_serializable,
            "accuracy": float(local_accuracy),
            "sample_size": int(len(train)),
            "eval": {"tp": tp, "fp": fp, "tn": tn, "fn": fn}
        }
        
        try:
            response = requests.post(f"{server_url}/upload_weights", json=payload, timeout=30)
            if response.status_code == 200:
                time.sleep(2)
                get_resp = requests.get(f"{server_url}/get_global_model", timeout=30)
                if get_resp.status_code == 200:
                    global_data = get_resp.json()
                    global_state_dict = {k: torch.tensor(v) for k, v in global_data['state_dict'].items()}
                    local_model.load_state_dict(global_state_dict)
                    print(f"[{args.host}] Sinkronisasi Model Global Ronde {global_data['round']} Sukses.")
        except Exception as e:
            print(f"[{args.host}] Kendala API Aggregator: {e}")
            
        captured_flows.clear()
        round_idx += 1
        time.sleep(1)

if __name__ == '__main__':
    main()
