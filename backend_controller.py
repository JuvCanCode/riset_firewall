#!/usr/bin/env python3
from flask import Flask, request, jsonify
import threading
import torch
import torch.nn as nn
import numpy as np
import time
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

from features import synth_dataset

app = Flask(__name__)

NUM_CLIENTS = 4  # h1, h2, h3, h4

# Arsitektur model wajib sama persis dengan Local Agent
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

state_lock = threading.Lock()   # server threaded=True: lindungi received_updates / model / round
global_model = FirewallNN()
received_updates = {}
round_count = 0
mode = "train"                  # "train" = fase learning, "test" = model dibekukan (agent tidak training)

history_metrics = {
    "accuracy": [], "precision": [], "recall": [], "f1_score": [], "fpr": [],
    "timestamp": [],   # titik tengah jendela sniff (rata-rata keempat agent) -> pemetaan fase skenario
    "is_test": [],     # 1.0 jika ronde dijalankan pada mode test
    "real_tp": [], "real_fp": [], "real_tn": [], "real_fn": []
}

# =====================================================================
# SERVER-SIDE VALIDATION DATASET (dibangkitkan ulang di /reset)
# =====================================================================
def make_test_set():
    f, l = synth_dataset(n=1000, attack_ratio=0.4, seed=42)
    return torch.tensor(f), torch.tensor(l)

X_test, y_test = make_test_set()


@app.route('/upload_weights', methods=['POST'])
def upload_weights():
    global round_count

    data = request.json
    host_id = data['host_id']
    state_dict = {k: torch.tensor(v) for k, v in data['state_dict'].items()}
    accuracy = data['accuracy']
    sample_size = data['sample_size']
    t_mid = float(data.get('t_mid', time.time()))
    ev_in = data.get('eval', {"tp": 0, "fp": 0, "tn": 0, "fn": 0})

    with state_lock:
        received_updates[host_id] = {
            'state_dict': state_dict,
            'accuracy': accuracy,
            'sample_size': sample_size,
            't_mid': t_mid,
            'eval': ev_in
        }
        ev = ev_in
        print(f"[ROUND {round_count}|{mode}] Update dari {host_id} (Akurasi Lokal: {accuracy:.3f}, "
              f"Eval riil TP={ev['tp']} FP={ev['fp']} TN={ev['tn']} FN={ev['fn']}) "
              f"[{len(received_updates)}/{NUM_CLIENTS}]")

        if len(received_updates) == NUM_CLIENTS:
            aggregate_models()
            round_count += 1
            received_updates.clear()

    return jsonify({"status": "success", "message": "Weights received"})


def aggregate_models():
    """Dipanggil dengan state_lock sudah dipegang."""
    global global_model, history_metrics
    print(f"--- Quality-Weighted Aggregation Ronde {round_count} ---")

    # Skor kualitas = balanced accuracy lokal x jumlah sampel
    scores = {h: node['accuracy'] * node['sample_size'] for h, node in received_updates.items()}
    total_quality_score = sum(scores.values())
    if total_quality_score <= 0:
        print("-> Skor kualitas total 0, fallback ke FedAvg (bobot jumlah sampel).")
        scores = {h: float(node['sample_size']) for h, node in received_updates.items()}
        total_quality_score = sum(scores.values()) or 1.0

    global_state = global_model.state_dict()
    new_global_state = {key: torch.zeros_like(val, dtype=torch.float32) for key, val in global_state.items()}

    for key in new_global_state.keys():
        for host_id, node in received_updates.items():
            quality_factor = scores[host_id] / total_quality_score
            new_global_state[key] += node['state_dict'][key].float() * quality_factor

    global_model.load_state_dict(new_global_state)

    # ---------------- Evaluasi server pada data uji sintetis ----------------
    global_model.eval()
    with torch.no_grad():
        outputs = global_model(X_test)
        suspicious = X_test[:, 8:9]
        confidence = torch.abs(outputs - 0.5) * 2.0
        threat_score = 0.6 * outputs + 0.3 * suspicious + 0.1 * confidence

        y_pred = (threat_score > 0.6).float().numpy()   # threshold deteksi 0.6 dari paper
        y_raw = (outputs > 0.5).float().numpy()          # diagnostik: keputusan murni dari output model
        y_true = y_test.numpy()

    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = fp / (tn + fp) if (tn + fp) > 0 else 0.0

    history_metrics["accuracy"].append(acc)
    history_metrics["precision"].append(prec)
    history_metrics["recall"].append(rec)
    history_metrics["f1_score"].append(f1)
    history_metrics["fpr"].append(fpr)
    history_metrics["timestamp"].append(float(np.mean([n['t_mid'] for n in received_updates.values()])))
    history_metrics["is_test"].append(1.0 if mode == "test" else 0.0)
    for k in ("tp", "fp", "tn", "fn"):
        history_metrics[f"real_{k}"].append(sum(int(n['eval'].get(k, 0)) for n in received_updates.values()))

    print(f"[SERVER EVAL ROUND {round_count}] Threat-score -> Acc: {acc:.4f}, Prec: {prec:.4f}, "
          f"Rec: {rec:.4f}, FPR: {fpr:.4f}")
    print(f"  [diag] p>0.5 saja -> Prec {precision_score(y_true, y_raw, zero_division=0):.3f} "
          f"Rec {recall_score(y_true, y_raw, zero_division=0):.3f}")


@app.route('/get_global_model', methods=['GET'])
def get_global_model():
    with state_lock:
        state_dict_serializable = {k: v.numpy().tolist() for k, v in global_model.state_dict().items()}
        return jsonify({"state_dict": state_dict_serializable, "round": round_count, "mode": mode})


@app.route('/get_mode', methods=['GET'])
def get_mode():
    return jsonify({"mode": mode})


@app.route('/set_mode', methods=['POST'])
def set_mode():
    global mode
    new_mode = request.json.get('mode', 'train')
    if new_mode not in ('train', 'test'):
        return jsonify({"error": "mode harus 'train' atau 'test'"}), 400
    with state_lock:
        mode = new_mode
    print(f"[MODE] Server berpindah ke mode '{mode}'.")
    return jsonify({"mode": mode})


@app.route('/get_history', methods=['GET'])
def get_history():
    with state_lock:
        return jsonify({k: [float(x) for x in v] for k, v in history_metrics.items()})


@app.route('/reset', methods=['POST'])
def reset_state():
    global global_model, round_count, mode, X_test, y_test
    with state_lock:
        global_model = FirewallNN()
        round_count = 0
        mode = "train"
        received_updates.clear()
        for v in history_metrics.values():
            v.clear()
        X_test, y_test = make_test_set()
    print("[RESET] State server dikosongkan untuk eksperimen baru.")
    return jsonify({"status": "reset"})


@app.route('/get_evaluation_metrics', methods=['GET'])
def get_evaluation_metrics():
    with state_lock:
        if history_metrics["accuracy"]:
            return jsonify({
                "accuracy": float(np.mean(history_metrics["accuracy"])),
                "precision": float(np.mean(history_metrics["precision"])),
                "recall": float(np.mean(history_metrics["recall"])),
                "f1_score": float(np.mean(history_metrics["f1_score"])),
                "fpr": float(np.mean(history_metrics["fpr"])),
                "rounds": len(history_metrics["accuracy"])
            })
        return jsonify({
            "accuracy": 0.0, "precision": 0.0, "recall": 0.0, "f1_score": 0.0, "fpr": 0.0,
            "rounds": 0
        })


if __name__ == '__main__':
    print("Membuka Server Agregator FL pada port 5000...")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)