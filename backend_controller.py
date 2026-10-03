#!/usr/bin/env python3
from flask import Flask, request, jsonify
import torch
import torch.nn as nn
import numpy as np
import time
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

app = Flask(__name__)

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

global_model = FirewallNN()
received_updates = {}
round_count = 0

# Wadah perekam performa RIIL hasil pengujian Server-Side
history_metrics = {
    "accuracy": [],
    "precision": [],
    "recall": [],
    "f1_score": [],
    "fpr": [],
    "timestamp": [],  # waktu (epoch detik) selesainya tiap ronde agregasi -> untuk pemetaan fase skenario
    # Confusion matrix evaluasi federated pada TRAFIK RIIL (jumlah dari keempat agent per ronde)
    "real_tp": [], "real_fp": [], "real_tn": [], "real_fn": []
}

# =====================================================================
# SERVER-SIDE VALIDATION DATASET
# =====================================================================
# Data uji sintetis terisolasi di server (benign = label 0, serangan = label 1).
# PERBAIKAN: dibangkitkan oleh features.synth_dataset() yang memakai SKALA & SEMANTIK FITUR
# YANG SAMA dengan FeatureExtractor di agent. Sebelumnya fitur uji acak uniform dengan
# p_size=0.95 sebagai penanda serangan, padahal di agent p_size maksimal ~0.02 -> model global
# tidak pernah bisa mengenali serangan di data uji (Precision/Recall = 0).
from features import synth_dataset
test_features, test_labels = synth_dataset(n=1000, attack_ratio=0.4, seed=42)

X_test = torch.tensor(test_features)
y_test = torch.tensor(test_labels)
# =====================================================================

@app.route('/upload_weights', methods=['POST'])
def upload_weights():
    global received_updates, round_count
    
    data = request.json
    host_id = data['host_id']
    state_dict_json = data['state_dict']
    accuracy = data['accuracy']
    sample_size = data['sample_size']
    
    # Rekonstruksi bobot enkripsi JSON menjadi PyTorch Tensor
    state_dict = {k: torch.tensor(v) for k, v in state_dict_json.items()}
    
    received_updates[host_id] = {
        'state_dict': state_dict,
        'accuracy': accuracy,
        'sample_size': sample_size,
        'eval': data.get('eval', {"tp": 0, "fp": 0, "tn": 0, "fn": 0})
    }
    
    ev = received_updates[host_id]['eval']
    print(f"[ROUND {round_count}] Menerima update dari {host_id} (Akurasi Lokal: {accuracy:.3f}, "
          f"Eval riil TP={ev['tp']} FP={ev['fp']} TN={ev['tn']} FN={ev['fn']})")
    
    # Agregasi dieksekusi jika ketiga host (h1, h2, h3) telah menyetor model lokal
    # Harus diubah ke 4 karena topologi menggunakan h1, h2, h3, dan h4
    if len(received_updates) == 4:
        aggregate_models()
        round_count += 1
        received_updates.clear()
        
    return jsonify({"status": "success", "message": "Weights received"})

def aggregate_models():
    global global_model, received_updates, history_metrics
    print(f"--- Memulai Quality-Weighted Aggregation Ronde {round_count} ---")
    
    # Skor kualitas = balanced accuracy lokal x jumlah sampel
    scores = {h: node['accuracy'] * node['sample_size'] for h, node in received_updates.items()}
    total_quality_score = sum(scores.values())
    if total_quality_score <= 0:
        # PERBAIKAN: sebelumnya ronde dilewati diam-diam. Fallback ke FedAvg berbasis jumlah sampel.
        print("-> Skor kualitas total 0, fallback ke FedAvg (bobot jumlah sampel).")
        scores = {h: float(node['sample_size']) for h, node in received_updates.items()}
        total_quality_score = sum(scores.values()) or 1.0
        
    global_state = global_model.state_dict()
    new_global_state = {key: torch.zeros_like(val, dtype=torch.float32) for key, val in global_state.items()}
    
    # Formula Pembobotan Kualitas (Quality-Weighted Federated Aggregation)
    for key in new_global_state.keys():
        for host_id, node in received_updates.items():
            quality_factor = scores[host_id] / total_quality_score
            new_global_state[key] += node['state_dict'][key].float() * quality_factor
            
    global_model.load_state_dict(new_global_state)
    print("-> Agregasi Model Global Sukses. Menjalankan Server-Side Evaluation...")
    
    # =====================================================================
# EVALUASI MANDIRI OLEH SERVER MENGGUNAKAN CONFUSION MATRIX RIIL
# =====================================================================
    global_model.eval()
    with torch.no_grad():
        outputs = global_model(X_test)
        y_pred = (outputs > 0.5).float().numpy()
        y_true = y_test.numpy()
        
    # Hitung metrik standar klasifikasi AI secara objektif
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    
    # Menghitung False Positive Rate (FPR) asli dari matriks konfusi
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = fp / (tn + fp) if (tn + fp) > 0 else 0.0
    
    # Simpan hasil kalkulasi murni ke dalam riwayat metrik
    history_metrics["accuracy"].append(acc)
    history_metrics["precision"].append(prec)
    history_metrics["recall"].append(rec)
    history_metrics["f1_score"].append(f1)
    history_metrics["fpr"].append(fpr)
    history_metrics["timestamp"].append(time.time())
    for k in ("tp", "fp", "tn", "fn"):
        history_metrics[f"real_{k}"].append(sum(int(n['eval'].get(k, 0)) for n in received_updates.values()))
    
    print(f"[SERVER EVAL ROUND {round_count}] Hasil Riil -> Acc: {acc:.4f}, Prec: {prec:.4f}, Rec: {rec:.4f}, FPR: {fpr:.4f}")

@app.route('/get_global_model', methods=['GET'])
def get_global_model():
    state_dict_serializable = {k: v.numpy().tolist() for k, v in global_model.state_dict().items()}
    return jsonify({"state_dict": state_dict_serializable, "round": round_count})

@app.route('/get_history', methods=['GET'])
def get_history():
    # Riwayat metrik per ronde (beserta timestamp) untuk analisis per fase skenario
    return jsonify({k: [float(x) for x in v] for k, v in history_metrics.items()})

@app.route('/reset', methods=['POST'])
def reset_state():
    # Dipanggil di awal tiap eksperimen agar hasil run sebelumnya tidak ikut terhitung
    global global_model, round_count
    global_model = FirewallNN()
    round_count = 0
    received_updates.clear()
    for v in history_metrics.values():
        v.clear()
    print("[RESET] State server dikosongkan untuk eksperimen baru.")
    return jsonify({"status": "reset"})

@app.route('/get_evaluation_metrics', methods=['GET'])
def get_evaluation_metrics():
    # Menjamin otomasi eksperimen mendapatkan nilai rata-rata kalkulasi riil
    if history_metrics["accuracy"]:
        return jsonify({
            "accuracy": float(np.mean(history_metrics["accuracy"])),
            "precision": float(np.mean(history_metrics["precision"])),
            "recall": float(np.mean(history_metrics["recall"])),
            "f1_score": float(np.mean(history_metrics["f1_score"])),
            "fpr": float(np.mean(history_metrics["fpr"])),
            "rounds": len(history_metrics["accuracy"])
        })
    else:
        # Jika otomatisasi meminta metrik terlalu dini sebelum agregasi pertama selesai
        return jsonify({
            "accuracy": 0.0, "precision": 0.0, "recall": 0.0, "f1_score": 0.0, "fpr": 0.0,
            "rounds": 0
        })

if __name__ == '__main__':
    print("Membuka Server Agregator FL Valid Terverifikasi pada port 5000...")
   
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)

