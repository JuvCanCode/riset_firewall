#!/usr/bin/env python3
"""
Definisi fitur bersama untuk Local Agent dan Server.

Agent dan server WAJIB memakai skala fitur yang sama; jika tidak, model global
yang dilatih di agent tidak akan pernah cocok dengan data uji di server
(penyebab Precision/Recall = 0 sebelumnya).

10 Fitur (semua ternormalisasi 0..1):
  0 p_size        : panjang paket / 1500 (MTU Ethernet), dipotong di 1.0
  1 time_sin      : posisi waktu dalam sehari (sinus)
  2 seq_num       : TCP sequence number / 2^32 (0 jika bukan TCP)
  3 src_ip        : oktet terakhir IP sumber / 255
  4 dst_ip        : oktet terakhir IP tujuan / 255
  5 proto         : 0.1 TCP, 0.2 UDP, 0.3 ICMP, 0.4 lainnya
  6 ttl           : TTL / 255
  7 pkt_rate      : laju paket dari IP sumber yang sama dalam jendela 1 detik / 1000
  8 suspicious    : 1.0 jika TCP ke port terlarang (security_policy.blocked_ports)
  9 entropy       : Shannon entropy payload (bit per byte) / 8
"""
import json
import math
import os
import time
from collections import Counter, defaultdict, deque

import numpy as np

NUM_FEATURES = 10
MTU = 1500.0
RATE_CAP = 1000.0
ICMP_FLOOD_MIN_LEN = 1000  # paket ICMP > 1000 byte dianggap bagian dari ICMP flood

PROTO_TCP, PROTO_UDP, PROTO_ICMP, PROTO_OTHER = 0.1, 0.2, 0.3, 0.4

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def load_blocked_ports():
    try:
        with open(os.path.join(_BASE_DIR, 'config.json')) as f:
            return set(json.load(f)['security_policy']['blocked_ports'])
    except Exception:
        return {21, 22, 23, 3389}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


class FeatureExtractor:
    """Mengubah paket Scapy menjadi (feature_vector, label). Menyimpan state laju per IP sumber."""

    def __init__(self, blocked_ports=None):
        self.blocked_ports = blocked_ports if blocked_ports is not None else load_blocked_ports()
        self._windows = defaultdict(deque)

    def _rate(self, src, ts):
        w = self._windows[src]
        w.append(ts)
        while w and ts - w[0] > 1.0:
            w.popleft()
        return len(w)

    def extract(self, packet):
        from scapy.all import IP, TCP, UDP, ICMP
        if IP not in packet:
            return None
        ip = packet[IP]
        ts = float(getattr(packet, 'time', time.time()))
        length = len(packet)

        is_tcp, is_udp, is_icmp = TCP in packet, UDP in packet, ICMP in packet
        proto = PROTO_TCP if is_tcp else (PROTO_UDP if is_udp else (PROTO_ICMP if is_icmp else PROTO_OTHER))
        suspicious = 1.0 if (is_tcp and packet[TCP].dport in self.blocked_ports) else 0.0

        payload = bytes(ip.payload.payload) if ip.payload is not None else b''

        features = [
            min(length / MTU, 1.0),
            float(np.sin(2 * np.pi * (ts % 86400) / 86400.0)),
            packet[TCP].seq / 4294967295.0 if is_tcp else 0.0,
            float(ip.src.split('.')[-1]) / 255.0,
            float(ip.dst.split('.')[-1]) / 255.0,
            proto,
            ip.ttl / 255.0,
            min(self._rate(ip.src, ts), RATE_CAP) / RATE_CAP,
            suspicious,
            _entropy(payload[:512]) / 8.0,
        ]
        return features, [label_packet(is_icmp, length, suspicious)]


def label_packet(is_icmp, length, suspicious):
    """Ground truth: ICMP flood (paket ICMP besar) ATAU akses TCP ke port terlarang."""
    return 1.0 if (suspicious == 1.0 or (is_icmp and length > ICMP_FLOOD_MIN_LEN)) else 0.0


def synth_dataset(n=1000, attack_ratio=0.4, seed=42):
    """
    Data uji sisi server yang disintesis dengan SEMANTIK FITUR YANG SAMA dengan FeatureExtractor.
    Berisi kasus sulit: benign dengan paket TCP besar (bulk transfer) dan benign dengan laju tinggi
    (mis. korban yang sedang membalas flood), sehingga model tidak bisa lulus hanya dari 1 fitur.
    """
    rng = np.random.default_rng(seed)
    n_att = int(n * attack_ratio)
    X = np.zeros((n, NUM_FEATURES), dtype=np.float32)
    y = np.zeros((n, 1), dtype=np.float32)

    def ip():
        return rng.integers(1, 255) / 255.0

    for i in range(n):
        attack = i < n_att
        t_sin = rng.uniform(-1, 1)
        ttl = rng.choice([64, 63, 128]) / 255.0
        if attack:
            if rng.random() < 0.85:  # ICMP flood
                length = rng.integers(ICMP_FLOOD_MIN_LEN + 1, 1515)
                rate = rng.uniform(150, 1000) if rng.random() < 0.9 else rng.uniform(20, 150)
                X[i] = [min(length / MTU, 1), t_sin, 0, ip(), ip(), PROTO_ICMP, ttl,
                        min(rate, RATE_CAP) / RATE_CAP, 0.0, rng.uniform(0.0, 0.6)]
            else:  # akses / scanning ke port terlarang
                length = rng.integers(54, 80)
                rate = rng.uniform(1, 300)
                X[i] = [length / MTU, t_sin, rng.random(), ip(), ip(), PROTO_TCP, ttl,
                        rate / RATE_CAP, 1.0, rng.uniform(0.0, 0.2)]
            y[i] = 1.0
        else:
            kind = rng.random()
            rate = rng.uniform(1, 40) if rng.random() < 0.85 else rng.uniform(150, 1000)
            if kind < 0.35:  # ping normal
                length = rng.integers(60, 200)
                X[i] = [length / MTU, t_sin, 0, ip(), ip(), PROTO_ICMP, ttl,
                        rate / RATE_CAP, 0.0, rng.uniform(0.0, 0.6)]
            elif kind < 0.85:  # TCP biasa (kecil s.d. bulk)
                length = rng.integers(54, 200) if rng.random() < 0.7 else rng.integers(800, 1515)
                X[i] = [min(length / MTU, 1), t_sin, rng.random(), ip(), ip(), PROTO_TCP, ttl,
                        rate / RATE_CAP, 0.0, rng.uniform(0.3, 1.0)]
            else:  # UDP (DNS, dsb.)
                length = rng.integers(60, 600)
                X[i] = [length / MTU, t_sin, 0, ip(), ip(), PROTO_UDP, ttl,
                        rate / RATE_CAP, 0.0, rng.uniform(0.3, 0.9)]
    perm = rng.permutation(n)
    return X[perm], y[perm]


def baseline_benign(n=10, seed=None):
    """Data cadangan saat tidak ada trafik sama sekali (diambil dari distribusi benign sintetis)."""
    X, y = synth_dataset(n * 3, attack_ratio=0.0, seed=seed)
    return [(list(map(float, X[i])), [0.0]) for i in range(n)]
