"""
Sentinels — Local Model Retrainer
==================================
Trains a new RandomForest using SYNTHETIC flows whose features match
the exact output of FlowTracker.extract_features().

Why: the CICIDS-2017 pkl was trained by CICFlowMeter which computes
features slightly differently, so the model always predicts Normal.
This script builds a model calibrated to OUR feature extraction.

Run:
    venv/bin/python retrain_local.py
Output:
    app/ml/sentinels_rf_model.pkl  (overwrites the old one)
"""

import os
import random
import numpy as np
import warnings
warnings.filterwarnings('ignore')

FEATURES = [
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Total Length of Fwd Packets',
    'Total Length of Bwd Packets',
    'Fwd Packet Length Mean',
    'Fwd Packet Length Std',
    'Bwd Packet Length Mean',
    'Bwd Packet Length Std',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Flow IAT Mean',
    'Flow IAT Std',
    'SYN Flag Count',
    'FIN Flag Count',
    'RST Flag Count',
    'PSH Flag Count',
    'ACK Flag Count',
    'Average Packet Size',
    'Down/Up Ratio',
]

rng = random.Random(42)


def jitter(val, pct=0.25):
    """Add ±pct random noise."""
    lo = val * (1 - pct)
    hi = val * (1 + pct)
    return max(0.0, rng.uniform(lo, hi))


def make_flow(**kw):
    """Build a feature vector dict from keyword overrides."""
    base = {f: 0.0 for f in FEATURES}
    base.update(kw)
    # Derived fields
    total_pkts  = base['Total Fwd Packets'] + base['Total Backward Packets']
    total_bytes = base['Total Length of Fwd Packets'] + base['Total Length of Bwd Packets']
    dur_s       = max(base['Flow Duration'] / 1e6, 1e-9)
    base['Flow Bytes/s']       = total_bytes / dur_s
    base['Flow Packets/s']     = total_pkts  / dur_s
    base['Average Packet Size']= total_bytes / max(total_pkts, 1)
    base['Down/Up Ratio']      = base['Total Backward Packets'] / max(base['Total Fwd Packets'], 1)
    return base


# ── Synthetic flow generators ──────────────────────────────────────────────────

def gen_normal(n=1200):
    """
    Normal traffic — covers every real flow type seen on a live LAN:
      - UDP flows: DNS queries, mDNS, SSDP, broadcast (no TCP flags)
      - ICMPv6 neighbor discovery / router advertisement (no TCP flags)
      - Short TCP: quick SYN+FIN handshake or SYN+RST without data
      - Medium TCP: standard HTTP/HTTPS with data exchange
      - Long TCP: large file transfers
    The wide variety prevents the model from mis-classifying any short
    flow as an attack class.
    """
    samples = []

    # ── UDP / ICMP / non-TCP flows (40 % of Normal) ───────────────────────────
    for _ in range(n * 40 // 100):
        fwd = rng.randint(1, 3)
        bwd = rng.randint(0, 2)
        dur = rng.uniform(500, 50_000)              # 0.5ms – 50ms
        pkt_size = rng.uniform(40, 200)
        samples.append(make_flow(**{
            'Flow Duration':               dur,
            'Total Fwd Packets':           float(fwd),
            'Total Backward Packets':      float(bwd),
            'Total Length of Fwd Packets': fwd * pkt_size,
            'Total Length of Bwd Packets': bwd * pkt_size * rng.uniform(0.8, 1.5),
            'Fwd Packet Length Mean':      pkt_size,
            'Fwd Packet Length Std':       jitter(pkt_size * 0.1, 0.3),
            'Bwd Packet Length Mean':      pkt_size * rng.uniform(0.8, 1.5) if bwd else 0.0,
            'Bwd Packet Length Std':       0.0,
            'Flow IAT Mean':               dur / max(fwd + bwd - 1, 1),
            'Flow IAT Std':                0.0,
            # All TCP flag counts are 0 (UDP / ICMP)
            'SYN Flag Count':              0.0,
            'FIN Flag Count':              0.0,
            'RST Flag Count':              0.0,
            'PSH Flag Count':              0.0,
            'ACK Flag Count':              0.0,
        }))

    # ── Short TCP: SYN + FIN teardown, no data (10 %) ─────────────────────────
    for _ in range(n * 10 // 100):
        dur = rng.uniform(2_000, 30_000)            # 2ms – 30ms
        samples.append(make_flow(**{
            'Flow Duration':               dur,
            'Total Fwd Packets':           2.0,
            'Total Backward Packets':      2.0,
            'Total Length of Fwd Packets': jitter(80, 0.3),
            'Total Length of Bwd Packets': jitter(80, 0.3),
            'Fwd Packet Length Mean':      jitter(40, 0.3),
            'Fwd Packet Length Std':       0.0,
            'Bwd Packet Length Mean':      jitter(40, 0.3),
            'Bwd Packet Length Std':       0.0,
            'Flow IAT Mean':               dur / 3,
            'Flow IAT Std':                jitter(dur / 6, 0.4),
            'SYN Flag Count':              1.0,
            'FIN Flag Count':              2.0,   # FIN both sides
            'RST Flag Count':              0.0,   # ← key: no RST
            'PSH Flag Count':              0.0,
            'ACK Flag Count':              3.0,
        }))

    # ── Medium TCP: HTTP / HTTPS with data (30 %) ─────────────────────────────
    for _ in range(n * 30 // 100):
        fwd = rng.randint(3, 15)
        bwd = rng.randint(2, 12)
        dur = rng.uniform(50_000, 2_000_000)
        fwd_mean = rng.uniform(100, 800)
        bwd_mean = rng.uniform(200, 2000)
        ack = fwd + bwd - 1
        samples.append(make_flow(**{
            'Flow Duration':               dur,
            'Total Fwd Packets':           float(fwd),
            'Total Backward Packets':      float(bwd),
            'Total Length of Fwd Packets': fwd * fwd_mean,
            'Total Length of Bwd Packets': bwd * bwd_mean,
            'Fwd Packet Length Mean':      fwd_mean,
            'Fwd Packet Length Std':       jitter(fwd_mean * 0.25, 0.4),
            'Bwd Packet Length Mean':      bwd_mean,
            'Bwd Packet Length Std':       jitter(bwd_mean * 0.25, 0.4),
            'Flow IAT Mean':               dur / max(fwd + bwd - 1, 1),
            'Flow IAT Std':                jitter(dur / max(fwd + bwd - 1, 1) * 0.35),
            'SYN Flag Count':              1.0,
            'FIN Flag Count':              float(rng.randint(1, 2)),
            'RST Flag Count':              0.0,
            'PSH Flag Count':              float(rng.randint(1, max(fwd // 2, 2))),
            'ACK Flag Count':              float(max(ack, 1)),
        }))

    # ── Long TCP: file transfers / streaming (20 %) ───────────────────────────
    for _ in range(n * 20 // 100):
        fwd = rng.randint(15, 80)
        bwd = rng.randint(10, 60)
        dur = rng.uniform(1_000_000, 10_000_000)
        fwd_mean = rng.uniform(800, 1400)
        bwd_mean = rng.uniform(800, 1400)
        ack = fwd + bwd - 1
        samples.append(make_flow(**{
            'Flow Duration':               dur,
            'Total Fwd Packets':           float(fwd),
            'Total Backward Packets':      float(bwd),
            'Total Length of Fwd Packets': fwd * fwd_mean,
            'Total Length of Bwd Packets': bwd * bwd_mean,
            'Fwd Packet Length Mean':      fwd_mean,
            'Fwd Packet Length Std':       jitter(fwd_mean * 0.15, 0.3),
            'Bwd Packet Length Mean':      bwd_mean,
            'Bwd Packet Length Std':       jitter(bwd_mean * 0.15, 0.3),
            'Flow IAT Mean':               dur / max(fwd + bwd - 1, 1),
            'Flow IAT Std':                jitter(dur / max(fwd + bwd - 1, 1) * 0.2),
            'SYN Flag Count':              1.0,
            'FIN Flag Count':              2.0,
            'RST Flag Count':              0.0,
            'PSH Flag Count':              float(rng.randint(fwd // 3, fwd)),
            'ACK Flag Count':              float(max(ack, 1)),
        }))

    return samples


def gen_dos(n=600):
    """
    DoS Hulk / GoldenEye: many very short HTTP flows, high packet rate,
    SYN+RST, minimal response, bidirectional.
    """
    samples = []
    for _ in range(n):
        dur = jitter(8_000, 0.5)        # ~8ms
        samples.append(make_flow(**{
            'Flow Duration':               dur,
            'Total Fwd Packets':           3.0,
            'Total Backward Packets':      2.0,
            'Total Length of Fwd Packets': jitter(90, 0.3),
            'Total Length of Bwd Packets': jitter(55, 0.3),
            'Fwd Packet Length Mean':      jitter(30, 0.3),
            'Fwd Packet Length Std':       jitter(12, 0.5),
            'Bwd Packet Length Mean':      jitter(27, 0.3),
            'Bwd Packet Length Std':       jitter(5, 0.5),
            'Flow IAT Mean':               dur / 4,
            'Flow IAT Std':                jitter(dur / 8, 0.5),
            'SYN Flag Count':              1.0,
            'FIN Flag Count':              0.0,
            'RST Flag Count':              1.0,
            'PSH Flag Count':              2.0,
            'ACK Flag Count':              3.0,
        }))
    return samples


def gen_portscan(n=600):
    """
    Nmap SYN scan: 1 fwd (SYN) + 1 bwd (RST-ACK) per port.
    Key discriminators vs Normal:
      - SYN=1 AND RST=1 (RST-ACK response from closed port)
      - FIN=0, PSH=0  (no graceful teardown, no data at all)
      - Only 2 packets total, sub-2ms duration
    These flag combos don't appear in Normal or any other attack class.
    """
    samples = []
    for _ in range(n):
        dur = jitter(1_500, 0.4)        # ~1.5ms — faster than any normal TCP
        pkt = jitter(40, 0.15)
        samples.append(make_flow(**{
            'Flow Duration':               dur,
            'Total Fwd Packets':           1.0,
            'Total Backward Packets':      1.0,
            'Total Length of Fwd Packets': pkt,
            'Total Length of Bwd Packets': pkt,
            'Fwd Packet Length Mean':      pkt,
            'Fwd Packet Length Std':       0.0,
            'Bwd Packet Length Mean':      pkt,
            'Bwd Packet Length Std':       0.0,
            'Flow IAT Mean':               dur,
            'Flow IAT Std':                0.0,
            'SYN Flag Count':              1.0,   # SYN probe
            'FIN Flag Count':              0.0,   # ← no FIN
            'RST Flag Count':              1.0,   # ← RST-ACK from target
            'PSH Flag Count':              0.0,   # ← no data
            'ACK Flag Count':              1.0,   # ← ACK in RST-ACK
        }))
    return samples


def gen_bruteforce(n=600):
    """
    SSH-Patator: per-attempt flow, 7 fwd + 4 bwd,
    ~0.5s duration, SYN:1 + RST:1, high PSH+ACK, moderate bytes.
    """
    samples = []
    for _ in range(n):
        fwd = rng.randint(6, 9)
        bwd = rng.randint(3, 5)
        dur = jitter(500_000, 0.3)
        fwd_mean = jitter(57, 0.3)
        bwd_mean = jitter(70, 0.3)
        samples.append(make_flow(**{
            'Flow Duration':               dur,
            'Total Fwd Packets':           float(fwd),
            'Total Backward Packets':      float(bwd),
            'Total Length of Fwd Packets': fwd * fwd_mean,
            'Total Length of Bwd Packets': bwd * bwd_mean,
            'Fwd Packet Length Mean':      fwd_mean,
            'Fwd Packet Length Std':       jitter(fwd_mean * 0.35, 0.4),
            'Bwd Packet Length Mean':      bwd_mean,
            'Bwd Packet Length Std':       jitter(bwd_mean * 0.25, 0.4),
            'Flow IAT Mean':               dur / (fwd + bwd),
            'Flow IAT Std':                jitter(15_000, 0.5),
            'SYN Flag Count':              1.0,
            'FIN Flag Count':              0.0,
            'RST Flag Count':              1.0,
            'PSH Flag Count':              float(rng.randint(3, 6)),
            'ACK Flag Count':              float(fwd + bwd - 2),
        }))
    return samples


def gen_botnet(n=600):
    """
    Botnet C2 beacon: small periodic bidirectional flow.
    Regular IAT, small payload, SYN+FIN×2, PSH+ACK pattern.
    """
    samples = []
    for _ in range(n):
        dur = jitter(260_000, 0.3)
        samples.append(make_flow(**{
            'Flow Duration':               dur,
            'Total Fwd Packets':           4.0,
            'Total Backward Packets':      3.0,
            'Total Length of Fwd Packets': jitter(100, 0.3),
            'Total Length of Bwd Packets': jitter(80, 0.3),
            'Fwd Packet Length Mean':      jitter(25, 0.3),
            'Fwd Packet Length Std':       jitter(8, 0.5),
            'Bwd Packet Length Mean':      jitter(26, 0.3),
            'Bwd Packet Length Std':       jitter(5, 0.5),
            'Flow IAT Mean':               jitter(37_000, 0.3),
            'Flow IAT Std':                jitter(8_000, 0.5),
            'SYN Flag Count':              1.0,
            'FIN Flag Count':              2.0,
            'RST Flag Count':              0.0,
            'PSH Flag Count':              2.0,
            'ACK Flag Count':              5.0,
        }))
    return samples


def gen_webattack(n=600):
    """
    XSS / SQLi / path traversal: attack HTTP probes are characterised by
    short but data-dense flows where the server responds with an error
    (small bwd_bytes) and RST closes the connection (not FIN).
    Key discriminators vs Normal HTTP:
      - RST=1, FIN=0 (server closes connection immediately on error)
      - High PSH ratio relative to total packets
      - Asymmetric fwd>>bwd byte sizes (large request, small error reply)
    """
    samples = []
    for _ in range(n):
        dur = jitter(50_000, 0.3)           # shorter than normal HTTP
        fwd_bytes = jitter(350, 0.3)        # large attack payload
        bwd_bytes = jitter(60, 0.3)         # tiny error response
        samples.append(make_flow(**{
            'Flow Duration':               dur,
            'Total Fwd Packets':           3.0,
            'Total Backward Packets':      2.0,
            'Total Length of Fwd Packets': fwd_bytes,
            'Total Length of Bwd Packets': bwd_bytes,
            'Fwd Packet Length Mean':      fwd_bytes / 3,
            'Fwd Packet Length Std':       jitter(40, 0.4),
            'Bwd Packet Length Mean':      bwd_bytes / 2,
            'Bwd Packet Length Std':       jitter(10, 0.5),
            'Flow IAT Mean':               jitter(12_000, 0.3),
            'Flow IAT Std':                jitter(3_000, 0.5),
            'SYN Flag Count':              1.0,
            'FIN Flag Count':              0.0,   # ← no graceful close
            'RST Flag Count':              1.0,   # ← RST on error
            'PSH Flag Count':              3.0,   # ← high PSH
            'ACK Flag Count':              3.0,
        }))
    return samples


# ── Build dataset ──────────────────────────────────────────────────────────────

print('[Retrain] Generating synthetic flow dataset...')

CLASS_GEN = [
    ('Normal',     lambda: gen_normal(1200)),
    ('DoS',        lambda: gen_dos(600)),
    ('PortScan',   lambda: gen_portscan(600)),
    ('BruteForce', lambda: gen_bruteforce(600)),
    ('Botnet',     lambda: gen_botnet(600)),
    ('WebAttack',  lambda: gen_webattack(600)),
]

X_rows, y_rows = [], []
for label, generator in CLASS_GEN:
    flows = generator()
    for flow in flows:
        X_rows.append([flow[f] for f in FEATURES])
        y_rows.append(label)
    print(f'  {label:12s}: {len(flows)} samples')

X = np.array(X_rows, dtype=float)
y = np.array(y_rows)

# Sanitise
X = np.nan_to_num(X, nan=0.0, posinf=1e9, neginf=0.0)

print(f'\n[Retrain] Total samples: {len(X)}')
print(f'[Retrain] Feature count: {X.shape[1]}')

# ── Train ──────────────────────────────────────────────────────────────────────

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

le = LabelEncoder()
y_enc = le.fit_transform(y)

X_train, X_test, y_train, y_test = train_test_split(
    X, y_enc, test_size=0.2, random_state=42, stratify=y_enc
)

print('\n[Retrain] Training RandomForest...')
rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    min_samples_leaf=2,
    class_weight='balanced',
    n_jobs=-1,
    random_state=42,
)
rf.fit(X_train, y_train)

y_pred = rf.predict(X_test)
print('\n[Retrain] Classification report:')
print(classification_report(y_test, y_pred, target_names=le.classes_))

# ── Save ───────────────────────────────────────────────────────────────────────

import joblib

bundle = {
    'model':         rf,
    'label_encoder': le,
    'features':      FEATURES,
    'version':       '2.0-local',
    'trained_on':    'synthetic-flows-matched-to-FlowTracker',
}

out_path = os.path.join(os.path.dirname(__file__), 'app', 'ml', 'sentinels_rf_model.pkl')
joblib.dump(bundle, out_path)
print(f'\n[Retrain] Model saved to {out_path}')
print('[Retrain] Reload it in Settings → ML Threat Classifier → Reload Model')
