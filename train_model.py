"""
Sentinels - Random Forest Classifier Training Script
=====================================================
Run this in a Kaggle notebook with the CICIDS-2017 dataset.

Dataset: https://www.kaggle.com/datasets/cicdataset/cicids2017
(Or any mirror — search "CICIDS2017" on Kaggle)

Instructions:
  1. Create a new Kaggle notebook
  2. Add the CICIDS-2017 dataset as input
  3. Paste this entire script and run all cells
  4. Download the output file: sentinels_rf_model.pkl
  5. In Sentinels Settings page, upload that pkl file

Output: sentinels_rf_model.pkl (~50-200 MB depending on n_estimators)
"""

import os
import glob
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# ── 1. CONFIG ─────────────────────────────────────────────────────────────────

# Kaggle input path — adjust if your dataset folder name differs
DATA_PATH = '/kaggle/input/datasets/kk0105/cicids2017/MachineLearningCSV/MachineLearningCSV/MachineLearningCVE/'

OUTPUT_PATH = 'sentinels_rf_model.pkl'

# These are the EXACT 20 features our FlowTracker computes from Scapy.
# They must match what flow_tracker.py produces.
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

# Map raw CICIDS-2017 labels → Sentinels threat categories
LABEL_MAP = {
    'BENIGN':                          'Normal',
    'DoS Hulk':                        'DoS',
    'DDoS':                            'DoS',
    'DoS GoldenEye':                   'DoS',
    'DoS slowloris':                   'DoS',
    'DoS Slowhttptest':                'DoS',
    'PortScan':                        'PortScan',
    'FTP-Patator':                     'BruteForce',
    'SSH-Patator':                     'BruteForce',
    'Bot':                             'Botnet',
    'Web Attack \u2013 Brute Force':   'WebAttack',   # em-dash variant
    'Web Attack \u2013 XSS':           'WebAttack',
    'Web Attack \u2013 Sql Injection':  'WebAttack',
    'Web Attack - Brute Force':        'WebAttack',   # hyphen variant
    'Web Attack - XSS':                'WebAttack',
    'Web Attack - Sql Injection':      'WebAttack',
    'Infiltration':                    'Infiltration',
    'Heartbleed':                      'Heartbleed',
}

# ── 2. LOAD DATA ──────────────────────────────────────────────────────────────

print('Scanning for CSV files...')
# deduplicate in case both glob patterns match the same files
csv_files = sorted(set(
    glob.glob(os.path.join(DATA_PATH, '**/*.csv'), recursive=True) +
    glob.glob(os.path.join(DATA_PATH, '*.csv'))
))

if not csv_files:
    raise FileNotFoundError(
        f'No CSV files found under {DATA_PATH}\n'
        'Make sure you added the CICIDS-2017 dataset to this notebook.'
    )

print(f'Found {len(csv_files)} file(s):')
for f in csv_files:
    print(f'  {f}')

dfs = []
for path in csv_files:
    print(f'\nLoading {os.path.basename(path)}...')
    df = pd.read_csv(path, low_memory=False, encoding='latin-1')
    # Strip leading/trailing whitespace from column names (some versions have it)
    df.columns = df.columns.str.strip()
    print(f'  Shape: {df.shape}  |  Columns: {len(df.columns)}')
    dfs.append(df)

df = pd.concat(dfs, ignore_index=True)
print(f'\nTotal dataset shape: {df.shape}')

# ── 3. VERIFY REQUIRED COLUMNS ───────────────────────────────────────────────

missing = [f for f in FEATURES if f not in df.columns]
if missing:
    print('\nWARNING: These feature columns are missing from the dataset:')
    for m in missing:
        print(f'  - {m}')
    print('\nAvailable columns:')
    print(list(df.columns))
    raise ValueError('Dataset is missing required feature columns. See above.')

if 'Label' not in df.columns:
    raise ValueError('"Label" column not found in dataset.')

# ── 4. MAP LABELS ─────────────────────────────────────────────────────────────

print('\nOriginal label distribution:')
print(df['Label'].value_counts())

# Normalize labels: replace any garbled non-ASCII characters (e.g. ï¿½) with a hyphen
# This fixes "Web Attack ï¿½ Brute Force" → "Web Attack - Brute Force"
import re
df['Label'] = df['Label'].str.strip().apply(
    lambda x: re.sub(r'[^\x00-\x7F]+', '-', str(x)).strip()
)

df['label_mapped'] = df['Label'].map(LABEL_MAP)

unmapped = df[df['label_mapped'].isna()]['Label'].unique()
if len(unmapped):
    print(f'\nWARNING: Unmapped labels (will be dropped): {unmapped}')
    df = df[df['label_mapped'].notna()]

print('\nMapped label distribution:')
print(df['label_mapped'].value_counts())

# ── 5. PREPARE FEATURES ───────────────────────────────────────────────────────

X = df[FEATURES].copy()
y = df['label_mapped']

# Replace inf values and NaN
X.replace([np.inf, -np.inf], np.nan, inplace=True)
X.fillna(0, inplace=True)

# Clip extreme outliers to prevent them from dominating the model
for col in X.columns:
    p99 = X[col].quantile(0.9999)
    if p99 > 0:
        X[col] = X[col].clip(upper=p99 * 10)

print(f'\nFeature matrix shape: {X.shape}')
print(f'Any remaining NaN: {X.isna().any().any()}')
print(f'Any inf: {np.isinf(X.values).any()}')

# ── 6. ENCODE LABELS ──────────────────────────────────────────────────────────

le = LabelEncoder()
y_enc = le.fit_transform(y)
print(f'\nLabel classes: {list(le.classes_)}')

# ── 7. TRAIN / TEST SPLIT ─────────────────────────────────────────────────────

X_train, X_test, y_train, y_test = train_test_split(
    X, y_enc,
    test_size=0.2,
    random_state=42,
    stratify=y_enc
)
print(f'\nTrain size: {len(X_train):,}  |  Test size: {len(X_test):,}')

# ── 8. TRAIN RANDOM FOREST ───────────────────────────────────────────────────

print('\nTraining Random Forest...')
print('(This takes 3-10 minutes on Kaggle depending on dataset size)')

rf = RandomForestClassifier(
    n_estimators=100,       # 100 trees — good balance of accuracy vs file size
    max_depth=20,           # prevents overfitting
    min_samples_leaf=5,     # avoids memorising rare noisy samples
    n_jobs=-1,              # use all CPU cores
    random_state=42,
    class_weight='balanced' # handles class imbalance (BENIGN >> attacks)
)
rf.fit(X_train, y_train)
print('Training complete.')

# ── 9. EVALUATE ───────────────────────────────────────────────────────────────

print('\n── Test Set Performance ──────────────────────────────────')
y_pred = rf.predict(X_test)
print(classification_report(y_test, y_pred, target_names=le.classes_))

print('\nTop 10 feature importances:')
importances = sorted(
    zip(FEATURES, rf.feature_importances_),
    key=lambda x: x[1], reverse=True
)
for name, score in importances[:10]:
    bar = '█' * int(score * 200)
    print(f'  {name:<40} {score:.4f}  {bar}')

# ── 10. SAVE MODEL ────────────────────────────────────────────────────────────

model_bundle = {
    'model': rf,
    'label_encoder': le,
    'features': FEATURES,
    'version': '1.0',
    'trained_on': 'CICIDS-2017',
}

joblib.dump(model_bundle, OUTPUT_PATH, compress=3)
size_mb = os.path.getsize(OUTPUT_PATH) / (1024 * 1024)
print(f'\nModel saved to: {OUTPUT_PATH}  ({size_mb:.1f} MB)')
print('\nNext step: Download sentinels_rf_model.pkl and upload it')
print('in Sentinels → Settings → ML Model Import.')
