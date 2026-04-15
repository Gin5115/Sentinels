"""
ML Engine for Sentinels.

Loads the pre-trained Random Forest model (sentinels_rf_model.pkl) and
classifies completed network flows into threat categories.

Gracefully no-ops when no model is installed — the rest of the system
continues working with rule-based detection only.
"""

import os
import threading
import numpy as np

# Default path: app/ml/sentinels_rf_model.pkl
_DEFAULT_MODEL_PATH = os.path.join(
    os.path.dirname(__file__), '..', 'ml', 'sentinels_rf_model.pkl'
)

# Severity per threat class (matches Sentinels' existing severity scale)
_SEVERITY = {
    'Normal':       None,
    'DoS':          'HIGH',
    'PortScan':     'LOW',
    'BruteForce':   'HIGH',
    'Botnet':       'CRITICAL',
    'WebAttack':    'MEDIUM',
    'Infiltration': 'CRITICAL',
    'Heartbleed':   'CRITICAL',
    'Other':        'INFO',
}

_DESCRIPTION = {
    'DoS':          'ML: Denial of Service traffic pattern detected',
    'PortScan':     'ML: Port Scan behaviour detected',
    'BruteForce':   'ML: Brute Force attack pattern detected',
    'Botnet':       'ML: Botnet / C2 communication detected',
    'WebAttack':    'ML: Web Attack detected (XSS / SQLi / BruteForce)',
    'Infiltration': 'ML: Infiltration attempt detected',
    'Heartbleed':   'ML: Heartbleed exploit attempt detected',
    'Other':        'ML: Anomalous traffic pattern detected',
}


class MLEngine:
    """
    Wraps a pre-trained scikit-learn pipeline (RandomForest + LabelEncoder).

    Thread-safe.  Inference: ~1 ms per flow.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._model = None
        self._label_encoder = None
        self._features = None
        self._loaded = False
        self._model_path = os.path.normpath(_DEFAULT_MODEL_PATH)
        self._classes = []

    # ── loading ───────────────────────────────────────────────────────────────

    def load_model(self, path=None):
        """
        Load model bundle from disk.
        Returns True on success, False if file not found.
        Raises on corrupt/incompatible file.
        """
        try:
            import joblib
        except ImportError:
            print('[MLEngine] joblib not installed — run: pip install joblib')
            return False

        target = os.path.normpath(path or self._model_path)

        if not os.path.exists(target):
            print(f'[MLEngine] No model at {target} — ML detection disabled')
            return False

        try:
            bundle = joblib.load(target)
            with self._lock:
                self._model = bundle['model']
                self._label_encoder = bundle['label_encoder']
                self._features = bundle['features']
                self._classes = list(bundle['label_encoder'].classes_)
                self._loaded = True
                self._model_path = target
            print(f'[MLEngine] Model loaded from {target}')
            print(f'[MLEngine] Classes: {self._classes}')
            return True
        except Exception as exc:
            print(f'[MLEngine] Failed to load model: {exc}')
            return False

    def is_loaded(self):
        return self._loaded

    # ── inference ─────────────────────────────────────────────────────────────

    def classify_flow(self, flow):
        """
        Classify a completed Flow object.

        Returns:
            dict  — threat info if a non-Normal class is predicted
            None  — if flow is Normal or model is not loaded
        """
        if not self._loaded:
            return None

        features = flow.extract_features()

        with self._lock:
            vec = np.array([[features.get(f, 0.0) for f in self._features]],
                           dtype=float)
            vec = np.nan_to_num(vec, nan=0.0, posinf=1e9, neginf=0.0)

            idx = self._model.predict(vec)[0]
            label = self._label_encoder.inverse_transform([idx])[0]
            proba = self._model.predict_proba(vec)[0]
            confidence = float(proba.max())


        if label == 'Normal':
            return None

        # Require ≥35% confidence — low threshold is safe because Normal
        # flows are already suppressed above; this only filters random
        # noise from tiny flows where the model has no signal.
        if confidence < 0.35:
            return None

        severity = _SEVERITY.get(label, 'MEDIUM')
        if severity is None:
            return None

        return {
            'type':          f'ML: {label}',
            'ip':            flow.src_ip,
            'dst_ip':        flow.dst_ip,
            'severity':      severity,
            'description':   _DESCRIPTION.get(label, f'ML: {label} detected'),
            'confidence':    round(confidence * 100, 1),
            'flow_packets':  flow.fwd_packets + flow.bwd_packets,
            'flow_duration': round(flow.last_time - flow.start_time, 3),
            'src_port':      flow.src_port,
            'dst_port':      flow.dst_port,
            'protocol':      flow.protocol,
        }

    # ── status / management ───────────────────────────────────────────────────

    def get_status(self):
        with self._lock:
            return {
                'loaded':     self._loaded,
                'model_path': self._model_path,
                'classes':    self._classes,
            }

    def clear(self):
        """No-op — model stays loaded across resets, only flow state resets."""
        pass


# ── singleton ─────────────────────────────────────────────────────────────────

_ml_engine_instance = None


def get_ml_engine() -> MLEngine:
    global _ml_engine_instance
    if _ml_engine_instance is None:
        _ml_engine_instance = MLEngine()
        _ml_engine_instance.load_model()   # silent no-op if no model file yet
    return _ml_engine_instance
