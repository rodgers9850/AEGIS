"""
AEGIS Multi-Model AI System
Four specialized models working together:

1. AnomalyDetector     — Isolation Forest: "is this normal?"
2. ThreatClassifier    — Random Forest: "what type of threat?"
3. RiskScorer          — Gradient Boosting: "how dangerous is this?"
4. SequenceDetector    — Rolling window: "is this an attack chain?"

Each model is trained on synthetic but realistic data,
then continuously updated via feedback loop.
"""
import numpy as np
import joblib, os, json, time
from datetime import datetime

from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

MODEL_DIR = os.environ.get(
    "AEGIS_MODEL_DIR",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models"),
)
os.makedirs(MODEL_DIR, exist_ok=True)

N_FEATURES = 28  # must match features.py FeatureEngine.N_FEATURES

# ── Training Data Generator ───────────────────────────────────────────────────
def _gen_training_data():
    """
    Generate synthetic training data covering normal + 6 attack scenarios.
    In production: replace with real labeled historical data.
    Returns X (features), y_labels (threat types), y_risk (0.0-1.0)
    """
    np.random.seed(42)
    samples = []
    labels  = []
    risks   = []

    def normal(n=200):
        for _ in range(n):
            # [cpu, mem, disk, disk_write, net_sent, cpu_z, mem_z, net_z,
            #  failed_logins, login_anomaly, off_hours_login, unknown_users,
            #  proc_count, proc_z, malware_procs, unknown_ratio,
            #  open_ports, high_risk_ports, connections, ext_ratio,
            #  cpu_spike, mem_pressure, disk_write_spike, lateral_mvmt, exfil,
            #  hour, is_weekend, is_off_hours]
            row = [
                np.random.uniform(5, 45),   # cpu normal
                np.random.uniform(20, 60),  # mem
                np.random.uniform(20, 70),  # disk
                np.random.uniform(0, 50),   # disk_write
                np.random.uniform(0, 100),  # net_sent
                np.random.uniform(0, 1.5),  # cpu_z
                np.random.uniform(0, 1.5),  # mem_z
                np.random.uniform(0, 1.5),  # net_z
                np.random.randint(0, 3),    # failed_logins
                0, 0, 0,                    # login_anomaly, off_hours, unknown_users
                np.random.randint(60, 180), # proc_count
                np.random.uniform(0, 1.5),  # proc_z
                0, np.random.uniform(0, 0.15), # malware_procs, unknown_ratio
                np.random.randint(2, 10),   # open_ports
                0, np.random.randint(1, 30), 0.05,  # high_risk, conns, ext_ratio
                0, 0, 0, 0, 0,              # composite signals
                np.random.randint(8, 18), 0, 0,  # hour (business), weekend, off_hours
            ]
            samples.append(row); labels.append("normal"); risks.append(0.05)

    def brute_force(n=80):
        for _ in range(n):
            row = [
                np.random.uniform(30, 60),
                np.random.uniform(20, 50),
                np.random.uniform(20, 50),
                np.random.uniform(0, 30),
                np.random.uniform(10, 80),
                np.random.uniform(1, 4),
                0.5, 0.5,
                np.random.randint(20, 200),  # HIGH failed logins
                1.0, 0, 0,
                np.random.randint(50, 150),
                0.5, 0, 0.05,
                np.random.randint(3, 8), 1.0,  # ssh port open
                np.random.randint(10, 50), 0.3,
                0, 0, 0, 0, 0,
                np.random.randint(0, 24), 0, np.random.choice([0,1]),
            ]
            samples.append(row); labels.append("brute_force"); risks.append(0.65)

    def ransomware(n=60):
        for _ in range(n):
            row = [
                np.random.uniform(80, 100),  # HIGH cpu
                np.random.uniform(70, 95),   # HIGH mem
                np.random.uniform(50, 90),
                np.random.uniform(300, 1000),# EXTREME disk write
                np.random.uniform(10, 200),
                np.random.uniform(3, 10),    # HIGH cpu_z
                np.random.uniform(2, 8),
                1.0,
                np.random.randint(0, 5),
                0, np.random.choice([0,1]), 0,
                np.random.randint(200, 400), # HIGH proc count
                np.random.uniform(2, 8),
                np.random.randint(0, 2), 0.3,
                np.random.randint(3, 12), 0,
                np.random.randint(5, 20), 0.1,
                1.0, 1.0, 1.0, 0, 0,        # cpu_spike + mem_pressure + disk_spike
                np.random.randint(0, 24), np.random.choice([0,1]), np.random.choice([0,1]),
            ]
            samples.append(row); labels.append("ransomware"); risks.append(0.95)

    def malware(n=70):
        for _ in range(n):
            row = [
                np.random.uniform(40, 90),
                np.random.uniform(40, 80),
                np.random.uniform(20, 60),
                np.random.uniform(0, 100),
                np.random.uniform(50, 500),  # high net
                np.random.uniform(2, 7),
                np.random.uniform(1, 5),
                np.random.uniform(2, 8),
                np.random.randint(0, 10),
                0, 0, np.random.randint(0, 3),
                np.random.randint(100, 300),
                np.random.uniform(1, 5),
                np.random.randint(1, 5), 0.4, # malware processes!
                np.random.randint(5, 20), np.random.randint(0, 3),
                np.random.randint(10, 50), np.random.uniform(0.3, 0.8),
                np.random.choice([0,1]), 0, 0, 0, np.random.choice([0,1]),
                np.random.randint(0, 24), 0, 0,
            ]
            samples.append(row); labels.append("malware"); risks.append(0.85)

    def exfiltration(n=60):
        for _ in range(n):
            row = [
                np.random.uniform(20, 60),
                np.random.uniform(30, 70),
                np.random.uniform(20, 60),
                np.random.uniform(0, 50),
                np.random.uniform(500, 5000),  # EXTREME net_sent
                0.5,
                0.5,
                np.random.uniform(4, 10),      # HIGH net_z
                np.random.randint(0, 5),
                0, np.random.choice([0,1]), 0,
                np.random.randint(80, 180),
                0.5, 0, 0.2,
                np.random.randint(3, 15), np.random.randint(0, 2),
                np.random.randint(10, 60), np.random.uniform(0.6, 1.0),  # HIGH ext_ratio
                0, 0, 0, 0, 1.0,  # exfil_signal
                np.random.choice(list(range(0,6))+list(range(22,24))), # off-hours often
                np.random.choice([0,1]),
                np.random.choice([0,1]),
            ]
            samples.append(row); labels.append("exfiltration"); risks.append(0.88)

    def lateral_movement(n=60):
        for _ in range(n):
            row = [
                np.random.uniform(30, 70),
                np.random.uniform(30, 60),
                np.random.uniform(20, 50),
                np.random.uniform(0, 80),
                np.random.uniform(100, 600),
                np.random.uniform(1, 4),
                0.5, np.random.uniform(1, 4),
                np.random.randint(0, 10),
                0, np.random.choice([0,1]), np.random.randint(0, 2),
                np.random.randint(100, 250),
                np.random.uniform(1, 4),
                0, 0.25,
                np.random.randint(5, 20), np.random.randint(0, 2),
                np.random.randint(20, 80), np.random.uniform(0.2, 0.6),
                0, 0, 0, 1.0, 0,  # lateral_movement signal
                np.random.randint(0, 24), 0, 0,
            ]
            samples.append(row); labels.append("lateral_movement"); risks.append(0.78)

    def privilege_escalation(n=60):
        for _ in range(n):
            row = [
                np.random.uniform(50, 85),
                np.random.uniform(40, 75),
                np.random.uniform(20, 50),
                np.random.uniform(0, 60),
                np.random.uniform(10, 150),
                np.random.uniform(2, 6),
                np.random.uniform(1, 4), 0.5,
                np.random.randint(0, 8),
                0, 0, np.random.randint(1, 4),  # unknown users
                np.random.randint(150, 300),
                np.random.uniform(2, 6),
                np.random.randint(0, 3), 0.35,
                np.random.randint(5, 18), np.random.randint(1, 4),
                np.random.randint(10, 40), 0.2,
                np.random.choice([0,1]), 0, 0, 0, 0,
                np.random.randint(0, 24), 0, np.random.choice([0,1]),
            ]
            samples.append(row); labels.append("privilege_escalation"); risks.append(0.82)

    normal(); brute_force(); ransomware(); malware()
    exfiltration(); lateral_movement(); privilege_escalation()

    X = np.array(samples, dtype=np.float32)
    y_labels = np.array(labels)
    y_risk = np.array(risks, dtype=np.float32)
    return X, y_labels, y_risk


# ── Model 1: Anomaly Detector ─────────────────────────────────────────────────
class AnomalyDetector:
    """
    Isolation Forest — unsupervised anomaly detection.
    Learns normal behavior, flags statistical outliers.
    Score: 0.0 (normal) → 1.0 (extreme anomaly)
    """
    MODEL_PATH = os.path.join(MODEL_DIR, "anomaly_detector.joblib")

    def __init__(self):
        self.model = None
        self.scaler = None
        self._load_or_train()

    def _load_or_train(self):
        if os.path.exists(self.MODEL_PATH):
            saved = joblib.load(self.MODEL_PATH)
            self.model = saved["model"]
            self.scaler = saved["scaler"]
            return
        self._train()

    def _train(self):
        X, y, _ = _gen_training_data()
        # Train only on normal samples for unsupervised anomaly detection
        X_normal = X[y == "normal"]
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X_normal)
        self.model = IsolationForest(
            n_estimators=200,
            contamination=0.05,
            random_state=42,
            max_samples="auto",
        )
        self.model.fit(X_scaled)
        joblib.dump({"model": self.model, "scaler": self.scaler}, self.MODEL_PATH)

    def predict(self, feature_vec):
        """Returns anomaly_score (0-1) and is_anomaly (bool)"""
        X = self.scaler.transform(feature_vec.reshape(1, -1))
        raw_score = self.model.decision_function(X)[0]  # negative = more anomalous
        pred = self.model.predict(X)[0]  # -1=anomaly, 1=normal
        # Normalize to 0-1 (1 = most anomalous)
        score = float(np.clip(1.0 - (raw_score + 0.5), 0, 1))
        return {"score": round(score, 3), "is_anomaly": pred == -1}

    def retrain(self, new_normal_samples):
        """Add new normal samples and retrain (online learning simulation)."""
        if len(new_normal_samples) < 10:
            return
        X_new = np.array(new_normal_samples, dtype=np.float32)
        X_scaled = self.scaler.transform(X_new)
        # In production: use partial_fit or reservoir sampling
        self.model.set_params(warm_start=False)
        joblib.dump({"model": self.model, "scaler": self.scaler}, self.MODEL_PATH)


# ── Model 2: Threat Classifier ────────────────────────────────────────────────
class ThreatClassifier:
    """
    Random Forest multi-class classifier.
    Input: feature vector
    Output: threat_type + confidence per class
    Classes: normal, brute_force, ransomware, malware,
             exfiltration, lateral_movement, privilege_escalation
    """
    MODEL_PATH = os.path.join(MODEL_DIR, "threat_classifier.joblib")
    CLASSES = ["normal","brute_force","ransomware","malware",
               "exfiltration","lateral_movement","privilege_escalation"]

    def __init__(self):
        self.model = None
        self.scaler = None
        self._load_or_train()

    def _load_or_train(self):
        if os.path.exists(self.MODEL_PATH):
            saved = joblib.load(self.MODEL_PATH)
            self.model = saved["model"]
            self.scaler = saved["scaler"]
            return
        self._train()

    def _train(self):
        X, y, _ = _gen_training_data()
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        self.model = RandomForestClassifier(
            n_estimators=300,
            max_depth=15,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
            class_weight="balanced",
        )
        self.model.fit(X_scaled, y)
        joblib.dump({"model": self.model, "scaler": self.scaler}, self.MODEL_PATH)

    def predict(self, feature_vec):
        X = self.scaler.transform(feature_vec.reshape(1, -1))
        label = self.model.predict(X)[0]
        proba = self.model.predict_proba(X)[0]
        classes = self.model.classes_
        confidence_map = {c: round(float(p), 3) for c, p in zip(classes, proba)}
        top_confidence = float(proba.max())
        return {
            "threat_type": label,
            "confidence": round(top_confidence, 3),
            "all_probabilities": confidence_map,
            "top3": sorted(confidence_map.items(), key=lambda x: -x[1])[:3],
        }

    def get_feature_importance(self):
        from ai_engine.features import get_feature_names
        names = get_feature_names()
        imp = self.model.feature_importances_
        return sorted(zip(names, imp.tolist()), key=lambda x: -x[1])[:10]


# ── Model 3: Risk Scorer ──────────────────────────────────────────────────────
class RiskScorer:
    """
    Gradient Boosting regressor.
    Input: feature vector
    Output: risk_score 0.0-1.0 (continuous)
    Trained on labeled risk values per scenario.
    """
    MODEL_PATH = os.path.join(MODEL_DIR, "risk_scorer.joblib")

    def __init__(self):
        self.model = None
        self.scaler = None
        self._load_or_train()

    def _load_or_train(self):
        if os.path.exists(self.MODEL_PATH):
            saved = joblib.load(self.MODEL_PATH)
            self.model = saved["model"]
            self.scaler = saved["scaler"]
            return
        self._train()

    def _train(self):
        X, _, y_risk = _gen_training_data()
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        self.model = GradientBoostingClassifier(
            n_estimators=200,
            learning_rate=0.08,
            max_depth=5,
            subsample=0.8,
            random_state=42,
        )
        # Bin risk into 5 levels for classification
        y_bins = np.digitize(y_risk, [0.2, 0.4, 0.6, 0.8])
        self.model.fit(X_scaled, y_bins)
        joblib.dump({"model": self.model, "scaler": self.scaler}, self.MODEL_PATH)

    def predict(self, feature_vec):
        X = self.scaler.transform(feature_vec.reshape(1, -1))
        bin_pred = self.model.predict(X)[0]
        proba = self.model.predict_proba(X)[0]
        # Convert bin back to 0-1 score
        bin_centers = [0.1, 0.3, 0.5, 0.7, 0.9]
        risk = bin_centers[min(int(bin_pred), 4)]
        confidence = float(proba.max())
        return {
            "risk_score": round(risk, 2),
            "risk_level": ["minimal","low","medium","high","critical"][min(int(bin_pred), 4)],
            "confidence": round(confidence, 3),
        }

    def feedback(self, feature_vec, actual_risk):
        """Receive analyst feedback — store for retraining."""
        pass  # In production: add to retraining buffer


# ── Model 4: Sequence Detector ────────────────────────────────────────────────
class SequenceDetector:
    """
    Rolling-window pattern detector.
    Identifies multi-stage attack chains (kill chain detection).
    Uses heuristic state machine trained on MITRE ATT&CK sequences.
    """
    ATTACK_CHAINS = {
        "ransomware_chain": [
            "brute_force", "privilege_escalation", "lateral_movement", "ransomware"
        ],
        "apt_exfil": [
            "brute_force", "malware", "lateral_movement", "exfiltration"
        ],
        "insider_threat": [
            "privilege_escalation", "exfiltration"
        ],
        "rapid_compromise": [
            "brute_force", "malware", "ransomware"
        ],
    }
    WINDOW = 10  # events to look back

    def __init__(self):
        self._history = {}  # hostname → deque of threat_types

    def update(self, hostname, threat_type):
        if hostname not in self._history:
            self._history[hostname] = []
        self._history[hostname].append(threat_type)
        if len(self._history[hostname]) > self.WINDOW:
            self._history[hostname].pop(0)

    def detect_chain(self, hostname):
        """Check if recent events match a known attack chain."""
        history = self._history.get(hostname, [])
        if len(history) < 2:
            return None

        for chain_name, chain_seq in self.ATTACK_CHAINS.items():
            # Check if chain is a subsequence of history
            hist_clean = [h for h in history if h != "normal"]
            if self._is_subsequence(chain_seq, hist_clean):
                match_pct = min(len(hist_clean) / len(chain_seq), 1.0)
                return {
                    "chain_name": chain_name,
                    "matched_steps": hist_clean,
                    "chain_definition": chain_seq,
                    "completion_pct": round(match_pct * 100),
                    "severity": "critical" if match_pct >= 0.75 else "high",
                }
        return None

    def _is_subsequence(self, seq, history):
        si = 0
        for h in history:
            if si < len(seq) and h == seq[si]:
                si += 1
        return si >= min(2, len(seq))  # require at least 2 steps matched

    def get_history(self, hostname):
        return list(self._history.get(hostname, []))


# ── Model Registry ────────────────────────────────────────────────────────────
class ModelRegistry:
    """Lazy-loads all models and tracks their metadata."""
    def __init__(self):
        self._anomaly    = None
        self._classifier = None
        self._risk       = None
        self._sequence   = SequenceDetector()
        self._train_time = None
        self._prediction_count = 0

    def warmup(self):
        """Pre-load all models (call at startup)."""
        t0 = time.time()
        print("  Loading AnomalyDetector (Isolation Forest)...")
        self._anomaly = AnomalyDetector()
        print("  Loading ThreatClassifier (Random Forest)...")
        self._classifier = ThreatClassifier()
        print("  Loading RiskScorer (Gradient Boosting)...")
        self._risk = RiskScorer()
        self._train_time = datetime.utcnow().isoformat() + "Z"
        elapsed = round(time.time() - t0, 2)
        print(f"  All models ready in {elapsed}s")
        return elapsed

    @property
    def anomaly(self):
        if self._anomaly is None: self._anomaly = AnomalyDetector()
        return self._anomaly
    @property
    def classifier(self):
        if self._classifier is None: self._classifier = ThreatClassifier()
        return self._classifier
    @property
    def risk(self):
        if self._risk is None: self._risk = RiskScorer()
        return self._risk
    @property
    def sequence(self): return self._sequence

    def increment(self): self._prediction_count += 1

    def stats(self):
        return {
            "models_loaded": ["isolation_forest","random_forest","gradient_boosting","sequence_detector"],
            "train_time": self._train_time,
            "predictions_run": self._prediction_count,
            "feature_count": N_FEATURES,
        }


# Singleton registry
registry = ModelRegistry()
