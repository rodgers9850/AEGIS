"""
AEGIS Feature Engineering Engine
Converts raw psutil agent telemetry into structured numerical feature vectors
that can be consumed by ML models.

Raw data → meaningful signals → feature vector → AI models
"""
import numpy as np
from datetime import datetime

# ── Process Whitelists ────────────────────────────────────────────────────────
SAFE_PROCESSES = {
    # System processes
    "systemd","init","kthreadd","kworker","ksoftirqd","migration","rcu_sched",
    "watchdog","kdevtmpfs","netns","kauditd","khungtaskd","oom_reaper",
    # Common services
    "sshd","nginx","apache2","httpd","mysqld","postgres","redis-server",
    "docker","containerd","kubelet","journald","rsyslogd","cron","atd",
    # User apps
    "bash","sh","zsh","fish","python3","python","node","java","ruby","php",
    "chrome","firefox","safari","code","vim","nano","less","cat","grep","awk",
    "systemctl","ps","top","htop","ls","cp","mv","find","curl","wget","git",
    "ssh","scp","rsync","tar","gzip","unzip","openssl","gpg",
}

MALWARE_SIGNATURES = {
    "mimikatz","meterpreter","cobaltstrike","psexec","wce.exe","pwdump",
    "nc.exe","ncat","netcat","cryptolocker","wannacry","lazagne","masscan",
    "hydra","john","hashcat","medusa","reaver","aircrack","sqlmap","metasploit",
    "empire","covenant","havoc","sliver","brute_ratel","posh_c2",
}

HIGH_RISK_PORTS = {22, 23, 3389, 5900, 4444, 8080, 8443, 31337, 1337}
SENSITIVE_PORTS = {21, 25, 110, 143, 3306, 5432, 6379, 27017, 9200}

# ── Baseline Store (per-host rolling statistics) ──────────────────────────────
class BaselineStore:
    """Maintains per-host rolling baselines for anomaly detection."""
    def __init__(self):
        self._data = {}  # hostname → {metric → [values]}
        self._window = 50  # rolling window size

    def update(self, hostname, metrics):
        if hostname not in self._data:
            self._data[hostname] = {k: [] for k in metrics}
        for k, v in metrics.items():
            if k not in self._data[hostname]:
                self._data[hostname][k] = []
            self._data[hostname][k].append(float(v))
            if len(self._data[hostname][k]) > self._window:
                self._data[hostname][k].pop(0)

    def mean(self, hostname, metric):
        vals = self._data.get(hostname, {}).get(metric, [])
        return float(np.mean(vals)) if vals else 30.0

    def std(self, hostname, metric):
        vals = self._data.get(hostname, {}).get(metric, [])
        return float(np.std(vals)) if len(vals) > 2 else 10.0

    def z_score(self, hostname, metric, value):
        mu = self.mean(hostname, metric)
        sigma = self.std(hostname, metric) or 1.0
        return abs(value - mu) / sigma

    def has_baseline(self, hostname):
        return hostname in self._data and len(self._data[hostname].get("cpu_percent", [])) >= 5

# Singleton baseline store
_baseline_store = BaselineStore()


# ── Main Feature Engineering ──────────────────────────────────────────────────
class FeatureEngine:
    """
    Transforms raw agent telemetry into a structured feature vector.
    Output is a fixed-length numpy array + human-readable feature dict.
    """

    FEATURE_NAMES = [
        # Resource metrics (0-4)
        "cpu_percent", "memory_percent", "disk_percent",
        "disk_write_mb", "net_sent_mb",

        # Z-scores vs baseline (5-7) - how many std devs from normal
        "cpu_zscore", "memory_zscore", "net_zscore",

        # Identity signals (8-11)
        "failed_logins", "login_anomaly",          # > 2× baseline avg
        "off_hours_login", "unknown_user_count",

        # Process signals (12-15)
        "process_count", "process_count_zscore",
        "malware_process_count", "unknown_process_ratio",

        # Network signals (16-19)
        "open_port_count", "high_risk_port_count",
        "connection_count", "external_connection_ratio",

        # Composite risk signals (20-24)
        "cpu_spike",           # cpu > 85 AND zscore > 2
        "memory_pressure",     # memory > 85
        "disk_write_spike",    # disk_write > 200MB
        "lateral_movement",    # internal connections to many hosts
        "data_exfil_signal",   # high outbound to external IPs

        # Time context (25-27)
        "hour_of_day", "is_weekend", "is_off_hours",
    ]

    N_FEATURES = len(FEATURE_NAMES)  # 28

    def __init__(self):
        self.baseline = _baseline_store

    def extract(self, raw):
        """
        Extract features from raw agent data dict.
        Returns (feature_vector: np.array, feature_dict: dict, context: dict)
        """
        hostname = raw.get("hostname", "unknown")
        now = datetime.utcnow()
        hour = now.hour
        is_weekend = now.weekday() >= 5
        is_off_hours = hour < 6 or hour > 21

        # Update baseline
        self.baseline.update(hostname, {
            "cpu_percent": raw.get("cpu_percent", 0),
            "memory_percent": raw.get("memory_percent", 0),
            "net_sent_mb": raw.get("bytes_sent_mb", 0),
            "process_count": raw.get("process_count", 0),
            "failed_logins": raw.get("failed_logins", 0),
        })

        # ── Resource ──
        cpu = float(raw.get("cpu_percent", 0))
        mem = float(raw.get("memory_percent", 0))
        disk = float(raw.get("disk_percent", 0))
        disk_write = float(raw.get("disk_write_mb", 0))
        net_sent = float(raw.get("bytes_sent_mb", 0))

        # ── Z-scores ──
        cpu_z  = self.baseline.z_score(hostname, "cpu_percent", cpu)
        mem_z  = self.baseline.z_score(hostname, "memory_percent", mem)
        net_z  = self.baseline.z_score(hostname, "net_sent_mb", net_sent)

        # ── Identity ──
        failed = int(raw.get("failed_logins", 0))
        users  = raw.get("logged_in_users", [])
        login_avg = self.baseline.mean(hostname, "failed_logins")
        login_anomaly = 1.0 if failed > max(login_avg * 2, 5) else 0.0
        unknown_users = sum(1 for u in users if u.lower() not in {
            "root","ubuntu","admin","administrator","vagrant","ec2-user","user"
        })

        # ── Processes ──
        procs = [p.lower() for p in raw.get("processes", [])]
        proc_count = int(raw.get("process_count", len(procs)))
        proc_z = self.baseline.z_score(hostname, "process_count", proc_count)
        malware_count = sum(1 for p in procs if any(m in p for m in MALWARE_SIGNATURES))
        safe_set = SAFE_PROCESSES
        unknown_procs = [p for p in procs if p.split(".")[0] not in safe_set]
        unknown_ratio = len(unknown_procs) / max(len(procs), 1)

        # ── Network ──
        conns = raw.get("network_connections", [])
        ports = set(raw.get("open_ports", []))
        high_risk_ports = len(ports & HIGH_RISK_PORTS)
        external = [c for c in conns if c.get("raddr") and not str(c.get("raddr","")).startswith(("192.","10.","172."))]
        ext_ratio = len(external) / max(len(conns), 1)

        # ── Composite signals ──
        cpu_spike       = 1.0 if cpu > 85 and cpu_z > 2.0 else 0.0
        mem_pressure    = 1.0 if mem > 85 else 0.0
        disk_write_spike= 1.0 if disk_write > 200 else 0.0
        lateral_mvmt    = 1.0 if len({
            address for c in conns
            if (address := str(c.get("raddr") or "")).startswith(("192.", "10."))
        }) > 10 else 0.0
        exfil_signal    = 1.0 if net_sent > 500 and ext_ratio > 0.5 else 0.0

        vec = np.array([
            cpu, mem, disk, disk_write, net_sent,
            min(cpu_z, 10.0), min(mem_z, 10.0), min(net_z, 10.0),
            float(failed), login_anomaly, float(is_off_hours and len(users) > 0), float(unknown_users),
            float(proc_count), min(proc_z, 10.0), float(malware_count), unknown_ratio,
            float(len(ports)), float(high_risk_ports), float(len(conns)), ext_ratio,
            cpu_spike, mem_pressure, disk_write_spike, lateral_mvmt, exfil_signal,
            float(hour), float(is_weekend), float(is_off_hours),
        ], dtype=np.float32)

        feature_dict = dict(zip(self.FEATURE_NAMES, vec.tolist()))

        context = {
            "hostname": hostname,
            "hour": hour,
            "is_weekend": is_weekend,
            "is_off_hours": is_off_hours,
            "has_baseline": self.baseline.has_baseline(hostname),
            "baseline_cpu": round(self.baseline.mean(hostname, "cpu_percent"), 1),
            "baseline_logins": round(self.baseline.mean(hostname, "failed_logins"), 1),
            "malware_processes": [p for p in procs if any(m in p for m in MALWARE_SIGNATURES)],
            "unknown_users": [u for u in users if u.lower() not in {"root","ubuntu","admin","administrator","vagrant","ec2-user","user"}],
            "suspicious_ports": list(ports & (HIGH_RISK_PORTS | SENSITIVE_PORTS)),
        }

        return vec, feature_dict, context

# Singleton
_feature_engine = FeatureEngine()

def extract_features(raw_data):
    return _feature_engine.extract(raw_data)

def get_feature_names():
    return FeatureEngine.FEATURE_NAMES

def get_baseline_store():
    return _baseline_store
