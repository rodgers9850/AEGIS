"""
AEGIS Decision Engine + Explainable AI (XAI)
Combines outputs from all 4 models into a final decision with
full human-readable explanation of WHY the decision was made.

Input:  feature_vec + feature_dict + context + model outputs
Output: DecisionResult with threat_type, severity, confidence,
        explanation, evidence, recommended_actions
"""
from datetime import datetime


# ── Severity Mapping ──────────────────────────────────────────────────────────
THREAT_SEVERITY = {
    "normal":               "low",
    "brute_force":          "high",
    "ransomware":           "critical",
    "malware":              "critical",
    "exfiltration":         "critical",
    "lateral_movement":     "high",
    "privilege_escalation": "high",
}

THREAT_MITRE = {
    "brute_force":          "T1110 — Brute Force",
    "ransomware":           "T1486 — Data Encrypted for Impact",
    "malware":              "T1059 — Command and Scripting Interpreter",
    "exfiltration":         "T1041 — Exfiltration Over C2 Channel",
    "lateral_movement":     "T1021 — Remote Services",
    "privilege_escalation": "T1068 — Exploitation for Privilege Escalation",
}

AUTO_ACTIONS = {
    ("ransomware",           "critical"): ["isolate_device","backup_trigger","block_c2","notify_admin","forensic_snapshot"],
    ("malware",              "critical"): ["isolate_device","kill_process","block_ip","notify_admin"],
    ("exfiltration",         "critical"): ["isolate_device","block_ip","notify_admin","forensic_snapshot"],
    ("brute_force",          "high"):     ["block_ip","rate_limit","notify_admin"],
    ("brute_force",          "critical"): ["block_ip","lock_account","notify_admin"],
    ("lateral_movement",     "high"):     ["isolate_device","notify_admin","log_forensic"],
    ("privilege_escalation", "high"):     ["lock_account","kill_process","notify_admin"],
    ("privilege_escalation", "critical"): ["lock_account","isolate_device","notify_admin","forensic_snapshot"],
}


class DecisionResult:
    """Full AI decision with explanation."""
    __slots__ = [
        "threat_type","severity","confidence","anomaly_score","risk_score",
        "explanation","evidence","why_not_normal","recommended_actions",
        "attack_chain","feature_importance","context","timestamp",
        "model_votes","should_alert",
    ]
    def __init__(self, **kwargs):
        for k in self.__slots__:
            setattr(self, k, kwargs.get(k))

    def to_dict(self):
        return {k: getattr(self, k) for k in self.__slots__}


class DecisionEngine:
    """
    Combines outputs from all 4 AI models into a final decision.
    Implements ensemble voting + confidence thresholds + XAI.
    """

    # Confidence thresholds
    ALERT_THRESHOLD     = 0.45   # below = skip alert
    CRITICAL_THRESHOLD  = 0.75   # above + critical type = critical severity
    ANOMALY_THRESHOLD   = 0.55   # isolation forest anomaly score

    def decide(self, feature_vec, feature_dict, context,
               anomaly_result, classifier_result, risk_result, chain_result):
        """
        Master decision combining all model outputs.
        Returns DecisionResult with full explanation.
        """
        threat_type = classifier_result["threat_type"]
        clf_conf    = classifier_result["confidence"]
        anomaly_sc  = anomaly_result["score"]
        is_anomaly  = anomaly_result["is_anomaly"]
        risk_sc     = risk_result["risk_score"]

        # ── Ensemble Vote ─────────────────────────────────────────────────────
        # Combine classifier confidence + anomaly signal + risk score
        if threat_type == "normal" and not is_anomaly and risk_sc < 0.3:
            final_conf = clf_conf * 0.9
            final_type = "normal"
        elif threat_type == "normal" and is_anomaly:
            # Anomaly detector overrides normal classification
            final_type = "malware"  # unknown threat — conservative
            final_conf = anomaly_sc * 0.7
        else:
            # Weight: classifier 50%, anomaly 25%, risk 25%
            final_conf = (clf_conf * 0.50 + anomaly_sc * 0.25 + risk_sc * 0.25)
            final_type = threat_type

        # ── Severity ──────────────────────────────────────────────────────────
        base_sev = THREAT_SEVERITY.get(final_type, "low")
        if final_type != "normal" and final_conf >= self.CRITICAL_THRESHOLD and base_sev == "high":
            severity = "critical"
        elif final_type != "normal" and final_conf < 0.5:
            severity = "medium"  # uncertain → downgrade
        else:
            severity = base_sev

        should_alert = (final_type != "normal" and final_conf >= self.ALERT_THRESHOLD)

        # ── Recommended Actions ───────────────────────────────────────────────
        actions = AUTO_ACTIONS.get((final_type, severity), [])
        if not actions and severity in ("high","critical"):
            actions = ["notify_admin","log_forensic"]

        # ── Explainability ────────────────────────────────────────────────────
        explanation = self._explain(
            final_type, severity, final_conf, anomaly_sc, risk_sc,
            feature_dict, context, is_anomaly, chain_result
        )

        # ── Evidence (top contributing features) ─────────────────────────────
        evidence = self._build_evidence(feature_dict, context, final_type)

        # ── Why not normal ────────────────────────────────────────────────────
        why_not = self._why_not_normal(feature_dict, context, anomaly_sc, is_anomaly)

        # ── Feature importance for this decision ──────────────────────────────
        feat_imp = self._feature_importance(feature_dict, final_type)

        return DecisionResult(
            threat_type        = final_type,
            severity           = severity,
            confidence         = round(final_conf, 3),
            anomaly_score      = round(anomaly_sc, 3),
            risk_score         = round(risk_sc, 2),
            explanation        = explanation,
            evidence           = evidence,
            why_not_normal     = why_not,
            recommended_actions= actions,
            attack_chain       = chain_result,
            feature_importance = feat_imp,
            context            = context,
            timestamp          = datetime.utcnow().isoformat() + "Z",
            model_votes        = {
                "classifier":   {"type": threat_type, "confidence": clf_conf},
                "anomaly_detector": {"score": anomaly_sc, "is_anomaly": is_anomaly},
                "risk_scorer":  {"risk_score": risk_sc, "level": risk_result["risk_level"]},
                "top3_probs":   classifier_result["top3"],
            },
            should_alert       = should_alert,
        )

    def _explain(self, threat_type, severity, conf, anomaly_sc, risk_sc,
                 features, context, is_anomaly, chain):
        """Generate a human-readable explanation paragraph."""
        hostname = context.get("hostname","unknown")
        parts = []

        if threat_type == "normal":
            return f"All metrics on {hostname} are within normal baseline parameters. No threat detected."

        conf_pct  = round(conf * 100)
        risk_pct  = round(risk_sc * 100)
        anom_pct  = round(anomaly_sc * 100)

        type_desc = {
            "brute_force":          f"repeated authentication failures ({int(features.get('failed_logins',0))} failed logins)",
            "ransomware":           f"extreme disk write activity ({features.get('disk_write_mb',0):.0f}MB) combined with high CPU and memory pressure",
            "malware":              f"known malicious processes in memory and anomalous network behaviour",
            "exfiltration":         f"excessive outbound data transfer ({features.get('net_sent_mb',0):.0f}MB sent) with {round(features.get('external_connection_ratio',0)*100)}% external connections",
            "lateral_movement":     f"unusual internal network scanning pattern across multiple hosts",
            "privilege_escalation": f"unknown user accounts appearing with elevated access patterns",
        }.get(threat_type, "anomalous system behaviour")

        parts.append(f"AI detected {threat_type.replace('_',' ')} on {hostname} with {conf_pct}% confidence.")
        parts.append(f"Triggered by {type_desc}.")

        if is_anomaly:
            parts.append(f"Isolation Forest anomaly score: {anom_pct}% (behaviour deviates significantly from {hostname}'s 30-day baseline).")

        if features.get("cpu_zscore", 0) > 2.5:
            cpu_b = context.get("baseline_cpu", 25)
            parts.append(f"CPU at {features.get('cpu_percent',0):.0f}% is {features.get('cpu_zscore',0):.1f}σ above baseline ({cpu_b:.0f}%).")

        if features.get("malware_process_count", 0) > 0:
            procs = context.get("malware_processes", [])
            parts.append(f"Malware signature match: processes {procs} found in memory.")

        if context.get("is_off_hours") and context.get("unknown_users"):
            parts.append(f"Off-hours activity ({context.get('hour',0):02d}:00 UTC) by unknown user(s): {context.get('unknown_users',[])}.")

        if chain:
            parts.append(f"Attack chain '{chain['chain_name']}' detected: {chain['matched_steps']} → {chain['completion_pct']}% complete.")

        mitre = THREAT_MITRE.get(threat_type)
        if mitre:
            parts.append(f"MITRE ATT&CK: {mitre}.")

        parts.append(f"Risk score: {risk_pct}/100. Automated response: {len(AUTO_ACTIONS.get((threat_type,severity),[]))} actions queued.")

        return " ".join(parts)

    def _build_evidence(self, features, context, threat_type):
        """Build structured evidence list."""
        ev = []
        if features.get("cpu_percent", 0) > 80:
            ev.append({"metric":"CPU Usage","value":f"{features['cpu_percent']:.1f}%","significance":"high","why":"Exceeds 80% threshold"})
        if features.get("failed_logins", 0) > 5:
            ev.append({"metric":"Failed Logins","value":str(int(features["failed_logins"])),"significance":"high","why":f"Exceeds 5 — possible brute force"})
        if features.get("disk_write_mb", 0) > 100:
            ev.append({"metric":"Disk Write","value":f"{features['disk_write_mb']:.0f}MB","significance":"critical","why":"Unusual write volume — possible encryption"})
        if features.get("net_sent_mb", 0) > 200:
            ev.append({"metric":"Net Outbound","value":f"{features['net_sent_mb']:.0f}MB","significance":"high","why":"Unusual outbound data volume"})
        if features.get("malware_process_count", 0) > 0:
            ev.append({"metric":"Malware Processes","value":str(context.get("malware_processes",[])), "significance":"critical","why":"Known malicious process signature"})
        if context.get("unknown_users"):
            ev.append({"metric":"Unknown Users","value":str(context["unknown_users"]),"significance":"high","why":"User not in known-good baseline"})
        if context.get("suspicious_ports"):
            ev.append({"metric":"High-Risk Ports","value":str(context["suspicious_ports"]),"significance":"medium","why":"Ports associated with C2 or exploitation"})
        if features.get("cpu_zscore", 0) > 2:
            ev.append({"metric":"CPU Anomaly","value":f"{features['cpu_zscore']:.1f}σ above baseline","significance":"high","why":"Statistical deviation from 30-day baseline"})
        return ev

    def _why_not_normal(self, features, context, anomaly_sc, is_anomaly):
        """List specific reasons why this was NOT classified as normal."""
        reasons = []
        if features.get("malware_process_count", 0) > 0:
            reasons.append(f"Malware signatures detected in process list")
        if features.get("failed_logins", 0) > 10:
            reasons.append(f"{int(features['failed_logins'])} failed logins — {int(features['login_anomaly']*100)}% above baseline")
        if features.get("disk_write_mb", 0) > 200:
            reasons.append(f"Disk write {features['disk_write_mb']:.0f}MB exceeds ransomware threshold (200MB)")
        if features.get("net_sent_mb", 0) > 500:
            reasons.append(f"Network egress {features['net_sent_mb']:.0f}MB suggests exfiltration")
        if features.get("cpu_zscore", 0) > 3:
            reasons.append(f"CPU {features['cpu_zscore']:.1f}σ above host baseline — not normal workload")
        if is_anomaly:
            reasons.append(f"Isolation Forest score {anomaly_sc:.2f} — statistical outlier vs training data")
        if context.get("unknown_users"):
            reasons.append(f"Unknown users logged in: {context['unknown_users']}")
        return reasons

    def _feature_importance(self, features, threat_type):
        """Return top features driving this specific decision."""
        relevance = {
            "brute_force":          ["failed_logins","login_anomaly","cpu_zscore"],
            "ransomware":           ["disk_write_mb","disk_write_spike","cpu_percent","memory_percent"],
            "malware":              ["malware_process_count","unknown_process_ratio","net_sent_mb"],
            "exfiltration":         ["net_sent_mb","external_connection_ratio","net_zscore"],
            "lateral_movement":     ["lateral_movement","connection_count","net_sent_mb"],
            "privilege_escalation": ["unknown_user_count","off_hours_login","cpu_zscore"],
        }
        keys = relevance.get(threat_type, list(features.keys())[:5])
        return [{"feature": k, "value": round(float(features.get(k, 0)), 3)} for k in keys]


# Singleton
_decision_engine = DecisionEngine()

def make_decision(feature_vec, feature_dict, context,
                  anomaly_result, classifier_result, risk_result, chain_result):
    return _decision_engine.decide(
        feature_vec, feature_dict, context,
        anomaly_result, classifier_result, risk_result, chain_result
    )
