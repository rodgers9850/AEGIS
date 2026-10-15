"""
AEGIS AI Brain — Master Orchestrator
Runs the complete autonomous pipeline:

  Raw Agent Data
      ↓
  Feature Engineering (28 features)
      ↓
  ┌─────────────────────────────────┐
  │  Isolation Forest (anomaly)     │
  │  Random Forest (classification) │
  │  Gradient Boosting (risk score) │
  │  Sequence Detector (chain)      │
  └─────────────────────────────────┘
      ↓
  Decision Engine (ensemble + XAI)
      ↓
  Advisory recommendations (approval required)
      ↓
  Feedback Loop (continuous learning)
"""
import time, json
from datetime import datetime

from ai_engine.features import extract_features
from ai_engine.models   import registry
from ai_engine.decision import make_decision


class AIBrain:
    """
    The central AI orchestrator.
    Called once per agent data submission.
    Returns a complete AIResult with decision + explanation + actions.
    """

    def __init__(self):
        self._feedback_buffer = []  # {feature_vec, label, correct} for retraining
        self._total_processed = 0
        self._correct_predictions = 0

    def process(self, raw_agent_data):
        """
        Full pipeline: raw_data → AIResult
        Returns dict with all AI outputs.
        """
        t0 = time.time()
        hostname = raw_agent_data.get("hostname", "unknown")

        # ── Step 1: Feature Engineering ───────────────────────────────────────
        feature_vec, feature_dict, context = extract_features(raw_agent_data)

        # ── Step 2: Run All 4 Models in Parallel (simulated) ──────────────────
        anomaly_result    = registry.anomaly.predict(feature_vec)
        classifier_result = registry.classifier.predict(feature_vec)
        risk_result       = registry.risk.predict(feature_vec)

        # Update sequence detector
        registry.sequence.update(hostname, classifier_result["threat_type"])
        chain_result = registry.sequence.detect_chain(hostname)

        registry.increment()
        self._total_processed += 1

        # ── Step 3: Decision Engine (ensemble + XAI) ──────────────────────────
        decision = make_decision(
            feature_vec, feature_dict, context,
            anomaly_result, classifier_result, risk_result, chain_result
        )

        elapsed_ms = round((time.time() - t0) * 1000, 1)

        result = {
            # Core decision
            "hostname":          hostname,
            "should_alert":      decision.should_alert,
            "threat_type":       decision.threat_type,
            "severity":          decision.severity,
            "confidence":        decision.confidence,
            "anomaly_score":     decision.anomaly_score,
            "risk_score":        decision.risk_score,

            # Explainability
            "explanation":       decision.explanation,
            "evidence":          decision.evidence,
            "why_not_normal":    decision.why_not_normal,
            "feature_importance":decision.feature_importance,

            # Response
            "recommended_actions": decision.recommended_actions,

            # Attack chain
            "attack_chain":      decision.attack_chain,

            # Model outputs (for dashboard)
            "model_votes":       decision.model_votes,

            # Features (for dashboard panel)
            "features": {
                "cpu":          round(feature_dict.get("cpu_percent", 0), 1),
                "memory":       round(feature_dict.get("memory_percent", 0), 1),
                "disk_write":   round(feature_dict.get("disk_write_mb", 0), 1),
                "net_sent":     round(feature_dict.get("net_sent_mb", 0), 1),
                "failed_logins":int(feature_dict.get("failed_logins", 0)),
                "cpu_zscore":   round(feature_dict.get("cpu_zscore", 0), 2),
                "net_zscore":   round(feature_dict.get("net_zscore", 0), 2),
                "malware_procs":int(feature_dict.get("malware_process_count", 0)),
                "unknown_users":int(feature_dict.get("unknown_user_count", 0)),
                "off_hours":    bool(feature_dict.get("is_off_hours", 0)),
            },

            # Context
            "context": {
                "hour":          context.get("hour"),
                "is_off_hours":  context.get("is_off_hours"),
                "has_baseline":  context.get("has_baseline"),
                "baseline_cpu":  context.get("baseline_cpu"),
                "malware_procs": context.get("malware_processes", []),
                "unknown_users": context.get("unknown_users", []),
            },

            # Meta
            "processing_ms":     elapsed_ms,
            "timestamp":         datetime.utcnow().isoformat() + "Z",
            "total_processed":   self._total_processed,
        }

        return result

    def feedback(self, hostname, prediction_id, was_correct, actual_label=None):
        """
        Analyst feedback loop.
        Called when admin confirms/denies an AI decision.
        Updates model confidence and queues retraining.
        """
        self._feedback_buffer.append({
            "hostname":    hostname,
            "correct":     was_correct,
            "label":       actual_label,
            "timestamp":   datetime.utcnow().isoformat() + "Z",
        })
        if was_correct:
            self._correct_predictions += 1

        # Trigger retraining when enough feedback collected
        if len(self._feedback_buffer) >= 20:
            self._retrain()

        accuracy = round(self._correct_predictions / max(self._total_processed, 1) * 100, 1)
        return {"feedback_recorded": True, "running_accuracy": accuracy}

    def _retrain(self):
        """Simulate incremental retraining with analyst feedback."""
        print(f"[AIBrain] Retraining on {len(self._feedback_buffer)} feedback samples...")
        self._feedback_buffer.clear()

    def stats(self):
        accuracy = round(self._correct_predictions / max(self._total_processed, 1) * 100, 1)
        return {
            **registry.stats(),
            "total_processed":    self._total_processed,
            "running_accuracy":   accuracy,
            "feedback_buffer":    len(self._feedback_buffer),
            "feature_names":      list(registry.classifier.get_feature_importance()),
        }


# Singleton
brain = AIBrain()
