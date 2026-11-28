import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    elasticsearch_url: str = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch:9200")
    elastic_password: str = os.getenv("ELASTIC_PASSWORD", "")
    kibana_url: str = os.getenv("KIBANA_URL", "http://localhost:5601")
    pi_host: str = os.getenv("PI_HOST", "")
    pi_user: str = os.getenv("PI_USER", "trapsig")
    pi_ssh_key: str = os.getenv("PI_SSH_KEY", "/home/trapsig/.ssh/pi_ssh_key")
    pi_known_hosts: str = os.getenv("PI_KNOWN_HOSTS", "/home/trapsig/.ssh/known_hosts")
    lab_subnet: str = os.getenv("LAB_SUBNET", "192.168.50.0/24")
    session_timeout_seconds: int = int(os.getenv("SESSION_TIMEOUT_SECONDS", "300"))
    # Detection firing is decided by the learned policy (see services/ml), not by
    # fixed thresholds; the old brute_force/web_enumeration/multi_service knobs
    # were removed with the rule engine. Posture-based per-IP sensitivity tuning
    # is driven by the RL hardening agent (services/hardening.py).
    processing_interval_seconds: int = int(os.getenv("PROCESSING_INTERVAL_SECONDS", "10"))
    # Single-writer safety: only the elected leader materializes derived data, so
    # multiple backend replicas never double-write. Set PROCESSOR_ENABLED=false on
    # a replica to keep it purely an API server.
    processor_enabled: bool = os.getenv("PROCESSOR_ENABLED", "true").lower() not in {"0", "false", "no"}
    processor_leader_election: bool = os.getenv("PROCESSOR_LEADER_ELECTION", "true").lower() not in {"0", "false", "no"}
    processor_lock_ttl_seconds: int = int(os.getenv("PROCESSOR_LOCK_TTL_SECONDS", "30"))
    posture_elevated_threshold_scale: float = float(os.getenv("POSTURE_ELEVATED_THRESHOLD_SCALE", "0.7"))
    posture_locked_threshold_scale: float = float(os.getenv("POSTURE_LOCKED_THRESHOLD_SCALE", "0.4"))
    processing_event_limit: int = int(os.getenv("PROCESSING_EVENT_LIMIT", "10000"))
    # Incremental processing: new events are found by event.ingested after a
    # persisted watermark; only their sources are re-sessionized.
    processing_backfill_seconds: int = int(os.getenv("PROCESSING_BACKFILL_SECONDS", str(7 * 86400)))
    # 0: an experiment finish() runs process_once right after its events are
    # searchable, so nothing may be held back; the re-read overlap covers events
    # that become searchable after their ingest stamp (writes are idempotent).
    processing_ingest_lag_seconds: int = int(os.getenv("PROCESSING_INGEST_LAG_SECONDS", "0"))
    processing_overlap_seconds: int = int(os.getenv("PROCESSING_OVERLAP_SECONDS", "30"))
    processing_batch_events: int = int(os.getenv("PROCESSING_BATCH_EVENTS", "20000"))
    cors_origins: str = os.getenv("CORS_ORIGINS", "http://localhost:3000")
    # Optional shared-secret API auth. When API_KEY is set, every request must send
    # it in the X-API-Key header (health check and OpenAPI docs are exempt). Unset
    # (the default) keeps the API open for the isolated lab. TLS is expected to be
    # terminated by a reverse proxy in front of the backend; see docs/guides/SETUP.md.
    api_key: str = os.getenv("API_KEY", "")
    scenario_dir: str = os.getenv(
        "SCENARIO_DIR",
        str(Path(__file__).resolve().parents[2] / "attacks" / "scenarios"),
    )
    experiment_settle_timeout_seconds: float = float(os.getenv("EXPERIMENT_SETTLE_TIMEOUT_SECONDS", "25"))
    experiment_settle_quiet_seconds: float = float(os.getenv("EXPERIMENT_SETTLE_QUIET_SECONDS", "3"))
    experiment_settle_poll_seconds: float = float(os.getenv("EXPERIMENT_SETTLE_POLL_SECONDS", "1"))
    # A run is bounded (<= 120 s per step, 25 s settle); one still "running" or
    # "correlating" after this long was orphaned by a crash and must not block the lab.
    experiment_stale_seconds: int = int(os.getenv("EXPERIMENT_STALE_SECONDS", "1800"))
    trapsig_revision: str | None = os.getenv("TRAPSIG_REVISION") or None
    evaluation_step_time_tolerance_seconds: float = float(os.getenv("EVALUATION_STEP_TIME_TOLERANCE_SECONDS", "2"))


@lru_cache
def get_settings() -> Settings:
    return Settings()
