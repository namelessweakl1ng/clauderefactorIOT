// Types for the v2 platform endpoints (mirrors the FastAPI responses).

export type AttackRef = { id: string; name: string | null; tactics: string[]; domain: string | null; known: boolean; mapping: string };

export type Signal = {
  engine: "rule" | "ml" | "anomaly";
  type: string;
  confidence: number;
  severity: string;
  reason: string;
  version: string;
  rule_name?: string;
  rule_title?: string;
  observed?: number | null;
  features?: { feature: string; value: number; contribution?: number; attribution_share?: number; description: string }[];
  evidence_event_ids: string[];
};

export type Rule = {
  name: string;
  id: string;
  title: string;
  version: number;
  status: string;
  level: string;
  kind: "event" | "correlation";
  description: string;
  detection_type: string | null;
  confidence: number;
  generate: boolean;
  tags: string[];
  attack_techniques: string[];
  falsepositives: string[];
  correlation: { type: string; rules: string[]; timespan_seconds: number | null; field?: string } | null;
  enabled: boolean;
  override: boolean;
  test_count: number;
};

export type Engines = {
  mode: string;
  detector_version: string;
  rules: { version: string; count: number; generating: number };
  ml: { policy_version: string; heads: string[]; feature_names: string[]; confidence_calibrated: boolean };
  anomaly: { model_version: string; threshold: number; trained_on: number; trees: number } | null;
};

export type Score = { tp: number; fp: number; fn: number; tn: number; precision: number | null; recall: number | null; f1: number | null; fpr: number | null; fnr: number | null; support: number };

export type EngineReport = {
  per_class: Record<string, Score>;
  macro_f1: number | null;
  macro_f1_fold_std: number | null;
  alert: Score;
  unexpected_detections_on_attacks: number;
  latency_ms: { p50: number | null; p95: number | null; n: number };
  model_bytes_mean?: number;
  train_seconds_mean?: number;
};

export type Comparison = {
  report_id: string;
  created_at: string;
  provenance: string[];
  synthetic_warning: boolean;
  sessions: number;
  attack_sessions: number;
  control_sessions: number;
  groups: number;
  folds: number;
  seed: number;
  classes: string[];
  ruleset_version: string;
  anomaly_fit_on: string[];
  leakage_check: { groups_spanning_folds: number; naive_split: { ml_trained_macro_f1_random_split: number | null; ml_trained_macro_f1_grouped: number | null; leakage_inflation: number | null } | null };
  engines: Record<string, EngineReport>;
  requested_by?: string;
};

export type Technique = { id: string; name: string; tactics: string[]; domain: string; rules: string[]; default_for_types: string[]; observed_detections: number };

export type ServiceHealth = { name: string; plugin: string; protocol?: string; transport: string; port: number; public_port: number; listening: boolean; events: number; errors: number; last_event_at: string | null };

export type SensorInstance = {
  instance_id: string;
  persona_id: string;
  persona_name?: string;
  persona_version?: number;
  persona_sha256?: string;
  persona_origin?: string;
  status: string;
  received_at: string;
  uptime_seconds?: number;
  services: ServiceHealth[];
  process: { rss_bytes?: number | null; threads?: number; loadavg?: number[] | null };
};

export type Sensor = { sensor_id: string; hostname?: string; sensor_ip?: string; status: string; last_seen: string | null; services_total: number; services_listening: number; events_total: number; instances: SensorInstance[] };

export type PersonaSummary = {
  id: string;
  name: string;
  device_type: string;
  vendor: string;
  model: string;
  firmware: string;
  description: string;
  enabled: boolean;
  version: number;
  credential_count: number;
  interaction: { max_messages: number; max_seconds: number };
  services: { name: string; plugin: string; protocol: string; transport: string; interaction: string; port: number; public_port: number; enabled: boolean }[];
  content_sha256: string;
  origin: string;
  stored_versions: number;
  deployments: { sensor_id: string; status: string; running_version?: number; in_sync: boolean; received_at: string }[];
};

export type ArmSummary = {
  experiments: number;
  counts: Record<string, number>;
  metrics: { precision: number | null; recall: number | null; f1: number | null; false_positive_rate: number | null };
  recall_ci95: [number, number] | null;
  false_positive_rate_ci95: [number, number] | null;
  detection_latency_median_seconds: number | null;
  scenarios: string[];
  detector_versions: string[];
};

export type ArmComparison = {
  labels: [string, string];
  arms: Record<string, ArmSummary>;
  delta: Record<string, number | null>;
  tests: { recall_fisher_p: number | null; false_positive_rate_fisher_p: number | null; alpha: number };
  shared_scenarios: string[];
  warnings: string[];
  conclusion: string;
};

export type NetworkSummary = {
  honeypot_events: number;
  events_with_community_id: number;
  events_matched: number;
  coverage: number | null;
  flows: number;
  flows_without_honeypot_event: number;
  window_minutes: number;
  sampled: boolean;
  network_only: { sources: { source_ip: string; flows: number; distinct_destination_ports: number; conn_states: Record<string, number>; scan_like_ratio: number; bytes: number; likely_port_scan: boolean }[]; likely_port_scanners: string[] };
};

export type FleetSlot = { persona_id: string; bind_ip?: string | null; enabled?: boolean; status: string; services_listening: number; services_total: number; events: number };
export type FleetSensor = {
  sensor_id: string;
  label?: string | null;
  os?: string | null;
  origin: string;
  version: number;
  hostname?: string | null;
  sensor_ip?: string | null;
  agent_version?: string | null;
  last_seen?: string | null;
  personas: FleetSlot[];
  running_but_unassigned: string[];
};
export type FleetPersona = { id: string; name: string; device_type: string; ports: string[] };
