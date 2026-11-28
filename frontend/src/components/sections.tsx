// Self-loading server sections shared by pages (ATT&CK coverage, network intelligence).

import { Card, Empty, ErrorNote, Stat, StatRow, Status, Table } from "@/components/ui";
import { ago, load, num, pct } from "@/lib/api";
import type { NetworkSummary, Technique } from "@/lib/platform";

export async function AttackCoverage() {
  const coverage = await load<{ tactics: string[]; techniques: Technique[] }>("/detection/attack");
  const techniques = coverage.data?.techniques ?? [];
  const tactics = (coverage.data?.tactics ?? []).filter((tactic) => techniques.some((t) => t.tactics.includes(tactic)));
  const maxObserved = Math.max(1, ...techniques.map((t) => t.observed_detections));
  const covered = techniques.filter((t) => t.rules.length || t.default_for_types.length).length;
  const seen = techniques.filter((t) => t.observed_detections).length;
  return (
    <Card title={`ATT&CK coverage (${covered}/${techniques.length} techniques covered, ${seen} observed)`} wide>
      <ErrorNote error={coverage.error} />
      <div className="attack-matrix" style={{ gridTemplateColumns: `repeat(${Math.max(1, tactics.length)}, minmax(150px, 1fr))` }}>
        {tactics.map((tactic) => (
          <div key={tactic} className="tactic-column">
            <h4>{tactic.replaceAll("-", " ")}</h4>
            {techniques
              .filter((t) => t.tactics.includes(tactic))
              .map((t) => (
                <div
                  key={t.id}
                  className={`technique ${t.rules.length || t.default_for_types.length ? "covered" : "uncovered"}`}
                  style={{ "--intensity": t.observed_detections / maxObserved } as React.CSSProperties}
                  title={`rules: ${t.rules.join(", ") || "none"}; default for: ${t.default_for_types.join(", ") || "none"}`}
                >
                  <code>{t.id}</code>
                  <span>{t.name}</span>
                  <small>{t.domain} · {t.rules.length} rules · {t.observed_detections} seen</small>
                </div>
              ))}
          </div>
        ))}
      </div>
      <p className="muted">Shading = observed detections. Dashed = no detection logic maps to the technique (a coverage gap). Mappings are analyst assertions, not measurements.</p>
    </Card>
  );
}

export async function NetworkIntelligence() {
  const [status, summary] = await Promise.all([
    load<{ enabled: boolean; flows_indexed: number }>("/network/status"),
    load<NetworkSummary>("/network/summary?minutes=1440"),
  ]);
  if (status.data && !status.data.enabled) {
    return (
      <Card title="Network intelligence (Zeek)" wide>
        <Empty>Passive monitoring is off. On the Pi: <code>docker compose --profile netmon up -d zeek</code> (~150–250 MB RAM). Flows are then joined to honeypot events by Community ID.</Empty>
      </Card>
    );
  }
  const data = summary.data;
  return (
    <Card title="Network intelligence (Zeek, last 24 h)" wide>
      <ErrorNote error={status.error || summary.error} />
      {data && (
        <>
          <StatRow>
            <Stat label="Flows" value={data.flows} hint={data.sampled ? "sampled" : undefined} />
            <Stat label="Correlation coverage" value={pct(data.coverage)} hint="honeypot events whose flow Zeek saw" tone={data.coverage != null && data.coverage < 0.9 ? "warn" : "ok"} />
            <Stat label="Network-only flows" value={data.flows_without_honeypot_event} hint="never reached a decoy" />
            <Stat label="Likely port scanners" value={data.network_only.likely_port_scanners.length} tone={data.network_only.likely_port_scanners.length ? "warn" : undefined} />
          </StatRow>
          <Table
            head={["Source", "Flows", "Distinct ports", "Scan-like", "Assessment"]}
            empty="Every flow carried a honeypot interaction."
            rows={data.network_only.sources.slice(0, 15).map((s) => [
              <span key="s" className="mono">{s.source_ip}</span>,
              s.flows,
              s.distinct_destination_ports,
              pct(s.scan_like_ratio),
              s.likely_port_scan ? <b key="a" className="severity-text high">port scan</b> : "—",
            ])}
          />
        </>
      )}
    </Card>
  );
}

type Generation = { policy_version?: string; trained_at?: string; source?: string; active?: boolean; validation_macro_f1?: number | null; validation_ece?: number | null; training_example_count?: number; calibrated?: boolean };

export async function ModelHistory() {
  const generations = await load<Generation[]>("/detection/model-history");
  return (
    <Card title="ML detector generations" wide>
      <ErrorNote error={generations.error} />
      <Table
        head={["Version", "Trained", "Source", "Examples", "Held-out macro-F1", "ECE", "Calibrated", "Active"]}
        empty="Only the shipped bootstrap model is in use. Retrain with python -m backend.app.tools.train_detector."
        rows={(generations.data ?? []).slice(0, 10).map((g) => [
          <span key="v" className="mono">{g.policy_version}</span>,
          ago(g.trained_at),
          g.source ?? "—",
          g.training_example_count ?? "—",
          num(g.validation_macro_f1),
          num(g.validation_ece),
          g.calibrated ? "yes" : "no",
          <Status key="a" value={g.active ? "enabled" : "disabled"} />,
        ])}
      />
    </Card>
  );
}
