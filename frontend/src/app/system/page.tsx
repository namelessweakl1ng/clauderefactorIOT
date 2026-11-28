import { NetworkIntelligence } from "@/components/sections";
import { Card, ErrorNote, PageHeader, Stat, StatRow, Status, Table } from "@/components/ui";
import { ago, load, secondsSince } from "@/lib/api";
import type { Engines, Sensor } from "@/lib/platform";
import type { SystemStatus } from "@/lib/types";

export const dynamic = "force-dynamic";

type Processor = { last_run?: string | null; last_error?: string | null; sessions_written?: number; detections_written?: number; hardening_transitions?: number; is_leader?: boolean; leader_owner?: string | null };
type Status2 = SystemStatus & { counts?: SystemStatus["counts"] & { dead_letter?: number }; processor?: Processor };
type Audit = { audit_id: string; timestamp: string; principal: string | null; role: string | null; method: string; path: string; status: number; outcome: string; client_ip: string | null };

export default async function Page() {
  const [status, engines, sensors, network, audit] = await Promise.all([
    load<Status2>("/system/status"),
    load<Engines>("/detection/engines"),
    load<Sensor[]>("/sensors"),
    load<{ enabled: boolean; flows_indexed: number }>("/network/status"),
    load<Audit[]>("/audit?limit=50"),
  ]);
  const s = status.data ?? {};
  const counts = s.counts ?? {};
  const processor = s.processor ?? {};
  const staleSeconds = secondsSince(processor.last_run);
  return (
    <>
      <PageHeader eyebrow="Platform · observability" title="OBSERVABILITY" lede="Health of every pipeline stage: sensors → Filebeat → Logstash → Elasticsearch → processor → API. Prometheus metrics are at /metrics; this view is the operator summary." />
      <ErrorNote error={status.error} />
      <StatRow>
        <Stat label="Elasticsearch" value={<Status value={s.elasticsearch} />} />
        <Stat label="Processor" value={processor.last_error ? <Status value="failed" /> : <Status value={staleSeconds != null && staleSeconds < 120 ? "running" : "degraded"} />} hint={`last run ${ago(processor.last_run)}${processor.is_leader === false ? " · standby replica" : ""}`} />
        <Stat label="Dead letters" value={counts.dead_letter ?? 0} tone={(counts.dead_letter ?? 0) > 0 ? "warn" : "ok"} hint="records rejected by validation" />
        <Stat label="Sensors" value={`${(sensors.data ?? []).filter((x) => x.status === "online").length} / ${(sensors.data ?? []).length}`} hint="heartbeat-derived" />
        <Stat label="Network monitoring" value={network.data?.enabled ? "on" : "off"} hint={`${network.data?.flows_indexed ?? 0} flows`} />
      </StatRow>
      <div className="grid-2">
        <Card title="Data volumes">
          <Table head={["Index", "Documents"]} empty="" rows={[["events (raw, immutable)", counts.events ?? "—"], ["sessions", counts.sessions ?? "—"], ["detections", counts.detections ?? "—"], ["experiments", counts.experiments ?? "—"], ["dead letters", counts.dead_letter ?? 0]]} />
        </Card>
        <Card title="Processor cycle">
          <Table
            head={["Signal", "Value"]}
            empty=""
            rows={[
              ["Last run", ago(processor.last_run)],
              ["Last error", processor.last_error ? <span key="e" className="severity-text high">{processor.last_error}</span> : "none"],
              ["Sessions written (last cycle)", processor.sessions_written ?? "—"],
              ["Detections written (last cycle)", processor.detections_written ?? "—"],
              ["Posture transitions (last cycle)", processor.hardening_transitions ?? "—"],
              ["Writer", processor.leader_owner ?? (processor.is_leader ? "this replica" : "—")],
            ]}
          />
        </Card>
        <Card title="Detection engines">
          <ErrorNote error={engines.error} />
          {engines.data && (
            <Table
              head={["Engine", "Version"]}
              empty=""
              rows={[
                ["Mode", engines.data.mode],
                ["Rules", `${engines.data.rules.version} (${engines.data.rules.count})`],
                ["Learned policy", engines.data.ml.policy_version],
                ["Anomaly", engines.data.anomaly?.model_version ?? "not trained"],
              ]}
            />
          )}
        </Card>
        <Card title="Platform services">
          <Table
            head={["Service", "State"]}
            empty=""
            rows={[
              ["Backend API", <Status key="b" value={s.backend} />],
              ["Logstash", <Status key="l" value={s.logstash} />],
              ["Legacy Pi SSH control", <Status key="p" value={s.pi} />],
              ["Kibana", s.kibana_url ? <a key="k" href={s.kibana_url} target="_blank" rel="noreferrer">open ↗</a> : "not configured"],
            ]}
          />
        </Card>
      </div>
      <NetworkIntelligence />
      <Card title="Audit trail (admin)" wide>
        {audit.error ? (
          <p className="muted">Audit records are visible to the admin role only ({audit.error}).</p>
        ) : (
          <Table
            head={["Time", "Principal", "Role", "Request", "Status", "Outcome", "Client"]}
            empty="No audited actions yet. Every write and every denied request is recorded."
            rows={(audit.data ?? []).map((a) => [ago(a.timestamp), a.principal ?? "—", a.role ?? "—", <span key="r" className="mono">{a.method} {a.path}</span>, a.status, <Status key="o" value={a.outcome === "ok" ? "passed" : a.outcome === "forbidden" || a.outcome === "unauthenticated" ? "failed" : a.outcome} />, a.client_ip ?? "—"])}
          />
        )}
      </Card>
    </>
  );
}
