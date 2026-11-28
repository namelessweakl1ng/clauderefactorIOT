import Link from "next/link";

import { HorizontalBars, Timeline } from "@/components/soc-charts";
import { Card, Chips, Empty, ErrorNote, PageHeader, Stat, StatRow, Table } from "@/components/ui";
import { ago, load, pct } from "@/lib/api";
import type { Sensor } from "@/lib/platform";
import type { AnalyticsOverview } from "@/lib/types";

export const dynamic = "force-dynamic";

const RANGES = [[60, "1h"], [1440, "24h"], [10080, "7d"], [43200, "30d"]] as const;
const SEVERITY = { critical: "#ef5362", high: "#dc6671", medium: "#d7a548", low: "#4b9bd5" };

type Detection = { detection_id?: string; timestamp?: string; severity?: string; type?: string; source_ip?: string; reason?: string; fired_by?: string[] };
type Agent = { config: { mode: string }; evaluated_decisions: number; harm_rate: number | null; mean_reward: number | null };
type Decision = { decision_id: string; decided_at: string; source_ip: string; context: string; previous_action: string; enforced_action: string; reason: string };

export default async function Overview({ searchParams }: { searchParams: Promise<{ minutes?: string }> }) {
  const requested = Number((await searchParams).minutes || 1440);
  const minutes = RANGES.some(([value]) => value === requested) ? requested : 1440;
  const [analytics, sensors, agent, decisions, hardened] = await Promise.all([
    load<AnalyticsOverview>(`/analytics/overview?minutes=${minutes}`),
    load<Sensor[]>("/sensors"),
    load<Agent>("/adaptation/agent"),
    load<Decision[]>("/adaptation/decisions?limit=6"),
    load<{ source_ip: string; actions: string[] }[]>("/adaptation/posture"),
  ]);
  const a = analytics.data;
  const fleet = sensors.data ?? [];
  const online = fleet.filter((s) => s.status === "online").length;
  return (
    <>
      <PageHeader eyebrow="Operations" title="OVERVIEW" lede="What the decoys saw, what was detected, and how the adaptive defence responded.">
        <div className="segmented">{RANGES.map(([value, label]) => <Link key={value} className={value === minutes ? "active" : ""} href={`/?minutes=${value}`}>{label}</Link>)}</div>
      </PageHeader>
      <ErrorNote error={analytics.error} />
      <StatRow>
        <Stat label="Events" value={a?.totals.events ?? "—"} />
        <Stat label="Attack sessions" value={a?.totals.sessions ?? "—"} />
        <Stat label="Detections" value={a?.totals.detections ?? "—"} />
        <Stat label="Unique sources" value={a?.totals.unique_sources ?? "—"} />
        <Stat label="Sources hardened now" value={(hardened.data ?? []).filter((p) => p.actions?.length).length} hint={agent.data ? `agent ${agent.data.config.mode}` : undefined} />
        <Stat label="Attacker success under agent" value={pct(agent.data?.harm_rate)} hint={`${agent.data?.evaluated_decisions ?? 0} evaluated decisions`} />
        <Stat label="Sensors online" value={`${online} / ${fleet.length}`} tone={fleet.length && online < fleet.length ? "warn" : undefined} />
      </StatRow>

      <Card title="Activity over time" wide><Timeline data={a?.events_over_time ?? []} /></Card>
      <div className="grid-2">
        <Card title="Protocols"><HorizontalBars data={a?.protocols ?? []} /></Card>
        <Card title="Top sources"><HorizontalBars data={a?.top_sources ?? []} /></Card>
        <Card title="Detection types"><HorizontalBars data={a?.detection_types ?? []} /></Card>
        <Card title="Detection severity"><HorizontalBars data={a?.detection_severity ?? []} colors={SEVERITY} /></Card>
      </div>

      <div className="grid-2">
        <Card title="Recent detections" action={<Link href="/detections">All →</Link>}>
          <Table
            head={["When", "Severity", "Type", "Source", "Engines"]}
            empty="No detections in this window."
            rows={((a?.recent_detections ?? []) as Detection[]).slice(0, 8).map((d) => [
              ago(d.timestamp),
              <span key="s" className={`severity-text ${d.severity}`}>{d.severity}</span>,
              <code key="t">{d.type}</code>,
              <span key="ip" className="mono">{d.source_ip}</span>,
              (d.fired_by ?? []).join(" + ") || "ml",
            ])}
          />
        </Card>
        <Card title="Recent hardening changes" action={<Link href="/adaptation">Why →</Link>}>
          {(decisions.data ?? []).length ? (
            <Table
              head={["When", "Source", "Stage", "Change"]}
              empty=""
              rows={(decisions.data ?? []).map((d) => [ago(d.decided_at), <span key="s" className="mono">{d.source_ip}</span>, <code key="c">{d.context}</code>, `${d.previous_action} → ${d.enforced_action}`])}
            />
          ) : (
            <Empty>The agent has not acted yet.</Empty>
          )}
        </Card>
      </div>

      <Card title="Sensor fleet" action={<Link href="/honeypots">Manage →</Link>} wide>
        <Table
          head={["Sensor", "Status", "Personas", "Services listening", "Last heartbeat"]}
          empty="No sensor heartbeats yet. Set BACKEND_URL (and SENSOR_API_KEY) in sensor/.env."
          rows={fleet.map((s) => [
            <span key="s" className="mono">{s.sensor_id}</span>,
            s.status,
            <Chips key="p" items={s.instances.map((i) => i.persona_id)} />,
            `${s.services_listening} / ${s.services_total}`,
            ago(s.last_seen),
          ])}
        />
      </Card>
    </>
  );
}
