import { HorizontalBars } from "@/components/soc-charts";
import { Card, Chips, Empty, ErrorNote, PageHeader } from "@/components/ui";
import { displayValue, load, num } from "@/lib/api";
import type { AttackRef, Signal } from "@/lib/platform";
import type { AnalyticsOverview } from "@/lib/types";

export const dynamic = "force-dynamic";

const colors = { critical: "#ef5362", high: "#dc6671", medium: "#d7a548", low: "#4b9bd5" };

type Detection = {
  detection_id: string;
  timestamp?: string;
  severity?: string;
  type?: string;
  source_ip?: string;
  session_id?: string;
  reason?: string;
  confidence?: number;
  fired_by?: string[];
  attack?: AttackRef[];
  signals?: Signal[];
  evidence_event_ids?: string[];
};

function SignalDetail({ signal }: { signal: Signal }) {
  return (
    <div className="signal">
      <header>
        <b>{signal.engine === "rule" ? signal.rule_title : signal.engine === "ml" ? "Learned policy" : "Anomaly engine"}</b>
        <span className="muted mono">{signal.engine === "rule" ? signal.rule_name : signal.version}</span>
        <span>confidence {num(signal.confidence, 2)}{signal.engine !== "rule" ? " (uncalibrated)" : " (author prior)"}</span>
      </header>
      <p>{signal.reason}</p>
      {signal.features && signal.features.length > 0 && (
        <table className="data-table compact">
          <thead><tr><th>Feature</th><th>Observed</th><th>{signal.engine === "ml" ? "Contribution (w·x)" : "Attribution share"}</th></tr></thead>
          <tbody>{signal.features.map((f) => <tr key={f.feature}><td>{f.description}</td><td className="mono">{num(f.value, 2)}</td><td className="mono">{signal.engine === "ml" ? num(f.contribution, 3) : num(f.attribution_share, 2)}</td></tr>)}</tbody>
        </table>
      )}
      <small className="muted">{signal.evidence_event_ids.length} evidence event(s)</small>
    </div>
  );
}

export default async function Page() {
  const [detections, analytics] = await Promise.all([load<Detection[]>("/detections"), load<AnalyticsOverview>("/analytics/overview?minutes=1440")]);
  return (
    <>
      <PageHeader eyebrow="Intelligence · last 24 hours" title="DETECTIONS" lede="Each detection lists every engine that fired, why, the exact evidence events, and the ATT&CK techniques it maps to." />
      <ErrorNote error={detections.error || analytics.error} />
      <div className="grid-2">
        <Card title="Severity (24 h)"><HorizontalBars data={analytics.data?.detection_severity || []} colors={colors} /></Card>
        <Card title="Detection types (24 h)"><HorizontalBars data={analytics.data?.detection_types || []} /></Card>
      </div>
      {detections.data?.length ? (
        <div className="detection-list">
          {detections.data.map((item) => (
            <details key={item.detection_id} className="detection-item">
              <summary>
                <span className={`severity-text ${item.severity}`}>{displayValue(item.severity)}</span>
                <code>{item.type}</code>
                <span className="mono">{item.source_ip}</span>
                <span className="engines">{(item.fired_by ?? ["ml"]).map((e) => <span key={e} className={`engine ${e}`}>{e}</span>)}</span>
                <Chips items={(item.attack ?? []).map((a) => a.id)} />
                <span className="muted">{item.timestamp ? new Date(item.timestamp).toLocaleString() : "—"}</span>
                <span className="reason">{item.reason}</span>
              </summary>
              <div className="detection-body">
                <div className="detail-grid">
                  <div><small>DETECTION</small><strong className="mono">{item.detection_id}</strong></div>
                  <div><small>SESSION</small><strong className="mono">{item.session_id}</strong></div>
                  <div><small>EVIDENCE EVENTS</small><strong className="mono">{(item.evidence_event_ids ?? []).slice(0, 12).join(" ") || "—"}{(item.evidence_event_ids?.length ?? 0) > 12 ? " …" : ""}</strong></div>
                </div>
                {(item.attack ?? []).length > 0 && (
                  <p className="muted">ATT&amp;CK: {(item.attack ?? []).map((a) => `${a.id} ${a.name ?? "(unknown id)"} [${a.mapping}]`).join(" · ")}</p>
                )}
                {(item.signals ?? []).map((signal, index) => <SignalDetail key={index} signal={signal} />)}
                {!item.signals && <p className="muted">Materialized before multi-engine signals existed; reason above is the learned policy&apos;s.</p>}
              </div>
            </details>
          ))}
        </div>
      ) : (
        !detections.error && <Empty>No detections yet. Run a controlled scenario from the Experiments page to generate evidence.</Empty>
      )}
    </>
  );
}
