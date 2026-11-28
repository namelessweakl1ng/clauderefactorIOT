import Link from "next/link";

import { Chips, Empty, ErrorNote, PageHeader } from "@/components/ui";
import { load } from "@/lib/api";

export const dynamic = "force-dynamic";

type Event = {
  _id?: string;
  "@timestamp"?: string;
  event?: { action?: string; category?: string; outcome?: string };
  source?: { ip?: string };
  destination?: { port?: number };
  service?: { name?: string };
  network?: { protocol?: string; transport?: string };
  persona?: { id?: string };
  hardening?: { actions?: string[]; decision_id?: string };
};

type Session = {
  session_id: string;
  source_ip: string;
  start_time: string;
  end_time: string;
  duration?: number;
  event_count?: number;
  services_touched?: string[];
  personas?: string[];
  failed_authentication_attempts?: number;
  commands?: string[];
  urls?: string[];
};

const WINDOWS = [[60, "1h"], [1440, "24h"], [10080, "7d"]] as const;
const FILTERS = ["source_ip", "protocol", "category", "outcome"] as const;

function time(value?: string) {
  return value ? new Date(value).toLocaleString([], { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "—";
}

function summaryOf(e: Event & Record<string, unknown>) {
  for (const key of ["url", "process", "mqtt", "modbus", "coap", "rtsp", "ftp", "dns", "ssdp", "authentication"]) {
    const value = e[key] as Record<string, unknown> | undefined;
    if (!value) continue;
    const detail = value.path ?? value.command_line ?? value.topic ?? value.function ?? value.uri_path ?? value.uri ?? value.command ?? value.qname ?? value.st ?? value.username;
    if (detail) return `${key}: ${String(detail)}`;
  }
  return "";
}

export default async function Page({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const params = await searchParams;
  const view = params.view === "sessions" ? "sessions" : "events";
  const minutes = WINDOWS.some(([value]) => String(value) === params.minutes) ? Number(params.minutes) : 1440;
  const query = new URLSearchParams({ minutes: String(minutes), size: "200" });
  for (const key of FILTERS) if (params[key]) query.set(key, params[key]!);
  const [events, sessions] = await Promise.all([
    view === "events" ? load<Event[]>(`/events?${query}`) : Promise.resolve({ data: null, error: null }),
    view === "sessions" ? load<Session[]>("/sessions") : Promise.resolve({ data: null, error: null }),
  ]);
  const tab = (name: string, label: string) => <Link className={view === name ? "active" : ""} href={`/events?view=${name}`}>{label}</Link>;
  const filteredSessions = (sessions.data ?? []).filter((s) => !params.source_ip || s.source_ip === params.source_ip);
  return (
    <>
      <PageHeader eyebrow="Operations · evidence" title="INVESTIGATE" lede="Raw, immutable telemetry and the attacker sessions reconstructed from it. Expand any row for the full normalized record.">
        <div className="segmented">{tab("events", "Events")}{tab("sessions", "Sessions")}</div>
      </PageHeader>
      <form className="inline-form filter-bar">
        <input type="hidden" name="view" value={view} />
        <label>Window<select name="minutes" defaultValue={String(minutes)}>{WINDOWS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
        <label>Source IP<input name="source_ip" defaultValue={params.source_ip} placeholder="192.168.50.20" /></label>
        {view === "events" && (
          <>
            <label>Protocol<input name="protocol" defaultValue={params.protocol} placeholder="modbus" /></label>
            <label>Category<input name="category" defaultValue={params.category} placeholder="authentication" /></label>
            <label>Outcome<input name="outcome" defaultValue={params.outcome} placeholder="success" /></label>
          </>
        )}
        <button type="submit">Apply</button>
      </form>
      <ErrorNote error={events.error || sessions.error} />

      {view === "events" &&
        (events.data?.length ? (
          <div className="detection-list">
            {events.data.map((e, index) => (
              <details key={e._id ?? index} className="detection-item">
                <summary>
                  <span className="mono">{time(e["@timestamp"])}</span>
                  <Link className="mono" href={`/events?source_ip=${e.source?.ip}`}>{e.source?.ip}</Link>
                  <span>{e.persona?.id ?? e.service?.name}</span>
                  <code>{e.network?.protocol}{e.destination?.port ? `:${e.destination.port}` : ""}</code>
                  <span>{e.event?.action}</span>
                  <span className={`outcome ${e.event?.outcome ?? ""}`}>{e.event?.outcome}</span>
                  {e.hardening?.actions?.length ? <Chips items={e.hardening.actions.map((a) => `hardened: ${a}`)} /> : null}
                  <span className="reason">{summaryOf(e as Event & Record<string, unknown>)}</span>
                </summary>
                <pre className="json">{JSON.stringify(e, null, 2)}</pre>
              </details>
            ))}
          </div>
        ) : (
          !events.error && <Empty>No events in this window. Widen the window or run a scenario.</Empty>
        ))}

      {view === "sessions" &&
        (filteredSessions.length ? (
          <div className="detection-list">
            {filteredSessions.map((s) => (
              <details key={s.session_id} className="detection-item">
                <summary>
                  <Link className="mono" href={`/events?source_ip=${s.source_ip}`}>{s.source_ip}</Link>
                  <span className="mono">{time(s.start_time)} → {time(s.end_time)}</span>
                  <span>{s.event_count ?? 0} events</span>
                  <Chips items={s.personas?.length ? s.personas : s.services_touched ?? []} />
                  {(s.failed_authentication_attempts ?? 0) > 0 && <span className="outcome failure">{s.failed_authentication_attempts} failed logins</span>}
                </summary>
                <div className="detail-grid">
                  <div><small>SESSION</small><strong>{s.session_id}</strong></div>
                  <div><small>SERVICES</small><strong>{(s.services_touched ?? []).join(", ") || "—"}</strong></div>
                  <div><small>COMMANDS</small><strong>{(s.commands ?? []).slice(0, 10).join(" · ") || "—"}</strong></div>
                  <div><small>PATHS</small><strong>{(s.urls ?? []).slice(0, 10).join(" · ") || "—"}</strong></div>
                </div>
              </details>
            ))}
          </div>
        ) : (
          !sessions.error && <Empty>No sessions reconstructed yet.</Empty>
        ))}
    </>
  );
}
