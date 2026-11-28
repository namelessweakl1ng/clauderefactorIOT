"use client";

import { useEffect, useMemo, useRef, useState } from "react";

type Telemetry = {
  _id: string;
  "@timestamp"?: string;
  event?: { id?: string; action?: string; category?: string; outcome?: string; ingested?: string };
  source?: { ip?: string; port?: number };
  destination?: { port?: number };
  service?: { name?: string };
  network?: { protocol?: string; transport?: string };
  persona?: { id?: string };
};

type LiveDetection = { detection_id: string; type: string; severity: string; confidence: number; source_ip: string; reason: string; fired_by?: string[]; attack?: { id: string }[]; detected_at: string };

const MAX_EVENTS = 250;
const MAX_DETECTIONS = 60;

function time(value?: string) {
  return value ? new Date(value).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "—";
}

export function LiveStream() {
  const [events, setEvents] = useState<Telemetry[]>([]);
  const [detections, setDetections] = useState<LiveDetection[]>([]);
  const [state, setState] = useState<"connecting" | "live" | "reconnecting">("connecting");
  const [paused, setPaused] = useState(false);
  const pausedRef = useRef(paused);
  useEffect(() => {
    pausedRef.current = paused;
  }, [paused]);

  useEffect(() => {
    const source = new EventSource("/api/stream/events?lookback_seconds=300");
    source.onopen = () => setState("live");
    source.onerror = () => setState("reconnecting");
    source.addEventListener("telemetry", (message) => {
      if (pausedRef.current) return;
      const item = JSON.parse((message as MessageEvent).data) as Telemetry;
      setEvents((current) => [item, ...current].slice(0, MAX_EVENTS));
    });
    source.addEventListener("detection", (message) => {
      const item = JSON.parse((message as MessageEvent).data) as LiveDetection;
      setDetections((current) => [item, ...current.filter((d) => d.detection_id !== item.detection_id)].slice(0, MAX_DETECTIONS));
    });
    return () => source.close();
  }, []);

  const protocols = useMemo(() => {
    const counts = new Map<string, number>();
    for (const item of events) {
      const key = `${item.network?.protocol ?? "?"}/${item.network?.transport ?? "tcp"}`;
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    return [...counts.entries()].sort((a, b) => b[1] - a[1]);
  }, [events]);

  const sources = useMemo(() => {
    const counts = new Map<string, { count: number; services: Set<string> }>();
    for (const item of events) {
      const ip = item.source?.ip ?? "?";
      const entry = counts.get(ip) ?? { count: 0, services: new Set<string>() };
      entry.count += 1;
      if (item.service?.name) entry.services.add(item.service.name);
      counts.set(ip, entry);
    }
    return [...counts.entries()].sort((a, b) => b[1].count - a[1].count).slice(0, 8);
  }, [events]);

  const maxProtocol = protocols[0]?.[1] ?? 1;

  return (
    <div className="live-grid">
      <div className="live-toolbar">
        <span className={`status ${state === "live" ? "ok" : "warn"}`}><i aria-hidden="true" />{state === "live" ? "streaming" : state}</span>
        <span className="muted">{events.length} events buffered (last {MAX_EVENTS}) · loopback probes excluded · passwords masked</span>
        <button type="button" onClick={() => setPaused((value) => !value)} aria-pressed={paused}>{paused ? "Resume" : "Pause"}</button>
      </div>
      <section className="card wide">
        <header><h3>Event stream</h3></header>
        <div className="card-body">
          {events.length ? (
            <div className="table-scroll tall">
              <table className="data-table compact">
                <thead><tr><th>Time</th><th>Source</th><th>Service</th><th>Protocol</th><th>Persona</th><th>Action</th><th>Outcome</th></tr></thead>
                <tbody>
                  {events.map((item) => (
                    <tr key={item._id}>
                      <td className="mono">{time(item["@timestamp"])}</td>
                      <td className="mono">{item.source?.ip}</td>
                      <td>{item.service?.name}</td>
                      <td>{item.network?.protocol}{item.destination?.port ? `:${item.destination.port}` : ""}</td>
                      <td>{item.persona?.id ?? "legacy"}</td>
                      <td>{item.event?.action}</td>
                      <td className={`outcome ${item.event?.outcome ?? ""}`}>{item.event?.outcome}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty-state">Waiting for telemetry. Events appear here within a few seconds of ingestion; nothing has been ingested in the last five minutes.</div>
          )}
        </div>
      </section>
      <section className="card">
        <header><h3>Protocol mix (buffer)</h3></header>
        <div className="card-body">
          {protocols.length ? (
            <div className="bar-chart">{protocols.map(([name, count]) => <div className="bar-row" key={name}><span>{name}</span><div className="bar-track"><i style={{ width: `${(count / maxProtocol) * 100}%` }} /></div><b>{count}</b></div>)}</div>
          ) : <div className="empty-state">No events yet.</div>}
        </div>
      </section>
      <section className="card">
        <header><h3>Active sources (buffer)</h3></header>
        <div className="card-body">
          {sources.length ? (
            <table className="data-table compact"><thead><tr><th>Source</th><th>Events</th><th>Services</th></tr></thead>
              <tbody>{sources.map(([ip, entry]) => <tr key={ip}><td className="mono">{ip}</td><td>{entry.count}</td><td>{[...entry.services].join(", ")}</td></tr>)}</tbody></table>
          ) : <div className="empty-state">No active sources.</div>}
        </div>
      </section>
      <section className="card wide">
        <header><h3>New detections</h3></header>
        <div className="card-body">
          {detections.length ? (
            <table className="data-table compact">
              <thead><tr><th>Time</th><th>Severity</th><th>Type</th><th>Source</th><th>Engines</th><th>ATT&amp;CK</th><th>Reason</th></tr></thead>
              <tbody>{detections.map((d) => <tr key={d.detection_id}><td className="mono">{time(d.detected_at)}</td><td className={`severity-text ${d.severity}`}>{d.severity}</td><td>{d.type}</td><td className="mono">{d.source_ip}</td><td>{d.fired_by?.join(" + ")}</td><td className="mono">{d.attack?.map((a) => a.id).join(" ")}</td><td>{d.reason}</td></tr>)}</tbody>
            </table>
          ) : <div className="empty-state">No detections materialized during this view.</div>}
        </div>
      </section>
    </div>
  );
}
