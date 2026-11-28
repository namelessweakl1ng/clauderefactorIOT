"use client";

import { useRouter } from "next/navigation";
import { useMemo, useState } from "react";

import { ago, api, errorMessage } from "@/lib/api";
import type { FleetPersona, FleetSensor } from "@/lib/platform";

import { Status } from "./ui";

type Slot = { persona_id: string; bind_ip: string; enabled: boolean };

function SensorEditor({ sensor, catalogue, owner }: { sensor: FleetSensor; catalogue: FleetPersona[]; owner: Map<string, string> }) {
  const router = useRouter();
  const initial = useMemo(
    () => Object.fromEntries(sensor.personas.map((p) => [p.persona_id, { persona_id: p.persona_id, bind_ip: p.bind_ip ?? "", enabled: p.enabled !== false }])) as Record<string, Slot>,
    [sensor],
  );
  const [slots, setSlots] = useState<Record<string, Slot>>(initial);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const live = Object.fromEntries(sensor.personas.map((p) => [p.persona_id, p]));
  const dirty = JSON.stringify(slots) !== JSON.stringify(initial);

  function toggle(id: string) {
    setSaved(false);
    setSlots((current) => {
      const next = { ...current };
      if (next[id]) delete next[id];
      else next[id] = { persona_id: id, bind_ip: "", enabled: true };
      return next;
    });
  }

  async function save() {
    setBusy(true);
    setError(null);
    try {
      const personas = Object.values(slots).map((s) => ({ persona_id: s.persona_id, bind_ip: s.bind_ip.trim() || null, enabled: s.enabled }));
      await api(`/fleet/${encodeURIComponent(sensor.sensor_id)}`, { method: "PUT", body: JSON.stringify({ label: sensor.label, os: sensor.os, personas }) });
      setSaved(true);
      router.refresh();
    } catch (caught) {
      setError(errorMessage(caught, "Assignment rejected"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fleet-sensor">
      <header>
        <b className="mono">{sensor.sensor_id}</b> <small className="muted">{sensor.label ?? ""} {sensor.os ? `· ${sensor.os}` : ""}</small>
        <br />
        <small className="muted">
          {sensor.sensor_ip ? `${sensor.hostname ?? "?"} ${sensor.sensor_ip} · seen ${ago(sensor.last_seen)}` : "agent never connected"} · assignment v{sensor.version} ({sensor.origin})
        </small>
      </header>
      <ul className="fleet-list">
        {catalogue.map((persona) => {
          const slot = slots[persona.id];
          const elsewhere = owner.get(persona.id);
          const taken = elsewhere && elsewhere !== sensor.sensor_id;
          return (
            <li key={persona.id} className={slot ? "on" : ""}>
              <label title={persona.ports.join(", ")}>
                <input type="checkbox" checked={!!slot} onChange={() => toggle(persona.id)} />
                <span>
                  {persona.name} <small className="muted mono">{persona.ports.join(" ")}</small>
                  {taken && !slot && <small className="muted"> · on {elsewhere}</small>}
                </span>
              </label>
              {slot && (
                <span className="fleet-slot">
                  <input
                    aria-label={`Bind IP for ${persona.id}`}
                    placeholder="all addresses"
                    value={slot.bind_ip}
                    onChange={(e) => {
                      setSaved(false);
                      setSlots({ ...slots, [persona.id]: { ...slot, bind_ip: e.target.value } });
                    }}
                  />
                  {live[persona.id] && <Status value={live[persona.id].status} />}
                  {live[persona.id] && <small className="muted">{live[persona.id].services_listening}/{live[persona.id].services_total} listening · {live[persona.id].events} ev</small>}
                </span>
              )}
            </li>
          );
        })}
      </ul>
      {sensor.running_but_unassigned.length > 0 && <div className="inline-alert warn">Running but no longer assigned (stops on next agent poll): {sensor.running_but_unassigned.join(", ")}</div>}
      <div className="inline-form">
        <button type="button" disabled={busy || !dirty} onClick={save}>{busy ? "Validating…" : "Save assignment"}</button>
        {saved && !dirty && <small className="muted">Saved. The agent applies it within one poll interval.</small>}
        {error && <span className="field-error">{error}</span>}
      </div>
    </div>
  );
}

export function FleetEditor({ fleet, catalogue }: { fleet: FleetSensor[]; catalogue: FleetPersona[] }) {
  const owner = new Map<string, string>();
  for (const sensor of fleet) for (const p of sensor.personas) owner.set(p.persona_id, sensor.sensor_id);
  return <div className="fleet-grid">{fleet.map((sensor) => <SensorEditor key={sensor.sensor_id} sensor={sensor} catalogue={catalogue} owner={owner} />)}</div>;
}
