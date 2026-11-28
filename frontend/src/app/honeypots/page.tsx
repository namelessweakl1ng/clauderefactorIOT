import { FleetEditor } from "@/components/fleet-editor";
import { HoneypotGrid } from "@/components/honeypot-grid";
import { PersonaToggle } from "@/components/lab-actions";
import { Card, Chips, ErrorNote, PageHeader, Stat, StatRow, Status, Table } from "@/components/ui";
import { ago, load } from "@/lib/api";
import type { FleetPersona, FleetSensor, PersonaSummary, Sensor } from "@/lib/platform";

export const dynamic = "force-dynamic";

type LegacyHoneypot = Parameters<typeof HoneypotGrid>[0]["initial"][number];
type Plugin = { name: string; protocol: string; transport: string; interaction: string; default_port: number; description: string };

function mib(bytes?: number | null) {
  return typeof bytes === "number" ? `${(bytes / 1048576).toFixed(0)} MiB` : "—";
}

export default async function Page() {
  const [devices, assignable, sensors, personas, plugins, legacy] = await Promise.all([
    load<FleetSensor[]>("/fleet"),
    load<FleetPersona[]>("/fleet/personas"),
    load<Sensor[]>("/sensors"),
    load<PersonaSummary[]>("/personas"),
    load<Plugin[]>("/personas/plugins"),
    load<LegacyHoneypot[]>("/honeypots"),
  ]);
  const fleet = sensors.data ?? [];
  const catalog = personas.data ?? [];
  const instances = fleet.flatMap((sensor) => sensor.instances.map((instance) => ({ sensor, instance })));
  return (
    <>
      <PageHeader eyebrow="Honeypot management" title="SENSORS & PERSONAS" lede="Central assignment of personas to devices, sensor health from authenticated heartbeats, the declarative device-persona catalogue, and where each persona is deployed and whether it runs the current definition." />
      <StatRow>
        <Stat label="Sensors online" value={`${fleet.filter((s) => s.status === "online").length} / ${fleet.length}`} tone={fleet.some((s) => s.status !== "online") ? "warn" : "ok"} />
        <Stat label="Services listening" value={`${fleet.reduce((n, s) => n + s.services_listening, 0)} / ${fleet.reduce((n, s) => n + s.services_total, 0)}`} />
        <Stat label="Personas" value={`${catalog.filter((p) => p.enabled).length} enabled / ${catalog.length}`} />
        <Stat label="Out of sync" value={catalog.reduce((n, p) => n + p.deployments.filter((d) => !d.in_sync).length, 0)} hint="restart persona container to deploy" />
      </StatRow>
      <Card title="Fleet: which device runs which personas" wide>
        <ErrorNote error={devices.error ?? assignable.error} />
        <p className="muted">Each physical device runs <code>sensor/honeypots/agent.py</code>, which polls its assignment from here, starts or stops personas without a restart, and ships events to Logstash. Personas on one device share its IP unless you give them a bind IP (an extra address/alias on that device). Port clashes on the same address are rejected.</p>
        {devices.data && assignable.data && <FleetEditor fleet={devices.data} catalogue={assignable.data} />}
      </Card>
      <Card title="Persona instances (from heartbeats)" wide>
        <ErrorNote error={sensors.error} />
        <Table
          head={["Sensor", "Persona", "Status", "Services", "Events / errors", "Memory", "Last heartbeat"]}
          empty="No heartbeats received. Persona containers send them when BACKEND_URL and SENSOR_API_KEY are set on the sensor; containers are listed in the section below."
          rows={instances.map(({ sensor, instance }) => [
            <span key="s"><b className="mono">{sensor.sensor_id}</b><br /><small className="muted">{sensor.hostname} {sensor.sensor_ip}</small></span>,
            <span key="p">{instance.persona_name ?? instance.persona_id}<br /><small className="muted mono">v{instance.persona_version} · {instance.persona_origin}</small></span>,
            <Status key="st" value={instance.status} />,
            <span key="sv" className="service-list">{instance.services.map((svc) => <span key={svc.name} className={svc.listening ? "svc up" : "svc down"} title={`${svc.plugin} ${svc.transport}/${svc.port} → ${svc.public_port}`}>{svc.protocol ?? svc.plugin}:{svc.public_port}</span>)}</span>,
            `${instance.services.reduce((n, s) => n + s.events, 0)} / ${instance.services.reduce((n, s) => n + s.errors, 0)}`,
            mib(instance.process.rss_bytes),
            ago(instance.received_at),
          ])}
        />
      </Card>
      <Card title="Persona catalogue" wide>
        <ErrorNote error={personas.error} />
        <Table
          head={["Enabled", "Device", "Type", "Services", "Version", "Deployments"]}
          empty="No personas found."
          rows={catalog.map((persona) => [
            <PersonaToggle key="t" id={persona.id} enabled={persona.enabled} />,
            <span key="d"><b>{persona.name}</b><br /><small className="muted">{persona.vendor} {persona.model} · fw {persona.firmware}</small><br /><small className="muted">{persona.description}</small></span>,
            <code key="ty">{persona.device_type}</code>,
            <Chips key="sv" items={persona.services.map((s) => `${s.protocol}/${s.transport}:${s.public_port}`)} />,
            <span key="v" className="mono">v{persona.version} ({persona.origin})<br /><small className="muted">{persona.content_sha256.slice(0, 12)}</small></span>,
            persona.deployments.length ? (
              <span key="dep">{persona.deployments.map((d) => <span key={d.sensor_id} className="dep-line"><Status value={d.in_sync ? "in_sync" : "drift"} /> {d.sensor_id}</span>)}</span>
            ) : <span key="dep" className="muted">not deployed</span>,
          ])}
        />
        <p className="muted">Editing: <code>PUT /personas/&lt;id&gt;</code> (admin) validates with the sensor&apos;s own validator and stores a new immutable version. Sensors with <code>PERSONA_FROM_BACKEND=true</code> load it on restart: <code>docker compose restart &lt;container&gt;</code> or the restart button below.</p>
      </Card>
      <Card title="Protocol plugins" wide>
        <ErrorNote error={plugins.error} />
        <Table
          head={["Plugin", "Protocol", "Transport", "Interaction", "Default port", "Behaviour"]}
          empty="No plugins registered."
          rows={(plugins.data ?? []).map((p) => [<code key="n">{p.name}</code>, p.protocol, p.transport, p.interaction, p.default_port, <small key="d" className="muted">{p.description}</small>])}
        />
      </Card>
      <Card title="Device containers (start / stop / restart over the SSH whitelist)" wide>
        <ErrorNote error={legacy.error} />
        {legacy.data && <HoneypotGrid initial={legacy.data} />}
      </Card>
    </>
  );
}
