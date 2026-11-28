// Shared presentational primitives for the research console. Server-safe.

export function PageHeader({ eyebrow, title, lede, children }: { eyebrow: string; title: string; lede: string; children?: React.ReactNode }) {
  return (
    <header className="page-header">
      <p className="eyebrow">{eyebrow}</p>
      <div className="page-title-row"><h2>{title}</h2>{children}</div>
      <p className="lede">{lede}</p>
    </header>
  );
}

export function Stat({ label, value, hint, tone }: { label: string; value: React.ReactNode; hint?: string; tone?: "ok" | "warn" | "danger" }) {
  return (
    <div className={`stat ${tone ?? ""}`}>
      <small>{label}</small>
      <strong>{value}</strong>
      {hint && <span>{hint}</span>}
    </div>
  );
}

export function StatRow({ children }: { children: React.ReactNode }) {
  return <div className="stat-row">{children}</div>;
}

const TONES: Record<string, "ok" | "warn" | "danger" | "neutral"> = {
  online: "ok", healthy: "ok", running: "ok", green: "ok", enabled: "ok", in_sync: "ok", passed: "ok",
  degraded: "warn", yellow: "warn", elevated: "warn", disabled: "neutral", normal: "neutral",
  offline: "danger", red: "danger", locked: "danger", unreachable: "danger", failed: "danger", drift: "warn",
};

export function Status({ value }: { value: string | null | undefined }) {
  const key = String(value ?? "unknown").toLowerCase();
  return <span className={`status ${TONES[key] ?? "neutral"}`}><i aria-hidden="true" />{key}</span>;
}

export function Card({ title, children, action, wide }: { title: string; children: React.ReactNode; action?: React.ReactNode; wide?: boolean }) {
  return (
    <section className={`card ${wide ? "wide" : ""}`}>
      <header><h3>{title}</h3>{action}</header>
      <div className="card-body">{children}</div>
    </section>
  );
}

export function Empty({ children }: { children: React.ReactNode }) {
  return <div className="empty-state">{children}</div>;
}

export function ErrorNote({ error }: { error: string | null }) {
  return error ? <div className="inline-alert danger" role="alert">{error}</div> : null;
}

export function Table({ head, rows, empty }: { head: string[]; rows: React.ReactNode[][]; empty: React.ReactNode }) {
  if (!rows.length) return <Empty>{empty}</Empty>;
  return (
    <div className="table-scroll">
      <table className="data-table">
        <thead><tr>{head.map((cell) => <th key={cell} scope="col">{cell}</th>)}</tr></thead>
        <tbody>{rows.map((row, index) => <tr key={index}>{row.map((cell, column) => <td key={column}>{cell}</td>)}</tr>)}</tbody>
      </table>
    </div>
  );
}

export function Chips({ items }: { items: string[] }) {
  return <span className="chips">{items.map((item) => <code key={item}>{item}</code>)}</span>;
}

/** Proportion bar with an optional confidence interval overlay. */
export function RateBar({ value, interval }: { value: number | null | undefined; interval?: [number, number] | null }) {
  if (typeof value !== "number") return <span className="muted">—</span>;
  return (
    <span className="rate-bar" title={interval ? `95% CI ${(interval[0] * 100).toFixed(0)}–${(interval[1] * 100).toFixed(0)}%` : undefined}>
      <span className="rate-track">
        {interval && <span className="rate-ci" style={{ left: `${interval[0] * 100}%`, width: `${(interval[1] - interval[0]) * 100}%` }} />}
        <span className="rate-mark" style={{ left: `${value * 100}%` }} />
      </span>
      <b>{(value * 100).toFixed(0)}%</b>
    </span>
  );
}
