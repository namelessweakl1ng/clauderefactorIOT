"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { api, errorMessage, num, pct } from "@/lib/api";
import type { ArmComparison } from "@/lib/platform";

import { RateBar } from "./ui";

function useAction() {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function run(fn: () => Promise<unknown>, context: string) {
    setBusy(true);
    setError(null);
    try {
      await fn();
      router.refresh();
    } catch (caught) {
      setError(errorMessage(caught, context));
    } finally {
      setBusy(false);
    }
  }
  return { busy, error, run };
}

export function RuleToggle({ id, name, enabled }: { id: string; name: string; enabled: boolean }) {
  const { busy, error, run } = useAction();
  return (
    <span className="toggle-cell">
      <button
        type="button"
        className={`toggle ${enabled ? "on" : "off"}`}
        disabled={busy}
        aria-pressed={enabled}
        aria-label={`${enabled ? "Disable" : "Enable"} rule ${name}`}
        onClick={() => run(() => api(`/detection/rules/${id}/state`, { method: "POST", body: JSON.stringify({ enabled: !enabled, reason: "changed from console" }) }), "Rule change failed")}
      >
        {busy ? "…" : enabled ? "ON" : "OFF"}
      </button>
      {error && <small className="field-error">{error}</small>}
    </span>
  );
}

export function PersonaToggle({ id, enabled }: { id: string; enabled: boolean }) {
  const { busy, error, run } = useAction();
  return (
    <span className="toggle-cell">
      <button
        type="button"
        className={`toggle ${enabled ? "on" : "off"}`}
        disabled={busy}
        aria-pressed={enabled}
        aria-label={`${enabled ? "Disable" : "Enable"} persona ${id}`}
        onClick={() => run(() => api(`/personas/${id}/state`, { method: "POST", body: JSON.stringify({ enabled: !enabled }) }), "Persona change failed")}
      >
        {busy ? "…" : enabled ? "ENABLED" : "DISABLED"}
      </button>
      {error && <small className="field-error">{error}</small>}
    </span>
  );
}

export function ComparisonRunner() {
  const { busy, error, run } = useAction();
  const [source, setSource] = useState<"logged" | "synthetic">("logged");
  const [folds, setFolds] = useState(5);
  return (
    <form
      className="inline-form"
      onSubmit={(event) => {
        event.preventDefault();
        run(() => api("/detection/comparisons", { method: "POST", body: JSON.stringify({ source, folds }) }), "Comparison failed");
      }}
    >
      <label>
        Data
        <select value={source} onChange={(event) => setSource(event.target.value as "logged" | "synthetic")}>
          <option value="logged">Logged experiments</option>
          <option value="synthetic">Synthetic corpus (method check only)</option>
        </select>
      </label>
      <label>
        Folds
        <input type="number" min={2} max={10} value={folds} onChange={(event) => setFolds(Number(event.target.value))} />
      </label>
      <button type="submit" disabled={busy}>{busy ? "Running grouped CV…" : "Run comparison"}</button>
      {error && <span className="field-error">{error}</span>}
    </form>
  );
}

export function ArmCompare({ conditions }: { conditions: string[] }) {
  const [a, setA] = useState(conditions[0] ?? "");
  const [b, setB] = useState(conditions[1] ?? conditions[0] ?? "");
  const [result, setResult] = useState<ArmComparison | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function compare(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      setResult(await api<ArmComparison>(`/experiment-lab/compare?condition_a=${encodeURIComponent(a)}&condition_b=${encodeURIComponent(b)}`));
    } catch (caught) {
      setResult(null);
      setError(errorMessage(caught, "Comparison unavailable"));
    } finally {
      setBusy(false);
    }
  }
  return (
    <div>
      <form className="inline-form" onSubmit={compare}>
        <label>Baseline arm<select value={a} onChange={(event) => setA(event.target.value)}>{conditions.map((c) => <option key={c}>{c}</option>)}</select></label>
        <label>Treatment arm<select value={b} onChange={(event) => setB(event.target.value)}>{conditions.map((c) => <option key={c}>{c}</option>)}</select></label>
        <button type="submit" disabled={busy || !a || !b || a === b}>{busy ? "Comparing…" : "Compare"}</button>
        {error && <span className="field-error">{error}</span>}
      </form>
      {result && (
        <div className="arm-result">
          <p className="conclusion">{result.conclusion}</p>
          <div className="table-scroll">
            <table className="data-table">
              <thead><tr><th>Arm</th><th>Runs</th><th>TP / FN / FP / TN / Inconcl.</th><th>Recall (95% CI)</th><th>False-positive rate (95% CI)</th><th>Median detection latency</th></tr></thead>
              <tbody>
                {result.labels.map((label) => {
                  const arm = result.arms[label];
                  const c = arm.counts;
                  return (
                    <tr key={label}>
                      <td><b>{label}</b></td>
                      <td>{arm.experiments}</td>
                      <td className="mono">{c.TP} / {c.FN} / {c.FP} / {c.TN} / {c.INCONCLUSIVE}</td>
                      <td><RateBar value={arm.metrics.recall} interval={arm.recall_ci95} /></td>
                      <td><RateBar value={arm.metrics.false_positive_rate} interval={arm.false_positive_rate_ci95} /></td>
                      <td>{arm.detection_latency_median_seconds == null ? "—" : `${num(arm.detection_latency_median_seconds, 1)} s`}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <p className="muted">
            Δ recall {result.delta.recall == null ? "—" : pct(result.delta.recall, 1)} · Fisher p (recall) {num(result.tests.recall_fisher_p)} · Fisher p (FPR) {num(result.tests.false_positive_rate_fisher_p)} · shared scenarios: {result.shared_scenarios.join(", ") || "none"}
          </p>
          {result.warnings.map((warning) => <div key={warning} className="inline-alert warn">{warning}</div>)}
        </div>
      )}
    </div>
  );
}
