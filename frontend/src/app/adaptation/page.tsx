import { Card, Chips, Empty, ErrorNote, PageHeader, Stat, StatRow, Table } from "@/components/ui";
import { ago, load, pct } from "@/lib/api";

export const dynamic = "force-dynamic";

type Decision = {
  decision_id: string;
  source_ip: string;
  context: string;
  stage: string;
  returning: boolean;
  detection_types: string[];
  action: string;
  enforced_action: string;
  effects: string[];
  previous_action: string;
  changed: boolean;
  mode: string;
  chosen_by: "explore" | "exploit" | "safety";
  means: Record<string, number>;
  reason: string;
  decided_at: string;
  expires_at: string;
  status: "active" | "evaluated";
  outcome?: { reward: number; intel: number; new_behaviours: number; harm_events: number; events: number; explanation: string; credited_to: string };
};

type Agent = {
  config: { mode: string; allowed_actions: string[]; window_seconds: number; agent_version: string; discount: number; source_cap: number };
  contexts: string[];
  trained: { report_id: string; installed_at: string; gate_passed: boolean; forced: boolean; prior_cap: number } | null;
  actions: Record<string, string[]>;
  table: { context: string; action: string; expected_reward: number; outcomes: number; evidence: number; prior_evidence: number; mean_observed_reward: number | null }[];
  best_action_by_context: Record<string, string>;
  evaluated_decisions: number;
  mean_reward: number | null;
  harm_rate: number | null;
  learning_curve: { n: number; mean_reward: number }[];
};

type Posture = { source_ip: string; action: string; actions: string[]; level: string; decision_id: string | null; updated_at: string };
type Policy = { kind: string; state: string; reward: string; learning: string[]; safety: string[]; window_seconds: number };
type PolicyResult = {
  policy: string;
  decisions: number;
  mean_reward: number;
  mean_reward_ci95: [number, number];
  harm_rate: number;
  mean_intel: number;
  engagement: number;
  left_early_rate: number;
  mean_regret: number | null;
  safety_floor_breaches: number;
};
type Training = {
  origin: string | null;
  detail?: string;
  report_id?: string;
  generated_at?: string;
  outcome_table?: { generated_at: string; scenarios: number; repeats: number };
  split?: { train: string[]; held_out: string[] };
  attacker_model?: { archetypes: Record<string, { weight: number; patience: number; return_p: number; escalates: boolean }>; ot_share: number };
  training?: { episodes: number; decisions: number; curve: { decisions: number; mean_reward: number; harm_rate: number }[] };
  evaluation?: { episodes: number; on: string; policies: PolicyResult[] };
  learned_vs_rules?: { mean: number; ci95: [number, number]; episodes: number };
  gate?: { checks: Record<string, boolean>; passed: boolean };
};

const ACTIONS = ["observe", "tarpit", "deny_auth", "read_only", "quarantine"];

function reward(value: number | null | undefined) {
  if (typeof value !== "number") return "—";
  return `${value >= 0 ? "+" : ""}${value.toFixed(2)}`;
}

function TrainingReport({ report }: { report: Training }) {
  if (!report.origin || !report.evaluation) return <Empty>{report.detail ?? "No training report yet."}</Empty>;
  const gate = report.gate!;
  const diff = report.learned_vs_rules!;
  return (
    <>
      <p className="muted">
        {report.origin} · {report.report_id} · outcome table measured {report.outcome_table ? ago(report.outcome_table.generated_at) : "—"} over{" "}
        {report.outcome_table?.scenarios} attack scenarios × 5 actions on the real persona runtime. Trained on {report.split?.train.length} scenarios (
        {report.training?.decisions} decisions); evaluated on {report.evaluation.on} ({report.split?.held_out.length} attacks never seen in training),{" "}
        {report.evaluation.episodes} attacker episodes per policy on identical seeds.
      </p>
      <Table
        head={["Policy", "Mean reward (95% CI)", "Attacker success", "Intel", "Left early", "Regret", "Floor breaches"]}
        empty=""
        rows={report.evaluation.policies.map((r) => [
          <b key="p">{r.policy}</b>,
          <span key="r" className="mono">
            {reward(r.mean_reward)} <small className="muted">[{reward(r.mean_reward_ci95[0])}, {reward(r.mean_reward_ci95[1])}]</small>
          </span>,
          pct(r.harm_rate, 1),
          r.mean_intel.toFixed(2),
          pct(r.left_early_rate, 1),
          r.mean_regret == null ? "—" : r.mean_regret.toFixed(3),
          r.safety_floor_breaches,
        ])}
      />
      <p className={gate.passed ? "outcome-good" : "outcome-bad"}>
        Learned − expert rules: {reward(diff.mean)} per decision (paired 95% CI {reward(diff.ci95[0])} … {reward(diff.ci95[1])}). Gate{" "}
        {gate.passed ? "PASSED" : "FAILED"}: {Object.entries(gate.checks).map(([check, ok]) => (ok ? "✓ " : "✗ ") + check).join(" · ")}
      </p>
      {report.attacker_model && (
        <p className="muted">
          Modelled (not measured) attacker mix:{" "}
          {Object.entries(report.attacker_model.archetypes)
            .map(([name, m]) => name + " " + pct(m.weight) + " (patience " + m.patience + ", returns " + pct(m.return_p) + (m.escalates ? ", escalates/adapts" : "") + ")")
            .join(" · ")}{" "}
          · {pct(report.attacker_model.ot_share)} start on OT.
        </p>
      )}
    </>
  );
}

function LearningCurve({ points }: { points: { n: number; mean_reward: number }[] }) {
  if (points.length < 2) return <Empty>The curve appears after two evaluated decisions.</Empty>;
  const width = 640;
  const height = 150;
  const max = points.at(-1)!.n;
  const y = (r: number) => height - ((r + 1) / 2) * height;
  const path = points.map((p, i) => `${i ? "L" : "M"}${((p.n - 1) / Math.max(1, max - 1)) * width},${y(p.mean_reward)}`).join(" ");
  return (
    <div className="timeline">
      <svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" role="img" aria-label="Running mean reward per evaluated decision">
        <line x1="0" y1={y(0)} x2={width} y2={y(0)} />
        <path d={path} fill="none" stroke="var(--cyan)" strokeWidth="2" />
      </svg>
      <div className="axis"><span>decision 1</span><span>running mean reward (line = 0)</span><span>decision {max}</span></div>
    </div>
  );
}

export default async function Page() {
  const [agent, decisions, posture, policy, training] = await Promise.all([
    load<Agent>("/adaptation/agent"),
    load<Decision[]>("/adaptation/decisions?limit=60"),
    load<Posture[]>("/adaptation/posture"),
    load<Policy>("/adaptation/policy"),
    load<Training>("/adaptation/training"),
  ]);
  const a = agent.data;
  const hardened = (posture.data ?? []).filter((p) => p.actions?.length);
  const byDecision = new Map((decisions.data ?? []).map((d) => [d.decision_id, d]));
  const cell = (context: string, action: string) => a?.table.find((row) => row.context === context && row.action === action);
  return (
    <>
      <PageHeader
        eyebrow="Defence · reinforcement learning"
        title="ADAPTIVE DEFENCE"
        lede="A Thompson-sampling agent chooses how each attacking source is hardened, measures what the attacker did next, and learns which hardening works best per kill-chain stage, attack surface (IT/OT) and history. It is pre-trained on outcomes measured against the real personas and keeps learning live. Every change is listed with its reason and measured outcome."
      />
      <ErrorNote error={agent.error || decisions.error} />
      {a && (
        <StatRow>
          <Stat label="Mode" value={a.config.mode} tone={a.config.mode === "enforce" ? "ok" : "warn"} hint={a.config.agent_version} />
          <Stat
            label="Trained prior"
            value={a.trained ? (a.trained.gate_passed ? "installed" : "forced") : "none"}
            tone={a.trained ? (a.trained.gate_passed ? "ok" : "warn") : undefined}
            hint={a.trained ? a.trained.report_id + " · " + ago(a.trained.installed_at) : "learning from scratch"}
          />
          <Stat label="Sources hardened now" value={hardened.length} />
          <Stat label="Decisions evaluated" value={a.evaluated_decisions} hint={`window ${a.config.window_seconds}s each`} />
          <Stat label="Mean reward" value={reward(a.mean_reward)} hint="range −1 … +1" tone={a.mean_reward != null && a.mean_reward < 0 ? "danger" : undefined} />
          <Stat label="Attacker success rate" value={pct(a.harm_rate)} hint="decisions where the attacker still succeeded" tone={a.harm_rate ? "warn" : "ok"} />
        </StatRow>
      )}

      <Card title="Hardened right now" wide>
        <Table
          head={["Source", "Action", "Effects on the sensors", "Why", "Since", "Measured until"]}
          empty="No source is currently hardened. The agent acts as soon as a source produces a detection."
          rows={hardened.map((p) => {
            const d = p.decision_id ? byDecision.get(p.decision_id) : undefined;
            return [
              <span key="s" className="mono">{p.source_ip}</span>,
              <b key="a">{p.action}</b>,
              <Chips key="e" items={p.actions} />,
              <small key="w">{d?.reason ?? "—"}</small>,
              ago(p.updated_at),
              d?.expires_at ? new Date(d.expires_at).toLocaleTimeString() : "—",
            ];
          })}
        />
      </Card>

      <Card title="What changed and why" wide>
        {(decisions.data ?? []).length ? (
          <div className="decision-list">
            {(decisions.data ?? []).map((d) => (
              <article key={d.decision_id} className={`decision ${d.chosen_by}`}>
                <header>
                  <span className="mono">{new Date(d.decided_at).toLocaleString()}</span>
                  <b className="mono">{d.source_ip}</b>
                  <code>{d.context}</code>
                  <span className={d.changed ? "change" : "muted"}>
                    {d.previous_action} → <b>{d.enforced_action}</b>
                    {d.mode !== "enforce" ? ` (recommended ${d.action})` : ""}
                  </span>
                  <span className={`engine ${d.chosen_by === "exploit" ? "rule" : d.chosen_by === "explore" ? "anomaly" : "ml"}`}>{d.chosen_by}</span>
                </header>
                <p>{d.reason}</p>
                <p className="muted">Triggered by: {d.detection_types.join(", ")}</p>
                <div className="alternatives">
                  {ACTIONS.map((action) => (
                    <span key={action} className={action === d.action ? "alt chosen" : "alt"}>
                      {action} <b>{reward(2 * (d.means[action] ?? 0.5) - 1)}</b>
                    </span>
                  ))}
                </div>
                {d.outcome ? (
                  <p className={d.outcome.harm_events ? "outcome-bad" : "outcome-good"}>
                    Outcome {reward(d.outcome.reward)}: {d.outcome.explanation}
                    {d.outcome.credited_to !== d.action ? ` (credited to ${d.outcome.credited_to})` : ""}
                  </p>
                ) : (
                  <p className="muted">Measuring the attacker&apos;s response until {new Date(d.expires_at).toLocaleTimeString()}…</p>
                )}
              </article>
            ))}
          </div>
        ) : (
          <Empty>No decisions yet. Run an attack scenario (e.g. <code>camera-rtsp-default-creds</code>) to see the agent act.</Empty>
        )}
      </Card>

      <Card title="Offline training and held-out evaluation" wide>
        <ErrorNote error={training.error} />
        {training.data && <TrainingReport report={training.data} />}
      </Card>

      <Card title="What the agent has learned (expected reward per context × action)" wide>
        {a ? (
          <div className="table-scroll">
            <table className="data-table heat">
              <thead><tr><th>Context</th>{ACTIONS.map((action) => <th key={action}>{action}</th>)}<th>Best so far</th></tr></thead>
              <tbody>
                {a.contexts.map((context) => (
                  <tr key={context}>
                    <td className="mono">{context}</td>
                    {ACTIONS.map((action) => {
                      const row = cell(context, action);
                      const value = row?.expected_reward ?? 0;
                      return (
                        <td key={action} className="heat-cell" style={{ "--intensity": row?.evidence ? Math.max(0, value) : 0 } as React.CSSProperties} title={(row?.outcomes ?? 0) + " live outcome(s); " + (row?.prior_evidence ?? 0) + " pseudo-outcomes from training"}>
                          {row?.evidence ? reward(value) : "·"}<small> n={row?.outcomes ?? 0}{row?.prior_evidence ? "+p" : ""}</small>
                        </td>
                      );
                    })}
                    <td><b>{a.best_action_by_context[context] ?? "—"}</b></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <Empty>Agent state unavailable.</Empty>}
        <p className="muted">
          Each cell is the posterior mean of the Beta model on the reward scale. n = live outcomes; “+p” = includes the trained prior (at most {a?.trained?.prior_cap ?? 20} pseudo-outcomes per
          cell, so live data keeps moving it); “·” = no evidence yet. Decisions also borrow capped evidence from same-stage contexts, decay old evidence by {a?.config.discount} per update,
          and down-weight any single source after {a?.config.source_cap} outcomes.
        </p>
      </Card>

      <div className="grid-2">
        <Card title="Learning curve">{a && <LearningCurve points={a.learning_curve} />}</Card>
        <Card title="How the agent works">
          {policy.data && (
            <Table
              head={["Part", "Definition"]}
              empty=""
              rows={[
                ["Algorithm", policy.data.kind],
                ["State", policy.data.state],
                ["Reward", policy.data.reward],
                ...(policy.data.learning ?? []).map((rule, index) => [index ? "" : "Learning", rule]),
                ["Window", `${policy.data.window_seconds}s per decision`],
                ...policy.data.safety.map((rule, index) => [index ? "" : "Safety", rule]),
                ...Object.entries(a?.actions ?? {}).map(([action, effects]) => [`action: ${action}`, effects.join(" + ") || "no change"]),
              ]}
            />
          )}
        </Card>
      </div>

    </>
  );
}
