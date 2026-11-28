import Link from "next/link";

import { ArmCompare } from "@/components/lab-actions";
import { Card, Empty, ErrorNote, PageHeader, RateBar, Stat, StatRow, Status, Table } from "@/components/ui";
import { load, num, pct } from "@/lib/api";
import type { Comparison } from "@/lib/platform";
import type { EvaluationCohort, EvaluationRow, EvaluationSummary, Scenario } from "@/lib/types";

export const dynamic = "force-dynamic";

type Condition = { condition: string; experiments: number; completed: number; batches: string[] };
type Decision = { status: string; enforced_action: string; outcome?: { reward: number; harm_events: number; new_behaviours: number; events: number } };

const ENGINE_LABELS: Record<string, string> = { rules: "Rules", ml_trained: "ML (retrained)", anomaly: "Anomaly", hybrid: "Hybrid (deployed)" };
const ACTIONS = ["observe", "tarpit", "deny_auth", "read_only", "quarantine"];

function outcomeLabel(row: EvaluationRow | undefined) {
  if (!row) return <span className="muted">not run</span>;
  if (row.trial_kind === "control") return `TN ${row.tn ?? 0} / FP ${row.fp ?? 0}`;
  return `TP ${row.tp ?? 0} / FN ${row.fn ?? 0}`;
}

function scenarioStatus(row: EvaluationRow | undefined, kind: string) {
  if (!row || !row.scored_count) return "no evidence";
  const good = kind === "control" ? (row.fp ?? 0) === 0 : (row.fn ?? 0) === 0;
  return good ? "passed" : "failed";
}

function hardeningByAction(decisions: Decision[]) {
  return ACTIONS.map((action) => {
    const done = decisions.filter((d) => d.status === "evaluated" && d.outcome && d.enforced_action === action);
    const harmed = done.filter((d) => (d.outcome?.harm_events ?? 0) > 0).length;
    const reward = done.length ? done.reduce((sum, d) => sum + (d.outcome?.reward ?? 0), 0) / done.length : null;
    const intel = done.length ? done.reduce((sum, d) => sum + (d.outcome?.new_behaviours ?? 0), 0) / done.length : null;
    return { action, n: done.length, successRate: done.length ? harmed / done.length : null, reward, intel };
  });
}

function CohortMetrics({ cohort }: { cohort: EvaluationCohort }) {
  const o = cohort.overall;
  return (
    <>
      <StatRow>
        <Stat label="Scored runs" value={String(o.scored_experiments ?? 0)} hint={`${o.inconclusive_experiments ?? 0} inconclusive (excluded)`} />
        <Stat label="Recall" value={pct(o.recall, 1)} hint={`TP ${o.TP ?? 0} · FN ${o.FN ?? 0}`} />
        <Stat label="Precision" value={pct(o.precision, 1)} />
        <Stat label="False-positive rate" value={pct(o.false_positive_rate, 1)} hint={`controls: TN ${cohort.controls.tn} · FP ${cohort.controls.fp}`} tone={(o.false_positive_rate ?? 0) > 0 ? "warn" : "ok"} />
        <Stat label="F1" value={num(o.f1)} />
        <Stat label="Detection latency p95" value={cohort.latency.detection_latency?.p95 == null ? "—" : `${num(cohort.latency.detection_latency.p95, 1)} s`} hint="experiment start → detection" />
      </StatRow>
      <Card title="Per detection type (positive-vs-control)" wide>
        <Table
          head={["Detection type", "TP / FN", "FP / TN", "Recall", "Precision", "F1"]}
          empty="No scored attack runs in this cohort."
          rows={cohort.per_detection_type
            .filter((row) => row.tp + row.fn + row.fp > 0)
            .map((row) => [<code key="t">{row.detection_type}</code>, `${row.tp} / ${row.fn}`, `${row.fp} / ${row.tn}`, <RateBar key="r" value={row.recall} />, <RateBar key="p" value={row.precision} />, num(row.f1)])}
        />
      </Card>
    </>
  );
}

export default async function Page({ searchParams }: { searchParams: Promise<{ config?: string }> }) {
  const [summary, scenarios, comparisons, conditions, decisions] = await Promise.all([
    load<EvaluationSummary>("/evaluation/summary"),
    load<Scenario[]>("/scenarios"),
    load<Comparison[]>("/detection/comparisons"),
    load<Condition[]>("/experiment-lab/conditions"),
    load<Decision[]>("/adaptation/decisions?limit=1000"),
  ]);
  const data = summary.data;
  const requested = (await searchParams).config;
  const cohort = data?.cohorts.find((c) => c.evaluation_config_fingerprint === requested) ?? data?.cohorts.find((c) => c.evaluation_config_fingerprint === data?.most_recent_evaluation_config_fingerprint);
  const perScenario = new Map((cohort?.per_scenario ?? []).map((row) => [row.scenario_id, row]));
  const catalog = [...(scenarios.data ?? [])].sort((a, b) => a.trial_kind.localeCompare(b.trial_kind) || a.id.localeCompare(b.id));
  const withEvidence = catalog.filter((s) => perScenario.get(s.id)?.scored_count).length;
  const latest = comparisons.data?.[0];
  const arms = (conditions.data ?? []).filter((c) => c.condition !== "(none)" && c.completed > 0).map((c) => c.condition);
  const hardening = hardeningByAction(decisions.data ?? []);
  const observed = hardening.find((h) => h.action === "observe");
  const hardened = hardening.filter((h) => h.action !== "observe" && h.n);
  const hardenedRuns = hardened.reduce((n, h) => n + h.n, 0);
  const hardenedSuccess = hardenedRuns ? hardened.reduce((n, h) => n + (h.successRate ?? 0) * h.n, 0) / hardenedRuns : null;

  return (
    <>
      <PageHeader
        eyebrow="Laboratory · measured results"
        title="EVALUATION"
        lede="How well TRAPSIG detects and contains attacks, measured only from completed controlled experiments. Inconclusive runs never count as negatives; cohorts with different software or configuration are never mixed."
      >
        {cohort && (
          <span className="inline-form">
            <a className="button-link" href={`/api/evaluation/export.csv?evaluation_config_fingerprint=${cohort.evaluation_config_fingerprint}`}>Export CSV</a>
            <a className="button-link" href={`/api/evaluation/export.json?evaluation_config_fingerprint=${cohort.evaluation_config_fingerprint}`}>Export JSON</a>
          </span>
        )}
      </PageHeader>
      <ErrorNote error={summary.error} />

      {data && data.cohorts.length > 1 && (
        <div className="segmented" role="navigation" aria-label="Evaluation cohort">
          {data.cohorts.map((c) => (
            <Link key={c.evaluation_config_fingerprint} className={c === cohort ? "active" : ""} href={`/evaluation?config=${c.evaluation_config_fingerprint}`}>
              {c.evaluation_config_fingerprint.slice(0, 10)}
            </Link>
          ))}
        </div>
      )}

      {cohort ? (
        <CohortMetrics cohort={cohort} />
      ) : (
        <Card title="Detection performance" wide>
          <Empty>
            No scored cohort yet. Create experiments on the Experiments page (record <code>TRAPSIG_REVISION</code> so runs form a cohort) and run each scenario at least five times.
            {data?.legacy_incomplete_count ? ` ${data.legacy_incomplete_count} completed run(s) lack evaluation metadata and are excluded.` : ""}
            {data?.unversioned_batches[0] ? ` Latest unversioned batch: ${data.unversioned_batches[0].evaluation_batch_id} (${data.unversioned_batches[0].completed_experiments} runs, descriptive only).` : ""}
          </Empty>
        </Card>
      )}

      <Card title={`Scenario coverage (${withEvidence} of ${catalog.length} scenarios have evidence)`} wide>
        <ErrorNote error={scenarios.error} />
        <Table
          head={["Scenario", "Kind", "Expected", "Services", "Runs", "Result", "Status"]}
          empty="Scenario catalogue unavailable."
          rows={catalog.map((s) => {
            const row = perScenario.get(s.id);
            return [
              <span key="n"><b>{s.name}</b><br /><small className="mono muted">{s.id}</small></span>,
              s.trial_kind,
              s.expected_detection ? <code key="e">{s.expected_detection}</code> : "none",
              s.target_services.join(", "),
              row?.run_count ?? 0,
              outcomeLabel(row),
              <Status key="st" value={scenarioStatus(row, s.trial_kind)} />,
            ];
          })}
        />
        <p className="muted">“no evidence” means the scenario has not been run in this cohort. Every persona scenario is also verified in CI against the real sensor code, but only lab runs count here.</p>
      </Card>

      <div className="grid-2">
        <Card title="Does RL hardening contain attackers?">
          <ErrorNote error={decisions.error} />
          {hardening.some((h) => h.n) ? (
            <>
              <StatRow>
                <Stat label="Attacker success · observed" value={pct(observed?.successRate)} hint={`${observed?.n ?? 0} decision(s)`} />
                <Stat label="Attacker success · hardened" value={pct(hardenedSuccess)} hint={`${hardenedRuns} decision(s)`} tone={hardenedSuccess != null && observed?.successRate != null && hardenedSuccess < observed.successRate ? "ok" : undefined} />
              </StatRow>
              <Table
                head={["Action", "Decisions", "Attacker success", "Mean reward", "New behaviours / decision"]}
                empty=""
                rows={hardening.map((h) => [<code key="a">{h.action}</code>, h.n, h.n ? <RateBar key="s" value={h.successRate} /> : "—", h.reward == null ? "—" : num(h.reward, 2), h.intel == null ? "—" : num(h.intel, 1)])}
              />
              <p className="muted">From evaluated agent decisions (5-minute windows). This is observational: the agent chooses actions by context, so compare arms below for a controlled answer.</p>
            </>
          ) : (
            <Empty>No evaluated hardening decisions yet. They appear 5 minutes after the agent first acts on an attacking source.</Empty>
          )}
        </Card>
        <Card title="Engine comparison (grouped CV)" action={<Link href="/detection-lab">Detection Lab →</Link>}>
          {latest ? (
            <>
              {latest.synthetic_warning && <div className="inline-alert warn">Latest report uses the synthetic corpus (method check only).</div>}
              <Table
                head={["Engine", "Macro-F1", "Alert recall", "Alert FPR"]}
                empty=""
                rows={Object.entries(latest.engines)
                  .filter(([name]) => name in ENGINE_LABELS)
                  .map(([name, e]) => [ENGINE_LABELS[name], num(e.macro_f1), pct(e.alert.recall), pct(e.alert.fpr, 1)])}
              />
              <p className="muted">{latest.sessions} sessions · {latest.groups} groups · {latest.folds} folds · {latest.provenance.join("+")}</p>
            </>
          ) : (
            <Empty>No engine comparison yet. Run one from the Detection Lab.</Empty>
          )}
        </Card>
      </div>

      <Card title="Controlled comparison between conditions" wide>
        <ErrorNote error={conditions.error} />
        {arms.length >= 2 ? (
          <ArmCompare conditions={arms} />
        ) : (
          <Empty>
            Needs completed experiments in two conditions, e.g. <code>baseline</code> (<code>HARDENING_MODE=off</code>) and <code>rl-hardening</code>, each scenario repeated at least five times.
          </Empty>
        )}
      </Card>
    </>
  );
}
