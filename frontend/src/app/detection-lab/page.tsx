import { ComparisonRunner, RuleToggle } from "@/components/lab-actions";
import { AttackCoverage, ModelHistory } from "@/components/sections";
import { Card, Chips, Empty, ErrorNote, PageHeader, Stat, StatRow, Status, Table } from "@/components/ui";
import { ago, load, num, pct } from "@/lib/api";
import type { Comparison, Engines, Rule } from "@/lib/platform";

export const dynamic = "force-dynamic";

const ENGINE_LABELS: Record<string, string> = {
  rules: "Rules (Sigma-style)",
  ml_bootstrap: "ML · shipped policy",
  ml_trained: "ML · retrained per fold",
  anomaly: "Anomaly · isolation forest",
  hybrid: "Hybrid (deployed)",
};

function ComparisonView({ report }: { report: Comparison }) {
  const engines = Object.entries(report.engines);
  const classes = report.classes;
  const leak = report.leakage_check.naive_split;
  return (
    <>
      {report.synthetic_warning && (
        <div className="inline-alert warn">Synthetic corpus: this validates the method, not the platform. Synthetic labels partly encode rule thresholds, so rules are favoured.</div>
      )}
      <StatRow>
        <Stat label="Sessions" value={report.sessions} hint={`${report.attack_sessions} attack · ${report.control_sessions} control`} />
        <Stat label="Groups / folds" value={`${report.groups} / ${report.folds}`} hint="GroupKFold by experiment or attacker" />
        <Stat label="Groups spanning folds" value={report.leakage_check.groups_spanning_folds} tone={report.leakage_check.groups_spanning_folds ? "danger" : "ok"} hint="must be 0" />
        <Stat
          label="Random-split inflation"
          value={leak?.leakage_inflation == null ? "—" : `${leak.leakage_inflation >= 0 ? "+" : ""}${num(leak.leakage_inflation)}`}
          hint="macro-F1 a naive split would overstate"
        />
      </StatRow>
      <Table
        head={["Engine", "Macro-F1", "±σ folds", "Alert recall", "Alert FPR", "Unexpected on attacks", "p95 latency", "Model size"]}
        empty="No engines evaluated."
        rows={engines.map(([name, engine]) => [
          <b key="n">{ENGINE_LABELS[name] ?? name}</b>,
          num(engine.macro_f1),
          num(engine.macro_f1_fold_std),
          pct(engine.alert.recall),
          pct(engine.alert.fpr, 1),
          engine.unexpected_detections_on_attacks,
          engine.latency_ms.p95 == null ? "—" : `${num(engine.latency_ms.p95, 3)} ms`,
          engine.model_bytes_mean ? `${(engine.model_bytes_mean / 1024).toFixed(1)} KiB` : "—",
        ])}
      />
      <h4 className="subhead">Per-class recall (positive-vs-control)</h4>
      <div className="table-scroll">
        <table className="data-table heat">
          <thead><tr><th>Class</th>{engines.map(([name]) => <th key={name}>{name}</th>)}</tr></thead>
          <tbody>
            {classes.map((kind) => (
              <tr key={kind}>
                <td className="mono">{kind}</td>
                {engines.map(([name, engine]) => {
                  const recall = engine.per_class[kind]?.recall;
                  return <td key={name} style={{ "--intensity": recall ?? 0 } as React.CSSProperties} className="heat-cell">{recall == null ? "—" : pct(recall)}</td>;
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="muted">Report {report.report_id} · {ago(report.created_at)} · ruleset {report.ruleset_version} · anomaly fit on {report.anomaly_fit_on.join(", ")} · seed {report.seed}. Scores are uncalibrated.</p>
    </>
  );
}

export default async function Page() {
  const [engines, rules, selfTest, comparisons] = await Promise.all([
    load<Engines>("/detection/engines"),
    load<Rule[]>("/detection/rules"),
    load<{ cases: number; passed: number; failures: { rule: string; test: string }[]; ruleset_version: string }>("/detection/rules/self-test"),
    load<Comparison[]>("/detection/comparisons"),
  ]);
  const generating = (rules.data ?? []).filter((rule) => rule.generate);
  const building = (rules.data ?? []).filter((rule) => !rule.generate);
  const latest = comparisons.data?.[0];
  return (
    <>
      <PageHeader eyebrow="Laboratory · detection" title="DETECTION LAB" lede="Rule engine, learned policy and anomaly engine side by side: what is active, whether it passes its own tests, and how the engines compare under grouped cross-validation." />
      <ErrorNote error={engines.error} />
      {engines.data && (
        <StatRow>
          <Stat label="Mode" value={engines.data.mode} hint={engines.data.detector_version} />
          <Stat label="Rules" value={`${engines.data.rules.generating} / ${engines.data.rules.count}`} hint={`generating / total · ${engines.data.rules.version}`} />
          <Stat label="Learned policy" value={engines.data.ml.heads.length + " heads"} hint={engines.data.ml.policy_version} />
          <Stat label="Anomaly model" value={engines.data.anomaly ? `≥ ${num(engines.data.anomaly.threshold, 2)}` : "not trained"} hint={engines.data.anomaly ? `${engines.data.anomaly.model_version} · n=${engines.data.anomaly.trained_on}` : "python -m backend.app.tools.train_anomaly"} tone={engines.data.anomaly ? undefined : "warn"} />
          {selfTest.data && <Stat label="Rule self-test" value={`${selfTest.data.passed}/${selfTest.data.cases}`} tone={selfTest.data.failures.length ? "danger" : "ok"} hint="embedded positive/negative cases" />}
        </StatRow>
      )}
      <Card title="Engine comparison" wide action={<ComparisonRunner />}>
        <ErrorNote error={comparisons.error} />
        {latest ? <ComparisonView report={latest} /> : <Empty>No comparison has been run. Run one on logged experiments (needs completed experiments from at least two groups) or on the synthetic corpus to check the method.</Empty>}
        {comparisons.data && comparisons.data.length > 1 && (
          <p className="muted">Earlier reports: {comparisons.data.slice(1, 8).map((c) => `${c.report_id} (${c.provenance.join("+")}, ${ago(c.created_at)})`).join(" · ")}</p>
        )}
      </Card>
      <Card title={`Detection rules (${generating.length})`} wide>
        <ErrorNote error={rules.error} />
        <Table
          head={["Active", "Rule", "Type", "Level", "Kind", "ATT&CK", "Status", "Tests"]}
          empty="No rules loaded."
          rows={generating.map((rule) => [
            <RuleToggle key="t" id={rule.id} name={rule.name} enabled={rule.enabled} />,
            <span key="r"><b>{rule.title}</b><br /><small className="mono muted">{rule.name} v{rule.version}{rule.override ? " · operator override" : ""}</small><br /><small className="muted">{rule.description}</small></span>,
            <code key="y">{rule.detection_type}</code>,
            <span key="l" className={`severity-text ${rule.level}`}>{rule.level}</span>,
            rule.correlation ? `${rule.correlation.type}${rule.correlation.timespan_seconds ? ` / ${rule.correlation.timespan_seconds}s` : ""}` : "event",
            <Chips key="a" items={rule.attack_techniques} />,
            <Status key="s" value={rule.status} />,
            rule.test_count,
          ])}
        />
        <p className="muted">Building blocks (feed correlations, never alert alone): {building.map((rule) => rule.name).join(", ")}. Rule content is versioned in Git; only activation is runtime state, and every change is audited.</p>
      </Card>
      {selfTest.data && selfTest.data.failures.length > 0 && (
        <Card title="Failing rule tests"><Table head={["Rule", "Case"]} empty="" rows={selfTest.data.failures.map((f) => [f.rule, f.test])} /></Card>
      )}
      <ModelHistory />
      <AttackCoverage />
    </>
  );
}
