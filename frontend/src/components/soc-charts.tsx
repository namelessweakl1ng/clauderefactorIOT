import type { CountBucket } from "@/lib/types";

export const EmptyChart = () => <div className="chart-empty">NO DATA IN SELECTED TIME RANGE</div>;

export function HorizontalBars({ data, colors }: { data: CountBucket[]; colors?: Record<string, string> }) {
  if (!data.length) return <EmptyChart />;
  const maximum = Math.max(...data.map((item) => item.count), 1);
  return <div className="bar-chart">{data.map((item) => <div className="bar-row" key={item.name}><span title={item.name}>{item.name}</span><div className="bar-track"><i style={{ width: `${(item.count / maximum) * 100}%`, background: colors?.[item.name.toLowerCase()] }} /></div><b>{item.count}</b></div>)}</div>;
}

export function Timeline({ data }: { data: { time: string; count: number }[] }) {
  if (!data.length) return <EmptyChart />;
  const width = 700, height = 172, max = Math.max(...data.map((item) => item.count), 1);
  const points = data.map((item, index) => `${data.length === 1 ? width / 2 : index * width / (data.length - 1)},${height - item.count / max * (height - 20)}`).join(" ");
  const area = `0,${height} ${points} ${width},${height}`;
  return <div className="timeline"><svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" role="img" aria-label="Events over time"><line x1="0" y1={height / 2} x2={width} y2={height / 2} /><polygon points={area} /><polyline points={points} /></svg><div className="axis"><span>{new Date(data[0].time).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span><span>PEAK {max}</span><span>{new Date(data.at(-1)!.time).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span></div></div>;
}
