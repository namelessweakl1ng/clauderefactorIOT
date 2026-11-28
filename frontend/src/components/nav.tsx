"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const sections = [
  {
    label: "Operations",
    links: [
      ["Overview", "/"],
      ["Live Operations", "/live"],
      ["Investigate", "/events"],
    ],
  },
  {
    label: "Defence",
    links: [
      ["Detections", "/detections"],
      ["Adaptive Defence", "/adaptation"],
    ],
  },
  {
    label: "Laboratory",
    links: [
      ["Experiments", "/experiments"],
      ["Evaluation", "/evaluation"],
      ["Detection Lab", "/detection-lab"],
    ],
  },
  {
    label: "Platform",
    links: [
      ["Sensors & Personas", "/honeypots"],
      ["Observability", "/system"],
    ],
  },
] as const;

export function Nav() {
  const pathname = usePathname();
  return (
    <aside className="sidebar">
      <div className="brand"><h1>TRAPSIG</h1><p>IOT DECEPTION RESEARCH</p></div>
      <nav aria-label="Primary">
        {sections.map((section) => (
          <div key={section.label} className="nav-group">
            <div className="nav-label">{section.label}</div>
            {section.links.map(([name, path]) => {
              const active = path === "/" ? pathname === path : pathname === path || pathname.startsWith(`${path}/`);
              return <Link key={path} href={path} className={active ? "active" : ""} aria-current={active ? "page" : undefined}>{name}</Link>;
            })}
          </div>
        ))}
      </nav>
      <div className="sidebar-foot"><span className="pulse" /> Isolated laboratory</div>
    </aside>
  );
}
