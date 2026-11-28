# frontend/: the TRAPSIG console (Next.js)

Server-rendered pages that read the backend API. Browser calls go through a
proxy route that attaches the API key, so the key never reaches the browser.

| Page | Route | Source |
| --- | --- | --- |
| Overview | `/` | `src/app/page.tsx` |
| Live Operations (SSE stream) | `/live` | `src/app/live/` |
| Investigate (events + sessions) | `/events` | `src/app/events/` |
| Detections | `/detections` | `src/app/detections/` |
| Adaptive Defence (RL hardening, training report) | `/adaptation` | `src/app/adaptation/` |
| Experiments | `/experiments` | `src/app/experiments/` |
| Evaluation | `/evaluation` | `src/app/evaluation/` |
| Detection Lab (rules, engines, ATT&CK, model history) | `/detection-lab` | `src/app/detection-lab/` |
| Sensors & Personas (fleet editor) | `/honeypots` | `src/app/honeypots/` |
| Observability (pipeline, network, audit) | `/system` | `src/app/system/` |

Shared pieces: `src/components/` (UI kit, charts, client-side actions such as
the fleet editor), `src/lib/` (API client and types), and `src/app/api/[...path]/`
(the proxy).

```bash
npm ci
npm run dev                 # http://localhost:3000, expects the API at API_URL (default http://backend:8000)
npm run build && npx eslint src && npx tsc --noEmit
```
