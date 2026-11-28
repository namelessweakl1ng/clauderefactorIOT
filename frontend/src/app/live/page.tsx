import { LiveStream } from "@/components/live-stream";
import { PageHeader } from "@/components/ui";

export const dynamic = "force-dynamic";

export default function Page() {
  return (
    <>
      <PageHeader
        eyebrow="Operations · real time"
        title="LIVE OPERATIONS"
        lede="Server-sent stream of newly ingested telemetry and newly materialized detections across every sensor and persona."
      />
      <LiveStream />
    </>
  );
}
