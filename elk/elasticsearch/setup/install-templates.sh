#!/bin/sh
set -eu
base=${ELASTICSEARCH_URL:-http://elasticsearch:9200}
# Install ILM retention policies BEFORE templates that reference them, so index
# creation can attach the lifecycle. Idempotent; safe to re-run.
if [ -d /ilm ]; then
  for file in /ilm/*.json; do
    [ -e "$file" ] || continue
    name=$(basename "$file" .json)
    curl -fsS -X PUT -H 'Content-Type: application/json' --data-binary "@$file" "$base/_ilm/policy/$name"
  done
fi
for file in /templates/*.json; do
  name=$(basename "$file" .json)
  curl -fsS -X PUT -H 'Content-Type: application/json' --data-binary "@$file" "$base/_index_template/$name"
done
# Templates do not update existing indices. This known-name-only, idempotent update
# fixes the single-node replica setting without recreating or deleting any data.
curl -fsS -X PUT -H 'Content-Type: application/json' \
  --data '{"index":{"number_of_replicas":0}}' \
  "$base/trapsig-events-*,trapsig-dead-letter-*,trapsig-sessions,trapsig-detections,trapsig-experiments,trapsig-policy,trapsig-posture,trapsig-hardening-decisions,trapsig-hardening-agent,trapsig-locks,trapsig-network-*,trapsig-sensor-instances,trapsig-personas,trapsig-rule-state,trapsig-audit,trapsig-model-anomaly,trapsig-comparisons/_settings?allow_no_indices=true&ignore_unavailable=true&expand_wildcards=all"
# Additive mappings for exact existing derived indices; never delete or recreate data.
for index in trapsig-experiments trapsig-detections; do
  if curl -fsS -I "$base/$index" >/dev/null; then
    curl -fsS -X PUT -H 'Content-Type: application/json' \
      --data-binary "@/mapping-upgrades/$index.json" "$base/$index/_mapping"
  fi
done
