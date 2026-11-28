# elk/: the ingest pipeline (Logstash, Elasticsearch, optional Kibana)

```
elk/
├── logstash/
│   ├── pipelines/00-input.conf          inputs: Beats :5044 (Filebeat) and HTTP :5045 (fleet agents)
│   ├── pipelines/20-json-honeypots.conf persona records -> schema v2
│   ├── pipelines/10-cowrie.conf, 30-zeek.conf
│   ├── pipelines/90-validation.conf     schema checks, event.ingested, dead-letter routing
│   ├── pipelines/99-output.conf         -> trapsig-events-* (and trapsig-network-* for Zeek)
│   └── config/
├── elasticsearch/
│   ├── index-templates/   mappings for every trapsig-* index
│   ├── ilm/, mapping-upgrades/, setup/
└── kibana/                optional (docker compose --profile kibana)
```

The pipeline and the backend's `normalizer.py` share one contract (protocol
namespaces, schema version), and parity tests in `tests/ingestion/` keep them
in sync. Event fields: [EVENT_SCHEMA](../docs/reference/EVENT_SCHEMA.md).
