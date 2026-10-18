# Workflows

JSON definitions of the sensor workflows. Each step lists its inputs, outputs, governing standards, the repo tools, features and controls it maps to, and known gaps. See `docs/6.4-crash-triage-workflow.md` for the narrative.

| File | Purpose |
|---|---|
| `crash-triage.workflow.json` | Crash to root cause, phases 0-11 |
| `telemetry-detection.workflow.json` | Collection to threat verdict, steps 1-10 |
| `capability-map.json` | Reverse index from each tool, feature or control to the steps that use it |
| `schema/workflow.schema.json` | JSON Schema for the workflow files |

Step `status` is one of `implemented`, `partial`, `planned` or `external` (done outside the sensor).

All workflows run only under RoE-ITlusions-Testlab-2026, on in-scope testlab systems.
