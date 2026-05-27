# Runtime Java Current State And History

## Scope

This note documents the intended semantics for runtime Java vulnerability results on the manager side.

Two different concerns must remain separated:

1. current state for "what is vulnerable right now"
2. history for "what changed over time"

## Current-State Index

`wazuh-states-vulnerabilities-runtime-java` is a current-state index.

That means:

- each document represents the latest known state for one `agent + inventory_id + vulnerability_id`
- a runtime Java full resync must rebuild that state from scratch
- documents not re-emitted by the latest full resync must be removed

For this reason, manager-side runtime Java full resync must use:

- `wazuh.session.scan_mode = full`
- `clear_existing = yes`

Delta scans keep using:

- `wazuh.session.scan_mode = delta`
- `clear_existing = no`

Because the index is current-state, later delta scans are allowed to overwrite the session metadata stored in the
same document. The current document is not a historical record.

## Why This Matters

If a full resync keeps `clear_existing = no`, stale runtime Java vulnerability documents remain in the current-state
index even after the vulnerable component is no longer present. That makes remediation look incomplete when it is not.

## Minimal History Plan

History should be implemented separately from the current-state index.

Recommended minimal model:

1. Keep `wazuh-states-vulnerabilities-runtime-java` as the only source for current runtime Java vulnerability state.
2. Add a separate append-only history stream or index for changes only.
3. Emit history events only when the current state changes:
   - `detected`
   - `resolved`
   - optionally `metadata_updated`
4. Each history event should include:
   - `agent.id`
   - `inventory_id`
   - `runtime_path`
   - `package.name`
   - `vulnerability.id`
   - `session.id`
   - `scan_mode`
   - `event.type`
   - `event.created`
5. Dashboards that answer "what is still open" must read the current-state index, not the history stream.

## Release Gate

Runtime Java vulnerability detection is release-ready only after the following are true:

1. full runtime Java resync is classified as `full`
2. manager logs show `clear_existing=yes` for runtime Java full resync sessions
3. stale results disappear after a full resync
4. dashboards and queries treat runtime Java results as current state, not history
