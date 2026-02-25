# Customer POV: CLI Connector

Send test events to AIAAP via `curl` - zero infrastructure required.

## Prerequisites

- `make up` (AIAAP control plane running locally)
- `curl` and `python3` (standard tools)

## Run

```bash
cd examples/customer_env_cli
./send_events.sh     # Posts 5 sample events with connector metadata
./verify.sh          # Checks connector registered + events visible
```

Or from the repo root:
```bash
make pov-cli
```

## What it does

1. POSTs 5 events to `POST http://localhost:8100/api/events` with:
   - `connector_type: "cli"`
   - `connector_instance_id: "pov-cli-01"`
2. Verifies `GET /api/connectors` returns the registered instance
3. Verifies events appear in `GET /api/events`

## Next steps

- Open the **Connectors** dashboard page → see `pov-cli-01` as a healthy instance
- Send events with `connector_type: "ebpf"` to simulate an eBPF sensor
- Use `connector_type: "cloudtrail"` to simulate a CloudTrail forwarder
