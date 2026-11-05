# gateway — Sandswap API Server

The HTTP API server and VM pool manager for Sandswap.  Receives agent code-
execution requests (`POST /agent/execute`), authenticates with API keys,
orchestrates the VM pool (sticky lease, pre-warming), and relays commands to
the sandlot node over a persistent gRPC bidirectional stream.

## Role in Sandswap

```
External Agent (HTTP)
       │
       ▼
┌──────────────────────┐     gRPC stream       ┌──────────────────┐
│  gateway (:3000)     │◄─────────────────────►│  sandlot (node)  │
│  (:9998 stream)      │                        │  ┌────────────┐  │
│                      │                        │  │  sandvmm   │  │
│  - /agent/execute    │                        │  │ (KVM proc) │  │
│  - /human/sandfs    │                        │  └─────┬──────┘  │
│  - registry          │                        │        │KVM     │
│  - pool manager      │                        │  ┌─────▼──────┐  │
│  - lease manager     │                        │  │  microVM   │  │
└──────────────────────┘                        │  │  warden    │  │
                                                │  └───────────┘  │
                                                └──────────────────┘
```

## API

| Method | Path | Description |
|--------|------|-------------|
| POST   | `/agent/execute` | Execute shell code in a SandFS sandbox (auth: Bearer token) |
| POST   | `/human/sandfs` | Create a SandFS (returns API key + rootfs path) |
| GET    | `/human/sandfs` | List all SandFS instances |
| DELETE | `/human/sandfs/{id}` | Delete a SandFS and its volume |
| GET    | `/health` | Gateway health check |
| GET    | `/stats` | Pool statistics |

Full schemas and the complete endpoint list (file I/O, background exec,
templates, ownership) are in the documentation — see below.

## Key Components

- **`cmd/main.go`** — entry point: CLI flags, HTTP + gRPC server startup
- **`handler/execute.go`** — `POST /agent/execute` handler with per-stage timing (parse/lease/acquire/attach/exec)
- **`handler/human.go`** — Agent CRUD, health, stats endpoints
- **`pool/manager.go`** — VM pool state machine: CLEAN→IN_USE→LEASED→RELEASING→CLEAN
- **`pool/sandlot_stream.go`** — gRPC stream client for VM commands
- **`registry/sandfs.go`** — SandFS identity, API keys, rootfs directory creation
- **`lease/sticky.go`** — Sticky lease for same-agent reuse
- **`stream/server.go`** — gRPC `NodeStream` service accepting sandlot connections
- **`proto/stream/`** — Protobuf protocol (gateway↔sandlot)

## Build

```bash
cd gateway && go build -o output/gateway ./cmd/
```

## Documentation

- Agent HTTP API — request/response schemas, background-exec lifecycle, client guidance: Agent HTTP API — [integration guide](../docs/integration/agent-http.md) + [reference](../docs/reference/agent-api.md)
- Human/operator API — SandFS CRUD, templates, ownership endpoints: [docs/reference/human-api.md](../docs/reference/human-api.md)
- Configuration — CLI flags, distributed modes, etcd identity store, stream tuning: [docs/operations/configuration/gateway.md](../docs/operations/configuration/gateway.md)
- Architecture — pool management, scheduling, resilience model: [docs/how-it-works/architecture.md](../docs/how-it-works/architecture.md)

## License

Business Source License 1.1 — converts to Apache-2.0 on 2028-11-30. See
[../LICENSE](../LICENSE) and [../NOTICE](../NOTICE).
