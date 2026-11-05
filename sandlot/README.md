# sandlot

The per-node daemon of Sandswap. It manages the microVM pool (spawns and
monitors `sandvmm` KVM processes), performs agent SandFS hot-swap over
native virtio-fs (`allowed_dirs` update + in-guest bind mount), relays
exec/file I/O to the in-VM warden over raw vsock, and reaches the gateway
through a single **outbound-only** persistent gRPC stream — no listening
ports. Surviving VMs are re-adopted after a sandlot restart from persisted
state (`core/state.json` + API sockets).

## Build

```bash
bash build/build.sh go    # gateway + sandlot → output/
# or:
cd sandlot && go build -o ../output/sandlot ./cmd/
```

Prerequisites: `/dev/vhost-vsock` readable (checked at startup); for guest
networking, bridge + NAT via `deploy/setup-network.sh`; optional mTLS
certs for the gateway stream.

## Documentation

- Architecture and communication paths (gateway ↔ sandlot stream, sandlot →
  sandvmm HTTP API, sandlot → warden vsock): [docs/how-it-works/architecture.md](../docs/how-it-works/architecture.md)
- microVM lifecycle states (CLEAN → IN_USE → LEASED → RELEASING → CLEAN,
  sticky lease, recycle policy): [docs/how-it-works/vm-lifecycle.md](../docs/how-it-works/vm-lifecycle.md)
- Resilience state machine (CONNECTED → TOLERATING → CLEANING → DONE),
  crash detection, re-adoption, and the warden countdown: [docs/how-it-works/resilience.md](../docs/how-it-works/resilience.md)
- Configuration — CLI flags, optional YAML, hot-reloadable vs
  restart-required fields: [docs/operations/configuration/sandlot.md](../docs/operations/configuration/sandlot.md)

## License

Business Source License 1.1 — converts to Apache-2.0 on 2028-11-30. See
[../LICENSE](../LICENSE) and [../NOTICE](../NOTICE).
