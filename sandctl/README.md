# sandctl

Sandswap **client** CLI — the gateway HTTPS API client (`api …`), DNS
querying (`dns …`), and read-only pool/health views (`pool` / `health-all`)
in one binary. Deployment and component lifecycle belong to
`deploy/baremetal` (systemd); sandctl never starts, stops or configures a
component. Standalone stdlib-only Go module, builds independently of the
gateway/sandlot modules.

## Build

```bash
bash build/build.sh sandctl   # → output/sandctl
# or as part of the full Go build:
bash build/build.sh go         # gateway+sandlot+boxout+dns+sandctl
```

## Usage

```
sandctl [global-flags] <command> [subcommand] [flags] [args]
sandctl api health
```

The deployers write `/etc/sandswap/sandctl.env` (public URLs + CA, root:root
0644) once a deployment is healthy; sandctl reads it automatically. Set
`SANDSWAP_SANDCTL_ENV` to point at another contract. CLI flags always win.
`sandctl` never reads a service identity's private key.

## Documentation

- Full client guide — every command, subcommand, flag, and the client
  contract: [docs/operations/sandctl.md](../docs/operations/sandctl.md)
- Step-by-step quick start (deploy with the bare-metal deployer, then drive
  the API): [docs/getting-started/index.md](../docs/getting-started/index.md)
