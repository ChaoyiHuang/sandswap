# SQLite Template

See [docs/how-it-works/templates.md](../../docs/how-it-works/templates.md) for how Sandswap templates work (layers, refs, instantiation).

A lightweight SQLite template for Sandswap.

## Features

- **Embedded database**: No server process needed
- **Zero configuration**: Works out of the box
- **Persistent storage**: Database files stored in `/workspace/`

## Metadata status

`template.json` fields (`default_timeout`, `is_serverless`, `idle_timeout`,
`env`) are DECLARED metadata today — the runtime does not yet enforce them
(execution timeouts come from the request / gateway flags; there is no
idle-based auto-cleanup). Treat this file as the forward-looking manifest;
enforcement is tracked in the release backlog.

## Usage

### Create SandFS with SQLite template

```bash
curl -X POST http://localhost:3000/human/sandfs \
  -H "Content-Type: application/json" \
  -d '{"name":"my-db","template":"sqlite:v1"}'
```

### Access database

```bash
# Execute SQL
curl -X POST http://localhost:3000/agent/execute \
  -H "Authorization: Bearer sk-sandswap-xxx" \
  -H "Content-Type: application/json" \
  -d '{
    "code": "sqlite3 /workspace/data.db \"CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);\"",
    "language": "shell"
  }'

# Python with sqlite3 module
curl -X POST http://localhost:3000/agent/execute \
  -H "Authorization: Bearer sk-sandswap-xxx" \
  -H "Content-Type: application/json" \
  -d '{
    "code": "import sqlite3; conn = sqlite3.connect(\"/workspace/data.db\"); print(conn.execute(\"SELECT sqlite_version()\").fetchone())",
    "language": "python"
  }'
```

## Environment Variables

`template.json` declares `SQLITE_DB_PATH` (`/workspace/data.db`),
`SQLITE_JOURNAL_MODE` (`WAL`) and `SQLITE_BUSY_TIMEOUT` (`5000`) as the
template's configuration contract. They are declared metadata today — Sandswap
does not inject them (see "Metadata status" above); an application running in
the sandbox can set them itself before opening the database.

## Template Layers

1. **layer-0**: Base busybox (from base template)
2. **layer-1**: SQLite3 binary and libraries
3. **layer-2**: Workspace configuration

## Why SQLite for Sandswap?

1. **No server process**: Lower resource usage, faster startup
2. **File-based**: Natural fit for sandbox filesystem model
3. **Zero configuration**: No need to manage users, permissions, or network
4. **Atomic commits**: Built-in transaction support
5. **Perfect for AI agents**: Each agent gets isolated database

## Differences from MySQL

| Aspect | MySQL | SQLite |
|--------|-------|--------|
| Process | Server process | Embedded library |
| Startup time | ~1-2 seconds | Instant |
| Memory usage | 100-500MB | ~1MB |
| Configuration | Complex (users, grants) | Zero config |
| Network | TCP port needed | No network needed |
| Concurrency | High (multiple connections) | Moderate (WAL mode) |
| Storage | Dedicated volume | Single file |
| Best for | Multi-user apps | Single-user, embedded |

## Building the Template

This directory is the template's **metadata** (`template.json`) only — a
real template needs the layer directories next to it
(`layer-0/` base busybox, `layer-1/` sqlite3 binary and libraries):

```bash
# 1. Assemble the layers (see docs/building/templates.md for the recipes):
#    templates/sqlite/layer-0/  ← busybox rootfs (build.sh rootfs-template)
#    templates/sqlite/layer-1/  ← sqlite3 binary + libraries
# 2. Publish with the ORAS-based script:
bash build/build-template.sh ./templates/sqlite sqlite:v1 <registry>

# Or, once the layers are registered in a gateway's local store, push from
# the gateway instead:
sandctl api template push sqlite:v1
```
