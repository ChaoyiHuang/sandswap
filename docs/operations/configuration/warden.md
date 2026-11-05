---
title: Warden
nav_order: 5
parent: Configuration
grand_parent: Operations
---

# Warden Configuration

> Source: `warden/src/config.rs`.

**What the warden is.** The warden is the in-VM PID 1: it mounts proc/sys/dev, brings up the guest network, reaps children, and serves the raw vsock protocol (port 1024) that sandlot drives — mount+exec, unmount with cgroup clearing, file ops, heartbeats. See [Architecture](../../how-it-works/architecture.md).

**How it is configured.** There is no config file in normal operation: the warden reads `/proc/cmdline` once at boot (after mounting `/proc`) and takes `warden.*` parameters from it, with environment variables as an override layer. Almost all of these parameters are **written by the sandlot** when it assembles the kernel command line at VM create (`sandlot/vmm/launcher.go` `buildCmdline`) — operators configure them indirectly through [Sandlot](sandlot.md) flags (`-warden-countdown-sec`, `-warden-max-exec-timeout-sec`, the `network.*` backend). Only the environment-variable layer is a genuinely warden-local surface (e.g. for initramfs builds used in isolation).

**Precedence** (highest wins):

1. Environment variables (where one exists — see table below).
2. Kernel cmdline `warden.*` parameters.
3. Built-in defaults.

A TOML config file also exists (`warden.config_file=<path>` on the cmdline, or `--config/-c` in argv) but is a specialty escape hatch: it supplies **base** values that the kernel-cmdline `warden.*` parameters then override one by one (environment variables still override both). It only carries `log_level`; it is unused in Sandswap deployments.

`warden.log_vport` (a vsock log listener) **does not exist**: no deployment
path sets it and no consumer reads it, and an enabled listener would be an
unauthenticated vsock port outside vsockguard's port-1024 rule. Logs go to
stdout (the preferred `/dev/console`; with the current cmdline that is hvc0 →
`<sandbox>/console.log`). `<sandbox>/serial.log` carries `earlyprintk`
(earliest boot/panic) only.

## 1. Kernel cmdline parameters and environment overrides

**Background — hardening and exec bounds.** These bound what a single exec or file op can consume inside the guest: the per-agent cgroup memory share, output truncation, sync-exec timeouts, and single-op byte caps. The timeouts apply to sync commands only — background execs are bounded by the VM lease, not a per-command timeout.

| Kernel cmdline | Environment | Default | Meaning |
|---|---|---|---|
| `warden.agent_mem_percent=<u32>` | `AGENT_MEM_PERCENT` | 70 | Per-agent memory budget = guest MemTotal × this / 100, enforced in two ways. **Background execs**: per-agent cgroup `memory.max` (they self-migrate in `pre_exec`) — bounds the aggregate. **Sync execs**: per-process `setrlimit(RLIMIT_AS)` in `pre_exec` (one syscall, inherited by the child tree) — sync execs deliberately do NOT join the cgroup, because a cgroup v2 task migration costs 8–20 ms inside KVM microVMs (measured; µs-scale on bare metal) and sits on the exec hot path. RLIMIT_AS bounds each PROCESS, not the aggregate: `exec_slots` parallel sync execs can together reach slots × the cap before the guest OOM killer intervenes — self-contained (one SandFS per VM; the agent only OOMs its own VM; warden/PID 1 is OOM-exempt), and deliberately not prorated per slot because RLIMIT_AS counts address space, which legitimate heavy runtimes (Python/JVM) map far beyond their RSS. `0` disables both (and skips enabling the memory controller). |
| `warden.tmpfs_size_mb=<u32>` | `TMPFS_SIZE_MB` | 0 (auto = MemTotal/4) | Per-mount size cap (MiB) for the agent-visible tmpfs mounts (`/dev/shm` always; `/tmp` in overlay mode). tmpfs is **unreclaimable** guest memory: without a cap, filling it walks the guest to the OOM corner where every eligible victim (agent processes only — warden/PID 1 is OOM-exempt and additionally pins `oom_score_adj=-1000`) is dead but the tmpfs pages remain, ending in a VM-killing OOM storm. RLIMIT_AS cannot prevent this (tmpfs writes consume no address space). With the cap, the failure is a plain `ENOSPC` at the writer. `0` = auto (MemTotal/4); a huge value effectively disables it. |
| `warden.pidfd=<0\|1>` | `WARDEN_PIDFD` | 1 (on) | Sync-exec exit wait via pidfd (`pidfd_open` + epoll + `waitid(P_PIDFD)`) — saves the ~1 ms SIGCHLD wakeup hop chain per exec. `0` restores the SIGCHLD-registry-only wait. The registry oneshot remains the status source either way (the pidfd is only the wakeup source), so the central reaper can never race a waiter into a lost status. |
| `warden.max_output_bytes=<bytes>` | `MAX_OUTPUT_BYTES` | 1048576 (1 MiB) | stdout/stderr are truncated to this many bytes per exec, keeping the warden↔sandlot vsock channel from being blown up by huge output. |
| `warden.default_exec_timeout=<sec>` | `DEFAULT_EXEC_TIMEOUT` | 30 | Command timeout applied when the caller omits one (or sends 0); the command is killed via `kill(-pgid)` past it. |
| `warden.max_exec_timeout=<sec>` | `MAX_EXEC_TIMEOUT` | 180 | Upper bound a caller can request; larger requests are clamped. The gateway clamps too, but the warden is the independent final authority. Sandlot sets it per-VM via `-warden-max-exec-timeout-sec` / `microvm.warden_max_exec_timeout_sec` (restart-required). |
| `warden.cgroup_clear_timeout=<sec>` | `CGROUP_CLEAR_TIMEOUT` | 5 | How long `unmount_workspace` waits for the per-agent cgroup to empty after `cgroup.kill` before proceeding (a D-state process may linger). Off the `/execute` E2E path. |
| `warden.warden_countdown_sec=<sec>` | `WARDEN_COUNTDOWN_SEC` | 300 | The single countdown: how long the warden tolerates heartbeat (OP_MEM_STATS) silence while a mount is live before exiting the VM (last-resort mount release). Business RPCs deliberately do NOT reset it; the sandlot stops heartbeating at T_tolerance, so a mount still live at T_tolerance + T_warden triggers `reboot(POWER_OFF)`. Set by sandlot from `-warden-countdown-sec`. |
| `warden.max_file_read_bytes=<bytes>` | `MAX_FILE_READ_BYTES` | 16777216 (16 MB) | Hard cap on bytes a single file READ can return. Also caps a positive file-WRITE offset: an unbounded sparse seek would let one file op mint an arbitrarily large apparent file whose hole a host-side template save materializes into shared storage. |
| `warden.max_body_len=<bytes>` | `MAX_BODY_LEN` | 16777216 (16 MB) | Hard cap on a single vsock request frame body (bounds file WRITE data and any request body). |
| `warden.max_bg_log_bytes=<bytes>` | `MAX_BG_LOG_BYTES` | 67108864 (64 MB) | Secondary aggregate cap on a background exec's log on the RAM-backed initramfs rootfs. The pipe relay already bounds every log to `bg_log_tail_bytes`; this watchdog is the backstop for a producer that bypasses the relay. `0` disables the watchdog. |
| `warden.bg_log_tail_bytes=<bytes>` | `BG_LOG_TAIL_BYTES` | 8192 (8 KiB) | How many bytes of a background exec's merged stdout/stderr the relay keeps (and `status` returns). The relay continues reading (pipe backpressure) but retains only this tail, so a `yes`-flood cannot exhaust guest memory. No file-size rlimit is imposed — agent files are never truncated. `0` = default. |
| `warden.log=<level>` | `SANDSWAP_WARDEN_LOG_LEVEL` | `info` | Log level (`trace`/`debug`/`info`/`warn`/`error`/`critical`; case-sensitive, `fatal`/`panic` map to critical). Sandlot sets it per-VM via `-warden-log` / `microvm.warden_log` — deliberately restart-required: debug lines drain the guest console on the measured path (hvc0 now; the legacy UART cost ~83 µs/char), so an online flip is not offered. |

**Background — guest networking.** These are appended by the sandlot network provider when it provisions a VM; the warden reads them at boot and configures eth0 via netlink. Missing/empty means an offline VM — they are never hand-written. The vsock listen port is not configurable: it is the compile-time constant `raw_server::PORT` (1024), matched by sandlot's warden client.

| Kernel cmdline | Set by | Meaning |
|---|---|---|
| `warden.net_ip=<ipv4>` / `warden.net_prefix=<len>` / `warden.net_gw=<ipv4>` | bridge backend | Static IPv4 addressing for eth0. |
| `warden.net_ip6=<ipv6>` / `warden.net_prefix6=<len>` / `warden.net_gw6=<ipv6>` | routed-ipv6 backend | Static IPv6 addressing (v6-only provisioning leaves v4 offline). |
| `warden.net_dns=<csv>` | both backends | Guest resolv.conf nameservers (comma-separated). |
| `warden.net_mac=<mac>` | both backends | MAC address for eth0. |

## 2. Startup clamps and invariants

The warden enforces these itself at boot (`config.rs`); the sandlot and gateway re-check their ends at startup/connect:

- **`default_exec_timeout ≤ max_exec_timeout`** — a larger default is clamped down to max (otherwise every default exec would be silently clamped anyway).
- **`warden_countdown ≥ max_exec_timeout` and `warden_countdown ≥ cgroup_clear_timeout`** — the countdown is clamped UP to the tighter bound: a legal max-length exec must never trip the countdown mid-run, and an unmount's reap must finish inside it.
- **Exec timeout must stay strictly below the countdown** — keep the chain `gateway -max-exec-timeout-sec` = `warden.max_exec_timeout` < `warden_countdown_sec` (defaults: 180 < 300). The countdown must only ever trip a cleanup overrun, never a legal long exec. Note the warden's own clamp makes an effective countdown equal to max_exec_timeout possible, so leave real headroom (the sandlot warns when `warden-countdown-sec ≤ warden-max-exec-timeout-sec + 30s`).
- **Hard ceilings** — `warden.max_exec_timeout` above 3600 s or `warden.warden_countdown_sec` above 4200 s (3600 + 600) is a boot-time configuration error, not a silent clamp: the gateway anchors its mount-release proof on the countdown it configured, so a value that stretches that proof must be refused, not accepted.
- **The 16 MB chain** — `warden.max_file_read_bytes` / `warden.max_body_len` (env `MAX_FILE_READ_BYTES` / `MAX_BODY_LEN`) and the gRPC `max_msg_size` on both [Gateway](gateway.md) and [Sandlot](sandlot.md) must all be ≥ 16 MB, so a file op accepted over gRPC is never rejected at the vsock layer. The `/agent/file` HTTP body limit is 50 MB (not 16 MB) so a 16 MB binary write survives base64+JSON inflation (~21 MB).

All warden configuration is **boot-time only**: it is read once per VM and never re-read. A configuration change takes effect on the next VM (pool recycling and destroy-and-replace turn that over naturally — there is no reload signal).
