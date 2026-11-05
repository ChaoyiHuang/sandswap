# warden

Warden runs as **PID 1 (init)** inside each Sandswap KVM microVM. Over a raw
vsock protocol (port 1024) it mounts the agent's rootfs (virtio-fs bind or
read-only overlay + writable workspace/home), executes commands — sync and background —
inside a hardened chroot, serves file I/O, and tears everything down at agent
switch (per-agent cgroup kill, unmount, cache clearing). It is a pure chroot
executor: no container lifecycle, no namespace management, no OCI runtime.

## Build

Statically linked musl binary — no host library dependencies, safe as PID 1:

```bash
cd warden && ./build.sh                 # → target/<arch>-unknown-linux-musl/release/warden (copied to output/warden)
# or from the repo root:
bash build/build.sh warden      # same build, with freshness tracking
bash build/build.sh initramfs   # packages warden + busybox → output/initramfs.cpio.gz
```

Prerequisite: `rustup target add $(uname -m)-unknown-linux-musl`.

## Configuration

Read from kernel cmdline, TOML file, and env (priority order in
`src/config.rs`): exec timeouts, output caps, per-agent cgroup memory share,
guest network, and the countdown. All parameters and defaults are documented
in [docs/operations/configuration/warden.md](../docs/operations/configuration/warden.md).

## Documentation

- Wire protocol and op set (mount/exec/file/mem-stats, request/response
  frames): [docs/reference/protocols.md](../docs/reference/protocols.md)
- Workspace mount modes (flat bind vs read-only overlay + writable workspace/home): [docs/how-it-works/sandfs.md](../docs/how-it-works/sandfs.md)
- Isolation layers (chroot, caps + seccomp profiles, cgroup, masked /proc,
  minimal /dev) and the agent-switch memory-clearing chain: [docs/how-it-works/threat-model.md](../docs/how-it-works/threat-model.md)
- The single countdown as last-resort mount release — only `OP_MEM_STATS`
  heartbeats reset it; expiry with a live mount **powers the VM off**
  (`reboot(POWER_OFF)` → ACPI shutdown → sandvmm exits → mount released;
  never `exit(1)`, which from PID 1 only panics the kernel and hangs the VM): [docs/how-it-works/resilience.md](../docs/how-it-works/resilience.md)

## License

Business Source License 1.1 — converts to Apache-2.0 on 2028-11-30. See
[../LICENSE](../LICENSE) and [../NOTICE](../NOTICE).
