# vsockguard

A BPF LSM program that pins the host side of the warden vsock transport. It
hooks `socket_connect` and denies `connect()` to `AF_VSOCK` port `1024` for
every UID except the sandlot service UID (kept in a BPF map, written by the
loader at attach time) — closing the **active impersonation** path: the
warden performs zero authentication, and an AF_VSOCK `connect()` goes
through no device node, so permissions alone cannot keep a local user from
dialing a warden and sending mount/exec frames. All other address families
and ports pass through untouched.

## Layout

| File | Role |
|------|------|
| `vsockguard.bpf.c` | The BPF LSM program (C, compiled by clang) |
| `vsockguardctl.c` | libbpf control tool: `attach` / `detach` (issues `BPF_LINK_CREATE`; bpftool v7.x has no LSM-link subcommand) |
| `vmlinux.h` | Generated from `/sys/kernel/btf/vmlinux` — kernel-specific, **not committed** |
| `LICENSE-GPL-2.0` | GPL-2.0 text (one branch of the dual license, below) |

## Build

```bash
bash build/build.sh vsockguard     # → output/vsockguard.bpf.o + output/vsockguardctl
```

Prerequisites: `clang`, `libbpf-dev`, `bpftool`.

## Attach / verify

```bash
security/setup-bpf-lsm.sh          # one-time kernel boot config (reboot required)
security/vsockguard-attach.sh [uid]
security/vsockguard-verify.sh      # enforcement check: probe as allowed/denied uid
security/vsockguard-detach.sh
```

**⚠️ The kernel's `bpf` LSM must be active** (`/sys/kernel/security/lsm`)
or the attached program is a silent no-op — `vsockguardctl` refuses to
attach otherwise.

## Documentation

- How it works, threat analysis, and the complementary passive-sniffing
  layer (host security invariants):
  [docs/how-it-works/vsockguard.md](../../docs/how-it-works/vsockguard.md)
- Full host setup: [docs/deployment/host-hardening.md](../../docs/deployment/host-hardening.md)

## License

GPL-2.0-only OR BUSL-1.1, at your option. The Linux kernel exposes the BPF
helpers this program needs only to programs whose `license` ELF declaration
is GPL-compatible, so the copy loaded into the kernel is GPL-2.0-only
(`_license[]` is pinned to `"GPL"`); the BSL branch keeps the files aligned
with the rest of the repository. GPL text: [LICENSE-GPL-2.0](LICENSE-GPL-2.0);
BSL text: the root [LICENSE](../../LICENSE). Full notice in the file headers
and the root [NOTICE](../../NOTICE).
