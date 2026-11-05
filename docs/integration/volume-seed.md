---
title: Volume-Name Seed Integration
nav_order: 10
parent: Integration
---

# Volume-Name Seed Integration

For the operators and platform teams wiring Sandswap's volume-name seed into
an external secret-management system — HashiCorp Vault, a cloud secrets
manager, a sealed systemd credential, External Secrets Operator, or a plain
deployment script.

Sandswap integrates with **none of them directly**. What it provides is a
channel contract: any system that can atomically place a file (or, on k8s, a
Secret key) where the prov sandlot reads can supply the seed, and the
rotation protocol makes a supply change safe. The mechanism — why the seed
exists, how the derived names keep a compromised FUSE daemon from enumerating
tenants — is the storage contract's volume-naming row in
[Storage](../operations/storage.md) and the isolation layer it belongs to in
[Isolation and swap](../how-it-works/isolation-and-swap.md). This page is the
integration side only: where the files go, what an injector must honour, how
to verify the injection landed, and how rotation works through each channel.
The deployment mechanics live in the seed-channel section of
[Install — Bare Metal](../deployment/install-baremetal.md) and the
seed-rotation runbook in [Install — Kubernetes](../deployment/install-kubernetes.md).

## 1. The one rule that shapes everything: supply ≠ rotate

The seed is the **index key** of every volume's on-disk directory name
(`sf-` + base32(HMAC-SHA256(seed, sandfs_id))[:128 bits]). A value change is
not like rotating a password — it makes every existing volume directory
unresolvable: `delete` answers false success (ENOENT) while the tenant's data
sits in place, and `create` silently builds a second tree for the tenant.

So the two concerns are split by design:

- **The injector SUPPLIES material** — storage, access control, audit,
  cross-host distribution, encryption at rest. All the things a secret
  manager is good at.
- **Only the prov instance MOVES the pointer**, and only through the
  stage → run → promote window driven by `rotate-volume-seed.sh`. The prov
  config (`provision.volume_seed_file` / `volume_seed_next_file`) is the
  single pointer authority; no injector can move it.

Corollary: **never** point the seed at a channel whose value changes on its
own — Vault dynamic secrets with TTL renewal, an ESO refresh that rewrites
values, a CSI rotation poll that swaps file content in place. The seed must
be a static, deliberately-rotated secret.

## 2. The injection contract

Whatever supplies the seed, these five rules are the contract. Sandswap's
runtime guards assume them; breaking one turns a rotation into an outage
(at best) or a silent tenant split (at worst).

1. **One file per generation, at a NEW path.** A rotation adds `gen-N+1`
   beside `gen-N` and the config pointer moves; the file a live generation
   points at is never rewritten. Generation-labeled names (`gen-3`, `gen-4`)
   make that visible in `ls` and in your secret store.
2. **Atomic writes** — temp file in the same directory, then `mv` (or
   `install` to a temp name + `mv`). The instance re-reads on fsnotify within
   ~200 ms and additionally requires two agreeing reads before adopting, so
   a torn or mid-write value is retried, never adopted. But a *stable* torn
   value would look like an ordinary edit — atomicity is what removes the
   whole class.
3. **Scope** `root:sandprov` `0640` (`SANDPROV_GROUP`), directory `0750`. Only
   the prov identity reads it (the prov units carry
   `SupplementaryGroups=… sandprov`); the sandvmm identity (987) must not read
   the seed — every sandvmm spawn replaces its supplementary-group set with
   exactly `microvm.vmm_groups` (`setpriv --groups`, `--clear-groups` when
   empty), so the merged sandlot's sandprov grant is never inherited by the
   VMM/FUSE passthrough daemon — and nobody else may REPLACE it: a
   world-writable parent directory defeats the file's own mode. On k8s the
   mount is the pod's Secret volume (one key per generation).
4. **Never delete a generation file.** An aborted rotation window is
   recovered by re-staging the SAME file; a deleted one orphans the volumes
   already renamed under it.
5. **The seed never travels** in argv (`/proc/<pid>/cmdline` is
   world-readable), in a log line, or in any file the sandvmm identity can
   read. Pipe it; never echo it.

## 3. Channel options

| Channel | Seed lives in | Rest strength | Rotation | Fits |
|---|---|---|---|---|
| Persistent file (default) | `/etc/sandswap/volume-seed`, minted once by the deployer | the file and every copy of it (images, backups) | hot (config pointer moves) | closed labs, single-node |
| **tmpfs fetch** | `/run/sandswap/seed/gen-N`, materialized at boot | nothing on disk; the disk never holds plaintext | hot | bare metal with a secret store reachable at boot |
| **systemd credential** | `$CREDENTIALS_DIRECTORY/gen-N` | ciphertext on disk, bound to this machine (TPM2 or host key) | restart-based | bare metal, no network dependency at boot |
| **k8s Secret** | one key per generation, mounted at `/sandswap-seed/` | etcd (enable encryption-at-rest) | hot (ConfigMap pointer moves) | Kubernetes — every external manager slots in |

All four present the SAME face to the prov instance: a file path named by
`provision.volume_seed_file`. Choosing a channel changes nothing else — the
same config, the same tool, the same guards.

### 3.1 tmpfs fetch (the injection hook)

Copy `deploy/baremetal/seed-fetch.sh.template` to
`/usr/local/lib/sandswap/seed-fetch.sh` (0755 root), replace
`fetch_generation()` with your store's read, and enable the shipped unit:

```bash
install -m 0755 deploy/baremetal/seed-fetch.sh.template /usr/local/lib/sandswap/seed-fetch.sh
$EDITOR /usr/local/lib/sandswap/seed-fetch.sh   # replace fetch_generation()
systemctl enable --now sandswap-seed-fetch.service
```

The template's comment block carries one-line examples for the common
stores (Vault KV v2, AWS Secrets Manager, GCP Secret Manager, a systemd
credential, a sealed file). The unit is a oneshot that runs before the prov
instance and materializes every generation path the config names — the
config tells it WHAT to fetch, your code tells it WHERE from. It is
deliberately not `Requires=`d by the prov unit: a failed fetch must not keep
the instance down — the instance itself refuses to start without a readable
current generation, which is the guard that matters.

Because `/run` is tmpfs, the disk never holds the seed; the fetch re-runs at
every boot. Pair it with the host policies from the same bare-metal section
(no swap, `LimitCORE=0`) — a tmpfs file's pages can still be swapped out.

### 3.2 systemd credential

For hosts where the boot should not depend on reaching a secret store, seal
the generation into a credential and let systemd decrypt it at service
start:

```bash
systemd-creds encrypt --name=gen-3 --with-key=host \
    gen-3.plaintext /etc/credstore.encrypted/gen-3
```

and in the prov unit:

```ini
[Service]
LoadCredentialEncrypted=gen-3:/etc/credstore.encrypted/gen-3
```

The config then points at the fixed path
`/run/credentials/sandswap-sandlot-prov.service/gen-3` — no variable
expansion needed. Requires systemd ≥ 250 (v247 has the credential
framework, v250 the encrypted variant). `--with-key=host` needs nothing
beyond systemd (the host key lands in
`/var/lib/systemd/credential.secret`); the TPM2 variant additionally needs
the tss2 userspace libraries — `systemd-analyze has-tpm2` reports which
half is missing.

Measured properties (systemd 259): the credential file is mode `0400`
root-owned inside a `0500` directory mounted from tmpfs **with `noswap`** —
i.e. the documented "unswappable memory" — another uid's read is denied,
`systemd-creds list` inside the unit classifies it `secure`, and the
directory disappears when the service stops. Rotation is restart-based
(credentials are fixed at service start): the startup generation guard is
what makes that final restart safe.

### 3.3 Kubernetes

The `sandswap-volume-seed` Secret holds **one key per naming generation**
(the legacy first generation keeps the key name `volume-seed`; later ones
are `gen-3`-style). The ConfigMap's `volume_seed_file` /
`volume_seed_next_file` are the pointer, and pointer moves hot-reload — no
`rollout restart`. Any external manager slots in behind the Secret:

- **External Secrets Operator**: set `mergePolicy: Merge` on the
  `ExternalSecret` — ESO's default rewrites the whole `data` map and would
  drop the staged generation key mid-window.
- **Secrets Store CSI driver**: files land in the pod directly; beware
  `secretObjects` sync (it re-creates a Secret behind your back) and give
  `rotationPollInterval` a value only if you also re-point the ConfigMap
  deliberately.
- **Vault Agent Injector / Vault Secrets Operator**: render one file per
  generation into the shared volume; the pod reads files, so no env vars.

Set `SANDSWAP_VOLUME_SEED_NO_MINT=1` on any injected deployment: the
deployer then REFUSES to mint a replacement seed when the Secret is absent
instead of silently orphaning every volume name. The cleanup backs up every
generation key, not just the first.

## 4. Verifying an injection landed

Three independent views, side by side:

```bash
rotate-volume-seed.sh --prov-config /etc/sandswap/sandlot-prov.yaml \
    --human-url https://localhost:3100 --template-tool output/template-tool --status
```

1. **The adoption record** `/run/sandswap/volume-seed-state.json` — what the
   RUNNING instance derived from the configured sources right now:
   fingerprints, the staged generation, per-source resolution state
   (`resolved: false` = your injector has not materialized the file yet),
   and the last refusal. Tooling asserts against this record instead of
   grepping the journal. It is written `0640` (root:`sandprov` when the
   instance runs as root; best-effort scope), contains generation
   FINGERPRINTS and counts only — never a volume directory name or a seed
   value — and is published tmp+fsync+rename.
2. **The fleet view** `GET /stats` → `prov_seeds[]` — every connected prov
   instance's reported generations with `age_sec` (the view lags one
   heartbeat, ~30 s).
3. **The disk** — `template-tool seed-scan` reads every volume's generation
   stamp under the volumes root.

`security/verify-host-security.sh` independently checks every configured
seed path (current AND staged) plus the tmpfs directory mode, and probes
that the sandvmm identity cannot read them.

## 5. Rotating through an injected channel

The window is the same on every channel; only who materializes the new
generation differs.

```bash
rotate-volume-seed.sh ... --rotation on        # sandfs creation refused fleet-wide
rotate-volume-seed.sh ... --maintenance on     # agent traffic refused (503, no restart)
# wait for the drain (/stats in_use → 0)
rotate-volume-seed.sh ... --stage              # tool: mint OR --seed-file <your gen-N+1>
rotate-volume-seed.sh ... --run                # rename every volume + update records
rotate-volume-seed.sh ... --promote            # staged becomes current
rotate-volume-seed.sh ... --rotation off && rotate-volume-seed.sh ... --maintenance off
```

Your injector's only job is step `--stage`: place the new generation at its
NEW path (atomically, correctly scoped) before or as the pointer names it.
Everything after that is verified, not assumed — `--stage` returns only
after the running instance ADOPTED the staged generation (creation actually
frozen), `--run` refuses unless that adoption is visible, `--promote` runs
the completeness gate (the instance refuses a premature promotion
independently, so a config-only promote on k8s is gated server-side), and
`--rotation off` / `--maintenance off` refuse to close the window while any
prov instance still reports the retired generation.

Multi-host fleets: add `--prov-hosts h1,h2` to `--stage`/`--promote` — the
stage fans the SAME generation file to every host (minting per host would
rename different volumes in different directions). On k8s a shared Secret +
ConfigMap give the fan-out for free.

## 6. Troubleshooting

| Symptom | Meaning | Fix |
|---|---|---|
| prov instance start refuses: "carry a naming generation that no configured seed derives" | the startup guard found volumes whose FOREIGN generation no configured seed names — your injected source was replaced, rolled back, or pointed at the wrong generation | point the source back at the generation the stamps carry; or the deliberate re-key path `-allow-seed-generation-mismatch` + the one-time migration |
| prov instance start WARNS: "carry a stamp that could not be authenticated" (start continues) | an UNVERIFIED stamp — unsigned or tampered with (the flat volume root is tenant-writable, so a compromised guest kernel can rewrite it). Not fatal by design: one tampered stamp must not crash-loop the storage plane or hijack a rotation | create/swap and the mount identity check refuse the volume, delete QUARANTINES it, and a promotion refuses the tree; inspect and remove the forged volume, or point the seed back at the generation the tree was created under |
| `ERROR: provision seed change REFUSED … volume_seed changed while a rotation is staged` | the CURRENT generation's value changed outside the window — tampering or a botched injector rewrite | restore the source's previous value; the live instance kept serving the old generation throughout |
| `--stage` fails: "the running prov instance has NOT adopted the staged generation" | the staged file is missing, unreadable by the prov identity, malformed, or a non-atomic writer is mid-write | check `--status`'s `sources[].resolved`; fix scope (`root:sandprov` 0640) or materialize the file |
| `--promote` refuses: "N volume(s) still carry the pre-promote generation" | `--run` has not renamed everything (the daemon refuses this too, independently) | complete `--run` (idempotent); never force the pointer past the gate |
| creates fail `ROTATION_IN_PROGRESS` | the rotation window flag is on | intended; close the window with `--rotation off` after the rotation completes |
| `/stats prov_seeds` shows a stale `age_sec` | that instance stopped heartbeating | it is not evidence of convergence; fix the instance first |

The seed's secrecy is what the name space rests on: treat a suspected
seed leak as a rotation trigger, not a re-mint — re-staging the same
generation files preserves every volume, re-minting orphans all of them.
