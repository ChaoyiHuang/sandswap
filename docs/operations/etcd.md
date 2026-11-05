---
title: etcd
nav_order: 3
parent: Operations
---

# etcd

Multi-gateway Sandswap coordinates through etcd: ownership records
(`/sandswap/owner/`, one key per sandfs), gateway health / load / routing
registry (one key per gateway), and node presence keys (one per sandlot).
Steady-state writes are **zero per execution cycle** by design (placement CAS
fires only on real placement changes), so etcd load is dominated by reads and
by fleet churn — but the **revision history grows without bound unless
compacted**, and the default 2GB quota eventually trips `NOSPACE`, which makes
etcd refuse writes and the whole control plane fail closed (every gateway
503s). This page is the lifecycle runbook: size it, compact it, back it up.

## 1. Sizing

| Fleet scale | Ownership keys | Live data | Suggested quota |
|---|---|---|---|
| 10K sandfs | 10K | ~2-3 MB | default 2G |
| 100K sandfs | 100K | ~20-30 MB | 4G |
| 1M sandfs | 1M | ~200-300 MB | 8G |

Live data is small; the quota budget is consumed by **revision history** (every
put/delete retains its old revision until compaction) and by the identity
prefix when agents/sandfs records are counted (etcd-backed identity store adds
its own keys — roughly the agent + sandfs count again).

```
--quota-backend-bytes=8G          # 1M-sandfs reference; leaves compaction slack
```

Read load (the other sizing axis): the gateways' Claim revalidation is
linearizable — `Gets/s ≈ actively-queried sandfs ÷ -ownership-cache-ttl-sec`
(default 30s ⇒ ~3.3K gets/s at 100K active). Adding exec gateways does NOT
divide this (each sandfs has exactly one owner gateway); raise the TTL to
lower it. sandns's owner lookups are serializable and already TTL-cached
(30s default).

## 2. Compaction

Enable auto-compaction on every member — the code handles `ErrCompacted`
gracefully (the ownership watch falls back to watching from the current
revision and the per-key cache TTLs self-heal the gap; sandns re-lists every
30s), so periodic compaction is **safe for correctness**:

```
--auto-compaction-revision=10000   # keep the last 10k revisions
```

Bounded history keeps the backend file from growing forever AND keeps
watch-replay windows short. If you prefer time-based, `--auto-compaction=1h`
is equivalent for this workload.

## 3. Defragmentation

Compaction releases revisions logically; the disk space is returned only by
defrag. Low-traffic maintenance, one member at a time (a member undergoing
defrag briefly serves stale data):

```bash
etcdctl --endpoints=<member> defrag
etcdctl endpoint status --write-out=table   # watch DB SIZE drop per member
```

Run after large fleet churn (bulk sandfs deletion, mass takeover events), not
on a schedule.

## 4. Backup and restore

```bash
etcdctl snapshot save /backup/etcd-$(date +%F).snap
etcdctl snapshot status /backup/etcd-$(date +%F).snap --write-out=table
```

Restore into a fresh cluster (all members restore the SAME snapshot):

```bash
etcdutl snapshot restore /backup/etcd-YYYY-MM-DD.snap \
  --data-dir /var/lib/etcd-restore-0 --name etcd-0 \
  --initial-cluster etcd-0=https://etcd-0:2380,... \
  --initial-advertise-peer-urls https://etcd-0:2380
```

After a restore, ownership keys are as-of the snapshot: gateways re-derive
liveness from their health keys, and the tolerance-first takeover rules
resolve any stale records the same way they resolve a crashed gateway — no
manual key surgery.

## 5. NOSPACE recovery

Symptom: gateways log health-key write failures, claims fail closed
(cluster-wide 503s), `etcdctl alarm list` shows `NOSPACE`.

```bash
etcdctl alarm list
etcdctl compact <current_revision>        # etcdctl endpoint status --write-out=json
etcdctl defrag                            # per member
etcdctl alarm disarm
```

Then raise the quota / verify auto-compaction is actually enabled, or the
alarm re-trips.

## 6. Host requirements

- **NTP/chrony discipline on every gateway and sandns host** — liveness is judged
  by cross-host timestamps (`last_healthy_ts` is written with the gateway's
  clock and compared with the reading host's clock). See
  [Deployment Prerequisites](../deployment/prerequisites.md).
- Odd member count (3 or 5), spread across failure domains; NVMe class storage
  — Claim revalidations are linearizable (quorum) reads.
