---
title: Benchmark
nav_order: 3
has_children: true
permalink: /benchmark/
---

# Benchmark

Measured performance reports. Numbers are snapshots tied to the hardware and
build noted in each report — not guarantees.

1. **[Benchmark Report — Bare Metal](baremetal.md)** — the reference
   numbers: end-to-end HTTP/MCP latencies and per-stage breakdowns
   on TencentOS bare metal, measured with the host stack and each microVM
   CPU/NUMA-pinned (`e2e/pin.sh`).
2. **[Benchmark Report — Nested-virt](nested-virt.md)** — the same benchmark
   suite inside a GCP VM, with the measured why-it's-slower analysis.
   Nested-virt runs are never pinned (the L1 vCPUs are already
   outer-scheduled).
3. **[Benchmark Report — Bare Metal: microVM Reuse Capacity](baremetal-load.md)** —
   the bare-metal capacity report: the ideal paced-lane test, the
   traffic-shaped test and the realistic AI agent model, each in pure-cold
   and mixed-turn shapes, with distinct whole-core allocations for loadgen /
   gateway / sandlot and the microVM pool. The physical-core mapping is the
   recommendation; the logical-core (SMT) mapping is a control (it halves the
   per-VM rate and adds no host capacity). Results are reported at three
   latency tiers (1.05x / 1.5x / 2x of the no-load baseline) with the absolute
   millisecond budgets. Raw logs are in `baremetal-load-raw/` beside the report.
4. **[Benchmark Report — Nested-virt: microVM Reuse Capacity](nested-virt-load.md)** —
   three models on the same two-microVM host: the ideal paced-lane test
   (one lane per microVM, continuously fed), the traffic-shaped test (a
   full agent population queued per lane, one in-flight request per VM),
   and the realistic AI agent business capacity (0.9-1.5 s
   think time, 1-3 requests per turn, warm follow-ups inside the 1 ms
   sticky window, busy refusals retried like a real agent). Reports
   per-microVM and host cold reuses/s for each, the 1x/2x business
   capacity, and why a small nested host understates a production pool or
   fleet.
5. **[Reproducing the Benchmarks](reproducing.md)** — two ways to run the
   benchmark scripts yourself: the full developer build, or the prebuilt
   release package (no toolchain; benchmark scripts are bundled in the
   release tarball).
