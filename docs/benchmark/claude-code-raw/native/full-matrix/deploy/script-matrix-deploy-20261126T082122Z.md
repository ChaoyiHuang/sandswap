# Script matrix — every .sh under deploy/

Generated 2026-11-26T08:21:22Z · repo 1e5cf6e95e6b · tree_dirty=0 · boot `6ab23126`
Heads (row counts): 1e5cf6e95e6b=36
Enumerated **36** scripts · rows **36** · BLOCKED-PRODUCT=1 · PASS=35

| script | class | verdict | secs | reason / finding |
|---|---|---|---|---|
| `deploy/baremetal/cleanup.sh` | C | PASS | 2 |  |
| `deploy/baremetal/common.sh` | F | PASS | 0 | library — validated through deploy/baremetal/sandswap-ops.sh |
| `deploy/baremetal/deploy-cluster-multi-gw-simulation.sh` | H | PASS | 39 |  |
| `deploy/baremetal/deploy-cluster-multi-gw.sh` | E | PASS | 1 |  |
| `deploy/baremetal/deploy-cluster-one-gw-simulation.sh` | H | PASS | 18 | residue:units:sandswap-gateway@exec.service sandswap-gateway@human.service sandswap-network.service sandswap-sandlot-instance@sl1.service sandswap-sandlot-instance@sl2.service sandswap-sandlot-prov.service ,taps:tap-9b6cc72afc tap-4c90fefae0 ,ports::2379 :2380 :3000 :3100 :9996 :9998 |
| `deploy/baremetal/deploy-cluster-one-gw.sh` | H | PASS | 9 | residue:units:sandswap-etcd.service sandswap-gateway@exec.service sandswap-gateway@human.service sandswap-network.service sandswap-sandlot-prov.service sandswap-sandlot.service sandswap-vsock-retune.service ,taps:tap-c67bfb4c60 tap-213f495dd7 ,ports::2379 :2380 :3000 :3100 :9996 :9998 |
| `deploy/baremetal/deploy-egress-enabler.sh` | C | PASS | 154 |  |
| `deploy/baremetal/deploy-lib.sh` | F | PASS | 0 | library — validated through deploy/baremetal/verify-failover.sh |
| `deploy/baremetal/deploy-one-machine-etcd.sh` | H | PASS | 18 |  |
| `deploy/baremetal/deploy-single-node.sh` | H | PASS | 15 | residue:units:sandswap-gateway.service sandswap-network.service sandswap-sandlot.service ,taps:tap-1ee2485074 tap-1a3a7a4eb3 tap-d7d905a43d ,ports::3000 :3100 :9998 |
| `deploy/baremetal/gen-baremetal-certs.sh` | C | PASS | 2 |  |
| `deploy/baremetal/rotate-volume-seed.sh` | B | PASS | 0 |  |
| `deploy/baremetal/sandswap-apply-prov-ownership.sh` | C | PASS | 0 |  |
| `deploy/baremetal/sandswap-ops.sh` | B | PASS | 0 |  |
| `deploy/baremetal/setup-host.sh` | C | PASS | 2 | residue:units:sandswap-network.service |
| `deploy/baremetal/uninstall.sh` | C | PASS | 6 |  |
| `deploy/baremetal/verify-binpack.sh` | C | PASS | 89 | residue:taps:tap-e38d89f6c6 tap-5d650c51d1 tap-dc55ea8852 tap-0bbd4eafd2 tap-a41ad92ef6 tap-911e2c69ff |
| `deploy/baremetal/verify-cert-rotation.sh` | B | PASS | 33 |  |
| `deploy/baremetal/verify-eino.sh` | B | PASS | 88 |  |
| `deploy/baremetal/verify-etcd-fence.sh` | B | PASS | 44 |  |
| `deploy/baremetal/verify-failover.sh` | C | PASS | 106 | residue:taps:tap-1ee2485074 |
| `deploy/baremetal/verify-negative-path.sh` | B | PASS | 6 |  |
| `deploy/gen-certs.sh` | C | PASS | 3 |  |
| `deploy/k8s/build-images.sh` | C | PASS | 31 |  |
| `deploy/k8s/deploy-k8s-boxout.sh` | K | PASS | 76 |  |
| `deploy/k8s/deploy-k8s-egress-enabler.sh` | K | PASS | 256 |  |
| `deploy/k8s/deploy-k8s-embedded.sh` | K | PASS | 429 |  |
| `deploy/k8s/deploy-lib.sh` | F | PASS | 0 | library — validated through deploy/k8s/deploy-k8s-embedded.sh |
| `deploy/k8s/gen-k8s-certs.sh` | C | PASS | 1 |  |
| `deploy/k8s/images/boxout-entrypoint.sh` | F | PASS | 0 | library — validated through deploy/k8s/deploy-k8s-boxout.sh |
| `deploy/k8s/images/sandlot-entrypoint.sh` | F | PASS | 0 | library — validated through deploy/k8s/deploy-k8s-embedded.sh |
| `deploy/k8s/k8s-cleanup.sh` | C | PASS | 0 |  |
| `deploy/k8s/k8s-host-setup.sh` | C | BLOCKED-PRODUCT | 0 | expected-refusal: boxout uid pin: host sandlot uid=985 != 65536 (combined dev host; k8s legs unaffected) |
| `deploy/k8s/verify-k8s.sh` | K | PASS | 144 |  |
| `deploy/run-matrix.sh` | F | PASS | 0 | library — validated through deploy/baremetal/deploy-single-node.sh |
| `deploy/setup-network.sh` | C | PASS | 0 |  |

## Self-check

- enumerated == rows: **True** (36 enumerated, 36 rows)
- missing: none
- duplicate: none
- library rows without a consumer verdict: none
