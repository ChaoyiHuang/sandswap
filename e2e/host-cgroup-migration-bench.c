// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0.

/*
 * host-cgroup-migration-bench.c — reference baseline for cgroup v2 task
 * migration cost on the BARE-METAL host kernel.
 *
 * Why this exists: inside KVM microVMs, a real cgroup v2 task migration
 * (writing a pid into cgroup.procs) measured 8-20 ms on CH v6.2 AND v6.16.9
 * guest kernels, while the identical operation on the bare-metal host kernel
 * takes ~5 µs (first migration ~5 ms — one-time lazy init). That 1000x gap
 * is what pushed the per-exec migration off the sync-exec hot path.
 *
 * Re-run this when the host kernel or KVM changes to refresh the baseline,
 * or after a guest-kernel upgrade to re-check whether the guest-side cost
 * has converged (if it ever does, the sync-exec cgroup membership — and its
 * transient memory cap — can be reconsidered).
 *
 * Build & run:  gcc -O2 -o /tmp/cgmig e2e/host-cgroup-migration-bench.c && /tmp/cgmig
 * (root required: mkdir + writes under /sys/fs/cgroup)
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

int main(void) {
    const char *cg = "/sys/fs/cgroup/sstest";
    char buf[64], path[128];
    mkdir(cg, 0755);

    /* A settled, sleeping child to migrate back and forth. */
    pid_t pid = fork();
    if (pid == 0) {
        execl("/bin/sleep", "sleep", "30", NULL);
        _exit(1);
    }
    usleep(100000);

    int n = snprintf(buf, sizeof buf, "%d\n", pid);
    snprintf(path, sizeof path, "%s/cgroup.procs", cg);

    for (int i = 0; i < 5; i++) {
        int fd = open(path, O_WRONLY);
        if (fd < 0) { perror("open cgroup.procs (not root? no cgroup v2?)"); return 1; }
        double t0 = now_ms();
        if (write(fd, buf, n) < 0) { perror("write"); return 1; }
        double t1 = now_ms();
        close(fd);

        int rfd = open("/sys/fs/cgroup/cgroup.procs", O_WRONLY);
        double t2 = now_ms();
        if (write(rfd, buf, n) < 0) { perror("write root"); return 1; }
        double t3 = now_ms();
        close(rfd);

        printf("iter %d: migrate_in=%.3fms  migrate_out=%.3fms\n", i, t1 - t0, t3 - t2);
    }

    kill(pid, 9);
    waitpid(pid, NULL, 0);
    rmdir(cg);
    printf("(first iter includes one-time lazy init; steady-state is the baseline)\n");
    return 0;
}
