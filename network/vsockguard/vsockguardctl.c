// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: GPL-2.0-only OR BUSL-1.1
//
// Dual-licensed at your option, matching vsockguard.bpf.c in this
// directory (its header explains why the GPL branch exists):
//
//   - GPL-2.0-only (text: LICENSE-GPL-2.0 in this directory).
//
//   - BUSL-1.1: use of this software is governed by the Business Source
//     License included in the LICENSE file at the root of this repository.
//     As of the Change Date specified in that file, in accordance with
//     the Business Source License, use of this software will be governed
//     by the Apache License, Version 2.0.
//
// vsockguardctl — control tool for the vsockguard BPF LSM program.
// vsockguard is a BPF LSM hook on socket_connect that denies connect() to the
// AF_VSOCK warden port (1024) for every UID except the sandlot service UID.
// This tool loads + attaches it (and detaches it) — a thin libbpf wrapper
// around bpf_program__attach_lsm (the only way to attach BPF_PROG_TYPE_LSM;
// it issues BPF_LINK_CREATE, which bpftool v7.x does not expose as a
// subcommand). "ctl" = control: it does both attach and detach, not just load.
// Usage:
//   vsockguardctl attach <vsockguard.bpf.o> <uid> <prog_pin> <link_pin> <map_pin>
//     Opens the object, loads it (resolving the lsm/socket_connect BTF id),
//     writes <uid> into the allowed_uid map (key 0), attaches the LSM link, and
//     pins prog + link + map so they survive this process exiting.
//   vsockguardctl detach <link_pin> <prog_pin> <map_pin>
//   vsockguardctl status <map_pin>
//     prints the pinned allowed_uid (key 0); exits non-zero when the map is
//     not pinned. Read-only — used by the verify script so it never has to
//     attach/detach a production pin.
//     Detaches the link (via its pin) and removes all pins.
// Requires: CAP_BPF + CAP_SYS_ADMIN, and the `bpf` LSM active
// (/sys/kernel/security/lsm must list `bpf`). If attach fails with EPERM/EINVAL
// and `bpf` is absent, the operator must run security/setup-bpf-lsm.sh once and
// reboot. Build: see build/build.sh (build_vsockguard).

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define PROG_NAME  "vsockguard_socket_connect"
#define MAP_NAME   "allowed_uid"
#define MAP_KEY    0u
#define LSM_LIST   "/sys/kernel/security/lsm"

/* Returns 1 if the `bpf` LSM is active. Without it, bpf_lsm_socket_connect is
 * never registered, so an attached program is a SILENT no-op — the link pins
 * fine but connect() is never denied. We refuse to attach in that state rather
 * than give a false sense of enforcement. */
static int bpf_lsm_active(void)
{
    FILE *f = fopen(LSM_LIST, "r");
    char buf[512];
    int found = 0;
    if (!f)
        return 0;
    if (fgets(buf, sizeof(buf), f)) {
        char *p = buf;
        /* match "bpf" as a whole comma-separated token */
        while (*p) {
            char *tok = p;
            char *comma = strchr(p, ',');
            if (comma)
                *comma = '\0';
            if (strcmp(tok, "bpf") == 0) {
                found = 1;
                break;
            }
            if (!comma)
                break;
            p = comma + 1;
        }
    }
    fclose(f);
    return found;
}

static int do_attach(const char *obj_path, unsigned int uid,
                     const char *prog_pin, const char *link_pin,
                     const char *map_pin)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    struct bpf_map *map;
    struct bpf_link *link;
    int err;

    if (!bpf_lsm_active()) {
        fprintf(stderr,
            "vsockguard: REFUSING to attach — the `bpf` LSM is not active.\n"
            "  An attached program would be a silent no-op (the link pins but\n"
            "  connect() is never denied). Enable it ONCE:\n"
            "    sudo bash security/setup-bpf-lsm.sh   # adds bpf to lsm= boot param\n"
            "    sudo reboot\n"
            "  Then re-run attach. Verify with: cat %s\n",
            LSM_LIST);
        return 1;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    obj = bpf_object__open_file(obj_path, NULL);
    if (!obj) {
        fprintf(stderr, "vsockguard: open %s failed: %s\n",
                obj_path, strerror(errno));
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "vsockguard: load failed: %s\n", strerror(-err));
        bpf_object__close(obj);
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, PROG_NAME);
    map = bpf_object__find_map_by_name(obj, MAP_NAME);
    if (!prog || !map) {
        fprintf(stderr, "vsockguard: missing prog '%s' or map '%s' in %s\n",
                PROG_NAME, MAP_NAME, obj_path);
        bpf_object__close(obj);
        return 1;
    }

    /* Seed the allowed UID before attaching so the filter is never fail-open
     * (well, fail-open only in the unreachable no-map branch). */
    __u32 key = MAP_KEY, val = uid;
    err = bpf_map_update_elem(bpf_map__fd(map), &key, &val, BPF_ANY);
    if (err) {
        fprintf(stderr, "vsockguard: set allowed_uid=%u failed: %s\n",
                uid, strerror(-err));
        bpf_object__close(obj);
        return 1;
    }

    /* Pin prog + map first so they persist once we pin the link and exit. */
    err = bpf_program__pin(prog, prog_pin);
    if (err && errno != EEXIST) {
        fprintf(stderr, "vsockguard: pin prog %s failed: %s\n",
                prog_pin, strerror(-err));
        bpf_object__close(obj);
        return 1;
    }
    err = bpf_map__pin(map, map_pin);
    if (err && errno != EEXIST) {
        fprintf(stderr, "vsockguard: pin map %s failed: %s\n",
                map_pin, strerror(-err));
        bpf_object__close(obj);
        return 1;
    }

    link = bpf_program__attach_lsm(prog);
    if (!link) {
        err = errno;
        fprintf(stderr,
                "vsockguard: attach lsm/socket_connect failed: %s\n",
                strerror(err));
        if (err == EPERM || err == EINVAL) {
            fprintf(stderr, "  hint: the `bpf` LSM is not active. Check:\n"
                    "    cat /sys/kernel/security/lsm\n"
                    "  If `bpf` is absent, run security/setup-bpf-lsm.sh and "
                    "reboot, then re-attach.\n");
        }
        bpf_object__close(obj);
        return 1;
    }

    err = bpf_link__pin(link, link_pin);
    if (err && errno != EEXIST) {
        fprintf(stderr, "vsockguard: pin link %s failed: %s\n",
                link_pin, strerror(errno));
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 1;
    }
    if (err && errno == EEXIST) {
        /* A stale pin from a prior unclean run. The attach script is supposed
         * to detach first, but if a pin survived, unlink it and re-pin the
         * freshly attached link so the pin matches reality. */
        unlink(link_pin);
        err = bpf_link__pin(link, link_pin);
        if (err) {
            fprintf(stderr, "vsockguard: re-pin link %s failed: %s\n",
                    link_pin, strerror(errno));
            bpf_link__destroy(link);
            bpf_object__close(obj);
            return 1;
        }
    }

    printf("vsockguard: attached (allowed_uid=%u); pins:\n  %s\n  %s\n  %s\n",
           uid, prog_pin, link_pin, map_pin);
    bpf_link__disconnect(link); /* keep link alive via pin after close */
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}

static int do_status(const char *map_pin)
{
    int fd = bpf_obj_get(map_pin);
    if (fd < 0) {
        fprintf(stderr, "vsockguard: no map pin at %s\n", map_pin);
        return 1;
    }
    unsigned int key = 0, val = 0;
    if (bpf_map_lookup_elem(fd, &key, &val) != 0) {
        fprintf(stderr, "vsockguard: map lookup at %s: %s\n", map_pin, strerror(errno));
        close(fd);
        return 1;
    }
    printf("%u\n", val);
    close(fd);
    return 0;
}

static int do_detach(const char *link_pin, const char *prog_pin,
                     const char *map_pin)
{
    /* bpf_link__open takes the pin path; destroy detaches + unpins the link.
     * Unlink all pins afterward as belt-and-suspenders: a detach during an
     * unclean shutdown can leave a stale link pin that bpf_link__destroy did
     * not remove. */
    struct bpf_link *link = bpf_link__open(link_pin);
    if (link) {
        bpf_link__destroy(link);
    } else {
        fprintf(stderr, "vsockguard: no link pin at %s — already detached?\n",
                link_pin);
    }
    unlink(link_pin);
    unlink(prog_pin);
    unlink(map_pin);
    printf("vsockguard: detached; removed pins %s %s %s\n",
           link_pin, prog_pin, map_pin);
    return 0;
}

int main(int argc, char **argv)
{
    /* attach <obj> <uid> <prog_pin> <link_pin> <map_pin>  → 7 args total */
    if (argc == 7 && strcmp(argv[1], "attach") == 0) {
        char *end;
        unsigned long uid = strtoul(argv[3], &end, 10);
        if (*end != '\0') {
            fprintf(stderr, "vsockguard: invalid uid '%s'\n", argv[3]);
            return 2;
        }
        return do_attach(argv[2], (unsigned int)uid, argv[4], argv[5], argv[6]);
    }

    /* detach <link_pin> <prog_pin> <map_pin>  → 5 args total */
    if (argc == 5 && strcmp(argv[1], "detach") == 0) {
        return do_detach(argv[2], argv[3], argv[4]);
    }

    /* status <map_pin>  → 3 args total */
    if (argc == 3 && strcmp(argv[1], "status") == 0) {
        return do_status(argv[2]);
    }

    fprintf(stderr,
        "usage:\n"
        "  %s attach <vsockguard.bpf.o> <uid> <prog_pin> <link_pin> <map_pin>\n"
        "  %s detach <link_pin> <prog_pin> <map_pin>\n"
        "  %s status <map_pin>\n",
        argv[0], argv[0], argv[0]);
    return 2;
}
