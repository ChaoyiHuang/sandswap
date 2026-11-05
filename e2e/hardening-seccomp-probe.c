/* hardening-seccomp-probe — static helper for the guest-kernel / seccomp
 * hardening e2e.
 *
 * Runs inside the agent's chroot and proves:
 *   1. user namespaces are closed at runtime: clone3(CLONE_NEWUSER) does not
 *      succeed (EINVAL/ENOSYS when the kernel compiles USER_NS out; EUSERS/
 *      EPERM when the warden's max_user_namespaces=0 sysctl is live), and
 *      /proc/sys/user/max_user_namespaces is 0 or absent;
 *   2. the class-completeness seccomp denials return EPERM for the raw
 *      syscall numbers (mount_setattr, statmount, listmount, pidfd_open,
 *      pidfd_send_signal, ioprio_set).
 *
 * Output is intentionally one-line-per-check so the shell caller can grep
 * exact tokens. Exit status is 0 only when every check passed.
 *
 * Build: gcc -static -O2 -o hardening_seccomp_probe hardening-seccomp-probe.c
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* x86_64 syscall numbers (the e2e runs on x86_64 guests). */
#ifndef SYS_mount_setattr
#define SYS_mount_setattr 442
#endif
#ifndef SYS_statmount
#define SYS_statmount 454
#endif
#ifndef SYS_listmount
#define SYS_listmount 455
#endif
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal 424
#endif
#ifndef SYS_ioprio_set
#define SYS_ioprio_set 251
#endif
#ifndef SYS_modify_ldt
#define SYS_modify_ldt 154
#endif

/* A denied syscall must return EPERM (the seccomp filter's action). Any other
 * outcome — success, ENOSYS from a wrong number, EINVAL from missing kernel
 * support — is a failure of the probe, because it cannot distinguish "denied
 * by our filter" from "not implemented". */
static int denied(const char *name, long rc)
{
    int e = errno;
    if (rc == -1 && e == EPERM) {
        printf("OK:%s:EPERM\n", name);
        return 0;
    }
    printf("BAD:%s:rc=%ld errno=%d\n", name, rc, e);
    return 1;
}

int main(void)
{
    int bad = 0;

    /* 1a. The runtime sysctl (present on a USER_NS=y kernel; absent when the
     * release kernel compiled USER_NS out — both are acceptable). */
    FILE *f = fopen("/proc/sys/user/max_user_namespaces", "r");
    if (f == NULL) {
        printf("USERNSSYSCTL:ABSENT\n");
    } else {
        char buf[64] = {0};
        if (fgets(buf, sizeof(buf), f) != NULL) {
            buf[strcspn(buf, "\n")] = '\0';
            printf("USERNSSYSCTL:%s\n", buf);
        } else {
            printf("USERNSSYSCTL:READERR\n");
            bad++;
        }
        fclose(f);
    }

    /* 1b. clone3(CLONE_NEWUSER) must NOT succeed. If it does, the parent kills
     * the child and reports BAD; the child exits immediately on success. */
    struct clone_args args;
    memset(&args, 0, sizeof(args));
    args.flags = CLONE_NEWUSER;
    void *stack = malloc(1 << 20);
    if (stack == NULL) {
        printf("BAD:clone3_newuser:no_stack\n");
        bad++;
    } else {
        args.stack = (unsigned long long)stack;
        args.stack_size = 1 << 20;
        long rc = syscall(SYS_clone3, &args, sizeof(args));
        if (rc == -1) {
            printf("OK:clone3_newuser:errno=%d\n", errno);
        } else if (rc == 0) {
            /* Child: a successful userns creation is the failure. */
            _exit(0);
        } else {
            printf("BAD:clone3_newuser:child_pid=%ld\n", rc);
            kill((pid_t)rc, SIGKILL);
            waitpid((pid_t)rc, NULL, 0);
            bad++;
        }
        free(stack);
    }

    /* 2. Class-completeness seccomp denials. The arguments are deliberately
     * invalid: the filter's EPERM must win before the kernel validates them,
     * which also proves the filter sits ahead of the handler. */
    bad |= denied("mount_setattr", syscall(SYS_mount_setattr, -100, "", 0, NULL, 0));
    bad |= denied("statmount", syscall(SYS_statmount, 0, NULL, 0, 0));
    bad |= denied("listmount", syscall(SYS_listmount, 0, NULL, 0, 0));
    bad |= denied("pidfd_open", syscall(SYS_pidfd_open, getpid(), 0));
    bad |= denied("pidfd_send_signal", syscall(SYS_pidfd_send_signal, -1, 0, NULL, 0));
    bad |= denied("ioprio_set", syscall(SYS_ioprio_set, 1, 0, 0));
    bad |= denied("modify_ldt", syscall(SYS_modify_ldt, 0, NULL, 0));

    /* 3. socket(AF_VSOCK) is denied by an argument rule; every other family
     * must stay available (AF_INET is the outbound-network proof). */
    {
        int vfd = socket(AF_VSOCK, SOCK_STREAM, 0);
        if (vfd == -1 && errno == EPERM) {
            printf("OK:vsock_socket:EPERM\n");
        } else {
            if (vfd >= 0) close(vfd);
            printf("BAD:vsock_socket:rc=%d errno=%d\n", vfd, errno);
            bad++;
        }
        int ifd = socket(AF_INET, SOCK_STREAM, 0);
        if (ifd >= 0) {
            printf("OK:inet_socket:allowed\n");
            close(ifd);
        } else {
            printf("BAD:inet_socket:errno=%d\n", errno);
            bad++;
        }
    }

    /* 4. Descriptor hygiene: execve must leave only stdio (+ this directory
     * stream). A non-CLOEXEC fd leaked by the warden (e.g. another exec's
     * pidfd) would show up here. */
    {
        DIR *d = opendir("/proc/self/fd");
        if (d == NULL) {
            printf("BAD:fdhygiene:opendir errno=%d\n", errno);
            bad++;
        } else {
            int dfd = dirfd(d);
            struct dirent *e;
            int extra = 0;
            while ((e = readdir(d)) != NULL) {
                int n;
                if (sscanf(e->d_name, "%d", &n) != 1) continue;
                if (n <= 2 || n == dfd) continue;
                printf("BAD:fdhygiene:leaked_fd=%d\n", n);
                extra++;
            }
            closedir(d);
            if (extra == 0) printf("OK:fdhygiene:only-stdio\n");
            bad += extra;
        }
    }

    printf("HARDENING_PROBE:%s\n", bad ? "FAIL" : "PASS");
    return bad ? 1 : 0;
}
