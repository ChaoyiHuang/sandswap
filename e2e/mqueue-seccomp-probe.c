/* mqueue-seccomp-probe — tiny static helper for the cross-tenant mqueue seccomp-denial test.
 *
 * The guest template's Python is statically linked and its CDLL(None) mq_open
 * differs from the glibc the black-box C probe used; a compiled static glibc
 * helper gives the test a real mq_open. Usage:
 *   mqueue-seccomp-probe send <name> <secret>   create + send (exit 0)
 *   mqueue-seccomp-probe recv <name>            open + receive; prints LEAK:<data> (exit 0)
 *                                  or mq_open_ro: ENOENT (exit 2) when swept
 */
#include <errno.h>
#include <fcntl.h>
#include <mqueue.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s send|recv <name> [secret]\n", argv[0]);
        return 64;
    }
    if (!strcmp(argv[1], "send")) {
        if (argc < 4) return 64;
        struct mq_attr a = {0};
        a.mq_maxmsg = 10;
        a.mq_msgsize = 256;
        mqd_t q = mq_open(argv[2], O_CREAT | O_RDWR, 0600, &a);
        if (q == (mqd_t)-1) { perror("mq_open"); return 1; }
        if (mq_send(q, argv[3], strlen(argv[3]) + 1, 1) != 0) {
            perror("mq_send");
            mq_close(q);
            return 1;
        }
        mq_close(q);
        return 0;
    }
    if (!strcmp(argv[1], "recv")) {
        mqd_t q = mq_open(argv[2], O_RDONLY);
        if (q == (mqd_t)-1) {
            printf("mq_open_ro: %s\n", strerror(errno));
            return 2;
        }
        char buf[256];
        ssize_t n = mq_receive(q, buf, sizeof(buf), NULL);
        if (n < 0) {
            printf("mq_receive: %s\n", strerror(errno));
            mq_close(q);
            return 3;
        }
        printf("LEAK:%s\n", buf);
        mq_close(q);
        return 0;
    }
    return 64;
}
