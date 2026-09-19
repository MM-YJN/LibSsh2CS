/*
 * libssh2 capture harness — increment 5 oracle.
 *
 * Produces, for one SSH session pinned to a single cipher/MAC/kex/hostkey combo:
 *   - on stderr (gated by LIBSSH2_PACKET_DUMP env var): "PKTDUMP KEY <letter> <len> <hex...>"
 *     for each of the 6 RFC 4253 derived keys (A-F).
 *   - via the libssh2 trace handler (LIBSSH2_TRACE_TRANS): hexdump-formatted
 *     plaintext + ciphertext of every packet, four channels:
 *       "libssh2_transport_write plain"   / "plain2"  — outbound plaintext (pre-encrypt)
 *       "libssh2_transport_write send()"             — outbound ciphertext (post-encrypt)
 *       "libssh2_transport_read() raw"                — inbound ciphertext (raw socket)
 *       "libssh2_transport_read() plain"             — inbound plaintext (post-decrypt)
 *
 * The trace handler writes one "TRACE: <line>" per libssh2 trace call to stdout
 * (flushed). The orchestrator script parses both streams into per-mode fixture
 * files. This harness asserts nothing — it is a data producer.
 *
 * Build: gcc -I<libssh2-include> -L<libssh2-cap-lib> capture.c -lssh2 -lcrypto -lssl
 * Run:   LIBSSH2_PACKET_DUMP=1 LD_LIBRARY_PATH=<lib> ./capture <args>
 *
 * NOT shipped as a build artifact of the C# test project — it is a one-shot
 * fixture generator invoked by generate-goldens.sh. The committed artifacts
 * are the resulting fixture files under tests/LibSsh2CS.UnitTests/Fixtures/packet/.
 */

#include <libssh2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static void trace_cb(LIBSSH2_SESSION *s, void *ctx,
                     const char *data, size_t length)
{
    /* Emit every trace line prefixed with "TRACE: " so the parser can split
     * them unambiguously. libssh2 does not always newline-terminate, so add one. */
    fputs("TRACE: ", stdout);
    fwrite(data, 1, length, stdout);
    if(length == 0 || data[length - 1] != '\n') {
        fputc('\n', stdout);
    }
    fflush(stdout);
}

static int tcp_connect(const char *host, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0) { return -1; }
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    if(inet_pton(AF_INET, host, &a.sin_addr) != 1) { close(fd); return -1; }
    if(connect(fd, (struct sockaddr*)&a, sizeof(a)) != 0) { close(fd); return -1; }
    return fd;
}

static void set_pref(LIBSSH2_SESSION *s, int method, const char *value)
{
    if(value && value[0]) {
        libssh2_session_method_pref(s, method, value);
    }
}

int main(int argc, char **argv)
{
    /* Args: host port user privkey cipher mac kex hostkey payload */
    if(argc != 10) {
        fprintf(stderr, "usage: %s host port user privkey cipher mac kex hostkey payload\n",
                argv[0]);
        return 99;
    }
    const char *host = argv[1];
    int port = atoi(argv[2]);
    const char *user = argv[3];
    const char *privkey = argv[4];
    const char *cipher = argv[5];
    const char *mac = argv[6];
    const char *kex = argv[7];
    const char *hostkey = argv[8];
    const char *payload = argv[9];

    libssh2_init(0);

    int fd = tcp_connect(host, port);
    if(fd < 0) { fprintf(stderr, "connect failed\n"); return 1; }

    LIBSSH2_SESSION *s = libssh2_session_init_ex(NULL, NULL, NULL, NULL);
    libssh2_session_set_blocking(s, 1);
    libssh2_trace_sethandler(s, NULL, trace_cb);
    libssh2_trace(s, LIBSSH2_TRACE_TRANS);

    /* Pin algorithms BEFORE the handshake. Empty string = use default. */
    set_pref(s, 0, kex);       /* LIBSSH2_METHOD_KEX */
    set_pref(s, 1, hostkey);   /* LIBSSH2_METHOD_HOSTKEY */
    set_pref(s, 2, cipher);    /* LIBSSH2_METHOD_CRYPT_CS */
    set_pref(s, 3, cipher);    /* LIBSSH2_METHOD_CRYPT_SC */
    set_pref(s, 4, mac);       /* LIBSSH2_METHOD_MAC_CS */
    set_pref(s, 5, mac);       /* LIBSSH2_METHOD_MAC_SC */

    int rc = libssh2_session_handshake(s, fd);
    if(rc != 0) {
        char *e = NULL;
        libssh2_session_last_error(s, &e, NULL, 0);
        fprintf(stderr, "HANDSHAKE_FAIL rc=%d (%s) cipher=%s mac=%s kex=%s\n",
                rc, e ? e : "?", cipher, mac, kex);
        return 2;
    }
    fprintf(stderr, "HANDSHAKE_OK kex=%s crypt=%s mac=%s hostkey=%s\n",
            libssh2_session_methods(s, 0), libssh2_session_methods(s, 3),
            libssh2_session_methods(s, 5), libssh2_session_methods(s, 1));

    rc = libssh2_userauth_publickey_fromfile(s, user, NULL, privkey, NULL);
    if(rc != 0) {
        fprintf(stderr, "AUTH_FAIL rc=%d\n", rc);
        return 3;
    }
    fprintf(stderr, "AUTH_OK\n");

    LIBSSH2_CHANNEL *ch = libssh2_channel_open_session(s);
    if(!ch) { fprintf(stderr, "OPEN_FAIL\n"); return 4; }

    rc = libssh2_channel_exec(ch, payload);
    if(rc != 0) { fprintf(stderr, "EXEC_FAIL rc=%d\n", rc); return 5; }

    char buf[256];
    ssize_t n;
    while((n = libssh2_channel_read(ch, buf, sizeof(buf))) > 0) {
        /* drain — we only care about the packets, not the payload text */
    }
    int exitcode = libssh2_channel_get_exit_status(ch);
    fprintf(stderr, "EXEC_EXIT=%d\n", exitcode);

    libssh2_channel_free(ch);
    libssh2_session_disconnect(s, "capture done");
    libssh2_session_free(s);
    close(fd);
    libssh2_exit();
    return 0;
}