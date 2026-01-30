/* Minimal TLS 1.3 client for bare-metal with WOLFSSL_USER_IO and no RTOS. */

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* POSIX transport helpers (replace with your BSP/port layer).         */
/* ------------------------------------------------------------------ */
static void posix_sleep_ms(int ms)
{
    if (ms <= 0) {
        return;
    }
    usleep((useconds_t)ms * 1000);
}

static int posix_set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int posix_connect_nonblock(int fd, const struct sockaddr* sa,
                                  socklen_t sa_len, int timeout_ms)
{
    int ret = connect(fd, sa, sa_len);
    if (ret == 0) {
        return 0;
    }
    if (ret < 0 && errno != EINPROGRESS) {
        return -1;
    }

    /* Wait for connect to finish. */
    fd_set wfds;
    struct timeval tv;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    ret = select(fd + 1, NULL, &wfds, NULL, &tv);
    if (ret <= 0) {
        return -1;
    }
    if (FD_ISSET(fd, &wfds)) {
        int so_err = 0;
        socklen_t len = sizeof(so_err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &len) < 0) {
            return -1;
        }
        if (so_err != 0) {
            errno = so_err;
            return -1;
        }
        return 0;
    }
    return -1;
}

static int posix_net_connect(const char* host, int port)
{
    char port_str[8];
    struct addrinfo hints;
    struct addrinfo* res = NULL;
    struct addrinfo* it = NULL;
    int fd = -1;
    int ret;

    snprintf(port_str, sizeof(port_str), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        return -1;
    }

    for (it = res; it != NULL; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (posix_set_nonblocking(fd) != 0) {
            close(fd);
            fd = -1;
            continue;
        }
        ret = posix_connect_nonblock(fd, it->ai_addr, (socklen_t)it->ai_addrlen,
                                     5000);
        if (ret == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }

    if (res != NULL) {
        freeaddrinfo(res);
    }
    return fd;
}

/* ------------------------------------------------------------------ */
/* WOLFSSL_USER_IO callbacks.                                          */
/* ------------------------------------------------------------------ */
static int posix_send_cb(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    int fd = (int)(intptr_t)ctx;
    int ret = (int)send(fd, buf, (size_t)sz, 0);
    if (ret >= 0) {
        return ret;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    }
    return WOLFSSL_CBIO_ERR_GENERAL;
}

static int posix_recv_cb(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    int fd = (int)(intptr_t)ctx;
    int ret = (int)recv(fd, buf, (size_t)sz, 0);
    if (ret >= 0) {
        return ret;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }
    return WOLFSSL_CBIO_ERR_GENERAL;
}

int posix_getdevrandom(unsigned char *out, word32 sz)
{
    ssize_t ret;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    ret = read(fd, out, sz);
    close(fd);
    if (ret != (ssize_t)sz) {
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
int tls13_client_run(const char* host, int port)
{
    int ret = -1;
    int net = -1;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    char rx[128];
    char tx[256];
    int tx_len = 0;
    int wouldblock_count = 0;

    net = posix_net_connect(host, port);
    if (net < 0) {
        return -1;
    }

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        return -1;
    }
#ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
#endif

    ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    if (ctx == NULL) {
        goto out;
    }

    /* Bare-metal demo: disable verification unless you load CA/peer certs. */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);

    wolfSSL_SetIORecv(ctx, posix_recv_cb);
    wolfSSL_SetIOSend(ctx, posix_send_cb);

    wolfSSL_CTX_UseSNI(ctx, WOLFSSL_SNI_HOST_NAME, host, strlen(host));

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        goto out;
    }

    wolfSSL_SetIOReadCtx(ssl, (void*)(intptr_t)net);
    wolfSSL_SetIOWriteCtx(ssl, (void*)(intptr_t)net);
    (void)wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, host, (word16)XSTRLEN(host));

    /* Non-blocking style loop. */
    for (;;) {
        ret = wolfSSL_connect(ssl);
        if (ret == WOLFSSL_SUCCESS) {
            break;
        }
        ret = wolfSSL_get_error(ssl, 0);
        if (ret == WC_PENDING_E ||
            ret == WOLFSSL_ERROR_WANT_READ ||
            ret == WOLFSSL_ERROR_WANT_WRITE) {
            if (ret == WOLFSSL_ERROR_WANT_READ ||
                ret == WOLFSSL_ERROR_WANT_WRITE) {
                wouldblock_count++;
            }
            posix_sleep_ms(1);
            continue;
        }
        goto out;
    }

    tx_len = XSNPRINTF(tx, sizeof(tx),
        "GET / HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: wolfSSL-baremetal\r\n"
        "Connection: close\r\n"
        "\r\n",
        host);
    if (tx_len <= 0 || tx_len >= (int)sizeof(tx)) {
        goto out;
    }

    for (;;) {
        ret = wolfSSL_write(ssl, tx, tx_len);
        if (ret > 0) {
            break;
        }
        ret = wolfSSL_get_error(ssl, 0);
        if (ret == WC_PENDING_E ||
            ret == WOLFSSL_ERROR_WANT_READ ||
            ret == WOLFSSL_ERROR_WANT_WRITE) {
            if (ret == WOLFSSL_ERROR_WANT_READ ||
                ret == WOLFSSL_ERROR_WANT_WRITE) {
                wouldblock_count++;
            }
            posix_sleep_ms(1);
            continue;
        }
        goto out;
    }

    XMEMSET(rx, 0, sizeof(rx));
    for (;;) {
        ret = wolfSSL_read(ssl, rx, (int)sizeof(rx) - 1);
        if (ret > 0) {
            rx[ret] = '\0';
            printf("RX: %s\n", rx);
            break;
        }
        ret = wolfSSL_get_error(ssl, 0);
        if (ret == WC_PENDING_E ||
            ret == WOLFSSL_ERROR_WANT_READ ||
            ret == WOLFSSL_ERROR_WANT_WRITE) {
            if (ret == WOLFSSL_ERROR_WANT_READ ||
                ret == WOLFSSL_ERROR_WANT_WRITE) {
                wouldblock_count++;
            }
            posix_sleep_ms(1);
            continue;
        }
        goto out;
    }

    printf("WANT_READ/WRITE count: %d\n", wouldblock_count);
    ret = 0;

out:
    if (ssl != NULL) {
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
    }
    if (ctx != NULL) {
        wolfSSL_CTX_free(ctx);
    }
    wolfSSL_Cleanup();
    if (net >= 0) {
        close(net);
    }
    return ret;
}

#ifndef NO_MAIN_DRIVER
int main(void)
{
    /* Replace host/port with your target. */
    return tls13_client_run("www.google.com", 443);
}
#endif
