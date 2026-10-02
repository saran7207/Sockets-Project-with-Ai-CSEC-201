#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define BUF_SIZE 1048576

int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int b64_decode(const char *in, unsigned char *out) {
    int val = 0, bits = -8, n = 0;
    for (; *in && *in != '='; in++) {
        int d = b64_val(*in);
        if (d < 0) continue;
        val = (val << 6) | d;
        bits += 6;
        if (bits >= 0) {
            out[n++] = (unsigned char)((val >> bits) & 0xFF);
            bits -= 8;
        }
    }
    return n;
}

int main(int argc, char *argv[]) {
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    int port = argc > 2 ? atoi(argv[2]) : 5050;

    int sock = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    inet_pton(AF_INET, host, &server.sin_addr);

    connect(sock, (struct sockaddr *)&server, sizeof(server));

    static char buf[BUF_SIZE];
    static unsigned char decoded[BUF_SIZE];

    /* SETUP PHASE: unsecured only */
    char *hello = "SS,RFMP,v1.0,0";
    send(sock, hello, strlen(hello), 0);

    int n = recv(sock, buf, BUF_SIZE - 1, 0);
    buf[n] = '\0';
    printf("Server said: %s\n", buf);

    char filename[256];
    printf("Filename to read: ");
    scanf("%255s", filename);

    /* OPERATION PHASE: only openRead */
    char cmd[300];
    snprintf(cmd, sizeof(cmd), "CM,openRead,%s", filename);
    send(sock, cmd, strlen(cmd), 0);

    n = recv(sock, buf, BUF_SIZE - 1, 0);
    buf[n] = '\0';

    if (strncmp(buf, "EE,", 3) == 0) {
        printf("Server error: %s\n", buf + 3);
    } else if (strncmp(buf, "DP,", 3) == 0) {
        int len = b64_decode(buf + 3, decoded);
        printf("----- FILE CONTENT -----\n");
        fwrite(decoded, 1, len, stdout);
        printf("\n-------------------------\n");
    } else {
        printf("Unexpected: %s\n", buf);
    }

    /* CLOSING PHASE */
    send(sock, "EN", 2, 0);
    close(sock);
    return 0;
}