#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")   // tells MSVC to link the Winsock library

#define BUF_SIZE 1048576   /* generous one-shot recv() size, same idea as BUF in the Python files */

/* Maps one base64 character to the 6-bit value it represents.
   Returns -1 for anything that isn't a valid base64 character (like '='). */
int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* C has no built-in base64 decoder (unlike Python's base64.b64decode), so we
   write it by hand. base64 packs data 6 bits at a time (64 possible symbols
   = 2^6), while real bytes are 8 bits each - so 4 base64 characters always
   carry exactly 3 real bytes (4*6 = 3*8 = 24 bits).
   `val` accumulates bits as each character comes in; the moment we have 8
   or more unspent bits sitting in it, we peel off one whole byte and write
   it to `out`. Returns how many real bytes were decoded. */
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
    /* Defaults to localhost:5050 but can be overridden: client.exe <ip> <port> */
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    int port = argc > 2 ? atoi(argv[2]) : 5050;

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    /* Windows-only step with no Python/Linux equivalent: Windows requires
       you to explicitly "turn on" its networking subsystem (Winsock)
       before any socket call will work at all. */

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);   /* AF_INET = IPv4, SOCK_STREAM = TCP */

    /* Building the address by hand - Python's socket.connect((host, port))
       does this same packing for you invisibly. */
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);              /* host byte order -> network byte order */
    server.sin_addr.s_addr = inet_addr(host);   /* "127.0.0.1" text -> the binary address form */

    connect(sock, (struct sockaddr *)&server, sizeof(server));

    static char buf[BUF_SIZE];
    static unsigned char decoded[BUF_SIZE];

    /* This client never asks for encryption - the assignment only requires
       the C client to implement the plain, unsecured openRead path. */
    char *hello = "SS,RFMP,v1.0,0";
    send(sock, hello, (int)strlen(hello), 0);

    int n = recv(sock, buf, BUF_SIZE - 1, 0);
    buf[n] = '\0';   /* C strings need an explicit null terminator - recv()
                         doesn't add one, unlike Python's recv() + decode() */
    printf("Server said: %s\n", buf);   /* expect the bare "CC" packet */

    char filename[256];
    printf("Filename to read: ");
    scanf("%255s", filename);

    char cmd[300];
    snprintf(cmd, sizeof(cmd), "CM,openRead,%s", filename);
    send(sock, cmd, (int)strlen(cmd), 0);

    n = recv(sock, buf, BUF_SIZE - 1, 0);
    buf[n] = '\0';

    if (strncmp(buf, "EE,", 3) == 0) {
        /* Exception-Packet: server found no such file (or another error) */
        printf("Server error: %s\n", buf + 3);
    } else if (strncmp(buf, "DP,", 3) == 0) {
        /* Data-Packet: everything after "DP," is base64 text, not the real
           file bytes yet - decode it back to the original bytes first. */
        int len = b64_decode(buf + 3, decoded);
        printf("----- FILE CONTENT -----\n");
        fwrite(decoded, 1, len, stdout);
        printf("\n-------------------------\n");
    } else {
        printf("Unexpected: %s\n", buf);
    }

    send(sock, "EN", 2, 0);   /* End-Packet - tells the server we're done */

    closesocket(sock);     /* Windows uses closesocket(), Linux/Mac use close() */
    WSACleanup();          /* matching "turn off" call for WSAStartup above */
    return 0;
}