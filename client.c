#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    int port = argc > 2 ? atoi(argv[2]) : 5050;

    printf("Host: %s\n", host);
    printf("Port: %d\n", port);

    return 0;
}