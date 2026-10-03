#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "protocol.h"

#define MAX_LINE 4096
#define MAX_ID 64

typedef struct {
    char host[64];
    int port;
    char worker_id[MAX_ID];
    int heartbeat_ms;
} WorkerConfig;


int main(void) {

    int parse_args(int argc, char *argv[], WorkerConfig *cfg);

    int fd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in server;

    memset(&server, 0, sizeof(server));

    server.sin_family = AF_INET;
    server.sin_port = htons(9000);

    inet_pton(AF_INET, "127.0.0.1", &server.sin_addr);

    connect(fd, (struct sockaddr *)&server, sizeof(server));

    printf("Connecting to %s:%d\n", "127.0.0.1", 9000);

    char line[MAX_LINE];

    recv_line(fd, line, sizeof(line));

    printf("%s", line);

    send_line( fd, "START task=4 worker=worker-1\n");

    close(fd);

    return 0;
}
