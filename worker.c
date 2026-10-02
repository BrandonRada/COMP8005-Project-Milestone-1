#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "protocol.h"

int main(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in server;

    memset(&server, 0, sizeof(server));

    server.sin_family = AF_INET;
    server.sin_port = htons(9000);

    inet_pton(AF_INET, "127.0.0.1", &server.sin_addr);

    connect(fd, (struct sockaddr *)&server, sizeof(server));

    char line[MAX_LINE];

    recv_line(fd, line, sizeof(line));

    printf("%s", line);

    send_line( fd, "START task=4 worker=worker-1\n");

    close(fd);

    return 0;
}
