#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "protocol.h"

int main(void) {

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr;

    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(9000);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr));

    listen(listen_fd, 8);

    printf("Controller waiting...\n");

    int worker_fd = accept(listen_fd, NULL, NULL);

    printf("Worker connected\n");

    send_line( worker_fd, "ASSIGN task=4 worker=worker-1 range=0-7055 length=2\n");

    char line[MAX_LINE];

    while (recv_line( worker_fd, line, sizeof(line)) > 0) {
        printf("%s", line);
    }

    close(worker_fd);
    close(listen_fd);

    return 0;
}
