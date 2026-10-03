#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stddef.h>

#define MAX_LINE 4096

int send_all(int fd, const char *buf, size_t len);

int send_line(int fd, const char *line);

int recv_line(int fd, char *buffer, size_t max_len);

#endif
