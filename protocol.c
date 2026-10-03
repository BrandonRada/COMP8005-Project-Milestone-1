#include "protocol.h"

#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
// Send every byte in the buffer, ensures everything has been written
int send_all(int fd, const char *buf, size_t len) {
	size_t total = 0;

	while (total < len) {
		ssize_t n = send(fd, buf + total, len - total, 0);

		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			return -1;
		}
		
		if (n == 0) {
			return -1;
		}
		
		total += (size_t)n;
	}

	return 0;
}

// Send one line protocol message
int send_line(int fd, const char *line) {
	return send_all(fd, line, strlen(line));
}

// Recieve one line protocol message, reading a byte at a time until new line is recieved or the buffer is full
int recv_line(int fd, char *buf, size_t max_len) {
	if (buf == NULL || max_len < 2) {
		return -1;
	} 
	
	size_t pos = 0;

	while (pos < max_len - 1) {
		char c;

		ssize_t n = recv(fd, &c, 1, 0);

		if (n < 0){
			if (errno == EINTR) {
				continue;
			}
			
			return -1;
		}
		
		if (n == 0) {
			// The connection was closed
			if (pos == 0) {
				return -1;
			}
			break;
		}

		buf[pos++] = c;

		if (c == '\n'){
			break;
		}
	}

	buf[pos] = '\0';
	
	// If the buffer is completely filled and has not seen '\n', their is an oversized protocol line exceediding max length
	if (pos == max_len -1 && buf[pos - 1] != '\n') {
		return -1;
	}

	return (int)pos;
}
