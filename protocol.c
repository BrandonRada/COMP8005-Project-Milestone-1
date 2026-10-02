#include "protocol.h"
 
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
 
int send_all(int fd, const char *buf, size_t len) {
	size_t total = 0;
 
	while (total < len) {
		ssize_t n = send(fd, buf + total, len - total, 0);
 
		if (n <= 0) {
			return -1;
 		}
		total += n;
	}
 
	return 0;
}


int send_line(int fd, const char *line) {
	return send_all(fd, line, strlen(line));
}
 
int recv_line(int fd, char *buf, size_t max_len) {
	size_t pos = 0;
 
	while (pos < max_len - 1) {
		char c;
 
		ssize_t n = recv(fd, &c, 1, 0);
 
		if (n <= 0){
			return -1;
 		}
 
		buf[pos++] = c;
 
		if (c == '\n'){
			break;
		}
	}
 
	buf[pos] = '\0';
 
	return (int)pos;
}
