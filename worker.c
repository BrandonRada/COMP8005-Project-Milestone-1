#define _GNU_SOURCE
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <crypt.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <time.h>

#include "protocol.h"
#include "common.h"

//#define MAX_PASSWORD_LEN 127
#define MAX_HOST_LEN 64
#define TARGET_HASH_LEN 256

typedef struct {
    char host[MAX_HOST_LEN];
    int port;
    char worker_id[MAX_ID];
    int heartbeat_ms;
} WorkerConfig;

typedef struct {
	int task_id;
	char worker_id[MAX_ID];
	uint64_t start_index;
	uint64_t end_index;
	size_t length;
	char target_hash[TARGET_HASH_LEN];
} Assignment;

// REturn the time in milliseconds
static uint64_t now_ms(void) {
	struct timespec ts;
	
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
		return 0;
	}
	
	return ((uint64_t)ts.tv_sec * 1000ULL) + ((uint64_t)ts.tv_nsec / 1000000ULL);
}

// Prints some help/command line usage for Worker program
static void usage(const char *program) {
	printf(
		"Usage:\n"
        	"  %s --host <host> --port <port> \\\n"
        	"     --id <worker-id> --heartbeat-ms <ms>\n"
        	"\n"
        	"Options:\n"
        	"  --host <host>              Controller hostname/IP\n"
        	"  --port <port>     	      Controller TCP port\n"
        	"  --id <worker-id>           Worker ID\n"
        	"  --heartbeat-ms <ms>        heartbeat interval\n"
        	"  --help                     show this help\n",
        	program
	);
}

// Helper function for Worker to parse args
static int parse_args(int argc, char *argv[], WorkerConfig *cfg) {
	if (cfg == NULL) {
		return -1;
	}
	
	memset(cfg, 0, sizeof(*cfg));
	
	for (int i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "--help") == 0) {
			usage(argv[0]);
			exit(0);
		}
		
		if (strcmp(argv[i], "--host")==0) {
			if (i + 1 >= argc) {
				fprintf(stderr, "--host required\n");
				return -1;
			}
			
			strncpy(cfg->host, argv[++i], sizeof(cfg->host) - 1);
			
			cfg->host[sizeof(cfg->host) - 1] = '\0';
			
			continue;
		}
		
		if (strcmp(argv[i], "--port") == 0) {
			if (i + 1 >= argc) {
				fprintf(stderr, "--port required\n");
				return -1;
			}
			
			cfg->port = atoi(argv[++i]);
			
			if (cfg->port <= 0 || cfg->port > 65535) {
				fprintf(stderr, "Invalid port\n (out of range)");
				return -1;
			}
			continue;
		}
		
		if (strcmp(argv[i], "--id") == 0) {
			if (i + 1 >= argc) {
				fprintf(stderr, "--id required\n");
				return -1;
			}
			
			strncpy(cfg->worker_id, argv[++i], sizeof(cfg->worker_id) - 1);
			
			cfg->worker_id[sizeof(cfg->worker_id) - 1] = '\0';
			
			continue;
		}
		
		if(strcmp(argv[i], "--heartbeat-ms") == 0) {
			if (i + 1 >= argc) {
				fprintf(stderr, "--heartbeat-ms required\n");
				return -1;
			}
			
			cfg->heartbeat_ms = atoi(argv[++i]);
			
			if (cfg->heartbeat_ms <= 0) {
				fprintf(stderr, "Invalid heartbeat interval\n");
				return -1;
			}
			continue;
		}
		fprintf(stderr, "Unknown option: %s\n", argv[i]);
		return -1;
	}
	
	if (cfg->host[0] == '\0') {
		fprintf(stderr, "Missing --host\n");
		return -1;
	}
	
	if (cfg->port == 0) {
		fprintf(stderr, "Missing --port\n");
		return -1;
	}
	
	if (cfg->worker_id[0] == '\0') {
		fprintf(stderr, "Missing --id\n");
		return -1;
	}
	
	if (cfg->heartbeat_ms <= 0) {
		fprintf(stderr, "Missing or invalid --heartbeat-ms\n");
		return -1;
	}
	return 0;
}

// Load the charset from the input filepath
static int load_charset(const char *path, char *charset, size_t *charset_size) {
	if (path == NULL || charset == NULL || charset_size == NULL) {
		return -1;
	}
	
	FILE *fp = fopen(path, "r");
	
	if (fp == NULL) {
		perror("fopen charset");
		printf("DEBUG: Entered Path [%s]\n", path);
		return -1;
	}
	
	size_t n = 0;
	int c;
	
	while ((c = fgetc(fp)) != EOF) {
		if (c == '\n' || c == '\r') {
			continue;
		}
		if (n >= MAX_CHARSET - 1) {
			fprintf(stderr, "Charset is too large\n");
			fclose(fp);
			return -1;
		}

		charset[n++] = (char)c;
	}
	fclose(fp);

	charset[n] = '\0';
	*charset_size = n;

	if (n == 0) {
		fprintf(stderr, "Charset is empty\n");
		return -1;
	}

	// Not sure if i need ti add this but checks duplicates could be safe but also idk
	for (size_t i = 0; i < n; ++i) {
		for (size_t j = i + 1; j < n; ++j) {
			if (charset[i] == charset[j]) {
				fprintf(stderr, "Charset contains duplicate characters\n");
				return -1;
			}
		}
	}
    	return 0;
}

// Decode the candidate ID into a password using the charset
static int decode_index(uint64_t index, size_t length, const char *charset, size_t charset_size, char *candidate, size_t candidate_size) {
	if (candidate == NULL || charset == NULL || charset_size == 0) {
		return -1;
	}
	
	if (length + 1 > candidate_size) {
		return -1;
	}
	
	uint64_t value = index;
	
	for (size_t pos = length; pos > 0; --pos) {
		candidate[pos - 1] = charset[value % charset_size];
		value /= charset_size;
	}
	
	candidate[length] = '\0';
	
	return 0;
}

// Connect to controller server
static int connect_to_controller(const char *host, int port) {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("Socket");
		return -1;
	}
	
	struct sockaddr_in server;
	
	memset(&server, 0, sizeof(server));
	
	server.sin_family = AF_INET;
	// Test with 64 just to see what it does lol
	server.sin_port = htons((uint16_t)port);
	
	if (inet_pton(AF_INET, host, &server.sin_addr) != 1) {
		fprintf(stderr, "Invalid Controller address: %s\n", host);
		close(fd);
		return -1;
	}
	
	if (connect(fd, (struct sockaddr *)&server, sizeof(server)) < 0) {
		perror("connect");
		close(fd);
		return -1;
	}
	return fd;
}


int main(int argc, char *argv[]) {   
    	WorkerConfig cfg;

	if (parse_args(argc, argv, &cfg) != 0) {
		usage(argv[0]);
		return 1;
	}

	printf("Connecting to %s:%d\n", cfg.host, cfg.port);

	int fd = connect_to_controller(cfg.host, cfg.port);

	if (fd < 0) {
		return 1;
	}

	printf("Connected to Controller\n");

	// Register the Worker
	char message[MAX_LINE];

	snprintf(message, sizeof(message), "REGISTER worker=%s\n", cfg.worker_id);

	if (send_line(fd, message) != 0) {
		fprintf(stderr, "Failec to send REGISTER\n");
		close(fd);
		return 1;
	}

	printf("SEND %s", message);
    
	// Receive ASSIGN form Controller
	char line[MAX_LINE];
	
	if (recv_line(fd, line, sizeof(line)) < 0) {
		fprintf(stderr, "Failed to receive ASSIGN\n");
		close(fd);
		return 1;
	}
	
	printf("RECV %s", line);
	
	Assignment assignment;
	memset(&assignment, 0, sizeof(assignment));
	
	char assigned_worker[MAX_ID];
	memset(assigned_worker, 0, sizeof(assigned_worker));
	
	int parsed = sscanf(
		line,
		"ASSIGN task=%d worker=%63s range=%" SCNu64
		"-%" SCNu64 " length=%zu hash=%255s",
		&assignment.task_id,
		assigned_worker,
		&assignment.start_index,
		&assignment.end_index,
		&assignment.length,
		assignment.target_hash
	);
	
	if (parsed != 6) {
		fprintf(stderr, "Invalid ASSIGN message\n");
		close(fd);
		return 1;
	}
	
	// Check that the Controller assignment is meant for this worker
	if (strcmp(assigned_worker, cfg.worker_id) != 0) {
		fprintf(stderr, "ASSIGN is for Worker %s, not %s\n", assigned_worker, cfg.worker_id);
		close(fd);
		return 1;
	}
	
	strncpy(assignment.worker_id, assigned_worker, sizeof(assignment.worker_id) - 1);
	
	// Check that the assigned password length is in the allowed range
	if (assignment.length == 0 || assignment.length > MAX_PASSWORD_LEN) {
		fprintf(stderr, "Invalid assignment length\n");
		close(fd);
		return 1;
	}

	// Load the charset file since we will need it for decoding of the candidate ids
	char charset[MAX_CHARSET];
	size_t charset_size = 0;
	// Wasnt sure how we should get the charset for the worker, so for now ASSUME THAT WHERE WORKER IS RUN ALSO HAS THE CHARSET FILE
	if (load_charset("safe-charset.txt", charset, &charset_size) != 0) {
		fprintf(stderr, "Worker could not load safe-charset.txt\n");
		close(fd);
		return 1;
	}
	
	// Tell the Controller this task is being started
	snprintf(message, sizeof(message), "START task=%d worker=%s\n", assignment.task_id, cfg.worker_id);
	
	if (send_line(fd, message) != 0) {
		fprintf(stderr, "Failed to send START\n");
		close(fd);
		return 1;
	}
	
	printf("SEND %s", message);
	
	// Search
	uint64_t progress = 0;
	uint64_t last_heartbeat = now_ms();
	int found = 0;
	uint64_t found_index = 0;
	char found_candidate[MAX_PASSWORD_LEN + 1];
	
	memset(found_candidate, 0, sizeof(found_candidate));
	
	for (uint64_t index = assignment.start_index; index <= assignment.end_index; ++index) {
		char candidate[MAX_PASSWORD_LEN + 1];
		
		if (decode_index(index, assignment.length, charset, charset_size, candidate, sizeof(candidate)) != 0) {
			fprintf(stderr, "Failed to decode candidate index %" PRIu64 "\n", index);
			close(fd);
			return 1;
		}
		
		// Hash current candidate using Controllers target hash
		struct crypt_data data;
		memset(&data, 0, sizeof(data));
		
		char *candidate_hash = crypt_r(candidate, assignment.target_hash, &data);
		
		if (candidate_hash == NULL) {
			fprintf(stderr, "crypt_r() failed at index %" PRIu64 "\n", index);
			close(fd);
			return 1;
		}
		
		// Increase progress metric
		progress ++;
		
		if (strcmp(candidate_hash, assignment.target_hash) == 0) {
			found = 1;
			found_index = index;
			
			strncpy(found_candidate, candidate, sizeof(found_candidate) - 1);
			
			found_candidate[sizeof(found_candidate) - 1] = '\0';
			break;
		}
		
		// Send heartbeat
		uint64_t current = now_ms();
		
		if (current - last_heartbeat >= (uint64_t)cfg.heartbeat_ms) {
			snprintf(
				message,
				sizeof(message),
				"HEARTBEAT worker=%s task=%d"
				" state=WORKING progress=%" PRIu64 "\n",
				cfg.worker_id,
				assignment.task_id,
				progress
			);
			
			if (send_line(fd, message) != 0) {
				fprintf(stderr, "Controller disconnected during heartbeat\n");
				close(fd);
				return 1;
			}
			
			printf("SEND %s", message);
			last_heartbeat = current;
		}
	}
	
	// Send the final result
	if (found) {
		snprintf(
			message,
			sizeof(message),
			"RESULT task=%d worker=%s status=FOUND"
			" index=%" PRIu64 " candidate=%s\n",
			assignment.task_id,
			cfg.worker_id,
			found_index,
			found_candidate
		);
	} else {
		snprintf(
			message,
			sizeof(message),
			"RESULT task=%d worker=%s status=NOT_FOUND"
			" index=0 candidate=NONE\n",
			assignment.task_id,
			cfg.worker_id
		);
	}
	
	if (send_line(fd, message) != 0) {
		fprintf(stderr, "Failed to send RESULT\n");
		close(fd);
		return 1;
	}
	
	printf("SEND %s", message);
	
	// Wait for Controllers COMPLETE
	if (recv_line(fd, line, sizeof(line)) < 0) {
		fprintf(stderr, "Controller closed connection before COMPLETE\n");
		close(fd);
		return 1;
	}
	
	printf("RECV %s", line);
	close(fd);
	return 0;
}
