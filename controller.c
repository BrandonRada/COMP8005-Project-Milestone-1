#define _GNU_SOURCE
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <crypt.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <time.h>

#include "protocol.h"
#include "common.h"

#define HASH_SETTING "$6$rounds=5000$comp8005$"
//#define MAX_PASSWORD_LEN 127

typedef struct {
    int port;
    char password[MAX_PASSWORD_LEN + 1];
    char charset_file[MAX_CHARSET];
    int timeout_ms;
} ControllerConfig;

typedef struct {
	int task_id;
	uint64_t start_index;
	uint64_t end_index;
	
	size_t length;
	
	int pending;
	int complete;
} TaskInfo;

// REturn the time in milliseconds
static uint64_t now_ms(void) {
	struct timespec ts;
	
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
		return 0;
	}
	
	return ((uint64_t)ts.tv_sec * 1000ULL) + ((uint64_t)ts.tv_nsec / 1000000ULL);
}

// Prints some help/command line usage for Controller program
static void usage(const char *program) {
	printf(
		"Usage:\n"
        	"  %s --port <port> --password <plaintext> \\\n"
        	"     --charset-file <path> --timeout-ms <ms>\n"
        	"\n"
        	"Options:\n"
        	"  --port <port>              TCP listening port\n"
        	"  --password <plaintext>     classroom test password\n"
        	"  --charset-file <path>      ordered charset file\n"
        	"  --timeout-ms <ms>          heartbeat timeout\n"
        	"  --help                     show this help\n",
        	program
	);
}

// Helper function for Controller to parse args
static int parse_args(int argc, char *argv[], ControllerConfig *cfg) {
	if (cfg == NULL) {
		return -1;
	}
	
	memset(cfg, 0, sizeof(*cfg));
	
	for (int i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "--help") == 0) {
			usage(argv[0]);
			exit(0);
		}
		
		if (strcmp(argv[i], "--port")==0) {
			if (i + 1 >= argc) {
				fprintf(stderr, "--port required\n");
				return -1;
			}
			
			cfg->port = atoi(argv[++i]);
			
			if (cfg->port <= 0 || cfg->port > 65535) {
				fprintf(stderr, "Invalid port (out of range)\n");
				return -1;
			}
			continue;
		}
		
		if (strcmp(argv[i], "--password") == 0) {
			if (i + 1 >= argc) {
				fprintf(stderr, "--password required\n");
				return -1;
			}
			
			strncpy(cfg->password, argv[++i], sizeof(cfg->password) - 1);
			
			cfg->password[sizeof(cfg->password) - 1] = '\0';
			
			continue;
		}
		
		if (strcmp(argv[i], "--charset-file") == 0) {
			if (i + 1 >= argc) {
				fprintf(stderr, "--charset-file required\n");
				return -1;
			}
			
			strncpy(cfg->charset_file, argv[++i], sizeof(cfg->charset_file) - 1);
			
			cfg->charset_file[sizeof(cfg->charset_file) - 1] = '\0';
			
			continue;
		}
		
		if(strcmp(argv[i], "--timeout-ms") == 0) {
			if (i + 1 >= argc) {
				fprintf(stderr, "--timeout-ms required\n");
				return -1;
			}
			
			cfg->timeout_ms = atoi(argv[++i]);
			
			if (cfg->timeout_ms <= 0) {
				fprintf(stderr, "Invalid timeout\n");
				return -1;
			}
			continue;
		}
		fprintf(stderr, "Unknown option: %s\n", argv[i]);
		return -1;
	}
	
	if (cfg->port == 0) {
		fprintf(stderr, "Missing --port\n");
		return -1;
	}
	
	if (cfg->password[0] == '\0') {
		fprintf(stderr, "Missing --password\n");
		return -1;
	}
	
	if (cfg->charset_file[0] == '\0') {
		fprintf(stderr, "Missing --charset-file\n");
		return -1;
	}
	
	if (cfg->timeout_ms <= 0) {
		fprintf(stderr, "Missing or invalid --timeout-ms\n");
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

	// Not sure if i need ti add this but checks duplicates
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

static int calculate_keyspace( size_t charset_size, size_t length, uint64_t *result) {
	if (result == NULL || charset_size == 0) {
		return -1;
	}

	uint64_t total = 1;

	for (size_t i = 0; i < length; ++i) {

	 	if (total > UINT64_MAX / charset_size) {
		return -1;
		}

		total *= charset_size;
	}

	*result = total;

	return 0;
}

// Create the target SHA-512 crypt hash
static int create_target_hash( const char *password, char *target_hash, size_t target_hash_size) {
	if (password == NULL ||target_hash == NULL ||
		target_hash_size == 0) {
		return -1;
	}

	struct crypt_data data;

	memset(&data, 0, sizeof(data));

	char *result = crypt_r( password, HASH_SETTING, &data);

	if (result == NULL) {
		fprintf(stderr, "crypt_r() failed while creating target hash\n");
		return -1;
	}

	strncpy( target_hash, result, target_hash_size - 1);

	target_hash[target_hash_size - 1] = '\0';

	return 0;
}

// Creates listening tcp socket
static int create_server(int port) {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	
	if (fd < 0) {
		perror("socket");
		return -1;
	}
	int yes = 1;
	
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
		perror("setsockopt");
		close(fd);
		return -1;
	}
	struct sockaddr_in addr;
	
	memset(&addr, 0, sizeof(addr));
	
	addr.sin_family = AF_INET;
	addr.sin_port = htons((uint16_t)port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		close(fd);
		return -1;
	}
	
	if (listen(fd, 8) < 0) {
		perror("listen");
		close(fd);
		return -1;
	}
	return fd;
}

static int validate_candidate(const char *candidate, size_t length, uint64_t index, const char *charset, size_t charset_size, const char *target_hash) {
	if (candidate == NULL || charset == NULL || target_hash == NULL) {
		return 0;
	}
	
	if (strlen(candidate) != length) {
		return 0;
	}
	
	// Validate that each character can be found in the official charset.
	for (size_t i = 0; i < length; ++i) {
		int found = 0;
		for (size_t j = 0; j < charset_size; ++j) {
			if (candidate[i] == charset[j]) {
				found = 1;
				break;
			}
		}
		
		if (!found) {
			return 0;
		}
	}
	
	// Validate candidates numeric ID is the reported index
	uint64_t calculated_index = 0;
	for (size_t i = 0; i < length; ++i) {
		size_t position = 0;
		int found = 0;
		
		for (size_t j = 0; j < charset_size; ++j) {
			if (candidate[i] == charset[j]) {
				position = j;
				found = 1;
				break;
			}
		}
		
		if (!found) {
			return 0;
		}
		
		calculated_index = calculated_index * charset_size + position;
	}
	if (calculated_index != index) {
		return 0;
	}
	
	// Has the candidate now
	struct crypt_data data;
	
	memset(&data, 0, sizeof(data));
	
	char *candidate_hash = crypt_r(candidate, target_hash, &data);
	
	if (candidate_hash == NULL) {
		return 0;
	}
	
	return strcmp(candidate_hash, target_hash) == 0;
}

// Helper to convert the workers state into a printable string
static const char *state_name(worker_state_t state) {
	switch(state) {
		case IDLE:
			return "IDLE";
		case WORKING:
			return "WORKING";
		case STALE:
			return "STALE";
		default:
			return "UNKNOWN";
	}
}


int main(int argc, char *argv[]) {
	signal(SIGPIPE, SIG_IGN);
	
	ControllerConfig cfg;
	
	if (parse_args(argc, argv, &cfg) != 0) {
		usage(argv[0]);
		return 1;
	}
	
	char charset[MAX_CHARSET];
	size_t charset_size = 0;
	
	if (load_charset(cfg.charset_file, charset, &charset_size) != 0) {
		return 1;
	}
	
	size_t password_length = strlen(cfg.password);
	
	if (password_length == 0 || password_length > MAX_PASSWORD_LEN) {
		fprintf(stderr, "Invalid password length\n");
		return 1;
	}
	
	uint64_t keyspace = 0;
	
	if (calculate_keyspace(charset_size, password_length, &keyspace) != 0) {
		fprintf(stderr, "Calculation error\n");
		return 1;
	}
	
	// Create the target hash
	char target_hash[256];
	
	if (create_target_hash(cfg.password, target_hash, sizeof(target_hash)) != 0) {
		return 1;
	}
	
	printf("Target length: %zu\n", password_length);
	printf("Charset size: %zu\n", charset_size);
	printf("Keyspace: %" PRIu64 "\n", keyspace);
	printf("Target hash: %s\n", target_hash);
	
	// Create the task
	TaskInfo task;
	
	memset(&task, 0, sizeof(task));
	
	task.task_id = 1;
	task.start_index = 0;
	task.end_index = keyspace - 1;
	task.length = password_length;
	task.pending = 1;
	task.complete = 0;
	
	int listen_fd = create_server(cfg.port);
	
	if (listen_fd < 0) {
		return 1;
	}
	
	printf("Listening on port %d\n", cfg.port);
	printf("Controller waiting for Worker...\n");
	
	// Accept a worker
	int worker_fd = accept(listen_fd, NULL, NULL);
	
	if (worker_fd < 0) {
		perror("accept");
		close(listen_fd);
		return 1;
	}
	
	printf("Worker connected\n");
	
	WorkerInfo worker;
	
	memset(&worker, 0, sizeof(worker));
	
	worker.state = IDLE;
	worker.task_id = task.task_id;
	worker.progress = 0;
	
	char line[MAX_LINE];
	
	// Make sure the first message to the controller is REGISTER
	if (recv_line(worker_fd, line, sizeof(line)) < 0) {
		fprintf(stderr, "Failed to recieve Register\n");
		
		close(worker_fd);
		close(listen_fd);
		return 1;
	}
	
	printf("RECV %s", line);
	
	char registered_id[MAX_ID];
	memset(registered_id, 0, sizeof(registered_id));
	
	if (sscanf(line, "REGISTER worker=%63s", registered_id) != 1) {
		fprintf(stderr, "Invalid REGISTER message\n");
		
		close(worker_fd);
		close(listen_fd);
		return 1;
	}
	
	strncpy(worker.worker_id, registered_id, sizeof(worker.worker_id) -1);
	
	worker.worker_id[sizeof(worker.worker_id) - 1] = '\0';
	worker.last_seen_ms = now_ms();
	
	// Controller assign the work
	char assign[MAX_LINE];
	
	snprintf(assign, sizeof(assign), "ASSIGN task=%d worker=%s range=%" PRIu64 "-%" PRIu64" length=%zu hash=%s\n", task.task_id, worker.worker_id, task.start_index, task.end_index, task.length, target_hash);
	
	if (send_line(worker_fd, assign) != 0) {
		fprintf(stderr, "Failed to send ASSIGN\n");
		close(worker_fd);
		close(listen_fd);
		return 1;
	}
	
	printf("SEND %s", assign);
	
	task.pending = 0;
	uint64_t sequence = 1;
	
	// Main worker loop
	while (!task.complete) {
		struct pollfd pfd;
		memset(&pfd, 0, sizeof(pfd));
		
		pfd.fd = worker_fd;
		pfd.events = POLLIN;
		
		int poll_result = poll (&pfd, 1, 100);
		
		if (poll_result < 0) {
			if (errno == EINTR) {
				continue;
			}
			perror("poll");
			break;
		}
		
		// Check workers liveliness
		uint64_t current_ms = now_ms();
		
		uint64_t age_ms = current_ms - worker.last_seen_ms;
		
		// STALE if the worker is WORKING and the heartbeat age is bigger than the timeout time.
		if(worker.state == WORKING && age_ms >= (uint64_t)cfg.timeout_ms) {
			worker.state = STALE;
			
			printf(
			"seq=%02" PRIu64
			" event=STALE worker=%s task=%d age_ms=%" PRIu64
			" timeout_ms=%d state=%s\n",
			sequence++,
			worker.worker_id,
			worker.task_id,
			age_ms,
			cfg.timeout_ms,
			state_name(worker.state)
			);
			
			// Set task to PENDING since its unfinished
			task.pending = 1;
			
			printf("Task %d is now PENDING\n", task.task_id);
			
			break;
		}
		
		if (poll_result == 0) {
			continue;
		}
		
		if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) {
			if (worker.state == WORKING) {
				worker.state = STALE;
				task.pending = 1;
				
				printf(
					"seq=%02" PRIu64
					" event=STALE worker=%s task=%d reason=connection_closed"
					" state=%s\n",
					sequence++,
					worker.worker_id,
					worker.task_id,
					state_name(worker.state)
				);
				
				printf("Task %d is now PENDING\n", task.task_id);
			}
			break;
		}
		
		if (!(pfd.revents & POLLIN)) {
			continue;
		}
		
		int received = recv_line(worker_fd, line, sizeof(line));
		
		if (received < 0) {
			if (worker.state == WORKING) {
				worker.state = STALE;
				task.pending = 1;
				
				printf(
					"seq=%02" PRIu64
					" event=STALE worker=%s task=%d reason=connection_closed"
					" state=%s\n",
					sequence++,
					worker.worker_id,
					worker.task_id,
					state_name(worker.state)
				);
				
				printf("Task %d is now PENDING\n", task.task_id);
			}
			break;
		}
		
		printf("RECV %s", line);
		
		// Contacted worker
		worker.last_seen_ms = now_ms();
		
		// Start
		if (strncmp(line, "START ", 6) == 0) {
			int task_id = 0;
			char worker_id[MAX_ID];
			
			if (sscanf(line, "START task=%d worker=%63s", &task_id, worker_id) == 2) {
				if (task_id == task.task_id && strcmp(worker_id, worker.worker_id) ==0) {
					worker.state = WORKING;
					
					printf(
						"seq=%02" PRIu64
						" event=START task=%d worker=%s\n",
						sequence++,
						task.task_id,
						worker.worker_id
					);
				}
			}
			continue;
		}
		
		// Heartbeat
		if (strncmp(line, "HEARTBEAT ", 10) == 0) {
			int task_id = 0;
			char worker_id[MAX_ID];
			char state[32];
			size_t progress = 0;
			
			memset(worker_id, 0 , sizeof(worker_id));
			memset(state, 0, sizeof(state));
			
			int parsed = sscanf(line, "HEARTBEAT worker=%63s task=%d state=%31s progress=%zu", worker_id, &task_id, state, &progress);
			
			if (parsed == 4 && task_id == task.task_id && strcmp(worker_id, worker.worker_id) == 0) {
				worker.state = WORKING;
				worker.progress = progress;
				worker.last_seen_ms = now_ms();
				worker.last_progress_ms = now_ms();
				
				printf(
					"seq=%02" PRIu64
					" event=HEARTBEAT worker=%s task=%d"
					" state=%s progress=%zu\n",
					sequence++,
					worker.worker_id,
					worker.task_id,
					state,
					progress
				);
			}
			continue;
		}
		
		// Result
		if (strncmp(line, "RESULT ", 7) == 0) {
			int task_id = 0;
			char worker_id[MAX_ID];
			char status[32];
			uint64_t index = 0;
			char candidate[MAX_PASSWORD_LEN + 1];
			
			memset(worker_id, 0, sizeof(worker_id));
			memset(status, 0, sizeof(status));
			memset(candidate, 0, sizeof(candidate));
			
			int parsed = sscanf(
				line, 
				"RESULT task=%d worker=%63s status=%31s"
				" index=%" SCNu64 " candidate=%127s",
				&task_id,
				worker_id,
				status,
				&index,
				candidate
				);
				
				if (parsed != 5) {
					fprintf(stderr, "Invalid RESULT message\n");
					
					continue;
				}
				
				int accepted = 0;
				const char *reason = "invalid_result";
				
				// Validate task ownership
				if (task_id != task.task_id) {
					reason = "wrong_task";
				}
				
				// Validate worker ownership
				else if (strcmp(worker_id, worker.worker_id) != 0) {
					reason = "wrong_worker";
				}
				
				else if (strcmp(status, "FOUND") == 0) {
					// Index must be inside assigned range
					if (index < task.start_index || index > task.end_index) {
						reason = "index_out_of_range";
					}
					
					// Candidate needs to reproduce the target hash
					else if (!validate_candidate(candidate, task.length, index, charset, charset_size, target_hash)) {
						reason = "candidate_does_not_match_target";
					}
					else {
						accepted = 1;
						reason = "candidate_matches_target";
					}
				}
				else if (strcmp(status, "NOT_FOUND") == 0) {
					// If the worker completes the assigned range and its not found we can accept it
					accepted = 1;
					reason = "range_exhausted";
				}
				
				if (accepted) {
					task.complete = 1;
					task.pending = 0;
					
					worker.state = IDLE;
					
					printf(
						"seq=%02" PRIu64
						" event=RESULT task=%d worker=%s"
						" status=%s index=%" PRIu64
						" candidate=%s\n",
						sequence++,
						task.task_id,
						worker.worker_id,
						status,
						index,
						candidate
					);
					
					printf(
						"seq=%02" PRIu64
						" event=COMPLETE task=%d accepted=yes"
						" reason=%s\n",
						sequence++,
						task.task_id,
						reason
					);
					
					char complete[MAX_LINE];
					
					snprintf(complete, sizeof(complete), "COMPLETE task=%d accepted=yes reason=%s\n", task.task_id, reason);
					
					send_line(worker_fd, complete);
				} else {
					printf(
						"seq=%02" PRIu64
						" event=RESULT task=%d worker=%s"
						" status=%s accepted=no reason=%s\n",
						sequence++,
						task.task_id,
						worker.worker_id,
						status,
						reason
					);
					
					char complete[MAX_LINE];
					
					snprintf(complete, sizeof(complete), "COMPLETE task=%d accepted=no reason=%s\n", task.task_id, reason);
					
					send_line(worker_fd, complete);
				}
				continue;
		}
		// Unknown protocol message
		fprintf(stderr, "Unknown protocol message: %s", line);	
	}
	
	if (task.pending && !task.complete) {
		printf("Task %d remains PENDING, waiting for another Worker.\n", task.task_id);
	}
	
	close(worker_fd);
	close(listen_fd);
	
	return task.complete ? 0 : 0;
}
