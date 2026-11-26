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
#include <limits.h>

#include "protocol.h"
#include "common.h"

#define HASH_SETTING "$6$rounds=5000$comp8005$"
//#define MAX_PASSWORD_LEN 127

typedef struct {
    int port;
    char password[MAX_PASSWORD_LEN + 1];
    char charset_file[MAX_CHARSET];
    int timeout_ms;
    int worker_count;
    int show_adaptive_lease;
} ControllerConfig;

typedef enum {
	TASK_PENDING,
	TASK_LEASED,
	TASK_COMPLETE
} task_state_t;

typedef struct {
	int task_id;
	uint64_t start_index;
	uint64_t end_index;
	
	size_t length;
	
	task_state_t state;
	char worker_id[MAX_ID];
	char lease_id[MAX_ID];
	
	uint64_t lease_deadline_ms;
	uint64_t assigned_at_ms;
	
	int assignment_attempt;
} TaskInfo;

#define LEASE_MIN_MS       2000ULL
#define LEASE_MAX_MS       60000ULL
#define LEASE_FALLBACK_MS  10000ULL
#define LEASE_MULTIPLIER 2.0

typedef struct {
	double total_completion_ms;
	double total_candidates;
} LeaseHistory;

static const char *task_state_name(task_state_t state);
static uint64_t calculate_lease_duration(const TaskInfo *task, const LeaseHistory *history, int show_adaptive_lease);

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
        	"     --charset-file <path> --timeout-ms <ms>\\\n"
        	"     --workers <count>\n"
        	"Options:\n"
        	"  --port <port>              TCP listening port\n"
        	"  --password <plaintext>     classroom test password\n"
        	"  --charset-file <path>      ordered charset file\n"
        	"  --timeout-ms <ms>          heartbeat timeout\n"
        	"  --workers <count>          number of Workers\n"
        	"  --help                     show this help\n"
        	"  --show-adaptive-lease     Show adaptive lease calculations\n",
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
		
		if(strcmp(argv[i], "--workers") == 0) {
			if (i + 1 >= argc) {
				fprintf(stderr, "--workers required\n");
				return -1;
			}
			
			cfg->worker_count = atoi(argv[++i]);
			
			if (cfg->worker_count <= 0) {
				fprintf(stderr, "Invalid Worker Count\n");
				return -1;
			}
			continue;
		}
		
		if (strcmp(argv[i], "--show-adaptive-lease") == 0) {
			cfg->show_adaptive_lease = 1;
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
	
	if (cfg->worker_count <= 0) {
		fprintf(stderr, "Missing or invalid --workers\n");
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

// Creates tasks that will be provided to the workers
static int create_tasks(uint64_t keyspace, size_t length, int worker_count, TaskInfo **out_tasks, size_t *out_count) {
	if (keyspace == 0 || worker_count <= 0 || out_tasks == NULL || out_count == NULL) {
		return -1;
	}
	
	// Target x amount of tasks per worker (for now I try 4)
	uint64_t desired_tasks = (uint64_t)worker_count * 4;
	
	// Calculate keyspace/desired_tasks to get chunk size
	uint64_t chunk_size = keyspace / desired_tasks + (keyspace % desired_tasks != 0);
	
	// Calculate the actual number of tasks
	uint64_t task_count = keyspace / chunk_size + (keyspace % chunk_size != 0);
	
	if (task_count > INT_MAX || task_count > SIZE_MAX / sizeof(TaskInfo)) {
		fprintf(stderr, "Too many tasks to allocate\n");
		return -1;
	}
	
	TaskInfo *tasks = calloc((size_t)task_count, sizeof(TaskInfo));
	
	if (tasks == NULL) {
		perror("calloc tasks");
		return -1;
	}
	
	printf("Task chunking algorithm:\n");
	printf("  Total candidates: %" PRIu64 "\n", keyspace);
	printf("  Worker count: %d\n", worker_count);
	printf("  Desired tasks: %" PRIu64 "\n", desired_tasks);
	printf("  Chosen chunk size: %" PRIu64 "\n", chunk_size);
	printf("  Actual task count: %" PRIu64 "\n", task_count);
	
	uint64_t start = 0;
	
	for (uint64_t i = 0; i < task_count; ++i) {
		uint64_t remaining = keyspace - start;
		uint64_t count = remaining < chunk_size ? remaining : chunk_size;
		
		tasks[i].task_id = (int)(i + 1);
		tasks[i].start_index = start;
		tasks[i].end_index = start + count - 1;
		tasks[i].length = length;
		
		tasks[i].state = TASK_PENDING;
		tasks[i].assignment_attempt = 0;
		
		printf(
			"event=TASK_CREATED task=%d range=%" PRIu64
			"-%" PRIu64 " state=%s\n",
			tasks[i].task_id,
			tasks[i].start_index,
			tasks[i].end_index,
			task_state_name(tasks[i].state)
		);
		
		start += count;
	}
	*out_tasks = tasks;
	*out_count = (size_t)task_count;
	
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

// Helper to convert the tasks state into a printable string
static const char *task_state_name(task_state_t state) {
	switch(state) {
		case TASK_PENDING:
			return "PENDING";
		
		case TASK_LEASED:
			return "LEASED";
			
		case TASK_COMPLETE:
			return "COMPLETE";
		
		default:
			return "UNKNOWN";
	}
}

// Generate a new lease ID every time a task is assigned
static void generate_lease_id(TaskInfo *task) {
	task->assignment_attempt++;
	
	snprintf(
		task->lease_id,
		sizeof(task->lease_id),
		"T%d-A%d-%" PRIu64,
		task->task_id,
		task->assignment_attempt,
		now_ms()
	);
}

static TaskInfo *find_pending_task(TaskInfo *tasks, size_t task_count) {
	for (size_t i = 0; i < task_count; ++i) {
		if (tasks[i].state == TASK_PENDING) {
			return &tasks[i];
		}
	}
	return NULL;
}

static int all_tasks_complete(TaskInfo *tasks, size_t task_count) {
	for (size_t i = 0; i < task_count; ++i) {
		if (tasks[i].state != TASK_COMPLETE) {
			return 0;
		}
	}
	return 1;
}

static int assign_task(WorkerInfo *worker, TaskInfo *task, const char *target_hash, const LeaseHistory *history, int show_adaptive_lease) {
	if (worker == NULL || task == NULL || target_hash == NULL || worker->fd < 0 || task->state != TASK_PENDING) {
		return -1;
	}
	
	generate_lease_id(task);
	
	uint64_t assigned_time = now_ms();
	uint64_t lease_duration = calculate_lease_duration(task, history, show_adaptive_lease);
	
	task->state = TASK_LEASED;
	task->assigned_at_ms = assigned_time;
	task->lease_deadline_ms = assigned_time + lease_duration;
	
	strncpy(task->worker_id, worker->worker_id, sizeof(task->worker_id) - 1);
	task->worker_id[sizeof(task->worker_id) - 1] = '\0';
	
	worker->task_id = task->task_id;
	worker->state = WORKING;
	worker->progress = 0;
	worker->last_seen_ms = now_ms();
	worker->last_progress_ms = now_ms();
	
	strncpy(worker->lease_id, task->lease_id, sizeof(worker->lease_id) - 1);
	worker->lease_id[sizeof(worker->lease_id) - 1] = '\0';
	
	char message[MAX_LINE];
	
	snprintf(
		message,
		sizeof(message),
		"ASSIGN task=%d worker=%s lease=%s range=%" PRIu64
		"-%" PRIu64 " length=%zu hash=%s\n",
		task->task_id,
		worker->worker_id,
		task->lease_id,
		task->start_index,
		task->end_index,
		task->length,
		target_hash
	);
	
	if (send_line(worker->fd, message) != 0) {
		perror("send ASSIGN");
		
		task->state = TASK_PENDING;
		task->worker_id[0] = '\0';
		task->lease_id[0] = '\0';
		task->lease_deadline_ms = 0;
		
		worker->state = STALE;
		worker->task_id = 0;
		worker->lease_id[0] = '\0';
		
		return -1;
	}
	
	printf("SEND %s", message);
	printf(
		"event=TASK_ASSIGNED task=%d worker=%s lease=%s "
		"range=%" PRIu64 "-%" PRIu64 " lease_ms=%" PRIu64 "\n",
		task->task_id,
		worker->worker_id,
		task->lease_id,
		task->start_index,
		task->end_index,
		lease_duration
	);
	
	return 0;
}

static int register_workers(int listen_fd, WorkerInfo *workers, int worker_count) {
	for (int i = 0; i < worker_count; ++i) {
		int worker_fd = accept(listen_fd, NULL, NULL);
		
		if (worker_fd < 0) {
			perror("accept");
			return -1;
		}
		
		char line[MAX_LINE];
		char registered_id[MAX_ID] = {0};
		
		if (recv_line(worker_fd, line, sizeof(line)) < 0) {
			fprintf(stderr, "Failed to receive REGISTER\n");
			close(worker_fd);
			return -1;
		}
		
		printf("RECV %s", line);
		
		if (sscanf(line, "REGISTER worker=%63s", registered_id) != 1) {
			fprintf(stderr, "Invalid REGISTER message\n");
			close(worker_fd);
			return -1;
		}
		
		// Ensure Worker IDs are unique
		for (int j = 0; j < i; ++j) {
			if (strcmp(workers[j].worker_id, registered_id) == 0) {
				fprintf(stderr, "Duplicate Worker ID: %s\n", registered_id);
				close(worker_fd);
				return -1;
			}
		}
		
		memset(&workers[i], 0, sizeof(workers[i]));
		
		workers[i].fd = worker_fd;
		workers[i].state = IDLE;
		workers[i].task_id = 0;
		workers[i].last_seen_ms = now_ms();
		
		strncpy(workers[i].worker_id, registered_id, sizeof(workers[i].worker_id) - 1);
		
		printf("event=WORKER_REGISTERED worker=%s slot=%d\n", workers[i].worker_id, i);
		
		}
	return 0;
}

static void assign_available_tasks(WorkerInfo *workers, int worker_count, TaskInfo *tasks, size_t task_count, const char *target_hash, const LeaseHistory *history, int show_adaptive_lease) {
	for (int i = 0; i < worker_count; ++i) {
		if (workers[i].state != IDLE || workers[i].fd < 0) {
			continue;
		}
		
		TaskInfo *task = find_pending_task(tasks, task_count);
		
		if (task == NULL) {
			break;
		}
		
		if (assign_task(&workers[i], task, target_hash, history, show_adaptive_lease) != 0) {
			fprintf(stderr, "Failed to assign task to Worker %s\n", workers[i].worker_id);
		}
		
	}
}

static TaskInfo *find_task_by_id(TaskInfo *tasks, size_t task_count, int task_id) {
	for (size_t i = 0; i < task_count; ++i) {
		if (tasks[i].task_id == task_id) {
			return &tasks[i];
		}
	}
	
	return NULL;
}

static uint64_t calculate_lease_duration(const TaskInfo *task, const LeaseHistory *history, int show_adaptive_lease) {
	if (task == NULL || history == NULL) {
		return LEASE_FALLBACK_MS;
	}
	
	// No accepted completion history yet
	if (history->total_candidates <= 0.0) {
		if (show_adaptive_lease) {
			printf("ADAPTIVE_LEASE: no samples yet; using fallback=%llu ms\n", (unsigned long long)LEASE_FALLBACK_MS);
		}
		
		return LEASE_FALLBACK_MS;
	}
	
	uint64_t candidate_count = task->end_index - task->start_index + 1;
	
	
	double average_ms_per_candidate = history->total_completion_ms / history->total_candidates;
	
	double estimated_duration = average_ms_per_candidate * (double)candidate_count * LEASE_MULTIPLIER;
	
	// Apply minimum and maximum lease bounds
	uint64_t lease_duration;
	
	// Apply minimum and maximum lease bounds
	if (estimated_duration < (double)LEASE_MIN_MS) {
		return LEASE_MIN_MS;
	}
	
	if (estimated_duration > (double)LEASE_MAX_MS) {
		return LEASE_MAX_MS;
	} else {
		return (uint64_t)(estimated_duration + 0.999);
	}
	if (show_adaptive_lease) {
		printf(
			"ADAPTIVE_LEASE: avg=%.4f ms/candidate, "
			"next_task_candidates=%" PRIu64
			", multiplier=%.1f, estimate=%.2f ms, "
			"final=%" PRIu64 " ms\n",
			average_ms_per_candidate,
			candidate_count,
			LEASE_MULTIPLIER,
			estimated_duration,
			lease_duration
		);
	}
			
	
	return lease_duration;
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
	
	// Create the global task table
	TaskInfo *tasks = NULL;
	size_t task_count = 0;
	
	if (create_tasks(keyspace, password_length, cfg.worker_count, &tasks, &task_count) != 0) {
		free(tasks);
		return -1;
	}
	
	// Allocate Worker info and polling
	WorkerInfo *workers = calloc((size_t)cfg.worker_count, sizeof(WorkerInfo));
	
	struct pollfd *pfds = calloc((size_t)cfg.worker_count, sizeof(struct pollfd));
	
	if (workers == NULL || pfds == NULL) {
		perror("calloc workers/pfds");
		free(workers);
		free(pfds);
		free(tasks);
		return 1;
	}
	
	for (int i = 0; i < cfg.worker_count; ++i) {
		workers[i].fd = -1;
		pfds[i].fd = -1;
	}	
	
	int listen_fd = create_server(cfg.port);
	
	if (listen_fd < 0) {
		free(pfds);
		free(tasks);
		return 1;
	}
	
	printf("Listening on port %d\n", cfg.port);
	printf("Controller waiting for %d Workers...\n", cfg.worker_count);
	
	// Register all configured Workers
	if (register_workers(listen_fd, workers, cfg.worker_count) != 0) {
		for (int i = 0; i < cfg.worker_count; ++i) {
			if (workers[i].fd >= 0) {
				close(workers[i].fd);
			}
		}
		
		close(listen_fd);
		free(workers);
		free(pfds);
		free(tasks);
		return 1;
	}
	
	LeaseHistory lease_history = {0};
	//int password_found = 0;
	
	// Distribute the initial tasks
	assign_available_tasks(workers, cfg.worker_count, tasks, task_count, target_hash, &lease_history, cfg.show_adaptive_lease);
	
	uint64_t sequence = 1;

	// Main worker scheduling loop
	while (!all_tasks_complete(tasks, task_count)) {
	
		int active_workers = 0;
		
		for (int i = 0; i < cfg.worker_count; ++i) {
			pfds[i].fd = workers[i].fd;
			pfds[i].events = POLLIN;
			pfds[i].revents = 0;
			
			if (workers[i].fd >= 0) {
				active_workers++;
			}
		}
		
		if (active_workers == 0) {
			fprintf(stderr, "No connected Workers remain.\n");
			break;
		}
		
		int poll_result = poll(pfds, (nfds_t)cfg.worker_count, 100);
		
		if (poll_result < 0) {
			if (errno == EINTR) {
				continue;
			}
			
			perror("poll");
			break;
		}
				
		// Check workers liveliness
		uint64_t current_ms = now_ms();
		
		for (int i = 0; i < cfg.worker_count; ++i) {
			WorkerInfo *worker = &workers[i];
			
			if (worker->fd < 0 || worker->task_id == 0) {
				continue;
			}
			
			TaskInfo *task = find_task_by_id(tasks, task_count, worker->task_id);
			
			if (task == NULL || task->state != TASK_LEASED) {
				continue;
			}
			
			uint64_t age_ms = current_ms - worker->last_seen_ms;
			
			// STALE if the workers lease expiresz or is WORKING and the heartbeat age is bigger than the timeout time.
			if (current_ms >= task->lease_deadline_ms) {
				printf(
					"seq=%02" PRIu64
					" event=LEASE_EXPIRED worker=%s task=%d lease=%s\n",
					sequence++,
					worker->worker_id,
					task->task_id,
					task->lease_id
				);
				
				task->state = TASK_PENDING;
				task->worker_id[0] = '\0';
				task->lease_id[0] = '\0';
				task->lease_deadline_ms = 0;
				
				worker->state = STALE;
				
				continue;
			}
			
			// Heartbeat timeout, dont remove worker or work, mark them as suspected (mentioned on week 6 slide 9)
			if (worker->state == WORKING && age_ms >= (uint64_t)cfg.timeout_ms) {
				printf(
					"seq=%02" PRIu64
					" event=WORKER_SUSPECTED worker=%s task=%d age_ms=%" PRIu64 "\n",
					sequence++,
					worker->worker_id,
					worker->task_id,
					age_ms
				);
				
				//task->state = TASK_PENDING;
				//task->worker_id[0] = '\0';
				//task->lease_id[0] = '\0';
				//task->lease_deadline_ms = 0;
				
				worker->state = STALE;
			}
		}
		
		// Process the messages from each connected worker
		for (int i = 0; i < cfg.worker_count; ++i) {
			WorkerInfo *worker = &workers[i];
			
			if (worker->fd < 0) {
				continue;
			}
			
			if (pfds[i].revents & (POLLHUP | POLLERR | POLLNVAL)) {
				printf("event=WORKER_DISCONNECTED worker=%s\n", worker->worker_id);
				
				TaskInfo *task = find_task_by_id(tasks, task_count, worker->task_id);
				
				if (task != NULL && task->state == TASK_LEASED && strcmp(task->lease_id, worker->lease_id) == 0) {
					task->state = TASK_PENDING;
					task->worker_id[0] = '\0';
					task->lease_id[0] = '\0';
					task->lease_deadline_ms = 0;
				}
				
				close(worker->fd);
				worker->fd = -1;
				worker->state = STALE;
				worker->task_id = 0;
				worker->lease_id[0] = '\0';
				
				continue;
			}
			
			if (!(pfds[i].revents & POLLIN)) {
				continue;
			}
			
			char line[MAX_LINE];
			
			int received = recv_line(worker->fd, line, sizeof(line));
			
			if (received < 0) {
				printf("event=WORKER_DISCONNECTED worker=%s\n", worker->worker_id);
				
				TaskInfo *task = find_task_by_id(tasks, task_count, worker->task_id);
				
				if (task != NULL && task->state == TASK_LEASED && strcmp(task->lease_id, worker->lease_id) == 0) {
					task->state = TASK_PENDING;
					task->worker_id[0] = '\0';
					task->lease_id[0] = '\0';
					task->lease_deadline_ms = 0;
				}
				
				close(worker->fd);
				worker->fd = -1;
				worker->state = STALE;
				worker->task_id = 0;
				worker->lease_id[0] = '\0';
				
				continue;
			}
			
			printf("RECV %s", line);
			worker->last_seen_ms = now_ms();
			
			// Start message
			if (strncmp(line, "START ", 6) == 0) {
				int task_id = 0;
				char worker_id[MAX_ID] = {0};
				char lease_id[MAX_ID] = {0};
				
				int parsed = sscanf(line, "START task=%d worker=%63s lease=%63s", &task_id, worker_id, lease_id);
				
				TaskInfo *task = find_task_by_id(tasks, task_count, task_id);
				
				if (parsed == 3 && task != NULL && task->state == TASK_LEASED && task_id == worker->task_id && strcmp(worker_id, worker->worker_id) == 0 && strcmp(lease_id, worker->lease_id) == 0 && strcmp(lease_id, task->lease_id) == 0) {
					worker->state = WORKING;
					
					printf(
						"seq=%02" PRIu64
						" event=START task=%d worker=%s lease=%s\n",
						sequence++,
						task_id,
						worker->worker_id,
						lease_id
					);
				} else {
					printf("Rejected START: invalid task or lease\n");
				}
				continue;
			}
			
			// Heartbeat
			if (strncmp(line, "HEARTBEAT ", 10) == 0) {
				int task_id = 0;
				char worker_id[MAX_ID];
				char lease_id[MAX_ID];
				char state[32];
				uint64_t progress = 0;
				
				int parsed = sscanf(line, "HEARTBEAT worker=%63s task=%d lease=%63s state=%31s progress=%" SCNu64, worker_id, &task_id, lease_id, state, &progress);
				
				TaskInfo *task = find_task_by_id(tasks, task_count, task_id);
				
				if (parsed == 5 && task != NULL && task->state == TASK_LEASED && task_id == worker->task_id && strcmp(worker_id, worker->worker_id) == 0 && strcmp(lease_id, worker->lease_id) == 0 && strcmp(lease_id, task->lease_id) == 0) {
				
					worker->state = WORKING;
					
					if (progress > worker->progress) {
						worker->progress = (size_t)progress;
						worker->last_progress_ms = now_ms();
					}
					
					printf(
						"seq=%02" PRIu64
						" event=HEARTBEAT worker=%s task=%d "
						" progress=%" PRIu64 "\n",
						sequence++,
						worker->worker_id,
						task_id,
						progress
					);
				} else {
					printf("Rejected HEARTBEAT: task, or lease mismatch\n");
				}
				continue;
			}
			
			// Result
			if (strncmp(line, "RESULT ", 7) == 0) {
				int task_id = 0;
				char worker_id[MAX_ID] = {0};
				char lease_id[MAX_ID] = {0};
				char status[32] = {0};
				uint64_t index = 0;
				char candidate[MAX_PASSWORD_LEN + 1] = {0};
			
				int parsed = sscanf(
					line, 
					"RESULT task=%d worker=%63s lease=%63s status=%31s"
					" index=%" SCNu64 " candidate=%127s",
					&task_id,
					worker_id,
					lease_id,
					status,
					&index,
					candidate
				);
				
				if (parsed != 6) {
					fprintf(stderr, "Invalid RESULT message\n");
					continue;
				}
				
				TaskInfo *task = find_task_by_id(tasks, task_count, task_id);
				
				int accepted = 0;
				const char *reason = "invalid_result";
				
				// Validate task ownership
				if (task == NULL) {
					reason = "wrong_task";
				}
				
				// Validate worker ownership
				else if (strcmp(worker_id, worker->worker_id) != 0) {
					reason = "wrong_worker";
				}
				
				// Validate that this task still has an active lease
				else if (task->state != TASK_LEASED) {
					reason = "task_not_leased";
				}
				
				// Validate that this is the correct workers task
				else if (task_id != worker->task_id) {
					reason = "wrong_worker_task";
				}
				
				// Validate that the result belongs to the current assignment
				else if (strcmp(lease_id, task->lease_id) != 0 || strcmp(lease_id, worker->lease_id) != 0) {
					reason = "stale_lease";
				}
				
				// Validate that the task is within its deadline
				else if (now_ms() > task->lease_deadline_ms) {
					reason = "late_result";
				}
				
				// Validate that this task belogns to the owner
				else if (strcmp(task->worker_id, worker->worker_id) != 0) {
					reason = "wrong_task_owner";
				}
				
				else if (strcmp(status, "FOUND") == 0) {
				
					// Check that the task index is in the valid range
					if (index < task->start_index || index > task->end_index) {
						reason = "index_out_of_range";
						
					// Validate that the candidate matches the target (Candidate needs to reproduce the target hash)
					} else if (!validate_candidate(candidate, task->length, index, charset, charset_size, target_hash)) {
						reason = "candidate_does_not_match_target";
						
					// The candidate matches the target and passes all checks, this can be accepted!
					} else {
						accepted = 1;
						reason = "candidate_matches_target";
						//password_found = 1;
						
						printf("\n");
						printf("========================================\n");
						printf("PASSWORD FOUND AND VERIFIED: %s\n", candidate);
						//printf("Stopping assignment of new tasks.\n");
						printf("========================================\n\n");
					}
				// If the worker completes the assigned range and its not found we can accept it
				} else if (strcmp(status, "NOT_FOUND") == 0) {
					accepted = 1;
					reason = "range_exhausted";
				}
				
				char complete[MAX_LINE];
				int current_assignment = task_id == worker->task_id && strcmp(worker_id, worker->worker_id) == 0 && strcmp(lease_id, worker->lease_id) == 0;
				
				if (accepted) {
					uint64_t completed_at = now_ms();
					uint64_t elapsed_ms = completed_at - task->assigned_at_ms;
					
					uint64_t candidate_count =task->end_index - task->start_index + 1;
								
					lease_history.total_completion_ms += (double)elapsed_ms;
					lease_history.total_candidates += (double)candidate_count;
					if (cfg.show_adaptive_lease) {
						printf(
							"ADAPTIVE_SAMPLE: task=%d elapsed=%" PRIu64
							" ms candidates=%" PRIu64
							" cumulative_avg=%.4f ms/candidate\n",
							task_id,
							elapsed_ms,
							candidate_count,
							lease_history.total_completion_ms / lease_history.total_candidates
						);
					}
					
				
					task->state = TASK_COMPLETE;
					
					printf(
						"event=LEASE_HISTORY task=%d elapsed_ms=%" PRIu64
						" candidates=%" PRIu64 "\n",
						task_id,
						elapsed_ms,
						candidate_count
					);
					
					printf(
						"seq=%02" PRIu64
						" event=RESULT task=%d worker=%s"
						" status=%s index=%" PRIu64 " candidate=%s\n"
						" accepted=yes reason=%s\n",
						sequence++,
						task_id,
						worker->worker_id,
						status,
						index,
						candidate,
						reason
					);
					
					snprintf(
						complete,
						sizeof(complete),
						"COMPLETE task=%d lease=%s accepted=yes reason=%s\n",
						task_id,
						lease_id,
						reason
					);
				} else {
					printf(
						"seq=%02" PRIu64
						" event=RESULT task=%d worker=%s "
						"status=%s accepted=no reason=%s\n",
						sequence++,
						task_id,
						worker->worker_id,
						status,
						reason
					);
					
					snprintf(
						complete,
						sizeof(complete),
						"COMPLETE task=%d lease=%s accepted=no reason=%s\n",
						task_id,
						lease_id,
						reason					
					);
					
					// If this is an active lease return the task to pending for another attempt
					if (task != NULL && task->state == TASK_LEASED && strcmp(task->lease_id, lease_id) == 0) {
						task->state = TASK_PENDING;
						task->worker_id[0] = '\0';
						task->lease_id[0] = '\0';
						task->lease_deadline_ms = 0;
					}
				}
				
				printf("SEND %s", complete);
				
				if (send_line(worker->fd, complete) != 0) {
					perror("send COMPLETE");
					continue;
				}
				
				// Worker can now receive another assignment
				if (current_assignment) {
					worker->state = IDLE;
					worker->task_id = 0;
					worker->lease_id[0] = '\0';
					worker->progress = 0;
					worker->last_seen_ms = now_ms();
				}
				
				
				continue;
			}
			fprintf(stderr, "Unknown protocol message: %s", line);		
		}
		
		// Give newly idle Workers the next pending tasks.
		//if (!password_found) {
			assign_available_tasks(workers, cfg.worker_count, tasks, task_count, target_hash, &lease_history, cfg.show_adaptive_lease);
		//}
	}
	
	if (all_tasks_complete(tasks, task_count)) {
		printf("\nAll %zu tasks completed successfully.\n", task_count);
	} else {
		fprintf(stderr, "\nNot all tasks could be completed.\n");
	}
	
	int success = all_tasks_complete(tasks, task_count);
	
	for (int i = 0; i < cfg.worker_count; ++i) {
		if (workers[i].fd >= 0) {
			close(workers[i].fd);
		}
	}
	
	close(listen_fd);
	
	free(workers);
	free(pfds);
	free(tasks);
	
	return success ? 0 : 1;
}
