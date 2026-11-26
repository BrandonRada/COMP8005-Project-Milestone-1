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
#include <pthread.h>
#include <signal.h>
#include <limits.h>
#include <stdarg.h>

#include "protocol.h"
#include "common.h"

//#define MAX_PASSWORD_LEN 127
#define MAX_HOST_LEN 64
#define TARGET_HASH_LEN 256
#define DEFAULT_CHUNK_SIZE 256

typedef struct {
    	char host[MAX_HOST_LEN];
    	int port;
    	char worker_id[MAX_ID];
    	int heartbeat_ms;
    	int threads;
    	int test_exit_after_assign;
    	int test_duplicate_result;
} WorkerConfig;

typedef struct {
	int task_id;
	char worker_id[MAX_ID];
	char lease_id[MAX_ID];
	
	uint64_t start_index;
	uint64_t end_index;
	size_t length;
	char target_hash[TARGET_HASH_LEN];
} Assignment;

typedef struct {
	uint64_t id;
	uint64_t start;
	uint64_t end;
	int finished;
} Subtask;

typedef struct {
	const Assignment *assignment;
	const char *charset;
	size_t charset_size;
	Subtask *subtasks;
	size_t subtask_count;
	size_t next_subtask;
	pthread_mutex_t claim_mutex;
	pthread_mutex_t result_mutex;
	pthread_mutex_t log_mutex;
	int found;
	uint64_t found_index;
	char found_candidate[MAX_PASSWORD_LEN + 1];
	uint64_t progress;
	int active_threads;
	pthread_mutex_t progress_mutex;
	pthread_cond_t done_cond;
	int fatal_error;
} SearchState;

typedef struct {
	SearchState *shared;
	int thread_number;
} ThreadArg;

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
		"\nUsage:\n"
        	"  %s --host <host> --port <port> \\\n"
        	"     --id <worker-id> --heartbeat-ms <ms> --threads <count>\n"
        	"\n"
        	"Options:\n"
        	"  --host <host>              Controller hostname/IP\n"
        	"  --port <port>     	      Controller TCP port\n"
        	"  --id <worker-id>           Worker ID\n"
        	"  --heartbeat-ms <ms>        heartbeat interval\n"
        	"  --threads <count>	      number of pthreads (>=1)\n"
        	"  --help                     show this help\n"
        	"  --test-exit-after-assign  Exit after receiving an assignment (testing)\n"
        	"  --test-duplicate-result  Send the first accepted result twice (testing)\n",
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
			
			char *endptr;
			errno = 0;
			
			long port = strtol(argv[++i], &endptr, 10);
			
			if (errno != 0 || endptr == argv[i] || *endptr != '\0' || port <= 0 || port > 65535) {
				fprintf(stderr, "Invalid port\n");
				return -1;
			}
			cfg->port = (int)port;
			
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
			
			char *endptr;
			errno = 0;
			
			long heartbeat = strtol(argv[++i], &endptr, 10);
			
			if (errno != 0 || endptr == argv[i] || *endptr != '\0' || heartbeat <= 0 || heartbeat > INT_MAX) {
				fprintf(stderr, "Invalid heartbeat interval\n");
				return -1;
			}
			cfg->heartbeat_ms = (int)heartbeat;
			continue;
		}
		
		if (strcmp(argv[i], "--threads") == 0) {
			if (i + 1 >= argc) {
				fprintf(stderr, "--threads required\n");
				return -1;
			}
			
			char *endptr;
			errno = 0;
			
			long thread_count = strtol(argv[++i], &endptr, 10);
			
			if (errno != 0 || endptr == argv[i] || *endptr != '\0' || thread_count <= 0 || thread_count > INT_MAX) {
				fprintf(stderr, "Invalid thread amount: %s\n", argv[i]);
				return -1;
			}
			cfg->threads = (int)thread_count;
			continue;
		}
		if (strcmp(argv[i], "--test-exit-after-assign") == 0) {
			cfg->test_exit_after_assign = 1;
			continue;
		}
		if (strcmp(argv[i], "--test-duplicate-result") == 0) {
			cfg->test_duplicate_result = 1;
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
	
	if (cfg->threads <= 0) {
		fprintf(stderr, "Missing or invalid --threads\n");
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

// Helps trace events that occur
static void trace(SearchState *s, const char *fmt, ...) {
	va_list ap;
	pthread_mutex_lock(&s->log_mutex);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	fflush(stdout);
	pthread_mutex_unlock(&s->log_mutex);	
}

static void *search_thread(void *op) {
	ThreadArg *arg = op;
	SearchState *s = arg->shared;
	int thread_no = arg->thread_number;
	const Assignment *a = s->assignment;
	
	trace(s, "event=THREAD_START task=%d worker=%s thread=%d\n", a->task_id, a->worker_id, thread_no);
	
	for (;;) {
		size_t claimed_index;
		uint64_t start, end;
		int has_work = 0;
		
		pthread_mutex_lock(&s->claim_mutex);
		pthread_mutex_lock(&s->result_mutex);
		int already_found = s->found;
		pthread_mutex_unlock(&s->result_mutex);
		
		if (!already_found && s->next_subtask < s->subtask_count) {
			claimed_index = s->next_subtask++;
			s->subtasks[claimed_index].finished = 0;
			start = s->subtasks[claimed_index].start;
			end = s->subtasks[claimed_index].end;
			has_work = 1;
		}
		
		pthread_mutex_unlock(&s->claim_mutex);
		
		if (!has_work) {
			break;
		}
		
		trace(s, "event=THREAD_CLAIM task=%d worker=%s thread=%d subtask=%" PRIu64 " range=%" PRIu64 "-%" PRIu64 "\n", a->task_id, a->worker_id, thread_no, s->subtasks[claimed_index].id, start, end);
		
		uint64_t local_count = 0;
		int local_found = 0;
		uint64_t local_found_index = 0;
		char local_candidate[MAX_PASSWORD_LEN + 1] = {0};
		
		for (uint64_t index = start;; ++index) {
			pthread_mutex_lock(&s->result_mutex);
			already_found = s->found;
			pthread_mutex_unlock(&s->result_mutex);
			if (already_found) break;
			
			char candidate[MAX_PASSWORD_LEN + 1];
			
			if (decode_index(index, a->length, s->charset, s->charset_size,
				candidate, sizeof(candidate)) != 0) {
				pthread_mutex_lock(&s->progress_mutex);
				s->fatal_error = 1;
				pthread_mutex_unlock(&s->progress_mutex);
				break;
			}
			
			struct crypt_data data;
			memset(&data, 0, sizeof(data));
			char *hash = crypt_r(candidate, a->target_hash, &data);
			
			if(!hash) {
				pthread_mutex_lock(&s->progress_mutex);
				s->fatal_error = 1;
				pthread_mutex_unlock(&s->progress_mutex);
				break;
			}
			++local_count;
			
			// Found the target hash!
			if (strcmp(hash, a->target_hash) == 0) {
				local_found = 1;
				local_found_index = index;
				strncpy(local_candidate, candidate, sizeof(local_candidate) - 1);
				break;
			}
			
			// Avoid going over end (overflow)
			if (index == end) {
				break;
			}
		}
		
		pthread_mutex_lock(&s->progress_mutex);
		s->progress += local_count;	
		pthread_mutex_unlock(&s->progress_mutex);
		
		if (local_found) {
			pthread_mutex_lock(&s->result_mutex);
			if (!s->found) {
				s->found = 1;
				s->found_index = local_found_index;
				strcpy(s->found_candidate, local_candidate);
			}
			pthread_mutex_unlock(&s->result_mutex);
		}
			
		pthread_mutex_lock(&s->claim_mutex);
		s->subtasks[claimed_index].finished = 1;
		pthread_mutex_unlock(&s->claim_mutex);
			
		trace(s, "event=THREAD_DONE task=%d worker=%s thread=%d subtask=%" PRIu64 " status=%s checked=%" PRIu64 "\n", a->task_id, a->worker_id, thread_no, s->subtasks[claimed_index].id, local_found ? "FOUND" : "NOT_FOUND", local_count);
		
		if (local_found) {
			break;
		}
	}	
	
	trace(s, "event=THREAD_EXIT task=%d worker=%s thread=%d\n", a->task_id, a->worker_id, thread_no);
	pthread_mutex_lock(&s->progress_mutex);
	s->active_threads = s->active_threads - 1;
	pthread_cond_broadcast(&s->done_cond);
	pthread_mutex_unlock(&s->progress_mutex);
	return NULL;
}

static int init_search_state(SearchState *s) {
	if (pthread_mutex_init(&s->claim_mutex, NULL) != 0) {
		return -1;
	}
	
	if (pthread_mutex_init(&s->result_mutex, NULL) != 0) { 
		pthread_mutex_destroy(&s->claim_mutex); 
		return -1; 
	}
	
	if (pthread_mutex_init(&s->log_mutex, NULL) != 0) {
		pthread_mutex_destroy(&s->result_mutex);
		pthread_mutex_destroy(&s->claim_mutex);
		return -1;
	}
	
	if (pthread_mutex_init(&s->progress_mutex, NULL) != 0) {
		pthread_mutex_destroy(&s->log_mutex);
		pthread_mutex_destroy(&s->result_mutex);
		pthread_mutex_destroy(&s->claim_mutex);
		return -1;
	}
	
	if (pthread_cond_init(&s->done_cond, NULL) != 0) {
		pthread_mutex_destroy(&s->progress_mutex);
		pthread_mutex_destroy(&s->log_mutex);
		pthread_mutex_destroy(&s->result_mutex);
		pthread_mutex_destroy(&s->claim_mutex);
		return -1;
	}
	
	return 0;
}

static void destroy_search_state(SearchState *s) {
	pthread_cond_destroy(&s->done_cond);
	pthread_mutex_destroy(&s->progress_mutex);
	pthread_mutex_destroy(&s->log_mutex);
	pthread_mutex_destroy(&s->result_mutex);
	pthread_mutex_destroy(&s->claim_mutex);
}

int main(int argc, char *argv[]) {   
    	signal(SIGPIPE, SIG_IGN);
    	WorkerConfig cfg;
    	
    	int test_duplicate_done = 0;
    	

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
    	for(;;) {
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
			"ASSIGN task=%d worker=%63s lease=%63s range=%" SCNu64
			"-%" SCNu64 " length=%zu hash=%255s",
			&assignment.task_id,
			assigned_worker,
			assignment.lease_id,
			&assignment.start_index,
			&assignment.end_index,
			&assignment.length,
			assignment.target_hash
		);
		
		if (parsed != 7) {
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
		// TEST: Simulate Worker failure after receiving an assignment
		if (cfg.test_exit_after_assign) {
			printf(
				"event=TEST_FAILURE task=%d worker=%s lease=%s action=disconnect\n",
				assignment.task_id,
				cfg.worker_id,
				assignment.lease_id
			);
			fflush(stdout);
			close(fd);
			return 0;
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
		snprintf(message, sizeof(message), "START task=%d worker=%s lease=%s\n", assignment.task_id, cfg.worker_id, assignment.lease_id);
		
		if (send_line(fd, message) != 0) {
			fprintf(stderr, "Failed to send START\n");
			close(fd);
			return 1;
		}
		
		printf("SEND %s", message);
		
		// Subtasks
		uint64_t range_size = assignment.end_index - assignment.start_index + 1;
		size_t subtask_count = (size_t)(range_size / DEFAULT_CHUNK_SIZE + (range_size % DEFAULT_CHUNK_SIZE != 0));
		if (subtask_count == 0 || subtask_count > SIZE_MAX / sizeof(Subtask)) {
			fprintf(stderr, "Assigned range is too large\n");
			close(fd);
			return 1;
		}
		
		Subtask *subtasks = calloc(subtask_count, sizeof(*subtasks));
		if (!subtasks) { 
			perror("calloc subtasks");
			close(fd);
			return 1;
		}
		
		uint64_t next = assignment.start_index;
		
		for (size_t i = 0; i < subtask_count; ++i) {
			uint64_t remaining = assignment.end_index - next;
			uint64_t length = remaining >= DEFAULT_CHUNK_SIZE - 1 ? DEFAULT_CHUNK_SIZE : remaining + 1;
			subtasks[i].id = i;
			subtasks[i].start = next;
			subtasks[i].end = next + length - 1;
			next = subtasks[i].end;
			
			if (i + 1 < subtask_count) {
				++next;
			}
		}
		
		SearchState state;
		memset(&state, 0, sizeof(state));
		state.assignment = &assignment;
		state.charset = charset;
		state.charset_size = charset_size;
		state.subtasks = subtasks;
		state.subtask_count = subtask_count;
		
		if (init_search_state(&state) != 0) {
			fprintf(stderr, "Failed to initialize thread synchronization\n");
			free(subtasks);
			close(fd);
			return 1;
		}
		
		pthread_t *threads = calloc((size_t)cfg.threads, sizeof(*threads));
		ThreadArg *args = calloc((size_t)cfg.threads, sizeof(*args));
		
		if (!threads || !args) {
			perror("calloc threads");
			free(threads);
			free(args);
			destroy_search_state(&state);
			free(subtasks);
			close(fd);
			return 1;
		}
		
		int created = 0;
		uint64_t last_heartbeat = now_ms();
		int create_failed = 0;
		
		for (int i = 0; i < cfg.threads; ++i) {
			args[i].shared = &state;
			args[i].thread_number = i;
			pthread_mutex_lock(&state.progress_mutex);
			state.active_threads++;
			pthread_mutex_unlock(&state.progress_mutex);
			int res = pthread_create(&threads[i], NULL, search_thread, &args[i]);
			
			if (res != 0) {
				pthread_mutex_lock(&state.progress_mutex);
				state.active_threads--;
				pthread_mutex_unlock(&state.progress_mutex);
				fprintf(stderr, "pthread_create failed for thread %d: %s\n", i, strerror(res));
				create_failed = 1;
				break;
			}
			++created;
		}
		
		// Heartbeats on main thread while pthreads do the searches
		for (;;) {
			pthread_mutex_lock(&state.progress_mutex);
			int active = state.active_threads;
			uint64_t progress = state.progress;
			int fatal_error = state.fatal_error;
			pthread_mutex_unlock(&state.progress_mutex);
			
			if (active == 0) {
				break;
			}
			
			if(fatal_error) {
				break;
			}
			
			uint64_t current = now_ms();
			if (current - last_heartbeat >= (uint64_t)cfg.heartbeat_ms) {
				snprintf(message, sizeof(message), "HEARTBEAT worker=%s task=%d lease=%s state=WORKING progress=%" PRIu64 "\n", cfg.worker_id, assignment.task_id, assignment.lease_id, progress);

				if (send_line(fd, message) != 0) {
					fprintf(stderr, "Controller disconnected during heartbeat\n");
					create_failed = 1;
					break;
				}
				
				printf("SEND %s", message);
				last_heartbeat = current;	
			}
			
			struct timespec pause = {0, 20 * 1000 * 1000};
			nanosleep(&pause, NULL);
		}
		
		int join_failed = 0;
		
		for (int i = 0; i < created; ++i) {
			int rc = pthread_join(threads[i], NULL);
			if (rc != 0) {
				fprintf(stderr, "pthread_join failed for thread %d: %s\n", i, strerror(rc));
				join_failed = 1;
			}
			else {
				printf("event=THREAD_JOIN task=%d worker=%s thread=%d status=joined\n", assignment.task_id, cfg.worker_id, i);
			}
		}
		
		if (create_failed || join_failed || state.fatal_error || created != cfg.threads) {
			fprintf(stderr, "Search did not complete successfully (created=%d requested=%d)\n", created, cfg.threads);
			free(threads);
			free(args);
			destroy_search_state(&state);
			free(subtasks);
			close(fd);
			return 1;
		}
		
		// Search
		int found = 0;
		uint64_t found_index = 0;
		char found_candidate[MAX_PASSWORD_LEN + 1];
		
		// Grab the found and found_index shared values
		pthread_mutex_lock(&state.result_mutex);
		found = state.found;
		found_index = state.found_index;
		
		// Copy the found candidate into the variable "found" for checking and then sending if possible
		memcpy(found_candidate, state.found_candidate, sizeof(found_candidate));
		pthread_mutex_unlock(&state.result_mutex);
		
		// Check if the target was found, if it was, let the controller know
		if (found) {
			snprintf(
				message,
				sizeof(message),
				"RESULT task=%d worker=%s lease=%s status=FOUND index=%" PRIu64 " candidate=%s\n",
				assignment.task_id,
				cfg.worker_id,
				assignment.lease_id,
				found_index,
				found_candidate
			);
		// Else, the target has not been found and the controller must be notified
		} else {
			snprintf(
				message,
				sizeof(message),
				"RESULT task=%d worker=%s lease=%s status=NOT_FOUND index=0 candidate=NONE\n",
				assignment.task_id,
				cfg.worker_id,
				assignment.lease_id
			);
		}
		
		if (send_line(fd, message) != 0) {
			fprintf(stderr, "Failed to send RESULT\n");
			free(threads);
			free(args);
			destroy_search_state(&state);
			free(subtasks);
			close(fd);
			return 1;
		}
		printf("SEND %s", message);
		
		if (recv_line(fd, line, sizeof(line)) < 0) {
			fprintf(stderr, "Controller closed before sending COMPLETE\n");
			free(threads);
			free(args);
			destroy_search_state(&state);
			free(subtasks);
			close(fd);
			return 1;
		}
		printf("RECV %s", line);
		
		int valid_complete = 0;
		
		int completed_task = 0;
		char completed_lease[MAX_ID] = {0};
		char accepted[16] = {0};
		char reason[128] = {0};
		
		//memset(completed_lease, 0, sizeof(completed_lease));
		//memset(accepted, 0, sizeof(accepted));
		
		int parsed_complete = sscanf(
			line,
			"COMPLETE task=%d lease=%63s accepted=%15s reason=%127s",
			&completed_task,
			completed_lease,
			accepted,
			reason
		);
		
		if (parsed_complete == 4 && completed_task == assignment.task_id && strcmp(completed_lease, assignment.lease_id) == 0 && (strcmp(accepted, "yes") == 0 || strcmp(accepted, "no") == 0)) {
		
			valid_complete = 1;
			
			printf(
				"event=TASK_ACKNOWLEDGED task=%d lease=%s accepted=%s reason=%s\n",
				completed_task,
				completed_lease,
				accepted,
				reason
			);
		
		}
		
		// TEST: Send the same result again after the Controller accepted it
		if (cfg.test_duplicate_result && !test_duplicate_done && valid_complete && strcmp(accepted, "yes") == 0) {
			test_duplicate_done = 1;
			printf(
				"event=TEST_DUPLICATE task=%d worker=%s lease=%s\n",
				assignment.task_id,
				cfg.worker_id,
				assignment.lease_id
			);
			
			fflush(stdout);
			
			if (send_line(fd, message) != 0) {
				perror("send duplicate result");
				close(fd);
				return 1;
			}
			printf("SEND_DUPLICATE %s", message);
			if (recv_line(fd, line, sizeof(line)) < 0) {
				perror("recv duplicate acknowledgement");
				close(fd);
				return 1;
			}
			printf("RECV_DUPLICATE %s", line);
		}
		
		
		free(threads);
		free(args);
		destroy_search_state(&state);
		free(subtasks);
		
		if (!valid_complete) {
			fprintf(stderr, "Invalid COMPLETE message\n");
			close(fd);
			return 1;
		}
		printf("Worker %s waiting for another assignment...\n", cfg.worker_id);
    	}
}
