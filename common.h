#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

#define MAX_LINE 4096
#define MAX_ID 64

typedef enum {
	IDLE,
	WORKING,
	STALE
} worker_state_t;

typedef struct {
	char worker_id[MAX_ID];
 
	worker_state_t state;

	uint64_t last_seen_ms;
	uint64_t last_progress_ms;

	int task_id;
	size_t progress;
} WorkerInfo;

#endif
