CC=gcc

CFLAGS=-Wall -Wextra -std=c11

build: controller worker

controller: controller.c protocol.c
	$(CC) $(CFLAGS) -o controller controller.c protocol.c

worker: worker.c protocol.c
	$(CC) $(CFLAGS) -o worker worker.c protocol.c

clean:
	rm -f controller worker
