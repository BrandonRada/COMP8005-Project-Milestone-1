CC=gcc

CFLAGS=-Wall -Wextra -std=c11

LIBS=-lcrypt

build: controller worker

controller: controller.c protocol.c
	$(CC) $(CFLAGS) -o controller controller.c protocol.c $(LIBS)

worker: worker.c protocol.c
	$(CC) $(CFLAGS) -o worker worker.c protocol.c $(LIBS)

clean:
	rm -f controller worker
