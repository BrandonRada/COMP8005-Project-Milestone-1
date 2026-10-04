# COMP 8005 - Milestone 1

This Project implements the COMP 8005 Project Milestone 1.

The Program/System is made up of two processes:

- Controller 	- Acts as the TCP Server and manages the task, target hash, worker state, and the result.

- Worker 	- Acts as the TCP Client and searches an assigned keyspace, hashing candidate passwords until a matching hash is found (or not found).

The Controller and Worker communicate with each other using TCP messages.

## Requirements
- Linux
- GCC
- Make

## Building
From the project directory, run in terminal:
make build
- This created the ./controller and ./worker

To remove the compiled files:
make clean

## Running
Open two terminals
EXAMPLE:
In the first, start the controller:
./controller --port 9000 --password 'a!' --charset-file safe-charset.txt --timeout-ms 5000

In the second, start the controller:
./worker --host 127.0.0.1 --port 9000 --id worker-1 --heartbeat-ms 1000

You will see several messages inside both terminals.
In order to more consistantly see heartbeat messages, make the --heartbeat-ms setting shorter (ex. 100).

## Command Help
Both of the programs have a command --help which provides insight into each setting.:
- Controller 	- ./controller --help
- Worker 	- ./worker --help

## Protocol
The main TCP messages used are:
- ASSIGN 	- Controller assigns a task to the worker
- START 	- Worker reports that it has started working on the task
- HEARTBEAT 	- Worker reports that it is still active and shows its progress
- RESULT 	- Worker reports what it found
- COMPLETE 	- Controller reports that the task is complete and if the result was accepted

## Files
These are the files that come with the project:
- controller.c		- This is the Controller code
- worker.c		- This is the Worker code
- protocol.c		- This contains TCP send and receive helpers
- protocol.h		- This contains TCP protocol helper declerations
- common.h		- This contains constants that are used in multiple files
- Makefile		- This is the build config
- safe-charset.txt	- This is the Projects safe character set that is used for both the Controller and Worker
- README.md		- This is the project documentation
