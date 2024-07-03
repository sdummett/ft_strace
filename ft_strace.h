#ifndef FT_STRACE_H
#define FT_STRACE_H

/* C standard library */
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* POSIX */
#include <unistd.h>
#include <sys/user.h>
#include <sys/wait.h>

/* Linux */
#include <syscall.h>
#include <sys/ptrace.h>

/* The Makefile generated a syscall string
 * table using the `ausyscall` command
 */
// #include "syscall_table.h"

void handle_signals(pid_t tracee_pid, int status);
void handle_syscalls(pid_t tracee_pid);

#define FATAL(...)                               \
	do                                           \
	{                                            \
		fprintf(stderr, "strace: " __VA_ARGS__); \
		fputc('\n', stderr);                     \
		exit(EXIT_FAILURE);                      \
	} while (0)

#endif
