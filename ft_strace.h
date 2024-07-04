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

void		handle_signal(pid_t tracee_pid);
const char	*signal_name(int signo);
const char	*siginfo_code_name(int si_code);
void		handle_syscall(pid_t tracee_pid);

#define FATAL(...)                               \
	do                                           \
	{                                            \
		fprintf(stderr, "strace: " __VA_ARGS__); \
		fputc('\n', stderr);                     \
		exit(EXIT_FAILURE);                      \
	} while (0)

#endif
