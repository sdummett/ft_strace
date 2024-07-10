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

#include <stdbool.h>
/* The Makefile generated a syscall string
 * table using the `ausyscall` command
 */
// #include "syscall_table.h"

const char	*signal_name(int signo);
const char	*siginfo_code_name(int si_code);
void		print_syscall_entry(pid_t tracee_pid);
void		print_syscall_exit(pid_t tracee_pid);
void		pr_error(char *function, char *syscall);
int 		print_siginfo(pid_t tracee_pid);


#endif
