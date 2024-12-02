#ifndef FT_STRACE_H
#define FT_STRACE_H

#define SYSCALL_TRAP (SIGTRAP | 0x80)
#define SIGINFO_STR_SIZE 128

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

const char	*get_signal_name(int signo);
const char	*get_siginfo_code_name(int si_code);
void		print_syscall_entry(pid_t tracee_pid);
void		print_syscall_exit(pid_t tracee_pid);
void		print_error_and_exit(const char *function, const char *syscall);
int			print_signal_info(pid_t tracee_pid);

#endif
