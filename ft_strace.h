#ifndef FT_STRACE_H
#define FT_STRACE_H

#define SYSCALL_TRAP (SIGTRAP | 0x80)
#define SIGINFO_STR_SIZE 128
#define MAX_BUFFER_SIZE 256

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
#include <sys/uio.h>

#include <stdbool.h>
#include <ctype.h>

const char	*get_signal_name(int signo);
const char	*get_siginfo_code_name(int si_code);
void		print_syscall_entry(pid_t tracee_pid);
void		print_syscall_exit(pid_t tracee_pid);
void		print_error_and_exit(const char *function, const char *syscall);
int			print_signal_info(pid_t tracee_pid);
void		format_write(pid_t pid, struct user_regs_struct *regs);
void		escape_string(const char *input, char *output, size_t max_length);
ssize_t		read_process_memory(pid_t pid, void *remote_addr, void *local_buffer, size_t length);

#endif
