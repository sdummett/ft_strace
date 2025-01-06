#ifndef FT_STRACE_H
#define FT_STRACE_H

// Define _GNU_SOURCE so we can use process_vm_readv
#define _GNU_SOURCE

#define SYSCALL_TRAP (SIGTRAP | 0x80)
#define SIGINFO_STR_SIZE 128
#define MAX_BUFFER_SIZE 256

/*
 * Standard and POSIX headers
 */
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <stdbool.h>
#include <ctype.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <elf.h>

/*
 * Custom tables for errno values and signals
 */
#include <errno_table.h>
#include <signal_table.h>

/*
 * Structures for 32-bit (i386) register state
 */
typedef struct s_i386_user_regs
{
	uint32_t ebx;
	uint32_t ecx;
	uint32_t edx;
	uint32_t esi;
	uint32_t edi;
	uint32_t ebp;
	uint32_t eax;
	uint32_t xds;
	uint32_t xes;
	uint32_t xfs;
	uint32_t xgs;
	uint32_t orig_eax;
	uint32_t eip;
	uint32_t xcs;
	uint32_t eflags;
	uint32_t esp;
	uint32_t xss;
} t_i386_user_regs;

/*
 * Structures for 64-bit (x86_64) register state
 */
typedef struct s_x86_64_user_regs
{
	uint64_t r15;
	uint64_t r14;
	uint64_t r13;
	uint64_t r12;
	uint64_t rbp;
	uint64_t rbx;
	uint64_t r11;
	uint64_t r10;
	uint64_t r9;
	uint64_t r8;
	uint64_t rax;
	uint64_t rcx;
	uint64_t rdx;
	uint64_t rsi;
	uint64_t rdi;
	uint64_t orig_rax;
	uint64_t rip;
	uint64_t cs;
	uint64_t eflags;
	uint64_t rsp;
	uint64_t ss;
	uint64_t fs_base;
	uint64_t gs_base;
	uint64_t ds;
	uint64_t es;
	uint64_t fs;
	uint64_t gs;
} t_x86_64_user_regs;

/*
 * Union that can represent either 32-bit or 64-bit registers
 */
typedef union u_user_regs
{
	t_i386_user_regs regs32;
	t_x86_64_user_regs regs64;
} t_user_regs;

/*
 * Architecture enum to differentiate between 32-bit and 64-bit binaries
 */
typedef enum e_arch
{
	X_32 = 32,
	X_64 = 64,
} t_arch;

/*
 * Enum describing the type of each syscall argument
 */
typedef enum e_arg_type
{
	ARG_TYPE_INT,
	ARG_TYPE_LONG,
	ARG_TYPE_PTR,
	ARG_TYPE_STR,
	ARG_TYPE_SIZE,
} t_arg_type;

/*
 * Structure describing a single syscall:
 * - number: syscall number
 * - name: human-readable name
 * - num_args: how many arguments it takes
 * - arg_types: the type of each argument
 */
typedef struct s_syscall_entry
{
	long unsigned int number;
	const char *name;
	int num_args;
	t_arg_type arg_types[6];
} t_syscall_entry;

/*
 * Function prototypes for signal handling, syscall entry/exit printing,
 * error handling, memory reads, etc.
 */
const char *get_signal_name(int signo);
const char *get_siginfo_code_name(int si_code);
void print_syscall_entry(pid_t tracee_pid);
void print_syscall_exit(pid_t tracee_pid);
void print_error_and_exit(const char *function, const char *syscall);
int print_signal_info(pid_t tracee_pid);
void escape_string(const char *input, char *output, size_t max_length);
ssize_t read_process_memory(pid_t pid, void *remote_addr, void *local_buffer, size_t length);
char *get_full_path(const char *filename);
void block_signals();

#endif // FT_STRACE_H
