#include "ft_strace.h"
#include "syscall_table.h"

void print_syscall_entry(pid_t tracee_pid)
{
	struct user_regs_struct regs;

	/* Gather system call arguments */
	if (ptrace(PTRACE_GETREGS, tracee_pid, 0, &regs) == -1)
		pr_error("handle_syscall", "ptrace(PTRACE_GETREGS)");
	long syscall = regs.orig_rax;

	/* Print a representation of the system call */
	fprintf(stderr, "%s(%ld, %ld, %ld, %ld, %ld, %ld)",
			g_syscall_names[syscall],
			(long)regs.rdi, (long)regs.rsi, (long)regs.rdx,
			(long)regs.r10, (long)regs.r8, (long)regs.r9);
}

void print_syscall_exit(pid_t tracee_pid)
{
	struct user_regs_struct regs;

	/* Get system call result */
	if (ptrace(PTRACE_GETREGS, tracee_pid, 0, &regs) == -1)
		pr_error("handle_syscall", "ptrace(PTRACE_GETREGS)");

	/* Print system call result */
	fprintf(stderr, " = %ld\n", (long)regs.rax);
}
