#include "ft_strace.h"
#include "syscall_table.h"

void print_syscall_entry(pid_t tracee_pid)
{
	struct user_regs_struct regs;

	if (ptrace(PTRACE_GETREGS, tracee_pid, 0, &regs) == -1)
		print_error_and_exit("print_syscall_entry", "ptrace(PTRACE_GETREGS)");
	long syscall_number = regs.orig_rax;

	if (syscall_number == SYS_write)
		format_write(tracee_pid, &regs);
	else
	{
		fprintf(stderr, "%s(%ld, %ld, %ld, %ld, %ld, %ld)",
				g_syscall_names[syscall_number],
				(long)regs.rdi, (long)regs.rsi, (long)regs.rdx,
				(long)regs.r10, (long)regs.r8, (long)regs.r9);
	}
}

void print_syscall_exit(pid_t tracee_pid)
{
	struct user_regs_struct regs;

	if (ptrace(PTRACE_GETREGS, tracee_pid, 0, &regs) == -1)
		print_error_and_exit("print_syscall_exit", "ptrace(PTRACE_GETREGS)");

	fprintf(stderr, " = %ld\n", (long)regs.rax);
}
