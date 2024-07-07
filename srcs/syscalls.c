#include "ft_strace.h"
#include "syscall_table.h"

void handle_syscall(pid_t tracee_pid)
{
	/* Gather system call arguments */
	struct user_regs_struct regs;
	if (ptrace(PTRACE_GETREGS, tracee_pid, 0, &regs) == -1)
		pr_error("handle_syscall", "ptrace(PTRACE_GETREGS)");
	long syscall = regs.orig_rax;

	/* Print a representation of the system call */
	fprintf(stderr, "%s(%ld, %ld, %ld, %ld, %ld, %ld)",
			g_syscall_names[syscall],
			(long)regs.rdi, (long)regs.rsi, (long)regs.rdx,
			(long)regs.r10, (long)regs.r8, (long)regs.r9);

	/* Run system call and stop on exit */
	if (ptrace(PTRACE_SYSCALL, tracee_pid, 0, 0) == -1)
		pr_error("handle_syscall", "ptrace(PTRACE_SYSCALL)");
	if (waitpid(tracee_pid, 0, 0) == -1)
		pr_error("handle_syscall", "waitpid");

	/* Get system call result */
	if (ptrace(PTRACE_GETREGS, tracee_pid, 0, &regs) == -1)
	{
		fputs(" = ?\n", stderr);
		if (errno == ESRCH)
			exit(regs.rdi); // system call was _exit(2) or similar
		pr_error("handle_syscall", "ptrace(PTRACE_GETREGS)");
	}

	/* Print system call result */
	fprintf(stderr, " = %ld\n", (long)regs.rax);
	if (ptrace(PTRACE_SYSCALL, tracee_pid, 0, 0) == -1)
		pr_error("handle_syscall", "ptrace(PTRACE_SYSCALL)");
}
