#include "ft_strace.h"
#include "syscall_table.h"

void print_syscall_entry(pid_t tracee_pid)
{
	struct user_regs_struct regs;

	// Récupère les registres du processus tracé
	if (ptrace(PTRACE_GETREGS, tracee_pid, 0, &regs) == -1)
		print_error_and_exit("print_syscall_entry", "ptrace(PTRACE_GETREGS)");
	long syscall_number = regs.orig_rax;

	// Affiche le nom du syscall et ses arguments
	fprintf(stderr, "%s(%ld, %ld, %ld, %ld, %ld, %ld)",
			g_syscall_names[syscall_number],
			(long)regs.rdi, (long)regs.rsi, (long)regs.rdx,
			(long)regs.r10, (long)regs.r8, (long)regs.r9);
}

void print_syscall_exit(pid_t tracee_pid)
{
	struct user_regs_struct regs;

	// Récupère le résultat du syscall
	if (ptrace(PTRACE_GETREGS, tracee_pid, 0, &regs) == -1)
		print_error_and_exit("print_syscall_exit", "ptrace(PTRACE_GETREGS)");

	// Affiche le résultat du syscall
	fprintf(stderr, " = %ld\n", (long)regs.rax);
}
