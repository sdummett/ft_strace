#include "ft_strace.h"

void pr_error(char *function, char *syscall) {
	fprintf(stderr, "ft_strace: %s: %s: %s.\n", function, syscall, strerror(errno));
	exit(EXIT_FAILURE);
}

int do_child(char **argv)
{
	ptrace(PTRACE_TRACEME);
	/* Because we're now a tracee, execvp will block until the parent
	 * attaches and allows us to continue. */
	if (execvp(argv[1], argv + 1))
		pr_error("do_child", "execvp");
	return 0;
}

int do_trace(pid_t tracee_pid)
{
	/* parent */
	/* sync with execvp */
	if (waitpid(tracee_pid, 0, 0) < 0)
		pr_error("do_trace", "waitpid");

	/*	PTRACE_O_EXITKILL: ???
	 * 	PTRACE_O_TRACESYSGOOD: ???
	 */
	if (ptrace(PTRACE_SETOPTIONS, tracee_pid, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD) == -1)
		pr_error("do_trace", "ptrace(PTRACE_SETOPTIONS)");

	/* Enter next system call */
	if (ptrace(PTRACE_SYSCALL, tracee_pid, 0, 0) == -1)
		pr_error("do_trace", "ptrace(PTRACE_SYSCALL)");

	while (1)
	{
		// printf("[FT_STRACE PID]: %d\n", getpid());
		int status;
		if (waitpid(tracee_pid, &status, 0) == -1)
			pr_error("do_trace", "waitpid");

		int sig = WSTOPSIG(status);

		if (WIFEXITED(status))
		{
			printf("Child exited with status %d\n", WEXITSTATUS(status));
		}
		else if (WIFSIGNALED(status))
		{
			printf("Child killed by signal %d (%s)\n", WTERMSIG(status), signal_name(WTERMSIG(status)));
		}
		/* If child has stopped by a signal */
		// Ignore SIGTRAP signals generated by syscall
		else if (WIFSTOPPED(status) && sig != (SIGTRAP | 0x80))
		{
			handle_signal(tracee_pid);
		}
		else if (WIFSTOPPED(status) && sig == (SIGTRAP | 0x80))
		{
			handle_syscall(tracee_pid);
		}
	}
	return 0;
}

int main(int argc, char *argv[])
{
	if (argc <= 1)
		fprintf(stderr, "too few arguments: %d", argc);

	pid_t pid = fork();
	if (pid == -1)
		pr_error("main", "fork");
	else if (pid == 0)
		return do_child(argv);
	return do_trace(pid);
}
