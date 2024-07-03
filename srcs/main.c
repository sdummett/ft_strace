#include "ft_strace.h"

int do_child(char **argv)
{
	ptrace(PTRACE_TRACEME);
	/* Because we're now a tracee, execvp will block until the parent
	 * attaches and allows us to continue. */
	return execvp(argv[1], argv + 1);
	// FATAL("%s", strerror(errno));
}

int do_trace(pid_t tracee_pid)
{
	/* parent */
	/* sync with execvp */
	waitpid(tracee_pid, 0, 0);

	/*	PTRACE_O_EXITKILL: ???
	 * 	PTRACE_O_TRACESYSGOOD: ???
	 */
	ptrace(PTRACE_SETOPTIONS, tracee_pid, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD);

	while (1)
	{
		/* Enter next system call */
		if (ptrace(PTRACE_SYSCALL, tracee_pid, 0, 0) == -1)
			FATAL("%s", strerror(errno));

		int status;
		if (waitpid(tracee_pid, &status, 0) == -1)
			FATAL("%s", strerror(errno));

		handle_signals(tracee_pid, status);
		handle_syscalls(tracee_pid);
	}
	return 0;
}

int main(int argc, char *argv[])
{
	if (argc <= 1)
		FATAL("too few arguments: %d", argc);

	pid_t pid = fork();
	if (pid == -1)
		FATAL("%s", strerror(errno));
	else if (pid == 0)
		return do_child(argv);
	return do_trace(pid);
}
