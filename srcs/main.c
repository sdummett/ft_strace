#include "ft_strace.h"

int execute_tracee(char **argv)
{
	// Stop this process so the parent can attach using ptrace
	raise(SIGSTOP);

	// Replace the current process image with the target program
	if (execvp(argv[1], argv + 1))
		print_error_and_exit("execute_tracee", "execvp");
	return EXIT_SUCCESS;
}

int start_tracing(pid_t tracee_pid)
{
	// Attach to the child process for tracing
	if (ptrace(PTRACE_SEIZE, tracee_pid, 0, 0) == -1)
		print_error_and_exit("start_tracing", "ptrace(PTRACE_SEIZE)");

	// Wait for the child to stop before setting ptrace options
	if (waitpid(tracee_pid, 0, 0) == -1)
		print_error_and_exit("start_tracing", "waitpid");

	// Configure ptrace to kill the tracee on unexpected exits and distinguish syscall stops
	if (ptrace(PTRACE_SETOPTIONS, tracee_pid, 0,
			   PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD) == -1)
		print_error_and_exit("start_tracing", "ptrace(PTRACE_SETOPTIONS)");

	bool is_syscall_entry = true;
	int signal_number = 0;

	while (1)
	{
		// Resume the process until the next syscall or signal
		if (ptrace(PTRACE_SYSCALL, tracee_pid, 0, signal_number) == -1)
			print_error_and_exit("start_tracing", "ptrace(PTRACE_SYSCALL)");
		signal_number = 0;

		int status;
		if (waitpid(tracee_pid, &status, 0) == -1)
			print_error_and_exit("start_tracing", "waitpid");

		int stop_signal = WSTOPSIG(status);

		// If the process stopped for a reason unrelated to a syscall, handle the signal
		if (WIFSTOPPED(status) && stop_signal != SYSCALL_TRAP)
			signal_number = print_signal_info(tracee_pid);
		else if (WIFSTOPPED(status) && stop_signal == SYSCALL_TRAP)
		{
			if (is_syscall_entry)
				print_syscall_entry(tracee_pid);
			else
				print_syscall_exit(tracee_pid);
			is_syscall_entry = !is_syscall_entry;
		}

		// Check if the tracee has exited or was killed by a signal
		if (WIFEXITED(status))
		{
			// If we were still printing syscall args, close them properly
			if (!is_syscall_entry)
				fprintf(stderr, ") = ?\n");
			fprintf(stderr, "+++ exited with %d +++\n", WEXITSTATUS(status));
			exit(WEXITSTATUS(status));
		}
		else if (WIFSIGNALED(status))
		{
			if (!is_syscall_entry)
				fprintf(stderr, " = ?\n");
			fprintf(stderr, "+++ killed by %s +++\n", get_signal_name(WTERMSIG(status)));
			raise(WTERMSIG(status));
			exit(status);
		}
	}
	return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
	// Block certain signals in the parent to avoid interruptions
	block_signals();

	if (argc <= 1)
	{
		fprintf(stderr, "%s: must have PROG [ARGS]\n", argv[0]);
		return EXIT_FAILURE;
	}

	struct stat file_stat;
	char *file_path = get_full_path(argv[1]);

	// If the file isn't found or stat fails, report the error
	if (!file_path || stat(file_path, &file_stat) < 0)
	{
		fprintf(stderr, "%s: Can't stat '%s': %s\n",
				argv[0], argv[1], strerror(errno));
		return 1;
	}

	int fd = open(file_path, O_RDONLY);
	if (fd == -1)
	{
		free(file_path);
		print_error_and_exit("main", "open");
	}

	// Map the file into memory to inspect its ELF header
	Elf64_Ehdr *ehdr = mmap(NULL, file_stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (ehdr == MAP_FAILED)
	{
		close(fd);
		free(file_path);
		print_error_and_exit("main", "mmap");
	}

	int binary_arch = ehdr->e_ident[EI_CLASS];

	munmap(ehdr, file_stat.st_size);
	close(fd);
	free(file_path);

	// Check if it's a 32-bit or 64-bit ELF; otherwise it's unsupported
	if (binary_arch != ELFCLASS64 && binary_arch != ELFCLASS32)
	{
		fprintf(stderr, "%s: Unknown architecture for %s\n", argv[0], argv[1]);
		return 1;
	}

	// Fork to create a child (tracee) and parent (traceur)
	pid_t pid = fork();
	if (pid == -1)
		print_error_and_exit("main", "fork");
	else if (pid == 0)
		return execute_tracee(argv);

	return start_tracing(pid);
}
