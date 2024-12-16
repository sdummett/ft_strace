#include "ft_strace.h"

int execute_tracee(char **argv)
{
	// Indique au parent qu'il peut attacher ce processus
	raise(SIGSTOP);

	// Exécute le programme à tracer
	if (execvp(argv[1], argv + 1))
		print_error_and_exit("execute_tracee", "execvp");
	return EXIT_SUCCESS;
}

int start_tracing(pid_t tracee_pid)
{
	// Parent : initialisation du traçage
	if (ptrace(PTRACE_SEIZE, tracee_pid, 0, 0) == -1)
		print_error_and_exit("start_tracing", "ptrace(PTRACE_SEIZE)");

	if (waitpid(tracee_pid, 0, 0) == -1)
		print_error_and_exit("start_tracing", "waitpid");

	if (ptrace(PTRACE_SETOPTIONS, tracee_pid, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD) == -1)
		print_error_and_exit("start_tracing", "ptrace(PTRACE_SETOPTIONS)");

	bool is_syscall_entry = true;
	int signal_number = 0;

	while (1)
	{
		// Continue le processus jusqu'au prochain syscall ou signal
		if (ptrace(PTRACE_SYSCALL, tracee_pid, 0, signal_number) == -1)
			print_error_and_exit("start_tracing", "ptrace(PTRACE_SYSCALL)");
		signal_number = 0;

		int status;
		if (waitpid(tracee_pid, &status, 0) == -1)
			print_error_and_exit("start_tracing", "waitpid");

		int stop_signal = WSTOPSIG(status);

		// Gestion des signaux autres que les arrêts de syscall
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

		// Gestion de la fin du processus tracé
		if (WIFEXITED(status))
		{
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
		}
	}
	return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
	if (argc <= 1)
	{
		fprintf(stderr, "%s: must have PROG [ARGS]\n", argv[0]);
		return EXIT_FAILURE;
	}

	struct stat file_stat;
	char *file_path = get_full_path(argv[1]);

	if (!file_path || stat(file_path, &file_stat) < 0)
	{
		fprintf(stderr, "%s: Can't stat '%s': %s\n", argv[0], argv[1], strerror(errno));
		return 1;
	}

	int fd = open(file_path, O_RDONLY);
	if (fd == -1)
	{
		free(file_path);
		print_error_and_exit("main", "open");
	}

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

	if (binary_arch != ELFCLASS64 && binary_arch != ELFCLASS32)
	{
		fprintf(stderr, "%s: Unknown architecture for %s\n", argv[0], argv[1]);
		return 1;
	}

	pid_t pid = fork();
	if (pid == -1)
		print_error_and_exit("main", "fork");
	else if (pid == 0)
		return execute_tracee(argv);
	return start_tracing(pid);
}
