#include "ft_strace.h"
#include "syscallent.h"

void print_syscall_args(long unsigned syscall_number, void *args[6], pid_t tracee_pid)
{
	if (syscall_number >= (sizeof(syscall_table) / sizeof(syscall_entry_t)))
	{
		fprintf(stderr, "Unknown syscall: %ld\n", syscall_number);
		return;
	}

	syscall_entry_t entry = syscall_table[syscall_number];
	fprintf(stderr, "%s(", entry.name);

	for (int j = 0; j < entry.num_args; j++)
	{
		long val = *((long *)args[j]);

		switch (entry.arg_types[j])
		{
		case ARG_TYPE_INT:
			// val holds an integer argument
			fprintf(stderr, "%d", (int)val);
			break;
		case ARG_TYPE_LONG:
			// val holds a long argument
			fprintf(stderr, "%ld", val);
			break;
		case ARG_TYPE_PTR:
			// val holds a pointer argument
			fprintf(stderr, "%p", (void *)val);
			break;
		case ARG_TYPE_STR:
			void *buf_addr = (void *)val;

			// Limit buffer size to avoid overflow
			size_t max_read_size = MAX_BUFFER_SIZE - 1;
			char buffer[MAX_BUFFER_SIZE] = {0};

			// Read buffer content from the traced process's memory
			ssize_t bytes_read = read_process_memory(tracee_pid, (void *)buf_addr, buffer, max_read_size);
			if (bytes_read == -1)
				snprintf(buffer, sizeof(buffer), "<Unable to read memory>");
			else
				buffer[bytes_read] = '\0';

			// Escape special characters for safe display
			char escaped_buffer[MAX_BUFFER_SIZE * 4]; // size sufficient for escaped characters
			escape_string(buffer, escaped_buffer, sizeof(escaped_buffer));

			// Truncate if too long
			// Format the output with truncation logic
			if (strlen(escaped_buffer) > 33)
				fprintf(stderr, "\"%.33s\"...", escaped_buffer);
			else
				fprintf(stderr, "\"%s\"", escaped_buffer);
			break;
		case ARG_TYPE_SIZE:
			// val holds a size_t
			fprintf(stderr, "%zu", (size_t)val);
			break;
		default:
			fprintf(stderr, "?");
			break;
		}

		if (j < entry.num_args - 1)
			fprintf(stderr, ", ");
	}
}

void print_syscall_entry(pid_t tracee_pid)
{
	struct user_regs_struct regs;

	if (ptrace(PTRACE_GETREGS, tracee_pid, 0, &regs) == -1)
		print_error_and_exit("print_syscall_entry", "ptrace(PTRACE_GETREGS)");
	unsigned long long syscall_number = regs.orig_rax;

	void *args[6] = {
		&regs.rdi,
		&regs.rsi,
		&regs.rdx,
		&regs.r10,
		&regs.r8,
		&regs.r9,
	};

	print_syscall_args((int)syscall_number, args, tracee_pid);
}

void print_syscall_exit(pid_t tracee_pid)
{
	struct user_regs_struct regs;

	if (ptrace(PTRACE_GETREGS, tracee_pid, 0, &regs) == -1)
		print_error_and_exit("print_syscall_exit", "ptrace(PTRACE_GETREGS)");

	fprintf(stderr, ") = %ld\n", (long)regs.rax);
}
