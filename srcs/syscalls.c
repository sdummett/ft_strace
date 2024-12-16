#include "ft_strace.h"
#include "syscallent_x64.h"
#include "syscallent_x32.h"

t_syscall_entry *get_syscall_entry(long unsigned syscall_number, t_arch arch)
{
	union
	{
		t_syscall_entry *x32;
		t_syscall_entry *x64;
	} syscall_table_current;

	size_t table_size;
	if (arch == X_64)
	{
		syscall_table_current.x64 = syscall_table_x64;
		table_size = sizeof(syscall_table_x64) / sizeof(syscall_table_x64[0]);
	}
	else
	{
		syscall_table_current.x32 = syscall_table_x32;
		table_size = sizeof(syscall_table_x32) / sizeof(syscall_table_x32[0]);
	}

	for (size_t i = 0; i < table_size; i++)
	{
		t_syscall_entry *entry = (arch == X_64) ? &syscall_table_current.x64[i]
												: &syscall_table_current.x32[i];
		if (entry->number == syscall_number)
			return entry;
	}

	return NULL;
}

void print_syscall_args(long unsigned syscall_number, void *args[6], pid_t tracee_pid, t_arch arch)
{
	t_syscall_entry *syscall = get_syscall_entry(syscall_number, arch);

	if (!syscall)
	{
		fprintf(stderr, "Unknown syscall: %ld\n", syscall_number);
		return;
	}

	fprintf(stderr, "%s(", syscall->name);

	for (int j = 0; j < syscall->num_args; j++)
	{
		long val = *((long *)args[j]);

		switch (syscall->arg_types[j])
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

		if (j < syscall->num_args - 1)
			fprintf(stderr, ", ");
	}
}

void set_regs32_to_current_regs(t_x86_64_user_regs *current_regs, t_i386_user_regs *regs32)
{
	current_regs->orig_rax = regs32->orig_eax;
	current_regs->rax = regs32->eax;
	current_regs->rdi = regs32->ebx;
	current_regs->rsi = regs32->ecx;
	current_regs->rdx = regs32->edx;
	current_regs->rcx = regs32->esi;
	current_regs->r8 = regs32->edi;
	current_regs->r9 = regs32->ebp;
}

void print_syscall_entry(pid_t tracee_pid)
{
	t_user_regs regs;
	struct iovec iov = {
		.iov_base = &regs,
		.iov_len = sizeof(regs),
	};

	if (ptrace(PTRACE_GETREGSET, tracee_pid, (void *)NT_PRSTATUS, &iov) == -1)
		print_error_and_exit("print_syscall_entry", "ptrace(PTRACE_GETREGSET)");

	t_arch arch = (regs.regs32.xcs == 0x0 && regs.regs64.cs == 0x33) ? X_64 : X_32;

	t_x86_64_user_regs current_regs = {0};
	if (arch == X_64)
		current_regs = regs.regs64;
	else
		set_regs32_to_current_regs(&current_regs, &regs.regs32);

	unsigned long long syscall_number = current_regs.orig_rax;

	void *args[6] = {
		&current_regs.rdi,
		&current_regs.rsi,
		&current_regs.rdx,
		&current_regs.r10,
		&current_regs.r8,
		&current_regs.r9,
	};

	print_syscall_args(syscall_number, args, tracee_pid, arch);
}

void print_syscall_exit(pid_t tracee_pid)
{
	struct user_regs_struct regs;

	if (ptrace(PTRACE_GETREGS, tracee_pid, 0, &regs) == -1)
		print_error_and_exit("print_syscall_exit", "ptrace(PTRACE_GETREGS)");

	fprintf(stderr, ") = %lld\n", regs.rax);
}
