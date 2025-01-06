#include "ft_strace.h"
#include "syscallent_x64.h"
#include "syscallent_x32.h"

t_syscall_entry *get_syscall_entry(long unsigned syscall_number, t_arch arch)
{
	// Union allows us to select between the 32-bit and 64-bit syscall tables
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

	// Iterate through the selected syscall table to find a match
	for (size_t i = 0; i < table_size; i++)
	{
		t_syscall_entry *entry = (arch == X_64) ? &syscall_table_current.x64[i]
												: &syscall_table_current.x32[i];

		if (entry->number == syscall_number)
			return entry;
	}

	// Return NULL if the syscall number is not found
	return NULL;
}

void print_syscall_args(long unsigned syscall_number, void *args[6], pid_t tracee_pid, t_arch arch)
{
	// Retrieve the appropriate syscall entry
	t_syscall_entry *syscall = get_syscall_entry(syscall_number, arch);
	if (!syscall)
	{
		fprintf(stderr, "Unknown syscall: %ld\n", syscall_number);
		return;
	}

	fprintf(stderr, "%s(", syscall->name);

	// Print each argument based on its type (int, long, ptr, string, etc.)
	for (int j = 0; j < syscall->num_args; j++)
	{
		long val = *((long *)args[j]);

		switch (syscall->arg_types[j])
		{
		case ARG_TYPE_INT:
			// Output the argument as an integer
			fprintf(stderr, "%d", (int)val);
			break;
		case ARG_TYPE_LONG:
			// Output the argument as a long
			fprintf(stderr, "%ld", val);
			break;
		case ARG_TYPE_PTR:
			// Output the argument as a pointer
			fprintf(stderr, "%p", (void *)val);
			break;
		case ARG_TYPE_STR:
		{
			// Read the string from the tracee's memory and escape special characters
			void *buf_addr = (void *)val;
			size_t max_read_size = MAX_BUFFER_SIZE - 1;
			char buffer[MAX_BUFFER_SIZE] = {0};

			// Pull the data from the tracee
			ssize_t bytes_read = read_process_memory(tracee_pid, buf_addr, buffer, max_read_size);
			if (bytes_read == -1)
				snprintf(buffer, sizeof(buffer), "<Unable to read memory>");
			else
				buffer[bytes_read] = '\0';

			// Escape non-printable characters
			char escaped_buffer[MAX_BUFFER_SIZE * 4];
			escape_string(buffer, escaped_buffer, sizeof(escaped_buffer));

			// Truncate the output if it's too long
			if (strlen(escaped_buffer) > 33)
				fprintf(stderr, "\"%.33s\"...", escaped_buffer);
			else
				fprintf(stderr, "\"%s\"", escaped_buffer);
			break;
		}
		case ARG_TYPE_SIZE:
			// Output the argument as size_t
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
	// Map the 32-bit registers into the 64-bit register structure
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
	// Fetch the register values to identify the syscall and its arguments
	t_user_regs regs;
	struct iovec iov = {
		.iov_base = &regs,
		.iov_len = sizeof(regs),
	};

	if (ptrace(PTRACE_GETREGSET, tracee_pid, (void *)NT_PRSTATUS, &iov) == -1)
		print_error_and_exit("print_syscall_entry", "ptrace(PTRACE_GETREGSET)");

	// Detect the architecture by checking register segments
	t_arch arch = (regs.regs32.xcs == 0x0 && regs.regs64.cs == 0x33) ? X_64 : X_32;

	// Copy the 32-bit registers into a 64-bit structure if needed
	t_x86_64_user_regs current_regs = {0};
	if (arch == X_64)
		current_regs = regs.regs64;
	else
		set_regs32_to_current_regs(&current_regs, &regs.regs32);

	// orig_rax holds the syscall number in x86_64
	unsigned long long syscall_number = current_regs.orig_rax;

	// Gather arguments in the standard x86_64 calling convention order
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

const char *errno_to_name(int err)
{
	// Match an errno to its textual name in errno_names
	for (int i = 0; errno_names[i].name != NULL; i++)
	{
		if (errno_names[i].code == err)
			return errno_names[i].name;
	}
	return NULL;
}

void print_syscall_exit(pid_t tracee_pid)
{
	// Once the syscall finishes, retrieve the registers to see the return value
	struct user_regs_struct regs;

	if (ptrace(PTRACE_GETREGS, tracee_pid, 0, &regs) == -1)
		print_error_and_exit("print_syscall_exit", "ptrace(PTRACE_GETREGS)");

	long long retval = (long long)regs.rax;

	// If retval is negative, interpret it as errno
	if (retval < 0)
	{
		int err = -retval;
		const char *err_name = errno_to_name(err);
		if (!err_name)
			err_name = "UNKNOWN_ERRNO";

		fprintf(stderr, ") = -1 %s (%s)\n", err_name, strerror(err));
	}
	else
	{
		// Otherwise, just print the return value
		fprintf(stderr, ") = %lld\n", retval);
	}
}
