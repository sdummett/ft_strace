#include "ft_strace.h"

void format_write(pid_t pid, struct user_regs_struct *regs)
{
	int fd = (int)regs->rdi;
	unsigned long buf_addr = regs->rsi;
	size_t count = (size_t)regs->rdx;

	// Limit buffer size to avoid overflow
	size_t max_read_size = (count < MAX_BUFFER_SIZE - 1) ? count : MAX_BUFFER_SIZE - 1;
	char buffer[MAX_BUFFER_SIZE] = {0};

	// Read buffer content from the traced process's memory
	ssize_t bytes_read = read_process_memory(pid, (void *)buf_addr, buffer, max_read_size);
	if (bytes_read == -1)
		snprintf(buffer, sizeof(buffer), "<Unable to read memory>");
	else
		buffer[bytes_read] = '\0';

	// Escape special characters for safe display
	char escaped_buffer[MAX_BUFFER_SIZE * 4]; // Size sufficient for escaped characters
	escape_string(buffer, escaped_buffer, sizeof(escaped_buffer));

	// Format the output with truncation logic
	if (strlen(escaped_buffer) > 33)
		fprintf(stderr, "write(%d, \"%.33s\"..., %zu)", fd, escaped_buffer, count);
	else
		fprintf(stderr, "write(%d, \"%s\", %zu)", fd, escaped_buffer, count);
}
