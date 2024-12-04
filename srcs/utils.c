#include "ft_strace.h"

ssize_t read_process_memory(pid_t pid, void *remote_addr, void *local_buffer, size_t length)
{
	struct iovec local_iov = {.iov_base = local_buffer, .iov_len = length};
	struct iovec remote_iov = {.iov_base = remote_addr, .iov_len = length};

	ssize_t nread = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
	if (nread == -1)
		return -1;
	return nread;
}

void escape_string(const char *input, char *output, size_t max_length)
{
	size_t i = 0, j = 0;
	while (input[i] != '\0' && j < max_length - 1)
	{
		if (isprint((unsigned char)input[i]))
			output[j++] = input[i];
		else
		{
			if (j + 4 >= max_length - 1)
				break;
			snprintf(&output[j], 5, "\\x%02x", (unsigned char)input[i]);
			j += 4;
		}
		i++;
	}
	output[j] = '\0';
}

void print_error_and_exit(const char *function, const char *syscall)
{
	fprintf(stderr, "ft_strace: %s: %s: %s.\n", function, syscall, strerror(errno));
	exit(EXIT_FAILURE);
}
