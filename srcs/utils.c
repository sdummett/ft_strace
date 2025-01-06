#include "ft_strace.h"

ssize_t read_process_memory(pid_t pid, void *remote_addr, void *local_buffer, size_t length)
{
	// Use process_vm_readv to copy data from the tracee's memory into local_buffer
	struct iovec local_iov = {.iov_base = local_buffer, .iov_len = length};
	struct iovec remote_iov = {.iov_base = remote_addr, .iov_len = length};

	ssize_t nread = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
	if (nread == -1)
		return -1;
	return nread;
}

void escape_string(const char *input, char *output, size_t max_length)
{
	// Convert non-printable characters into their escaped form (\xHH)
	size_t i = 0, j = 0;
	while (input[i] != '\0' && j < max_length - 1)
	{
		if (isprint((unsigned char)input[i]))
		{
			output[j++] = input[i];
		}
		else
		{
			// Ensure there's room for the 4-character escape sequence
			if (j + 4 >= max_length - 1)
				break;
			snprintf(&output[j], 5, "\\x%02x", (unsigned char)input[i]);
			j += 4;
		}
		i++;
	}
	output[j] = '\0';
}

char *get_full_path(const char *filename)
{
	// Handle paths that start with "./"
	struct stat file_stat;
	if (filename[0] == '.')
	{
		char full_path[4096];
		char cwd[4096];
		snprintf(full_path, sizeof(full_path), "%s%s",
				 getcwd(cwd, sizeof(cwd)), filename + 1);
		if (stat(filename, &file_stat) == 0)
			return strdup(filename);
	}

	// If filename is not a direct path, attempt to locate it in PATH
	char *path = getenv("PATH");
	if (!path)
		return NULL;

	char *paths = strdup(path);
	char *dir = strtok(paths, ":");

	// Check each directory in PATH to see if the file exists
	while (dir)
	{
		char full_path[4096];
		snprintf(full_path, sizeof(full_path), "%s/%s", dir, filename);
		if (stat(full_path, &file_stat) == 0)
		{
			free(paths);
			return strdup(full_path);
		}
		dir = strtok(NULL, ":");
	}

	free(paths);
	return NULL;
}

void print_error_and_exit(const char *function, const char *syscall)
{
	// Print the error message and terminate the program
	fprintf(stderr, "ft_strace: %s: %s: %s.\n",
			function, syscall, strerror(errno));
	exit(EXIT_FAILURE);
}
