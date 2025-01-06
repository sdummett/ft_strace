#include "ft_strace.h"

int print_signal_info(pid_t tracee_pid)
{
	char siginfo_str[SIGINFO_STR_SIZE];

	siginfo_t siginfo;
	if (ptrace(PTRACE_GETSIGINFO, tracee_pid, NULL, &siginfo) == -1)
		print_error_and_exit("print_signal_info", "ptrace(PTRACE_GETSIGINFO)");

	snprintf(siginfo_str, SIGINFO_STR_SIZE, "{si_signo=%s, si_code=%s, si_pid=%d, si_uid=%d}",
			 get_signal_name(siginfo.si_signo), get_siginfo_code_name(siginfo.si_code),
			 siginfo.si_pid, siginfo.si_uid);
	printf("--- %s %s ---\n", get_signal_name(siginfo.si_signo), siginfo_str);

	return siginfo.si_signo;
}

const char *get_signal_name(int signo)
{
	if (signo == 32)
		return "SIGRTMIN";
	if (signo == 33)
		return "SIGRT_1";

	if (signo >= SIGRTMIN && signo <= SIGRTMAX)
	{
		static char rt_signame[32];
		snprintf(rt_signame, sizeof(rt_signame), "SIGRT_%d", signo - SIGRTMIN + 2);
		return rt_signame;
	}

	for (const signal_entry_t *entry = signals_table; entry->name != NULL; entry++)
	{
		if (entry->signo == signo)
			return entry->name;
	}

	return "UNKNOWN";
}

void block_signals()
{
	sigset_t set;

	if (sigemptyset(&set) == -1)
		print_error_and_exit("block_signals", "sigemptyset(&set)");

	if (sigaddset(&set, SIGHUP) == -1 ||
		sigaddset(&set, SIGINT) == -1 ||
		sigaddset(&set, SIGQUIT) == -1 ||
		sigaddset(&set, SIGPIPE) == -1 ||
		sigaddset(&set, SIGTERM) == -1)
	{
		print_error_and_exit("block_signals", "sigaddset(&set, SIGNAL)");
	}

	if (sigprocmask(SIG_BLOCK, &set, NULL) == -1)
		print_error_and_exit("block_signals", "sigprocmask(SIG_BLOCK, &set, NULL");
}

const char *get_siginfo_code_name(int si_code)
{
	switch (si_code)
	{
	case SI_USER:
		return "SI_USER";
	case SI_KERNEL:
		return "SI_KERNEL";
	case SI_QUEUE:
		return "SI_QUEUE";
	case SI_TIMER:
		return "SI_TIMER";
	case SI_MESGQ:
		return "SI_MESGQ";
	case SI_ASYNCIO:
		return "SI_ASYNCIO";
	case SI_SIGIO:
		return "SI_SIGIO";
	case SI_TKILL:
		return "SI_TKILL";
	default:
		return "UNKNOWN";
	}
}
