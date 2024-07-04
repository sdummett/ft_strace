#include "ft_strace.h"

void print_siginfo(siginfo_t *siginfo)
{
	char siginfo_str[128];
	// char *signo_str = strsignal(siginfo->si_signo);
	snprintf(siginfo_str, 128, "{si_signo=%s, si_code=%s, si_pid=%d, si_uid=%d}",
			 signal_name(siginfo->si_signo), siginfo_code_name(siginfo->si_code), siginfo->si_pid, siginfo->si_uid);
	printf("--- %s %s ---\n", signal_name(siginfo->si_signo), siginfo_str);
}

void handle_signal(pid_t tracee_pid)
{
	siginfo_t siginfo;
	ptrace(PTRACE_GETSIGINFO, tracee_pid, NULL, &siginfo);
	print_siginfo(&siginfo);
}

// Function to convert signo to string
const char *signal_name(int signo)
{
	// Handle real-time signals separately
	if (signo >= SIGRTMIN && signo <= SIGRTMAX)
	{
		static char rt_signame[32];
		snprintf(rt_signame, sizeof(rt_signame), "SIGRT_%d", signo - 32);
		return rt_signame;
	}

	// Handle standard POSIX signals
	switch (signo)
	{
	case SIGHUP:	return "SIGHUP";
	case SIGINT:	return "SIGINT";
	case SIGQUIT:	return "SIGQUIT";
	case SIGILL:	return "SIGILL";
	case SIGTRAP:	return "SIGTRAP";
	case SIGABRT:	return "SIGABRT";
	case SIGBUS:	return "SIGBUS";
	case SIGFPE:	return "SIGFPE";
	case SIGKILL:	return "SIGKILL";
	case SIGUSR1:	return "SIGUSR1";
	case SIGSEGV:	return "SIGSEGV";
	case SIGUSR2:	return "SIGUSR2";
	case SIGPIPE:	return "SIGPIPE";
	case SIGALRM:	return "SIGALRM";
	case SIGTERM:	return "SIGTERM";
	case SIGSTKFLT:	return "SIGSTKFLT";
	case SIGCHLD:	return "SIGCHLD";
	case SIGCONT:	return "SIGCONT";
	case SIGSTOP:	return "SIGSTOP";
	case SIGTSTP:	return "SIGTSTP";
	case SIGTTIN:	return "SIGTTIN";
	case SIGTTOU:	return "SIGTTOU";
	case SIGURG:	return "SIGURG";
	case SIGXCPU:	return "SIGXCPU";
	case SIGXFSZ:	return "SIGXFSZ";
	case SIGVTALRM:	return "SIGVTALRM";
	case SIGPROF:	return "SIGPROF";
	case SIGWINCH:	return "SIGWINCH";
	case SIGIO:		return "SIGIO";
	case SIGPWR:	return "SIGPWR";
	case SIGSYS:	return "SIGSYS";
	default:		return "UNKNOWN";
	}
}

// Function to convert si_code to string
const char *siginfo_code_name(int si_code)
{
	switch (si_code)
	{
	case SI_USER:		return "SI_USER";
	case SI_KERNEL:		return "SI_KERNEL";
	case SI_QUEUE:		return "SI_QUEUE";
	case SI_TIMER:		return "SI_TIMER";
	case SI_MESGQ:		return "SI_MESGQ";
	case SI_ASYNCIO:	return "SI_ASYNCIO";
	case SI_SIGIO:		return "SI_SIGIO";
	case SI_TKILL:		return "SI_TKILL";
	default:			return "UNKNOWN";
	}
}
