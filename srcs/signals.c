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
    // Gestion des signaux temps réel
    if (signo >= SIGRTMIN && signo <= SIGRTMAX)
    {
        static char rt_signame[32];
        snprintf(rt_signame, sizeof(rt_signame), "SIGRT_%d", signo - SIGRTMIN);
        return rt_signame;
    }

    // Gestion des signaux standards
    switch (signo)
    {
        case SIGHUP:    return "SIGHUP";
        case SIGINT:    return "SIGINT";
        case SIGQUIT:   return "SIGQUIT";
        case SIGILL:    return "SIGILL";
        case SIGTRAP:   return "SIGTRAP";
        case SIGABRT:   return "SIGABRT";
        case SIGBUS:    return "SIGBUS";
        case SIGFPE:    return "SIGFPE";
        case SIGKILL:   return "SIGKILL";
        case SIGUSR1:   return "SIGUSR1";
        case SIGSEGV:   return "SIGSEGV";
        case SIGUSR2:   return "SIGUSR2";
        case SIGPIPE:   return "SIGPIPE";
        case SIGALRM:   return "SIGALRM";
        case SIGTERM:   return "SIGTERM";
        case SIGCHLD:   return "SIGCHLD";
        case SIGCONT:   return "SIGCONT";
        case SIGSTOP:   return "SIGSTOP";
        case SIGTSTP:   return "SIGTSTP";
        case SIGTTIN:   return "SIGTTIN";
        case SIGTTOU:   return "SIGTTOU";
        case SIGURG:    return "SIGURG";
        case SIGXCPU:   return "SIGXCPU";
        case SIGXFSZ:   return "SIGXFSZ";
        case SIGVTALRM: return "SIGVTALRM";
        case SIGPROF:   return "SIGPROF";
        case SIGWINCH:  return "SIGWINCH";
        case SIGIO:     return "SIGIO";
        case SIGPWR:    return "SIGPWR";
        case SIGSYS:    return "SIGSYS";
        default:        return "UNKNOWN";
    }
}

const char *get_siginfo_code_name(int si_code)
{
    switch (si_code)
    {
        case SI_USER:       return "SI_USER";
        case SI_KERNEL:     return "SI_KERNEL";
        case SI_QUEUE:      return "SI_QUEUE";
        case SI_TIMER:      return "SI_TIMER";
        case SI_MESGQ:      return "SI_MESGQ";
        case SI_ASYNCIO:    return "SI_ASYNCIO";
        case SI_SIGIO:      return "SI_SIGIO";
        case SI_TKILL:      return "SI_TKILL";
        default:            return "UNKNOWN";
    }
}
