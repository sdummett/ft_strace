#ifndef SIGNAL_TABLE_H
#define SIGNAL_TABLE_H

#include <signal.h>

typedef struct {
    int         signo;
    const char *name;
} signal_entry_t;

static const signal_entry_t signals_table[] = {
    { SIGHUP,    "SIGHUP"    },
    { SIGINT,    "SIGINT"    },
    { SIGQUIT,   "SIGQUIT"   },
    { SIGILL,    "SIGILL"    },
    { SIGTRAP,   "SIGTRAP"   },
    { SIGABRT,   "SIGABRT"   },
    { SIGBUS,    "SIGBUS"    },
    { SIGFPE,    "SIGFPE"    },
    { SIGKILL,   "SIGKILL"   },
    { SIGUSR1,   "SIGUSR1"   },
    { SIGSEGV,   "SIGSEGV"   },
    { SIGUSR2,   "SIGUSR2"   },
    { SIGPIPE,   "SIGPIPE"   },
    { SIGALRM,   "SIGALRM"   },
    { SIGTERM,   "SIGTERM"   },
    { SIGCHLD,   "SIGCHLD"   },
    { SIGCONT,   "SIGCONT"   },
    { SIGSTOP,   "SIGSTOP"   },
    { SIGTSTP,   "SIGTSTP"   },
    { SIGTTIN,   "SIGTTIN"   },
    { SIGTTOU,   "SIGTTOU"   },
    { SIGURG,    "SIGURG"    },
    { SIGXCPU,   "SIGXCPU"   },
    { SIGXFSZ,   "SIGXFSZ"   },
    { SIGVTALRM, "SIGVTALRM" },
    { SIGPROF,   "SIGPROF"   },
    { SIGWINCH,  "SIGWINCH"  },
    { SIGIO,     "SIGIO"     },
    { SIGPWR,    "SIGPWR"    },
    { SIGSYS,    "SIGSYS"    },
	{ 0,         NULL        },
};

#endif /* SIGNAL_TABLE_H */
