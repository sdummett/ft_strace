#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

/* This program allows me to check how
*  strace behave when receiving any signals.
*
*  Standard signals are between [1-31].
*  Real-time signals are between [34-64].
*  Signals 32 & 33 are unknown,
*  receiving them kills the program.
*/

// Signal handler function
void handle_signal(int sig) {
	printf("Received signal %d (%s)\n", sig, strsignal(sig));
}

int main() {
	struct sigaction sa;
	sa.sa_handler = handle_signal;
	sa.sa_flags = 0; // No special flags
	sigemptyset(&sa.sa_mask);

	printf("SIGRTMIN: %d, SIGRTMAX: %d.\n", SIGRTMIN, SIGRTMAX);
	// Register handler for all signals (including real-time signals)
	for (int i = 1; i < NSIG; i++) {
		if (sigaction(i, &sa, NULL) == -1) {
			perror("sigaction");
		}
	}

	// Infinite loop to keep the program running
	printf("Signal handling program. "
		"Send any signal to this process (PID: %d).\n", getpid());
	while (1) {
		pause(); // Wait for signals
	}

	return 0;
}
