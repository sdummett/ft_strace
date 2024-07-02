#ifndef FT_STRACE_H
#define FT_STRACE_H

/* C standard library */
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* POSIX */
#include <unistd.h>
#include <sys/user.h>
#include <sys/wait.h>

/* Linux */
#include <syscall.h>
#include <sys/ptrace.h>

/* The Makefile generated a syscall string
 * table using the `ausyscall` command
*/
#include "syscall_table.h"

#endif