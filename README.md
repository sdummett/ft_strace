# ft_strace

**ft_strace** is a simplified reimplementation of the `strace` command, written in C. It intercepts and displays system calls made by a target program, as well as the signals it receives.  

---

## Description

- Monitors a target program and prints out its system calls in a format inspired by the original `strace`.
- Utilizes specific `ptrace` options (e.g., `PTRACE_SYSCALL`, `PTRACE_GETREGSET`, etc.).
- Compatible with both 32-bit and 64-bit binaries.

---

## Implementation Details

**ft_strace** relies on the Linux **ptrace** interface to intercept system calls and handle signals. This involves:
- Attaching to the target process to trace its execution and intercept any system call entries/exits.
- Retrieving register values to display arguments for each system call.
- Managing signals carefully to ensure the traced process can continue running without unintended interruptions.
- Handling both 32-bit and 64-bit binaries by adapting to differences in register structures and calling conventions.

This low-level approach offers insight into how processes communicate with the kernel and how signals can be relayed and handled in user-space programs.

---

## Compilation

Navigate to the project directory and run:

```bash
make
```

This will produce an executable named **ft_strace**.

---

## Usage

```bash
./ft_strace <program> [arguments]
```

**Example**:
```bash
./ft_strace /bin/ls -l
```

---

## Additional Resources

- **ptrace** documentation: [man ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html)  
- **strace** documentation: [man strace](https://man7.org/linux/man-pages/man1/strace.1.html)
