#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include "elf64.h"
#include "read_elf_func.h"
#include <stdbool.h>
#define RELOCATABLE_ADDRESS 0

void getArgs(int argc, char *argv[], char **func_name, char **exe_file_name);
pid_t runTarget(const char *func, char **argv);
void runFuncCounter(pid_t child_pid, unsigned long func_addr);

void getArgs(int argc, char *argv[], char **func_name, char **exe_file_name)
{
    if (argc != 3)
    {
        printf("Usage: %s <function name> <executable file name>\n", argv[0]);
        exit(1);
    }
    *func_name = argv[1];
    *exe_file_name = argv[2];
}

pid_t runTarget(const char *func, char **argv)
{
    pid_t pid = fork();

    if (pid > 0)
    {
        return pid;
    }
    else if (pid == 0)
    {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
        {
            perror("ptrace");
            exit(1);
        }
        execl(func, *(argv + 2), NULL);
    }
    else
    {
        perror("fork");
        exit(1);
    }
}

void runFuncCounter(pid_t child_pid, unsigned long func_addr)
{
    if (func_addr == RELOCATABLE_ADDRESS)
    {
        // TODO: handle the case where the function is not defined in the executable file
    }
    // initialize variables
    int wait_status, calls_counter = 0;
    struct user_regs_struct regs;
    waitpid(child_pid, &wait_status, 0);
    // insert breakpoint at the function's address
    long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)func_addr, NULL);
    unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void *)func_addr, (void *)data_trap);
    // run the program so it would get to the breakpoint
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    bool in_func = true;
    while (WIFSTOPPED(wait_status))
    {
        waitpid(child_pid, &wait_status, 0);
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        if (regs.rip - 1 == func_addr)
        {

            // ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
            // unsigned long rsp = regs.rsp;

            // ptrace(PTRACE_POKETEXT, child_pid, (void*)func_addr, (void*)data);

            // Elf64_Addr return_address = ptrace(PTRACE_PEEKTEXT, child_pid, rsp, NULL);
            // unsigned long return_data = ptrace(PTRACE_PEEKTEXT, child_pid, return_address, NULL);
            // unsigned long return_data_trap = (return_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
            // ptrace(PTRACE_POKETEXT, child_pid, return_address, (void*)return_data_trap);

            // ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
            // regs.rip -= 1;
            // ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

            // ptrace(PTRACE_POKETEXT, child_pid, (void *)func_addr, (void *)data_trap);
            // ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        }
    }

    int main(int argc, char *argv[])
    {
        char *func_name;
        char *exe_file_name;
        getArgs(argc, argv, &func_name, &exe_file_name);
        int err = 1;
        unsigned long addr = find_symbol(func_name, exe_file_name, &err);
        if (err == -1)
        {
            printf("PRF:: %s not an executable! :(\n", exe_file_name);
            return 0;
        }
        if (err == -2)
        {
            printf("PRF:: %s is not a global symbol!\n", func_name);
            return 0;
        }
        if (err == -3)
        {
            printf("PRF:: %s not found!\n", func_name);
            return 0;
        }

        // TODO: handle the case where the function is not defined in the executable file
        //  Ndx == UND
        if (err == -4)
        {
            addr = RELOCATABLE_ADDRESS;
        }
        pid_t child_pid = runTarget(exe_file_name, argv);
        runFuncCountDebugger(child_pid, addr);
    }
