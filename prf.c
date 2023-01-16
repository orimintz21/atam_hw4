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
void runFuncCounter(pid_t child_pid, unsigned long func_addr, char *func_name, char *exe_file_name);
void getRelAddress(pid_t child_pid, unsigned long *func_addr, char *func_name, char *exe_file_name);
long putBreakpointInFunc(unsigned long func_address, pid_t child_pid);
void removeBreakpoint(pid_t child_pid, unsigned long func_addr, unsigned long data);
bool AtReturnAddress(pid_t child_pid, unsigned long return_address);
void getRetAddress(pid_t child_pid, struct user_regs_struct *regs, unsigned long *ret_address);

void getRelAddress(pid_t child_pid, unsigned long *func_addr, char *func_name, char *exe_file_name)
{
    // TODO
    FILE *fp = fopen(exe_file_name, "r");
    if (fp == NULL)
    {
        perror("fopen");
        exit(1);
    }

    fclose(fp);
}

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
// TODO: handle the case where the function is not defined in the executable file
long putBreakpointInFunc(unsigned long func_address, pid_t child_pid)
{
    long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)func_address, NULL);
    unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void *)func_address, (void *)data_trap);
    return data;
}

void removeBreakpoint(pid_t child_pid, unsigned long func_addr, unsigned long data)
{
    ptrace(PTRACE_POKETEXT, child_pid, (void *)func_addr, (void *)data);
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
    regs.rip -= 1;
    ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
}

bool AtReturnAddress(pid_t child_pid, unsigned long return_address)
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
    if (regs.rip - 1 == return_address)
    {
        return true;
    }
    return false;
}

void getRetAddress(pid_t child_pid, struct user_regs_struct *regs, unsigned long *ret_address)
{
    *ret_address = ptrace(PTRACE_PEEKTEXT, child_pid, regs->rsp, NULL);
}

void runFuncCounter(pid_t child_pid, unsigned long func_addr, char *func_name, char *exe_file_name)
{
    if (func_addr == RELOCATABLE_ADDRESS)
    {
        getRelAddress(child_pid, &func_addr, func_name, exe_file_name);
    }
    // initialize variables
    int wait_status, calls_counter = 0;
    struct user_regs_struct regs;
    unsigned long ret_address = 0;
    long ret_data = 0;
    waitpid(child_pid, &wait_status, 0);

    long first_func_command = putBreakpointInFunc(func_addr, child_pid);

    // run the program so it would get to the breakpoint
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    waitpid(child_pid, &wait_status, 0);
    while (WIFSTOPPED(wait_status))
    {
        if (regs.rip - 1 == func_addr)
        {

            ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
            getRetAddress(child_pid, &regs, &ret_address);
            ret_data = putBreakpointInFunc(ret_address, child_pid);
            removeBreakpoint(child_pid, func_addr, first_func_command);
            ptrace(PTRACE_CONT, child_pid, NULL, NULL);
            waitpid(child_pid, &wait_status, 0);
            while (!AtReturnAddress(child_pid, ret_address) && WIFSTOPPED(wait_status))
            {
                ptrace(PTRACE_CONT, child_pid, NULL, NULL);
                waitpid(child_pid, &wait_status, 0);
            }
            if (WIFSTOPPED(wait_status))
            {
                calls_counter++;
                ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
                printf("PRF:: run #%d returned with %d\n", calls_counter, regs.rax);
                removeBreakpoint(child_pid, ret_address, ret_data);
                first_func_command = putBreakpointInFunc(func_addr, child_pid);
            }
            else
            {
                printf("We have a stupid problem\n");
            }
        }
        else
        {
            ptrace(PTRACE_CONT, child_pid, NULL, NULL);
            waitpid(child_pid, &wait_status, 0);
        }
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
    runFuncCountCounter(child_pid, addr, func_name, exe_file_name);
}
