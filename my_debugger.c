
#include <stdio.h>
#include <stdarg.h>
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

void run_syscall_debugger(pid_t child_pid, Elf64_Addr start_add);


pid_t run_target(const char* programname)
{
	pid_t pid;
	
	pid = fork();
	
    if (pid > 0) {
        //printf("in father\n");
        return pid;
    } else if (pid == 0) {
        //printf("in son 1\n");
        int error = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		//printf("in son 2\n");
        if (error < 0) {
			perror("ptrace");
            system("uname -a");
			exit(1);
        }
        //printf("in son 3\n");
		execl(programname, programname, NULL);
		//printf("in son 4\n");

	} else {
		perror("fork");
        exit(1);
    }

    
}


void run_syscall_debugger(pid_t child_pid, Elf64_Addr start_add)
{
    int wait_status;
    unsigned long start = start_add;
	struct user_regs_struct regs;

    waitpid(child_pid, &wait_status, 0);
    //if(WIFSIGNALED(wait_status))return;


    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
    printf("DBG: Child stopped at RIP = 0x%llx\n", regs.rip);


    unsigned long long addr = start_add;
    unsigned long data = ptrace(PTRACE_PEEKTEXT, child_pid, start_add, NULL);
    printf("DBG: Original data at 0x%llx: 0x%lx\n", addr, data);

    unsigned long data_trap = (data & 0xFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, addr, (void*)data_trap);

    //peek after poke
    //unsigned long data_alon = ptrace(PTRACE_PEEKTEXT, child_pid, start_add, NULL);
    //printf("DBG: data is now at 0x%llx: 0x%lx\n", addr, data_alon);
    //

    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    waitpid(child_pid, &wait_status, 0);

    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
    printf("DBG: Child stopped at RIP = 0x%llx\n", regs.rip);

    unsigned long data2 = ptrace(PTRACE_PEEKTEXT, child_pid, addr, NULL);

    ptrace(PTRACE_POKETEXT, child_pid, addr, (void*)data);
    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
    regs.rip -= 1;
    printf("DBG: now at RIP = 0x%llx\n", regs.rip);
    ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
    printf("DBG: now again at RIP = 0x%llx\n", regs.rip);


    //ptrace(PTRACE_CONT, child_pid, 0, 0);
    //wait(&wait_status);


    while(1)
    {

    	ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
	    waitpid(child_pid, &wait_status, 0);
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        unsigned long long add = regs.rip - 2;
        int syscall_num = ptrace(PTRACE_PEEKUSER, RAX);
        
	    ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
	    waitpid(child_pid, &wait_status, 0);

        int return_val = ptrace(PTRACE_PEEKUSER, RAX);

	    ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
    	//printf("PRF:: syscall in 0x%llx returned with %d\n" ,add, return_val);
        ptrace(PTRACE_CONT, child_pid, 0, 0);
        waitpid(child_pid, &wait_status, 0);

        if(WIFEXITED(wait_status) > 0) break;
    }
    
}


int main(int argc, char** argv)
{
    pid_t child_pid;

    int fd = open(argv[2], O_RDONLY);
    if(fd == -1) exit(1);
    size_t len = lseek(fd, 0, SEEK_END);
    
    void *p = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
    
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)p;
    Elf64_Shdr *shdrs = (void*)ehdr+ehdr->e_shoff;
    Elf64_Shdr *txhdr;
    int found_function = -1;
    int symbol_num;
    Elf64_Sym *symtab;
    Elf64_Addr fun_add;
    Elf64_Shdr *strtab;
    char* strtab_b;
    
    Elf64_Shdr *sh_strtbl_p = &shdrs[ehdr->e_shoff];
    char *sh_strtbl_b = p + shdrs[ehdr->e_shstrndx].sh_offset;
    for(int i = 0; i<ehdr->e_shnum; i++){
        if(strcmp(sh_strtbl_b + shdrs[i].sh_name , ".symtab") == 0){
            symtab = (Elf64_Sym *)(p + shdrs[i].sh_offset);
            symbol_num = shdrs[i].sh_size/shdrs[i].sh_entsize;
        }

        if(strcmp(shdrs[i].sh_name + sh_strtbl_b, ".strtab") == 0){
            strtab = &shdrs[i];
            strtab_b = (char*)p + strtab->sh_offset;
        }

    }

    for(int i = 0; i<symbol_num; i++){
        if(strcmp(strtab_b + symtab[i].st_name, argv[1]) == 0){
            if(ELF64_ST_BIND(symtab[i].st_info) == 1)
            {
                found_function = 1;
                Elf64_Sym* sy = &symtab[i];
                fun_add = sy->st_value;
                break;
            }

        }
    }


    if(found_function == -1){
        printf("PRF:: not found!\n");
        exit(1);
    }


    child_pid = run_target(argv[2]);
	
	run_syscall_debugger(child_pid, fun_add);
    pid_t my_id = getpid();
    printf("hey i'm %d", my_id);
    return 0;
}