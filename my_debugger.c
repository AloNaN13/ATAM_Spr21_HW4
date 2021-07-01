
#include <stdio.h>
#include <stdbool.h>
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


pid_t run_target(const char* programname, char** args)
{
	pid_t pid;
	
	pid = fork();
	
    if (pid > 0) {
        return pid;
    } else if (pid == 0) {
        int error = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        if (error < 0) {
			perror("ptrace");
            system("uname -a");
			exit(1);
        }
		execl(programname, *args, NULL);

	} else {
		perror("fork");
        exit(1);
    }

    
}


void run_syscall_debugger(pid_t child_pid, Elf64_Addr start_add){
    
    int wait_status;
    unsigned long start = start_add;
	struct user_regs_struct regs;

    waitpid(child_pid, &wait_status, 0);

    unsigned long long addr = start_add;
    
    unsigned long data = ptrace(PTRACE_PEEKTEXT, child_pid, start_add, NULL);
    unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)data_trap);
    unsigned newdata = ptrace(PTRACE_PEEKTEXT, child_pid, start_add, NULL);

    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    wait(&wait_status);

    while(WIFSTOPPED(wait_status)){
        
        bool f = true;
        regs.rip = 0;  
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);

        unsigned long rsp = regs.rsp;
         
        Elf64_Addr ret_add = ptrace(PTRACE_PEEKTEXT, child_pid, rsp, NULL);
        unsigned long ret_data = ptrace(PTRACE_PEEKTEXT, child_pid, ret_add, NULL);
        unsigned long ret_data_trap = (ret_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, child_pid, ret_add, (void*)ret_data_trap);  
    
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        ptrace(PTRACE_POKETEXT, child_pid, addr, (void*)data);
        
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        regs.rip -= 1;
        ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

        while(!WIFEXITED(wait_status) && f)
        {
           
            ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
            wait(&wait_status);
              
            ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
            unsigned long long add = regs.rip - 2;

            if(regs.rip == ret_add + 1)
            {   
                ptrace(PTRACE_POKETEXT, child_pid, ret_add, (void*)ret_data);
        
                ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
                regs.rip -= 1;
                ptrace(PTRACE_SETREGS, child_pid, 0, &regs);       

                if(rsp < regs.rsp){
                    f = false;
                }
            }

            else{
                   
                ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
                wait(&wait_status);

                ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
                int return_val = regs.rax;

                if(return_val < 0){
                    printf("PRF:: syscall in %llx returned with %lld\n" ,add, regs.rax);
                }
            
            }
          
        }
        ptrace(PTRACE_POKETEXT, child_pid, addr, (void*)data_trap);
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        wait(&wait_status);    
            
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

    }

    for(int i = 0; i< ehdr->e_shnum; i++){
        if(strcmp(shdrs[i].sh_name + sh_strtbl_b, ".strtab") == 0){
            strtab = &shdrs[i];
            strtab_b = (char*)p + strtab->sh_offset;
        
            for(int j = 0; j<symbol_num; j++){
                
                if(strcmp(strtab_b + symtab[j].st_name, argv[1]) == 0){
                    if(ELF64_ST_BIND(symtab[j].st_info) == 1)
                    {
                        found_function = 1;
                        Elf64_Sym* sy = &symtab[j];
                        fun_add = sy->st_value;
                        break;
                    }
                    else{
                        printf("PRF:: local found!\n");
                        exit(1);
                    }

                }
            }
            
        }

    }


    if(found_function == -1){
        printf("PRF:: not found!\n");
        exit(1);
    }

    char** arg = argv + 2;
    child_pid = run_target(argv[2],arg );
	
	run_syscall_debugger(child_pid, fun_add);

    return 0;
}