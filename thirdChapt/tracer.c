/*
 * ptraceTst.c
 *
 *  Created on: 2018年4月16日
 *      Author: rodster
 */

/*
 * ptracetest.c
 *
 *  Created on: 2018年4月15日
 *      Author: rodster
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/wait.h>
#include "alia.h"
#include <string.h>
//Elf64_Addr lookup_symbol(handle_t *,const char *);

int main(int argc, char const *argv[],char **envp)
{
	int fd;
	handle_t h;
	struct stat st;
	long trap,orig;
	int status;
	unsigned int pid;
	char * args[2];

	puts(argv[0]);
	puts(argv[1]);
	puts(argv[2]);
	//execl("pwd",NULL);

	if (argc<3)
	{
		printf("Usage:%s<program><functon>\n",argv[0] );
		exit(0);

		/* code */
	}

	if ((h.exec=strdup(argv[1]))==NULL)
	{
		perror("strdup");
		exit(-1);
	}
	if ((h.symname=strdup(argv[2]))==NULL)
	{
		perror("strdup");
		exit(-1);
		/* code */
	}
	if ((fd=open(argv[1],O_RDONLY))<0)
	{
		perror("open");
		exit(-1);
		/* code */
	}
	if (fstat(fd,&st)<0)
	{
		perror("fstat");
		exit(-1);
		/* code */
	}

	h.mem=mmap(NULL,st.st_size,PROT_READ,MAP_PRIVATE,fd,0);
	if (h.mem==MAP_FAILED)
	{
		perror("mmap");
		exit(-1);

	}

	h.ehdr=(Elf64_Ehdr *)h.mem;
	h.phdr=(Elf64_Phdr *)(h.mem+h.ehdr->e_phoff);
	h.shdr=(Elf64_Shdr *)(h.mem+h.ehdr->e_shoff);

	//char * test=(char *)&h.mem[1];
	//printf("%s",test);
	if (h.mem[0]!=0x7f||!strcmp((char *)&h.mem[1],"ELF"))
	{
		printf("%s is not an ELF file\n",h.exec );
		exit(-1);
		/* code */
	}
	if (h.ehdr->e_shstrndx==0||h.ehdr->e_shoff==0||h.ehdr->e_shnum==0)
	{
		printf("Section header table not found\n");
		exit(-1);
		/* code */
	}
	if ((h.symaddr=lookup_symbol(&h,h.symname))==0)
	{
		printf("Unable to find symbol:%s not found in executable\n",h.symname);
		exit(-1);
		/* code */
	}
	close(fd);
	if ((pid=fork())<0)
	{
		perror("fork");
		exit(-1);
		/* code */
	}
	if (pid==0)
	{
		if (ptrace(PTRACE_TRACEME,pid,NULL,NULL)<0)
		{
			perror("PTRACE_TRACEME");
			exit(-1);
			/* code */
		}
		execve(h.exec,args,envp);
		/* code */
		exit(0);
	}
	wait(&status);
	printf("Beginning analysis of pid :%u at %lx\n",pid,h.symaddr );

	if ((orig=ptrace(PTRACE_PEEKTEXT,pid,h.symaddr,NULL))<0)
	{
		perror("errno");
		perror("PTRACE_PEEKTEXT");
		exit(-1);
		/* code */
	}
	trap=(orig&~0xff)|0xcc;
	if (ptrace(PTRACE_POKETEXT,pid,h.symaddr,trap)<0)
	{
		perror("PTRACE_POKETEXT");
		exit(-1);
	}


	strace:

	if (ptrace(PTRACE_CONT,pid,NULL,NULL)<0)
	{
		perror("PTRACE_CONT");
		exit(-1);
		/* code */
	}
	wait(&status);
	if (WIFSTOPPED(status)&&WSTOPSIG(status)==SIGTRAP)
	{
		if (ptrace(PTRACE_GETREGS,pid,NULL,&h.pt_reg)<0)
		{
			perror("PTRACE_GETREGS");
			exit(-1);
		}
		printf("\n Executable %s (pid:%u) has hit breakpoint 0x%llx\n",h.exec,pid,h.symname);
		printf("rcx: %llx\nrdx:%llx\nrbx: %llx\nrax:%llx \nrdi: %llx\nrsi:%llx\nr8: %llx\nr9: %llx\n r10:%llx\nr14:%llx \n r15:%llx\nrsp: %llx",h.pt_reg.rcx,h.pt_reg.rdx,h.pt_reg.rbx,h.pt_reg.rax,h.pt_reg.rdi,h.pt_reg.rsi,h.pt_reg.r8,h.pt_reg.r9,h.pt_reg.r10,h.pt_reg.r14,h.pt_reg.r15,h.pt_reg.rsp);
		printf("\nPlease hit any key to continue:\n");
		/* code */
		getchar();
		if (ptrace(PTRACE_POKETEXT,pid,h.symaddr,orig)<0)
		{
			perror("PTRACE_POKETEXT");
			exit(-1);
			/* code */
		}
		h.pt_reg.rip=h.pt_reg.rip-1;
		if (ptrace(PTRACE_SETREGS,pid,NULL,&h.pt_reg)<0)
		{
			perror("PTRACE_SETREGS");
			exit(-1);
		}

		if (ptrace(PTRACE_SINGLESTEP,pid,NULL,NULL)<0)
		{
			perror("PTRACE_SINGLESTEP");
			exit(-1);
		}
		wait(NULL);
		if (ptrace(PTRACE_POKETEXT,pid,h.symaddr,trap)<0)
		{
			perror("PTRACE_POKETEXT");
			exit(-1);
			/* code */
		}
		goto strace;
	}
		if (WIFEXITED(status))
		{
			printf("Complete tracing pid :%u\n",pid);
			exit(0);
		}


	return 0;
}
