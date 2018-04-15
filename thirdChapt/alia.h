/*
 * alia.h
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
typedef struct handle
{
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	uint8_t *mem;
	char *symname;
	Elf64_Addr symaddr;
	struct user_regs_struct pt_reg;
	char *exec;
}handle_t;


Elf64_Addr lookup_symbol(handle_t *h,const char *symname){
			int i,j;
			char *strtab;
			Elf64_Sym *symtab;
			/*for (int var = 0; var < h->ehdr->e_shnum; ++var) {
				printf("%d\n",h->shdr[var].sh_type);
			}*/
			for (i = 0; i < h->ehdr->e_shnum; i++)
			{
				printf("%d\n",h->shdr[i].sh_type);
				if (h->shdr[i].sh_type==SHT_SYMTAB)
				{
					strtab=(char *)&h->mem[h->shdr[h->shdr[i].sh_link].sh_offset];
					symtab=(Elf64_Sym *)&h->mem[h->shdr[i].sh_offset];
					for (j = 0; j < h->shdr[i].sh_size/sizeof(Elf64_Sym); j++)
					{
						if (strcmp(&strtab[symtab->st_name],symname)==0)
						{
							return (symtab->st_value);
						}
						symtab++;
					}
				}
				continue;
			}
			return 0;
}
