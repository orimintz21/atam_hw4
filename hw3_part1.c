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
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include "elf64.h"

#define ET_NONE 0 // No file type
#define ET_REL 1  // Relocatable file
#define ET_EXEC 2 // Executable file
#define ET_DYN 3  // Shared object file
#define ET_CORE 4 // Core file

/* symbol_name		- The symbol (maybe function) we need to search for.
 * exe_file_name	- The file where we search the symbol in.
 * error_val		- If  1: A global symbol was found, and defined in the given executable.
 * 			- If -1: Symbol not found.
 *			- If -2: Only a local symbol was found.
 * 			- If -3: File is not an executable.
 * 			- If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value		- The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */
#define SHT_STRTAB 3
#define SHT_SYMTAB 2
#define PT_LOAD 1
#define STB_GLOBAL 1
#define SHF_EXECINSTR 0x4
#define PF_X 0x1

int getIndex(Elf64_Shdr *section_header, Elf64_Ehdr *elf_header, char *section_header_string_table, char *section_name);
char *getSymbolTable(FILE *fp, Elf64_Shdr *section_header, Elf64_Ehdr *elf_header, char *section_header_string_table);
char *getStringTable(FILE *fp, Elf64_Shdr *section_header, Elf64_Ehdr *elf_header, char *section_header_string_table);
char *getSectionHeaderStringTable(FILE *fp, Elf64_Shdr *section_header, Elf64_Ehdr *elf_header);
Elf64_Phdr *getProgramHeader(FILE *fp, Elf64_Ehdr *elf_header);
Elf64_Sym *getSymbol(Elf64_Shdr *symbol_table_header, char *string_table, char *symbol_table, char *symbol_name);

void freeAllAndClose(FILE *fp, char *section_header_string_table, char *symbol_table, char *string_table);

unsigned long find_symbol(char *symbol_name, char *exe_file_name, int *error_val)
{
	if (!symbol_name || !exe_file_name)
	{
		*error_val = -1;
		return 0;
	}
	FILE *fp = fopen(exe_file_name, "r");
	if (fp == NULL)
	{
		*error_val = -3;
		return 0;
	}

	Elf64_Ehdr elf_header;
	fread(&elf_header, sizeof(Elf64_Ehdr), 1, fp);
	if (elf_header.e_type != ET_EXEC)
	{
		fclose(fp);
		*error_val = -3;
		return 0;
	}

	Elf64_Shdr section_header[elf_header.e_shentsize * elf_header.e_shnum];
	fseek(fp, elf_header.e_shoff, SEEK_SET);
	fread(section_header, elf_header.e_shentsize, elf_header.e_shnum, fp);

	char *section_header_string_table = getSectionHeaderStringTable(fp, section_header, &elf_header);

	char *symbol_table = getSymbolTable(fp, section_header, &elf_header, section_header_string_table);

	char *string_table = getStringTable(fp, section_header, &elf_header, section_header_string_table);

	int symtab_index = getIndex(section_header, &elf_header, section_header_string_table, ".symtab");
	Elf64_Shdr symbol_table_header = section_header[symtab_index];
	int num_of_symbols = symbol_table_header.sh_size / symbol_table_header.sh_entsize;
	Elf64_Sym *symbol = getSymbol(&symbol_table_header, string_table, symbol_table, symbol_name);
	if (!symbol)
	{
		*error_val = -1;
		freeAllAndClose(fp, section_header_string_table, symbol_table, string_table);
		return 0;
	}
	if (ELF64_ST_BIND(symbol->st_info) != STB_GLOBAL)
	{
		*error_val = -2;
		freeAllAndClose(fp, section_header_string_table, symbol_table, string_table);
		return 0;
	}
	if (symbol->st_shndx == SHN_UNDEF)
	{
		*error_val = -4;
		freeAllAndClose(fp, section_header_string_table, symbol_table, string_table);
		return 0;
	}
	*error_val = 1;
	freeAllAndClose(fp, section_header_string_table, symbol_table, string_table);
	return symbol->st_value;
}

int getIndex(Elf64_Shdr *section_header, Elf64_Ehdr *elf_header, char *section_header_string_table, char *section_name)
{
	for (int i = 0; i < elf_header->e_shnum; i++)
	{
		if (strcmp(section_header_string_table + section_header[i].sh_name, section_name) == 0)
		{
			return i;
		}
	}
	return -1;
}
char *getSymbolTable(FILE *fp, Elf64_Shdr *section_header, Elf64_Ehdr *elf_header, char *section_header_string_table)
{
	int symtab_index = getIndex(section_header, elf_header, section_header_string_table, ".symtab");
	Elf64_Shdr symbol_table_header = section_header[symtab_index];
	char *symbol_table = (char *)malloc(symbol_table_header.sh_size);
	fseek(fp, symbol_table_header.sh_offset, SEEK_SET);
	fread(symbol_table, symbol_table_header.sh_size, 1, fp);
	return symbol_table;
}

char *getStringTable(FILE *fp, Elf64_Shdr *section_header, Elf64_Ehdr *elf_header, char *section_header_string_table)
{
	int strtab_index = getIndex(section_header, elf_header, section_header_string_table, ".strtab");
	Elf64_Shdr string_table_header = section_header[strtab_index];
	char *string_table = (char *)malloc(string_table_header.sh_size);
	fseek(fp, string_table_header.sh_offset, SEEK_SET);
	fread(string_table, string_table_header.sh_size, 1, fp);
	return string_table;
}

char *getSectionHeaderStringTable(FILE *fp, Elf64_Shdr *section_header, Elf64_Ehdr *elf_header)
{
	Elf64_Shdr header_section_header_string_table = section_header[elf_header->e_shstrndx];
	char *section_header_string_table = (char *)malloc(header_section_header_string_table.sh_size);
	fseek(fp, header_section_header_string_table.sh_offset, SEEK_SET);
	fread(section_header_string_table, header_section_header_string_table.sh_size, 1, fp);
	return section_header_string_table;
}

Elf64_Sym *getSymbol(Elf64_Shdr *symbol_table_header, char *string_table, char *symbol_table, char *symbol_input)
{
	int num_of_symbols = symbol_table_header->sh_size / symbol_table_header->sh_entsize;
	Elf64_Sym *ret_symbol = NULL;
	for (int i = 0; i < num_of_symbols; ++i)
	{
		Elf64_Sym *symbol = (Elf64_Sym *)(symbol_table + i * symbol_table_header->sh_entsize);
		char *symbol_name = string_table + symbol->st_name;
		if (strcmp(symbol_name, symbol_input) == 0)
		{
			if (ELF64_ST_BIND(symbol->st_info) == STB_GLOBAL)
			{
				return symbol;
			}
			ret_symbol = symbol;
		}
	}
	return ret_symbol;
}

Elf64_Phdr *getProgramHeader(FILE *fp, Elf64_Ehdr *elf_header)
{
	Elf64_Phdr *program_header = malloc(elf_header->e_phentsize * elf_header->e_phnum);
	fseek(fp, elf_header->e_phoff, SEEK_SET);
	fread(program_header, elf_header->e_phentsize, elf_header->e_phnum, fp);
	return program_header;
}

void freeAllAndClose(FILE *fp, char *section_header_string_table, char *symbol_table, char *string_table)
{
	free(section_header_string_table);
	free(symbol_table);
	free(string_table);
	fclose(fp);
}

int main(int argc, char *const argv[])
{
	int err = 0;

	unsigned long addr = find_symbol(argv[1], argv[2], &err);

	if (addr > 0)
		printf("%s will be loaded to 0x%lx\n", argv[1], addr);
	else if (err == -2)
		printf("%s is not a global symbol! :(\n", argv[1]);
	else if (err == -1)
		printf("%s not found!\n", argv[1]);
	else if (err == -3)
		printf("%s not an executable! :(\n", argv[2]);
	else if (err == -4)
		printf("%s is a global symbol, but will come from a shared library\n", argv[1]);
	return 0;
}