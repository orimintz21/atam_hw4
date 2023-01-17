#ifndef _READ_ELF_FUNC_H_
#define _READ_ELF_FUNC_H_
#include "elf64.h"
#include <stdio.h>

unsigned long find_symbol(char *symbol_name, char *exe_file_name, int *error_val);

int getIndex(Elf64_Shdr *section_header, Elf64_Ehdr *elf_header, char *section_header_string_table, char *section_name);
char *getSymbolTable(FILE *fp, Elf64_Shdr *section_header, Elf64_Ehdr *elf_header, char *section_header_string_table);
char *getStringTable(FILE *fp, Elf64_Shdr *section_header, Elf64_Ehdr *elf_header, char *section_header_string_table);
char *getSectionHeaderStringTable(FILE *fp, Elf64_Shdr *section_header, Elf64_Ehdr *elf_header);
Elf64_Phdr *getProgramHeader(FILE *fp, Elf64_Ehdr *elf_header);
Elf64_Sym *getSymbol(Elf64_Shdr *symbol_table_header, char *string_table, char *symbol_table, char *symbol_name);
unsigned long getRelAddress(FILE *fp, Elf64_Shdr *section_header, Elf64_Ehdr *elf_header, char *section_header_string_table, char *symbol_name);

void freeAllAndClose(FILE *fp, char *section_header_string_table, char *symbol_table, char *string_table);
#endif // _READ_ELF_FUNC_H_