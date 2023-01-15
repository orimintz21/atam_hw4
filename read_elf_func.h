#ifndef _READ_ELF_FUNC_H_
#define _READ_ELF_FUNC_H_

unsigned long find_symbol(char *symbol_name, char *exe_file_name, int *error_val);

#endif // _READ_ELF_FUNC_H_