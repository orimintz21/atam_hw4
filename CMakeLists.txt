cmake_minimum_required(VERSION 3.10)
project(myproject C)
set(CMAKE_C_STANDARD 99)

add_executable(myproject prf.c read_elf_func.c)