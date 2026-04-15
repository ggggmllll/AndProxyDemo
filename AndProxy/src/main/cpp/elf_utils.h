#pragma once

#include <elf.h>
#include <cstdint>

/**
 * 获取指定模块在进程内存空间中的基地址
 * @param libname 模块名，例如 "libbinder.so"
 * @return 基地址，失败返回 0
 */
uintptr_t elf_get_library_base(const char* libname);

/**
 * 在模块的 GOT 表中查找指定函数的 GOT 表项地址（用于 Hook）
 * @param libname 模块名
 * @param funcname 目标函数名（mangled 名称）
 * @return GOT 表项地址，失败返回 0
 */
uintptr_t elf_find_got_entry(const char* libname, const char* funcname);

/**
 * 在模块的动态符号表中查找符号地址
 * @param libname 模块名
 * @param symbol_name 符号名（mangled 名称）
 * @return 符号运行时地址，失败返回 0
 */
uintptr_t elf_find_symbol(const char* libname, const char* symbol_name);

/**
 * 执行 GOT 表 Hook
 * @param got_addr 目标 GOT 表项的地址（可通过 elf_find_got_entry 获得）
 * @param new_func 新的函数指针
 * @param old_func 用于保存原始函数指针的输出参数（可选）
 */
void elf_got_hook(uintptr_t got_addr, void* new_func, void** old_func);