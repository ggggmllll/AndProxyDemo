#include "elf_utils.h"
#include "log.h"          // 你的日志模块
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <sys/mman.h>
#include <cerrno>

// ==================== 内部辅助函数 ====================

static uintptr_t get_dynamic_entry(const Elf64_Dyn* dyn, int64_t tag) {
    for (; dyn->d_tag != DT_NULL; ++dyn) {
        if (dyn->d_tag == tag) return dyn->d_un.d_ptr;
    }
    return 0;
}

static const Elf64_Dyn* find_dynamic_segment(uintptr_t base) {
    auto* ehdr = reinterpret_cast<const Elf64_Ehdr*>(base);
    auto* phdr = reinterpret_cast<const Elf64_Phdr*>(base + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; ++i) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            return reinterpret_cast<const Elf64_Dyn*>(base + phdr[i].p_vaddr);
        }
    }
    return nullptr;
}

// ==================== 公开接口实现 ====================

uintptr_t elf_get_library_base(const char* libname) {
    char line[512];
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        LOGE("Failed to open /proc/self/maps: %s", strerror(errno));
        return 0;
    }
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), fp)) {
        char* path = strchr(line, '/');
        if (path && strstr(path, libname)) {
            char* dash = strchr(line, '-');
            if (dash) {
                *dash = '\0';
                base = strtoull(line, nullptr, 16);
                LOGD("Found library %s at base 0x%lx", libname, base);
                break;
            }
        }
    }
    fclose(fp);
    return base;
}

// ---------- 内部辅助函数 ----------
static const Elf64_Shdr* get_section_by_name(const Elf64_Ehdr* ehdr, uintptr_t base, const char* name) {
    if (ehdr->e_shoff == 0 || ehdr->e_shstrndx == SHN_UNDEF) return nullptr;
    const auto* shdr = reinterpret_cast<const Elf64_Shdr*>(base + ehdr->e_shoff);
    const auto* shstr = reinterpret_cast<const Elf64_Shdr*>(base + ehdr->e_shoff + ehdr->e_shstrndx * sizeof(Elf64_Shdr));
    const char* shstrtab = reinterpret_cast<const char*>(base + shstr->sh_offset);
    for (int i = 0; i < ehdr->e_shnum; ++i) {
        if (strcmp(shstrtab + shdr[i].sh_name, name) == 0) {
            return &shdr[i];
        }
    }
    return nullptr;
}

// ---------- 符号查找（新实现）----------
uintptr_t elf_find_symbol(const char* libname, const char* symbol_name) {
    uintptr_t base = elf_get_library_base(libname);
    if (!base) {
        LOGE("elf_find_symbol: failed to get base of %s", libname);
        return 0;
    }

    auto* ehdr = reinterpret_cast<const Elf64_Ehdr*>(base);
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 || ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr->e_ident[EI_MAG2] != ELFMAG2 || ehdr->e_ident[EI_MAG3] != ELFMAG3) {
        LOGE("elf_find_symbol: invalid ELF header");
        return 0;
    }

    const Elf64_Dyn* dyn = find_dynamic_segment(base);
    if (!dyn) {
        LOGE("elf_find_symbol: no PT_DYNAMIC segment");
        return 0;
    }

    uintptr_t sym_off = get_dynamic_entry(dyn, DT_SYMTAB);
    uintptr_t str_off = get_dynamic_entry(dyn, DT_STRTAB);
    size_t str_size = get_dynamic_entry(dyn, DT_STRSZ);
    if (!sym_off || !str_off || !str_size) {
        LOGE("elf_find_symbol: missing DT_SYMTAB, DT_STRTAB, or DT_STRSZ");
        return 0;
    }

    auto* symtab = reinterpret_cast<const Elf64_Sym*>(base + sym_off);
    const char* strtab = reinterpret_cast<const char*>(base + str_off);
    size_t sym_count = 0;

    // 方式1：通过 .dynsym 节区大小确定符号数量
    const Elf64_Shdr* dynsym_sec = get_section_by_name(ehdr, base, ".dynsym");
    if (dynsym_sec) {
        sym_count = dynsym_sec->sh_size / sizeof(Elf64_Sym);
        LOGD("elf_find_symbol: .dynsym size = %zu, sym_count = %zu",
             (size_t)dynsym_sec->sh_size, sym_count);
    } else {
        // 方式2：回退到字符串表边界遍历
        LOGD("elf_find_symbol: .dynsym not found, scanning by strtab boundary");
        const char* str_end = strtab + str_size;
        const Elf64_Sym* sym = symtab;
        while (sym->st_name < str_size) {  // st_name 必须在字符串表内
            ++sym_count;
            ++sym;
            if (sym_count > 200000) {  // 安全上限
                LOGE("elf_find_symbol: too many symbols, aborting");
                return 0;
            }
        }
        LOGD("elf_find_symbol: estimated sym_count from strtab = %zu", sym_count);
    }

    // 遍历符号表查找目标符号
    for (size_t i = 0; i < sym_count; ++i) {
        if (symtab[i].st_name == 0) continue;
        const char* name = strtab + symtab[i].st_name;
        if (strcmp(name, symbol_name) == 0) {
            uintptr_t addr = base + symtab[i].st_value;
            LOGD("elf_find_symbol: found %s at 0x%lx", symbol_name, addr);
            return addr;
        }
    }

    LOGE("elf_find_symbol: symbol %s not found in %s", symbol_name, libname);
    return 0;
}

uintptr_t elf_find_got_entry(const char* libname, const char* funcname) {
    uintptr_t base = elf_get_library_base(libname);
    if (!base) return 0;

    auto* ehdr = reinterpret_cast<const Elf64_Ehdr*>(base);
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 || ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr->e_ident[EI_MAG2] != ELFMAG2 || ehdr->e_ident[EI_MAG3] != ELFMAG3) {
        LOGE("Invalid ELF header");
        return 0;
    }

    const Elf64_Dyn* dyn = find_dynamic_segment(base);
    if (!dyn) return 0;

    uintptr_t symtab_off = get_dynamic_entry(dyn, DT_SYMTAB);
    uintptr_t strtab_off = get_dynamic_entry(dyn, DT_STRTAB);
    uintptr_t relplt_off = get_dynamic_entry(dyn, DT_JMPREL);
    size_t relplt_size = get_dynamic_entry(dyn, DT_PLTRELSZ);
    if (!symtab_off || !strtab_off || !relplt_off || !relplt_size) return 0;

    auto* symtab = reinterpret_cast<const Elf64_Sym*>(base + symtab_off);
    const char* strtab = reinterpret_cast<const char*>(base + strtab_off);
    auto* relplt = reinterpret_cast<const Elf64_Rela*>(base + relplt_off);
    size_t num_rel = relplt_size / sizeof(Elf64_Rela);

    for (size_t i = 0; i < num_rel; ++i) {
        uint32_t sym_idx = ELF64_R_SYM(relplt[i].r_info);
        const char* sym_name = strtab + symtab[sym_idx].st_name;
        if (strcmp(sym_name, funcname) == 0) {
            return base + relplt[i].r_offset;
        }
    }
    return 0;
}

void elf_got_hook(uintptr_t got_addr, void* new_func, void** old_func) {
    void** got_ptr = reinterpret_cast<void**>(got_addr);
    void* orig = *got_ptr;

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) return;

    uintptr_t page_start = got_addr & ~(page_size - 1);
    if (mprotect(reinterpret_cast<void*>(page_start), page_size, PROT_READ | PROT_WRITE) == -1)
        return;

    *got_ptr = new_func;

    mprotect(reinterpret_cast<void*>(page_start), page_size, PROT_READ);  // 忽略失败

    if (old_func) *old_func = orig;
}