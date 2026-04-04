#include "BinderHook.h"
#include "binder_proxy.h"
#include "log.h"

#include <elf.h>
#include <thread>
#include <utility>
#include <vector>
#include <sys/mman.h>
#include <bits/sysconf.h>

thread_local BinderHook::TxnContext BinderHook::txnContext_;

extern int ioctl_proxy(int fd, unsigned long request, void* args);

BinderHook& BinderHook::instance() {
    static BinderHook inst;
    return inst;
}

BinderHook::~BinderHook() {
    std::lock_guard<std::mutex> lock(mapMutex_);
    for (auto& pair : addrMap_) {
        free((void*)pair.second);
    }
    addrMap_.clear();
}

// 通过 /proc/self/maps 获取库基址
static uintptr_t get_library_base(const char *libname) {
    char line[512];
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        LOGE("Failed to open /proc/self/maps: %s", strerror(errno));
        return 0;
    }

    uintptr_t base = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *path = strchr(line, '/');
        if (path) {
            if (strstr(path, libname) != NULL) {
                char *dash = strchr(line, '-');
                if (dash) {
                    *dash = '\0';
                    base = strtoull(line, NULL, 16);
                    LOGD("Found library %s at base 0x%lx", libname, base);
                    break;
                } else {
                    LOGE("Invalid map line (no dash): %s", line);
                }
            }
        }
    }
    fclose(fp);
    if (base == 0) {
        LOGE("Library %s not found in /proc/self/maps", libname);
    }
    return base;
}

// 从动态段中获取指定类型的信息（返回偏移量，需加 base）
static uintptr_t get_dynamic_info_offset(const Elf64_Dyn *dyn, int64_t tag) {
    for (; dyn->d_tag != DT_NULL; ++dyn) {
        if (dyn->d_tag == tag) {
            return dyn->d_un.d_ptr;
        }
    }
    return 0;
}

// 根据函数名在指定库中查找 GOT 条目地址
static uintptr_t find_got_entry(const char *libname, const char *funcname) {
    uintptr_t base = get_library_base(libname);
    if (base == 0) {
        LOGE("Failed to get base address for %s", libname);
        return 0;
    }

    // 读取 ELF 头
    Elf64_Ehdr *ehdr = (Elf64_Ehdr*)base;
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr->e_ident[EI_MAG3] != ELFMAG3) {
        LOGE("Invalid ELF header at base 0x%lx", base);
        return 0;
    }
    LOGD("Valid ELF header at base 0x%lx", base);

    // 找到 PT_DYNAMIC 程序头
    Elf64_Phdr *phdr = (Elf64_Phdr*)(base + ehdr->e_phoff);
    Elf64_Dyn *dyn = NULL;
    for (int i = 0; i < ehdr->e_phnum; ++i) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn = (Elf64_Dyn*)(base + phdr[i].p_vaddr);
            LOGD("Found PT_DYNAMIC at offset 0x%lx, vaddr 0x%lx",
                 phdr[i].p_offset, phdr[i].p_vaddr);
            break;
        }
    }
    if (!dyn) {
        LOGE("No PT_DYNAMIC segment found");
        return 0;
    }

    // 获取动态段中的关键信息（偏移量）
    uintptr_t symtab_off = get_dynamic_info_offset(dyn, DT_SYMTAB);
    uintptr_t strtab_off = get_dynamic_info_offset(dyn, DT_STRTAB);
    uintptr_t relplt_off = get_dynamic_info_offset(dyn, DT_JMPREL);
    size_t relplt_size = get_dynamic_info_offset(dyn, DT_PLTRELSZ);
    uintptr_t pltgot_off = get_dynamic_info_offset(dyn, DT_PLTGOT);

    if (!symtab_off) {
        LOGE("DT_SYMTAB not found");
        return 0;
    }
    if (!strtab_off) {
        LOGE("DT_STRTAB not found");
        return 0;
    }
    if (!relplt_off) {
        LOGE("DT_JMPREL not found");
        return 0;
    }
    if (!relplt_size) {
        LOGE("DT_PLTRELSZ is zero");
        return 0;
    }
    if (!pltgot_off) {
        LOGE("DT_PLTGOT not found");
        return 0;
    }

    // 计算实际内存地址（基址 + 偏移）
    Elf64_Sym *symtab = (Elf64_Sym*)(base + symtab_off);
    const char *strtab = (const char*)(base + strtab_off);
    Elf64_Rela *relplt = (Elf64_Rela*)(base + relplt_off);
    uintptr_t pltgot = base + pltgot_off;

    LOGD("symtab=0x%lx (offset 0x%lx), strtab=0x%lx, relplt=0x%lx, relplt_size=%zu, pltgot=0x%lx",
         (uintptr_t)symtab, symtab_off, (uintptr_t)strtab, (uintptr_t)relplt, relplt_size, pltgot);

    // 遍历 .rel.plt 重定位表
    size_t num_rel = relplt_size / sizeof(Elf64_Rela);
    LOGD("Number of relocations in .rel.plt: %zu", num_rel);
    for (size_t i = 0; i < num_rel; ++i) {
        uint32_t sym_idx = ELF64_R_SYM(relplt[i].r_info);
        const char *sym_name = strtab + symtab[sym_idx].st_name;
        if (strcmp(sym_name, funcname) == 0) {
            uintptr_t got_entry = base + relplt[i].r_offset;  // r_offset 也是偏移，需加基址
            LOGD("Found GOT entry for %s at 0x%lx (r_offset=0x%lx)",
                 funcname, got_entry, relplt[i].r_offset);
            return got_entry;
        }
    }

    LOGE("Function %s not found in .rel.plt", funcname);
    return 0;
}

static void got_hook(uintptr_t got_addr, void *new_func, void **old_func) {
    void **got_ptr = (void**)got_addr;
    void *orig = *got_ptr;

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        LOGE("sysconf(_SC_PAGESIZE) failed: %s", strerror(errno));
        return;
    }

    uintptr_t page_start = got_addr & ~(page_size - 1);
    LOGD("Got address 0x%lx, page_start 0x%lx, page_size %ld",
         got_addr, page_start, page_size);

    if (mprotect((void*)page_start, page_size, PROT_READ | PROT_WRITE) == -1) {
        LOGE("mprotect (write) failed: %s", strerror(errno));
        return;
    }

    // 执行 GOT 替换
    *got_ptr = new_func;
    LOGD("GOT entry at 0x%lx changed from %p to %p", got_addr, orig, new_func);

    if (mprotect((void*)page_start, page_size, PROT_READ) == -1) {
        LOGE("mprotect (read-only) failed: %s", strerror(errno));
        // 即使恢复失败，hook 已生效，只打印警告
    }

    if (old_func) *old_func = orig;
}

void BinderHook::init(JavaVM* vm) {
    uintptr_t got_entry = find_got_entry("libbinder.so", "ioctl");
    if (!got_entry) {
        LOGE("Failed to find GOT entry for ioctl");
        return;
    }

    got_hook(got_entry, (void*) ioctl_proxy, NULL);
    jvm_ = vm;
    JNIEnv* env;
    if (jvm_->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
        jvm_->AttachCurrentThread(&env, nullptr);
    }

    jclass dispatcherClass = env->FindClass("com/gumuluo/proxy/binder/BinderDispatcher");
    dispatcherClass_ = (jclass)env->NewGlobalRef(dispatcherClass);
    dispatchBeforeMid_ = env->GetStaticMethodID(dispatcherClass_, "dispatchBefore",
                                                "(Ljava/lang/String;Ljava/lang/String;Landroid/os/Parcel;Landroid/os/Parcel;)Z");
    dispatchAfterMid_ = env->GetStaticMethodID(dispatcherClass_, "dispatchAfter",
                                               "(Ljava/lang/String;Ljava/lang/String;Landroid/os/Parcel;Landroid/os/Parcel;)Z");

    env->DeleteLocalRef(dispatcherClass);
}

uintptr_t BinderHook::handle_free(uintptr_t addr) {
    std::lock_guard<std::mutex> lock(mapMutex_);
    auto it = addrMap_.find(addr);
    if (it != addrMap_.end()) {
        uintptr_t orig = it->first;
        free((void*)it->second);
        addrMap_.erase(it);
        return orig;
    }
    return 0;
}

static inline std::string dotted_to_slash(const std::string& dotted) {
    std::string slash = dotted;
    std::replace(slash.begin(), slash.end(), '.', '/');
    return slash;
}

// ==================== 新增回调管理函数 ====================
void BinderHook::registerCallback(const std::string& serviceName, const std::string& methodName,
                                  bool isBefore, BinderNativeCallback callback) {
    std::string key = (isBefore ? "before#" : "after#") + serviceName + "#" + methodName;
    std::lock_guard<std::mutex> lock(callbacksMutex_);
    callbacks_[key] = std::move(callback);
}

void BinderHook::unregisterCallback(const std::string& serviceName, const std::string& methodName,
                                    bool isBefore) {
    std::string key = (isBefore ? "before#" : "after#") + serviceName + "#" + methodName;
    std::lock_guard<std::mutex> lock(callbacksMutex_);
    callbacks_.erase(key);
}

void BinderHook::addJavaCallback(const std::string& serviceName, const std::string& methodName,
                                 bool isBefore) {
    auto callback = [this, serviceName, methodName, isBefore](
            binder_transaction_data* txn, bool isReply,
            uint8_t** outData, size_t* outDataSize,
            uint8_t** outOffsets, binder_size_t* outOffsetsSize) -> bool {
        return callJavaDispatcher(serviceName, methodName, isBefore, txn,
                                  outData, outDataSize, outOffsets, outOffsetsSize);
    };
    registerCallback(serviceName, methodName, isBefore, callback);
}

void BinderHook::removeJavaCallback(const std::string& serviceName, const std::string& methodName,
                                    bool isBefore) {
    unregisterCallback(serviceName, methodName, isBefore);
}

bool BinderHook::callJavaDispatcher(const std::string& serverName, const std::string& methodName,
                                    bool isBefore, binder_transaction_data* txn,
                                    uint8_t** outData, size_t* outDataSize,
                                    uint8_t** outOffsets, binder_size_t* outOffsetsSize) {
    JNIEnv* env;
    bool needDetach = false;
    if (jvm_->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
        jvm_->AttachCurrentThread(&env, nullptr);
        needDetach = true;
    }

    env->ExceptionClear();

    jclass parcelClass = env->FindClass("android/os/Parcel");
    if (env->ExceptionCheck() || !parcelClass) {
        env->ExceptionClear();
        if (needDetach) jvm_->DetachCurrentThread();
        return false;
    }
    jmethodID obtainMid = env->GetStaticMethodID(parcelClass, "obtain", "()Landroid/os/Parcel;");
    jmethodID unmarshallMid = env->GetMethodID(parcelClass, "unmarshall", "([BII)V");
    jmethodID setDataPositionMid = env->GetMethodID(parcelClass, "setDataPosition", "(I)V");
    jmethodID recycleMid = env->GetMethodID(parcelClass, "recycle", "()V");

    jobject dataParcel = env->CallStaticObjectMethod(parcelClass, obtainMid);
    jbyteArray byteArray = env->NewByteArray(txn->data_size);
    env->SetByteArrayRegion(byteArray, 0, txn->data_size, (const jbyte*)txn->data.ptr.buffer);
    env->CallVoidMethod(dataParcel, unmarshallMid, byteArray, 0, (jint)txn->data_size);
    env->CallVoidMethod(dataParcel, setDataPositionMid, 0);
    env->DeleteLocalRef(byteArray);

    jobject outParcel = env->CallStaticObjectMethod(parcelClass, obtainMid);
    jmethodID setDataSizeMid = env->GetMethodID(parcelClass, "setDataSize", "(I)V");
    if (setDataSizeMid) {
        env->CallVoidMethod(outParcel, setDataSizeMid, 0);
    }

    jstring jServer = env->NewStringUTF(serverName.c_str());
    jstring jMethod = env->NewStringUTF(methodName.c_str());

    jboolean modified;
    if (isBefore) {
        modified = env->CallStaticBooleanMethod(dispatcherClass_, dispatchBeforeMid_,
                                                jServer, jMethod, dataParcel, outParcel);
    } else {
        modified = env->CallStaticBooleanMethod(dispatcherClass_, dispatchAfterMid_,
                                                jServer, jMethod, dataParcel, outParcel);
    }

    env->DeleteLocalRef(jServer);
    env->DeleteLocalRef(jMethod);

    bool result = false;
    if (modified) {
        jmethodID dataSizeMid = env->GetMethodID(parcelClass, "dataSize", "()I");
        jint newSize = env->CallIntMethod(outParcel, dataSizeMid);
        if (newSize > 0) {
            jmethodID marshallMid = env->GetMethodID(parcelClass, "marshall", "()[B");
            jbyteArray newData = (jbyteArray)env->CallObjectMethod(outParcel, marshallMid);
            jsize newLen = env->GetArrayLength(newData);
            uint8_t* newBuf = (uint8_t*)malloc(newLen);
            env->GetByteArrayRegion(newData, 0, newLen, (jbyte*)newBuf);
            env->DeleteLocalRef(newData);
            *outData = newBuf;
            *outDataSize = newLen;
            *outOffsets = nullptr;
            *outOffsetsSize = 0;
            result = true;
            LOGD("Java callback modified data, new size=%zu", newLen);
        }
    }

    env->CallVoidMethod(dataParcel, recycleMid);
    env->CallVoidMethod(outParcel, recycleMid);
    env->DeleteLocalRef(dataParcel);
    env->DeleteLocalRef(outParcel);
    env->DeleteLocalRef(parcelClass);

    if (needDetach) jvm_->DetachCurrentThread();
    return result;
}


bool BinderHook::invokeJavaCallback(binder_transaction_data* txn, bool isReply,
                                    uint8_t** outData, size_t* outDataSize,
                                    uint8_t** outOffsets, binder_size_t* outOffsetsSize) {
    if (!isReply) {
        // 请求：获取服务名和方法名
        std::string serverName;
        auto itCache = serviceCache_.find(txn->target.handle);
        if (itCache != serviceCache_.end()) {
            serverName = itCache->second;
        } else {
            serverName = get_server_name(txn);
            if (!serverName.empty()) {
                serviceCache_[txn->target.handle] = serverName;
            }
        }
        if (serverName.empty()) {
            LOGD("Empty server name for request txn: code=%u", txn->code);
            return false;
        }

        std::string methodName;
        {
            std::lock_guard<std::mutex> lock(methodCacheMutex_);
            auto itService = methodCache_.find(serverName);
            if (itService != methodCache_.end()) {
                auto itCode = itService->second.find(txn->code);
                if (itCode != itService->second.end()) {
                    methodName = itCode->second;
                }
            }
        }
        if (methodName.empty()) {
            std::string slashName = dotted_to_slash(serverName);
            JNIEnv* env = nullptr;
            bool needDetach = false;
            if (jvm_->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
                jvm_->AttachCurrentThread(&env, nullptr);
                needDetach = true;
            }

            std::vector<std::string> classes_to_try = {
                slashName + "$Stub",
                slashName,
                "android/content/ContentProviderNative"
            };

            for (const auto& cls : classes_to_try) {
                methodName = get_transaction_name(env, cls.c_str(), txn->code);
                if (!methodName.empty()) {
                    break;
                }
            }

            if (needDetach) jvm_->DetachCurrentThread();

            // 3. 解析成功则写入缓存（加写锁）
            if (!methodName.empty()) {
                std::lock_guard<std::mutex> lock(methodCacheMutex_);
                methodCache_[serverName][txn->code] = methodName;
            }
        }
        if (methodName.empty()) {
            //LOGD("serverName: %s, Empty method name for code %u", serverName.c_str(), txn->code);
            return false;
        }
        LOGD("serverName: %s, Method name: %s, txn code: %d", serverName.c_str(), methodName.c_str(), txn->code);

        LOGD("serverName:%s. methodName:%s", serverName.c_str(), methodName.c_str());

        // 保存到线程局部存储
        txnContext_.serviceName = serverName;
        txnContext_.methodName = methodName;

        // 查找回调
        std::string key = "before#" + serverName + "#" + methodName;
        BinderNativeCallback cb;
        {
            std::lock_guard<std::mutex> lock(callbacksMutex_);
            auto it = callbacks_.find(key);
            if (it != callbacks_.end()) cb = it->second;
        }
        if (cb) {
            return cb(txn, isReply, outData, outDataSize, outOffsets, outOffsetsSize);
        }
        return false;
    }
    else {
        // 回复
        std::string serverName = txnContext_.serviceName;
        std::string methodName = txnContext_.methodName;
        if (serverName.empty() || methodName.empty()) return false;

        std::string key = "after#" + serverName + "#" + methodName;
        BinderNativeCallback cb;
        {
            std::lock_guard<std::mutex> lock(callbacksMutex_);
            auto it = callbacks_.find(key);
            if (it != callbacks_.end()) cb = it->second;
        }
        bool result = false;
        if (cb) {
            result = cb(txn, isReply, outData, outDataSize, outOffsets, outOffsetsSize);
        }
        txnContext_.serviceName.clear();
        txnContext_.methodName.clear();
        return result;
    }
}

void BinderHook::adjust_offsets(binder_transaction_data* txn, int delta) {
    if (txn->offsets_size == 0) return;
    auto* offs = (binder_size_t*)(uintptr_t)txn->data.ptr.offsets;
    size_t count = txn->offsets_size / sizeof(binder_size_t);
    for (size_t i = 0; i < count; ++i) {
        offs[i] += delta;
    }
}

bool BinderHook::replace_transaction_data(binder_transaction_data* txn,
                                          const uint8_t* newData, size_t newDataSize,
                                          const uint8_t* newOffsets, binder_size_t newOffsetsSize) {
    // 如果 newData 就是原始缓冲区地址，说明已经原地修改，无需任何操作
    if ((uintptr_t)newData == txn->data.ptr.buffer) {
        LOGD("replace_transaction_data: in-place modified, no action");
        return true;
    }

    LOGD("replace_transaction_data: newDataSize=%zu, old size=%llu", newDataSize, txn->data_size);
    LOGD("replace_transaction_data: old buffer=%p, new buffer will be allocated", (void*)txn->data.ptr.buffer);

    uint8_t* newDataBuf = (uint8_t*)malloc(newDataSize);
    if (!newDataBuf) return false;
    memcpy(newDataBuf, newData, newDataSize);
    LOGD("replace_transaction_data: allocated new buffer at %p", newDataBuf);

    binder_size_t* newOffsetsBuf = nullptr;
    if (newOffsetsSize > 0) {
        newOffsetsBuf = (binder_size_t*)malloc(newOffsetsSize);
        if (!newOffsetsBuf) {
            free(newDataBuf);
            return false;
        }
        memcpy(newOffsetsBuf, newOffsets, newOffsetsSize);
        LOGD("replace_transaction_data: allocated new offsets buffer at %p", newOffsetsBuf);
    }

    {
        std::lock_guard<std::mutex> lock(mapMutex_);
        addrMap_[(uintptr_t)txn->data.ptr.buffer] = (uintptr_t)newDataBuf;
    }

    int delta = (int)newDataSize - (int)txn->data_size;
    LOGD("replace_transaction_data: delta=%d", delta);

    txn->data.ptr.buffer = (binder_uintptr_t)newDataBuf;
    if (newOffsetsBuf) {
        txn->data.ptr.offsets = (binder_uintptr_t)newOffsetsBuf;
    }
    txn->data_size = newDataSize;
    if (newOffsetsSize != txn->offsets_size) {
        txn->offsets_size = newOffsetsSize;
        LOGD("replace_transaction_data: offsets_size changed to %llu", newOffsetsSize);
    }

    if (delta != 0) {
        adjust_offsets(txn, delta);
        LOGD("replace_transaction_data: offsets adjusted");
    }

    return true;
}

void BinderHook::process_write_commands(struct binder_write_read* bwr) {
    void* ptr = (void*)(uintptr_t)bwr->write_buffer;
    size_t remaining = bwr->write_size;

    while (remaining >= sizeof(uint32_t)) {
        uint32_t cmd = *(uint32_t*)ptr;
        size_t data_len = get_cmd_data_size(cmd, 0);
        if (remaining < sizeof(uint32_t) + data_len) break;

        void* dataPtr = (char*)ptr + sizeof(uint32_t);
        binder_transaction_data* txn = nullptr;
        bool isTransaction = false;

        if (cmd == BC_TRANSACTION || cmd == BC_REPLY) {
            txn = (binder_transaction_data*)dataPtr;
            isTransaction = true;
        } else if (cmd == BC_TRANSACTION_SG || cmd == BC_REPLY_SG) {
            auto* txn_sg = (binder_transaction_data_sg*)dataPtr;
            txn = &txn_sg->transaction_data;
            isTransaction = true;
        } else if (cmd == BC_FREE_BUFFER) {
            if (data_len >= sizeof(binder_uintptr_t)) {
                binder_uintptr_t* addr = (binder_uintptr_t*)dataPtr;
                uintptr_t orig = handle_free(*addr);
                if (orig) *addr = orig;
            }
        }

        if (isTransaction && txn) {
            uint8_t* newData = nullptr;
            size_t newDataSize = 0;
            uint8_t* newOffsets = nullptr;
            binder_size_t newOffsetsSize = 0;
            // 请求：isReply = false
            bool modified = invokeJavaCallback(txn, false, &newData, &newDataSize,
                                               &newOffsets, &newOffsetsSize);
            if (modified && newData) {
                // 请求数据修改，长度可能变化，使用 replace_transaction_data
                replace_transaction_data(txn, newData, newDataSize, newOffsets, newOffsetsSize);
                free(newData);
                if (newOffsets) free(newOffsets);
            }
        }

        ptr = (char*)ptr + sizeof(uint32_t) + data_len;
        remaining -= sizeof(uint32_t) + data_len;
    }
}

void BinderHook::process_read_commands(struct binder_write_read* bwr) {
    void* ptr = (void*)(uintptr_t)bwr->read_buffer;
    size_t remaining = bwr->read_size;

    while (remaining >= sizeof(uint32_t)) {
        uint32_t cmd = *(uint32_t*)ptr;
        size_t data_len = get_cmd_data_size(cmd, 1);
        if (remaining < sizeof(uint32_t) + data_len) break;

        void* dataPtr = (char*)ptr + sizeof(uint32_t);
        binder_transaction_data* txn = nullptr;
        bool isTransaction = false;

        if (cmd == BR_TRANSACTION || cmd == BR_REPLY) {
            txn = (binder_transaction_data*)dataPtr;
            isTransaction = true;
        } else if (cmd == BR_TRANSACTION_SEC_CTX) {
            auto* sec = (binder_transaction_data_secctx*)dataPtr;
            txn = &sec->transaction_data;
            isTransaction = true;
        }
        // 注意：驱动不会返回 BR_FREE_BUFFER，只有 BC_FREE_BUFFER 由用户空间发送

        if (isTransaction && txn) {
//            LOGD("process_read_commands: handling %s, code=%u, data_size=%llu",
//                 (cmd == BR_REPLY ? "BR_REPLY" : "BR_TRANSACTION"),
//                 txn->code, txn->data_size);

            if (txn->code == 8) { // Transaction code 8 corresponds to getApplicationInfo in IPackageManager
                 LOGD("process_read_commands: dumping data for code=8 (possibly getApplicationInfo)");
                 dump((void*)(uintptr_t)txn->data.ptr.buffer, txn->data_size > 256 ? 256 : txn->data_size);
            }

            uint8_t* newData = nullptr;
            size_t newDataSize = 0;
            uint8_t* newOffsets = nullptr;
            binder_size_t newOffsetsSize = 0;
            bool modified = invokeJavaCallback(txn, true, &newData, &newDataSize,
                                               &newOffsets, &newOffsetsSize);
            if (modified && newData) {
                LOGD("process_read_commands: replace_transaction_data called");
                replace_transaction_data(txn, newData, newDataSize, newOffsets, newOffsetsSize);
                free(newData);
                if (newOffsets) free(newOffsets);
            } else if (modified) {
                LOGD("process_read_commands: in-place modified, no replace");
            }
        }

        ptr = (char*)ptr + sizeof(uint32_t) + data_len;
        remaining -= sizeof(uint32_t) + data_len;
    }
}

int BinderHook::process_ioctl(int fd, unsigned long request, void* args) {
    if (request != BINDER_WRITE_READ) {
        return ioctl(fd, request, args);
    }

    auto* bwr = (struct binder_write_read*)args;

    if (bwr->write_size > 0 && bwr->write_buffer != 0) {
        process_write_commands(bwr);
    }

    int ret = ioctl(fd, request, args);

    if (bwr->read_size > 0 && bwr->read_buffer != 0) {
        process_read_commands(bwr);
    }

    return ret;
}