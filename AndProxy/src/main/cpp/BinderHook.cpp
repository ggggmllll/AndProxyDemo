#include "BinderHook.h"
#include "binder_proxy.h"
#include "log.h"

#include <elf.h>
#include <thread>
#include <utility>
#include <vector>
#include <sys/mman.h>
#include <bits/sysconf.h>
#include <algorithm>
#include <cinttypes>

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

// ==================== GOT Hook 相关函数（保持不变） ====================
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
        if (path && strstr(path, libname)) {
            char *dash = strchr(line, '-');
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

static uintptr_t get_dynamic_info_offset(const Elf64_Dyn *dyn, int64_t tag) {
    for (; dyn->d_tag != DT_NULL; ++dyn) {
        if (dyn->d_tag == tag) return dyn->d_un.d_ptr;
    }
    return 0;
}

static uintptr_t find_got_entry(const char *libname, const char *funcname) {
    uintptr_t base = get_library_base(libname);
    if (!base) return 0;
    auto *ehdr = (Elf64_Ehdr*)base;
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 || ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr->e_ident[EI_MAG2] != ELFMAG2 || ehdr->e_ident[EI_MAG3] != ELFMAG3) {
        LOGE("Invalid ELF header");
        return 0;
    }
    auto *phdr = (Elf64_Phdr*)(base + ehdr->e_phoff);
    Elf64_Dyn *dyn = nullptr;
    for (int i = 0; i < ehdr->e_phnum; ++i) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn = (Elf64_Dyn*)(base + phdr[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return 0;
    uintptr_t symtab_off = get_dynamic_info_offset(dyn, DT_SYMTAB);
    uintptr_t strtab_off = get_dynamic_info_offset(dyn, DT_STRTAB);
    uintptr_t relplt_off = get_dynamic_info_offset(dyn, DT_JMPREL);
    size_t relplt_size = get_dynamic_info_offset(dyn, DT_PLTRELSZ);
    if (!symtab_off || !strtab_off || !relplt_off || !relplt_size) return 0;
    auto *symtab = (Elf64_Sym*)(base + symtab_off);
    const char *strtab = (const char*)(base + strtab_off);
    auto *relplt = (Elf64_Rela*)(base + relplt_off);
    size_t num_rel = relplt_size / sizeof(Elf64_Rela);
    for (size_t i = 0; i < num_rel; ++i) {
        uint32_t sym_idx = ELF64_R_SYM(relplt[i].r_info);
        const char *sym_name = strtab + symtab[sym_idx].st_name;
        if (strcmp(sym_name, funcname) == 0) {
            return base + relplt[i].r_offset;
        }
    }
    return 0;
}

static void got_hook(uintptr_t got_addr, void *new_func, void **old_func) {
    void **got_ptr = (void**)got_addr;
    void *orig = *got_ptr;
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) return;
    uintptr_t page_start = got_addr & ~(page_size - 1);
    if (mprotect((void*)page_start, page_size, PROT_READ | PROT_WRITE) == -1) return;
    *got_ptr = new_func;
    if (mprotect((void*)page_start, page_size, PROT_READ) == -1) {
        // ignore
    }
    if (old_func) *old_func = orig;
}

void BinderHook::init(JavaVM* vm) {
    uintptr_t got_entry = find_got_entry("libbinder.so", "ioctl");
    if (!got_entry) {
        LOGE("Failed to find GOT entry for ioctl");
        return;
    }
    got_hook(got_entry, (void*)ioctl_proxy, nullptr);
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

// ==================== 回调管理 ====================
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
            uint8_t** outData, size_t* outDataSize) -> bool {
        return callJavaDispatcher(serviceName, methodName, isBefore, txn,
                                  outData, outDataSize);
    };
    registerCallback(serviceName, methodName, isBefore, callback);
}

void BinderHook::removeJavaCallback(const std::string& serviceName, const std::string& methodName,
                                    bool isBefore) {
    unregisterCallback(serviceName, methodName, isBefore);
}

// ==================== Java 调度器（适配新签名） ====================
bool BinderHook::callJavaDispatcher(const std::string& serverName, const std::string& methodName,
                                    bool isBefore, binder_transaction_data* txn,
                                    uint8_t** outData, size_t* outDataSize) {
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
    jbyteArray byteArray = env->NewByteArray((int) txn->data_size);
    env->SetByteArrayRegion(byteArray, 0, (int) txn->data_size, (const jbyte*)txn->data.ptr.buffer);
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
            auto newData = (jbyteArray)env->CallObjectMethod(outParcel, marshallMid);
            jsize newLen = env->GetArrayLength(newData);
            auto* newBuf = (uint8_t*)malloc(newLen);
            env->GetByteArrayRegion(newData, 0, newLen, (jbyte*)newBuf);
            env->DeleteLocalRef(newData);
            *outData = newBuf;
            *outDataSize = newLen;
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

// ==================== 核心回调调用（统一入口） ====================
bool BinderHook::invokeCallback(binder_transaction_data* txn, bool isReply,
                                uint8_t** outData, size_t* outDataSize) {
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
            return false;
        }

        std::string methodName;
        {
            std::lock_guard<std::mutex> lock(methodCacheMutex_);
            auto itService = methodCache_.find(serverName);
            if (itService != methodCache_.end()) {
                auto itCode = itService->second.find((int) txn->code);
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
            std::vector<std::string> classes_to_try = { slashName + "$Stub", slashName };
            for (const auto& cls : classes_to_try) {
                methodName = get_transaction_name(env, cls.c_str(), (int) txn->code);
                if (!methodName.empty()) break;
            }
            if (needDetach) jvm_->DetachCurrentThread();
            if (!methodName.empty()) {
                std::lock_guard<std::mutex> lock(methodCacheMutex_);
                methodCache_[serverName][(int) txn->code] = methodName;
            }
        }
        if (methodName.empty()) return false;

        LOGD("serverName: %s, Method name: %s, txn code: %d", serverName.c_str(), methodName.c_str(), txn->code);

        // 保存到线程局部存储
        txnContext_.serviceName = serverName;
        txnContext_.methodName = methodName;

        std::string key = "before#" + serverName + "#" + methodName;
        BinderNativeCallback cb;
        {
            std::lock_guard<std::mutex> lock(callbacksMutex_);
            auto it = callbacks_.find(key);
            if (it != callbacks_.end()) cb = it->second;
        }
        if (cb) {
            return cb(txn, isReply, outData, outDataSize);
        }
        return false;
    } else {
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
            result = cb(txn, isReply, outData, outDataSize);
        }
        txnContext_.serviceName.clear();
        txnContext_.methodName.clear();
        return result;
    }
}

// ==================== 偏移重建算法 ====================
struct BinderObjectInfo {
    binder_size_t old_offset;
    uint64_t signature;
};

struct Candidate {
    binder_size_t offset;
    uint64_t signature;
};

static uint64_t read_signature(const uint8_t* data, size_t offset) {
    return *(uint64_t*)(data + offset);
}

static std::vector<Candidate> scan_candidates(const uint8_t* newData, size_t newSize,
                                              const std::vector<uint64_t>& old_sigs) {
    std::vector<Candidate> candidates;
    for (size_t off = 0; off + 8 <= newSize; off++) {
        uint64_t sig = read_signature(newData, off);
        if (std::find(old_sigs.begin(), old_sigs.end(), sig) != old_sigs.end()) {
            candidates.push_back({(binder_size_t)off, sig});
        }
    }
    return candidates;
}

static bool match_offsets(const std::vector<BinderObjectInfo>& old_infos,
                          const std::vector<Candidate>& candidates,
                          int idx, size_t last_pos, int64_t accumulated_delta,
                          int64_t target_delta, std::vector<binder_size_t>& out_offsets) {
    if (idx == (int)old_infos.size()) {
        return accumulated_delta == target_delta;
    }
    for (size_t i = last_pos; i < candidates.size(); ++i) {
        if (candidates[i].signature != old_infos[idx].signature) continue;
        if (!out_offsets.empty() && candidates[i].offset <= out_offsets.back()) continue;
        int64_t delta = (int64_t)candidates[i].offset - (int64_t)old_infos[idx].old_offset;
        if (accumulated_delta + delta > target_delta + 1024) continue; // 简单剪枝
        out_offsets.push_back(candidates[i].offset);
        if (match_offsets(old_infos, candidates, idx + 1, i + 1,
                          accumulated_delta + delta, target_delta, out_offsets)) {
            return true;
        }
        out_offsets.pop_back();
    }
    return false;
}

static bool rebuild_offsets_from_signatures(const uint8_t* oldData, size_t oldSize,
                                                 const binder_size_t* oldOffsets, size_t oldOffsetsCount,
                                                 const uint8_t* newData, size_t newSize,
                                                 std::vector<binder_size_t>& out_offsets) {
    // 提取旧对象信息
    std::vector<BinderObjectInfo> old_infos;
    for (size_t i = 0; i < oldOffsetsCount; ++i) {
        binder_size_t off = oldOffsets[i];
        if (off + 8 > oldSize) {
            LOGE("Invalid old offset %" PRIu64, (uint64_t)off);
            return false;
        }
        old_infos.push_back({off, read_signature(oldData, off)});
    }

    // 收集旧签名集合
    std::vector<uint64_t> old_sigs;
    old_sigs.reserve(old_infos.size());
    for (auto& info : old_infos) old_sigs.push_back(info.signature);

    // 扫描新数据中的候选
    std::vector<Candidate> candidates = scan_candidates(newData, newSize, old_sigs);
    if (candidates.size() < oldOffsetsCount) {
        LOGE("Candidate count (%zu) < old object count (%zu)", candidates.size(), oldOffsetsCount);
        return false;
    }

    int64_t target_delta = (int64_t)newSize - (int64_t)oldSize;
    out_offsets.clear();
    bool success = match_offsets(old_infos, candidates, 0, 0, 0, target_delta, out_offsets);
    if (!success) {
        LOGE("Failed to match offsets with target delta %lld", (long long)target_delta);
        return false;
    }
    LOGD("Successfully rebuilt %zu offsets, total delta = %lld", out_offsets.size(), (long long)target_delta);
    return true;
}

// ==================== 数据替换（自动重建 offsets） ====================
bool BinderHook::replace_transaction_data_with_rebuild(binder_transaction_data* txn,
                                                       const uint8_t* newData, size_t newDataSize) {
    // 原地修改无需替换
    if ((uintptr_t)newData == txn->data.ptr.buffer) {
        LOGD("replace_transaction_data_with_rebuild: in-place modified, no action");
        return true;
    }

    // 获取旧数据信息
    const auto* oldData = (const uint8_t*)(uintptr_t)txn->data.ptr.buffer;
    size_t oldDataSize = txn->data_size;
    const auto* oldOffsets = (const binder_size_t*)(uintptr_t)txn->data.ptr.offsets;
    size_t oldOffsetsCount = txn->offsets_size / sizeof(binder_size_t);

    // 重建 offsets
    std::vector<binder_size_t> new_offsets_vec;
    if (!rebuild_offsets_from_signatures(oldData, oldDataSize, oldOffsets, oldOffsetsCount,
                                         newData, newDataSize, new_offsets_vec)) {
        LOGE("Failed to rebuild offsets, abort replacement");
        return false;
    }

    // 分配新缓冲区
    auto* newDataBuf = (uint8_t*)malloc(newDataSize);
    if (!newDataBuf) return false;
    memcpy(newDataBuf, newData, newDataSize);

    binder_size_t* newOffsetsBuf = nullptr;
    if (!new_offsets_vec.empty()) {
        newOffsetsBuf = (binder_size_t*)malloc(new_offsets_vec.size() * sizeof(binder_size_t));
        if (!newOffsetsBuf) {
            free(newDataBuf);
            return false;
        }
        memcpy(newOffsetsBuf, new_offsets_vec.data(), new_offsets_vec.size() * sizeof(binder_size_t));
    }

    // 替换指针并记录旧地址
    {
        std::lock_guard<std::mutex> lock(mapMutex_);
        addrMap_[(uintptr_t)txn->data.ptr.buffer] = (uintptr_t)newDataBuf;
        if (txn->data.ptr.offsets != 0) {
            addrMap_[(uintptr_t)txn->data.ptr.offsets] = (uintptr_t)newOffsetsBuf;
        }
    }

    txn->data.ptr.buffer = (binder_uintptr_t)newDataBuf;
    txn->data_size = newDataSize;
    txn->data.ptr.offsets = (binder_uintptr_t)newOffsetsBuf;
    txn->offsets_size = new_offsets_vec.size() * sizeof(binder_size_t);

    LOGD("Replaced transaction data with rebuilt offsets (new size=%zu, offsets count=%zu)",
         newDataSize, new_offsets_vec.size());
    return true;
}

// ==================== 命令处理 ====================
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
                auto* addr = (binder_uintptr_t*)dataPtr;
                uintptr_t orig = handle_free(*addr);
                if (orig) *addr = orig;
            }
        }

        if (isTransaction && txn) {
            uint8_t* newData = nullptr;
            size_t newDataSize = 0;
            bool modified = invokeCallback(txn, false, &newData, &newDataSize);
            if (modified && newData) {
                replace_transaction_data_with_rebuild(txn, newData, newDataSize);
                free(newData);
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

        if (isTransaction && txn) {
            uint8_t* newData = nullptr;
            size_t newDataSize = 0;
            bool modified = invokeCallback(txn, true, &newData, &newDataSize);
            if (modified && newData) {
                replace_transaction_data_with_rebuild(txn, newData, newDataSize);
                free(newData);
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