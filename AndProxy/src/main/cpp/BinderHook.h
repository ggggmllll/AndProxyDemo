//
// Created by lenovo on 2026/3/24.
//

#ifndef JVMTI_HOOK_BINDERHOOK_H
#define JVMTI_HOOK_BINDERHOOK_H

#include <jni.h>
#include <mutex>
#include <map>
#include <string>
#include "binder_proxy.h"  // 包含 binder 结构定义

// Native 回调函数原型
using BinderNativeCallback = std::function<bool(binder_transaction_data* txn,
                                                bool isReply,
                                                uint8_t** outData,
                                                size_t* outDataSize,
                                                uint8_t** outOffsets,
                                                binder_size_t* outOffsetsSize)>;

class BinderHook {
public:
    static BinderHook& instance();

    void init(JavaVM* vm);
    int process_ioctl(int fd, unsigned long request, void* args);

    // 注册/注销回调（统一接口）
    void registerCallback(const std::string& serviceName, const std::string& methodName,
                          bool isBefore, BinderNativeCallback callback);
    void unregisterCallback(const std::string& serviceName, const std::string& methodName,
                            bool isBefore);

    // 由 JNI 调用，用于注册 Java 回调（内部包装为 Native 回调）
    void addJavaCallback(const std::string& serviceName, const std::string& methodName, bool isBefore);
    void removeJavaCallback(const std::string& serviceName, const std::string& methodName, bool isBefore);

private:
    BinderHook() = default;
    ~BinderHook();

    bool invokeJavaCallback(binder_transaction_data* txn, bool isReply,
                            uint8_t** outData, size_t* outDataSize,
                            uint8_t** outOffsets, binder_size_t* outOffsetsSize);

    static void adjust_offsets(binder_transaction_data* txn, int delta);
    bool replace_transaction_data(binder_transaction_data* txn,
                                  const uint8_t* newData, size_t newDataSize,
                                  const uint8_t* newOffsets, binder_size_t newOffsetsSize);

    void process_write_commands(struct binder_write_read* bwr);
    void process_read_commands(struct binder_write_read* bwr);

    uintptr_t handle_free(uintptr_t addr);

    JavaVM* jvm_ = nullptr;
    jclass dispatcherClass_ = nullptr;
    jmethodID dispatchBeforeMid_ = nullptr;
    jmethodID dispatchAfterMid_ = nullptr;

    // 线程局部存储：保存当前请求的服务名和方法名
    struct TxnContext {
        std::string serviceName;
        std::string methodName;
    };
    static thread_local TxnContext txnContext_;

    // 内存映射：原地址 -> 新地址
    std::map<uintptr_t, uintptr_t> addrMap_;
    std::mutex mapMutex_;

    // 缓存：handle -> 服务名
    std::map<uint32_t, std::string> serviceCache_;
    // 缓存：code -> 方法名
    std::map<std::string, std::map<int, std::string>> methodCache_;
    std::mutex methodCacheMutex_;   // 新增互斥锁

    // 统一回调映射（key = (isBefore ? "before#" : "after#") + serviceName + "#" + methodName）
    std::map<std::string, BinderNativeCallback> callbacks_;
    std::mutex callbacksMutex_;

    // 封装 JNI 调用 Java 分派函数
    bool callJavaDispatcher(const std::string& serverName, const std::string& methodName,
                            bool isBefore, binder_transaction_data* txn,
                            uint8_t** outData, size_t* outDataSize,
                            uint8_t** outOffsets, binder_size_t* outOffsetsSize);
};


#endif //JVMTI_HOOK_BINDERHOOK_H
