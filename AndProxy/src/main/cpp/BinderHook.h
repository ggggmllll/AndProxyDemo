#ifndef HOOK_BINDERHOOK_H
#define HOOK_BINDERHOOK_H

#include <jni.h>
#include <mutex>
#include <map>
#include <string>
#include <functional>
#include <vector>
#include "binder_proxy.h"  // 包含 binder 结构定义

// Native 回调函数原型（不再需要提供 offsets，框架自动重建）
using BinderNativeCallback = std::function<bool(binder_transaction_data* txn,
                                                bool isReply,
                                                uint8_t** outData,
                                                size_t* outDataSize)>;

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

    // 统一的回调调用入口（替代原来的 invokeJavaCallback）
    bool invokeCallback(binder_transaction_data* txn, bool isReply,
                        uint8_t** outData, size_t* outDataSize);

    // 替换事务数据并自动重建 offsets
    bool replace_transaction_data_with_rebuild(binder_transaction_data* txn,
                                               const uint8_t* newData, size_t newDataSize);

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
    // 缓存：服务名 -> (code -> 方法名)
    std::map<std::string, std::map<int, std::string>> methodCache_;
    std::mutex methodCacheMutex_;

    // 统一回调映射（key = (isBefore ? "before#" : "after#") + serviceName + "#" + methodName）
    std::map<std::string, BinderNativeCallback> callbacks_;
    std::mutex callbacksMutex_;

    // 封装 JNI 调用 Java 分派函数
    bool callJavaDispatcher(const std::string& serverName, const std::string& methodName,
                            bool isBefore, binder_transaction_data* txn,
                            uint8_t** outData, size_t* outDataSize);
};

#endif //HOOK_BINDERHOOK_H