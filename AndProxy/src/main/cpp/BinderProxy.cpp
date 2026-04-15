//
// Created by lenovo on 2026/3/24.
//

#include "BinderHook.h"
#include "elf_utils.h"
#include "log.h"
#include <sys/system_properties.h>

extern "C" JNIEXPORT void JNICALL
Java_com_gumuluo_proxy_binder_BinderProxy_nativeInit(JNIEnv* env, jclass clazz) {
    JavaVM* vm;
    env->GetJavaVM(&vm);
    BinderHook::instance().init(vm);
}

// 外部符号：ioctl_proxy 由 hook 框架调用
int ioctl_proxy(int fd, unsigned long request, void* args) {
    return BinderHook::instance().process_ioctl(fd, request, args);
}

extern "C" JNIEXPORT void JNICALL
Java_com_gumuluo_proxy_binder_BinderDispatcher_nativeAddJavaCallback(JNIEnv* env, jclass clazz,
                                                                     jstring serviceName, jstring methodName,
                                                                     jboolean isBefore) {
    const char* svc = env->GetStringUTFChars(serviceName, nullptr);
    const char* mtd = env->GetStringUTFChars(methodName, nullptr);
    BinderHook::instance().addJavaCallback(svc, mtd, isBefore);
    env->ReleaseStringUTFChars(serviceName, svc);
    env->ReleaseStringUTFChars(methodName, mtd);
}

extern "C" JNIEXPORT void JNICALL
Java_com_gumuluo_proxy_binder_BinderDispatcher_nativeRemoveJavaCallback(JNIEnv* env, jclass clazz,
                                                                        jstring serviceName, jstring methodName,
                                                                        jboolean isBefore) {
    const char* svc = env->GetStringUTFChars(serviceName, nullptr);
    const char* mtd = env->GetStringUTFChars(methodName, nullptr);
    BinderHook::instance().removeJavaCallback(svc, mtd, isBefore);
    env->ReleaseStringUTFChars(serviceName, svc);
    env->ReleaseStringUTFChars(methodName, mtd);
}

// 获取当前设备的 API Level
static int get_api_level() {
    char sdk[PROP_VALUE_MAX] = {0};
    if (__system_property_get("ro.build.version.sdk", sdk) > 0) {
        return atoi(sdk);
    }
    return 0;
}

/**
 * 试探法从 BpBinder* 中提取 handle 值
 * @param bpBinder  指向 BpBinder 对象的指针
 * @return handle 值，失败返回 -1
 */
static int32_t extract_handle_heuristic(void* bpBinder) {
    if (!bpBinder) return -1;

    int api = get_api_level();
    LOGD("extract_handle_heuristic: API level = %d", api);

    // 基础候选集（按理论布局排列）
    std::vector<int32_t> offsets;

    // 根据 API Level 添加优先偏移
    if (api >= 33) {          // Android 13+
        offsets = {16, 40};
    } else if (api >= 1) {    // Android 11 及以下（含未知 API）
        offsets = {8, 32};
    } else {
        // 完全未知 API，尝试所有可能
        offsets = {8, 16, 32, 40, 24, 28, 36, 44};
    }

    // 去重（可选，但直接遍历即可）
    for (int32_t offset : offsets) {
        if (offset < 0 || offset > 128) continue;

        int32_t val = *reinterpret_cast<int32_t*>(static_cast<char*>(bpBinder) + offset);

        if (val > 0 && val < 256) {
            LOGD("extract_handle_heuristic: found plausible handle %d at offset %d (API %d)",
                 val, offset, api);
            return val;
        }
    }

    LOGE("extract_handle_heuristic: no plausible handle found (API %d)", api);
    return -1;
}

// 从 BpBinder* 中提取 handle 值
int32_t nativeExtractHandle(void* bpBinderPtr) {
    if (!bpBinderPtr) return -1;

    // 1. 优先尝试符号调用（如果存在）
//    uintptr_t debugHandleAddr = elf_find_symbol("libbinder.so",
//                                                "_ZNK7android8BpBinder20getDebugBinderHandleEv");
//    if (debugHandleAddr) {
//        using GetDebugHandle = std::optional<int32_t> (*)(void*);
//        auto func = reinterpret_cast<GetDebugHandle>(debugHandleAddr);
//        auto opt = func(bpBinderPtr);
//        if (opt.has_value()) {
//            LOGD("nativeExtractHandle: via getDebugBinderHandle = %d", opt.value());
//            return opt.value();
//        }
//    }

    // 2. 回退：多偏移量试探
    return extract_handle_heuristic(bpBinderPtr);
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_gumuluo_proxy_binder_BinderProxy_nativeExtractHandle(JNIEnv *env, jclass clazz,
                                                              jlong binder) {
    void* bpData = reinterpret_cast<void*>(binder);
    if (!bpData) {
        LOGE("nativeExtractHandle: null BinderProxyNativeData pointer");
        return -1;
    }

    // 1. 从 BinderProxyNativeData 中取出 mObject（sp<IBinder>），其内部仅一个指针
    void* ibinderPtr = *reinterpret_cast<void**>(bpData);
    LOGD("nativeExtractHandle: BinderProxyNativeData at %p, IBinder* = %p", bpData, ibinderPtr);

    // 2. 可选：dump 结构体内存，便于验证
    constexpr size_t kDumpSize = 64;
    LOGD("--- BinderProxyNativeData memory (first %zu bytes) ---", kDumpSize);
    dump(bpData, kDumpSize);
    LOGD("--- BpBinder memory (first 64 bytes) ---");
    dump(ibinderPtr, 64);

    // 3. 将 IBinder* 直接作为 BpBinder* 提取 handle
    int32_t handle = nativeExtractHandle(ibinderPtr);
    LOGD("nativeExtractHandle: extracted handle = %d", handle);
    return static_cast<jint>(handle);
}