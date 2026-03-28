#include <jni.h>
#include <malloc.h>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <cerrno>
#include <linux/filter.h>
#include <unistd.h>
#include <fcntl.h>

#include "seccomp_hook.h"
#include "log.h"

// 全局 JVM 引用
static JavaVM *g_jvm = nullptr;

// Java 类和方法 ID
static jclass svcInterceptorClass = nullptr;
static jclass hookRequestClass = nullptr;
static jfieldID hookRequestPtrField = nullptr;
static jclass hookResponseClass = nullptr;
static jfieldID hookResponsePtrField = nullptr;
static jclass callbackClass = nullptr;          // SvcInterceptor.Callback
static jmethodID hookRequestCtor = nullptr;
static jmethodID hookResponseCtor = nullptr;
static jmethodID callbackOnSyscall = nullptr;
static int g_handler_running = -1;

// 父进程线程用于处理子进程请求
static int g_sock_fd = -1;                    // 父进程持有的 socket 端
static pthread_t g_handler_thread;

// 子进程通过此 socket 向父进程发送请求
static int g_child_sock_fd = -1;              // 仅在子进程中使用

// ---------------------------------------------------------------------------
// 辅助函数：通过 socket 发送/接收数据
static int send_all(int fd, const void *buf, size_t len) {
    const char *p = (const char*)buf;
    size_t left = len;
    while (left > 0) {
        ssize_t sent = send(fd, p, left, 0);
        if (sent <= 0) return -1;
        p += sent;
        left -= sent;
    }
    return 0;
}

static int recv_all(int fd, void *buf, size_t len) {
    char *p = (char*)buf;
    size_t left = len;
    while (left > 0) {
        ssize_t r = recv(fd, p, left, 0);
        if (r <= 0) return -1;
        p += r;
        left -= r;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// 全局 C 回调（在 supervisor 子进程中执行）
static void global_java_callback(const hook_request_t *req, hook_response_t *resp, void *userdata) {
    LOGD("supervisor: entering callback");
    // 通过 socket 将请求发送给父进程
    if (g_child_sock_fd < 0) {
        LOGE("global_java_callback: socket not available\n");
        return;
    }

    // 发送请求数据
    LOGD("supervisor: before send_all");
    if (send_all(g_child_sock_fd, req, sizeof(*req)) < 0) {
        LOGE("send req failed\n");
        return;
    }
    LOGD("supervisor: after send_all");

    // 等待响应
    LOGD("supervisor: before recv_all");
    if (recv_all(g_child_sock_fd, resp, sizeof(*resp)) < 0) {
        LOGE("recv resp failed\n");
        return;
    }
    LOGD("supervisor: after recv_all");
}

// ---------------------------------------------------------------------------
// 父进程处理线程：接收子进程请求，调用 Java 回调，发送响应
static void *handler_thread_func(void *arg) {
    int sock_fd = (int)(intptr_t)arg;
    JNIEnv *env;
    g_jvm->AttachCurrentThread(&env, nullptr);

    LOGI("handler_thread_func started, sock_fd=%d", sock_fd);

    // 预先查找类和方法，避免每次调用都查找
    if (!svcInterceptorClass) {
        LOGE("handler thread: failed to find class com/gumuluo/proxy/SvcInterceptor");
        g_jvm->DetachCurrentThread();
        return nullptr;
    }
    jmethodID dispatchMethod = env->GetStaticMethodID(svcInterceptorClass,
                                                         "dispatchCallback",
                                                         "(Lcom/gumuluo/proxy/HookRequest;Lcom/gumuluo/proxy/HookResponse;I)V");
    if (!dispatchMethod) {
        LOGE("handler thread: failed to find method dispatchCallback");
        g_jvm->DetachCurrentThread();
        return nullptr;
    }
    LOGI("handler thread: found dispatchCallback method");

    hook_request_t req;
    hook_response_t resp;

    while (true) {
        //LOGI("handler thread waiting for request...");
        if (recv_all(sock_fd, &req, sizeof(req)) < 0) {
            if (errno == EINTR) continue;
            //LOGE("handler thread: recv_all failed, errno=%d", errno);
            continue;  // 改为 continue，避免线程退出
        }
        LOGI("handler thread received request id=%llu, nr=%d", req.id, req.syscall_nr);

        // 创建 Java 对象
        jobject requestObj = env->NewObject(hookRequestClass, hookRequestCtor, (jlong)&req);
        jobject responseObj = env->NewObject(hookResponseClass, hookResponseCtor, (jlong)&resp);
        if (!requestObj || !responseObj) {
            LOGE("handler thread: failed to create Java objects");
            // 发送默认响应，避免子进程卡死
            memset(&resp, 0, sizeof(resp));
            resp.id = req.id;
            resp.action = HOOK_ACTION_ALLOW;
            if (send_all(sock_fd, &resp, sizeof(resp)) < 0) {
                LOGE("handler thread: send fallback response failed");
            }
            continue;
        }

        // 初始化响应
        memset(&resp, 0, sizeof(resp));
        resp.id = req.id;
        resp.action = HOOK_ACTION_ALLOW;

        // 调用 Java 回调
        LOGI("handler thread: calling dispatchCallback for nr=%d", req.syscall_nr);
        env->CallStaticVoidMethod(svcInterceptorClass, dispatchMethod,
                                     requestObj, responseObj, req.syscall_nr);
        // 检查异常
        if (env->ExceptionCheck()) {
            LOGE("handler thread: Java exception occurred");
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        LOGI("handler thread: dispatchCallback returned");

        LOGI("handler thread: before send response, action=%d, error=%d, val=%lld",
             resp.action, resp.error, (long long)resp.val);

        // 发送响应
        if (send_all(sock_fd, &resp, sizeof(resp)) < 0) {
            LOGE("handler thread: send response failed, errno=%d", errno);
        } else {
            LOGI("handler thread: send response success");
        }

        env->DeleteLocalRef(requestObj);
        env->DeleteLocalRef(responseObj);
    }

    g_jvm->DetachCurrentThread();
    return nullptr;
}

// ---------------------------------------------------------------------------
// JNI_OnLoad

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    g_jvm = vm;
    JNIEnv *env;
    if (vm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK)
        return JNI_ERR;

    svcInterceptorClass = env->FindClass("com/gumuluo/proxy/SvcInterceptor");
    // 查找并缓存 HookRequest 类
    jclass localHookRequest = env->FindClass("com/gumuluo/proxy/HookRequest");
    if (!localHookRequest) return JNI_ERR;
    hookRequestClass = reinterpret_cast<jclass>(env->NewGlobalRef(localHookRequest));
    env->DeleteLocalRef(localHookRequest);

    // 查找并缓存 HookResponse 类
    jclass localHookResponse = env->FindClass("com/gumuluo/proxy/HookResponse");
    if (!localHookResponse) return JNI_ERR;
    hookResponseClass = reinterpret_cast<jclass>(env->NewGlobalRef(localHookResponse));
    env->DeleteLocalRef(localHookResponse);

    // 查找并缓存 Callback 接口（可能不需要，但保留）
    jclass localCallback = env->FindClass("com/gumuluo/proxy/SvcInterceptor$Callback");
    if (!localCallback) return JNI_ERR;
    callbackClass = reinterpret_cast<jclass>(env->NewGlobalRef(localCallback));
    env->DeleteLocalRef(localCallback);

    // 查找并缓存 SvcInterceptor 类
    jclass localSvcInterceptor = env->FindClass("com/gumuluo/proxy/SvcInterceptor");
    if (!localSvcInterceptor) {
        LOGE("JNI_OnLoad: failed to find SvcInterceptor class");
        return JNI_ERR;
    }
    svcInterceptorClass = reinterpret_cast<jclass>(env->NewGlobalRef(localSvcInterceptor));
    env->DeleteLocalRef(localSvcInterceptor);

    // 获取字段 ID
    hookRequestPtrField = env->GetFieldID(hookRequestClass, "nativePtr", "J");
    hookResponsePtrField = env->GetFieldID(hookResponseClass, "nativePtr", "J");

    // 获取构造函数
    hookRequestCtor = env->GetMethodID(hookRequestClass, "<init>", "(J)V");
    hookResponseCtor = env->GetMethodID(hookResponseClass, "<init>", "(J)V");

    // 获取回调方法（Callback 接口中的 onSyscall）
    callbackOnSyscall = env->GetMethodID(callbackClass, "onSyscall",
                                            "(Lcom/gumuluo/proxy/HookRequest;Lcom/gumuluo/proxy/HookResponse;)V");
    return JNI_VERSION_1_6;
}

// ---------------------------------------------------------------------------
// 初始化函数（支持系统调用列表）
extern "C" JNIEXPORT jint JNICALL Java_com_gumuluo_proxy_SvcInterceptor_init
        (JNIEnv *env, jclass clazz, jintArray syscallList) {
    if (syscallList == nullptr) return -1;
    if (g_handler_running > 0) return 0;

    // 1. 解析系统调用号数组（与之前相同）
    jsize len = env->GetArrayLength(syscallList);
    jint *elems = env->GetIntArrayElements(syscallList, nullptr);
    if (!elems) return -1;

    int hasTerm = 0;
    for (int i = 0; i < len; i++) {
        if (elems[i] == -1) { hasTerm = 1; break; }
    }

    int *c_list;
    int list_len;
    if (hasTerm) {
        c_list = (int*)malloc(len * sizeof(int));
        memcpy(c_list, elems, len * sizeof(int));
        list_len = len;
    } else {
        c_list = (int*)malloc((len + 1) * sizeof(int));
        memcpy(c_list, elems, len * sizeof(int));
        c_list[len] = -1;
        list_len = len + 1;
    }
    env->ReleaseIntArrayElements(syscallList, elems, JNI_ABORT);

    int num_entries = list_len - 1;
    auto *entries = (hook_entry_t*)malloc(num_entries * sizeof(hook_entry_t));
    if (!entries) { free(c_list); return -1; }
    for (int i = 0; i < num_entries; i++) {
        entries[i].nr = c_list[i];
        entries[i].callback = global_java_callback;
        entries[i].userdata = nullptr;
    }

    // 2. 创建 socketpair（父子进程通信）
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        LOGE("socketpair failed");
        free(c_list); free(entries);
        return -1;
    }
    g_sock_fd = sv[0];        // 父进程端（用于 handler 线程）
    g_child_sock_fd = sv[1];  // 子进程端（fork 后子进程使用）

    // 3. 启动处理线程（父线程）
    pthread_create(&g_handler_thread, nullptr, handler_thread_func, (void*)(intptr_t)g_sock_fd);
    g_handler_running = 1;

    // 4. 调用库初始化（内部会 fork 子进程）
    int ret = seccomp_hook_init(c_list, nullptr, entries, num_entries, 1);
    free(c_list);
    free(entries);

    if (ret != 0) {
        // 初始化失败，关闭 socket，线程将因 recv 错误而退出
        close(g_sock_fd);
        close(g_child_sock_fd);
        return ret;
    }

    // 5. 父进程关闭子进程端（子进程已有副本）
    close(g_child_sock_fd);
    g_child_sock_fd = -1;

    return 0;
}

// ---------------------------------------------------------------------------
// 压入文件（保持不变）
extern "C" JNIEXPORT jint JNICALL Java_com_gumuluo_proxy_SvcInterceptor_addFile(JNIEnv *env, jclass clazz, jobject request, jstring path) {
    auto *req = (hook_request_t*)env->GetLongField(request, hookRequestPtrField);
    const char *path_str = env->GetStringUTFChars(path, nullptr);
    if (!path_str) return -1;
    int fd = openat(AT_FDCWD, path_str, req->args[2], req->args[3]);
    int ret = seccomp_hook_add_fd(req, fd, 0);
    env->ReleaseStringUTFChars(path, path_str);
    return ret;
}

// ---------------------------------------------------------------------------
// 内存读写（保持不变）
extern "C" JNIEXPORT jlong JNICALL Java_com_gumuluo_proxy_SvcInterceptor_readMemory
        (JNIEnv *env, jclass clazz, jint pid, jlong remoteAddr, jbyteArray buffer, jint offset, jint len) {
    jbyte *buf = env->GetByteArrayElements(buffer, nullptr);
    if (!buf) return -1;
    ssize_t ret = seccomp_hook_read_mem(pid, (const void*)remoteAddr, buf + offset, len);
    env->ReleaseByteArrayElements(buffer, buf, 0);
    return (jlong)ret;
}

extern "C" JNIEXPORT jlong JNICALL Java_com_gumuluo_proxy_SvcInterceptor_writeMemory
        (JNIEnv *env, jclass clazz, jint pid, jlong remoteAddr, jbyteArray buffer, jint offset, jint len) {
    jbyte *buf = env->GetByteArrayElements(buffer, nullptr);
    if (!buf) return -1;
    ssize_t ret = seccomp_hook_write_mem(pid, (void*)remoteAddr, buf + offset, len);
    env->ReleaseByteArrayElements(buffer, buf, JNI_ABORT);
    return (jlong)ret;
}

// ---------------------------------------------------------------------------
// HookRequest 的 native 方法（保持不变）
extern "C" JNIEXPORT jint JNICALL Java_com_gumuluo_proxy_HookRequest_getSyscallNr
        (JNIEnv *env, jobject obj) {
    jlong ptr = env->GetLongField(obj, hookRequestPtrField);
    auto *req = (hook_request_t*)ptr;
    return req->syscall_nr;
}

extern "C" JNIEXPORT jint JNICALL Java_com_gumuluo_proxy_HookRequest_getPid
        (JNIEnv *env, jobject obj) {
    jlong ptr = env->GetLongField(obj, hookRequestPtrField);
    auto *req = (hook_request_t*)ptr;
    return req->pid;
}

extern "C" JNIEXPORT jlong JNICALL Java_com_gumuluo_proxy_HookRequest_getArg
        (JNIEnv *env, jobject obj, jint index) {
    if (index < 0 || index >= 6) return 0;
    jlong ptr = env->GetLongField(obj, hookRequestPtrField);
    auto *req = (hook_request_t*)ptr;
    return (jlong)req->args[index];
}

extern "C" JNIEXPORT jlong JNICALL Java_com_gumuluo_proxy_HookRequest_getRegX
        (JNIEnv *env, jobject obj, jint index) {
    if (index < 0 || index >= 31) return 0;
    jlong ptr = env->GetLongField(obj, hookRequestPtrField);
    auto *req = (hook_request_t*)ptr;
    return (jlong)req->regs.x[index];
}

extern "C" JNIEXPORT jlong JNICALL Java_com_gumuluo_proxy_HookRequest_getSp
        (JNIEnv *env, jobject obj) {
    jlong ptr = env->GetLongField(obj, hookRequestPtrField);
    auto *req = (hook_request_t*)ptr;
    return (jlong)req->regs.sp;
}

extern "C" JNIEXPORT jlong JNICALL Java_com_gumuluo_proxy_HookRequest_getPc
        (JNIEnv *env, jobject obj) {
    jlong ptr = env->GetLongField(obj, hookRequestPtrField);
    auto *req = (hook_request_t*)ptr;
    return (jlong)req->regs.pc;
}

extern "C" JNIEXPORT jlong JNICALL Java_com_gumuluo_proxy_HookRequest_getPstate
        (JNIEnv *env, jobject obj) {
    jlong ptr = env->GetLongField(obj, hookRequestPtrField);
    auto *req = (hook_request_t*)ptr;
    return (jlong)req->regs.pstate;
}

// ---------------------------------------------------------------------------
// HookResponse 的 native 方法（保持不变）
extern "C" JNIEXPORT void JNICALL Java_com_gumuluo_proxy_HookResponse_setAction
        (JNIEnv *env, jobject obj, jint action) {
    jlong ptr = env->GetLongField(obj, hookResponsePtrField);
    auto *resp = (hook_response_t*)ptr;
    resp->action = static_cast<hook_action_t>(action);
}

extern "C" JNIEXPORT void JNICALL Java_com_gumuluo_proxy_HookResponse_setError
        (JNIEnv *env, jobject obj, jint error) {
    jlong ptr = env->GetLongField(obj, hookResponsePtrField);
    auto *resp = (hook_response_t*)ptr;
    resp->error = -error;
}

extern "C" JNIEXPORT void JNICALL Java_com_gumuluo_proxy_HookResponse_setVal
        (JNIEnv *env, jobject obj, jlong val) {
    jlong ptr = env->GetLongField(obj, hookResponsePtrField);
    auto *resp = (hook_response_t*)ptr;
    resp->val = val;
}
