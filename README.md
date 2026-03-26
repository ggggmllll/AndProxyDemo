[中文](README.md) | [English](README_en.md)

# AndProxy – Android Binder 与系统调用拦截库

AndProxy 是一款 Android 底层拦截库，通过 **GOT Hook** 劫持 `libbinder.so` 中的 `ioctl` 调用，实现对 Binder 事务的拦截与修改；同时基于 **Seccomp** 用户态通知机制拦截指定系统调用，并在 Java 层提供统一的回调接口。该库适用于安全研究、隐私保护、自动化测试等场景。

---

## ✨ 特性

- **Binder 事务拦截**  
  - Hook `libbinder.so` 的 `ioctl`，捕获所有 Binder 读写操作  
  - 解析 `BR_TRANSACTION` / `BC_TRANSACTION` 等命令，自动提取服务名和方法名  
  - 支持在请求前（`before`）和回复后（`after`）注入 Java 回调，可修改事务数据  

- **系统调用拦截**  
  - 利用 **Seccomp** 用户态通知，拦截任意系统调用  
  - 通过 `process_vm_readv` / `process_vm_writev` 安全读写目标进程内存  
  - Java 回调可获取完整寄存器上下文、参数，并修改返回值或设置错误码  

- **简洁的 Java API**  
  - 无需理解底层 Binder 协议或 Seccomp 细节  
  - 自动将 Parcel 数据转换为 Java 对象，便于修改  

- **兼容性**  
  - 仅支持 **ARM64** 架构  
  - 需要 **Linux 内核 ≥ 5.10**（Seccomp 通知机制）  

---

## 📦 依赖

- Android SDK / NDK (NDK r25+，CMake 3.22+)  
- [GlossHook](https://github.com/XMDS/GlossHook) – 用于 GOT 表劫持  

---

## 🔧 使用指南

### 1. 初始化拦截器

在应用启动时（如 `Application.onCreate()`）调用：

```java
// 初始化 Binder 拦截
BinderProxy.init();

// 初始化系统调用拦截，传入需要拦截的系统调用号数组（以 -1 结尾）
int[] syscalls = new int[]{ __NR_openat, __NR_write, -1 };
SvcInterceptor.init(syscalls);
```

---

### 2. Binder 事务拦截示例

以下示例演示如何修改 `IPackageManager.getApplicationInfo` 返回的 `ApplicationInfo`，清除其中的 `DEBUGGABLE` 标志，实现“隐藏应用可调试状态”。

```java
// 注册 after 回调（在服务端返回数据后执行）
BinderDispatcher.registerAfter(
    "android.content.pm.IPackageManager",  // 服务接口名
    "getApplicationInfo",                  // 方法名
    new BinderInterceptor() {
        @Override
        public boolean onTransaction(Parcel data, Parcel outReply) {
            // 跳过服务端写入的异常信息（通常为 writeNoException）
            data.readException();

            // 读取原始 ApplicationInfo
            ApplicationInfo originalInfo = data.readTypedObject(ApplicationInfo.CREATOR);
            if (originalInfo == null) return false;

            // 修改 flags，移除 DEBUGGABLE 标志
            originalInfo.flags &= ~ApplicationInfo.FLAG_DEBUGGABLE;

            // 构造新的 outReply
            outReply.setDataPosition(0);
            outReply.writeNoException();
            outReply.writeTypedObject(originalInfo, 0);

            return true;  // 表示用 outReply 替换原始数据
        }
    }
);
```

**注销回调**：

```java
BinderDispatcher.unregisterAfter("android.content.pm.IPackageManager", "getApplicationInfo");
```

---

### 3. 系统调用拦截示例

以下示例拦截 `getpid` 系统调用，演示如何允许、拒绝或修改返回值。

```java
public class SvcInterceptorTest {
    private static final int SYS_GETPID = 172; // ARM64 getpid 系统调用号

    @Test
    public void testInterceptGetPid() throws Exception {
        int[] syscalls = new int[]{ SYS_GETPID, -1 };
        SvcInterceptor.init(syscalls);

        // 注册回调，仅打印日志并放行
        SvcInterceptor.registerHook(SYS_GETPID, new SvcInterceptor.Callback() {
            @Override
            public void onSyscall(HookRequest request, HookResponse response) {
                System.out.println("getpid called, pid=" + request.getPid());
                response.setAction(SvcInterceptor.ACTION_ALLOW);
            }
        });

        int pid = getpid();  // 原生方法，内部执行 syscall(SYS_GETPID)
        System.out.println("pid=" + pid);

        SvcInterceptor.unregisterHook(SYS_GETPID);
    }

    @Test
    public void testDenySyscall() throws Exception {
        int[] syscalls = new int[]{ SYS_GETPID, -1 };
        SvcInterceptor.init(syscalls);

        SvcInterceptor.registerHook(SYS_GETPID, new SvcInterceptor.Callback() {
            @Override
            public void onSyscall(HookRequest request, HookResponse response) {
                response.setAction(SvcInterceptor.ACTION_DENY);
                response.setError(EPERM);  // 返回权限错误
            }
        });

        int pid = getpid();
        assertEquals(-1, pid);  // 调用被拒绝，返回 -1
    }

    @Test
    public void testModifyReturnValue() throws Exception {
        int[] syscalls = new int[]{ SYS_GETPID, -1 };
        SvcInterceptor.init(syscalls);

        SvcInterceptor.registerHook(SYS_GETPID, new SvcInterceptor.Callback() {
            @Override
            public void onSyscall(HookRequest request, HookResponse response) {
                response.setAction(SvcInterceptor.ACTION_MODIFY);
                response.setVal(12345L);  // 强制返回 12345
            }
        });

        int pid = getpid();
        assertEquals(12345, pid);
    }

    private native int getpid();  // 通过 JNI 直接调用 syscall
}
```

**关键点说明**：

- `ACTION_ALLOW`：正常执行系统调用，不做修改。  
- `ACTION_DENY`：拒绝调用，设置错误码（如 `EPERM`）。  
- `ACTION_MODIFY`：修改返回值，通过 `setVal` 指定新的返回值。  

---

## 📚 API 参考

### Java API

#### Binder 拦截相关

| 类/接口 | 方法 | 说明 |
|---------|------|------|
| `BinderProxy` | `static void init()` | 初始化 Binder 拦截器（必须在应用启动时调用） |
| `BinderDispatcher` | `static void registerBefore(String serviceName, String methodName, BinderInterceptor interceptor)`<br>`static void registerAfter(...)`<br>`static void unregisterBefore(...)`<br>`static void unregisterAfter(...)` | 注册/注销 Binder 事务回调。<br>`serviceName`：服务接口名，如 `"android.content.pm.IPackageManager"`。<br>`methodName`：方法名，如 `"getApplicationInfo"`。<br>`interceptor`：实现 `onTransaction` 方法的回调。 |
| `BinderInterceptor` | `boolean onTransaction(Parcel data, Parcel outReply)` | 回调方法：<br>- `data`：原始事务数据（可读）<br>- `outReply`：用于构造新数据的 Parcel<br>- 返回 `true` 表示使用 `outReply` 替换原数据；返回 `false` 表示不修改。 |

#### 系统调用拦截相关

| 类/接口 | 方法 | 说明 |
|---------|------|------|
| `SvcInterceptor` | `static int init(int[] syscallList)` | 初始化系统调用拦截器，`syscallList` 为以 `-1` 结尾的系统调用号数组。返回 `0` 表示成功。 |
| | `static void registerHook(int syscallNr, Callback callback)` | 注册指定系统调用的回调。 |
| | `static void unregisterHook(int syscallNr)` | 注销指定系统调用的回调。 |
| | `static long readMemory(int pid, long remoteAddr, byte[] buffer, int offset, int len)` | 从目标进程读取内存（基于 `process_vm_readv`）。 |
| | `static long writeMemory(int pid, long remoteAddr, byte[] buffer, int offset, int len)` | 向目标进程写入内存（基于 `process_vm_writev`）。 |
| `SvcInterceptor.Callback` | `void onSyscall(HookRequest request, HookResponse response)` | 回调方法，参数 `request` 和 `response` 分别用于获取请求信息和设置响应。 |
| `HookRequest` | `int getSyscallNr()`<br>`int getPid()`<br>`long getArg(int index)`<br>`long getRegX(int index)`<br>`long getSp()`<br>`long getPc()`<br>`long getPstate()` | 获取系统调用号、调用进程 PID、参数（0~5）、寄存器值（x0~x30）、栈指针、程序计数器、处理器状态。 |
| `HookResponse` | `void setAction(int action)`<br>`void setError(int error)`<br>`void setVal(long val)` | 设置动作（`ACTION_ALLOW`/`ACTION_DENY`/`ACTION_MODIFY`）、错误码（仅在 `DENY` 时有效）、修改的返回值（仅在 `MODIFY` 时有效）。 |

#### 常量

| 类 | 常量 | 值 | 说明 |
|----|------|-----|------|
| `SvcInterceptor` | `ACTION_ALLOW` | 0 | 正常执行系统调用 |
| | `ACTION_DENY` | 1 | 拒绝调用，返回错误码 |
| | `ACTION_MODIFY` | 2 | 修改返回值 |

---

### C API

C 接口定义在以下头文件中，供 Native 代码直接使用。

#### `seccomp_hook.h` – Seccomp 钩子框架

| 函数 | 说明 |
|------|------|
| `int seccomp_hook_init(const int *syscall_list, const struct sock_fprog *custom_filter, const hook_entry_t *entries, int num_entries, int use_signal)` | 初始化 Seccomp 钩子，fork 出 supervisor 子进程，并安装 BPF 过滤器。 |
| `int seccomp_hook_register_remote(const int *syscall_list, const struct sock_fprog *custom_filter, hook_callback_t callback, void *userdata)` | 父进程远程注册钩子，通知 supervisor 子进程添加回调。 |
| `int seccomp_hook_unregister_remote(const int *syscall_list, hook_callback_t callback, void *userdata)` | 远程注销钩子。 |
| `ssize_t seccomp_hook_read_mem(pid_t pid, const void *remote_addr, void *local_buf, size_t len)`<br>`ssize_t seccomp_hook_write_mem(pid_t pid, void *remote_addr, const void *local_buf, size_t len)` | 安全读写目标进程内存（基于 `process_vm_readv`/`writev`）。 |
| `int seccomp_hook_add_fd(const hook_request_t *req, int srcfd, __u32 newfd_flags)` | 在 supervisor 中为目标进程添加文件描述符（用于模拟打开文件）。 |

**回调原型**：`typedef void (*hook_callback_t)(const hook_request_t *req, hook_response_t *resp, void *userdata);`

---

#### `BinderHook.h` – Binder Hook 核心类（C++）

| 类/方法 | 说明 |
|---------|------|
| `class BinderHook` | 单例类，管理 Binder 拦截。 |
| `static BinderHook& instance()` | 获取单例实例。 |
| `void init(JavaVM* vm)` | 初始化 GOT Hook，查找 `libbinder.so` 中 `ioctl` 的 GOT 条目并替换为代理函数。 |
| `void registerCallback(const std::string& serviceName, const std::string& methodName, bool isBefore, BinderNativeCallback callback)`<br>`void unregisterCallback(...)` | 注册/注销原生回调。回调类型为 `std::function<bool(binder_transaction_data*, bool, uint8_t**, size_t*, uint8_t**, binder_size_t*)>`。 |

---

## 📄 许可证

本项目基于 **GPL 2.0** 许可证开源，详情请参阅 [LICENSE](LICENSE) 文件。

---

## 🙏 致谢

- GOT Hook 实现基于 [GlossHook](https://github.com/XMDS/GlossHook)  
- Seccomp 通知机制参考 Linux 内核文档及 [Android 源码](https://cs.android.com/)  

---

## 📧 联系方式

如有问题或建议，欢迎提交 Issue 或联系 <1359640178@qq.com>。
