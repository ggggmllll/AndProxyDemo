[中文](README.md) | [English](README_en.md)

# AndProxy – Android Binder & Syscall Interception Library

AndProxy is a low‑level interception library for Android that hooks `ioctl` in `libbinder.so` via **GOT patching** to monitor and modify Binder transactions. It also uses **Seccomp** user‑space notifications to intercept arbitrary system calls and provides a unified Java callback interface. The library is suitable for security research, privacy protection, automated testing, and similar use cases.

---

## ✨ Features

- **Binder Transaction Interception**  
  - Hooks `ioctl` in `libbinder.so` to capture all Binder reads/writes  
  - Parses `BR_TRANSACTION` / `BC_TRANSACTION` commands and automatically extracts service and method names  
  - Supports registering **before** (request) and **after** (reply) callbacks in Java to modify transaction data  

- **Syscall Interception**  
  - Leverages **Seccomp** user‑space notifications to intercept any system call  
  - Safely reads/writes target process memory via `process_vm_readv` / `process_vm_writev`  
  - Java callbacks receive full register context and arguments, and can modify return values or set error codes  

- **Simple Java API**  
  - No need to understand low‑level Binder protocol or Seccomp details  
  - Parcel data is automatically converted to Java objects for easy modification  

- **Compatibility**  
  - Supports **ARM64** only  
  - Requires **Linux kernel ≥ 5.10** (Seccomp notification mechanism)  

---

## 📦 Dependencies

- Android SDK / NDK (NDK r25+, CMake 3.22+)  
- [GlossHook](https://github.com/XMDS/GlossHook) – used for GOT patching  

---

## 🔧 Usage Guide

### 1. Initialize the Interceptors

Call the following in your `Application.onCreate()`:

```java
// Initialize Binder interception
BinderProxy.init();

// Initialize syscall interception with an array of syscall numbers (terminated by -1)
int[] syscalls = new int[]{ __NR_openat, __NR_write, -1 };
SvcInterceptor.init(syscalls);
```

---

### 2. Binder Transaction Interception Example

The following example shows how to modify the `ApplicationInfo` returned by `IPackageManager.getApplicationInfo` to clear the `DEBUGGABLE` flag, effectively hiding the debuggable state of the app.

```java
// Register an after callback (executed after the service returns data)
BinderDispatcher.registerAfter(
    "android.content.pm.IPackageManager",  // service interface name
    "getApplicationInfo",                  // method name
    new BinderInterceptor() {
        @Override
        public boolean onTransaction(Parcel data, Parcel outReply) {
            // Skip the exception information written by the service (usually writeNoException)
            data.readException();

            // Read the original ApplicationInfo
            ApplicationInfo originalInfo = data.readTypedObject(ApplicationInfo.CREATOR);
            if (originalInfo == null) return false;

            // Modify the flags to remove the DEBUGGABLE flag
            originalInfo.flags &= ~ApplicationInfo.FLAG_DEBUGGABLE;

            // Build the new outReply
            outReply.setDataPosition(0);
            outReply.writeNoException();
            outReply.writeTypedObject(originalInfo, 0);

            return true;  // Tell the framework to replace the original data with outReply
        }
    }
);
```

**Unregistering the callback**:

```java
BinderDispatcher.unregisterAfter("android.content.pm.IPackageManager", "getApplicationInfo");
```

---

### 3. Syscall Interception Example

The following example intercepts the `getpid` syscall and demonstrates how to allow, deny, or modify the return value.

```java
public class SvcInterceptorTest {
    private static final int SYS_GETPID = 172; // ARM64 getpid syscall number

    @Test
    public void testInterceptGetPid() throws Exception {
        int[] syscalls = new int[]{ SYS_GETPID, -1 };
        SvcInterceptor.init(syscalls);

        // Register a callback that just logs and allows the call
        SvcInterceptor.registerHook(SYS_GETPID, new SvcInterceptor.Callback() {
            @Override
            public void onSyscall(HookRequest request, HookResponse response) {
                System.out.println("getpid called, pid=" + request.getPid());
                response.setAction(SvcInterceptor.ACTION_ALLOW);
            }
        });

        int pid = getpid();  // native method that executes syscall(SYS_GETPID)
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
                response.setError(EPERM);  // return permission error
            }
        });

        int pid = getpid();
        assertEquals(-1, pid);  // the call is denied, returns -1
    }

    @Test
    public void testModifyReturnValue() throws Exception {
        int[] syscalls = new int[]{ SYS_GETPID, -1 };
        SvcInterceptor.init(syscalls);

        SvcInterceptor.registerHook(SYS_GETPID, new SvcInterceptor.Callback() {
            @Override
            public void onSyscall(HookRequest request, HookResponse response) {
                response.setAction(SvcInterceptor.ACTION_MODIFY);
                response.setVal(12345L);  // force return 12345
            }
        });

        int pid = getpid();
        assertEquals(12345, pid);
    }

    private native int getpid();  // JNI wrapper that directly invokes the syscall
}
```

**Key actions**:

- `ACTION_ALLOW`: Execute the syscall normally, no modification.  
- `ACTION_DENY`: Reject the syscall, set an error code (e.g., `EPERM`).  
- `ACTION_MODIFY`: Modify the return value via `setVal`.

---

## 📚 API Reference

### Java API

#### Binder Interception

| Class / Interface | Method | Description |
|-------------------|--------|-------------|
| `BinderProxy` | `static void init()` | Initialize the Binder interceptor (must be called early in the app). |
| `BinderDispatcher` | `static void registerBefore(String serviceName, String methodName, BinderInterceptor interceptor)`<br>`static void registerAfter(...)`<br>`static void unregisterBefore(...)`<br>`static void unregisterAfter(...)` | Register/unregister Binder transaction callbacks.<br>`serviceName`: service interface name, e.g., `"android.content.pm.IPackageManager"`.<br>`methodName`: method name, e.g., `"getApplicationInfo"`.<br>`interceptor`: callback implementing `onTransaction`. |
| `BinderInterceptor` | `boolean onTransaction(Parcel data, Parcel outReply)` | Callback method:<br>- `data`: original transaction data (readable)<br>- `outReply`: Parcel used to construct new data<br>- Return `true` to replace original data with `outReply`; `false` to leave unchanged. |

#### Syscall Interception

| Class / Interface | Method | Description |
|-------------------|--------|-------------|
| `SvcInterceptor` | `static int init(int[] syscallList)` | Initialize the syscall interceptor. `syscallList` must be terminated with `-1`. Returns `0` on success. |
| | `static void registerHook(int syscallNr, Callback callback)` | Register a callback for a specific syscall number. |
| | `static void unregisterHook(int syscallNr)` | Unregister the callback for the given syscall number. |
| | `static long readMemory(int pid, long remoteAddr, byte[] buffer, int offset, int len)` | Read memory from a target process (based on `process_vm_readv`). |
| | `static long writeMemory(int pid, long remoteAddr, byte[] buffer, int offset, int len)` | Write memory to a target process (based on `process_vm_writev`). |
| `SvcInterceptor.Callback` | `void onSyscall(HookRequest request, HookResponse response)` | Callback method. `request` provides the syscall information, `response` is used to set the action. |
| `HookRequest` | `int getSyscallNr()`<br>`int getPid()`<br>`long getArg(int index)`<br>`long getRegX(int index)`<br>`long getSp()`<br>`long getPc()`<br>`long getPstate()` | Get syscall number, PID of the calling process, arguments (0‑5), register values (x0‑x30), stack pointer, program counter, and processor state. |
| `HookResponse` | `void setAction(int action)`<br>`void setError(int error)`<br>`void setVal(long val)` | Set the action (`ACTION_ALLOW`/`ACTION_DENY`/`ACTION_MODIFY`), error code (only valid for `DENY`), or modified return value (only valid for `MODIFY`). |

#### Constants

| Class | Constant | Value | Description |
|-------|----------|-------|-------------|
| `SvcInterceptor` | `ACTION_ALLOW` | 0 | Normal execution of the syscall |
| | `ACTION_DENY` | 1 | Deny the syscall, returning an error code |
| | `ACTION_MODIFY` | 2 | Override the return value |

---

### C API

The C interfaces are defined in the following headers for direct use in native code.

#### `seccomp_hook.h` – Seccomp Hook Framework

| Function | Description |
|----------|-------------|
| `int seccomp_hook_init(const int *syscall_list, const struct sock_fprog *custom_filter, const hook_entry_t *entries, int num_entries, int use_signal)` | Initialize the Seccomp hook, fork the supervisor child process, and install the BPF filter. |
| `int seccomp_hook_register_remote(const int *syscall_list, const struct sock_fprog *custom_filter, hook_callback_t callback, void *userdata)` | Register a hook remotely from the parent process, notifying the supervisor child to add a callback. |
| `int seccomp_hook_unregister_remote(const int *syscall_list, hook_callback_t callback, void *userdata)` | Unregister a hook remotely. |
| `ssize_t seccomp_hook_read_mem(pid_t pid, const void *remote_addr, void *local_buf, size_t len)`<br>`ssize_t seccomp_hook_write_mem(pid_t pid, void *remote_addr, const void *local_buf, size_t len)` | Safely read/write memory of a target process (based on `process_vm_readv`/`writev`). |
| `int seccomp_hook_add_fd(const hook_request_t *req, int srcfd, __u32 newfd_flags)` | Add a file descriptor for the target process inside the supervisor (e.g., to emulate opening a file). |

**Callback prototype**: `typedef void (*hook_callback_t)(const hook_request_t *req, hook_response_t *resp, void *userdata);`

---

#### `BinderHook.h` – Binder Hook Core (C++)

| Class / Method | Description |
|----------------|-------------|
| `class BinderHook` | Singleton class that manages Binder interception. |
| `static BinderHook& instance()` | Get the singleton instance. |
| `void init(JavaVM* vm)` | Initialize the GOT hook, find the GOT entry for `ioctl` in `libbinder.so`, and replace it with the proxy function. |
| `void registerCallback(const std::string& serviceName, const std::string& methodName, bool isBefore, BinderNativeCallback callback)`<br>`void unregisterCallback(...)` | Register/unregister a native callback. The callback type is `std::function<bool(binder_transaction_data*, bool, uint8_t**, size_t*, uint8_t**, binder_size_t*)>`. |

---

## 📄 License

This project is open‑sourced under the **GPL 2.0** license. See the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- GOT hook implementation based on [GlossHook](https://github.com/XMDS/GlossHook)  
- Seccomp notification mechanism inspired by Linux kernel documentation and [Android source code](https://cs.android.com/)

---

## 📧 Contact

If you have any questions or suggestions, please open an issue or contact <1359640178@qq.com>.
