package com.gumuluo.proxy;

import java.util.HashMap;
import java.util.Map;

public class SvcInterceptor {
    static {
        System.loadLibrary("proxy");
    }

    public static final int ACTION_ALLOW = 0;
    public static final int ACTION_DENY = 1;
    public static final int ACTION_MODIFY = 2;

    // 管理回调的映射
    private static final Map<Integer, Callback> callbacks = new HashMap<>();

    public static native int init(int[] syscallList);
    public static native long readMemory(int pid, long remoteAddr, byte[] buffer, int offset, int len);
    public static native long writeMemory(int pid, long remoteAddr, byte[] buffer, int offset, int len);
    public static native int addFile(HookRequest request, String path);

    // 注册钩子（Java 层实现）
    public static void registerHook(int syscallNr, Callback callback) {
        synchronized (callbacks) {
            callbacks.put(syscallNr, callback);
        }
    }

    public static void unregisterHook(int syscallNr) {
        synchronized (callbacks) {
            callbacks.remove(syscallNr);
        }
    }

    // 由 native 层调用的分发方法
    private static void dispatchCallback(HookRequest request, HookResponse response, int syscallNr) {
        Callback cb;
        synchronized (callbacks) {
            cb = callbacks.get(syscallNr);
        }
        if (cb != null) {
            cb.onSyscall(request, response);
        }
    }

    public interface Callback {
        void onSyscall(HookRequest request, HookResponse response);
    }
}