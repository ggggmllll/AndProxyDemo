package com.gumuluo.proxy.binder;

import android.annotation.SuppressLint;
import android.os.IBinder;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class BinderProxy {
    static {
        System.loadLibrary("proxy");
    }

    public static void init() {
        nativeInit();
    }

    private static native void nativeInit();

    private static native int nativeExtractHandle(long binder);

    /**
     * 通过服务名获取 Binder handle
     * @param serviceName 例如 "media.player"
     * @return handle 值，失败返回 -1
     */
    public static int getServiceHandle(String serviceName) {
        try {
            @SuppressLint("PrivateApi")
            Class<?> serviceManager = Class.forName("android.os.ServiceManager");
            Method getService = serviceManager.getMethod("getService", String.class);
            IBinder binder = (IBinder) getService.invoke(null, serviceName);
            if (binder == null) {
                return -1;
            }

            Field field = binder.getClass().getDeclaredField("mNativeData");
            field.setAccessible(true);
            long nativePtr = field.getLong(binder);

            if (nativePtr == 0) {
                return -1;
            }

            return nativeExtractHandle(nativePtr);
        } catch (Exception e) {
            return -1;
        }
    }
}
