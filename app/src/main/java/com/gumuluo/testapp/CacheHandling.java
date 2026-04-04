package com.gumuluo.testapp;

import android.content.pm.PackageManager;
import android.os.Parcel;

import java.lang.reflect.Field;
import java.util.Map;

/**
 * 缓存清理工具类
 * 清理PackageManager和Parcel中的各种缓存，确保Hook修改能够立即生效
 * 在修改系统状态后调用，避免缓存导致修改不生效
 */
public class CacheHandling {

    /**
     * 清理所有相关缓存
     * 包括PackageManager的包信息缓存和Parcel的Creator缓存
     * 在修改PackageInfo或ApplicationInfo后必须调用此方法
     */
    public static void clearCaches() {
        clearPackageInfoCache();
        clearSettingsCache();
    }

    /**
     * 清理Settings的缓存
     * 清除Settings.Secure对系统设置的缓存，确保Android ID等修改能够立即生效
     */
    private static void clearSettingsCache() {
        try {
            Class<?> secureClass = android.provider.Settings.Secure.class;
            Field cacheField = findFieldRecursively(secureClass, "sNameValueCache");
            Object cacheInstance = cacheField.get(null);

            if (cacheInstance != null) {
                try {
                    cacheInstance.getClass().getMethod("clear").invoke(cacheInstance);
                } catch (Throwable e) {
                    // 如果 clear 不存在，尝试清除 mValues
                    Field mValuesField = findFieldRecursively(cacheInstance.getClass(), "mValues");
                    Object values = mValuesField.get(cacheInstance);
                    if (values instanceof Map) {
                        ((Map<?, ?>) values).clear();
                    } else if (values != null) {
                        values.getClass().getMethod("clear").invoke(values);
                    }
                }
            }
        } catch (Throwable ignored) {
        }
    }

    /**
     * 清理PackageManager的包信息缓存
     * 清除系统对包信息的缓存，确保下次查询时重新加载修改后的信息
     */
    private static void clearPackageInfoCache() {
        try {
            // 获取PackageManager的sPackageInfoCache字段
            Field cacheField = findFieldRecursively(PackageManager.class, "sApplicationInfoCache");
            Object cacheInstance = cacheField.get(null);

            if (cacheInstance != null) {
                // 调用缓存对象的clear方法清空缓存
                cacheInstance.getClass().getMethod("clear").invoke(cacheInstance);
            }
        } catch (Throwable ignored) {
        }
    }

    /**
     * 递归查找字段
     * 在当前类及其父类中查找指定字段
     *
     * @param targetClass 要查找的起始类
     * @param fieldName 要查找的字段名
     * @return 找到的Field对象
     * @throws NoSuchFieldException 如果字段不存在
     */
    private static Field findFieldRecursively(Class<?> targetClass, String fieldName)
            throws NoSuchFieldException {
        Class<?> currentClass = targetClass;

        // 在当前类及其父类中递归查找字段
        while (currentClass != null && !Object.class.equals(currentClass)) {
            try {
                Field field = currentClass.getDeclaredField(fieldName);
                field.setAccessible(true);
                return field;
            } catch (NoSuchFieldException e) {
                // 在当前类中未找到，继续在父类中查找
                currentClass = currentClass.getSuperclass();
            }
        }

        throw new NoSuchFieldException("字段未找到: " + fieldName);
    }
}
