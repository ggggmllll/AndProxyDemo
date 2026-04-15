//
// Created by lenovo on 2026/3/14.
//

#ifndef LOG_H
#define LOG_H

#include <android/log.h>
#include <sstream>
#include <iomanip>

#define TAG "BinderProxy"

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)

#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// 将字节转换为可打印字符或 '.'
static inline char to_printable(unsigned char c) {
    return std::isprint(static_cast<unsigned char>(c)) ? static_cast<char>(c) : '.';
}

/**
 * 现代 C++ 风格 dump，使用指针 + 长度
 */
inline void dump(const void* ptr, size_t size) {
    if (!ptr || size == 0) {
        LOGD("dump: null pointer or zero size");
        return;
    }

    const auto* data = static_cast<const unsigned char*>(ptr);
    constexpr size_t kBytesPerLine = 16;

    for (size_t offset = 0; offset < size; offset += kBytesPerLine) {
        std::ostringstream line;
        // 偏移量：8位十六进制，右对齐补零
        line << std::hex << std::setfill('0') << std::setw(8) << offset << ":  ";

        // 十六进制部分
        for (size_t i = 0; i < kBytesPerLine; ++i) {
            if (offset + i < size) {
                line << std::hex << std::setw(2)
                     << static_cast<unsigned int>(data[offset + i]) << ' ';
            } else {
                line << "   ";  // 补齐不足16字节的行
            }
            if (i == 7) line << ' ';  // 第8字节后额外空格
        }

        line << ' ';  // 分隔符

        // ASCII 部分
        for (size_t i = 0; i < kBytesPerLine && offset + i < size; ++i) {
            line << to_printable(data[offset + i]);
        }

        LOGD("%s", line.str().c_str());
    }
}

#endif //LOG_H
