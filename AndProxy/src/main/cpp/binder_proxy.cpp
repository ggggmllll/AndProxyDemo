#include <cctype>
#include <cstring>
#include <map>
#include <string>
#include <vector>
#include <malloc.h>
#include <android/api-level.h>
#include "binder_proxy.h"
#include "log.h"

size_t get_cmd_data_size(uint32_t cmd, int is_read) {
    if (is_read) {
        // BR_* 命令
        switch (cmd) {
            case BR_ERROR:
            case BR_ACQUIRE_RESULT:
                return sizeof(__s32);
            case BR_TRANSACTION:
            case BR_REPLY:
                return sizeof(struct binder_transaction_data);
            case BR_TRANSACTION_SEC_CTX:
                return sizeof(struct binder_transaction_data_secctx);
            case BR_INCREFS:
            case BR_ACQUIRE:
            case BR_RELEASE:
            case BR_DECREFS:
                return sizeof(struct binder_ptr_cookie);
            case BR_ATTEMPT_ACQUIRE:
                return sizeof(struct binder_pri_ptr_cookie);
            case BR_DEAD_BINDER:
            case BR_CLEAR_DEATH_NOTIFICATION_DONE:
                return sizeof(binder_uintptr_t);
            default:
                // BR_OK, BR_NOOP, BR_TRANSACTION_COMPLETE, BR_DEAD_REPLY,
                // BR_FAILED_REPLY, BR_SPAWN_LOOPER 等无数据
                return 0;
        }
    } else {
        // BC_* 命令
        switch (cmd) {
            case BC_TRANSACTION:
            case BC_REPLY:
                return sizeof(struct binder_transaction_data);
            case BC_TRANSACTION_SG:
            case BC_REPLY_SG:
                return sizeof(struct binder_transaction_data_sg);
            case BC_FREE_BUFFER:
            case BC_DEAD_BINDER_DONE:
                return sizeof(binder_uintptr_t);
            case BC_INCREFS:
            case BC_ACQUIRE:
            case BC_RELEASE:
            case BC_DECREFS:
                return sizeof(__u32);
            case BC_INCREFS_DONE:
            case BC_ACQUIRE_DONE:
                return sizeof(struct binder_ptr_cookie);
            case BC_ATTEMPT_ACQUIRE:
                return sizeof(struct binder_pri_desc);
            case BC_REQUEST_DEATH_NOTIFICATION:
            case BC_CLEAR_DEATH_NOTIFICATION:
                return sizeof(struct binder_handle_cookie);
            default:
                // BC_REGISTER_LOOPER, BC_ENTER_LOOPER, BC_EXIT_LOOPER 无数据
                return 0;
        }
    }
}

//binder_transaction_data* parse_next_txn(void*& ptr, size_t& remaining, int is_read) {
//    if (ptr == nullptr || remaining < sizeof(uint32_t))
//        return nullptr;
//
//    uint32_t cmd = *reinterpret_cast<uint32_t*>(ptr);
//    size_t data_len = get_cmd_data_size(cmd, is_read);
//
//    // 检查剩余空间是否足够容纳命令头 + 数据
//    if (remaining < sizeof(uint32_t) + data_len)
//        return nullptr;
//
//    // 跳过命令码
//    ptr = static_cast<char*>(ptr) + sizeof(uint32_t);
//    remaining -= sizeof(uint32_t);
//
//    if (is_read) {
//        // 读取缓冲区命令 (BR_*)
//        switch (cmd) {
//            case BR_TRANSACTION: {
//                auto* tr = reinterpret_cast<binder_transaction_data*>(ptr);
//                ptr = static_cast<char*>(ptr) + data_len;
//                remaining -= data_len;
//                return tr;
//            }
//            case BR_TRANSACTION_SEC_CTX: {
//                auto* sec = reinterpret_cast<binder_transaction_data_secctx*>(ptr);
//                auto* tr = &sec->transaction_data;
//                ptr = static_cast<char*>(ptr) + data_len;
//                remaining -= data_len;
//                return tr;
//            }
//            case BR_REPLY: {
//                auto* tr = reinterpret_cast<binder_transaction_data*>(ptr);
//                ptr = static_cast<char*>(ptr) + data_len;
//                remaining -= data_len;
//                return tr;
//            }
//            default:
//                // 非事务命令：跳过数据部分
//                ptr = static_cast<char*>(ptr) + data_len;
//                remaining -= data_len;
//                return nullptr;
//        }
//    } else {
//        // 写入缓冲区命令 (BC_*)
//        switch (cmd) {
//            case BC_TRANSACTION:
//            case BC_REPLY: {
//                auto* tr = reinterpret_cast<binder_transaction_data*>(ptr);
//                ptr = static_cast<char*>(ptr) + data_len;
//                remaining -= data_len;
//                return tr;
//            }
//            case BC_TRANSACTION_SG:
//            case BC_REPLY_SG: {
//                auto* tr_sg = reinterpret_cast<binder_transaction_data_sg*>(ptr);
//                auto* tr = &tr_sg->transaction_data;
//                ptr = static_cast<char*>(ptr) + data_len;
//                remaining -= data_len;
//                return tr;
//            }
//            default:
//                // 非事务命令：跳过数据部分
//                ptr = static_cast<char*>(ptr) + data_len;
//                remaining -= data_len;
//                return nullptr;
//        }
//    }
//}


static const std::map<std::string, std::map<int, std::string>> special_maps = {
        {
                "android/content/IContentProvider",
                {
                        {1, "query"}, {2, "getType"}, {3, "insert"}, {4, "delete"},
                        {10, "update"}, {13, "bulkInsert"}, {14, "openFile"}, {15, "openAssetFile"},
                        {20, "applyBatch"}, {21, "call"}, {22, "getStreamTypes"}, {23, "openTypedAssetFile"},
                        {24, "createCancellationSignal"}, {25, "canonicalize"}, {26, "uncanonicalize"},
                        {27, "refresh"}, {28, "checkUriPermission"}, {29, "getTypeAsync"},
                        {30, "canonicalizeAsync"}, {31, "uncanonicalizeAsync"}, {32, "getTypeAnonymousAsync"}
                }
        }
        // 可继续添加其他服务
};

std::string get_transaction_name(JNIEnv* env, const char* class_name, int code) {
    // 类名合法性检查
    auto is_valid_class_name = [](const char* name) -> bool {
        if (!name || *name == '\0') return false;
        for (const char* p = name; *p; ++p) {
            unsigned char ch = *p;
            if (ch <= 0x20 || ch == ':' || ch == ';' || ch == '[' || ch == '(' || ch == ')')
                return false;
            if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                  (ch >= '0' && ch <= '9') || ch == '/' || ch == '$' || ch == '_'))
                return false;
        }
        return true;
    };

    if (!is_valid_class_name(class_name)) return {};

    auto it_special = special_maps.find(class_name);
    if (it_special != special_maps.end()) {
        auto it_code = it_special->second.find(code);
        if (it_code != it_special->second.end()) {
            LOGD("Special map hit: %s -> %s (code %d)", class_name, it_code->second.c_str(), code);
            return it_code->second;
        }
    }

    // ---------- 通用反射查找（原有逻辑，无验证） ----------
    jclass targetClass = env->FindClass(class_name);
    if (targetClass == nullptr) {
        env->ExceptionClear();
        return {};
    }

    jclass classClass = env->FindClass("java/lang/Class");
    jmethodID getDeclaredFields = env->GetMethodID(classClass, "getDeclaredFields", "()[Ljava/lang/reflect/Field;");
    jobjectArray fields = (jobjectArray)env->CallObjectMethod(targetClass, getDeclaredFields);
    env->DeleteLocalRef(classClass);
    if (fields == nullptr) {
        env->DeleteLocalRef(targetClass);
        return {};
    }

    std::string result;
    jsize len = env->GetArrayLength(fields);
    for (jsize i = 0; i < len; ++i) {
        jobject field = env->GetObjectArrayElement(fields, i);
        if (!field) continue;

        jclass fieldClass = env->GetObjectClass(field);
        jmethodID getName = env->GetMethodID(fieldClass, "getName", "()Ljava/lang/String;");
        jstring nameStr = (jstring)env->CallObjectMethod(field, getName);
        env->DeleteLocalRef(fieldClass);
        if (!nameStr) {
            env->DeleteLocalRef(field);
            continue;
        }

        const char* name = env->GetStringUTFChars(nameStr, nullptr);
        if (!name) {
            env->DeleteLocalRef(nameStr);
            env->DeleteLocalRef(field);
            continue;
        }

        size_t nameLen = strlen(name);
        // 匹配 "TRANSACTION_xxx"
        const char* prefix = "TRANSACTION_";
        if (nameLen > 12 && strncmp(name, prefix, 12) == 0) {
            jfieldID fieldID = env->GetStaticFieldID(targetClass, name, "I");
            if (fieldID) {
                jint value = env->GetStaticIntField(targetClass, fieldID);
                if (value == code) {
                    result = name + 12;   // 去掉 "TRANSACTION_"
                    env->ReleaseStringUTFChars(nameStr, name);
                    env->DeleteLocalRef(nameStr);
                    env->DeleteLocalRef(field);
                    break;
                }
            } else {
                env->ExceptionClear();
            }
        }
            // 匹配 "xxx_TRANSACTION"
        else if (nameLen > 12 && strcmp(name + nameLen - 12, "_TRANSACTION") == 0) {
            jfieldID fieldID = env->GetStaticFieldID(targetClass, name, "I");
            if (fieldID) {
                jint value = env->GetStaticIntField(targetClass, fieldID);
                if (value == code) {
                    result = std::string(name, nameLen - 12);
                    for (char& c : result) c = std::tolower(c);
                    env->ReleaseStringUTFChars(nameStr, name);
                    env->DeleteLocalRef(nameStr);
                    env->DeleteLocalRef(field);
                    break;
                }
            } else {
                env->ExceptionClear();
            }
        }

        env->ReleaseStringUTFChars(nameStr, name);
        env->DeleteLocalRef(nameStr);
        env->DeleteLocalRef(field);
    }

    env->DeleteLocalRef(fields);
    env->DeleteLocalRef(targetClass);
    return result;
}

std::string get_server_name(const binder_transaction_data* txn) {
    if (!txn || !txn->data.ptr.buffer || txn->data_size < 16) {
        return "";
    }

    const auto* base = reinterpret_cast<const uint8_t*>(
            static_cast<uintptr_t>(txn->data.ptr.buffer));
    size_t size = txn->data_size;

    // 辅助函数：从给定位置提取 UTF-16 字符串
    auto extract_utf16 = [&](size_t offset, int32_t len) -> std::string {
        if (offset + 4 + len * 2 > size) return "";
        const auto* name16 = reinterpret_cast<const uint16_t*>(base + offset + 4);
        std::string result;
        result.reserve(len);
        for (int32_t i = 0; i < len; ++i) {
            uint16_t ch = name16[i];
            if (ch < 0x80) {
                result.push_back(static_cast<char>(ch));
            } else if (ch < 0x800) {
                result.push_back(static_cast<char>(0xC0 | (ch >> 6)));
                result.push_back(static_cast<char>(0x80 | (ch & 0x3F)));
            } else {
                result.push_back(static_cast<char>(0xE0 | (ch >> 12)));
                result.push_back(static_cast<char>(0x80 | ((ch >> 6) & 0x3F)));
                result.push_back(static_cast<char>(0x80 | (ch & 0x3F)));
            }
        }
        return result;
    };

    // 服务名合法性检查：只允许字母、数字、点、下划线、美元符号
    auto is_valid_name = [](const std::string& s) -> bool {
        if (s.empty()) return false;
        return std::all_of(s.begin(), s.end(), [](char c) {
            return (c >= 'a' && c <= 'z') ||
                   (c >= 'A' && c <= 'Z') ||
                   (c >= '0' && c <= '9') ||
                   c == '.' || c == '_' || c == '$';
        });
    };

    // 首先寻找 "TSYS" 标志（flat_binder_object.hdr.type == BINDER_TYPE_BINDER）
    const uint32_t TSYS_MAGIC = 0x54535953;  // "TSYS"
    for (size_t offset = 8; offset + 8 <= size; ++offset) {
        if (*(uint32_t*)(base + offset) == TSYS_MAGIC) {
            size_t len_pos = offset + 4;
            if (len_pos + 4 > size) continue;
            int32_t nameLen = *(int32_t*)(base + len_pos);
            if (nameLen > 3 && nameLen <= 256) {
                std::string candidate = extract_utf16(len_pos, nameLen);
                if (!candidate.empty() && is_valid_name(candidate) &&
                    candidate.find('.') != std::string::npos) {
                    return candidate;
                }
            }
        }
    }

    // 回退到模糊搜索
    for (size_t offset = 0; offset + 6 <= size; ++offset) {
        const auto* len_ptr = reinterpret_cast<const int32_t*>(base + offset);
        int32_t nameLen = *len_ptr;
        if (nameLen <= 3 || nameLen > 256) continue;
        size_t str_bytes = static_cast<size_t>(nameLen) * 2;
        if (offset + 4 + str_bytes > size) continue;

        const auto* name16 = reinterpret_cast<const uint16_t*>(base + offset + 4);
        bool valid = true;
        for (int32_t i = 0; i < nameLen; ++i) {
            uint16_t ch = name16[i];
            if ((ch & 0xFF00) == 0) {
                uint8_t lo = ch & 0xFF;
                if (lo < 0x20 || lo > 0x7E) {
                    valid = false;
                    break;
                }
            }
        }
        if (!valid) continue;

        std::string result = extract_utf16(offset, nameLen);
        if (is_valid_name(result)) {
            return result;
        }
    }

    return "";
}