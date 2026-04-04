package com.gumuluo.testapp

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.gumuluo.proxy.binder.BinderDispatcher
import com.gumuluo.proxy.binder.BinderInterceptor
import com.gumuluo.proxy.binder.BinderProxy
import org.lsposed.hiddenapibypass.HiddenApiBypass

class MainActivity : ComponentActivity() {

    // 用于存储显示的结果
    private var resultText by mutableStateOf("未检测")
    private var resultTextAndroidId by mutableStateOf("未检测")

    companion object {
        private val isAndroidIdRequest = ThreadLocal<Boolean>()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        HiddenApiBypass.addHiddenApiExemptions("")
        BinderProxy.init()

        setContent {
            MaterialTheme {
                Column(
                    modifier = Modifier.fillMaxSize().padding(16.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Text(text = resultText, style = MaterialTheme.typography.headlineSmall)
                    Spacer(modifier = Modifier.height(16.dp))
                    Button(onClick = { checkReal() }) {
                        Text("检测真实状态")
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Button(onClick = { enableFraud() }) {
                        Text("启用欺诈")
                    }

                    Spacer(modifier = Modifier.height(32.dp))

                    Text(text = resultTextAndroidId, style = MaterialTheme.typography.headlineSmall)
                    Spacer(modifier = Modifier.height(16.dp))
                    Button(onClick = { checkRealAndroidId() }) {
                        Text("检测真实Android ID")
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Button(onClick = { enableAndroidIdFraud() }) {
                        Text("启用Android ID欺诈")
                    }
                }
            }
        }
    }

    /**
     * 获取真实的 debuggable 状态（不经过任何拦截）
     */
    private fun checkReal() {
        // 临时移除所有 after 回调，确保不受影响
        BinderDispatcher.unregisterAfter("android.content.pm.IPackageManager", "getApplicationInfo")
        CacheHandling.clearCaches()
        val isDebuggable = getDebuggableFlag()
        resultText = if (isDebuggable) "当前状态: DEBUGGABLE = true" else "当前状态: DEBUGGABLE = false"
    }

    /**
     * 注册拦截器，将返回的 ApplicationInfo 中的 DEBUGGABLE 标志清除
     */
    private fun enableFraud() {
        // 先注销已有的拦截器（如果有），避免重复
        BinderDispatcher.unregisterAfter("android.content.pm.IPackageManager", "getApplicationInfo")
        CacheHandling.clearCaches()

        // 注册新的 after 回调
        BinderDispatcher.registerAfter(
            "android.content.pm.IPackageManager",
            "getApplicationInfo",
            BinderInterceptor { data, outReply ->
                Log.d("Bypass", "========== Interceptor triggered ==========")
                Log.d("Bypass", "dataSize=${data.dataSize()}, dataAvail=${data.dataAvail()}")

                try {
                    // 1. 读取异常（安全跳过所有异常相关信息）
                    data.readException()
                } catch (e: Exception) {
                    // 如果服务返回了异常，记录日志并继续处理（但通常不会）
                    Log.w("Bypass", "Service threw exception: $e")
                    // 注意：这里不能直接返回 false，因为我们需要继续处理数据（可能有部分数据）
                }

                // 2. 读取 ApplicationInfo 对象（可能为 null）
                val originalInfo = data.readTypedObject(ApplicationInfo.CREATOR)
                if (originalInfo == null) {
                    Log.w("Bypass", "No ApplicationInfo returned")
                    return@BinderInterceptor false
                }

                // 3. 修改 flags
                val originalFlags = originalInfo.flags
                originalInfo.flags = originalFlags and ApplicationInfo.FLAG_DEBUGGABLE.inv()
                Log.d("Bypass", "Modified flags: 0x${Integer.toHexString(originalFlags)} -> 0x${Integer.toHexString(originalInfo.flags)}")

                // 4. 构造新的 outReply，模仿服务端的构造方式
                outReply.setDataPosition(0)
                outReply.writeNoException()                 // 写入异常码及可能的 StrictMode 信息
                outReply.writeTypedObject(originalInfo, 0)  // 写入对象标志 + 对象数据

                Log.d("Bypass", "Modified data size: ${outReply.dataSize()}")
                true
            }
        )

        // 重新获取状态（此时拦截器已生效）
        val isDebuggable = getDebuggableFlag()
        resultText = if (isDebuggable) "欺诈后状态: DEBUGGABLE = true" else "欺诈后状态: DEBUGGABLE = false"
    }

    /**
     * 通过 PackageManager 获取当前应用的 debuggable 标志
     */
    private fun getDebuggableFlag(): Boolean {
        return try {
            val pm = packageManager
            val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                PackageManager.ApplicationInfoFlags.of(0).value
            } else {
                0
            }
            val appInfo = pm.getApplicationInfo(packageName, flags.toInt())
            (appInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }

    private fun checkRealAndroidId() {
        BinderDispatcher.unregisterBefore("android.content.IContentProvider", "call")
        BinderDispatcher.unregisterAfter("android.content.IContentProvider", "call")
        CacheHandling.clearCaches()

        val androidId = Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID)
        resultTextAndroidId = "真实Android ID: $androidId"
    }

    private fun enableAndroidIdFraud() {
        // 先注销已有的拦截器
        BinderDispatcher.unregisterBefore("android.content.IContentProvider", "call")
        BinderDispatcher.unregisterAfter("android.content.IContentProvider", "call")
        CacheHandling.clearCaches()

        // 1. 注册 before 回调，识别是否为获取 Android ID 的请求
        BinderDispatcher.registerBefore(
            "android.content.IContentProvider",
            "call",
            BinderInterceptor { data, _ ->
                try {
                    // 读取 Interface Token
                    data.enforceInterface("android.content.IContentProvider")

                    // 判断是否为获取 Android ID 的请求
                    val bytes = data.marshall()
                    val str16 = String(bytes, Charsets.UTF_16LE)
                    val str8 = String(bytes, Charsets.UTF_8)
                    
                    if ((str16.contains("GET_secure") || str8.contains("GET_secure")) && 
                        (str16.contains("android_id") || str8.contains("android_id"))) {
                        isAndroidIdRequest.set(true)
                        Log.d("Bypass", "Intercepted Android ID request!")
                    } else {
                        isAndroidIdRequest.set(false)
                    }
                } catch (e: Exception) {
                    isAndroidIdRequest.set(false)
                }
                false
            }
        )

        // 2. 注册 after 回调，修改服务端返回的 Bundle
        BinderDispatcher.registerAfter(
            "android.content.IContentProvider",
            "call",
            BinderInterceptor { data, outReply ->
                if (isAndroidIdRequest.get() == true) {
                    isAndroidIdRequest.remove()

                    try {
                        data.readException()

                        val bundle = data.readBundle()
                        if (bundle != null) {
                            Log.d("Bypass", "Original Android ID: ${bundle.getString("value")}")

                            bundle.putString("value", "8888888888888888")

                            outReply.setDataPosition(0)
                            outReply.writeNoException()
                            outReply.writeBundle(bundle)

                            Log.d("Bypass", "Android ID modified successfully!")
                            return@BinderInterceptor true
                        }
                    } catch (e: Exception) {
                        Log.e("Bypass", "Failed to modify Android ID", e)
                    }
                }
                false
            }
        )

        val androidId = Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID)
        resultTextAndroidId = "欺诈后Android ID: $androidId"
    }
}