# VNCTF2025 逆向kotlindroid wp-先知社区

> **来源**: https://xz.aliyun.com/news/16997  
> **文章ID**: 16997

---

# 题解

![image.png](images/2d3f1c26-d7b2-3cdf-a130-bc64fcf2ae82)

编译的时候开了proguard保护，然后保留了so的符号，用jadx反编译有问题，用jeb反编译

![image (1).png](images/4bb5b1a8-5c67-333f-acb4-548218c00264)

在searchactivity中发现关键逻辑，可以提取到加密模式为AES-GCM，iv为114514，密文为MTE0NTE0HMuJKLOW1BqCAi2MxpHYjGjpPq82XXQ/jgx5WYrZ2MV53a9xjQVbRaVdRiXFrSn6EcQPzA==

![image (2).png](images/1a4d152b-3262-3619-9745-3de3208f1532)

函数getGCMParameterSpec设置了tag为128位

![image (3).png](images/94fbeb77-5774-35fe-a582-bfc6e9553568)

在button里面传了两个数组，异或之后可以得到key ：atrikeyssyekirta

![image (4).png](images/b3eae0dd-9a08-3791-9b97-e6a5514cb6cc)

在sec函数里可以发现调用了JNI类获得了一段数组arr\_b1作为add的值，然后在最后把生成的密文放在了iv的后面

![image (5).png](images/784edd3e-7beb-360b-b493-222410ee5adb)

在jni里面调用了本地方法native\_natget传入了一段数组new byte[]{0x7B, 0x71, 109, 99, 97, 0x7A, 0x7C, 105}

由于每次返回的add值是一样的，也可以直接用frida或者动调获得返回值

也可以静态分析，这是一个用kotlin编写的so，已经保留了全部的符号，可以直接搜索找到native\_natget函数

![image (6).png](images/38868867-ce40-3f6a-b84c-f12dad1225c5)

传了3个参数，最后一个是我们的数组

![image (7).png](images/fa741562-3704-3377-95bb-b169af96c6b6)

这里初始化了传入的数组创建了实例，然后入栈

![image (8).png](images/bba100a9-d2b3-3293-bb18-ae7597e140c0)

这里入栈了一段本地数据01 1f 09 11 15 1f 0e 0a 17

![image (9).png](images/9171c992-5c50-3cc7-878e-84de9a981f4f)

找到关键的加密循环

![image (10).png](images/cfc4b33e-6797-30a8-bb22-0ddf750f59b1)

可以看到有两个异或，Kotlin\_ByteArray\_get(x0\_43, 8 s% x0\_45))取了本地数据01 1f 09 11 15 1f 0e 0a 17的第9个数据0x17，x0\_42是循环分别取前8位， x0\_37是取当前实例，这个实例就是之前初始化的传入的数组

根据逻辑可以解出来mysecret

![image (11).png](images/0d26d807-7187-3674-826d-ba9b40812b97)

![image (13).png](images/ce7ddbc4-f584-3b2b-bf03-6ac8a0d05f6c)

![image (12).png](images/dd66a219-a7d6-3ac7-a5a4-660d56c5767f)

在后面可以发现有一个函数在mysecret后面加上了add这段字符串，然后传回给java层

最后根据获得的信息解密

![image (14).png](images/92620833-c35d-3d2c-b18e-4dddcd4287af)

# native部分源码

```
import platform.android.*
import kotlinx.cinterop.*
import kotlin.experimental.ExperimentalNativeApi
import kotlin.experimental.xor

@OptIn(ExperimentalForeignApi::class, ExperimentalNativeApi::class)
@CName("native_natget")
fun native_natget(env: CPointer<JNIEnvVar>, thiz: jobject, byteArray: CPointer<ByteVar>): jstring {
    memScoped {
        val length = env.pointed.pointed!!.GetArrayLength!!(env, byteArray)
        val ktByteArray = env.pointed.pointed!!.GetByteArrayElements!!(env, byteArray, null)!!
        val xorKey = byteArrayOf(0x01,0x1f,0x09,0x11,0x15,0x1f,0x0e,0x0a,0x17)
        val resultBytes = ByteArray(length)
        for (i in 0 until length) {
            resultBytes[i] = ktByteArray[i] xor xorKey[i % xorKey.size] xor xorKey[8 % xorKey.size]
        }
        val resultString = resultBytes.toKString() + "add"
        env.pointed.pointed!!.ReleaseByteArrayElements!!(env, byteArray, ktByteArray, 0)
        return env.pointed.pointed!!.NewStringUTF!!.invoke(env, resultString.cstr.ptr)!!
    }
}


@OptIn(ExperimentalNativeApi::class, ExperimentalForeignApi::class)
@CName("JNI_OnLoad")
fun JNI_OnLoad(vm: CPointer<JavaVMVar>, preserved: COpaquePointer): jint {
    return memScoped {
        val envStorage = alloc<CPointerVar<JNIEnvVar>>()
        val vmValue = vm.pointed.pointed!!
        val result = vmValue.GetEnv!!(vm, envStorage.ptr.reinterpret(), JNI_VERSION_1_6)
        if(result == JNI_OK){
            val env = envStorage.pointed!!.pointed!!
            val jclass = env.FindClass!!(envStorage.value, "com/atri/ezcompose/JNI".cstr.ptr)
            val jniMethod = allocArray<JNINativeMethod>(1)
            jniMethod[0].fnPtr = staticCFunction(::native_natget)
            jniMethod[0].name = "native_natget".cstr.ptr
            jniMethod[0].signature = "([B)Ljava/lang/String;".cstr.ptr
            env.RegisterNatives!!(envStorage.value, jclass, jniMethod, 1)
            __android_log_print(ANDROID_LOG_INFO.toInt(), "hello", "this is kotlin native kotlin_onload, %d, %d", sizeOf<CPointerVar<JNINativeMethod>>(), sizeOf<JNINativeMethod>())
        }
        JNI_VERSION_1_6
    }
}
```
