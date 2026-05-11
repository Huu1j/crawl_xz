# dongtai agent分析-先知社区

> **来源**: https://xz.aliyun.com/news/17854  
> **文章ID**: 17854

---

# iast实现

DongTai IAST Java Agent 是一个交互式应用安全测试工具，通过**字节码插桩**技术实现对Java应用的安全监控。技术原理还是基于java agent+ASM的技术；

项目代码：<https://github.com/HXSecurity/DongTai-agent-java.git>

项目有多个模块，

* iast-agent启动模块；主要是进行项目启动加载各个引擎；
* iast-core关键的插桩模块，本项目的核心；
* iast-spy等其他模块，不做过多介绍说明；

## 启动流程简析

1. io.dongtai.iast.core.AgentEngine.run() start()等生命周期控制方法，这里主要包含两部分：

1. ConfigEngine.init加载iast的**sink/source/propagator/http** 相关规则hook点，这部分后续介绍；
2. TransformEngine.start DongTai IAST Java Agent 实现字节码插桩的核心部分，它负责拦截和修改正在加载的 Java 类的字节码；这部分主要是 ：inst.addTransformer(); classFileTransformer.reTransform();这两个关键方法；具体实现在下面IastClassFileTransformer内

2. IastClassFileTransformer.transform 插桩的关键，采用ASM对关键方法进行hook；具体步骤可参考下文

1. 判断类是否需要转换（根据策略配置和类名过滤）
2. 构建类上下文和继承关系
3. 通过插件系统对类进行转换：ClassVisitor cv = plugins.initial(cw, classContext, policyManager);
4. 插入监控代码，用于后续的污点分析：cr.accept(cv, ClassReader.EXPAND\_FRAMES);
5. 返回转换后的字节码

3. **PluginRegister.initial** - 创建处理链.

1. DispatchApiCollector()：针对 Spring MVC/Spring Boot 应用的插件。处理 Spring MVC 控制器和 API 端点，收集 API 信息，监控 API 的响应数据处理。
2. DispatchJ2ee()：处理 Java EE/Jakarta EE 相关的组件。处理 Servlet 容器和 HTTP 请求/响应。
3. DispatchKafka()
4. DispatchJdbc()：处理 JDBC 相关操作，检测 SQL 注入的关键点，监控 SQL 语句的构造和执行；
5. DispatchShiro()
6. DispatchFeign()
7. DispatchDubbo()
8. DispatchClassPlugin()这个iast更为关键的点，上面是针对框架或者相关功能的扩展实现，本处理链是通用类插桩，加载所有相关污点分析的关键逻辑；

### TransformEngine引擎

```
public class TransformEngine implements IEngine {

    private Instrumentation inst;
    private IastClassFileTransformer classFileTransformer;

    @Override
    public void init(PropertyUtils cfg, Instrumentation inst, PolicyManager policyManager) {
        this.classFileTransformer = IastClassFileTransformer.getInstance(inst, policyManager);
        this.inst = inst;
    }

    @Override
    public void start() {
        try {
            DongTaiLog.debug("engine start to add transformer and retransform classes");
            inst.addTransformer(classFileTransformer, true);
            classFileTransformer.reTransform();
            DongTaiLog.debug("transform engine is successfully started");
        } catch (Throwable e) {
            DongTaiLog.error(ErrorCode.get("TRANSFORM_ENGINE_START_FAILED"), e);
        }
    }
```

### transform 方法执行流程

`transform` 方法是 DongTai IAST Java Agent 实现字节码插桩的核心部分，它负责拦截和修改正在加载的 Java 类的字节码。

DongTai IAST 的字节码插桩过程遵循以下流程：

1. 判断类是否需要转换（根据策略配置和类名过滤）
2. 构建类上下文和继承关系
3. 通过插件系统对类进行转换
4. 插入监控代码，用于后续的污点分析
5. 返回转换后的字节码

`transform` 方法在 `IastClassFileTransformer` 类中实现，作为 Java Instrumentation API 的关键方法，当 JVM 加载一个新类时会自动调用它：

1. 前置过滤

```
public byte[] transform(final ClassLoader loader,
                      final String internalClassName,
                      final Class<?> classBeingRedefined,
                      final ProtectionDomain protectionDomain,
                      final byte[] srcByteCodeArray) {
    // 排除 DongTai 自身线程，避免无限递归
    String threadName = Thread.currentThread().getName();
    if (threadName.startsWith("DongTai-IAST-Core")) {
        return null;
    }

    // 排除不需要处理的类
    if (internalClassName == null
            || internalClassName.startsWith("io/dongtai/")
            || internalClassName.startsWith("java/lang/iast/")
            || internalClassName.startsWith("META-INF/")
            || "module-info".equals(internalClassName)) {
        return null;
    }

    // 排除其他安全工具的加载器
    if (null != loader && loader.toString().toLowerCase().contains("rasp")) {
        return null;
    }
```

1. 特殊类处理和组件识别

```
try {
    // 进入 Agent 作用域，避免追踪 Agent 自身的操作
    ScopeManager.SCOPE_TRACKER.getPolicyScope().enterAgent();

    // 处理特殊类，如 QLExpress 和 FastJSON，为后续漏洞检测做准备
    if (" com/ql/util/express/config/QLExpressRunStrategy".substring(1).equals(internalClassName)){
        QLExpressCheck.setQLClassLoader(loader);
    }
    if (" com/alibaba/fastjson/JSON".substring(1).equals(internalClassName)) {
        FastjsonCheck.setJsonClassLoader(loader);
    } else if (" com/alibaba/fastjson/parser/ParserConfig".substring(1).equals(internalClassName)) {
        FastjsonCheck.setParseConfigClassLoader(loader);
    }

    // 软件成分分析 (SCA)，识别应用使用的第三方库
    if (loader != null && protectionDomain != null) {
        final CodeSource codeSource = protectionDomain.getCodeSource();
        if (codeSource == null) {
            return null;
        }
        URL location = codeSource.getLocation();
        if (location != null && !internalClassName.startsWith("sun/") && !location.getFile().isEmpty()) {
            ScaScanner.scanForSCA(location.getFile(), internalClassName);
        }
    }

```

2. 策略匹配和过滤

```
    // 根据策略判断是否需要对该类进行字节码修改
    if (null == classBeingRedefined && !configMatcher.canHook(internalClassName, this.policyManager)) {
        return null;
    }
```

3. 类信息准备和继承关系分析

```
    // 备份原始字节码
    byte[] sourceCodeBak = new byte[srcByteCodeArray.length];
    System.arraycopy(srcByteCodeArray, 0, sourceCodeBak, 0, srcByteCodeArray.length);
    final ClassReader cr = new ClassReader(sourceCodeBak);

    // 构建类上下文，包含类的基本信息
    ClassContext classContext = new ClassContext(cr, loader);
    if (Modifier.isInterface(classContext.getModifier())) {
        return null;  // 跳过接口
    }
    final String className = classContext.getClassName();

    // 分析类的继承关系，用于后续检查该类是否继承了敏感类
    Set<String> ancestors = classDiagram.getClassAncestorSet(className);
    if (ancestors == null) {
        ancestors = classDiagram.updateAncestorsByClassContext(loader, classContext);
    }
    classContext.setAncestors(ancestors);

```

4. 执行字节码转换

```
    // 创建 ClassWriter 用于生成修改后的字节码
    final ClassWriter cw = createClassWriter(loader, cr);
    // 创建并初始化类访问器链，根据策略注册相应的插件
    ClassVisitor cv = plugins.initial(cw, classContext, policyManager);

    if (cv instanceof AbstractClassVisitor) {
        // 开始访问和转换字节码
        cr.accept(cv, ClassReader.EXPAND_FRAMES);
        AbstractClassVisitor dumpClassVisitor = (AbstractClassVisitor) cv;

        // 检查是否实际进行了转换
        if (dumpClassVisitor.hasTransformed()) {
            // 保存原始字节码，用于后续可能的 redefine
            if (null == classBeingRedefined) {
                transformMap.put(className, srcByteCodeArray);
            } else {
                transformMap.put(classBeingRedefined, srcByteCodeArray);
            }
            transformCount++;
            // 如果开启了dump功能，将修改前后的字节码保存到文件系统
            return dumpClassIfNecessary(cr.getClassName(), cw.toByteArray(), srcByteCodeArray);
        }
    }
} catch (Throwable throwable) {
    DongTaiLog.warn(ErrorCode.get("TRANSFORM_CLASS_FAILED"), internalClassName, throwable);
} finally {
    // 离开Agent作用域
    ScopeManager.SCOPE_TRACKER.getPolicyScope().leaveAgent();
}

return null;  // 返回null表示不修改原字节码
```

### **PluginRegister链**

PluginRegister的逻辑，最关键的在于最后添加的DispatchClassPlugin。负责将安全策略与字节码转换联系起来，实现精确的方法级插桩。

```
    public PluginRegister() {
        this.plugins = new ArrayList<>();
        List<String> disabledPlugins = PropertyUtils.getDisabledPlugins();
        List<DispatchPlugin> allPlugins = new ArrayList<>(Arrays.asList(
                new DispatchApiCollector(),
                new DispatchJ2ee(),
                new DispatchKafka(),
                new DispatchJdbc(),
                new DispatchShiro(),
                new DispatchFeign(),
                new DispatchDubbo()
        ));
        allPlugins.removeIf(plugin -> disabledPlugins != null && disabledPlugins.contains(plugin.getName()));
        this.plugins.addAll(allPlugins);
        this.plugins.add(new DispatchClassPlugin());
    }

    public ClassVisitor initial(ClassVisitor classVisitor, ClassContext context, PolicyManager policyManager) {
        Policy policy = policyManager.getPolicy();
        if (policy == null) {
            return classVisitor;
        }

        classVisitor = new DispatchHardcodedPlugin().dispatch(classVisitor, context, policy);
        for (DispatchPlugin plugin : plugins) {
            ClassVisitor pluginVisitor = plugin.dispatch(classVisitor, context, policy);
            if (pluginVisitor != classVisitor) {
                classVisitor = pluginVisitor;
                // TODO: need transform multiple times?
                if (!context.getClassName().equals(DispatchJ2ee.APACHE_COYOTE_WRITER)) {
                    break;
                }
            }
        }
        return classVisitor;
    }
```

关键在于ClassVisit.visitMethod方法。最关键在于visitMethod中的lazyAop方法：

1. 关键组件 - MethodAdapter 数组，这些适配器会在 `MethodAdviceAdapter` 中被使用，根据策略节点的类型选择适当的适配器进行具体的字节码插桩操作。

1. **SourceAdapter**: 处理污点源，识别外部输入
2. **PropagatorAdapter**: 处理污点传播，跟踪数据流动
3. **SinkAdapter**: 处理危险方法调用点
4. **ValidatorAdapter**: 处理验证器，检测数据是否经过安全检查

2. policy.getPolicyNodesMap()获取之前规则引擎之前加载的所有服务端规则；
3. 遍历每个策略节点，使用其 `MethodMatcher` 检查当前方法是否匹配。如果有匹配的策略节点，创建一个 `MethodAdviceAdapter` 实例，并标记类已被转换。
4. `MethodAdviceAdapter`进行**MethodAdapter**中不同的适配器进行处理。主要是onMethodEnter、onMethodExit方法；
5. 而其中几乎所有的`MethodAdviceAdapter`中都有一个AbstractAdviceAdapter.trackMethod方法，而正是该方法定义了污点的处理过程，也就是漏洞的处理逻辑；而具体实现则是由SpyDispatcherImpl.collectMethod；

```
public class DispatchClassPlugin implements DispatchPlugin {
    private Set<String> ancestors;
    private String className;

    public DispatchClassPlugin() {
    }

    @Override
    public ClassVisitor dispatch(ClassVisitor classVisitor, ClassContext classContext, Policy policy) {
            ............
        return new ClassVisit(classVisitor, classContext, policy)
    }    

    public class ClassVisit extends AbstractClassVisitor {
        private int classVersion;
        private final MethodAdapter[] methodAdapters;

        ClassVisit(ClassVisitor classVisitor, ClassContext classContext, Policy policy) {
            super(classVisitor, classContext, policy);
            this.methodAdapters = new MethodAdapter[]{
                    new SourceAdapter(),
                    new PropagatorAdapter(),
                    new SinkAdapter(),
                    new ValidatorAdapter(),
            };
        }
        ...........

        @Override
        public MethodVisitor visitMethod(final int access, final String name, final String descriptor,
                                         final String signature, final String[] exceptions) {
            MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
            // 跳过接口、抽象方法和静态构造块
            if (Modifier.isInterface(access) || Modifier.isAbstract(access) || "<clinit>".equals(name)) {
                if (this.classVersion <= Opcodes.V1_6) {
                    mv = new JSRInlinerAdapter(mv, access, name, descriptor, signature, exceptions);
                }
                return mv;
            }
                        //检查当前类是否在黑名单中且未被特殊配置为忽略黑名单。
            if (this.policy.isBlacklistHooks(this.context.getClassName())
                    && !this.policy.isIgnoreBlacklistHooks(this.context.getClassName())
                    && !this.policy.isIgnoreInternalHooks(this.context.getClassName())) {
                if (this.classVersion <= Opcodes.V1_6) {
                    mv = new JSRInlinerAdapter(mv, access, name, descriptor, signature, exceptions);
                }
                return mv;
            }
                        //方法上下文构建:所属类信息（从 this.context 继承）、方法名、访问修饰符、方法描述符、参数类型列表
            MethodContext methodContext = new MethodContext(this.context, name);
            methodContext.setModifier(access);
            methodContext.setDescriptor(descriptor);
            methodContext.setParameters(AsmUtils.buildParameterTypes(descriptor));

                        //策略匹配与方法转换:核心逻辑，遍历之前匹配到的类名集合,调用 lazyAop 方法尝试应用 AOP 转换
            String matchedSignature;
            boolean methodIsTransformed = false;
            for (String matchedName : context.getMatchedClassSet()) {
                context.setMatchedClassName(matchedName);
                matchedSignature = AsmUtils.buildSignature(matchedName, name, descriptor);
                mv = lazyAop(mv, access, name, descriptor, matchedSignature, methodContext);
                methodIsTransformed = mv instanceof MethodAdviceAdapter;
                if (methodIsTransformed) break;

            }
            //特殊 JVM 版本处理
            if (methodIsTransformed && this.classVersion <= Opcodes.V1_6) {
                mv = new JSRInlinerAdapter(mv, access, name, descriptor, signature, exceptions);
            }
            //日志记录
            if (methodIsTransformed) {
                DongTaiLog.trace("rewrite method {} for listener[class={}]", context.getMatchedClassName(), context.getClassName());
            }

            return mv;
        }

        /**
         * 懒惰AOP，用于处理预定义HOOK点
         *
         * @param mv         方法访问器
         * @param access     方法访问控制符
         * @param name       方法名
         * @param descriptor 方法描述符
         * @param signature  方法签名
         * @return 修改后的方法访问器
         */
        //方法是实际进行策略匹配和方法转换的核心：
        private MethodVisitor lazyAop(MethodVisitor mv, int access, String name, String descriptor, String signature,
                                      MethodContext methodContext) {
            Set<PolicyNode> matchedNodes = new HashSet<PolicyNode>();

            Map<String, PolicyNode> policyNodesMap = this.policy.getPolicyNodesMap();
            if (policyNodesMap != null && policyNodesMap.size() != 0) {
                for (Map.Entry<String, PolicyNode> entry : policyNodesMap.entrySet()) {
                    if (entry.getValue().getMethodMatcher().match(methodContext)) {
                        matchedNodes.add(entry.getValue());
                    }
                }
            }

            if (matchedNodes.size() > 0) {
                mv = new MethodAdviceAdapter(mv, access, name, descriptor, signature,
                        matchedNodes, methodContext, this.methodAdapters);
                setTransformed();
            }

            return mv;
        }
    }
}
```

MethodAdviceAdapter在处理字节码时，会根据策略节点的类型，选择对应的适配器进行处理。这也就是IAST系统处理的核心；

```
public class MethodAdviceAdapter extends AbstractAdviceAdapter {
    private final Set<PolicyNode> policyNodes;
    private final MethodAdapter[] methodAdapters;

    @Override
    protected void onMethodEnter() {
        for (PolicyNode policyNode : policyNodes) {
            // 根据策略节点类型选择合适的适配器
            for (MethodAdapter adapter : methodAdapters) {
                if (adapter.canVisit(policyNode.getType())) {
                    adapter.onMethodEnter(mv, policyNode, context);
                    break;
                }
            }
        }
    }

    @Override
    protected void onMethodExit(int opcode) {
        for (PolicyNode policyNode : policyNodes) {
            // 同样，在方法退出时根据类型选择适配器
            for (MethodAdapter adapter : methodAdapters) {
                if (adapter.canVisit(policyNode.getType())) {
                    adapter.onMethodExit(mv, opcode, policyNode, context);
                    break;
                }
            }
        }
    }
    ......
}
```

## 规则加载

ConfigEngine.init()方法进行加载相关source、sink等规则点；

```
//ConfigEngine.init()
public class ConfigEngine implements IEngine {

    @Override
    public void init(PropertyUtils cfg, Instrumentation inst, PolicyManager policyManager) {
        DongTaiLog.debug("Initialize the core configuration of the engine");
        policyManager.loadPolicy(cfg.getPolicyPath());
        DongTaiLog.debug("The engine's core configuration is initialized successfully.");
    }
}
```

之后在policyManager.loadPolicy中PolicyBuilder.fetchFromServer()进行服务端请求获取相关规则，之后经过一系列的规则处理，保存到了Policy中的policyNodesMap中；

```
    public void loadPolicy(String policyPath) {
        try {
            JSONArray policyConfig;
            if (StringUtils.isEmpty(policyPath)) {
                policyConfig = PolicyBuilder.fetchFromServer();
            } else {
                policyConfig = PolicyBuilder.fetchFromFile(policyPath);
            }
            this.policy = PolicyBuilder.build(policyConfig);
        } catch (Throwable e) {
            DongTaiLog.error(ErrorCode.get("POLICY_LOAD_FAILED"), e);
        }
    }
    
public static final String HOOK_PROFILE = "/api/v1/profilesv2";

    public static JSONArray fetchFromServer() throws PolicyException {
        try {
            StringBuilder resp = HttpClientUtils.sendGet(ApiPath.HOOK_PROFILE, null);
            JSONObject respObj = new JSONObject(resp.toString());
            return respObj.getJSONArray(KEY_DATA);
        } catch (JSONException e) {
            throw new PolicyException(PolicyException.ERR_POLICY_CONFIG_FROM_SERVER_INVALID, e);
        }
    }    
```

最终会在lazyAop中的Map<String, PolicyNode> policyNodesMap = this.policy.getPolicyNodesMap()中进行相关规则的获取使用；

## 规则实现

前文我们知道所有的**MethodAdviceAdapter**中都有一个AbstractAdviceAdapter.trackMethod方法进行污点处理；在这里我们看下具体的实现；

1. **插桩位置**：

* Source/Propagator/Validator: 主要在方法返回前插桩 (`onMethodExit`)
* Sink: 主要在方法执行前插桩 (`onMethodEnter`)

2. **收集数据**：

* Source: 收集外部输入数据，标记为污点
* Propagator: 记录数据转换和传递过程
* Sink: 检查输入参数是否包含污点数据
* Validator: 记录数据验证操作

3. **调用方法**：

* 各适配器调用 `SpyDispatcher` 接口的不同方法
* 传递不同的参数和上下文信息

### source/sink/Propagato等处理

这里首先看下在不同sink、source等位置的具体实现

SourceAdapter:

```
    public void onMethodExit(MethodAdviceAdapter adapter, MethodVisitor mv, int opcode, MethodContext context,
                             Set<PolicyNode> policyNodes) {
        for (PolicyNode policyNode : policyNodes) {
            if (!(policyNode instanceof SourceNode)) {
                continue;
            }

            Label elseLabel = new Label();
            Label endLabel = new Label();

            isFirstScope(adapter);
            mv.visitJumpInsn(Opcodes.IFEQ, elseLabel);

            adapter.trackMethod(opcode, policyNode, true);

            adapter.mark(elseLabel);
            adapter.mark(endLabel);

            leaveScope(adapter, policyNode);
        }
    }
```

ValidatorAdapter:

```
    @Override
    public void onMethodExit(MethodAdviceAdapter adapter, MethodVisitor mv, int opcode, MethodContext context, Set<PolicyNode> policyNodes) {
        for (PolicyNode policyNode : policyNodes) {
            if (!(policyNode instanceof ValidatorNode)) {
                continue;
            }

            Label elseLabel = new Label();
            Label endLabel = new Label();

            isEnterScope(adapter);
            mv.visitJumpInsn(Opcodes.IFEQ, elseLabel);

            adapter.trackMethod(opcode, policyNode, true);

            adapter.mark(elseLabel);
            adapter.mark(endLabel);
        }
    }
```

PropagatorAdapter:

```
public void onMethodExit(MethodAdviceAdapter adapter, MethodVisitor mv, int opcode, MethodContext context,
                             Set<PolicyNode> policyNodes) {
        for (PolicyNode policyNode : policyNodes) {
            if (!(policyNode instanceof PropagatorNode)) {
                continue;
            }

            Label elseLabel = new Label();
            Label endLabel = new Label();

            String signature = context.toString();

            isFirstScope(adapter);
            mv.visitJumpInsn(Opcodes.IFEQ, elseLabel);

            adapter.trackMethod(opcode, policyNode, true);

            adapter.mark(elseLabel);
            adapter.mark(endLabel);

            leaveScope(adapter, signature, policyNode);
        }
    }
```

SinkAdapter:

```
    public void onMethodEnter(MethodAdviceAdapter adapter, MethodVisitor mv, MethodContext context,
                              Set<PolicyNode> policyNodes) {
        for (PolicyNode policyNode : policyNodes) {
            if (!(policyNode instanceof SinkNode)) {
                continue;
            }
            if ("ssrf".equals(((SinkNode) policyNode).getVulType())){
                adapter.skipCollect(-1, policyNode, false);
            }

            enterScope(adapter, policyNode);

            Label elseLabel = new Label();
            Label endLabel = new Label();

            isFirstScope(adapter);
            mv.visitJumpInsn(Opcodes.IFEQ, elseLabel);

            adapter.trackMethod(-1, policyNode, false);

            adapter.mark(elseLabel);
            adapter.mark(endLabel);
        }
    }
```

ASM进行hook的AbstractAdviceAdapter.trackMethod方法;

```
    public void trackMethod(
            final int opcode,
            final PolicyNode policyNode,
            final boolean captureRet
    ) {
        newLocal(ASM_TYPE_OBJECT);
        if (captureRet && !isThrow(opcode)) {
            loadReturn(opcode);
        } else {
            pushNull();
        }
        storeLocal(this.nextLocal - 1);
        invokeStatic(ASM_TYPE_SPY_HANDLER, SPY_HANDLER$getDispatcher);
        loadThisOrPushNullIfIsStatic();
        loadArgArray();
        loadLocal(this.nextLocal - 1);
        push(policyNode.toString());
        push(this.context.getClassName());
        push(this.context.getMatchedClassName());
        push(this.name);
        push(this.signature);
        push(Modifier.isStatic(this.access));
        invokeInterface(ASM_TYPE_SPY_DISPATCHER, SPY$collectMethod);
        pop();
    }
```

`SpyDispatcher` 接口（通过 `SpyDispatcherImpl` 实现）是连接字节码插桩和实际污点分析的桥梁：

当插入的监控代码执行 `collectMethod` 时，`SpyDispatcherImpl` 会根据策略类型做不同处理：

1. **Source 处理**：将外部输入标记为污点，创建 `TaintValue` 对象记录污点信息
2. **Propagator 处理**：检查输入参数是否包含污点，如果包含，将返回值也标记为污点，并计算新污点的范围
3. **Sink 处理**：检查输入参数是否包含污点，如果发现污点到达危险函数，就触发安全检查
4. **Validator 处理**：记录数据验证操作，更新污点的安全状态

SpyDispatcherImpl.collectMethod方法

```

    @Override
    public boolean collectMethod(Object instance, Object[] parameters, Object retObject, String policyKey,
                                 String className, String matchedClassName, String methodName, String signature,
                                 boolean isStatic) {
        try {
            ScopeManager.SCOPE_TRACKER.getPolicyScope().enterAgent();
            PolicyNode policyNode = getPolicyNode(policyKey);
            if (policyNode == null) {
                return false;
            }

            if (!isCollectAllowed(false)) {
                return false;
            }

            MethodEvent event = new MethodEvent(className, matchedClassName, methodName,
                    signature, instance, parameters, retObject);

            if ((policyNode instanceof SourceNode)) {
                SourceImpl.solveSource(event, (SourceNode) policyNode, INVOKE_ID_SEQUENCER);
                return true;
            } else if ((policyNode instanceof PropagatorNode)) {
                PropagatorImpl.solvePropagator(event, (PropagatorNode) policyNode, INVOKE_ID_SEQUENCER);
                return true;
            } else if ((policyNode instanceof SinkNode)) {
                SinkImpl.solveSink(event, (SinkNode) policyNode);
                return true;
            } else if ((policyNode instanceof ValidatorNode)) {
                ValidatorImpl.solveValidator(event,(ValidatorNode)policyNode, INVOKE_ID_SEQUENCER);
                return true;
            }

            return false;
        } catch (Throwable e) {
            DongTaiLog.error(ErrorCode.get("SPY_COLLECT_METHOD_FAILED"), e);
        } finally {
            ScopeManager.SCOPE_TRACKER.getPolicyScope().leaveAgent();
        }
        return false;
    }
```

### 漏洞检测

具体的漏洞检测及污点跟踪可参考，讲解的很明白：[https://m0d9.me/2022/10/18/DongTai-IAST-分析/](https://m0d9.me/2022/10/18/DongTai-IAST-%E5%88%86%E6%9E%90/)

其实不同漏洞在sink点是不同的处理逻辑，这个主要是 `io.dongtai.iast.core.handler.hookpoint.vulscan.dynamic.DynamicPropagatorScanner#scan` 中实现；

```
    @Override
    public void scan(MethodEvent event, SinkNode sinkNode) {
    //这里主要是特殊的 Sink 点进行安全性检查，主要是new FastjsonCheck(), new XXECheck(), new QLExpressCheck()。检查表明当前调用是安全。
        for (SinkSafeChecker chk : SAFE_CHECKERS) {
            if (chk.match(event, sinkNode) && chk.isSafe(event, sinkNode)) {
                return;
            }
        }
//这里主要是处理到sink点的http相关的方法，主要是针对类似ssrf这种避免重新处理，相当于判断相关http的方法是否第一次处理。第一次处理会做标记，避免后续再次处理；
        if (!HttpService.validate(event)) {
            return;
        }
//服务调用相关的特殊情况主要是http处理相关，用于SSRF相关漏洞（但是这里的处理逻辑和下面其实有关联。这里只是简单判断了当前方法的签名是否符合（基本是http相关的方法调用）
//就会走自动设置serviceCall为true。这就导致下面的污点处理sinkSourceHitTaintPool方法是否存在fasle或者true其实是不影响的，这部分针对ssrf的判断逻辑应该是在服务端进行实现了；）
        boolean serviceCall = false;
        for (ServiceTrace serviceTrace : SERVICE_TRACES) {
            if (serviceTrace.match(event, sinkNode)) {
                serviceCall = true;
                serviceTrace.addTrace(event, sinkNode);
            }
        }

//sinkSourceHitTaintPool方法是检测污点实现的基本判断逻辑
        boolean hit = sinkSourceHitTaintPool(event, sinkNode);
//如果发现服务调用或污点池命中则会进行下面的处理；正常逻辑是到了这里基本可以定义为漏洞，但是可能是随着项目发展，有一部分如ssrf的判断是在服务端实现了；
//收集调用堆栈（最多 5 层）
//检查是否在排除的堆栈中，如果是则返回
//设置事件的各种属性（调用堆栈、唯一ID、策略类型、源位置等）
//将事件添加到全局跟踪图中，为后续的漏洞报告做准备
        if (serviceCall || hit) {
            StackTraceElement[] stackTraceElements = StackUtils.createCallStack(5);
            if (sinkNode.hasDenyStack(stackTraceElements)) {
                return;
            }
            event.setCallStacks(stackTraceElements);
            int invokeId = SpyDispatcherImpl.INVOKE_ID_SEQUENCER.getAndIncrement();
            event.setInvokeId(invokeId);
            event.setPolicyType(PolicyNodeType.SINK.getName());
            event.setTaintPositions(sinkNode.getSources(), null);
            event.setStacks(stackTraceElements);

            EngineManager.TRACK_MAP.addTrackMethod(invokeId, event);
        }
    }
```

而后面的sinkSourceHitTaintPool方法则是关于污点跟踪的实现：

```
/**
     * sink方法的污点来源是否命中污点池，用于过滤未命中污点池的sink方法，避免浪费资源，设置污点源去向
     *
     * @param event    current method event
     * @param sinkNode current sink policy node
     * @return 当前方法是否命中污点池
     */
    private boolean sinkSourceHitTaintPool(MethodEvent event, SinkNode sinkNode) {
//特殊的漏洞类型（如路径遍历、SSRF、未验证的重定向）进行专门的源检查,虽然这里有ssrf的检测，但是其实并没有用，可能是未来的功能迁移；
        for (SinkSourceChecker chk : SOURCE_CHECKERS) {
            if (chk.match(event, sinkNode)) {
                return chk.checkSource(event, sinkNode);
            }
        }
//遍历 SinkNode 配置中指定的所有源位置（对象或参数），检查这些位置是否包含污点数据：
//判断参数是否非空
//判断参数类型是否支持污点追踪
//查询污点池，判断参数是否被标记为污点
//如果发现污点，将其添加到 sourceInstances 列表中
        List<Object> sourceInstances = new ArrayList<>();
        boolean hasTaint = false;
        boolean objHasTaint = false;
        Set<TaintPosition> sources = sinkNode.getSources();
        for (TaintPosition position : sources) {
            if (position.isObject()) {
                if (TaintPoolUtils.isNotEmpty(event.objectInstance)
                        && TaintPoolUtils.isAllowTaintType(event.objectInstance)
                        && TaintPoolUtils.poolContains(event.objectInstance, event)) {
                    objHasTaint = true;
                    hasTaint = true;
                    addSourceInstance(sourceInstances, event.objectInstance);
                }
            } else if (position.isParameter()) {
                int parameterIndex = position.getParameterIndex();
                if (parameterIndex >= event.parameterInstances.length) {
                    continue;
                }
                boolean paramHasTaint = false;
                Object parameter = event.parameterInstances[parameterIndex];
                if (TaintPoolUtils.isNotEmpty(parameter)
                        && TaintPoolUtils.isAllowTaintType(parameter)
                        && TaintPoolUtils.poolContains(parameter, event)) {
                    paramHasTaint = true;
                    hasTaint = true;
                    addSourceInstance(sourceInstances, parameter);
                }
                event.addParameterValue(parameterIndex, parameter, paramHasTaint);
            }
        }

//污点标记：对发现的污点数据进行标记验证：
//1、获取当前漏洞类型对应的标记检查规则
//2、提取必须存在的标记（required）和不允许存在的标记（disallowed）
//3、对每个污点实例：
//- 获取其在污点池中的范围信息
//- 检查是否满足标记要求：具有所有必需标记，且不具有任何禁止标记
//- 如果启用了验证检查，还会检查污点是否通过了安全验证
        if (!sourceInstances.isEmpty()) {
            List<TaintTag[]> tagList = TAINT_TAG_CHECKS.get(sinkNode.getVulType());
            if (tagList != null) {
                boolean tagsHit = false;
                TaintTag[] required = tagList.get(0);
                TaintTag[] disallowed = tagList.get(1);

                for (Object sourceInstance : sourceInstances) {
                    long hash = TaintPoolUtils.getStringHash(sourceInstance);
                    TaintRanges tr = EngineManager.TAINT_RANGES_POOL.get(hash);
                    if (tr == null || tr.isEmpty()) {
                        continue;
                    }
                    
                    boolean commonCondition = tr.hasRequiredTaintTags(required) && !tr.hasDisallowedTaintTags(disallowed);

                    if (PropertyUtils.validatedSink()) {
                        tagsHit = commonCondition && !tr.hasValidatedTags(disallowed);
                    } else {
                        tagsHit = commonCondition;
                    }
                }
                if (!tagsHit) {
                    return false;
                }
            }
        }

        if (hasTaint) {
            event.setObjectValue(event.objectInstance, objHasTaint);
        }

        return hasTaint;
    }

```

上面的检测有个关键点就是污点标签系统

每种漏洞类型都有两组标签：

1. **必须存在的标签**：污点数据必须具有的特征（如 UNTRUSTED 表示不可信数据）
2. **不应存在的标签**：如果污点数据具有这些标签，则不视为漏洞（如 HTML\_ENCODED 表示数据已经过 HTML 转义，不会导致 XSS）

这种设计允许做到了以下区分：

* 确实存在的漏洞（污点数据未经适当处理）
* 假阳性（污点数据经过了适当的验证或转义）

### 污点跟踪

在不同的solve处理逻辑中对于污点跟踪的方式主要按照下面的三个重要数据结构处理；

io.dongtai.iast.core.EngineManager：

```
public static final IastTrackMap TRACK_MAP = new IastTrackMap();
public static final IastTaintHashCodes TAINT_HASH_CODES = new IastTaintHashCodes();
public static final TaintRangesPool TAINT_RANGES_POOL = new TaintRangesPool();
```

结合上下文可以说明

* TRACK\_MAP：保存方法调用事件和调用关系的线程局部缓存，它记录了应用执行过程中的方法调用链信息。

* 存储所有被监控的方法调用事件（Source、Sink、Propagator）
* 根据调用ID维护方法调用之间的关系
* 为漏洞检测提供完整的调用链上下文
* 支持重构污点从源头到危险点的完整传播路径

* TAINT\_HASH\_CODES：记录被污点标记对象哈希码的线程局部集合，用于快速判断对象是否被污染。

* 提供快速查找机制，判断对象是否为污点
* 使用哈希码而非对象引用，降低内存占用
* 支持高效的污点检测操作
* 避免重复处理同一个污点对象

* TAINT\_RANGES\_POOL：存储污点数据详细信息的线程局部映射，记录每个污点对象的污染范围和标签。

* 存储污点数据的详细信息，包括污染范围和标签
* 支持部分污染的精细跟踪（例如，字符串中只有部分字符是污点）
* 维护污点数据的安全处理状态（如已转义、已验证等）
* 为漏洞检测提供污点特性信息

这三个数据结构协同工作，共同实现了 DongTai IAST 的完整污点跟踪和漏洞检测流程：

1、污点标记阶段(source)：

source：O、P

target：O、P、R

io.dongtai.iast.core.handler.hookpoint.controller.impl.SourceImpl#solveSource

* 如果method return为空或者为原始类型之类的无效污染、并且如果method 为getAttrribute，那么仅允许白名单内的arg，否则推出；
* `*trackTarget`\* 方法用来将source 的`returnInstance`结果放入了 EngineManager.TAINT\_HASH\_CODES/TAINT\_RANGES\_POOL 污点池中：**如果结果是Map、Collection、Array之类的，会进一步遍历其所有值，都加入TAINT\_HASH\_CODES/TAINT\_RANGES\_POOL**
* 将event 加入EngineManager.TRACK\_MAP 中

```
   private static final ArrayList<String> WHITE_ATTRIBUTES = new ArrayList<String>();
    private static final String METHOD_OF_GETATTRIBUTE = "getAttribute";

    public static void solveSource(MethodEvent event, SourceNode sourceNode, AtomicInteger invokeIdSequencer) {
        if (!TaintPoolUtils.isNotEmpty(event.returnInstance)
                || !TaintPoolUtils.isAllowTaintType(event.returnInstance)
                || !allowCall(event)) {
            return;
        }

// 1. 创建方法事件
        event.source = true;
        event.setCallStacks(StackUtils.createCallStack(4));

        int invokeId = invokeIdSequencer.getAndIncrement();
        event.setInvokeId(invokeId);
        event.setPolicyType(PolicyNodeType.SOURCE.getName());

// 2. 计算对象哈希码
// 3. 将哈希码添加到污点集合
// 4. 创建并存储污点范围信息
        boolean valid = trackTarget(event, sourceNode);
        if (!valid) {
            return;
        }

        for (TaintPosition src : sourceNode.getSources()) {
            if (src.isObject()) {
                event.setObjectValue(event.returnInstance, true);
            } else if (src.isParameter()) {
                if (event.parameterInstances.length > src.getParameterIndex()) {
                    event.addParameterValue(src.getParameterIndex(), event.parameterInstances[src.getParameterIndex()], true);
                }
            }
        }

        for (TaintPosition tgt : sourceNode.getTargets()) {
            if (tgt.isObject()) {
                event.setObjectValue(event.returnInstance, true);
            } else if (tgt.isParameter()) {
                if (event.parameterInstances.length > tgt.getParameterIndex()) {
                    event.addParameterValue(tgt.getParameterIndex(), event.parameterInstances[tgt.getParameterIndex()], true);
                }
            } else if (tgt.isReturn()) {
                event.setReturnValue(event.returnInstance, true);

            }
        }

        if (!TaintPosition.hasObject(sourceNode.getSources()) && !TaintPosition.hasObject(sourceNode.getTargets())) {
            event.setObjectValue(event.objectInstance, false);
        }

        event.setTaintPositions(sourceNode.getSources(), sourceNode.getTargets());
// 5. 记录方法调用事件
        EngineManager.TRACK_MAP.addTrackMethod(invokeId, event);
    }
```

2、 污点数据传播阶段

**PropagatorImpl#solvePropagator**

source：O、P

target：O、P、R

当污点数据在应用中流动和转换时：

* 当存在污点链则进行传播节点处理，首先根据规则propagatorNode.getSources()判断source是否命中污点链，如果存在则标记hasTaint可以进行下一步；
* 命中source后执行setTarget(propagatorNode, event)判断target逻辑，将target计算hast将结果录入TAINT\_HASH\_CODES，并根据污点标签系统标记污点位置，并录入TAINT\_RANGES\_POOL

```
private static void auxiliaryPropagator(MethodEvent event, PropagatorNode propagatorNode, AtomicInteger invokeIdSequencer) {
        Set<TaintPosition> sources = propagatorNode.getSources();
        if (!sources.isEmpty() && !propagatorNode.getTargets().isEmpty()) {
            boolean hasTaint = false;
//分析source来源是否存在污点，如果存在则标记hasTaint
            for(TaintPosition position : sources) {
                if (position.isObject()) {
                    boolean objHasTaint = false;
                    if (TaintPoolUtils.isNotEmpty(event.objectInstance) && TaintPoolUtils.isAllowTaintType(event.objectInstance) && TaintPoolUtils.poolContains(event.objectInstance, event)) {
                        objHasTaint = true;
                        hasTaint = true;
                    }

                    event.setObjectValue(event.objectInstance, objHasTaint);
                } else if (position.isParameter()) {
                    int parameterIndex = position.getParameterIndex();
                    if (parameterIndex < event.parameterInstances.length) {
                        boolean paramHasTaint = false;
                        Object parameter = event.parameterInstances[parameterIndex];
                        if (TaintPoolUtils.isNotEmpty(parameter) && TaintPoolUtils.isAllowTaintType(parameter) && TaintPoolUtils.poolContains(parameter, event)) {
                            paramHasTaint = true;
                            hasTaint = true;
                        }

                        event.addParameterValue(parameterIndex, parameter, paramHasTaint);
                    }
                }
            }

            if (hasTaint) {
            //污点数据录入TAINT_HASH_CODES，并根据污点标签系统标记污点位置，并录入TAINT_RANGES_POOL
                boolean valid = setTarget(propagatorNode, event);
                if (valid) {
                //当规则不是S：O和T:O这种情况则将objValue标记为非污点，但是这里并不影响整体流程，不清楚这一步骤有什么具体作用？
                    if (!TaintPosition.hasObject(sources) && !TaintPosition.hasObject(propagatorNode.getTargets())) {
                        event.setObjectValue(event.objectInstance, false);
                    }
//如果没有达到污点传播上限则将结果录入TRACK_MAP
                    addPropagator(propagatorNode, event, invokeIdSequencer);
                }
            }
        }
    }
```

3、漏洞检测阶段

这部分可以参考前文漏洞检测部分，在sink中之处理source，因为污点到达sink就说明是触发了危险方法（当然还是要看规则完整性）

source：O、P

当污点数据到达危险方法（Sink 点）时，下面是简单分析逻辑的伪代码：

```
// 假设这是执行 SQL 查询的方法
statement.executeQuery(query);  // 潜在的 SQL 注入点

// 在 DynamicPropagatorScanner.sinkSourceHitTaintPool 方法内

// 1. 检查参数是否为污点
long paramHash = TaintPoolUtils.getStringHash(query);
if (TAINT_HASH_CODES.contains(paramHash)) {
    // 2. 获取污点范围和标签
    TaintRanges ranges = TAINT_RANGES_POOL.get(paramHash);
    
    // 3. 根据漏洞类型检查标签
    // SQL 注入需要: UNTRUSTED 标签存在，SQL_ENCODED 标签不存在
    if (ranges.hasRequiredTaintTags(new TaintTag[]{TaintTag.UNTRUSTED}) && 
        !ranges.hasDisallowedTaintTags(new TaintTag[]{TaintTag.SQL_ENCODED})) {
        
        // 4. 确认漏洞
        MethodEvent event = new MethodEvent();
        // ...设置事件属性
        
        // 5. 记录漏洞事件
        int invokeId = invokeIdSequencer.getAndIncrement();
        event.setInvokeId(invokeId);
        TRACK_MAP.addTrackMethod(invokeId, event);
        
        // 6. 通过 TRACK_MAP 重构完整传播链
        // 收集漏洞上下文，生成完整报告
    }
}
```

​

参考文章

<https://su18.org/post/dongtai/#>

[https://m0d9.me/2022/10/18/DongTai-IAST-分析/](https://m0d9.me/2022/10/18/DongTai-IAST-%E5%88%86%E6%9E%90/)

<https://mp.weixin.qq.com/s/fq2m59L_2Piqyeufl6eZFQ>
