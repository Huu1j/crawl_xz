# 使用CodeQL挖掘Spring中的大量赋值漏洞-先知社区

> **来源**: https://xz.aliyun.com/news/18354  
> **文章ID**: 18354

---

## 什么是大量赋值漏洞

或许你没有听过“大量赋值漏洞”，但你一定在网络上见过这样的技巧：FUZZ请求参数的额外字段。比如：

1. 在某个获取用户列表的请求中,如 `/api/user?name=ad&orderby=id`,可以尝试 FUZZ SQL关键字,例如:`/api/user?name=ad&orderby=id&sort=desc,1/0&limit=0,1 PROCEDURE ANALYSE(..)`,可能发现潜在注入点;
2. 在注册账号场景中，可以尝试 FUZZ 内部字段,如设置用户身份的字段 `role=admin`、 `isAdmin=true`等,测试是否能意外获得管理员权限。

以上漏洞都存在一个共同点，即后端接收了这些本不应暴露给用户的字段，并进行了处理。而本文讨论的大量赋值漏洞，则是在此基础上的一个特殊案例。

大量赋值（Mass Assignment）是指，后端为了简化开发流程，自动将请求参数绑定到后端对象的属性上。但是，如果开发者**没有限制哪些字段可以被赋值**，攻击者就可能构造请求参数，注入原本不应由用户控制的敏感字段。如果后端接受并处理了这些敏感字段,则会引发一系列安全问题，也就是所谓的大量赋值漏洞（Mass Assignment Vulnerability）。

## Spring中的大量赋值

[Spring Framework](https://github.com/spring-projects/spring-framework) 是一个开源的 Java 应用程序开发框架，最初由 Rod Johnson 于 2003 年发布。它以其轻量级、模块化和强大的依赖注入（DI）与面向切面编程（AOP）特性而广受欢迎，尤其在 Java Web 开发中。

在 Web 开发中，Spring 提供了强大的请求映射与参数处理机制，其中使用最多的为[@RequestBody 注解](https://docs.spring.io/spring-framework/reference/web/webflux/controller/ann-methods/requestbody.html)。该注解能够将 HTTP 请求体中的 JSON、XML 等结构化数据反序列化为 Java 对象，并绑定到控制器方法的参数中。这种自动映射的机制极大地简化了数据解析与对象构造的过程。然而，正是这种便捷性，也可能在不经意间引入安全隐患：**如果未对绑定对象的字段进行严格控制，攻击者便可以利用** `@RequestBody` **自动赋值的特性，向对象注入敏感字段，进而引发大量赋值漏洞**。

接下来通过一段示例代码，逐步分析这一漏洞的形成过程及其利用方式：

在某一应用程序中，存在一个用户注册功能。该程序中通过`User`类, 定义了一个简单的 “用户” 数据模型，其代码如下:

```
// User.java
public class User{

    private String name;
    
    private String password;
    
    private String role;
    
    public void setName(String name){
        this.name = name;
    }
    ... Getters and Setters
}
```

现有以下路由代码,用于处理前端发起的用户注册请求,该请求直接使用 `@RequestBody`注解, 将用户的`POST传参`解析为 `User 类型参数`,随后直接通过 `service层` 保存在数据库中：

```
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserService userService;
    
    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody User newUser) {
        userService.save(newUser);
        return ResponseEntity.ok(newUser);
    }
}
```

`User表`对应的建表语句如下,可以看到其中的`role`字段默认为`user` :

```
CREATE TABLE `litemall_user` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(63) NOT NULL COMMENT '用户名称',
  `password` varchar(63) NOT NULL DEFAULT '' COMMENT '用户密码',
  `role` varchar(63) NOT NULL DEFAULT 'user' COMMENT '用户角色',
  ) 
```

现在让我们来看看前端是如何发起注册请求的,代码如下. 在前端代码中,\*\*没有显示声明 `role字段`内容,\*\*因此正常注册的用户应该是普通权限.

```
// api.js
export function register(username, password) {
  const endpoint = `${baseurl}/user/register`;
  const payload = {
    name: username,
    password: password
  };

  return axios.post(endpoint, payload, {
    headers: {
      'Content-Type': 'application/json'
    }
  });
}
```

然而由于 `@RequestBody` 会将请求体中字段自动绑定到 `User` 对象的每个属性上，而后端未对 `role 字段`做任何限制。因此,若攻击者成功FUZZ出该字段或者通过源码审计发现出该处存在绑定问题,这将导致攻击者成功注册为管理员用户。

如何修复？

很简单，如果用户权限只能由管理员设置,我们只需要在调用 `userService.save()`前,手动设置 `role` 为 `"user"`:

```
@PostMapping("/register")
public ResponseEntity<User> register(@RequestBody User newUser) {
    newUser.setRole("user");
    userService.save(newUser);
    return ResponseEntity.ok(newUser);
}
```

## 我的CodeQL探索之旅：如何发现CVE-2025-6702

上一章节演示了`Spring`中的大量赋值漏洞案例：后端通过 `@RequestBody`自动绑定了客户端传入的数据对象，**但未对敏感字段（如 role）进行显式设置或校验**，从而导致攻击者可以设置敏感参数实现权限提升。

本章节中，笔者将使用真实案例，揭示如何使用CodeQL发现CVE-2025-6702。首选需要明确任务，即：通过CodeQL，找到使用 `@RequestBody` 解析传入参数，且对应路由函数里未对相关字段使用 `setter方法`进行显示赋值。

进一步的，可将目标拆解为以下三个步骤:

1. 查找使用 `@RequestBody` 注解的参数
2. 在 步骤1 的基础上，需要满足该**参数类型为指定的数据结构**
3. 在 步骤2 的基础上，检测该参数 **未使用显式调用 setter 方法进行字段赋值**

### 查找使用`@RequestBody`注解的参数

参照官方[annotations-in-java](https://codeql.github.com/docs/codeql-language-guides/annotations-in-java/)案例，很容易查找到使用 `@RequestBody`作为注解的参数：

```
/**
 * This is an automatically generated file
 * @name Hello world
 * @kind problem
 * @problem.severity warning
 * @id java/example/hello-world
 */

import java

class RequestbodyAnnotation extends Annotation {
  RequestbodyAnnotation() {
    this.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestBody")
  }
}

from Parameter bodyParameter
where bodyParameter.getAnAnnotation() instanceof RequestbodyAnnotation
select bodyParameter, "has a @RequestBody annotation"
```

![](images/20260326202257-857dfde7-290e-1.png)

### 参数类型为指定的数据结构

通过对上一步查询结果的观察，发现存在非绑定类型的参数，如：`String` 类型。

因此我们需要进一步筛选出符合自动绑定类型的参数。

![](images/20260326202258-8621dcd9-290e-1.png)

通过阅读源码，发现该项目相关的绑定参数定义在 `org.linlinjava.litemall.db.domain`包下,且都符合`LitemallXXX`的命名格式,因此定义如下一个谓词进行过滤:

![](images/20260326202259-86d021d3-290e-1.png)

```
predicate daoClass(Class c) {
  c.getPackage().getName() = "org.linlinjava.litemall.db.domain" and
  c.getName().matches("Litemall%")
}
```

对应的`where` 语句更新为：

```
from Parameter bodyParameter
where bodyParameter.getAnAnnotation() instanceof RequestbodyAnnotation and
daoClass(bodyParameter.getType())
select bodyParameter, "has a @RequestBody annotation"
```

为了方便，将上面的代码进行整合，重新定义一个 BodyParameter 类,用来获取所有满足前两个步骤的请求参数:

```
class BodyParameter extends Parameter {
  BodyParameter() {
    this.getAnAnnotation() instanceof RequestbodyAnnotation and
    daoClass(this.getType())
  }
}
```

![](images/20260326202300-87797c29-290e-1.png)

### 未显式调用的`setter方法`

以`WxCartController.java:113:50`为例,可以看到在`add` 路由下, 该函数通过一系列的`setter 方法`显示设置字段值,最后调用 `cartService.add(cart)` 进行Service层的业务逻辑处理。因此如果能够找到未被显式调用的 `setter方法`，就可能发现潜在的大量赋值漏洞。

![](images/20260326202301-88272ae3-290e-1.png)

为了需要找到大量赋值类对应的 `setter方法`，作者定义了`SetterMethod`类,如下:

```
class SetterMethod extends Method {
  SetterMethod() {
    exists(Class c |
      daoClass(c) and
      this.getDeclaringType() = c and
      this.isPublic() and
      this.getName().regexpMatch("set.*") and
      this.getNumberOfParameters() = 1
    )
  }
}
```

该类主要依据 `setter` 方法特征的如下三个特征进行过滤：

1. public 方法
2. 方法名称格式为setXxx
3. setter方法只拥有一个参数

现在来完善 `from-where-select` 语句,用来查询所有未被显式调用的`setter方法`:

```
from SetterMethod allSetterMethods, BodyParameter requestBodyParam
where
  requestBodyParam.getType() = allSetterMethods.getDeclaringType() and
  not exists(MethodCall explicitCall |
    explicitCall.getCallee() = allSetterMethods and
    explicitCall.getQualifier().(VarAccess).getVariable() = requestBodyParam
  )
select requestBodyParam, "Dont't call setter: " + allSetterMethods.getName() + "explicitly" 
```

![](images/20260326202302-88ce30dc-290e-1.png)

执行查询语句，会发现得到了大量结果。由于只考虑用户侧可控的参数和请求,因此可以限定普通用户可访问的api来进行进一步过滤，如下，结果从539条减少到了94条.

![](images/20260326202303-89688ef8-290e-1.png)

### 变量传递优化

截止目前，已经完成了之前的所有任务，现在来浏览一下是否存在有趣的`setter方法`未被显式调用吧。通过浏览查询结果， `setPrice`引起了我的关注。嗯? 难道我们找到了一个未显式设置商品价格的参数?让我们来进一步确认：

![](images/20260326202304-8a174d6c-290e-1.png)

点击右侧蓝色字体,编辑器跳转到对应参数的代码片段.通过阅读代码后发现,这段代码确实没有显式调用 `setPirce`设置商品价格,**但是这段代码压根儿就没有处理我们传入的**`cart`**参数**.

因此,我们需要在此处进一步优化查询逻辑,使得通过`@RequestBody`传入的参数,**传入到了service层进行处理**。这并不复杂，通过[本地数据流](https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-java/#using-local-data-flow)就能满足我们的需求.不过在构造where语句前，先定义下 `serviceClass`，用于查找 `service层`的数据结构：

```
predicate serviceClass(Class c) {
  c.getPackage().getName() = "org.linlinjava.litemall.db.service" and
  c.getName().matches("%Service")
}
```

接着完善`from-where-select`语句：

```
import semmle.code.java.dataflow.DataFlow

from SetterMethod allSetterMethods, BodyParameter requestBodyParam
where
  requestBodyParam.getType() = allSetterMethods.getDeclaringType() and
  not exists(MethodCall explicitCall |
    explicitCall.getCallee() = allSetterMethods and
    explicitCall.getQualifier().(VarAccess).getVariable() = requestBodyParam
  ) and
  exists(MethodCall call |
    serviceClass(call.getQualifier().(VarAccess).getVariable().getType()) and
    DataFlow::localFlow(DataFlow::parameterNode(requestBodyParam),
      DataFlow::exprNode(call.getAnArgument()))
  ) and
  not requestBodyParam.getFile().getAbsolutePath().matches("%admin-api%")
select requestBodyParam, "Dont't call setter: " + allSetterMethods.getName() + " explicitly"
```

注意：由于优化的查询语句中使用到了数据流分析,因此需要导入相关模块: `semmle.code.java.dataflow.DataFlow`

执行查询，此时的查询结果从 94条 减少到了 66条。

![](images/20260326202305-8ac92204-290e-1.png)

### `getter`也算显式调用

继续浏览查询结果,又发现一个问题:虽然有些参数没用使用`setter函数`进行赋值处理,但是使用了`getter函数`获取对应的值.显然此时应该认为该参数为系统期望输入。因此我们需要过滤掉使用`getter函数`对应的`setter函数`。

![](images/20260326202307-8b7915de-290e-1.png)

如何才能满足上诉需求？笔者采用了一种最为直观的方法，将`getter方法`变为`setter方法`。在优化`where条件`之前，先定义所有的`setter方法`：

```
class GetterMethod extends Method {
  GetterMethod() {
    exists(Class c |
      daoClass(c) and
      this.getDeclaringType() = c and
      this.isPublic() and
      this.getName().regexpMatch("get.*")
    )
  }
}
```

接着使用`replaceAll("get", "set")`将对应的getter方法转为setter方法，如下：

```
from SetterMethod allSetterMethods, BodyParameter requestBodyParam
where
  requestBodyParam.getType() = allSetterMethods.getDeclaringType() and
  not exists(MethodCall explicitCall |
    explicitCall.getCallee() = allSetterMethods and
    explicitCall.getQualifier().(VarAccess).getVariable() = requestBodyParam
  ) and
  exists(MethodCall call |
    serviceClass(call.getQualifier().(VarAccess).getVariable().getType()) and
    DataFlow::localFlow(DataFlow::parameterNode(requestBodyParam),
      DataFlow::exprNode(call.getAnArgument()))
  ) and
   not exists(GetterMethod getterCall, MethodCall explicitCall |
    daoClass(getterCall.getDeclaringType()) and
    explicitCall.getCallee() = getterCall and
    explicitCall.getQualifier().(VarAccess).getVariable() = requestBodyParam and
    getterCall.getName().replaceAll("get", "set") = allSetterMethods.getName()
  ) and
  not requestBodyParam.getFile().getAbsolutePath().matches("%admin-api%")
select requestBodyParam, "Dont't call setter: " + allSetterMethods.getName() + " explicitly"
```

此时，结果从 66 条减少到了 56 条。

![](images/20260326202308-8c342bde-290e-1.png)

### 发现漏洞！

来感受下逐步优化查询语句后的成果吧。浏览查询结果过程中, `setAdminContent` 未被显式调用引起了笔者的关注。根据建表语句，发现该字段为“管理员回复内容”。最后经过测试，发现该接口存在大量赋值漏洞。如果你想查看漏洞细节，可以前往这里：<https://ctf-n0el4kls.notion.site/Litemall-Mass-Assignment-Vulnerability-in-wx-comment-post-21441990f447808b86d1cb15e37ecae9>

![](images/20260326202309-8cf15166-290e-1.png)

![](images/20260326202310-8d71a669-290e-1.png)

其次，还发现查询结果中多处存在未显示调用 `setDeleted` 方法，这允许用户自删除自己的评论/数据，应该没有用户无聊到通过大量赋值来“删除”自己的数据吧。

### 最后完整的CodeQL查询语句:

```
/**
 * This is an automatically generated file
 *
 * @name Hello world
 * @kind problem
 * @problem.severity warning
 * @id java/example/hello-world
 */

import java

class RequestbodyAnnotation extends Annotation {
  RequestbodyAnnotation() {
    this.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestBody")
  }
}

predicate daoClass(Class c) {
  c.getPackage().getName() = "org.linlinjava.litemall.db.domain" and
  c.getName().matches("Litemall%")
}

class BodyParameter extends Parameter {
  BodyParameter() {
    this.getAnAnnotation() instanceof RequestbodyAnnotation and
    daoClass(this.getType())
  }
}

class SetterMethod extends Method {
  SetterMethod() {
    exists(Class c |
      daoClass(c) and
      this.getDeclaringType() = c and
      this.isPublic() and
      this.getName().regexpMatch("set.*") and
      this.getNumberOfParameters() = 1
    )
  }
}

import semmle.code.java.dataflow.DataFlow
predicate serviceClass(Class c) {
  c.getPackage().getName() = "org.linlinjava.litemall.db.service" and
  c.getName().matches("%Service")
}


class GetterMethod extends Method {
  GetterMethod() {
    exists(Class c |
      daoClass(c) and
      this.getDeclaringType() = c and
      this.isPublic() and
      this.getName().regexpMatch("get.*")
    )
  }
}


from SetterMethod allSetterMethods, BodyParameter requestBodyParam
where
  requestBodyParam.getType() = allSetterMethods.getDeclaringType() and
  not exists(MethodCall explicitCall |
    explicitCall.getCallee() = allSetterMethods and
    explicitCall.getQualifier().(VarAccess).getVariable() = requestBodyParam
  ) and
  exists(MethodCall call |
    serviceClass(call.getQualifier().(VarAccess).getVariable().getType()) and
    DataFlow::localFlow(DataFlow::parameterNode(requestBodyParam),
      DataFlow::exprNode(call.getAnArgument()))
  ) and
   not exists(GetterMethod getterCall, MethodCall explicitCall |
    daoClass(getterCall.getDeclaringType()) and
    explicitCall.getCallee() = getterCall and
    explicitCall.getQualifier().(VarAccess).getVariable() = requestBodyParam and
    getterCall.getName().replaceAll("get", "set") = allSetterMethods.getName()
  ) and
  not requestBodyParam.getFile().getAbsolutePath().matches("%admin-api%")
select requestBodyParam, "Dont't call setter: " + allSetterMethods.getName() + " explicitly"

```

## Reference

<https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/>  
<https://portswigger.net/web-security/api-testing#mass-assignment-vulnerabilities>

<https://codeql.github.com/docs/codeql-language-guides/codeql-for-java/>

<https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/20-Testing_for_Mass_Assignment>
