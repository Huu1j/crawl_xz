# Mybatis-Flex浅析

> **来源**: https://forum.butian.net/share/2410  
> **文章ID**: 2410

---

0x00 关于Mybatis-Flex
===================

 MyBatis-Flex是一个MyBatis增强框架，它非常轻量、同时拥有极高的性能与灵活性。可以轻松的使用Mybaits-Flex连接任何数据库，其内置的QueryWrapper帮助我们极大的减少了SQL 编写的工作的同时，减少出错的可能性。

![image.png](images/attach-8c99ae10e492aa7265e0e34b9b13ea1b70ed9ede.png)

 通过引入相关的依赖即可使用对应的功能：

```xml
<dependency>  
   <groupId>com.mybatis-flex</groupId>  
   <artifactId>mybatis-flex-spring-boot-starter</artifactId>  
   <version>1.5.6</version>  
</dependency>
```

0x01 已有的安全措施
============

 在完成基于entity 的基本增删改查功能的同时，MyBatis-Flex进行了一定的优化，对于一些特殊的SQL操作场景还设计了一些安全措施，避免SQL注入的风险。

1.1 OrderBy排序
-------------

 OrderBy子句的内容通常是动态的，根据不同的查询需求可能会有不同的排序字段和排序方式。正因为OrderBy子句的内容是动态生成的，预编译无法处理动态的SQL语句。所以常常这类场景会存在SQL注入的风险。

 在Mybatis-Flex中，可以通过QueryWrapper对查询的对象进行封装操作，当然也包括排序操作。例如下面的例子：

```Java
@RequestMapping("/getAllUser")
public ApiResponse> getAllUser(String sort) {
    QueryWrapper queryWrapper = QueryWrapper.create().select().orderBy(sort);
    List userList = userMapper.selectListByQuery(queryWrapper);
    ApiResponse> response = new ApiResponse<>(200, "Success", userList);
    return response;
}
```

 可以看到正常情况下，实现了基于id字段进行排序：

![image.png](images/attach-c38357b7d8b98d53ad030069841762083d2a825a.png)

 这里尝试通过1/0进行SQL注入测试，返回500 status：

![image.png](images/attach-2e534272734c4a0668b086a7db0b8eca54a1ab4c.png)

 查看对应的报错堆栈信息，可以看到是Orderby的sql不安全，说明Mybatis Flex做了一定的安全防护：

![image.png](images/attach-ee8a95380307a3bbea07f179fe708a73a39ec838.png)

 查看`com.mybatisflex.core.query.QueryWrapper#orderBy`的具体实现：

![image.png](images/attach-a08aa4cfb7f626369c5fe65a1e604bacffcfb478.png)

 可以看到是通过实例化`com.mybatisflex.core.query.StringQueryOrderBy`来构建排序字段的，在StringQueryOrderBy的构造方法中，调用了SqlUtil.keepOrderBySqlSafely方法进行安全检查：

![image.png](images/attach-068b98b7ef65b1b8b96ca9d12ea7b889b5cbfece.png)

 这里对排序的内容进行了白名单控制，只允许字母、数字、下划线、空格、逗号和点号，若输入另外的内容（例如上面1/0中的`/`）会抛出IllegalArgumentException异常，从一定程度上防止了SQL注入的利用：

![image.png](images/attach-97b9549ecf8e8e5b7c9298ded789105561933bef.png)

 相比SpringData，可以看到SpringData对于排序字段的限制更为的严格，限制了排序字段只能包含数字、字母、'.'、'\_'和''字符，否则会抛出异常：

```Java
    private static final Predicate predicate = Pattern.compile("^[0-9a-zA-Z_\\.\\(\\)]*$").asPredicate();

    /**
     * Validates a {@link org.springframework.data.domain.Sort.Order}, to be either safe for use in SQL or to be
     * explicitely marked unsafe.
     * 
     * @param order the {@link org.springframework.data.domain.Sort.Order} to validate. Must not be null.
     */
    public static void validate(Sort.Order order) {

        String property = order.getProperty();
        boolean isMarkedUnsafe = order instanceof SqlSort.SqlOrder ro && ro.isUnsafe();
        if (isMarkedUnsafe) {
            return;
        }

        if (!predicate.test(property)) {
            throw new IllegalArgumentException(
                    "order fields that are not marked as unsafe must only consist of digits, letter, '.', '_', and '\'. If you want to sort by arbitrary expressions please use RelationalSort.unsafe. Note that such expressions become part of SQL statements and therefore need to be sanatized to prevent SQL injection attacks.");
        }
    }
```

1.2 列名column检查
--------------

 在SqlUtil中，还有一个keepColumnSafely方法用于列名的安全性检查。举例说明：

 在数据库查询中，GROUP BY 子句用于根据一个或多个列对结果集进行分组，并对每个分组进行聚合计算。它通常与聚合函数（如SUM、COUNT、AVG等）一起使用，以便对每个分组的数据进行汇总和分析。同样的，GROUP BY 子句通常是根据查询的需要来确定的，而分组的列以及分组的值可能在不同的查询中不同。这种动态性使得很难在预编译阶段确定具体的分组方式，所以常常这类场景会存在SQL注入的风险。

 在Mybatis-Flex中，可以通过QueryWrapper对查询的对象进行封装操作，当然也包括GROUP BY 操作。例如下面的例子,根据职业（career）分组，并计算每个职业的人数：

```Java
@RequestMapping("/groupByCareer")
public ApiResponse> groupByCareer() {
    QueryWrapper queryWrapper = QueryWrapper.create().select("career, COUNT(*)").groupBy("CAREER");
    List result = userMapper.selectRowsByQuery(queryWrapper);
    ApiResponse> response = new ApiResponse<>(200, "Success", result);
    return response;
}
```

![image.png](images/attach-337cb413ee68b855b8112d5b02dd3a2ea3366eac.png)

 查看`com.mybatisflex.core.query.QueryWrapper#groupBy`的具体实现：

![image.png](images/attach-dd6625d597e5661b0d5b757a8713bb70f37945e1.png)

 可以看到是通过实例化`com.mybatisflex.core.query.QueryColumn`来构建列名字段的，在QueryColumn的构造方法中，调用了SqlUtil.keepColumnSafely方法进行安全检查，首先通过`Character.isWhitespace(char ch)` 检查是否包含空白字符，是的话抛出IllegalArgumentException异常:

![image.png](images/attach-1ce1184d849e5a6a699b757f7c8499b96fb939a0.png)

 然后调用isUnSafeChar方法检查是否包含不安全的字符，同样的包含类似的字符也会抛出IllegalArgumentException异常：

![image.png](images/attach-83c888c3ab2ef250f9ce67f2731a200849e2e128.png)

![image.png](images/attach-f70a84238319f1786d17bd6cead42d5d401ca677.png)

 同样的，类似使用QueryMethods下的函数时，同样也有类似的安全检查，以COUNT方法为例：

![image.png](images/attach-36d1d3918170221e2a71a663c204cce1a8520272.png)

 可以看到同样的在构造方法会对column进行对应的安全检查：

![image.png](images/attach-0af810c4e34f50a65517b987ec9f2710e6975cfd.png)

0x02 常见SQL注入场景
==============

 跟mybatis-plus类型，若某些场景下使用不当，也会出现SQL注入的问题，下面列举一些常见的场景：

2.1 Mybatis原生注解&XML配置
-------------------------

 使用 MyBatis-Flex并不会影响原有的 MyBatis 的任何功能。同样可以使用原生注解&XML配置进行增删改查。所以同样的只需要找到`$`标注的参数。

2.2 QueryWrapper
----------------

 在QueryWrapper中由于部分场景存在动态sql的场景，若处理不当会存在SQL注入的风险，下面是一些常见的场景。

### 2.2.1 动态列名

 在QueryWrapper中可以通过`com.mybatisflex.core.query.QueryWrapper#select`方法构建动态列名的查询：

![image.png](images/attach-23caea5541a0cd64adfee3dbdc46a23ca2a23d92.png)

 根据前面的分析，在实例化QueryColumn的时候，会调用`SqlUtil.keepColumnSafely`进行相关的安全检查。所以通过QueryColumn构建的动态列名对SQL注入有一定的防护。

 但是除了QueryColumn以外，还可以通过直接传入String通过`com.mybatisflex.core.query.StringQueryColumn`构建动态列名：

![image.png](images/attach-3c3f22a9ce8e87ddb6504450075f1a7c64efbe9f.png)

 可以看到StringQueryColumn的构造方法并没有对应的安全检查，在某种情况下可能存在SQL注入风险：

![image.png](images/attach-add6b5005c215ad643fd5335ed895333db3d2761.png)

 看一个实际的例子，通过用户传入的column查询对应的列数据：

```Java
@RequestMapping("/getColumn")
public ApiResponse> getTbale(String column) {
    QueryWrapper queryWrapper = QueryWrapper.create().select(column);
    List result = userMapper.selectRowsByQuery(queryWrapper);
    ApiResponse> response = new ApiResponse<>(200, "Success", result);
    return response;
}
```

 根据前面的分析，因为这里column是动态查询，没有相关的限制的话会存在SQL注入风险：

![image.png](images/attach-052ca4c656421e8ae73ddb0553623833daedda4a.png)

 通过查看对应的堆栈信息可知，1/0成功执行，SQL注入存在：

![image.png](images/attach-7422b43b8c613a07d0bd49efa85eea35840db023.png)

### 2.2.2 Where动态条件

 `Where` 动态条件是 MyBatis-Flex 中一个重要的特性，它允许你根据不同的条件动态构建查询条件，从而更加灵活地执行数据库查询操作。例如下面的例子，通过where查询符合firstName条件的所有用户信息：

```Java
@RequestMapping("/getUserByFirstName")
public ApiResponse> getUserByFirstName(String firstName) {
    QueryWrapper queryWrapper = QueryWrapper.create().select().where("FIRST_NAME='"+firstName+"'");
    List result = userMapper.selectRowsByQuery(queryWrapper);
    ApiResponse> response = new ApiResponse<>(200, "Success", result);
    return response;
}
```

![image.png](images/attach-8104d86f6be9d4269b369de7d8ddf681453f0989.png)

 因为这里直接使用SQL拼接，存在SQL注入风险：

![image.png](images/attach-8539cc71a906badc80ce1b565d2a422508db4e6e.png)

 可以看到尝试引入的1/0成功执行，证明SQL注入存在：

![image.png](images/attach-6050694460582b23aa51d5063c97bb3e7bfed5d0.png)

 正确的方式应该跟其他主流ORM框架一样，在 SQL 语句中使用占位符（`?`）来表示参数的位置，然后通过设置参数值来填充这些占位符,通过预编译的方式避免SQL注入的风险：

```Java
QueryWrapper queryWrapper = QueryWrapper.create().select().where("FIRST_NAME=?",firstName);
```

除此以外，**类似and (...) 和or (...)是where条件的拓展，也存在类似的问题,在使用时需要注意：**

![image.png](images/attach-dc92fb9ea96981bc5449c19b6361a6319581f69e.png)

2.3 Db + Row 工具类
----------------

 Db + Row 工具类，提供了在 Entity 实体类之外的数据库操作能力。使用 Db + Row 时，无需对数据库表进行映射。可以调用一些内置的方法执行自定义的原生SQL。例如下面的例子，通过工具类自定义sql查询匹配first\_name的用户信息：

```Java
@RequestMapping("/getUserByDbRow")
public ApiResponse> getUserByDbRow(String name) {
    String listsql = "select * from user where first_name = '"+name+"'";
    List result = Db.selectListBySql(listsql);
    ApiResponse> response = new ApiResponse<>(200, "Success", result);
    return response;
}
```

![image.png](images/attach-e71c0b521816df2cb01c89ad74289183c5661df9.png)

 同样的，因为这里直接使用SQL拼接，存在SQL注入风险：

 当引入and 1=1查询逻辑时正常查询：

![image.png](images/attach-43a48ca3152ec7c6f29afdf629753b197be686fd.png)

 引入and 1=2逻辑时，查询结果为空，证明SQL注入存在：

![image.png](images/attach-f0ec04350a7a11a94df79de8b335195d446999cf.png)

 正确的方式应该跟其他主流ORM框架一样，在 SQL 语句中使用占位符（`?`）来表示参数的位置，然后通过设置参数值来填充这些占位符,通过预编译的方式避免SQL注入的风险：

```Java
String listsql = "select * from user where first_name = ?";
List result = Db.selectListBySql(listsql,name);
```

 同样的，同于类似排序/动态表名列名等无法预编译的场景，也应该进行一定的限制处理。
