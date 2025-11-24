# DocSys代码审计-先知社区

> **来源**: https://xz.aliyun.com/news/16234  
> **文章ID**: 16234

---

# 项目介绍

MxsDoc是基于Web的文件管理系统，支持权限管理、历史版本管理、Office预览/编辑、WPS预览/编辑、在线解压缩、文件分享、文件加密、远程存储、远程文件推送、秒传、断点续传、智能搜索、文件备注、回收站、自动备份、一键迁移、集群部署。 主要应用场景：文件管理系统、协同办公系统、电子书、知识管理系统、软件接口管理系统、自动备份软件、网页版SVN仓库、网页版GIT仓库。GPL 2.0开源协议.

# 环境搭建

这套系统的环境搭建真是搞了好久，和我往常搭过的系统都不一样搞了几次终于搞清楚了，虽然还有点问题但是问题不大，先下载下面两个文件

war包：<https://github.com/RainyGao-GitHub/DocSys/releases/download/DocSys_V2.02.36/DocSystem.war>

网站源码：<https://github.com/RainyGao-GitHub/DocSys/archive/refs/tags/DocSys_V2.02.36.zip>

由于系统是Eclipse项目，我没用过了，所以我是尝试在IDEA以Eclipse项目导入，但是会有一些问题，到现在没解决，只能用IDEA看源码，没法用IDEA启动项目，所以下面启动是下载官方打包好的war包使用tomcat启动

源码解压后使用idea打开

![](images/20241217134916-a7012c16-bc3a-1.png)

由于是Eclipse项目idea打开会载不全，添加一下模块就可以了

选择文件-->项目结构-->模块-->导入模块，选择源码文件

![](images/20241217134943-b6ac681a-bc3a-1.png)

导入格式选择Eclipse

![](images/20241217134951-bbbdb480-bc3a-1.png)

然后就可以了正常看代码了，问题就是这里报红，不过看代码不影响

![](images/20241217134959-c05d4064-bc3a-1.png)

![](images/20241217135004-c3b5158e-bc3a-1.png)

然后我们开始部署war包，把下载好的war包放到tomcat/webapps目录下，然后启动tomcat

启动完成之后访问:<http://127.0.0.1:8080/DocSystem>

这里我本地环境搞过一次了，不清楚哪里没删干净有缓存，正常访问页面会先要求创建用户，先创建一个管理员

创建完成后来到后台管理，在系统管理中选择数据库设置

![](images/20241217135011-c7657336-bc3a-1.png)

创建对应数据库并配置账号密码然后测试连接，连接成功的话选择重置数据库，系统会创建对应的表结构

![](images/20241217135016-cad84e62-bc3a-1.png)

然后这里一定要保存设置，不然系统的很多sql语句查询不会走数据库会走本地缓存文件

![](images/20241217135029-d25ecefe-bc3a-1.png)

我看了下这套系统没隔一段时间会自己备份数据，这里可以自己先手动导入一下sql文件

备份文件路径：\webapps\docSys.ini\backup\

根据时间导入最新的就行，导入完成后重启tomcat

![](images/20241217135036-d67b27a8-bc3a-1.png)

能监听到sql执行就可以了

# 漏洞挖掘

## 多处SQL注入

项目中发现存在mybatis依赖(项目的外部包在DocSystem\WEB-INF\lib中)

这个lib是war包解压出来的，源码没有

![](images/20241217135104-e75023a8-bc3a-1.png)

全局搜索关键词**${**

![](images/20241217135110-ead3ded4-bc3a-1.png)

有不少，我们随便点一个看下

文件路径：src/com/DocSystem/mapping/UserMapper.xml

![](images/20241217135116-ee7ea9d8-bc3a-1.png)

这里参数是name，对应的方法是queryUserWithParamLike，数据类型是HashMap,跳转到queryUserWithParamLike方法，到dao层，查看使用

![](images/20241217135123-f246622c-bc3a-1.png)

![](images/20241217135128-f5b2a146-bc3a-1.png)

往上跟到功能层

![](images/20241217135133-f8996dd6-bc3a-1.png)

![](images/20241217135138-fba38502-bc3a-1.png)

访问对应路由**/getUserList.do**

![](images/20241217135144-ff07c8d4-bc3a-1.png)

然后这里参数是**userName**，**pageIndex**，**pageSize**构造一下

![](images/20241217135153-048a0984-bc3b-1.png)

在username设置为\*，sqlmap一把搜哈

![](images/20241217135158-078d7968-bc3b-1.png)

存在注入，这里提一个醒，sqlmap使用的python版本不要太高，我本地python11跑不出注入，换10版本可以

## 文件操作类挖掘

这套系统是个文件管理系统，我们肯定是优先关注它的文件操作方面

系统可以创建仓库，我们可以先改下他创建仓库的默认地址

![](images/20241217135246-242a85c0-bc3b-1.png)

不然会默认创建在C盘

![](images/20241217135254-288dcd7a-bc3b-1.png)

访问我们创建好的仓库

![](images/20241217135259-2bf1e7d0-bc3b-1.png)

### 任意文件上传

先看下文件上传，随便上传一个文件抓下包

![](images/20241217135305-2f42a096-bc3b-1.png)

获取到路由uploadDoc.do，参数重点关注path和name

跳转到对应代码段看下

![](images/20241217135310-325d5190-bc3b-1.png)

这个方法代码有点多，做了一堆校验，但是没看到path和name的校验，直接看上传处理的部分

```
if(uploadFile != null) 
        {
            if(commitMsg == null || commitMsg.isEmpty())
            {
                commitMsg = "上传 " + path + name;
            }
            String commitUser = reposAccess.getAccessUser().getName();
            String chunkParentPath = Path.getReposTmpPathForUpload(repos,reposAccess.getAccessUser());
            List<CommonAction> actionList = new ArrayList<CommonAction>();
            boolean ret = false;
            if(dbDoc == null || dbDoc.getType() == 0)
            {
                ret = addDoc(repos, doc, 
                        uploadFile,
                        chunkNum, chunkSize, chunkParentPath,commitMsg, commitUser, reposAccess.getAccessUser(), rt, actionList);
                writeJson(rt, response);

                if(ret == true)
                {
                    executeCommonActionList(actionList, rt);
                    deleteChunks(name,chunkIndex, chunkNum,chunkParentPath);
                }                   
            }
            else
            {
                ret = updateDoc(repos, doc, 
                        uploadFile,  
                        chunkNum, chunkSize, chunkParentPath,commitMsg, commitUser, reposAccess.getAccessUser(), rt, actionList);                   

                writeJson(rt, response);    
                if(ret == true)
                {
                    executeCommonActionList(actionList, rt);
                    deleteChunks(name,chunkIndex, chunkNum,chunkParentPath);
                    deletePreviewFile(doc);
                }
            }
```

这里也没看到校验path和name，然后这里两个方法addDoc，updateDoc，一个添加文件，一个更新文件底层代码没区别

我这里跟addDoc

![](images/20241217135321-38b117c0-bc3b-1.png)

接着跟addDoc\_FSM方法，接着会来到updateRealDoc方法，这里会重新获取上传文件的路径和名称

![](images/20241217135326-3c25f952-bc3b-1.png)

然后使用FileUtil.saveFile保存文件，跟到这里也没看到path的处理，那么这里存在目录穿越

我们尝试构造上传path

![](images/20241217135332-3fb85740-bc3b-1.png)

成功上传到根目录

![](images/20241217135339-43ce81ce-bc3b-1.png)

如果这里和tomcat在一个磁盘知道tomcat路径就可以上传而已jsp文件到wabapps目录

![](images/20241217135349-495deb84-bc3b-1.png)

### 文件写入

![](images/20241217135357-4e80602e-bc3b-1.png)

抓包看下

![](images/20241217135407-543c60da-bc3b-1.png)

定位对应代码段

![](images/20241217135412-5715a6ae-bc3b-1.png)

前面的代码校验了用户权限和检测了文件是否存在，文件不存在则报错，那么这里只能考虑文件覆盖，但是不影响，因为这套系统新建文件的功能点同样可以跨目录

我们重点看出来文件写入的代码

![](images/20241217135417-5a629330-bc3b-1.png)

调用 updateRealDocContent 方法更新文档内容，这里path没有看到校验

![](images/20241217135422-5d7c4aa2-bc3b-1.png)

调用 saveRealDocContentEx 方法保存文档内容，继续跟进

![](images/20241217135431-624f6e1a-bc3b-1.png)

最后使用FileUtil.saveDataToFile方法保存，这里path直接从doc中获取没有检查，那么这里就存在目录穿越

![](images/20241217135436-6591843c-bc3b-1.png)

### 文件读取

这个在文件的预览和打开功能处

![](images/20241217135442-6925f9ac-bc3b-1.png)

抓包看路由和参数

![](images/20241217135446-6bca04dc-bc3b-1.png)

定位对应代码段，我这里就不放重复代码了，直接处理文件读取的部分

![](images/20241217135451-6ea29192-bc3b-1.png)

这里会检查文件类型，文本类型调用readRealDocContentEx方法，跟进

![](images/20241217135457-71e99e0e-bc3b-1.png)

这里依旧没有看到路径检测，那么这里就存在目录穿越问题

![](images/20241217135503-7583a064-bc3b-1.png)

### 任意文件删除

代码和读取上传没差多少，同样没校验path和name，这里就复现下，感兴趣自己下去跟

![](images/20241217135511-7a809130-bc3b-1.png)
