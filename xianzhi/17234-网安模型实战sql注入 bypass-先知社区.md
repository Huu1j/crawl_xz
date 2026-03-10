# 网安模型实战sql注入 bypass-先知社区

> **来源**: https://xz.aliyun.com/news/17234  
> **文章ID**: 17234

---

本次是攻防演练当中的一次sql注入 bypass随笔记录。也是第一次使用网安模型进行渗透测试。

![image.png](images/de6c07ab-edeb-3971-bfad-c0c44b3c17ad)

可以看到这是一个档案管理系统，首先就是判断是否存在SQL注入

![image.png](images/9fcffdbc-b753-3004-ae38-085c7ca89dd6)

Burp抓包正常登陆后，提示账号或密码错误

输入单引号之后报错

![image.png](images/8f04db6e-8492-37c1-a3f2-bb542ae349a9)

两个单引号正常![image.png](images/d5f28a44-897e-3f98-89c0-653ba55082da)

证明有很大的可能存在SQL注入。

服务器使用的是aspx，而且末尾加上--可以正常返回，所以大概率是mssql数据库。

构造一下闭合。试试or 1=1.

admin' or'1'=1，发现直接被WAF拦截了。

![image.png](images/286ba4c5-a3f1-37e7-b6fb-7aecfaf58302)

后续的bypass为了节约时间就直接用的AI来处理。

我这里用的是无问AI模型，感觉在网安方面的问题处理能力还是很不错的，相比其他的那些模型回答的要专业很多。

地址：http://chat.wwlib.cn

需要登录后才能用。

![image.png](images/407fa8e0-8f59-395d-a56f-c722f0d22983)

![image.png](images/893e801e-c868-3e8d-bedd-caf5895db4fd)

这里是给了我10余种绕过方法。逐一进行尝试之后。发现'+str(1/1)+' 可成功绕过

![image.png](images/7151ac09-ff93-3125-9c76-55d59af16e44)

果然，1/1是正常的。而1/0会报错，由此可以看出我们可以根据真和假来构造注入了

![image.png](images/cfcc4c59-651f-3096-8813-894cb76ed9eb)

通过无问AI给我们的提示，我们先来判断user的长度

Payload: admin'+str(1/(len(user)-1))+'

![image.png](images/3b842bc9-c43b-3fa6-9646-6d0bdd092c89)

减1正常，我们就一直试，发现到-3时，又报错了，说明user的长度为3

![image.png](images/8b2bd85d-a54a-3819-973e-01ec9703ef94)

到这里，我们才终于能够确定user的长度。接下来，就是跑他的值了，我们继续求助无问AI

![image.png](images/965dafd3-4deb-3a5f-b9ad-a590ff6ccb78)

AI建议我们使用substring来测试，那我们直接substring试试看。这里我们使用ascii码来判断user的值。

![image.png](images/1e02100a-b04a-34ff-b805-642ddfaf3007)

通过尝试发现100报错，说明第一位为d

![image.png](images/d98418c4-defa-3ffa-a43c-60b46089bda7)

第二位98，那就是b。

![image.png](images/ccd65560-2d22-354f-8627-121a921315cb)

第三位111 那就是o

连起来就是dbo。

至此，证明user的值位dbo。

​

总结

这次的测试还是很流畅的，至少补齐了我bypass waf的短板。

也不得不说这个模型在渗透测试上确实是能提供很有价值的技术辅助。
