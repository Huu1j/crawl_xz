# 一键过滤burpsuite杂包，实现精准抓包-先知社区

> **来源**: https://xz.aliyun.com/news/17040  
> **文章ID**: 17040

---

# 概述

burpsuite会抓到很多包，但很多并不是我们想要的，比如重复的，或者我只想抓取某一个域名的包，却抓取了所有网站的包，今天聊一些流量过滤的技巧，学会以后对效率会有很大提升

​

# Proxy SwitchyOmega

**概述**

这个代理插件应该不用介绍了吧，很常用的

![图片.png](images/de5c0cd6-3ac4-3cf9-8bfa-a04010c9c438)

**​**

**屏蔽网站，不进行代理**

将不想被代理的网站添加到不代理的地址列表即可

![图片.png](images/2a25f185-4d31-3910-9eeb-cb0a929a2a49)

**网站定点代理**

对指定网站进行代理，只会代理该网站的数据包，不会抓取该浏览器打开的其他网站，这个挺好用，我一直用的这种方法，相比上面那个我更喜欢这个，当然你可以联合起来用

![图片.png](images/a1930cee-316a-38eb-88fe-7424a0433898)

# Knife

**概述**

这是一个burpsuite插件，功能很多，但是我只使用了流量过滤功能，我使用的场景为比如我想抓百度的包，但是有一个百度的包一直在重复发，会影响查看正常的数据包，这时候就需要根据url进行匹配过滤掉这个包，这时候用knife这个插件就很方便

**​**

**使用**

默认界面，有很多功能

![图片.png](images/6aa9987c-42c7-33a0-8c1e-45e6eebc2e1f)删除了其他配置项，只留下流量过滤

![图片.png](images/5e9ae202-3d8c-3f12-ba16-6f222f4eea7a)假如我不想访问csdn，可以进行如下配置

knife中进行配置

![图片.png](images/e3515763-81c5-35b8-93ee-8ad3ab8947bc)history勾选

![图片.png](images/7366fa05-14d4-303b-95cf-daac17a746df)或者直接在历史数据包中进行配置

![图片.png](images/7c42d2e7-c0f8-39e7-9cfa-fa38b747c8fa)![图片.png](images/0e55eb60-b680-3848-8850-96d5ad1b0850)

**​**

**配置功能解释**

```
丢弃
Action_Drop_Request_If_Host_Matches 如果后续再次遇到当前Host的任何URL，自动丢弃（drop），不发送请求。

Action_Drop_Request_If_URL_Matches 如果后续再次遇到当前的URL，自动丢弃（drop），不发送请求。

Action_Drop_Request_If_Keyword_Matches 如果后续的URL中包含制定的关键词，自动丢弃（drop），不发送请求。

转发

Action_Forward_Request_If_Host_Matches 如果后续再次遇到当前Host的任何URL，自动放过（Forward），不做拦截。

Action_Forward_Request_If_URL_Matches 如果后续再次遇到当前的URL，自动放过（Forward），不做拦截。

Action_Forward_Request_If_Keyword_Matches 如果后续的URL中包含制定的关键词，自动放过（Forward），不做拦截。

丢弃和转发的异同：
两者都可以过滤网站数据包，但是丢弃会导致被屏蔽的的网站无法访问，因为经过burpsuite的流量直接被丢弃了没有发出去，转发则可以正常访问
可根据具体需求配置
```

# 相关工具

项目地址：

<https://github.com/bit4woo/knife>

夸克网盘：

<https://pan.quark.cn/s/ac32975ef62c>
