# 域渗透之Kerberos FAST突破

> **来源**: https://forum.butian.net/share/2828  
> **文章ID**: 2828

---

本章主要讲述了从突破域内kerbero-FAST安全机制以及向AS(Authentication Service)申请服务票据带来的危害性

kerberos认证回顾
============

- 简单回顾一下kerberos认证的过程，前四步是本文的重点。 1.用户向DC请求TGT 2.KDC返回TGT,该TGT使用密钥加密。 3.用户发送请求向KDC请求服务票据(ST)，并携带TGT 4.KDC使用密钥解密并验证TGT，验证无误后返回使用server密码加密的ST。 5.用户使用ST访问服务 6.服务器验证。

如图所示，图的出处来自[adsecurity](https://adsecurity.org/?p=1515)

![图片.png](images/attach-cb01109d56ffb86b2dc6f2354c253562224e8d0a.png)

AS-REP Roasting攻击
=================

- kerberos预认证使kerberos认证的第一步，用于防止爆破，在AS-REP中，KDC返回了客户端TGT和用于访问服务的会话密钥，该会话密钥使用客户端的密码进行加密，假如域内某个用户设置了"不需要kerberos预身份验证"，如图所示，攻击者可以指定用户请求票据，从而获得TGT和密钥进行离线爆破。

![图片.png](images/attach-7ab19cb106fbf794b46a2cba1c7e9be63234653a.png)

- AS-REP Roasting攻击演示 1.使用[Rubeus](https://github.com/GhostPack/Rubeus)进行AS-REP Roasting攻击获得hash。

![图片.png](images/attach-e91640a7e455e2d51deb5594cec33269b105e06f.png)

2.使用john对hash进行离线爆破，如果所示

![图片.png](images/attach-10ef2df4c3e563814ccfec77dd6118908e7b3af0.png)

kerbersting
===========

- kerbersting攻击介绍

在kerberos认证第四步完成后，进行kerberos认证的域用户将会收到service ticket，该票据使用目标服务的NTLM HASH进行加密，加密算法为RC4-HMAC，这时候我们就能使用相同的算法模拟生成ST，对获得的ST进行离线枚举。

- 为了方便下文的理解，我这里不适用Rubeus+kerberoast参数进行kerbersting，而是将kerbersting攻击分成三步

1.查找域内SPN，如图所示

![图片.png](images/attach-eafb5114821f1ef4523de2d32e4fd95c0a4d61f3.png)

2.利用Adminsitrator申请TGT，如图所示

![图片.png](images/attach-9b9c03d9022e4b73b575f2f731fddc81ab2624f3.png)

3.利用TGT申请服务票据，该服务票据用于访问cifs/stu1.jctest.com,票据使用lowuser用户的hash加密。如图所示

![图片.png](images/attach-9b1290f28240fb13f370e421293faf9e275a47d1.png)

4.对票据进行离线爆破,获取lowuser的密码

![图片.png](images/attach-0cfc137f4181b1db4b25cc65718d2ef83aff90b5.png)

FAST
====

回顾完了AS-REP Roasting攻击和kerbersting攻击，接下来讲一下一种域内安全机制-"Flexible Authentication Secure Tunneling",简称为FAST，值得一提的是开启FAST能很好的防御如nopac这类型漏洞，且配置简单，但很多企业并未开启。

- FAST介绍 在Windows-Server-2012中Active Directory开启了新功能FAST,FAST全称 Flexible Authentication Secure Tunneling，即灵活的身份验证隧道，该功能会监听在域服务中，旨在解决kerberos的安全问题，其在客户端和KDC之间提供了受到保护的传输通道，相当于在kerberos认证过程中加"盐",配置FAST后会让强制获得密钥变得困难，下面来测试一下。
- FAST配置

1.在组策略中找到KDC选项,将”KDC支持声明、复合身份认证和kerberos Armoring“选项设置为失败的非armoring身份验证请求，如图所示

![图片.png](images/attach-dbe9a4c5d9cb740972dbc6d3960525091a261290.png)  
2.在kerberos选项中启用“kerberos客户端支持声明、复合身份认证和kerberos Armoring”选项

![图片.png](images/attach-961fa05b9b16a5ab1050fd1a6d0cab768e9bc75e.png)  
3.更新组策略  
`gpupdate`

- FAST验证：

1. 未开启FAST前请求域用户的TGT票据(成功)

![图片.png](images/attach-fde9141dd6155f691169b55d14c8bf56b2264a2b.png)

2. 开启FAST后请求域用户TGT票据(失败)

![图片.png](images/attach-3756d3dd874ecec4ccd07f8b311f71f874db2817.png)

3. 开启FAST后使用TGT请求ST票据(失败)

![图片.png](images/attach-1fab0cc70fa05eff4327f336b745f9c98b47b5ce.png)

4. 开启FAST后进行 AS-REP Roasting攻击(失败)

![图片.png](images/attach-605c41971267be7f354ccc31d8579722fd87765b.png)

这样一来我们就可以发现，我们已经无法再去强制KDC返回对应用户的TGT，假如这个行为被阻拦，很多域内的攻击就无法进行，如票据传递、AS-REP Roasting利用等一系列需要申请TGT的攻击手法。正如上文中提到的kerbersting攻击手法也无法实现，因为该攻击手法需要先申请TGT，再去申请st，最终可以得出结论，FAST的配置，确实使kerberos认证变得更加安全。

FAST绕过
======

- 最近，研究员Charlie Clark发现了一件有趣的事情，在他发布的[文章](https://adsecurity.org/?p=1515)中指出，在AS-req请求的过程中，将req-body中的sname指定SPN时会返回该服务的ST票据，这一发现也就实现了不通过TGS而是通过AS来申请ST票据，同时他还发现，在开启FAST配置后，机器账户的as\_req请求被没有收到保护，接下来我们来试验一下，在开启FAST的情况下使用机器账户向AS认证服务器请求指定SPN的服务票据(ST)

1. 使用powermad申请机器用户，如果所示

`import-module .\\powermad.ps1 New-MachineAccount -MachineAccount fastbypass -Domain jctest.com -DomainController xxxxxx.jctest.com`

![图片.png](images/attach-92af959b19f83078f1ddd6931fa1291b3e648922.png)

2.在开启FAST的情况下使用机器账户申请TGT

![图片.png](images/attach-4f69d2be2e698cc4aa312474a14aa3aebcda3a99.png)

我们可以发现，使用机器账号能够在FAST开启的情况下申请TGT，其还是使用传统kerberos认证协议，如图所示

![图片.png](images/attach-13173d8785ccfc83db675efda08ce49f9f7be6e6.png)  
3.然后我们再使用经过Charlie Clark修改后的Rubeus，在发送的过程中将sname指向指定的spn，向AS发送请求使其返回指定的服务票据。只需在使用Rubeus的时候加上/service参数，如图所示

![图片.png](images/attach-3ac3091f2caa6453509ab371088c4230a8ed8a44.png)

4这是我们发现票据中的servicename已经指向了我们指定的spn，这时候使用该票据进行离线爆破可以发现我们已经获取注册该spn的域用户的密码

![图片.png](images/attach-4510e6259dfcab9f18bb611a5ff03beb31417f61.png)

![图片.png](images/attach-f40670b81d82c9dc3616a068a5578d83f5d7bf53.png)

5.此时已经验证了，通过修改snmae可以让AS认证服务器返回ST票据，并且使用机器账户可以绕过FAST机制来申请TGT，但是这种绕过存在一定的限制，我们都知道"CVE-2021-42287&42278"漏洞利用需要通过申请机器账户来请求TGT，然后利用TGT去通过s4uself协议申请ST票据，这时候就会发现，即使能绕过FAST申请TGT，但是还是无法去通过s4uself申请ST票据，如图所示

![图片.png](images/attach-9a4fe8e3922deed64cdd1674178f8c4771f6310b.png)

向AS申请服务票据的拓展
============

- 现在假设一个场景，我们拿下一台域内机器，但是我们没有任何的账号密码，而常规的kerbersoting攻击是需要一个域内任何用户的身份，但是我们只要发现了域内开启了不需要预认证的用户，再利用该用户通过AS认证服务请求ST票据，就可以实现不需要域内用户身份实现kerberosting
- 但还有一个问题就是，申请服务票据，我们得知道域内服务的spn名称，才能指定要申请的服务票据，这个问题在[该文章](https://swarm.ptsecurity.com/kerberoasting-without-spns/)得到解决，作者Sharoglazov指出，在没有SPN名称的情况下进行kerberosting，并且将该功能添加到了impacket下，如图所示

![图片.png](images/attach-baf2da33e1a892f3beb9ea25834aa4c210630085.png)  
最新的rubeus同样也实现了该功能

- 如此一来，我们就可以从域外实现从配置了不需要域认证的用户进行krberoasting。

1.假如我们现在是一台域外的机器，且没有任何账号密码，但我们知道了域名和域控的IP，使用kerbrute对域内用户进行枚举

![图片.png](images/attach-5b101c71ea146ea9278dcd83549b784aae00fcf6.png)

2.得到用户列表之后对用户列表进行探测，发现配置了不需要预认证的用户

![图片.png](images/attach-6146287ae95f31cfa3413de7e013e054f769dee0.png)

3.使用rubeus利用connect用户进行kerberoasting攻击，如图所示

![图片.png](images/attach-be771c26f71a3ff50552cb2ea3d6c170f3183177.png)

4.利用hashcat成功破解出密码

![图片.png](images/attach-7f3826bbf71190f6285c959f590642c1dd82b9ad.png)

5.查看数据包我们可以看到，每一次as\_req请求的cname都是connect，正是配置了不需要预认证的用户。

![图片.png](images/attach-03324deadd6d3c0e5df548336e7d82e263883977.png)

6.根据Sharoglazov[的文章](https://swarm.ptsecurity.com/kerberoasting-without-spns/)中指出，在kerberos认证的过程中，当向TGS请求服务票据的时候，将TGS-REQ请求的sname值改成SPN所属的账户的samaccountname值，请求并不会发生异常，那么这里的利用AS请求的ST票据也是同理，只要将AS-REQ中的sname值改成SPN所属用户的samaccountname值即可，例如我们的lowuser用户注册了一个spn，如图所示

![图片.png](images/attach-3344fa6fc05bb6b4f9457ffe2141a476b65547bf.png)  
7.然后在rebeus的请求过程中我们可以发现其将sname改成了lowuser用户对应的samaccountname值。

![图片.png](images/attach-46cd30b1f0135698e5765220d5ca27120f224e42.png)

8.最终实现了，在不知道用户密码和SPN的情况下，通过配置了不需要预认证的用户进行了kerberoasting。
