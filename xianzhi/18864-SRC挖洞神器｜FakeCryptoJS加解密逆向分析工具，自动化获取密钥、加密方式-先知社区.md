# SRC挖洞神器｜FakeCryptoJS加解密逆向分析工具，自动化获取密钥、加密方式-先知社区

> **来源**: https://xz.aliyun.com/news/18864  
> **文章ID**: 18864

---

## FakeCryptoJS 简介

CryptoJS常规加解密自吐密钥、加解密方式，快速定位加解密位置(无视混淆)。SRC和常规渗透神器。

GitHub 地址（好用点个star）：<https://github.com/keecth/FakeCryptoJS>

## 使用视频教程

[CryptoJS Hook大法](https://www.bilibili.com/video/BV1e8HQzgExF/?vd_source=0db2ad1c0370be8c178e3df580cfe1d9)

## 工具介绍

FakeCryptoJS 是一个专为开发者和安全研究人员（SRC、渗透测试）设计的油猴脚本。它能够自动识别网页中使用的 CryptoJS 库及其加密方式（例如 AES、DES、RSA），从而显著提高逆向分析和调试的效率。

**主要功能**

* 导出 AES/DES/RSA 加解密方法
* 控制台自动反馈密钥(key、iv)

**运行环境**

* 直接复制代码到控制台执行（小程序）
* 油猴插件自动化执行（浏览器）

## TODO

* 国密算法（演示视频： [SRC挖洞神器—国密sm2自吐密钥、加密算法](https://www.bilibili.com/video/BV115pEzNEy8/)）
