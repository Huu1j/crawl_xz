# 某info开源系统getshell漏洞挖掘-先知社区

> **来源**: https://xz.aliyun.com/news/17892  
> **文章ID**: 17892

---

**审计过程：**在入口文件admin/index.php中：

![image.png](images/img_17892_000.png)

用户可以通过m,c,a等参数控制加载的文件和方法，在app/system/entrance.php中存在重点代码：

![image.png](images/img_17892_001.png)

当M\_TYPE == 'system'并且M\_MODULE == 'include'时，会设置常量PATH\_OWN\_FILE为PATH\_APP.M\_TYPE.'/'.M\_MODULE.'/module/'

也就是路径：/app/system/include/module 这个文件夹，这个点非常重要。

M\_MODULE的值在入口文件中，通过参数传递，导致我们可以控制：

![image.png](images/img_17892_002.png)

M\_TYPE的值如下图所示：

![image.png](images/img_17892_003.png)

这里M\_NAME的值是由我们输入的，只要不赋值即可让M\_TYPE的值为system。

所以通过对参数m的控制可以设置常量PATH\_OWN\_FILE为/app/system/include/module 这个点非常重要，后续会用到。

继续往后会执行load::module()方法：

![image.png](images/img_17892_004.png)

![image.png](images/img_17892_005.png)

当module方法不传递任何参数时，会使用默认的参数值，也就是$path = ''，所以这里也就会将$path 的值设置为PATH\_OWN\_FILE，也就是路径：/app/system/include/module

后续的$modulename，$action变量的值也就是我们开头的通过参数a，c控制的值。

![image.png](images/img_17892_006.png)

后续进行self::\_load\_class($path, $modulename, $action);参数的实现如下：

![image.png](images/img_17892_007.png)

该方法就是将文件进行加载进来，并且new出该类的对象后，通过call\_user\_func进行方法的调用。

我们可以在/app/system/include/module目录下寻找到符合xxx.class.php的文件，如：/app/system/include/module/loadtemp.class.php 在给文件中存在doviewHtml方法是我们可以通过web进行调用的：

![image.png](images/img_17892_008.png)

该自研框架通过$\_M['form']['path'];等方式获取到用户的输入，等同于$\_POST['path']

最后一路执行会来到$view->dofetch的地方：

![image.png](images/img_17892_009.png)

这里我们完全可控$file参数：

![image.png](images/img_17892_010.png)

继续跟进fetch方法：

![image.png](images/img_17892_011.png)

跟进display方法：

![image.png](images/img_17892_012.png)

![image.png](images/img_17892_013.png)

重点关注$this->compile();//执行编译：

![image.png](images/img_17892_014.png)

![image.png](images/img_17892_015.png)

![image.png](images/img_17892_016.png)

在执行编译中，将我们输入的文件路径进行了内容读取，将读取后的内容写入到了$this->view->compileFile文件中，返回到开始的display方法中：

![image.png](images/img_17892_017.png)

通过include编译文件造成了任意代码执行漏洞。

### **文件上传处****：**

/app/system/include/module/uploadify.class.php 文件中的doupfile方法：

![image.png](images/img_17892_018.png)

![image.png](images/img_17892_019.png)

![image.png](images/img_17892_020.png)

可以直接上传白名单内的文件，配合上面的文件包含，造成任意代码执行漏洞。

漏洞复现：

![image.png](images/img_17892_021.png)

**修复建议：官网已经发布补丁，请及时更新补丁升级版本。**
