# 浅谈Go web中的Tar解压缩漏洞-先知社区

> **来源**: https://xz.aliyun.com/news/16641  
> **文章ID**: 16641

---

## Go web中的tar解压漏洞

在Go语言的Web开发中，处理文件上传和压缩文件（如tar文件）时，确实需要注意一些安全漏洞，其中之一就是tar文件中的路径遍历漏洞。这种漏洞允许攻击者通过精心构造的tar文件，将文件解压到任意目录，从而覆盖重要文件或执行其他恶意操作。

下面以一个Go-Web项目为例调试分析，主要源码如下auth.go

```
// controllers/auth.go  
package controllers  
  
import (  
    "Gotar/config"  
    "Gotar/db"    "Gotar/models"    "Gotar/utils"    "html/template"    "net/http"  
    "golang.org/x/crypto/bcrypt"    "gorm.io/gorm")  
  
// RegisterHandler 处理用户注册请求  
func RegisterHandler(w http.ResponseWriter, r *http.Request) {  
    // 如果是 POST 请求，则处理表单提交  
    if r.Method == http.MethodPost {  
       // 从表单中获取用户名和密码  
       username := r.FormValue("username")  
       password := r.FormValue("password")  
  
       // 使用 bcrypt 对密码进行哈希处理  
       hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)  
       if err != nil {  
          http.Error(w, "Failed to hash password", http.StatusInternalServerError)  
          return  
       }  
  
       // 创建一个新的用户对象，并将哈希后的密码存储在数据库中  
       user := models.User{Username: username, Password: string(hashedPassword)}  
       result := db.DB.Create(&user)  
       if result.Error != nil {  
          http.Error(w, "Failed to create user", http.StatusInternalServerError)  
          return  
       }  
  
       // 注册成功后重定向到登录页面  
       http.Redirect(w, r, "/login", http.StatusSeeOther)  
       return  
    }  
  
    // 如果不是 POST 请求，则渲染注册页面模板  
    tmpl := template.Must(template.ParseFiles("assets/register.html"))  
    tmpl.Execute(w, nil)  
}  
  
// LoginHandler 处理用户登录请求  
func LoginHandler(w http.ResponseWriter, r *http.Request) {  
    // 加载环境变量配置  
    config.LoadEnv()  
  
    // 如果是 POST 请求，则处理表单提交  
    if r.Method == http.MethodPost {  
       // 从表单中获取用户名和密码  
       username := r.FormValue("username")  
       password := r.FormValue("password")  
  
       // 根据用户名查询用户信息  
       var user models.User  
       result := db.DB.Where("username = ?", username).First(&user)  
       if result.Error != nil {  
          // 如果用户不存在，返回未授权错误  
          if result.Error == gorm.ErrRecordNotFound {  
             http.Error(w, "Invalid username or password", http.StatusUnauthorized)  
             return  
          }  
          // 其他数据库查询错误，返回内部服务器错误  
          http.Error(w, "Failed to query user", http.StatusInternalServerError)  
          return  
       }  
  
       // 验证用户提供的密码是否匹配数据库中的哈希密码  
       err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))  
       if err != nil {  
          http.Error(w, "Invalid username or password", http.StatusUnauthorized)  
          return  
       }  
  
       // 生成 JWT 令牌  
       token, err := utils.GenerateJWT(user.ID, user.IsAdmin, config.JWTKey)  
       if err != nil {  
          http.Error(w, "Failed to generate token", http.StatusInternalServerError)  
          return  
       }  
  
       // 设置 token Cookie       http.SetCookie(w, &http.Cookie{  
          Name:  "token",  
          Value: token,  
          Path:  "/",  
       })  
  
       // 登录成功后重定向到主页  
       http.Redirect(w, r, "/", http.StatusSeeOther)  
       return  
    }  
  
    // 如果不是 POST 请求，则渲染登录页面模板  
    tmpl := template.Must(template.ParseFiles("assets/login.html"))  
    tmpl.Execute(w, nil)  
}  
  
// LogoutHandler 处理用户登出请求  
func LogoutHandler(w http.ResponseWriter, r *http.Request) {  
    // 清除 token Cookie，使用户登出  
    http.SetCookie(w, &http.Cookie{  
       Name:   "token",  
       Value:  "",  
       Path:   "/",  
       MaxAge: -1, // MaxAge 为负数表示立即删除 Cookie    })  
  
    // 登出后重定向到登录页面  
    http.Redirect(w, r, "/login", http.StatusSeeOther)  
}
```

并且有中间件验证jwt

```
package middleware  
  
import (  
    "Gotar/config"  
    "Gotar/utils"    "context"    "net/http"  
    "github.com/golang-jwt/jwt")  
  
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {  
    // 返回一个新的 HTTP 处理函数，该处理函数会在调用 next 之前执行认证逻辑  
    return func(w http.ResponseWriter, r *http.Request) {  
       // 尝试从请求中获取名为 "token" 的 Cookie       cookie, err := r.Cookie("token")  
       if err != nil {  
          // 如果获取 Cookie 失败（例如用户未登录或 Cookie 不存在），重定向到 "/logout"          http.Redirect(w, r, "/logout", http.StatusSeeOther)  
          return  
       }  
  
       // 获取 token 的值  
       tokenStr := cookie.Value  
       // 创建一个 Claims 对象用于存储解析后的 JWT 声明  
       claims := &utils.Claims{}  
  
       // 解析 JWT 并验证签名  
       token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {  
          // 使用配置中的 JWT 密钥进行签名验证  
          return config.JWTKey, nil  
       })  
       if err != nil {  
          // 如果签名无效，返回 401 未授权错误  
          if err == jwt.ErrSignatureInvalid {  
             http.Error(w, "Unauthorized", http.StatusUnauthorized)  
             return  
          }  
          // 其他错误情况，返回 400 错误请求，并提示可能是黑客攻击  
          http.Error(w, "Bad request! Hacker!!!", http.StatusBadRequest)  
          return  
       }  
       // 如果 token 无效，返回 401 未授权错误  
       if !token.Valid {  
          http.Error(w, "Unauthorized", http.StatusUnauthorized)  
          return  
       }  
  
       // 将用户 ID 和管理员状态添加到请求上下文中  
       ctx := context.WithValue(r.Context(), "userID", claims.UserID)  
       ctx = context.WithValue(ctx, "isAdmin", claims.IsAdmin)  
  
       // 调用下一个处理函数，并将带有新上下文的请求传递给它  
       next.ServeHTTP(w, r.WithContext(ctx))  
    }  
}
```

file.go

```
package controllers  
  
import (  
    "Gotar/db"  
    "Gotar/models"    "fmt"    "html/template"    "io"    "net/http"    "os"    "path/filepath"    "strings"  
    "github.com/whyrusleeping/tar-utils")  
  
const (  
    uploadDir    = "./assets/uploads"  
    extractedDir = "./assets/extracted"  
)  
  
// UploadHandler 处理文件上传请求  
func UploadHandler(w http.ResponseWriter, r *http.Request) {  
    // 检查请求方法是否为 POST    if r.Method != http.MethodPost {  
       http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)  
       return  
    }  
  
    // 解析 multipart form 数据，设置最大文件大小为 10MB    err := r.ParseMultipartForm(10 << 20) // 10MB limit  
    if err != nil {  
       http.Error(w, "Failed to parse form", http.StatusBadRequest)  
       return  
    }  
  
    // 获取上传的文件  
    file, header, err := r.FormFile("file")  
    if err != nil {  
       http.Error(w, "Failed to retrieve file", http.StatusBadRequest)  
       return  
    }  
    defer file.Close() // 确保文件关闭  
  
    // 从上下文中获取当前用户 ID    userID := r.Context().Value("userID").(uint)  
  
    // 构建保存文件的路径，包含用户 ID 以确保文件隔离  
    filePath := filepath.Join(uploadDir, fmt.Sprintf("%d_%s", userID, header.Filename))  
    //    文件覆盖../../../config/.env  
    // 创建目标文件  
    outFile, err := os.Create(filePath)  
    if err != nil {  
       http.Error(w, "Failed to create file", http.StatusInternalServerError)  
       return  
    }  
    defer outFile.Close() // 确保文件关闭  
  
    // 将上传的文件内容复制到目标文件中  
    _, err = io.Copy(outFile, file)  
    if err != nil {  
       http.Error(w, "Failed to save file", http.StatusInternalServerError)  
       return  
    }  
  
    // 如果是 tar 文件，则解压到指定目录  
    extractedPath, err := extractTar(filePath, userID)  
    if err != nil {  
       http.Error(w, fmt.Sprintf("Failed to extract file: %v", err), http.StatusInternalServerError)  
       return  
    }  
  
    // 创建文件记录并保存到数据库  
    fileRecord := models.File{  
       UserID:        userID,  
       Name:          header.Filename,  
       Path:          filePath,  
       ExtractedPath: extractedPath,  
    }  
    db.DB.Create(&fileRecord)  
  
    // 重定向到文件列表页面  
    http.Redirect(w, r, "/files", http.StatusSeeOther)  
}  
  
// FilesHandler 处理文件列表请求  
func FilesHandler(w http.ResponseWriter, r *http.Request) {  
    // 查询所有文件记录  
    var files []models.File  
    db.DB.Find(&files)  
  
    // 渲染文件列表模板  
    tmpl := template.Must(template.ParseFiles("assets/files.html"))  
    tmpl.Execute(w, map[string]interface{}{  
       "Files": files,  
    })  
}  
  
// DownloadHandler 处理文件下载请求  
func DownloadHandler(w http.ResponseWriter, r *http.Request) {  
    // 从上下文中获取当前用户 ID    userID := r.Context().Value("userID").(uint)  
  
    // strings.TrimPrefix(r.URL.Path, "/download/")：移除 URL 路径中的 /download/ 前缀。  
    //strings.TrimSuffix(..., "/")：移除可能存在的末尾斜杠。最终得到的是文件 ID 字符串。  
    fileID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/download/"), "/")  
  
    // 根据文件 ID 和用户 ID 查询文件记录  
    var file models.File  
    result := db.DB.Where("id = ? AND user_id = ?", fileID, userID).First(&file)  
    if result.Error != nil {  
       http.Error(w, "File not found or access denied", http.StatusNotFound)  
       return  
    }  
  
    // 使用 ServeFile 发送文件给客户端  
    http.ServeFile(w, r, file.ExtractedPath)  
}  
  
// extractTar 解压 tar 文件到指定目录  
func extractTar(tarPath string, userID uint) (string, error) {  
    // 构建用户专属的解压目录  
    userDir := filepath.Join(extractedDir, fmt.Sprintf("%d", userID))  
  
    //os.ModePerm 是一个常量，值为 0777（八进制），表示最大权限（读、写、执行）。  
    err := os.MkdirAll(userDir, os.ModePerm) //递归地创建一个目录及其所有必要的父目录  
    if err != nil {  
       return "", err  
    }  
  
    // 打开 tar 文件  
    tarFile, err := os.Open(tarPath)  
    if err != nil {  
       return "", err  
    }  
    defer tarFile.Close()  
  
    // 创建一个 TarExtractor 实例并进行解压  
    extractor := &tar.Extractor{  
       Path: userDir,  
    }  
    err = extractor.Extract(tarFile)  
    if err != nil {  
       return "", err  
    }  
  
    // 返回解压后的目录路径  
    return userDir, nil  
}
```

审计代码，发现主要是文件上传、解压缩、下载，打开页面第一个为flag文件，但是下载不了因为没有jwt admin权限![](images/1621e225-075f-3a4b-956a-7338768e2d72)config下的加载配置文件函数会默认加载`.env``.env`中的存放的是jwtkey

```
JWT_SECRET=Hacker!!!Is_secret!!!
```

![](images/5043a428-1852-3e06-b4ee-e8f565ac5f19)

跟踪进文件解压处理函数，发现能够处理文件、目录以及软链接![](images/955a8902-ad42-3f47-8e38-8ccfd1d568c9)

* 使用 `tarReader.Next()` 逐个读取 tar 文件中的条目（文件、目录、符号链接等）。
* 对每个条目根据其类型 (`Typeflag`) 进行处理：
* `tar.TypeDir`：调用 `extractDir` 方法处理目录。
* `tar.TypeReg`：调用 `extractFile` 方法处理普通文件，并传递 `rootExists` 和 `rootIsDir` 参数以决定如何处理根目录。
* `tar.TypeSymlink`：调用 `extractSymlink` 方法处理符号链接。
* 如果遇到未知类型的条目，则返回错误信息。
* 当读取到文件末尾（`io.EOF`）时，退出循环。

并且因为每次登录账户都会重新调用加载env文件，那么我们想能不能利用解压缩覆盖.env文件![](images/3ecbf48c-f05e-34fc-ac1e-32fe0c6b0aaa)

### tar目录穿越的文件名问题

下面需要探究tar目录穿越的文件名问题跟踪进底层源码中的解压文件函数发现第一个处理路径方法`outputPath`![](images/a6266944-219b-3285-8288-72f8eebe959e)

调试跟进发现把路径字符串的第一个切片丢掉了，所以实际在这里我们需要回退四个目录也就是`../../../../config/.env`，但是如果你的文件名为`/../../../.env` 就只用三层，因为切片是按`/`划分的。![](images/f894fcff-378d-3864-8f8c-e51d4138168f)

#### P参数修改压缩包中路径

下面在linux中创建四层目录，然后再创建`.env`文件后压缩

```
echo "JWT_SECRET=abc" >../../../../.env
tar  -cPvf 11.tar ../../../../.env
```

**注意：**`-P` 选项的作用：

使用 `-P` 选项时，`tar` 会 **保留文件的绝对路径**，包括路径中的 `/`。这意味着无论你在哪个目录中执行 `tar` 命令，`tar` 会将完整的文件路径（从根目录 `/` 开始）包含在归档文件中。在没有使用 `-P` 选项的情况下，`tar` 在归档文件时通常会将文件的路径 **转化为相对路径**。也就是说，它会去掉文件路径的前缀部分

#### transform参数修改路径

或者可以用transform来修改压缩包文件中的路径

```
tar --create --file=hack.tar --transform 's,exp/,exp/../../../,' exp/.env
```

* `--transform` 选项用于修改归档中文件的路径。
* `'s,exp/,exp/../../../,'` 是一个正则替换表达式，意思是把归档文件路径中以 `exp/` 开头的部分替换为 `exp/../../../`。

之后上传后就会覆盖`.env`，重新登陆即可伪造jwt![](images/b74f252c-2120-3f48-8f8c-77f3450ebd7f)
