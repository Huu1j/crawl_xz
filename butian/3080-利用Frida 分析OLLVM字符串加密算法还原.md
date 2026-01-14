# 利用Frida 分析OLLVM字符串加密算法还原

> **来源**: https://forum.butian.net/share/3080  
> **文章ID**: 3080

---

**利用Frida 分析OLLVM字符串加密算法还原**
----------------------------

最近在网上学习OLLVM字符串加密算法还原这个技术，这里简单记录下，以这方面的样本为例，来分析下

代码审计java层

```php
public class HelloJni extends AppCompatActivity {
    TextView tv;

    public native String sign1(String str);

    public native String stringFromJNI();

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // android.support.v7.app.AppCompatActivity, android.support.v4.app.FragmentActivity, android.support.v4.app.SupportActivity, android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(com.example.hellojni_sign2.R.layout.activity_hello_jni);
        this.tv = (TextView) findViewById(com.example.hellojni_sign2.R.id.hello_textview);
        this.tv.setText(stringFromJNI());
        ((Button) findViewById(com.example.hellojni_sign2.R.id.button_sign1)).setOnClickListener(new View.OnClickListener() { // from class: com.example.hellojni.HelloJni.1
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                HelloJni.this.tv.setText(HelloJni.this.sign1(RandomStringUtils.randomAscii(16)));
            }
        });
    }

    static {
        System.loadLibrary("hello-jni");
    }
}
```

其中HelloJni.this.tv.setText(HelloJni.this.sign1(RandomStringUtils.randomAscii(16)));为主要java层代码分析，发现这里调用了sign1函数，sign1在native层，按照常规操作，我们去看native层，如下（由于本人太懒，这里不截图了贴出关键代码）：

第一步我们先看JNI\_OnLoad，可能一开始不会像一下代码的样子，这里修复了一些环境变量：

```php
jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
  jint v2; // w19
  JNIEnv *v4; // x20
  jclass v5; // x0
  JNIEnv *v6; // [xsp+8h] [xbp-48h] BYREF
  __int128 v7; // [xsp+10h] [xbp-40h] BYREF
  __int64 (__fastcall *v8)(); // [xsp+20h] [xbp-30h]
  __int64 v9; // [xsp+28h] [xbp-28h]

  v9 = *(_QWORD *)(_ReadStatusReg(ARM64_SYSREG(3, 3, 13, 0, 2)) + 40);
  v6 = 0LL;
  v2 = 65540;
  if ( (*vm)->GetEnv(vm, (void **)&v6, 65540LL) )
    return -1;
  v4 = v6;
  v8 = sub_E76C;
  v7 = *(_OWORD *)&sign1;
  v5 = (*v6)->FindClass(v6, &xmmword_37050);
  if ( !v5
    || (((__int64 (__fastcall *)(JNIEnv *, jclass, __int128 *, __int64))(*v4)->RegisterNatives)(v4, v5, &v7, 1LL) & 0x80000000) != 0 )
  {
    return -1;
  }
  return v2;
}
```

其中|| (((**int64 (**fastcall \*)(JNIEnv \*, jclass, **int128 \*,** int64))(\*v4)->RegisterNatives)(v4, v5, &v7, 1LL) & 0x80000000) != 0 ) 这部分注册了一个native v7，起初v7并没有分析出就是sign1函数，因为ollvm字符串加密的缘故,这里贴出脚本，用来辅助分析ollvm字符串的加密

stringollvmen.js:

```php
function print_hex(addr) {
    var base_hello_jni = Module.findBaseAddress("libhello-jni.so");
    console.log(hexdump(base_hello_jni.add(addr)));   //sign1  打印内存
}
```

其实直接打印对应的内存地址就可以了

第二部我们需要找出sign1的具体函数地址，由于ollvm字符串的加密原因加上代码多很难找到，这时候我们依靠frida辅助去找具体sign1的函数地址，通过以下脚本即可找到：

findSign1.js:

```php
function hook_sign1() { //寻找registernative在库里的地址并查询sign1在so的函数地址

    var module_libart = Process.findModuleByName("libart.so");
    console.log(module_libart);
    var addr_RegisterNatives = null;
    var addr_GetStringUTFChars = null;
    var addr_NewStringUTF = null;
    //枚举模块的符号
    var symbols = module_libart.enumerateSymbols();
    for (var i = 0; i < symbols.length; i++) {
        var name = symbols[i].name;
        if (name.indexOf("CheckJNI") == -1 && name.indexOf("JNI") > 0) {
            if (name.indexOf("RegisterNatives") > 0) {
                console.log(name);
                addr_RegisterNatives = symbols[i].address;
            }

        }
    }
    console.log(addr_RegisterNatives)
    if (addr_RegisterNatives) {
        Interceptor.attach(addr_RegisterNatives, {
            onEnter: function (args) {
                var java_class = Java.vm.tryGetEnv().getClassName(args[1]);
                console.log(java_class);
                var methods = args[2];
                var method_count = parseInt(args[3]);
                console.log("addr_RegisterNatives java_class:", java_class, "method_count:", method_count);
                for (var i = 0; i < method_count; i++) {
                    console.log(methods.add(i * Process.pointerSize * 3).readPointer().readCString());
                    console.log(methods.add(i * Process.pointerSize * 3 + Process.pointerSize).readPointer().readCString());
                    var fnPtr = methods.add(i * Process.pointerSize * 3 + Process.pointerSize * 2).readPointer();
                    var module_so = Process.findModuleByAddress(fnPtr);
                    console.log(module_so);
                    console.log(module_so.name + "addr: " + fnPtr.sub(module_so.base));  //sign1函数地址

                }
            }, onLeave: function (retval) {

            }
        })
    }

}
```

通过以下命令运行：

frida -U -f xxxx（包名） -l findSign1.js

找到了具体的sign1的地址位置在0xE76C 处，我们分析下sign1的代码逻辑,分析在注释里，按照逆向逻辑从小当上分析：

```php
jstring __fastcall sin1(JNIEnv *env, __int64 a2, void *a3)
{
  const char *v5; // x21
  unsigned __int64 v6; // x0
  __int64 v7; // x22
  char *v8; // x23
  unsigned __int64 v9; // x24
  char *v10; // x0
  unsigned __int64 v11; // x1
  jstring v12; // x19
  unsigned __int64 v14; // [xsp+8h] [xbp-98h] BYREF
  __int64 v15; // [xsp+10h] [xbp-90h]
  void *ptr; // [xsp+18h] [xbp-88h]
  char s[16]; // [xsp+20h] [xbp-80h] BYREF
  __int128 v18; // [xsp+30h] [xbp-70h] BYREF
  __int64 value; // [xsp+48h] [xbp-58h] BYREF
  __int64 v20; // [xsp+50h] [xbp-50h]
  __int64 v21; // [xsp+58h] [xbp-48h]

  v21 = *(_QWORD *)(_ReadStatusReg(ARM64_SYSREG(3, 3, 13, 0, 2)) + 40);
  v5 = (*env)->GetStringUTFChars(env, a3, 0LL); //获取传入的值
  v15 = 0LL;
  ptr = 0LL;
  v14 = 0LL;
  v6 = strlen(v5);
  v7 = v6;
  if ( v6 >= 0x17 )
  {
    v9 = (v6 + 16) & 0xFFFFFFFFFFFFFFF0LL;
    v8 = (char *)operator new(v9);
    v14 = v9 | 1;
    v15 = v7;
    ptr = v8;
    goto LABEL_5;
  }
  v8 = (char *)&v14 + 1;
  LOBYTE(v14) = 2 * v6;
  if ( v6 )
LABEL_5:
    memcpy(v8, v5, v7);
  v8[v7] = 0;
  (*env)->ReleaseStringUTFChars(env, a3, v5);
  if ( (v14 & 1) != 0 )
    v10 = (char *)ptr;
  else
    v10 = (char *)&v14 + 1;
  if ( (v14 & 1) != 0 )
    v11 = (unsigned int)v15;
  else
    v11 = (unsigned __int64)(unsigned __int8)v14 >> 1;
  value = 0LL;
  v20 = 0LL;
  sub_103F0(v10, v11, &value);
  *(_OWORD *)s = 0u;
  v18 = 0u; 
  sprintf(s, &byte_37040, (unsigned __int8)value);   //这一串继续了复制打印  
  sprintf(&s[2], &byte_37040, BYTE1(value)); //这一串继续了复制打印
  sprintf(&s[4], &byte_37040, BYTE2(value));//这一串继续了复制打印
  sprintf(&s[6], &byte_37040, BYTE3(value));//这一串继续了复制打印
  sprintf(&s[8], &byte_37040, BYTE4(value));//这一串继续了复制打印
  sprintf((char *)((unsigned __int64)s | 0xA), &byte_37040, BYTE5(value));//这一串继续了复制打印
  sprintf((char *)((unsigned __int64)s | 0xC), &byte_37040, BYTE6(value));//这一串继续了复制打印
  sprintf((char *)((unsigned __int64)s | 0xE), &byte_37040, HIBYTE(value));//这一串继续了复制打印
  sprintf((char *)&v18, &byte_37040, (unsigned __int8)v20);//这一串继续了复制打印
  sprintf((char *)&v18 + 2, &byte_37040, BYTE1(v20));//这一串继续了复制打印
  sprintf((char *)&v18 + 4, &byte_37040, BYTE2(v20));//这一串继续了复制打印
  sprintf((char *)&v18 + 6, &byte_37040, BYTE3(v20));//这一串继续了复制打印
  sprintf((char *)&v18 + 8, &byte_37040, BYTE4(v20));//这一串继续了复制打印
  sprintf((char *)&v18 + 10, &byte_37040, BYTE5(v20));//这一串继续了复制打印
  sprintf((char *)&v18 + 12, &byte_37040, BYTE6(v20));//这一串继续了复制打印
  sprintf((char *)&v18 + 14, &byte_37040, HIBYTE(v20));//这一串继续了复制打印
  v12 = (*env)->NewStringUTF(env, s);   //进行了最后的结果
  if ( (v14 & 1) != 0 )
    operator delete(ptr);
  return v12;
}
```

这里方便分析我们利用frida hook打印出GetStringUTFChars和NewStringUTF的值，脚本如下：

1.js

```php
function hook_libart() { //寻找registernative在库里的地址并查询sign1在so的函数地址

    var module_libart = Process.findModuleByName("libart.so");
    console.log(module_libart);
    var addr_RegisterNatives = null;
    var addr_GetStringUTFChars = null;
    var addr_NewStringUTF = null;
    //枚举模块的符号
    var symbols = module_libart.enumerateSymbols();
    for (var i = 0; i < symbols.length; i++) {
        var name = symbols[i].name;
        if (name.indexOf("CheckJNI") == -1 && name.indexOf("JNI") > 0) {
            if (name.indexOf("RegisterNatives") > 0) {
                console.log(name);
                addr_RegisterNatives = symbols[i].address;
            }
            else if (name.indexOf("GetStringUTFChars") > 0) {
                console.log(name);
                addr_GetStringUTFChars = symbols[i].address;
            } else if (name.indexOf("NewStringUTF") > 0) {
                console.log(name);
                addr_NewStringUTF = symbols[i].address;
            }

        }
    }
    console.log(addr_RegisterNatives)
    if (addr_RegisterNatives) {
        Interceptor.attach(addr_RegisterNatives, {
            onEnter: function (args) {
                var java_class = Java.vm.tryGetEnv().getClassName(args[1]);
                console.log(java_class);
                var methods = args[2];
                var method_count = parseInt(args[3]);
                console.log("addr_RegisterNatives java_class:", java_class, "method_count:", method_count);
                for (var i = 0; i < method_count; i++) {
                    console.log(methods.add(i * Process.pointerSize * 3).readPointer().readCString());
                    console.log(methods.add(i * Process.pointerSize * 3 + Process.pointerSize).readPointer().readCString());
                    var fnPtr = methods.add(i * Process.pointerSize * 3 + Process.pointerSize * 2).readPointer();
                    var module_so = Process.findModuleByAddress(fnPtr);
                    console.log(module_so);
                    console.log(module_so.name + "!" + fnPtr.sub(module_so.base));  //sign1函数地址

                }
            }, onLeave: function (retval) {

            }
        })
    }
    if (addr_GetStringUTFChars) {
        Interceptor.attach(addr_GetStringUTFChars, {
            onLeave : function(retval) {
                console.log("[GetStringUTFChars] : ", ptr(retval).readCString());
            }
        })
    }
    if (addr_NewStringUTF) {
        Interceptor.attach(addr_NewStringUTF, {
            onEnter : function(args) {
                console.log("[NewStringUTF] : ", ptr(args[1]).readCString());
            }
        })
    }
}
```

通过打印发现，我们可以看出GetStringUTFChars是获取的值（也就是java层传入的结果）即HelloJni.this.tv.setText(HelloJni.this.sign1(RandomStringUtils.randomAscii(16))); 这里是随机化的值，NewStringUTF值是通过一系列运算后的结果，也是主要我们分析算法的逻辑，这里我们先把java传入的值给它固定下来，hook下java层代码，脚本如下：

```php
function hook_java(){
    Java.perform(function(){
        var hellojni=Java.use("com.example.hellojni.HelloJni");
        hellojni.sign1.implementation=function(args){
            // var result=args;
            // result="0123456789abcdef";
            // console.log("args: ",args);
            return this.args("0123456789abcdef");
        }
    })
}
```

然后再测试下运行上面的1.js脚本，发现GetStringUTFChars的值已经被固定了，接下来就通过最后的NewStringUTF结果来具体还原算法，继续回过头看native层代码

```php
sprintf(s, &byte_37040, (unsigned __int8)value);
  sprintf(&s[2], &byte_37040, BYTE1(value));
  sprintf(&s[4], &byte_37040, BYTE2(value));
  sprintf(&s[6], &byte_37040, BYTE3(value));
  sprintf(&s[8], &byte_37040, BYTE4(value));
  sprintf((char *)((unsigned __int64)s | 0xA), &byte_37040, BYTE5(value));
  sprintf((char *)((unsigned __int64)s | 0xC), &byte_37040, BYTE6(value));
  sprintf((char *)((unsigned __int64)s | 0xE), &byte_37040, HIBYTE(value));
  sprintf((char *)&v18, &byte_37040, (unsigned __int8)v20);
  sprintf((char *)&v18 + 2, &byte_37040, BYTE1(v20));
  sprintf((char *)&v18 + 4, &byte_37040, BYTE2(v20));
  sprintf((char *)&v18 + 6, &byte_37040, BYTE3(v20));
  sprintf((char *)&v18 + 8, &byte_37040, BYTE4(v20));
  sprintf((char *)&v18 + 10, &byte_37040, BYTE5(v20));
  sprintf((char *)&v18 + 12, &byte_37040, BYTE6(v20));
  sprintf((char *)&v18 + 14, &byte_37040, HIBYTE(v20));
```

这里我们看下value的交叉引用按X键，看下谁在用它，通过查看发现 sub\_103F0(v10, v11, &value);在调用，我们进去看下具体代码实现逻辑，在里面具体代码如下：

```php
void __fastcall sub_1005C(char *a1, signed int a2, __int64 result_buufer)
{
  unsigned __int64 v6; // x0
  __int64 v7; // x22
  char *v8; // x23
  unsigned __int64 v9; // x24
  __int64 v10; // x8
  size_t v11; // w0
  size_t v12; // w0
  size_t v13; // w0
  unsigned __int64 v14; // x9
  bool v15; // w8
  unsigned __int64 i; // x24
  char *v17; // x8
  unsigned __int8 v18; // w9
  __int64 v19; // x8
  _BYTE *v20; // x0
  unsigned __int64 v21; // x9
  __int64 v22; // x24
  unsigned __int64 v23; // x8
  __int64 v24; // x22
  int j; // w19
  __int64 _result_bufefr; // [xsp+8h] [xbp-188h]
  __int64 v27[3]; // [xsp+10h] [xbp-180h] BYREF
  unsigned __int64 v28; // [xsp+28h] [xbp-168h] BYREF
  __int64 v29; // [xsp+30h] [xbp-160h]
  void *ptr; // [xsp+38h] [xbp-158h]
  __int128 v31; // [xsp+40h] [xbp-150h] BYREF
  __int128 v32; // [xsp+50h] [xbp-140h]
  __int128 v33; // [xsp+60h] [xbp-130h]
  __int128 v34[12]; // [xsp+70h] [xbp-120h] BYREF
  __int64 v35; // [xsp+130h] [xbp-60h]

  v35 = *(_QWORD *)(_ReadStatusReg(ARM64_SYSREG(3, 3, 13, 0, 2)) + 40);
  v31 = 0uLL;
  v32 = xmmword_2B310;
  v33 = xmmword_2B320;
  v29 = 0LL;
  ptr = 0LL;
  v28 = 0LL;
  v6 = strlen((const char *)&qword_37110);
  v7 = v6;
  _result_bufefr = result_buufer;
  if ( v6 >= 0x17 )
  {
    v9 = (v6 + 16) & 0xFFFFFFFFFFFFFFF0LL;
    v8 = (char *)operator new(v9);
    v28 = v9 | 1;
    v29 = v7;
    ptr = v8;
    goto LABEL_5;
  }
  v8 = (char *)&v28 + 1;
  LOBYTE(v28) = 2 * v6;
  if ( v6 )
LABEL_5:
    memcpy(v8, &qword_37110, v7);
  v8[v7] = 0;
  v10 = lrand48() % 3;  //随机数，由于每次点击结果不一样可能使用了rand，也是我们主要hook的位置固定下即可
  switch ( v10 )
  {
    case 2LL:
      v13 = strlen(&byte_3712C);
      sub_103F4((int)&v28, &byte_3712C, v13);
      break;
    case 1LL:
      v12 = strlen(&byte_37124);
      sub_103F4((int)&v28, &byte_37124, v12);
      break;
    case 0LL:
      v11 = strlen(&byte_3711C);
      sub_103F4((int)&v28, &byte_3711C, v11);
      break;
  }
  v14 = v29;
  if ( (v28 & 1) == 0 )
    v14 = (unsigned __int64)(unsigned __int8)v28 >> 1;
  v15 = (v28 & 1) == 0;
  if ( v14 )
  {
    for ( i = 0LL; i < v21; ++i )
    {
      v27[1] = 0LL;
      v27[2] = 0LL;
      v27[0] = 2LL;
      if ( v15 )
        v17 = (char *)&v28 + 1;
      else
        v17 = (char *)ptr;
      v18 = v17[i];
      v19 = v31 & 0x3F;
      *(_WORD *)((char *)v27 + 1) = v18;
      *(_QWORD *)&v31 = (unsigned int)(v31 + 1);
      if ( !(_DWORD)v31 )
        ++*((_QWORD *)&v31 + 1);
      v20 = (char *)v34 + v19;
      if ( v19 && (unsigned int)(64 - v19) <= 1 )
      {
        memcpy(v20, (char *)v27 + 1, 64 - v19);
        sub_F008(&v31, v34);
      }
      else
      {
        *v20 = BYTE1(v27[0]);
      }
      v21 = v29;
      if ( (v28 & 1) == 0 )
        v21 = (unsigned __int64)(unsigned __int8)v28 >> 1;
      v15 = (v28 & 1) == 0;
    }
  }
  if ( a2 >= 1 )
  {
    v22 = v31 & 0x3F;
    v23 = (unsigned int)(v31 + a2);
    *(_QWORD *)&v31 = v23;
    if ( v23 < a2 )
      ++*((_QWORD *)&v31 + 1);
    if ( v22 )
    {
      v24 = (unsigned int)(64 - v22);
      if ( (int)v24 <= a2 )
      {
        memcpy((char *)v34 + v22, a1, 64 - v22);
        sub_F008(&v31, v34);
        v22 = 0LL;
        a1 += v24;
        a2 -= v24;
      }
    }
    if ( a2 >= 64 )
    {
      for ( j = a2; j > 63; j -= 64 )
      {
        sub_F008(&v31, a1);
        a1 += 64;
      }
      a2 &= 0x3Fu;
    }
    if ( a2 >= 1 )
      memcpy((char *)v34 + v22, a1, a2);
  }
  sub_FD90(&v31, _result_bufefr);
  memset(v34, 0, sizeof(v34));
  v32 = 0u;
  v33 = 0u;
  v31 = 0u;
  if ( (v28 & 1) != 0 )
    operator delete(ptr);
}
```

我们继续用交叉引用看下result\_buufer的位置，按照逆向逻辑步骤来我们在最后面发现 sub\_FD90(&v31, \_result\_bufefr);在使用这个变量，我们进去分析下

```php
void *__fastcall sub_FD90(unsigned __int64 *a1, __int64 result_buufer)
{
  __int64 v2; // x10
  unsigned __int64 v4; // x8
  unsigned __int64 v5; // x9
  unsigned __int64 v7; // x26
  unsigned __int64 v8; // x12
  unsigned __int64 v9; // x25
  unsigned __int64 v10; // x9
  __int64 v11; // x22
  __int64 **v12; // x21
  unsigned __int64 v13; // x8
  unsigned __int64 v14; // x9
  __int64 v15; // x22
  char *v16; // x21
  size_t v17; // w25
  void *result; // x0
  char v19[4]; // [xsp+0h] [xbp-50h] BYREF
  __int16 v20; // [xsp+4h] [xbp-4Ch]
  char v21; // [xsp+6h] [xbp-4Ah]
  char v22; // [xsp+7h] [xbp-49h]
  __int64 v23; // [xsp+8h] [xbp-48h]

  v2 = 120LL;
  v23 = *(_QWORD *)(_ReadStatusReg(ARM64_SYSREG(3, 3, 13, 0, 2)) + 40);
  v5 = *a1;
  v4 = a1[1];
  v7 = *a1 & 0x3F;
  v8 = (8 * v4) | (*a1 >> 29);
  v19[0] = 8 * *a1;
  if ( v7 < 0x38 )
    v2 = 56LL;
  v19[1] = v5 >> 5;
  v9 = v2 - v7;
  v19[2] = v5 >> 13;
  v21 = BYTE2(v8);
  v19[3] = v5 >> 21;
  v20 = v8;
  v22 = BYTE3(v8);
  if ( (int)v2 - (int)v7 < 1 )
    goto LABEL_11;
  v10 = (unsigned int)(v9 + v5);
  *a1 = v10;
  if ( v10 < v9 )
    a1[1] = v4 + 1;
  if ( !v7 )
  {
    v12 = &off_2B330;
    if ( (int)v9 >= 64 )
      goto LABEL_23;
LABEL_9:
    if ( (int)v9 < 1 )
      goto LABEL_11;
    goto LABEL_10;
  }
  v11 = (unsigned int)(64 - v7);
  v12 = &off_2B330;
  if ( (int)v11 > (int)v9 )
  {
    if ( (int)v9 < 64 )
      goto LABEL_9;
    goto LABEL_23;
  }
  memcpy((char *)a1 + v7 + 48, &off_2B330, 64 - v7);
  sub_F008(a1, a1 + 6);                         // 貌似md5 0xD76AA478
  v7 = 0LL;
  v12 = (__int64 **)((char *)&off_2B330 + v11);
  LODWORD(v9) = v9 - v11;
  if ( (int)v9 < 64 )
    goto LABEL_9;
LABEL_23:
  sub_F008(a1, v12);
  v12 += 8;
  LODWORD(v9) = v9 & 0x3F;
  if ( (int)v9 >= 1 )
LABEL_10:
    memcpy((char *)a1 + v7 + 48, v12, v9);
LABEL_11:
  v13 = *a1 & 0x3F;
  v14 = (unsigned int)*a1 + 8;
  *a1 = v14;
  if ( (unsigned int)v14 <= 7 )
    ++a1[1];
  if ( !v13 )
  {
    v16 = v19;
    v17 = 8;
    goto LABEL_18;
  }
  v15 = (unsigned int)(64 - v13);
  v16 = v19;
  v17 = 8;
  if ( (unsigned int)v15 > 8 )
  {
LABEL_18:
    result = memcpy((char *)a1 + v13 + 48, v16, v17);
    goto LABEL_19;
  }
  memcpy((char *)a1 + v13 + 48, v19, 64 - v13);
  result = (void *)sub_F008(a1, a1 + 6);
  v17 = 8 - v15;
  if ( 8 - (int)v15 >= 1 )
  {
    v13 = 0LL;
    v16 = &v19[v15];
    goto LABEL_18;
  }
LABEL_19:
  *(_WORD *)result_buufer = a1[2];
  *(_BYTE *)(result_buufer + 2) = BYTE2(a1[2]);
  *(_BYTE *)(result_buufer + 3) = BYTE3(a1[2]);
  *(_WORD *)(result_buufer + 4) = a1[3];
  *(_BYTE *)(result_buufer + 6) = BYTE2(a1[3]);
  *(_BYTE *)(result_buufer + 7) = BYTE3(a1[3]);
  *(_WORD *)(result_buufer + 8) = a1[4];
  *(_BYTE *)(result_buufer + 10) = BYTE2(a1[4]);
  *(_BYTE *)(result_buufer + 11) = BYTE3(a1[4]);
  *(_WORD *)(result_buufer + 12) = a1[5];
  *(_BYTE *)(result_buufer + 14) = BYTE2(a1[5]);
  *(_BYTE *)(result_buufer + 15) = BYTE3(a1[5]);
  return result;
}
```

这里看下最后结果是什么，脚本如下：

```php
function hook_native() {  //sub_FD90(unsigned __int64 *a1, __int64 result_buufer)   
    var base_hello_jni = Module.findBaseAddress("libhello-jni.so");
    Interceptor.attach(base_hello_jni.add(0xFD90), {
        onEnter : function(args) {
            this.arg0 = args[0];    //hook sub_FD90函数的第一个参数
            this.arg1 = args[1];
        }, onLeave : function(retval) {  //将返回结果打印
            console.log("0xFD90:\r\n", hexdump(this.arg0), "\r\n", hexdump(this.arg1));
        }
    });
}
```

看到传入的参数值，这里再往上分析发现一个类似md5加密的函数sub\_F008 貌似md5 0xD76AA478，那么我们去hook打印这个加密的参数值，由于前面的lrand48随机化的函数，。我们先把随机化的返回结果给固定了，这里hook脚本如下（由于lrand48是libc的函数，直接hooklibc的返回值去触发它即可）：

```php
function hook_libc(){
    var lrand48=Module.findExportByName("libc.so","lrand48");
    Interceptor.attach(lrand48,{
        onLeave : function(retval){
            console.log("lrand48_value: ",retval);
            retval.replace(0xAAAAAAAA);  //固定值替换
            console.log("defind_lrand48: ",retval);
        }
    })
}
```

下面我们就可以去hook打印sub\_F008 （即加密函数值），脚本如下：

```php
function hook_native() {  //sub_FD90(unsigned __int64 *a1, __int64 result_buufer)   
    var base_hello_jni = Module.findBaseAddress("libhello-jni.so");
    Interceptor.attach(base_hello_jni.add(0xFD90), {
        onEnter : function(args) {
            this.arg0 = args[0];    //hook sub_FD90函数的第一个参数
            this.arg1 = args[1];
        }, onLeave : function(retval) {  //将返回结果打印
            console.log("0xFD90:\r\n", hexdump(this.arg0), "\r\n", hexdump(this.arg1));
        }
    });

    Interceptor.attach(base_hello_jni.add(0xF008), {
        onEnter : function(args) {
            this.arg0 = args[0];    
            this.arg1 = args[1];
        }, onLeave : function(retval) {
            console.log("0xF008:\r\n", hexdump(this.arg0), "\r\n", hexdump(this.arg1));
            console.log("0xF008:", ptr(this.arg1).readCString());
        }
    });
}
```

我们发现打印了一串名文字符串"+++++++++salt2+0123456789abcdef"，把这个字符串拿去md5加密，发现和我们的app应用程序结果是一样的，至此还原算法结束，此app应用程序的整题逻辑如下：

.datadiv\_decode OLLVM混淆的字符串的解密函数=======》md5("+++++++++salt2+" + "0123456789abcdef") = 5a6ecb4b69e035e521bf582135281509

结语：通过frida可以帮助我们分析ollvm 字符串加密算法的还原，也熟悉了frida在so层更深的利用技巧
