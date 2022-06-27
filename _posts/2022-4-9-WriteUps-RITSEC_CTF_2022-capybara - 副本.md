---
layout: post
title: "RITSEC_CTF_2022 - capybara"
categories: 
  - WriteUps
tags:
  - WP
  - PWN
  - RITSEC_CTF2022
last_modified_at: 2022-03-18T22:00:52+08:00
---

###Reverse/soup

一道经典逆向题，典型的出题思路是给你密文，考查一些加密算法，求出加密前的明文

之后有机会出题的话，大概逆向签到水题就是按这个思路去出

另外，请一定看好是否是考察加密算法的，曾经我憨憨地对着sha256解了半天，真是不堪回首的往事

- 这个题的话考察RC4加密算法

> RC4加密算法介绍：
>
> - 对称密码算法（加密和解密使用相同密钥），只要不泄露密钥，几乎不可能破解
>
> - 序列密码（也称为流密码），可变密钥长度
>
> - 工作方式是输出反馈，所以可以用一个短的密钥产生一个相对较长的密钥序列
>
> 加密步骤：
>
> 1. 密钥调度算法KSA
>
>    - 初始化状态向量S（256个字节，用来作为密钥流生成的种子）
>
>      - 即0,1,2,3,4,....,254,255
>
>    - 对状态向量S使用密钥进行替换
>
>      - 密钥流是短的密钥循环生成的，如密钥是abcde，密钥流就是abcdeabcdeabcde...（256字节）
>
>    - ```
>      len = strlen(key);
>      j = 0;
>      for ( i = 0; i <= 255; ++i )
>        S[i] = i;
>      for ( i_0 = 0; i_0 <= 255; ++i_0 )
>      {
>        j = (S[i_0] + j + key[i_0 % len]) % 256;
>        swap(&S[i_0], &S[j]);
>      }
>      ```
>
> 2. 密钥生成算法PRGA
>
>    - 通过伪随机数生成算法PRGA得到密钥流
>
>    - 密钥流与明文进行xor运算得到密文，解密用密钥流与密文进行xor运算
>
>    - ```
>      i = 0;
>      j = 0;
>      n = 0;
>      len = strlen(plaintext);
>      while ( n < len )
>      {
>        i = (i + 1) % 256;
>        j = (j + S[i]) % 256;
>        swap(&S[i], &S[j]);
>        ciphertext[n] = S[(S[i] + S[j]) % 256] ^ plaintext[n];
>        ++n;
>      }
>      ```

- 说回本题，拿到一个文件
- 查看文件格式，个人习惯是用file命令去查看，有的题通过用Winhex去查看文件头来查看格式

```
soup: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), 
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=7fa6c40f4517a13c2d0030df48c44a54788e5f5d, 
for GNU/Linux 3.2.0, with debug_info, not stripped
```

- ELF文件石锤，果然很典型
- 拖到IDA里按下F5反编译，打开main函数

```
  v9 = __readfsqword(0x28u);  // 一般都会看到，通常用于alarm函数，防止调试
  if ( argc > 2 )			  // 参数要大于2
  {
    v4 = strlen(argv[2]);
    ciphertext = (unsigned __int8 *)malloc(4 * v4);
    RC4((char *)argv[1], (char *)argv[2], ciphertext); // RC4算法实锤
    uwu = (unsigned __int8 *)malloc(0x20uLL);
    qmemcpy(uwu, "855E6EAD057B46A9D75F3E072F350438", 32);  // 加密后的密文
    sprintf(
      out,
   "%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX
   %02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX",
      *ciphertext,
      ciphertext[1],
      ciphertext[2],
      ciphertext[3],
      ciphertext[4],
      ciphertext[5],
      ciphertext[6],
      ciphertext[7],
      ciphertext[8],
      ciphertext[9],
      ciphertext[10],
      ciphertext[11],
      ciphertext[12],
      ciphertext[13],
      ciphertext[14],
      ciphertext[15]);
    for ( i = 0; i <= 32; ++i )
    {
      if ( out[i] != uwu[i] )
      {
        puts("Try a different order!");
        return 0;
      }
    }
    puts("You got your soup!");
    result = 0;
  }
  else
  {
    puts("Please order your soup correctly!");
    printf("Usage: %s <soup> <L33t_S0UP>\n", *argv);
    result = -1;
  }
  return result;
```

- `v9 = __readfsqword(0x28u);`一般都会看到，通常用于alarm函数，防止调试

- `RC4((char *)argv[1], (char *)argv[2], ciphertext)`明确看到了RC4算法
  - `int __cdecl RC4(char *key, char *plaintext, unsigned __int8 *ciphertext)`
  - 在反编译界面打开RC4函数，又看到了KSA和PRGA函数，打开看了下，原版RC4算法
- `qmemcpy(uwu, "855E6EAD057B46A9D75F3E072F350438", 32);`后面有个for循环专门用来判断out和uwu
  - 很明显，这就是加密后的密文了
  - 正好是16个字节
- `%02hhx`这里值得一提，如果你还在想怎么才能输出自对齐十六进制大写的话，这个格式值得借鉴
  - python的话可以用`%02X`

- `printf("Usage: %s <soup> <L33t_S0UP>\n", *argv);`

  - 第一个`%s`是argv[0]，也就是`./soup`
  - 第二个`<soup>`是argv[1]，在打开RC4函数后发现这个位置传入的是`key`
  - 第三个`<l33t_s0UP>`是argv[2]，在打开RC4函数后发现这个位置传入的是`plaintext`

  - > 一开始犯蠢，把<l33t_s0UP>看成密钥，解了半天都是错的QWQ

- 总结一下，密钥是`soup`，加密后的密文是`0x855E6EAD057B46A9D75F3E072F350438`

- RC4知道了密钥，解密就不是问题了

- 这里是自己写的RC4解密的脚本，也可以用网上的在线解密

```
key = "soup"
ciper_hex = "855E6EAD057B46A9D75F3E072F350438"
ciper = [int(ciper_hex[i*2 : i*2+2], 16) for i in range(16)]
plain = [0 for i in range(16)]
# print(ciper)
# print(''.join("%02X"%ciper[i] for i in range(16)))

# KSA function
llen = len(key)
s = [i for i in range(256)]
j = 0
for i in range(256):
    j = (s[i] + j + ord(key[i % llen])) % 256
    s[i], s[j] = s[j], s[i]

# PRGA function
llen = len(ciper)
i = 0
j = 0
for n in range(llen):
    i = (i + 1) % 256
    j = (j + s[i] ) % 256
    s[i], s[j] = s[j], s[i]
    plain[n] = ciper[n] ^ s[(s[i]+s[j])%256]

print(''.join(chr(plain[i]) for i in range(llen)))
```

- 得到的明文是`BR0CC0L1_CH3DD@R`，则flag是`RS{BR0CC0L1_CH3DD@R}`