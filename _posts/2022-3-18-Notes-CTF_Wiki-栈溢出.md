---
layout: post
title: "栈溢出入门"
categories: 
  - Notes
tags:
  - Pwn
last_modified_at: 2022-03-18T22:00:52+08:00
---

## 栈溢出入门

> 关于栈溢出，平时课程中已经有一定的了解，就是程序写入的字节数超过了申请的字节数，导致改变了其它变量的值，覆盖了其它内容

**checksec工具**

- 对ELF可执行文件进行扫描，检查其开启了哪些保护机制
- 可以通过github下载，Linux也可以直接使用`apt-get install checksec`安装
- 一些基本检查项
  - Arch：程序架构信息，以及大小端
  - Stack：No canary是没有开启堆栈溢出保护
    - Canary时随机产生的值，放到紧挨EBP的上一个位置
    - 当使用缓冲区溢出覆盖EBP或者EBP下方的返回地址时，会覆盖掉Canary的值
    - 程序结束时会检查Canary和之前是否一致，从而避免缓冲取溢出攻击
  - NX：开了NX保护，堆、栈、bss端就没有执行权限了
  - PIE：这个东西会将汇编的基址打乱，程序运行时依旧会在加载一个固定的基址上（不过和No PIE时基址不同）
  - RELRO（ASLR）：地址空间随机化，同PIE配合真正打乱基址

**栈溢出步骤**

- 寻找危险函数
  - gets，scanf，vscanf，sprintf，strcpy，strcat，bcopy等
- 确定填充长度
  - 相对于栈基地址的索引，如EBP-0x14
  - 相对应栈顶指针的所以，如ESP+0x14
  - 直接地址索引
- 覆盖需求
  - 覆盖函数返回地址，直接看EBP即可
  - 覆盖栈上某个变量的内容，精确计算位置
  - 覆盖bss段上某个变量的内容
  - 根据现实执行情况，覆盖特定的变量或地址的内容
