---
layout: post
title: "基本ROP"
categories: 
  - Notes
tags:
  - Pwn
last_modified_at: 2022-03-18T22:00:52+08:00

---

## 基本ROP

> ROP(Return Oriented Programming)，在栈缓冲区溢出的基础上，利用程序中已有的小片段(gadgets)来改变某些寄存器或者变量的值，从而控制程序的执行流程

**gadget**

- 以ret结尾的指令序列
- 通过这些指令序列，我们可以修改某些地址的内容，方便控制程序的执行流程

**ret2text**

- 控制程序执行程序本身已有代码(.text)