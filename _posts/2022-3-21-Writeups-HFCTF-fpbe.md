---
layout: post
title: "HFCTF2022 - fpbe"
categories: 
  - WriteUps
tags:
  - WP
  - Reverse
  - HFCTF2022
last_modified_at: 2022-03-18T22:00:52+08:00
---

### fpbe

> 一道关于BPF的逆向题

把ELF文件在IDA中打开，看到flag的验证函数uprobed_function，试着对那个验证函数进行破解

发现是对16位flag进行sha256加密，并对最后得到的hash值进行比对

面对没有改过的sha256加密算法，请保持一颗敬畏的心

至今sha256解密的方法还只是“碰撞”，也就是随机生成对应位数的flag，用sha256加密后的码和hash值进行比对

> 之前对sha256加密不熟悉，竟然试着对其进行解密，真是太天真了

---

**在解题之前，先介绍下sha256加密**（毕竟这折磨了我好久）

- sha256_init
  - 对一些值赋初值，datalen、bitlen为0
  - state[0~7]一般初始时选择的值是一样的，至少我查到的是一样的

- sha256_update
  - 将数据进行分组，分为64B即512位一组
  - 将数据存入data[]数组中，并用datalen记录存储的个数
  - 每够一组即datalen=64，会将bitlen的值加512，datalen的值清零，调用一次sha256_transform
- sha256_transform
  - 将64B的数据经过变换得到数组m[0~63]
  - 将计算前state[]的值导出为a,b,c,d,e,f,g,h
  - 进行64次迭代计算
    - h = g，g = f，f = e，d = c，c = b，b = a
    - t1 = (f & e ^ g & ~e) + (ROL(e, 7) ^ ROR(e, 11) ^ ROR(e, 6)) + h + k[i] + m[i]
    - 其中k数组是64个素数，一般使用的k数组是相同的
    - t2 = (ROL(a, 10) ^ ROR(a, 13) ^ ROR(a, 2)) + (a & (c ^ b) ^ c & b)
    - a = t1 + t2，e = d + t1
  - 最后state[0~7]对应加上计算得到的a,b,c,d,e,f,g,h
- sha256_final
  - 将数据最后不足64B的用0补足为64B，注意最后一个字节是该组有效数据的长度（即不包括补足0的比特数）
  - 调用一次sha256_transform
  - 将state[]数组的值导出，作为最后得到的hash值

---

**下面介绍下BPF的内容**

`BPF`是Linux内核中高度灵活且高效的类虚拟机的构造，允许以安全的方式在各个hook点执行字节码。它被用于许多Linux内核子系统中，最主要是网络，跟踪和安全

原始的BPF设计用于捕获和过滤与特定规则相匹配的网络数据包，即伯克利包过滤器(Berkeley Packet Filter)，筛选器被实现为要在基于寄存器的虚拟机上运行的程序。

如今，Linux内核仅运行`eBPF(extended BPF)`，并且在程序执行之前，已加载的`cBPF(classic BPF)`字节码在内核中透明地转换为eBPF表现形式

eBPF程序要经历的过程：

- 创建eBPF程序作为字节码
  - 编写为C代码，然后编译为驻留在**ELF文件**中的eBPF字节编码
  - 将程序加载到内核并创建必要的eBPF映射，是使用bpfLinux中的syscall完成的，此syscall允许加载字节码以及正在加载的eBPF程序类型的声明
- 将加载的程序附加到系统
  - 验证步骤课确保eBPF可以安全运行，不会循环、权限问题、不会崩溃等
  - JIT编译即时编译步骤将程序的通用字节码转换为特定于机器的指令集，以优化程序的执行速度
- 每种eBPF程序类型都有不同的过程来附加到其对应的系统

---

**本题中的BPF**

BPF是实现了一个内核虚拟机的，字节码文件也是ELF文件，通常以单独的文件形式存在或内联编译进程序中。题目只给了ELF，每个BPF字节码文件， 说明内联编译进去了，题目的关键就在于找到BPF的字节码。

在main函数中的fpbe_bpf_open_and_load函数入手，猜测是加载BPF的地方，一直查看函数调用，最终找到fpbe_bpf_create_skeleton函数，可以看到初始化skeleton时也初始化了BPF字节码和BPF程序

```
int __cdecl fpbe_bpf__create_skeleton(fpbe_bpf *obj)
{
  int result; // eax
  bpf_object_skeleton *s; // [rsp+18h] [rbp-8h]

  s = (bpf_object_skeleton *)calloc(1LL, 72LL);
  if ( !s )
    return -1;
  obj->skeleton = s;
  s->sz = 72LL;
  s->name = "fpbe_bpf";
  s->obj = &obj->obj;
  s->prog_cnt = 1;
  s->prog_skel_sz = 24;
  s->progs = (bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
  if ( s->progs )
  {
    s->progs->name = "uprobe";
    s->progs->prog = &obj->progs.uprobe;
    s->progs->link = &obj->links.uprobe;
    s->data_sz = 1648LL;
    s->data = &unk_4F4018;
    result = 0;
  }
  else
  {
    bpf_object__destroy_skeleton(s);
    result = -1;
  }
  return result;
}
```

可以看出，字节码data在`unk_4F4018`地址处，长度为`1648`，将其`dump`下来

---

**在IDA中dump数据**

我们需要在文件中dump一段数据，这里没接触过的话，需要了解一下

打开IDA菜单栏File选项，找到script command选项

打开后就可以写脚本了，可以使用IDC，或者是IDApython

**IDC写法**

```
static main()
{
	auto i,fp;
	fp = fopen("D:\\dump","wb");
	auto start = 0x4F4018;
	auto size = 1648;
	for(i=start; i<start+size; i++)
	{
		fputc(Byte(i),fp);
	}
	fp.close();
}
```

**IDApython写法**

```
import idaapi
start_address = 0x4F4018
data_length = 1648
data = idaapi.dbg_read_memory(start_address , data_length)
fp = open('D:\\dump2', 'wb')
fp.write(data)
fp.close()
```

当然这里的script commond还有许多其它高端的用法，这里只是展示了dump数据

---

**解析字节码**

使用插件解析字节码[cylance/eBPF_processor: An IDA processor for eBPF bytecode (github.com)](https://github.com/cylance/eBPF_processor)

插件按照github上的readme.md使用即可，通过调用图去进行分析，可惜这个插件不能反编译为伪代码

关于这个插件的使用分析[Reverse Engineering Ebpfkit Rootkit With BlackBerry's Enhanced IDA Processor Tool](https://blogs.blackberry.com/en/2021/12/reverse-engineering-ebpfkit-rootkit-with-blackberrys-free-ida-processor-tool)

以及通过eBPF的文档来进行逆向分析https://www.kernel.org/doc/html/latest/bpf/instruction-set.html

以下是官方WP中使用Ghidra软件和eBPF-for-Ghidra插件得到的结果，用作参考（用惯了IDA，懒得换了）

```
undefined8 uprobe(longlong inp)
{
  ulonglong flag1;
  ulonglong flag3;
  undefined8 uVar1;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined local_20;
  ulonglong flag4;
  ulonglong flag2;
  undefined local_8;
  
  flag3 = *(ulonglong *)(inp + 0x68) & 0xffffffff;
  flag4 = *(ulonglong *)(inp + 0x70) & 0xffffffff;
  flag2 = *(ulonglong *)(inp + 0x60) & 0xffffffff;
  local_8 = 0;
  flag1 = *(ulonglong *)(inp + 0x58) & 0xffffffff;
  uVar1 = 1;
  if ((((flag3 * 0xfb88 + flag4 * 0x6dc0 + flag2 * 0x71fb + flag1 * 0xcc8e == -0x5e8ca66b) &&
       (flag3 * 0x6ae5 + flag4 * 0xf1bf + flag2 * 0xadd3 + flag1 * 0x9284 == -0x1aabfcc0)) &&
      (flag3 * 0x8028 + flag4 * 0xdd85 + flag2 * 0x652d + flag1 * 0xe712 == 0xa6f374484da3)) &&
     (flag3 * 0xca43 + flag4 * 0x822c + flag2 * 0x7c8e + flag1 * 0xf23a == 0xb99c485a7277)) {
    flag2 = flag2 | flag1 << 0x20;
    flag4 = flag4 | flag3 << 0x20;
    local_28 = 755886917287302211;
    local_30 = 5064333215653776454;
    local_38 = 2329017756590022981;
    local_40 = 5642803763628229975;
    uVar1 = 0;
    local_20 = 0;
    bpf_trace_printk((char *)&local_40,0x21);
  }
  return uVar1;
```

这里对flag进行了验证，求解方程组可得

```
from z3 import *

def print_hex(index, num, ss):
 print("flag %d :" % index)
 print(hex(num))
 print(hex(ord(ss[3])), hex(ord(ss[2])), hex(ord(ss[1])), hex(ord(ss[0])))
 print("--------------------------------------------")

flag1 = BitVec("flag1", 32)
flag2 = BitVec("flag2", 32)
flag3 = BitVec("flag3", 32)
flag4 = BitVec("flag4", 32)


s = Solver()
s.add(flag2 * 0xfb88 + flag1 * 0x6dc0 + flag3 * 0x71fb + flag4 * 0xcc8e == -0x5e8ca66b&0xffffffff)
s.add(flag2 * 0x6ae5 + flag1 * 0xf1bf + flag3 * 0xadd3 + flag4 * 0x9284 == -0x1aabfcc0&0xffffffff)
s.add(flag2 * 0x8028 + flag1 * 0xdd85 + flag3 * 0x652d + flag4 * 0xe712 == 0xa6f374484da3)
s.add(flag2 * 0xca43 + flag1 * 0x822c + flag3 * 0x7c8e + flag4 * 0xf23a == 0xb99c485a7277)

if(s.check()==sat):
 m = s.model()
 # print (m)

# 同0x7fffffff按位与，是因为出现最高位为1的情况，导致无法转换为ascii字符
print((m[flag1].as_long()&0x7fffffff).to_bytes(4,'little').decode())
print((m[flag2].as_long()&0x7fffffff).to_bytes(4,'little').decode())
print((m[flag3].as_long()&0x7fffffff).to_bytes(4,'little').decode())
print((m[flag4].as_long()&0x7fffffff).to_bytes(4,'little').decode())

# print("--------------------------------------------")
# print_hex(1,861042224,"0vR3")
# print_hex(2,3798745459,"sAlb")
# print_hex(3,3295688819,"s8pD")
# print_hex(4,1932879922,"2h5s")
```

