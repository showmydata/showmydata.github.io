---
layout: post
title: "TQLCTF2022 - Tales of the Arrow"
categories: 
  - WriteUps
tags:
  - TQLCTF2022	
  - Reverse
  - WP
last_modified_at: 2022-02-24T17:34:52+08:00
---

## Tales of the Arrow

据出题人说这道题源于3SAT问题，感兴趣的可以自行了解下。

> 赛题描述 
>
> GodV: How to reverse if it is already reversed? Zoe: You need a good direction, and reverse it again. Flag: tqlctf{.+}

给出了以下文件：

```
# gen.py
import random

print("Enter the text within tqlctf{ ... }:")

id = input();

id_bytes = bytes(id, "ascii")
bits = ''.join(["{0:08b}".format(x) for x in id_bytes])

n = len(bits)
N = 5000

print(n)
print(N)


def get_lit(i):
    return (i+1) * (2*int(bits[i])-1)

for t in range(N):
    i = random.randint(0,n-1)
    p = random.randint(0,2)
    true_lit = get_lit(i)
    for j in range(3):
        if j == p:
            print(true_lit)
        else:
            tmp = random.randint(0,n-1)
            rand_true = get_lit(tmp)
            if random.randint(0,3)==0:
                print(rand_true)
            else:
                print(-rand_true)
```

```
# output.txt
136
5000
67
27
-41
-92
-77
79
-126
131
122
-99
90
8
...
```

结合阅读python代码和给的output文件可以发现

- n=136，按照ASCII码8位是一个字符，共有17个字符
- `get_lit`函数中`(2*int(bits[i]) -1)`其实就是得到对应位的符号，`bits[i]=0`就是负数，`bits[i]=1`就是正数，前面的`i+1`就是对应的位号(加一是因为从0开始计数)
- N=5000，迭代了5000次，每次输出3个数，有`1/3 + 2/3 * 1/4 = 1/2`的概率输出正确的`get_lit`，`2/3 * 3/4 = 1/2`的概率输出取反后的`get_lit`，所以不能通过统计来解题

该题的破解点在于部分位是确定的，因为ASCII码值范围为`0~127`，所以最高位为0，也就是说`bits[i*8+1]`（从第1位、第9位、第17位...）是确定为0的，对应`get_lit`就为负数，即`-1、-9、-17...`

另一点在于，5000次迭代中，每次迭代会输出一个肯定正确的`get_lit`，另两个则是随机输出正确的与取反后的`get_lit`，那么若这三个数中有两个是错误的`get_lit`，剩下一位必定为正确的，基于之前我们已经确定的位进行判断，直至获得了所有位

事实上，只循环了一遍就得到了正确的flag

```
import sys
def check_flag(data, n):
    for i in range(1, n+1):
        if(data[i] == 0):
             return False
    return True

def print_flag(data, n):
    flag = ''
    for i in range(0, int(n/8)):
        tmp = 0
        if (data[i*8+1] == 1):
            tmp += 128
        if (data[i*8+2] == 1):
            tmp += 64
        if (data[i*8+3] == 1):
            tmp += 32
        if (data[i*8+4] == 1):
            tmp += 16
        if (data[i*8+5] == 1):
            tmp += 8
        if (data[i*8+6] == 1):
            tmp += 4
        if (data[i*8+7] == 1):
            tmp += 2
        if (data[i*8+8] == 1):
            tmp += 1
        flag = flag + chr(tmp)
    print(flag)
    return
with open ("output.txt","r") as f:
    n = int(f.readline())
    N = int(f.readline())
    guess1 = [0 for i in range(N + 1)]
    guess2 = [0 for i in range(N + 1)]
    guess3 = [0 for i in range(N + 1)]

    true1 = [0 for i in range(N + 1)]
    true2 = [0 for i in range(N + 1)]
    true3 = [0 for i in range(N + 1)]

    data = [-1 for i in range(n + 1)]

    for i in range(0, 17):
        data[i*8+1] = 0


    # 读取数据
    for i in range(0, N):
        guess1[i+1] = int(f.readline())
        guess2[i+1] = int(f.readline())
        guess3[i+1] = int(f.readline())

    while(check_flag(data, n) == False):
        for i in range(1, N+1):
            # validate
            if (data[abs(guess1[i])] == 1 and guess1[i] < 0) or (data[abs(guess1[i])] == 0 and guess1[i] > 0):
                true1[i] = -1
            if (data[abs(guess2[i])] == 1 and guess2[i] < 0) or (data[abs(guess2[i])] == 0 and guess2[i] > 0):
                true2[i] = -1
            if (data[abs(guess3[i])] == 1 and guess3[i] < 0) or (data[abs(guess3[i])] == 0 and guess3[i] > 0):
                true3[i] = -1
            # print(i," ",true1[i]," ",true2[i]," ",true3[i])
            # update
            if (true1[i] == -1 and true2[i] == -1):
                print(i, " ", true1[i], " ", true2[i], " ", true3[i]," true3 = ",guess3[i])
                if(true3[i] == -1):
                    print("error")
                    sys.exit()
                if(guess3[i] > 0):
                    data[abs(guess3[i])] = 1
                else:
                    data[abs(guess3[i])] = 0

            elif (true1[i] == -1 and true3[i] == -1):
                print(i, " ", true1[i], " ", true2[i], " ", true3[i], " true2 = ", guess2[i])
                if (true2[i] == -1):
                    print("error")
                    sys.exit()
                if (guess2[i] > 0):
                    data[abs(guess2[i])] = 1
                else:
                    data[abs(guess2[i])] = 0

            elif (true2[i] == -1 and true3[i] == -1):
                print(i, " ", true1[i], " ", true2[i], " ", true3[i], " true1 = ", guess1[i])
                if (true1[i] == -1):
                    print("error")
                    sys.exit()
                if (guess1[i] > 0):
                    data[abs(guess1[i])] = 1
                else:
                    data[abs(guess1[i])] = 0

        print_flag(data, n)
        break
    f.close()
```

输出结果为`see_you_in_galaxy`，flag就是`tqlctf{see_you_in_galaxy}`
