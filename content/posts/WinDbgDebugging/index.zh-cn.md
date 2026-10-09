---
title: "WinDbg 调试"
date: 2021-07-21T12:00:00+08:00
lastmod: 2021-07-21T12:00:00+08:00
draft: false
author: "Shinn"
images: []
tags: ["WinDbg", "内核调试", "Windows内核", "reverse engineering"]
categories: ["调试/分析技术"]

twemoji: false
lightgallery: true
---

<!--more-->

## WinDbg调试

### 查看信息命令

#### 查看当前进程上下文（.process）

```c
0: kd> .process
Implicit process is now ffffbf01`4c48f040
```



#### 输出所有进程信息（!process 0 0）

```c
// 列出所有的进程信息
!process 0 0

// 列出目标进程名的信息，这里以'任务管理器'为例
!process 0 0 Taskmgr.exe
```

```c
0: kd> !process 0 0
**** NT ACTIVE PROCESS DUMP ****
PROCESS ffffbf014c48f040
    SessionId: none  Cid: 0004    Peb: 00000000  ParentCid: 0000
    DirBase: 001ad000  ObjectTable: ffffe78cd3219ac0  HandleCount: 2317.
    Image: System

PROCESS ffffbf014c47d080
    SessionId: none  Cid: 006c    Peb: 00000000  ParentCid: 0004
    DirBase: 00217000  ObjectTable: ffffe78cd3269c40  HandleCount:   0.
    Image: Registry

PROCESS ffffbf014f68d080
    SessionId: none  Cid: 013c    Peb: 1dcd6c0000  ParentCid: 0004
    DirBase: 101152000  ObjectTable: ffffe78cd37f9080  HandleCount:  53.
    Image: smss.exe

PROCESS ffffbf014f8e5140
    SessionId: 0  Cid: 01bc    Peb: 56a8bd4000  ParentCid: 01b0
    DirBase: 104fc8000  ObjectTable: ffffe78cd67a2340  HandleCount: 475.
    Image: csrss.exe
```



#### 查看对象符号(dt xxx)

1. 如下命令为最常用的的，当加载符号表后，可以使用`dt xxx`查看目标符号的完整信息

```c
// 中括号为可选，-r2表示进一步查看子结构的层数
dt [nt!] _PEB [-rx]
    
// 将目标地址按照_PEB的结构进行解析
dt _PEB addr
```

2. 如下是其他查看符号命令，

```c
// 显示所有nt符号中"_P"开头的符号
dt nt! _P*

// 直接查看PEB对象中Ldr字段的内容
dt [nt!] _PEB Ldr [addr]
```



#### 模糊搜索导出符号

1. 在我们调试时，往往会遇到忘记了某符号的完整名称，但是记得其中的一小部分，就可以使用模糊搜索

```c
// 搜索nt模块中所有以"Nt"开头的函数符号
x nt!Nt*
```

```c
// 输出结果
0: kd> x nt!nt*
fffff803`42dd6a8f nt!NtAcquireProcessActivityReference$filt$0 (void)
fffff803`42bdd620 nt!NtDeleteValueKey (void)
fffff803`42f51975 nt!NtQueryDriverEntryOrder$filt$1 (void)
fffff803`42cea060 nt!NtQueryEaFile (void)
fffff803`428d56b0 nt!NtCancelWaitCompletionPacket (void)
fffff803`42ce7930 nt!NtFlushBuffersFileEx (void)
fffff803`42dd5c80 nt!NtReleaseSemaphore$filt$0 (void)
fffff803`42dd66af nt!NtGetNlsSectionPtr$filt$0 (void)
fffff803`42c54950 nt!NtQueryMultipleValueKey (void)
fffff803`42f526d1 nt!NtSetSystemEnvironmentValue$filt$0 (void)
fffff803`42ce2640 nt!NtAlpcCreateResourceReserve (void)
fffff803`42c72ab0 nt!NtSetIoCompletionEx (void)
fffff803`42ed1172 nt!NtCreateEnclave$filt$0 (void)
```



#### 查看内存内容

1. 我们需要查看某指针内的数据，可以使用如下命令

```c
// 查看单字节数据
db xxx
    
// 还有查看双字节、4字节、8字节
dw、dd、dq
```

2. 在手工解析堆栈时，按照我们以往的阅读习惯，显示堆栈信息一般是竖着显示的

```c
// 显示4字节、8字节堆栈信息
dds、dqs
```



#### 修改内存内容

1. 这一部分跟上一小节的内容非常相似，如下所示：

```c
// 修改单字节数据
eb Addr xxx
    
// 修改2字节、4字节、8字节数据
ew、ed、eq
```



#### 查看堆栈信息

1. 在调试蓝屏时，我们往往需要查看堆栈，回溯查看一下调用方

```c
// 查看调用堆栈
k
    
// 显示更加详细的堆栈信息
kb、kv、kp
```



#### 解析线性地址

1. 我们在得到一个`线性地址`后，可能需要得到其对应的PML4E、PDPTE、PDE、PTE信息，当然是可以手动计算的，但是WinDbg提供了一键转换命令

```c
// 解析出va对应PML4E、PDPTE、PDE、PTE的详细信息
// PML4E、PDPTE、xxx的va、表项内容、pfn、属性
!pte va
```

```c
// 如下信息为一个2mb大物理页面的pte信息
1: kd> !pte ffffbf0152163280
                                           VA ffffbf0152163280
PXE at FFFFCFE7F3F9FBF0    PPE at FFFFCFE7F3F7E028    PDE at FFFFCFE7EFC05480    PTE at FFFFCFDF80A90B18
contains 0A00000005334863  contains 0A00000005337863  contains 8A0000011B8009E3  contains 0000000000000000
pfn 5334      ---DA--KWEV  pfn 5337      ---DA--KWEV  pfn 11b800    -GLDA--KW-V  LARGE PAGE pfn 11b823  
```



#### 线性地址转物理地址

1. 这个命令其实用的比较少

```c
// va转pa [页目录表基址] [线性地址]
!vtop DTB va
```



#### 查看物理内存内容

1. 我们有时需要读出一个物理地址中的内容，其实用法跟读线性地址内容差不多，就是前面多了一个'!'号

```c
// 读单字节物理内存
!db [Pa]

// 读2字节、4字节、8字节物理内存
!dw、!dd、!dq
```

```c
1: kd> !vtop 11e9c8000 ffffbf0152163280
Amd64VtoP: Virt ffffbf0152163280, pagedir 000000011e9c8000
Amd64VtoP: PML4E 000000011e9c8bf0
Amd64VtoP: PDPE 0000000005334028
Amd64VtoP: PDE 0000000005337480
Amd64VtoP: Large page mapped phys 000000011b963280
Virtual address ffffbf0152163280 translates to physical address 11b963280.

1: kd> !dq 11b963280 L2
#11b963280 00000000`00000003 ffffbf01`52cb4200

1: kd> dq ffffbf0152163280 L2
ffffbf01`52163280  00000000`00000003 ffffbf01`52cb4200
```



#### 查看已加载、已卸载的驱动模块

1. 连接了WinDbg后，可以查看虚拟机中已加载、已卸载的驱动模块

```c
lm
```



#### WinDbg当计算器使用

1. 我们在计算某些地址、偏移时，比较初级的做法是调用一个独立的计算器出来，但是WinDbg自身其实可以充当计算器使用的

```c
// 假设ServiceTableBase = fffff803`426c8340
// 假设Entry = 0271c104 
// 可以直接使用WinDbg的算数运算
? fffff803`426c8340 + (0271c104 >> 4)

// WinDbg输出结果为
Evaluate expression: -8782091149488 = fffff803`42939f50
    
// 此时u、uf可以看到正确的函数地址
0: kd> u fffff803`42939f50
nt!NtAccessCheck:
fffff803`42939f50 4c8bdc          mov     r11,rsp
fffff803`42939f53 4883ec68        sub     rsp,68h
fffff803`42939f57 488b8424a8000000 mov     rax,qword ptr [rsp+0A8h]
fffff803`42939f5f 4533d2          xor     r10d,r10d
fffff803`42939f62 458853f0        mov     byte ptr [r11-10h],r10b
fffff803`42939f66 498943e8        mov     qword ptr [r11-18h],rax
fffff803`42939f6a 488b8424a0000000 mov     rax,qword ptr [rsp+0A0h]
fffff803`42939f72 498943e0        mov     qword ptr [r11-20h],rax
```

2. 进制转换、类型转换，用法如下所示：

```c
1: kd> .formats a9c
Evaluate expression:
  Hex:     00000000`00000a9c
  Decimal: 2716
  Octal:   0000000000000000005234
  Binary:  00000000 00000000 00000000 00000000 00000000 00000000 00001010 10011100
  Chars:   ........
  Time:    Thu Jan  1 08:45:16 1970
  Float:   low 3.80593e-042 high 0
  Double:  1.34188e-320
```



### 调试命令

#### 载入符号表

1. 在调试时，往往首先会加载PDB符号表，因为在你列举出xxx信息后，发现确实符号表、导致解析失败，那么再加载符号表的话，可能就需要重新列举一遍xxx信息，导致浪费调试时间

```c
// 重新加载符号表
.reload
```

2. 强制重新加载符号表

```
.reload /f
```

3. 调用该命令重新载入符号表，往往是全局重载，那么会很耗时，此时我们可以重载指定的符号表，如下所示：

```
.reload /f TestDrv.sys
```



#### 内存断点

1. 使用WinDbg你下内存断点，如下所示：

```c
// 下内存断点
bp [Addr]
```



#### 硬件断点

1. 再大部分情况下，内存断点是足够支撑我们的调试需求的，但是某些情况下，我们需要对xxx对象下访问断点、回溯访问方，此时就需要借助硬件断点了，如下所示：

```c
// 阴硬件断点：访问、写入、执行断点
ba r/w/e
```



#### 查看断点列表

1. 查看断点列表，如下所示：

```c
// 列出所有的断点信息
bl
```

2. 单独禁用、启用某断点：

```c
be、bd
```



#### 附加到目标进程上下文

1. 我们在调试时按下WinDbg的中断按钮，此时断下的进程上下文是随机的，如果我们需要访问某个指定R3进程的内存，就需要主动附加过去：

```c
// 获取目标进程的EPROCESS
2: kd> !process 0 0 Taskmgr.exe
PROCESS ffffbf014c55e080
    SessionId: 1  Cid: 187c    Peb: 5c525d2000  ParentCid: 1108
    DirBase: 120507000  ObjectTable: ffffe78cd8f97cc0  HandleCount: 620.
    Image: Taskmgr.exe
        
// 附加过去
2: kd> .process /i ffffbf014c55e080
You need to continue execution (press 'g' <enter>) for the context
to be switched. When the debugger breaks in again, you will be in
the new process context.
    
// 如上给出的提示非常明显了，此时需要再次按下'g'，让虚拟机跑起来
2: kd> g
Break instruction exception - code 80000003 (first chance)
nt!DbgBreakPointWithStatus:
fffff803`429fefd0 cc              int     3
    
// 到了这里，才是真正附加到目标进程上下文了
1: kd> r cr3
cr3=0000000120507000
```



#### 自动放行断点

1. 可以设置异常的首次断下、二次断下

```c
sxe c0000005   -> first chance 就中断
sxd c0000005   -> first chance 不中断，second chance 中断
sxn c0000005   -> first/second chance 都不处理，不中断
```

2. 在某些特殊的调试场景，可能会频繁抛出`C0000005`异常，WinDbg会频繁反复断下，此时可以设置WinDbg自动放过（接管到特定的异常，自动帮你按下'g'键）

```c
// Windbg首次捕获到c0000005错误，自动按下g放行
sxe -c "g" c0000005
```
