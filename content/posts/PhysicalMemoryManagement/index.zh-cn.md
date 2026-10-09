---
title: "内存管理机制(2)：物理内存管理"
date: 2021-08-29T12:00:00+08:00
lastmod: 2021-08-29T12:00:00+08:00
draft: false
author: "Shinn"
images: []
tags: ["物理内存", "MmPfnDataBase", "内存管理", "扫描内存", "Windows内核"]
categories: ["Windows内核分析"]

twemoji: false
lightgallery: true
---

<!--more-->

## MmPfnDataBase

1. 在Win内核中，设置了一个全局变量`MmPfnDataBase`物理页帧数据库，这个变量每次开机时位置是随机的
2. `MmPfnDataBase`指向的其实是一个数组，数组中的每一个成员为`_MMPFN`，其定义如下所示：

```c
typedef struct _MMPFN
{
    union
    {
        PFN_NUMBER Flink;
        ULONG WsIndex;            // 该页面在进程工作集链表中的索引
        PKEVENT Event;
        NTSTATUS ReadStatus;
        SINGLE_LIST_ENTRY NextStackPfn;
        SWAPENTRY SwapEntry;
    } u1;
    PMMPTE PteAddress;            // 执行此页面的PTE的虚拟地址
    union
    {
        PFN_NUMBER Blink;
        ULONG_PTR ShareCount;        // 指向该页面的PTE数量
    } u2;
    union
    {
        struct
        {
            USHORT ReferenceCount;    // 代表这个页面必须要保留在内存中的引用计数
            MMPFNENTRY e1;
        };
        struct
        {
            USHORT ReferenceCount;
            USHORT ShortFlags;
        } e2;
    } u3;
    union
    {
        MMPTE OriginalPte;        // 包含了指向此页面的PTE的原始内容
        LONG AweReferenceCount;
        PMM_RMAP_ENTRY RmapListHead;
    };
    union
    {
        ULONG_PTR EntireFrame;
        struct
        {
            ULONG_PTR PteFrame:25;
            ULONG_PTR InPageError:1;
            ULONG_PTR VerifierAllocation:1;
            ULONG_PTR AweAllocation:1;
            ULONG_PTR Priority:3;
            ULONG_PTR MustBeCached:1;
        };
    } u4;                // 指向该页面的PTE所在的页表页面的物理页帧编号，以及一些标志位
```

3. 这个对象字段定义比较多，但是其中大部分内容其实无关紧要，我们可以将这个对象简化为如下：

```c
typedef struct _MMPFN
{
	PVOID Reserved1;
	PVOID PteAddress;													   //0x8
	struct _MMPTE OriginalPte;												//0x10
	UCHAR Reserved12[0x18];													//0x28
}MMPFN, *PMMPFN;
```

4. 其中比较有意思的字段是`PteAddress`，表示是哪个`Pte`引用了这块物理页面
5. `MmPfnDataBase`中的每一个成员都负责维护一块物理页面，所以当我们拿到一个物理地址时，想要反查其在页帧数据库中的位置也很简单，步骤如下：
   1. 老生常谈了，物理页面的大小粒度为4KB
   2. 那么一个物理地址，右移12位对齐后，就能得到一个物理页帧号
   3. 这个物理页帧号就可以作为一个数组下标，在`MmPfnDataBase`中定位到目标成员



## 6大物理页链表

1. Win内核中设置了6大链表，用于维护物理内存处于不同状态下的情况，如下所示：

| 链表名            | 定义                                                         |
| ----------------- | ------------------------------------------------------------ |
| Zeroed Page List  | 零化链表，其中的物理页面已经初始化好了，可以随时分配给R3、R0使用 |
| Free Page List    | 空闲链表，物理内存被释放、但是尚未零化。内核中会有一条单独的线程循环工作，将空闲物理页面零化后，加入到零化链表中 |
| Standby Page List | 就绪链表，当系统内存资源紧缺时，会将部分文件缓存、代码页面内存暂时加入到这个链表。特点是这块内存不属于任何进程、但是其中内容仍然有效，当原进程访问时会恢复映射关系。否则就会换出到磁盘 |
| Bad Page List     | 系统自检时，发现存在硬件层面损坏的物理页面，就会将其加入到**黑名单**，表示不能使用这部分物理内存 |

2. 剩下的2个物理页面链表，`逐渐弃用`了，这里不做讨论

3. 物理页面随着状态的变换，同一块物理页面会在不同的状态链表中切换



## 遍历物理内存

1. 在常规开发中，往往是不会遍历物理内存的，因为扫描的效率比较低
2. 但是在特殊场景，针对外挂Shellcode、驱动Shellcode，在极端情况下就需要扫描所有的物理内存
3. 要扫描物理内存，首先要获取所有物理内存范围：

```c
NTKERNELAPI
PPHYSICAL_MEMORY_RANGE
MmGetPhysicalMemoryRanges (
	VOID
);
```

4. 返回值是一个`PHYSICAL_MEMORY_RANGE`数组，每个成员定义如下所示：

```c
typedef struct _PHYSICAL_MEMORY_RANGE {
    PHYSICAL_ADDRESS BaseAddress;
    LARGE_INTEGER NumberOfBytes;
} PHYSICAL_MEMORY_RANGE, *PPHYSICAL_MEMORY_RANGE; 
```

5. 我们可以遍历返回的数组，知道最后一个成员`BaseAddress`、`NumberOfBytes`均为NULL就停下
6. 拿到了`PHYSICAL_ADDRESS`，可以`MmMapIoSpace`、`MmCopyMemory`等方式都可以读出物理页面内容，这里介绍一种另类的读取物理页面内容的方法：
   1. 分配一块悬空的线性地址
   2. 根据四级分页，将该线性地址进行拆分，定位到其在MmPTEBase中的位置
   3. 修改Pte的属性位、PageFrameNum页帧号，使该Pte映射到目标物理页面
   4. 使用这个Pte_View就可以正常访问该物理页面内容了



## 小结

1. 关于物理内存管理，这部分没什么深入、繁杂的内容，这篇笔记就写到这里吧
