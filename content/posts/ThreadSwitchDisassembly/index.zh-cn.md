---
title: "线程切换(2)：反汇编分析"
date: 2021-12-03T12:00:00+08:00
lastmod: 2021-12-03T12:00:00+08:00
draft: false
author: "Shinn"
images: []
tags: ["线程切换", "反汇编分析", "KiSwapThread", "reverse engineering", "Windows内核"]
categories: ["Windows内核分析"]

twemoji: false
lightgallery: true
---

<!--more-->

## 笔记定义

1. 关于本篇笔记，并不是完完全全逆清楚Win内核的线程切换全流程，而是分析其中的关键细节如何实现的，例如：如何查找新的线程、切换线程、切换上下文



## 搜索就绪线程

### KiSearchForNewThread

```c
@KiSearchForNewThread@8 proc near

.text:0045BF19                 mov     edi, edi
.text:0045BF1B                 push    ebp
.text:0045BF1C                 mov     ebp, esp
.text:0045BF1E                 and     esp, 0FFFFFFF8h
.text:0045BF21                 sub     esp, 1Ch
.text:0045BF24                 push    ebx
.text:0045BF25                 push    esi
.text:0045BF26                 mov     esi, eax        ; eax的内容怎么来的？
.text:0045BF26                                         ; 这里的eax是作为参数传递进来的，这部分调用链是自定义调用约定，正常不会使用eax传递参数的
.text:0045BF26                                         ; 需要向上追引用，发现最初来源是fs:[20]
.text:0045BF26                                         ; eax存放的是_KPCR.PrcbData
.text:0045BF28                 push    edi
.text:0045BF29                 mov     edi, [esi+_KPRCB.NextThread] ; 取出NextThraed备用线程，放到edi
.text:0045BF2C                 test    edi, edi
.text:0045BF2E                 jz      short loc_45BF40 ; NextThread == NULL直接跳转
.text:0045BF30                 and     [esi+_KPRCB.NextThread], 0 ; 清空NextThread
.text:0045BF34                 mov     [esi+_KPRCB.CurrentThread], edi ; 把NextThread设置到CurThread
.text:0045BF37                 mov     [edi+_KTHREAD.State], 2 ; 设置线程对象状态State = 2，表示正在运行
.text:0045BF3B                 jmp     loc_45C1FF      ; 无条件跳转，就是将edi赋值给eax
.text:0045BF3B                                         ; 平栈、返回
.text:0045BF40 ; ---------------------------------------------------------------------------
.text:0045BF40
.text:0045BF40 loc_45BF40:                             ; CODE XREF: KiSearchForNewThread(x,x)+15↑j
.text:0045BF40                 xor     ecx, ecx
.text:0045BF42                 call    @KiSelectReadyThread@8 ; 从当前CPU的32个就绪线程链表中选取线程对象

    // ....................................
@KiSearchForNewThread@8 endp
```



### KiSelectReadyThread

```c
.text:0042FC98 @KiSelectReadyThread@8 proc near        ; CODE XREF: KiSearchForNewThread(x,x)+29↓p
.text:0042FC98                                         ; KiRemoveBoostThread(x,x)+C6↓p ...
.text:0042FC98                 mov     edi, edi
.text:0042FC9A                 push    ebp
.text:0042FC9B                 mov     ebp, esp
.text:0042FC9D                 push    ecx             ; ecx为0
.text:0042FC9E                 mov     edx, [esi+_KPRCB.ReadySummary] ; 将当前CPU的ReadySummer位图赋值给edx
.text:0042FCA4                 shr     edx, cl
.text:0042FCA6                 xor     eax, eax        ; 清空eax
.text:0042FCA8                 test    edx, edx
.text:0042FCAA                 jz      short locret_42FCDD ; ReadySummary为0则跳转
.text:0042FCAC                 bsr     eax, edx        ; bsr作用：
.text:0042FCAC                                         ; 假设一个ReadySummary = 00010001000b
.text:0042FCAC                                         ; bsr的作用就是从左开始找，找到第一个非0位，计算该非0位是ReadySummary中的第几位
.text:0042FCAC                                         ; 本例子中是第8位
.text:0042FCAC                                         ; 所以bsr eax, edx执行后，eax = 8
.text:0042FCAC                                         ; 这个其实就是找出'优先级最高'的就绪链表
.text:0042FCAF                 push    edi
.text:0042FCB0                 mov     edi, eax
.text:0042FCB2                 add     edi, ecx
.text:0042FCB4                 mov     ecx, [esi+edi*8+_KPRCB.DispatcherReadyListHead.Flink] ;
.text:0042FCB4                                         ; 这里的edi其实就是数组下标，8是32位下LIST_ENTRY的大小
.text:0042FCB4                                         ; 从调度链表数组中取出目标数组的第一个线程对象
.text:0042FCBB                 mov     edx, [ecx]
.text:0042FCBD                 mov     [ebp-4], eax
.text:0042FCC0                 lea     eax, [ecx-74h]  ; 0x74:KTHREAD.SwapList
.text:0042FCC0                                         ; 取到KTHREAD的对象头保存到eax
.text:0042FCC3                 mov     ecx, [ecx+4]
.text:0042FCC6                 mov     [ecx], edx
.text:0042FCC8                 mov     [edx+4], ecx    ; 取出第一个线程对象了
.text:0042FCC8                                         ; 从当前链表中移除该对象
.text:0042FCCB                 cmp     edx, ecx        ; 判断移除成员后，当前链表是否为空
.text:0042FCCD                 jnz     short loc_42FCDC ; 为空则跳转
.text:0042FCCF                 mov     ecx, ds:_KiMask32Array[edi*4]
.text:0042FCD6                 xor     [esi+_KPRCB.ReadySummary], ecx ; 将ReadySummary的当前位置0
.text:0042FCDC
.text:0042FCDC loc_42FCDC:                             ; CODE XREF: KiSelectReadyThread(x,x)+35↑j
.text:0042FCDC                 pop     edi
.text:0042FCDD
.text:0042FCDD locret_42FCDD:                          ; CODE XREF: KiSelectReadyThread(x,x)+12↑j
.text:0042FCDD                 leave
.text:0042FCDE                 retn
.text:0042FCDE @KiSelectReadyThread@8 endp
```



## 切换线程

### KiSwapThread

```c
@KiSwapThread@8 proc near

// .............................................................

.text:0045BB1C                 mov     esi, edx        ; edx为KPCR.PrcbData
.text:0045BB1E                 xor     eax, eax
.text:0045BB20                 push    edi
.text:0045BB21                 mov     [esp+30h+OldThread], ecx ;
.text:0045BB21                                         ; ecx为原线程对象
.text:0045BB21                                         ; 这里是查阅WRK源码：
.text:0045BB21                                         ; LONG_PTR
.text:0045BB21                                         ; FASTCALL
.text:0045BB21                                         ; KiSwapThread (
.text:0045BB21                                         ;     IN PKTHREAD OldThread,
.text:0045BB21                                         ;     IN PKPRCB CurrentPrcb
.text:0045BB21                                         ; )
.text:0045BB25                 cmp     [esi+_KPRCB.DeferredReadyListHead.Next], eax ; 判断延迟就绪链表是否为空
.text:0045BB2B                 jz      short loc_45BB39 ; 为空则跳转

// .............................................................

.text:0045BBE7                 push    eax
.text:0045BBE8                 mov     eax, esi
.text:0045BBEA                 call    @KiSearchForNewThread@8 ; 这里就是我们之前分析过的查找函数
.text:0045BBEF                 test    eax, eax
.text:0045BBF1                 jnz     short loc_45BC3B ; 返回线程对象不为NULL则跳转

// .............................................................

.text:0045BC3B loc_45BC3B:                             ; CODE XREF: KiSwapThread(x,x)+E2↑j
.text:0045BC3B                 mov     edi, [esp+30h+OldThread] ; 取出局部变量保存的OldThread，放到edi
.text:0045BC3F                 cmp     eax, [esi+_KPRCB.IdleThread] ; 判断KiSearchForNewThread找到的线程对象，是否跟IdleThread一样
.text:0045BC42                 jz      short loc_45BC60
.text:0045BC44                 cmp     eax, edi        ; 判断KiSearchForNewThread找到的线程，是否跟当前线程一样
.text:0045BC46                 jz      short loc_45BC60
.text:0045BC48                 mov     cl, [eax+_KTHREAD.Running]
.text:0045BC4B                 test    cl, cl          ; 判断新线程是否处于运行中
.text:0045BC4D                 jz      short loc_45BC60
.text:0045BC4F                 mov     [eax+_KTHREAD.State], 3 ; 如果线程运行中，将线程State设置为备用状态
.text:0045BC53                 mov     [esi+_KPRCB.NextThread], eax ; 将找到的线程对象保存到NextThread
.text:0045BC56                 mov     eax, [esi+_KPRCB.IdleThread] ; 将IdleThread对象保存到eax
.text:0045BC59                 mov     [eax+_KTHREAD.State], 2 ; 设置线程State为运行中
.text:0045BC5D                 mov     [esi+_KPRCB.CurrentThread], eax ; 设置为KPRCB.CurThread

// .............................................................

.text:0045BD58                 call    _KiDeliverApc@12 ; 线程切换流程中，又有一次APC分发的机会

// .............................................................

.text:0045BD6C
.text:0045BD6C loc_45BD6C:                             ; CODE XREF: KiSwapThread(x,x)+15F↑j
.text:0045BD6C                 mov     edx, eax        ; edx存放NewThread
.text:0045BD6E                 mov     ecx, edi        ; ecx存放OldThread
.text:0045BD70                 call    @KiSwapContext@8 ;
.text:0045BD70                                         ; 切换线程上下文：
.text:0045BD70                                         ; 1. 切换堆栈esp
.text:0045BD70                                         ; 2. 前后进程不一致，还要切CR3

// .............................................................

@KiSwapThread@8 endp
```



### KiSwapContext

```c
.text:00454F00 ; int __fastcall KiSwapContext(_DWORD, _DWORD)
.text:00454F00 @KiSwapContext@8 proc near              ; CODE XREF: KiExitDispatcher(x,x,x,x,x)+13B↑p

// .............................................................

.text:00454F19                 mov     edi, ecx        ; 旧线程
.text:00454F1B                 mov     esi, edx        ; 新线程
.text:00454F1D                 movzx   ecx, [edi+_KTHREAD.WaitIrql]
.text:00454F21                 call    _SwapContext@0  ; SwapContext()
    
// .............................................................
    
.text:00454F38                 retn
.text:00454F38 @KiSwapContext@8 endp
```



### SwapContext

```c
_SwapContext@0  proc near

.text:004550A0                 cmp     [esi+_KTHREAD.Running], 0
.text:004550A4                 jz      short loc_4550AA ; 判断新线程没在运行了，则跳转
.text:004550A6                 pause                   ; 否则暂停一下，再跳转回去判断
.text:004550A8                 jmp     short _SwapContext@0 ; SwapContext()

// .............................................................

.text:004550F5                 inc     [ebx+_KPCR.___u0.__s1.ContextSwitches] ; 当前CPU的上下文切换的次数+1

// .............................................................

.text:0045512E                 mov     [edi+_KTHREAD.KernelStack], esp ; 将当前esp保存起来
.text:00455131                 mov     eax, [esi+_KTHREAD.InitialStack]
.text:00455134                 mov     esp, [esi+_KTHREAD.KernelStack]
.text:00455137                 mov     ebp, [esi+_KTHREAD.___u12.ApcState.Process]
.text:0045513A                 mov     eax, [edi+_KTHREAD.___u12.ApcState.Process]
.text:0045513D                 cmp     ebp, eax        ; 判断新、老线程的是不是同一个进程（养父）
.text:0045513F                 jz      short loc_45515E ; 相同则跳转
.text:00455141                 mov     ecx, [ebx+14h]
.text:00455144                 lock xor [ebp+_KPROCESS.ActiveProcessors.Bitmap], ecx
.text:00455148                 lock xor [eax+_KPROCESS.ActiveProcessors.Bitmap], ecx
.text:0045514C                 mov     ecx, [ebp+1Ch]
.text:0045514F                 or      ecx, [eax+1Ch]
.text:00455152                 jnz     loc_45522A
.text:00455158
.text:00455158 loc_455158:                             ; CODE XREF: _SwapContext_XRstorEnd+A2↓j
.text:00455158                 mov     eax, [ebp+_KPROCESS.DirectoryTableBase]
.text:0045515B                 mov     cr3, eax        ; 切换CR3

// .............................................................
```
