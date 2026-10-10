---
title: "监控回调分析(2)：线程创建回调"
date: 2022-03-07T12:00:00+08:00
lastmod: 2022-03-07T12:00:00+08:00
draft: false
author: "Shinn"
images: []
tags: ["监控回调", "线程创建回调", "PspCreateThreadNotifyRoutine", "Windows内核"]
categories: ["Windows内核分析"]

twemoji: false
lightgallery: true
---

<!--more-->

## 线程加载回调

1. 这部分内容，跟进程加载回调非常相似



## PsSetCreateThreadNotifyRoutine

```c
NTSTATUS __stdcall PsSetCreateThreadNotifyRoutine(
	PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine
)
{
  return PspSetCreateThreadNotifyRoutine(NotifyRoutine, 0i64);
}
```



## PsSetCreateThreadNotifyRoutineEx

```c
__int64 __fastcall PsSetCreateThreadNotifyRoutineEx(int a1, unsigned __int64 a2)
{
  unsigned int v3; // ebx

  if ( a1 )
  {
    if ( a1 != 1 )
      return 0xC000000Di64;
    v3 = 2;
  }
  else
  {
    v3 = 1;
  }
  if ( (unsigned int)MmVerifyCallbackFunctionCheckFlags(a2, 32) )// 
                                                // 1. 校验回调是否处于合法模块内
                                                // 2. 该模块是否已签名
    return PspSetCreateThreadNotifyRoutine(a2, v3);
  else
    return 0xC0000022i64;
}
```



## PspSetCreateThreadNotifyRoutine

1. 从以上伪代码可知，常规、Ex拓展版本，其实内部都是调用`PspSetCreateThreadNotifyRoutine`

```c
__int64 __fastcall PspSetCreateThreadNotifyRoutine(
	PVOID NotifyRoutine, 
	unsigned int a2)	// 注册常规线程创建回调，a2就是0
{
  char v2; // si
  struct _EX_RUNDOWN_REF *CallbackBlock; // rdi
  __int64 Index; // rbx

  v2 = a2;
  CallbackBlock = (struct _EX_RUNDOWN_REF *)ExAllocateCallBack((KSPIN_LOCK)NotifyRoutine, a2);
  if ( !CallbackBlock )
    return 0xC000009Ai64;
  Index = 0i64;
  while ( !ExCompareExchangeCallBack((signed __int64 *)&PspCreateThreadNotifyRoutine.Ptr + Index, CallbackBlock, 0i64) )
  {
    Index = (unsigned int)(Index + 1);
    if ( (unsigned int)Index >= 64 )
    {
      ExFreePoolWithTag(CallbackBlock, 0);      // CallbackBlock PspCreateThreadNotifyRoutine[64]中没有空位了，释放内存
      return 0xC000009Ai64;
    }
  }
  if ( (v2 & 1) != 0 )
  {
    _InterlockedIncrement(&PspCreateThreadNotifyRoutineNonSystemCount);
    if ( (PspNotifyEnableMask & 0x10) == 0 )
      _interlockedbittestandset(&PspNotifyEnableMask, 4u);
  }
  else                                          // 常规注册走这里
  {
    _InterlockedIncrement(&PspCreateThreadNotifyRoutineCount);// ThreadNotifyCount 加 1
    if ( (PspNotifyEnableMask & 8) == 0 )
      _interlockedbittestandset(&PspNotifyEnableMask, 3u);
  }
  return 0i64;
}
```

1. 由以上反汇编可知，线程创建回调也存在一个全局数组叫`PspCreateThreadNotifyRoutine`，WinDbg调试如下所示：

```c
// 可知当前系统只注册了1个NotifyRoutine
2: kd> dq PspCreateThreadNotifyRoutine
fffff803`432ec120  ffffbf01`4f87bfbf 00000000`00000000
fffff803`432ec130  00000000`00000000 00000000`00000000

// 去除低4位后，解析格式如下：
// [Lock][Routine][ExVersion]
2: kd> dq ffffbf01`4f87bfb0
ffffbf01`4f87bfb0  00000000`00000020 fffff803`481c1060
ffffbf01`4f87bfc0  00000000`00000000 018b480d`74c98548
ffffbf01`4f87bfd0  30316956`02038b00 fdfa2705`8d48fffe
ffffbf01`4f87bfe0  00000000`05060000 ffffbf01`4f87bfe8
ffffbf01`4f87bff0  ffffbf01`4f87bfe8 8940498b`4808438b
ffffbf01`4f87c000  634c7846`02032400 f5058d48`fffd1e84
ffffbf01`4f87c010  00750061`00650070 0073002e`00680074
ffffbf01`4f87c020  48ff0000`00730079 7c89fffd`8992058d

// 反汇编回调入口
2: kd> u fffff803`481c1060
fffff803`481c1060 4883ec28        sub     rsp,28h
fffff803`481c1064 4584c0          test    r8b,r8b
fffff803`481c1067 7406            je      fffff803`481c106f
fffff803`481c1069 4883c428        add     rsp,28h
fffff803`481c106d c3              ret
fffff803`481c106e cc              int     3
fffff803`481c106f 48895c2430      mov     qword ptr [rsp+30h],rbx
fffff803`481c1074 488d0d75600000  lea     rcx,[fffff803`481c70f0]
```
