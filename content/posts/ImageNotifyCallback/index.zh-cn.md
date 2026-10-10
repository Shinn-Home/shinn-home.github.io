---
title: "监控回调分析(3)：镜像加载回调"
date: 2022-03-08T12:00:00+08:00
lastmod: 2022-03-08T12:00:00+08:00
draft: false
author: "Shinn"
images: []
tags: ["监控回调", "镜像加载回调", "PspLoadImageNotifyRoutine", "Windows内核"]
categories: ["Windows内核分析"]

twemoji: false
lightgallery: true
---

<!--more-->

## 镜像加载回调

1. 这部分内容，跟进程加载回调非常相似




## PsSetLoadImageNotifyRoutine

```c
NTSTATUS __stdcall PsSetLoadImageNotifyRoutine(PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine)
{
  // 薄Wrapper，内部直接调用PsSetLoadImageNotifyRoutineEx
  return PsSetLoadImageNotifyRoutineEx(NotifyRoutine, 0i64);
}
```



## PsSetLoadImageNotifyRoutineEx

```c
__int64 __fastcall PsSetLoadImageNotifyRoutineEx(KSPIN_LOCK a1, KSPIN_LOCK a2)
{
  struct _EX_RUNDOWN_REF *CallbackBlock; // rdi
  __int64 Index; // rbx
  unsigned int v5; // ebx
  unsigned int v7; // [rsp+30h] [rbp-48h] BYREF
  KSPIN_LOCK v8; // [rsp+38h] [rbp-40h] BYREF
  struct _EVENT_DATA_DESCRIPTOR UserData; // [rsp+40h] [rbp-38h] BYREF
  int *v10; // [rsp+50h] [rbp-28h]
  int v11; // [rsp+58h] [rbp-20h]
  int v12; // [rsp+5Ch] [rbp-1Ch]

  if ( (a2 & 0xFFFFFFFFFFFFFFFEui64) != 0 )
    return 0xC00000F0i64;
  CallbackBlock = (struct _EX_RUNDOWN_REF *)ExAllocateCallBack(a1, a2);// 分配一个新的CallbackBlock对象
  if ( CallbackBlock )
  {
    Index = 0i64;
    while ( !ExCompareExchangeCallBack((signed __int64 *)&PspLoadImageNotifyRoutine.Ptr + Index, CallbackBlock, 0i64) )// 尝试加入到PspLoadImageNotifyRoutine[64]数组中
    {
      Index = (unsigned int)(Index + 1);
      if ( (unsigned int)Index >= 64 )
      {
        ExFreePoolWithTag(CallbackBlock, 0);
        goto LABEL_14;
      }
    }
    _InterlockedIncrement(&PspLoadImageNotifyRoutineCount);
    if ( (PspNotifyEnableMask & 1) == 0 )
      _interlockedbittestandset(&PspNotifyEnableMask, 0);
    v5 = 0;
  }
  else
  {
LABEL_14:
    v5 = -1073741670;
  }
  v7 = v5;
  v8 = a1;
  if ( EtwApiCallsProvRegHandle )
  {
    UserData.Reserved = 0;
    v12 = 0;
    UserData.Ptr = (unsigned __int64)&v8;
    UserData.Size = 8;
    v10 = (int *)&v7;
    v11 = 4;
    EtwWrite(EtwApiCallsProvRegHandle, &KERNEL_AUDIT_API_PSSETLOADIMAGENOTIFYROUTINE, 0i64, 2u, &UserData);
  }
  return v5;
}
```
