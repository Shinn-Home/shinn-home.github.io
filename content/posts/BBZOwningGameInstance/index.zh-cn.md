---
title: "八宝粥行动逆向笔记：OwningGameInstance加密分析"
date: 2025-06-22T12:00:00+08:00
lastmod: 2025-06-22T12:00:00+08:00
draft: false
author: "Shinn"
images: []
tags: ["八宝粥行动", "虚幻引擎", "逆向工程"]
categories: ["游戏引擎逆向、游戏安全分析"]

twemoji: false
lightgallery: true
---

<!--more-->

## 八宝粥OwningGameInstance加密分析

```c++
// rax返回值为OwningGameInstance
// 参数1为GWorld
__int64 __fastcall sub_14092C390(__int64 a1)
{
  __int64 v1; // rbx
  unsigned int v3; // ecx
  int v4; // eax
  unsigned int v5; // ecx

  v1 = *(_QWORD *)(a1 + 0x1B8);
  if ( !v1 )
    return 0i64;
  v3 = *(_DWORD *)(a1 + 0x1C0);
  if ( v3 >= 0x20 )
    return v1;
  v4 = dword_152F4B484;
  if ( !_bittest(&v4, v3) )
    return v1;
  v5 = dword_152F4B480 + v3;
  if ( v5 >= 0xC9 )
    v5 = 200;
  return v1 ^ ((__int64 (__fastcall *)(_QWORD))funcs_14092C3E3[v5])((unsigned int)dword_152F4B488);
}
```
