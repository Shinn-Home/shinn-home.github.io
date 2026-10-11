---
title: "八宝粥行动逆向笔记：GObject分析"
date: 2025-06-19T12:00:00+08:00
lastmod: 2025-06-19T12:00:00+08:00
draft: false
author: "Shinn"
images: []
tags: ["八宝粥行动", "虚幻引擎", "逆向工程"]
categories: ["游戏引擎逆向、游戏安全分析"]

twemoji: false
lightgallery: true
---

<!--more-->

## GObject

IDA搜索字符串（Ansi）

```c
"UObjectBaseInit"
```

搜索到引用后，直接转伪代码

```c
__int64 sub_14B217330()
{
  int v0; // edi
  __int64 v1; // rax
  __int64 v2; // r9
  __int64 v3; // rax
  const wchar_t *v4; // rcx
  __int64 v5; // rax
  unsigned int v6; // ebx
  char v7; // si
  int v8; // ebx
  unsigned __int128 v9; // rax
  __int64 v10; // rbx
  unsigned __int128 v11; // rax
  __int64 v12; // rax
  __int64 v13; // rsi
  __int64 v14; // rcx
  int v15; // eax
  __int64 v16; // rbx
  int v17; // eax
  int v18; // ebx
  int v20; // [rsp+50h] [rbp-30h] BYREF
  __int64 v21[2]; // [rsp+58h] [rbp-28h] BYREF
  char v22[24]; // [rsp+68h] [rbp-18h] BYREF
  char v23; // [rsp+B0h] [rbp+30h] BYREF
  char v24; // [rsp+B8h] [rbp+38h] BYREF
  int v25; // [rsp+C0h] [rbp+40h] BYREF
  int v26; // [rsp+C8h] [rbp+48h] BYREF

  sub_14092DD90(v22, "UObjectBaseInit");
  v0 = 0;
  v20 = 0;
  v25 = 0;
  v23 = 0;
  v24 = 0;
  v26 = 0x200000;
  sub_14AE1B0B0(
    qword_154A73948,
    (unsigned int)L"/Script/Engine.GarbageCollectionSettings",
    (unsigned int)L"gc.EnabledGCOffsetByPC",
    (unsigned int)&v24,
    (__int64)&unk_154A7DD08);
  byte_154A9AFF4 = v24;
  v21[0] = 0i64;
  v21[1] = 0i64;
  v1 = sub_14AE1AA80();
  LOBYTE(v2) = 1;
  if ( (unsigned __int8)sub_14AE85600(v1, L"-filehostip=", v21, v2) )
  {
    dword_153FA8E48 = 0;
  }
  else
  {
    sub_14AE1C7B0(
      qword_154A73948,
      (unsigned int)L"/Script/Engine.GarbageCollectionSettings",
      (unsigned int)L"gc.MaxObjectsNotConsideredByGC",
      (unsigned int)&v20,
      (__int64)&unk_154A7DD08);
    sub_14AE1C7B0(
      qword_154A73948,
      (unsigned int)L"/Script/Engine.GarbageCollectionSettings",
      (unsigned int)L"gc.SizeOfPermanentObjectPool",
      (unsigned int)&v25,
      (__int64)&unk_154A7DD08);
  }
  sub_14AE1C7B0(
    qword_154A73948,
    (unsigned int)L"/Script/Engine.GarbageCollectionSettings",
    (unsigned int)L"gc.MaxObjectsInGame",
    (unsigned int)&v26,
    (__int64)&unk_154A7DD08);
  sub_14AE1B0B0(
    qword_154A73948,
    (unsigned int)L"/Script/Engine.GarbageCollectionSettings",
    (unsigned int)L"gc.PreAllocateUObjectArray",
    (unsigned int)&v23,
    (__int64)&unk_154A7DD08);
  off_153F960A0(v21);
  sub_1408EF720(v21, 0i64);
  if ( off_153F960A0(v21) )
  {
    v3 = off_153F960A0(v21);
    sub_14AD7B320(v3);
  }
  if ( (unsigned __int8)byte_154A7DFA0 >= 6u )
  {
    v4 = L"Presizing";
    if ( v23 )
      v4 = L"Pre-allocating";
    sub_14ADF5040(
      (unsigned int)"Unknown",
      1153,
      (unsigned int)&unk_154A7DFA4,
      6,
      (__int64)L"%s for max %d objects, including %i objects not considered by GC, pre-allocating %i bytes for permanent pool.",
      v4,
      v26,
      v20,
      v25);
  }
  dword_154A9AE30 = v25;
  v5 = sub_14AD87600(v25, 0i64);
  v6 = v26;
  v7 = v23;
  qword_154A9AE38 = v5;
  qword_154A9AE40 = v5;
  qword_154A9AE48 = v5;
  dword_154A9B220 = v20;
  dword_154A9B218 = (v20 <= 0) - 1;
  if ( v26 <= 0 )
  {
    sub_14ADF5040(
      (unsigned int)"Unknown",
      45,
      (unsigned int)&unk_154A9AE54,
      1,
      (__int64)L"Max UObject count is invalid. It must be a number that is greater than 0.");
    sub_14AE28230();
  }
  v8 = sub_1408F39D0(v6) + 1;
  dword_154A9B228 = v8;
  dword_154A9B250 = sub_14B1EFC30((unsigned int)v8);
  v9 = (unsigned __int64)v8 * (unsigned __int128)8ui64;
  if ( !is_mul_ok(v8, 8ui64) )
    *(_QWORD *)&v9 = -1i64;
  qword_154A9B238 = sub_1426411F0(v9, *((_QWORD *)&v9 + 1));// GObject = 154A9B238
  sub_14E327C89(qword_154A9B238, 0i64, 8i64 * dword_154A9B228);
  if ( v7 )
  {
    v10 = dword_154A9B250;
    v11 = (unsigned __int64)dword_154A9B250 * (unsigned __int128)0x18ui64;
    if ( !is_mul_ok(dword_154A9B250, 0x18ui64) )
      *(_QWORD *)&v11 = -1i64;
    v12 = sub_1426411F0(v11, *((_QWORD *)&v11 + 1));
    v13 = v12;
    if ( v12 )
    {
      if ( v10 )
      {
        v14 = v12 + 12;
        do
        {
          *(_BYTE *)v14 &= 0xF0u;
          *(_QWORD *)(v14 - 12) = 0i64;
          *(_DWORD *)(v14 - 4) = 0;
          *(_QWORD *)(v14 + 4) = 0i64;
          v14 += 24i64;
          --v10;
        }
        while ( v10 );
      }
    }
    else
    {
      v13 = 0i64;
    }
    v15 = dword_154A9B228;
    qword_154A9B248 = v13;
    if ( dword_154A9B228 > 0 )
    {
      v16 = 0i64;
      while ( 1 )
      {
        v17 = sub_14B1EFC30((unsigned int)v0);
        v16 += 8i64;
        ++v0;
        // 这里也是特征，明显循环给qword_154A9B238填充对象
        *(_QWORD *)(v16 + qword_154A9B238 - 8) = v13 + 24i64 * v17;// GObject = 154A9B238
        v15 = dword_154A9B228;
        if ( v0 >= dword_154A9B228 )
          break;
        v13 = qword_154A9B248;
      }
    }
    HIDWORD(qword_154A9B22C) = v15;
  }
  v18 = dword_154A9B220;
  if ( dword_154A9B220 > 0 )
  {
    sub_14B1FE340(&dword_154A9B228, (unsigned int)(dword_154A9B220 + qword_154A9B22C - 1));
    LODWORD(qword_154A9B22C) = v18 + qword_154A9B22C;
  }
  sub_14B045AB0();
  byte_154A9B084 = 1;
  sub_14B219750();
  return sub_1408F5840((v8_qjs::External *)v22);
}
```



### 特征码

```c
"48 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 40 84 F6 0F 84 ?? ?? ?? ?? 48 63 1D ?? ?? ?? ?? B8"
```

```c
155602069 - 48 89 05 30D0740B     - mov [160D4F0A0],rax		// 160D4F0A0就是GObject
155602070 - E8 E43D7803           - call 158D85E59
155602075 - 40 84 F6              - test sil,sil
155602078 - 0F84 A0000000         - je 15560211E
15560207E - 48 63 1D 33D0740B     - movsxd  rbx,dword ptr [160D4F0B8]
155602085 - B8 18000000           - mov eax,00000018
```
