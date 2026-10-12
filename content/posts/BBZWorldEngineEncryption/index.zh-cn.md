---
title: "八宝粥行动逆向笔记：UWorld、UEngine、GName加密分析及GObject分析"
date: 2025-06-09T12:00:00+08:00
lastmod: 2025-06-09T12:00:00+08:00
draft: false
author: "Shinn"
images: []
tags: ["八宝粥行动", "虚幻引擎", "逆向工程"]
categories: ["游戏引擎逆向、游戏安全分析"]

twemoji: false
lightgallery: true
---

<!--more-->

## UWorld、UEngine加密分析


### GWorld加密

IDA搜索字符串，定位到`int32 FEnvQueryRequest::Execute`方法

```c++
"Unknown owner of request: %s";
"Unable to access world with owner: %s";
```

```c++
int32 FEnvQueryRequest::Execute(EEnvQueryRunMode::Type RunMode, FQueryFinishedSignature const& FinishDelegate)
{
	if (Owner == NULL)
	{
		Owner = FinishDelegate.GetUObject();
		if (Owner == NULL)
		{
			UE_LOG(LogEQS, Warning, TEXT("Unknown owner of request: %s"), *GetNameSafe(QueryTemplate));
			return INDEX_NONE;
		}
	}

	if (World == NULL)
	{
         // 这里会返回UWorld*
		World = GEngine->GetWorldFromContextObject(Owner, EGetWorldErrorMode::ReturnNull);
		if (World == NULL)
		{
			UE_LOG(LogEQS, Warning, TEXT("Unable to access world with owner: %s"), *GetNameSafe(Owner));
			return INDEX_NONE;
		}
	}

	UEnvQueryManager* EnvQueryManager = UEnvQueryManager::GetCurrent(World);
	if (EnvQueryManager == NULL)
	{
		UE_LOG(LogEQS, Warning, TEXT("Missing EQS manager!"));
		return INDEX_NONE;
	}

	return EnvQueryManager->RunQuery(*this, RunMode, FinishDelegate);
}
```

八宝粥IDA在对应方法的伪代码为

```c++
__int64 __fastcall sub_14AA57EB0(_QWORD *a1, unsigned int a2, v8_qjs::External *a3)
{
  __int64 (__fastcall ***v6)(_QWORD); // rax
  __int64 v7; // rax
  __int64 v8; // rax
  __int64 v9; // rcx
  __int64 v10; // rax
  void *v11; // rax
  __int64 v12; // rax
  __int64 v13; // rax
  void *v14; // rax
  int v15; // eax
  __int64 v16; // rsi
  __int64 v17; // rax
  __int64 v18; // rdx
  __int64 v19; // r8
  __int64 v20; // rax
  __int64 v21; // r14
  __int64 v22; // rsi
  _DWORD *v23; // rbx
  unsigned int v24; // edi
  v8_qjs::External *v25; // rdi
  __int64 v26; // r14
  __int64 v27; // rax
  __int64 v28; // rcx
  bool v29; // zf
  __int64 v31; // [rsp+30h] [rbp-10h] BYREF
  _DWORD *v32; // [rsp+38h] [rbp-8h]
  __int64 v33; // [rsp+70h] [rbp+30h] BYREF

  if ( a1[1] )
    goto LABEL_5;
  if ( !*((_DWORD *)a3 + 2) || (v6 = (__int64 (__fastcall ***)(_QWORD))off_1500540A0(a3)) == 0i64 )
  {
    a1[1] = 0i64;
LABEL_9:
    if ( (unsigned __int8)byte_150C78710 >= 3u )
    {
      if ( *a1 )
      {
        v33 = *(_QWORD *)(*a1 + 36i64);
        sub_148552FD0(&v33, &v31);
      }
      else
      {
        v31 = 0i64;
        v32 = 0i64;
        sub_14080A940((v8_qjs::External *)&v31);
        LODWORD(v32) = (_DWORD)v32 + 5;
        if ( (int)v32 > SHIDWORD(v32) )
          sub_14080A8A0((v8_qjs::External *)&v31);
        v10 = off_1500540A0(&v31);
        sub_1483F3110(v10, L"None", 10i64);
      }
      if ( (_DWORD)v32 )
        v11 = (void *)off_1500540A0(&v31);
      else
        v11 = &unk_14B95B5C8;
      sub_14848CEE0(
        (unsigned int)"Unknown",
        80,
        (unsigned int)&unk_150C78714,
        3,
        (__int64)L"Unknown owner of request: %s",
        v11);
      goto LABEL_31;
    }
    return 0xFFFFFFFFi64;
  }
  v7 = (**v6)(v6);
  a1[1] = v7;
  if ( !v7 )
    goto LABEL_9;
LABEL_5:
  v8 = a1[2];
  if ( !v8 )                                    // 这里是特征，判断World == NULL
      										// 跟源码对应上了，这里v8就是World
  {
   	// GEngine解密，这里v9就是GEngine
    if ( (unsigned __int8)off_150241E80() )
    {
      v33 = qword_150244E88;
      BYTE1(v33) = BYTE6(qword_150244E88) ^ 0x37;
      BYTE6(v33) = BYTE1(qword_150244E88) ^ 0x37;
      v9 = v33;
    }
    else
    {
      v9 = *(_QWORD *)qword_150242E88;
    }
      
    // GEngine作为参数1调call，返回的v8就是GWorld，下文继续分析sub_14A544E40这个call是什么
    v8 = sub_14A544E40(v9, a1[1], 0i64);
    a1[2] = v8;
    if ( !v8 )
    {
      if ( (unsigned __int8)byte_150C78710 >= 3u )
      {
        v12 = a1[1];
        if ( v12 )
        {
          v33 = *(_QWORD *)(v12 + 36);
          sub_148552FD0(&v33, &v31);
        }
        else
        {
          v31 = 0i64;
          v32 = 0i64;
          sub_14080A940((v8_qjs::External *)&v31);
          LODWORD(v32) = (_DWORD)v32 + 5;
          if ( (int)v32 > SHIDWORD(v32) )
            sub_14080A8A0((v8_qjs::External *)&v31);
          v13 = off_1500540A0(&v31);
          sub_1483F3110(v13, L"None", 10i64);
        }
        if ( (_DWORD)v32 )
          v14 = (void *)off_1500540A0(&v31);
        else
          v14 = &unk_14B95B5C8;
        sub_14848CEE0(
          (unsigned int)"Unknown",
          90,
          (unsigned int)&unk_150C78714,
          3,
          (__int64)L"Unable to access world with owner: %s",
          v14);
LABEL_31:
        off_1500540A0(&v31);
        sub_14080A880(&v31, 0i64);
        if ( off_1500540A0(&v31) )
        {
          v15 = off_1500540A0(&v31);
          sub_14841A4C0(v15);
        }
        return 0xFFFFFFFFi64;
      }
      return 0xFFFFFFFFi64;
    }
  }
  v16 = *(_QWORD *)(v8 + 344);
  if ( !v16
    || (v17 = sub_14AAD8D60(),
        v18 = *(_QWORD *)(v16 + 16),
        v19 = v17 + 56,
        v20 = *(int *)(v17 + 64),
        (int)v20 > *(_DWORD *)(v18 + 64))
    || *(_QWORD *)(*(_QWORD *)(v18 + 56) + 8 * v20) != v19 )
  {
    v16 = 0i64;
  }
  if ( !v16 || (v21 = *(_QWORD *)(v16 + 176)) == 0 )
  {
    if ( (unsigned __int8)byte_150C78710 >= 3u )
      sub_14848CEE0((unsigned int)"Unknown", 98, (unsigned int)&unk_150C78714, 3, (__int64)L"Missing EQS manager!");
    return 0xFFFFFFFFi64;
  }
  sub_14AA6E170(*(_QWORD *)(v16 + 176), &v31, a1, a2);
  v22 = v31;
  v23 = v32;
  if ( v31 )
  {
    sub_1408B7830((v8_qjs::External *)(v31 + 96), a3);
    v25 = (v8_qjs::External *)(v21 + 72);
    v26 = *(int *)(v21 + 80);
    *((_DWORD *)v25 + 2) = v26 + 1;
    if ( (int)v26 + 1 > *((_DWORD *)v25 + 3) )
      sub_140834340(v25);
    v27 = off_1500540A0(v25);
    v28 = 2 * v26;
    *(_QWORD *)(v27 + 8 * v28) = v22;
    *(_QWORD *)(v27 + 8 * v28 + 8) = v23;
    if ( v23 )
      ++v23[2];
    v24 = *(_DWORD *)(v22 + 48);
  }
  else
  {
    v24 = -1;
  }
  if ( v23 )
  {
    v29 = v23[2]-- == 1;
    if ( v29 )
    {
      (**(void (__fastcall ***)(_DWORD *))v23)(v23);
      v29 = v23[3]-- == 1;
      if ( v29 )
        (*(void (__fastcall **)(_DWORD *, __int64))(*(_QWORD *)v23 + 8i64))(v23, 1i64);
    }
  }
  return v24;
}
```

继续分析sub_14A544E40

```c++
GCloud::CApolloBufferWriter *__fastcall sub_14A544E40(__int64 a1, __int64 a2, int a3)
{
  __int64 v4; // rdi
  __int64 v6; // rax
  __int64 v7; // rsi
  void *v8; // rbx
  __int64 v9; // rdx
  int v10; // eax
  int v11; // eax
  char v12[8]; // [rsp+20h] [rbp-28h] BYREF
  int v13; // [rsp+28h] [rbp-20h]
  char v14[8]; // [rsp+30h] [rbp-18h] BYREF
  int v15; // [rsp+38h] [rbp-10h]
  __int64 v16; // [rsp+58h] [rbp+10h] BYREF
  __int64 v17; // [rsp+68h] [rbp+20h]

  v4 = a2;
  if ( a2 )
  {
    LOBYTE(v16) = 1;
    if ( a3 == 2 )
      v6 = sub_1487DE0B0(a2, &v16);
    else
      v6 = (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)a2 + 344i64))(a2);
    v7 = v6;
    if ( !(_BYTE)v16 )
      goto LABEL_26;
    if ( !v6 && a3 == 1 )
    {
      v17 = 0i64;
      sub_148837900(v4, v14, 0i64);
      v8 = &unk_14B95B5C8;
      if ( v15 != (_DWORD)v7 )
        off_1500540A0(v14);
      sub_1483DAA50((v8_qjs::External *)v12);
      if ( v13 )
        v8 = (void *)off_1500540A0(v12);
      LOBYTE(v9) = 3;
      sub_14883BF60(v8, v9, v17);
      off_1500540A0(v12);
      sub_14080A880(v12, 0i64);
      if ( off_1500540A0(v12) )
      {
        v10 = off_1500540A0(v12);
        sub_14841A4C0(v10);
      }
      off_1500540A0(v14);
      sub_14080A880(v14, 0i64);
      if ( off_1500540A0(v14) )
      {
        v11 = off_1500540A0(v14);
        sub_14841A4C0(v11);
      }
    }
    if ( !(_BYTE)v16 )
    {
LABEL_26:
      // 这里就是GWorld解密
      if ( !(unsigned __int8)off_150246E70() )
        return qword_150247E78;
      v16 = qword_150249E78;
      LOBYTE(v16) = HIBYTE(qword_150249E78) ^ 0x36;
      HIBYTE(v16) = qword_150249E78 ^ 0x36;
      return (GCloud::CApolloBufferWriter *)v16;
    }
    return (GCloud::CApolloBufferWriter *)v7;
  }
  else
  {
    if ( a3 == 1 )
    {
      v16 = 0i64;
      LOBYTE(a2) = 3;
      sub_14883BF60(L"UEngine::Get.World.4ContextObj", a2, 0i64);
    }
    return 0i64;
  }
}
```

## GName加密分析

通过字符串定位（Ansi）

```c
"ByteProperty"
```

搜索到引用函数后，再交叉引用即可

```c
if ( byte_154A8182C )
{
    v4 = &unk_154A81B00;
}
else
{
    v4 = (_QWORD *)sub_14AEA1CE0((__int64)&unk_154A81B00);	// GName = 154A81B00
    byte_154A8182C = 1;									 // 全局初始化标志位
}
v5 = (_WORD *)(v4[v3 + 1] + (unsigned int)(2 * v12));
v6 = v5 + 1;
v7 = (unsigned __int64)(unsigned __int16)*v5 >> 6;
if ( (*v5 & 1) != 0 )	// FNAME_ENTRY.bIsWide
{
    v8 = v7;
    sub_14E327C7D(v13, v6, 2 * v7);	// memcpy
    sub_14AEABF60(v13, (unsigned __int16)*v5 >> 6);// WideChar解密
    if ( (unsigned int)sub_14AD5CEE0(v13, a2, v7) )
        return 0;
    v9 = a2[v8];
    if ( !v14 )
        return v9 == 0;
    return v9 == 95 && (unsigned __int8)sub_14AEA0F40((unsigned int)(v14 - 1), &a2[v8 + 1]);
}
else
{
    sub_14E327C7D(v13, v6, (unsigned __int64)(unsigned __int16)*v5 >> 6);// memcpy
    sub_14AEABD50(v13, (unsigned __int16)*v5 >> 6);// Ansi解密
    if ( (unsigned int)sub_14AD5CE60(v13, a2, v7) )
        return 0;
    v11 = a2[v7];
    if ( !v14 )
        return v11 == 0;
    return v11 == 95 && (unsigned __int8)sub_14AEA0F40((unsigned int)(v14 - 1), &a2[v7 + 1]);
}
```

### 特征码

1. GName特征码

```c
"48 8D 15 ?? ?? ?? ?? EB ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B D0 C6 05 ?? ?? ?? ?? 01"
```

```c
DeltaForce_20260626_Ansi.exe+1528E3CB - 48 8D 15 EE96A90B     - lea rdx,[DeltaForce_20260626_Ansi.exe+20D27AC0]		// GName
DeltaForce_20260626_Ansi.exe+1528E3D2 - EB 16                 - jmp DeltaForce_20260626_Ansi.exe+1528E3EA
DeltaForce_20260626_Ansi.exe+1528E3D4 - 48 8D 0D E596A90B     - lea rcx,[DeltaForce_20260626_Ansi.exe+20D27AC0]		// GName
DeltaForce_20260626_Ansi.exe+1528E3DB - E8 F0130000           - call DeltaForce_20260626_Ansi.exe+1528F7D0
DeltaForce_20260626_Ansi.exe+1528E3E0 - 48 8B D0              - mov rdx,rax
DeltaForce_20260626_Ansi.exe+1528E3E3 - C6 05 1295A90B 01     - mov byte ptr [DeltaForce_20260626_Ansi.exe+20D278FC],01
DeltaForce_20260626_Ansi.exe+1528E3EA - 48 8B 44 24 20        - mov rax,[rsp+20]
```

2. 解密特征码

```c
"E8 ?? ?? ?? ?? 0F B7 16 48 8D 4C 24 ?? C1 EA ?? E8 ?? ?? ?? ?? 4C 8B C7 48 8D 4C 24 ?? 48 8B D3 E8"
```

```c
DeltaForce_20260626_Ansi.exe+1528E415 - E8 337AAF03           - call DeltaForce_20260626_Ansi.exe+18D85E4D
DeltaForce_20260626_Ansi.exe+1528E41A - 0FB7 16               - movzx edx,word ptr [rsi]
DeltaForce_20260626_Ansi.exe+1528E41D - 48 8D 4C 24 30        - lea rcx,[rsp+30]
DeltaForce_20260626_Ansi.exe+1528E422 - C1 EA 06              - shr edx,06
DeltaForce_20260626_Ansi.exe+1528E425 - E8 066D0000           - call DeltaForce_20260626_Ansi.exe+15295130	// WideChar解密Call
```

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
