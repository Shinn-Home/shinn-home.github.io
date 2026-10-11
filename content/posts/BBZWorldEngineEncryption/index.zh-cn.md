---
title: "八宝粥行动逆向笔记：UWorld、UEngine加密分析"
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

## BBZ加密分析


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
