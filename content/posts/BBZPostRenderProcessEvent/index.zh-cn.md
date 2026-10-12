---
title: "八宝粥行动逆向笔记：AHUD.PostRender函数指针、ProcessEvent反射调用引擎Call分析"
date: 2025-06-06T12:00:00+08:00
lastmod: 2025-06-06T12:00:00+08:00
draft: false
author: "Shinn"
images: []
tags: ["八宝粥行动", "虚幻引擎", "逆向工程"]
categories: ["游戏引擎逆向、游戏安全分析"]

twemoji: false
lightgallery: true
---

<!--more-->

## AHUD.PostRender

### UE源码

UE源码中有着`void UGameViewportClient::Draw(FViewport* InViewport, FCanvas* SceneCanvas)`方法，如下所示（这里使用到了GEngine、会有GEngine解密的痕迹）

```c++
void UGameViewportClient::Draw(FViewport* InViewport, FCanvas* SceneCanvas)
{
	//Valid SceneCanvas is required.  Make this explicit.
	check(SceneCanvas);

	BeginDrawDelegate.Broadcast();

	const bool bStereoRendering = GEngine->IsStereoscopic3D(InViewport);
	FCanvas* DebugCanvas = InViewport->GetDebugCanvas();

	// Create a temporary canvas if there isn't already one.
	static FName CanvasObjectName(TEXT("CanvasObject"));
	UCanvas* CanvasObject = GetCanvasByName(CanvasObjectName);
	CanvasObject->Canvas = SceneCanvas;

	// Create temp debug canvas object
	FIntPoint DebugCanvasSize = InViewport->GetSizeXY();
	if (bStereoRendering && GEngine->XRSystem.IsValid() && GEngine->XRSystem->GetHMDDevice())
	{
		DebugCanvasSize = GEngine->XRSystem->GetHMDDevice()->GetIdealDebugCanvasRenderTargetSize();
	}

	static FName DebugCanvasObjectName(TEXT("DebugCanvasObject"));
	UCanvas* DebugCanvasObject = GetCanvasByName(DebugCanvasObjectName);
	DebugCanvasObject->Init(DebugCanvasSize.X, DebugCanvasSize.Y, NULL, DebugCanvas);

    // ...
    
    // Render the player's HUD.
    // 这里是特征，会有一个判断，在IDA中翻译伪代码就是 if ( *(_QWORD *)(v238 + 0x0410) )
    // 这里的0x0410就是Dump SDK中MyHUD在APlayerController中的偏移
    // 找到 if ( *(_QWORD *)(v238 + 0x0410) )后，往下第2个call就是调用虚表函数，秒得PostRender下标
    if( PlayerController->MyHUD )
    {
        SCOPE_CYCLE_COUNTER(STAT_HudTime);

        DebugCanvasObject->SceneView = View;
        PlayerController->MyHUD->SetCanvas(CanvasObject, DebugCanvasObject);

        PlayerController->MyHUD->PostRender();

        // Put these pointers back as if a blueprint breakpoint hits during HUD PostRender they can
        // have been changed
        CanvasObject->Canvas = SceneCanvas;
        DebugCanvasObject->Canvas = DebugCanvas;

        // A side effect of PostRender is that the playercontroller could be destroyed
        if (!PlayerController->IsPendingKill())
        {
            PlayerController->MyHUD->SetCanvas(NULL, NULL);
        }
    }
    
    // ....
    
}
```



### IDA字符串

1. IDA中的Strings页面，搜索Unicode字符串
2. 可能会搜索出多条交叉引用，选其中一个最大的函数（约1700行左右的伪代码）

```c++
L"DebugCanvasObject"
```



### 直接拉到函数底部往上看

```c
__int64 __fastcall sub_14C9A7B80(__int64 a1, __int64 a2, __int64 a3)
{
    // ...
    
    // 这里的1024其实是APlayerController下MyHUD对象的偏移
    // 可以先Dump SDK，然后在IDA中搜索该偏移（Hex、Dec）就能快速定位到代码段
    if ( *(_QWORD *)(v237 + 1024) )
    {
        v249 = v291;
        *(_QWORD *)(v291 + 624) = v245;
        sub_14CA45BB0(*(_QWORD *)(v237 + 1024), v246, v249);
        // 这里是调用虚表中的PostRender函数，其下标为1840 / 8
        // PlayerController->MyHUD->PostRender();
        // 同时将自身MyHubd作为rcx进行传递
        // 直接对着这行代码下断点，就能定位到真正的PostRender函数，做特征码即可
        (*(void (__fastcall **)(_QWORD))(**(_QWORD **)(v237 + 1024) + 1840i64))(*(_QWORD *)(v237 + 1024));
        v250 = v291;
        *(_QWORD *)(v246 + 616) = v219;
        *(_QWORD *)(v250 + 616) = v293;
        v251 = *(_DWORD *)(v237 + 36);
        if ( (int)v251 >= (int)qword_154A9B22C )
        {
            v253 = 0i64;
        }
        else
        {
            v252 = (int)sub_1408F39D0(v251);
            v253 = *(_QWORD *)(qword_154A9B238 + 8 * v252) + 24i64 * (int)sub_1408F41D0(v251);
        }
        if ( (*(_DWORD *)(v253 + 8) & 0x20000000) == 0 )
            sub_14CA45BB0(*(_QWORD *)(v237 + 1024), 0i64, 0i64);
        v219 = v284;
    }
    
    // ...
}
```



### 特征码

1. 搜索到特征码后，向前搜索0x1000字节，找到"40 55"即"push rbp"即为函数头部

```c
"48 89 9B ?? ?? ?? ?? 48 8B CE C7 83 ?? ?? ?? ?? ?? ?? ?? ?? C7 83 ?? ?? ?? ?? ?? ?? ?? ?? C7 83 ?? ?? ?? ?? ?? ?? ?? ?? 48 C7 83 ?? ?? ?? ?? ?? ?? ?? ?? 48 8B 96 ?? ?? ?? ?? 48 8B 06 4C 8D 82 ?? ?? ?? ?? 48 81 C2 ?? ?? ?? ?? FF 90 ?? ?? ?? ?? E9"
```

```c
DeltaForceClient-Win64-Shipping_dump.exe+CA4B19D - 48 89 9B 60020000     - mov [rbx+00000260],rbx
DeltaForceClient-Win64-Shipping_dump.exe+CA4B1A4 - 48 8B CE              - mov rcx,rsi
DeltaForceClient-Win64-Shipping_dump.exe+CA4B1A7 - C7 83 58020000 00008040 - mov [rbx+00000258],40800000
DeltaForceClient-Win64-Shipping_dump.exe+CA4B1B1 - C7 83 5C020000 00004842 - mov [rbx+0000025C],42480000
DeltaForceClient-Win64-Shipping_dump.exe+CA4B1BB - C7 83 48020000 00008040 - mov [rbx+00000248],40800000
DeltaForceClient-Win64-Shipping_dump.exe+CA4B1C5 - 48 C7 83 4C020000 00004842 - mov qword ptr [rbx+0000024C],42480000
DeltaForceClient-Win64-Shipping_dump.exe+CA4B1D0 - 48 8B 96 C8030000     - mov rdx,[rsi+000003C8]
DeltaForceClient-Win64-Shipping_dump.exe+CA4B1D7 - 48 8B 06              - mov rax,[rsi]
DeltaForceClient-Win64-Shipping_dump.exe+CA4B1DA - 4C 8D 82 4C020000     - lea r8,[rdx+0000024C]
DeltaForceClient-Win64-Shipping_dump.exe+CA4B1E1 - 48 81 C2 54020000     - add rdx,00000254
DeltaForceClient-Win64-Shipping_dump.exe+CA4B1E8 - FF 90 08070000        - call qword ptr [rax+00000708]
```

## 定位ProcessEvent虚表位置

### UE引擎中，ProcessEvent是UObject下的一个虚表函数

借助这个函数，引擎可以在运行时通过反射执行方法，其函数原型如下：

```c++
// 参数1：UE中的Function对象
// 参数2：参数列表指针
void UObject::ProcessEvent(PVOID FuncObject, PVOID pArgList);
```

------

### UE中会大量调用ProcessEvent这个函数，所以直接右键查找引用

会得到如下的函数：

```c++
void UPropertyValue::ApplyViaFunctionSetter(UObject* TargetObject)
{
	//Reference: ScriptCore.cpp, UObject::CallFunctionByNameWithArguments

	if (!TargetObject)
	{
		UE_LOG(LogVariantContent, Error, TEXT("Trying to apply via function setter with a nullptr target object! (UPropertyValue: %s)"), *GetFullDisplayString());
		return;
	}
	if (!PropertySetter)
	{
		UE_LOG(LogVariantContent, Error, TEXT("Trying to apply via function setter with a nullptr function setter! (UPropertyValue: %s)"), *GetFullDisplayString());
		return;
	}

	FProperty* LastParameter = nullptr;

	// find the last parameter
	for ( TFieldIterator<FProperty> It(PropertySetter); It && (It->PropertyFlags&(CPF_Parm|CPF_ReturnParm)) == CPF_Parm; ++It )
	{
		LastParameter = *It;
	}

	// Parse all function parameters.
	uint8* Parms = (uint8*)FMemory_Alloca(PropertySetter->ParmsSize);
	FMemory::Memzero( Parms, PropertySetter->ParmsSize );

	for (TFieldIterator<FProperty> It(PropertySetter); It && It->HasAnyPropertyFlags(CPF_Parm); ++It)
	{
		FProperty* LocalProp = *It;
		checkSlow(LocalProp);
		if (!LocalProp->HasAnyPropertyFlags(CPF_ZeroConstructor))
		{
			LocalProp->InitializeValue_InContainer(Parms);
		}
	}

	const uint32 ExportFlags = PPF_None;
	int32 NumParamsEvaluated = 0;
	bool bAppliedRecordedData = false;

	FFieldClass* ThisValueClass = GetPropertyClass();
	int32 ThisValueSize = GetValueSizeInBytes();
	const TArray<uint8>& RecordedData = GetRecordedData();

	for( TFieldIterator<FProperty> It(PropertySetter); It && It->HasAnyPropertyFlags(CPF_Parm) && !It->HasAnyPropertyFlags(CPF_OutParm|CPF_ReturnParm); ++It, NumParamsEvaluated++ )
	{
		FProperty* PropertyParam = *It;
		checkSlow(PropertyParam); // Fix static analysis warning

		// Check for a default value
		FString* Defaults = PropertySetterParameterDefaults.Find(PropertyParam->GetName());
		if (Defaults)
		{
			const TCHAR* Result = PropertyParam->ImportText( **Defaults, PropertyParam->ContainerPtrToValuePtr<uint8>(Parms), ExportFlags, NULL );
			if (!Result)
			{
				UE_LOG(LogVariantContent, Error, TEXT("Failed at applying the default value for parameter '%s' of PropertyValue '%s'"), *PropertyParam->GetName(), *GetFullDisplayString());
			}
		}

		// Try adding our recorded data bytes
		if (!bAppliedRecordedData && PropertyParam->GetClass() == ThisValueClass)
		{
			bool bParamMatchesThisProperty = true;

			if (ThisValueClass->IsChildOf(FStructProperty::StaticClass()))
			{
				UScriptStruct* ThisStruct = GetStructPropertyStruct();
				UScriptStruct* PropStruct = CastField<FStructProperty>(PropertyParam)->Struct;

				bParamMatchesThisProperty = (ThisStruct == PropStruct);
			}

			if (bParamMatchesThisProperty)
			{
				uint8* StartAddr = It->ContainerPtrToValuePtr<uint8>(Parms);
				FMemory::Memcpy(StartAddr, RecordedData.GetData(), ThisValueSize);
				bAppliedRecordedData = true;
			}
		}
	}

	// HACK: Restore Visibility properties to operating recursively. Temporary until 4.23
	if (PropertySetter->GetName() == TEXT("SetVisibility") && PropertySetter->ParmsSize == 2 && Parms)
	{
		Parms[1] = true;
	}

	// Only actually call the function if we managed to pack our recorded bytes in the params. Else we will
	// just reset the object to defaults
	if (bAppliedRecordedData)
	{
		FEditorScriptExecutionGuard ScriptGuard;
         // ----------------------------------------------------这里调用了ProcessEvent-------------------------------------------------
		TargetObject->ProcessEvent(PropertySetter, Parms);
	}
	else
	{
		UE_LOG(LogVariantContent, Error, TEXT("Did not find a parameter that could receive our value of class %s"), *GetPropertyClass()->GetName());
	}

	// Destroy our params
	for( TFieldIterator<FProperty> It(PropertySetter); It && It->HasAnyPropertyFlags(CPF_Parm); ++It )
	{
		It->DestroyValue_InContainer(Parms);
	}
}
```

易得字符串特征，在IDA中搜索即可定位到引用

```c++
"Did not find a parameter that could receive our value of class %s";
"Failed at applying the default value for parameter '%s' of PropertyValue '%s";
"SetVisibility"
```

这里以八宝粥为例子，IDA中伪代码如下：

```c++
      //   L"SetVisibility"就是特征点，与源码中对照可知判断是否等于2（xxx == 2）
	  v43 = !(unsigned int)sub_1483FB980(v42, L"SetVisibility") && *(_WORD *)(a1[16] + 196i64) == 2 && v10;
      off_1500540A0(v56);
      sub_14080A880(v56, 0i64);
      if ( off_1500540A0(v56) )
      {
        v44 = off_1500540A0(v56);
        sub_14841A4C0(v44);
      }
	  // 再将返回值判断，如果为真，赋值为true
      if ( v43 )
        v10[1] = 1;
      if ( v19 )
      {
        sub_148824CC0(v50);
        // 这里非常明显就是调用ProcessEvent的虚表，v67就是UObject指针，虚表位置为544 / 8 = 68，所以下标就是[68]
        // 这里非常明显还有一个特征，这里的v67同时将this指针作为参数1传入
        (*(void (__fastcall **)(__int64, _QWORD, char *))(*(_QWORD *)v67 + 544i64))(v67, a1[16], v10);
        sub_148825C70(v50);
      }
      else if ( (unsigned __int8)byte_150655890 >= 2u )
      {
        v45 = (*(__int64 (__fastcall **)(_QWORD *))(*a1 + 640i64))(a1);
        sub_148552FD0(v45, v56);
        if ( v57 )
          k = (void *)off_1500540A0(v56);
        sub_14848CEE0(
          (unsigned int)"Unknown",
          1366,
          (unsigned int)&unk_150655894,
          2,
          (__int64)L"Did not find a parameter that could receive our value of class %s",
          k);
        off_1500540A0(v56);
        sub_14080A880(v56, 0i64);
        if ( off_1500540A0(v56) )
        {
          v46 = off_1500540A0(v56);
          sub_14841A4C0(v46);
        }
      }
```
