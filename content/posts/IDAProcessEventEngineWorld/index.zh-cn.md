---
title: "IDA分析引擎：ProcessEvent虚表下标、定位GEngine、GWorld"
date: 2023-05-09T12:00:00+08:00
lastmod: 2023-05-09T12:00:00+08:00
draft: false
author: "Shinn"
images: []
tags: ["虚幻引擎", "逆向工程"]
categories: ["游戏引擎逆向、游戏安全分析"]

twemoji: false
lightgallery: true
---

<!--more-->

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
				UE_LOG(LogVariantContent, Error, TEXT("Failed at applying the default value for parameter '%s' of PropertyValue '%s"), *PropertyParam->GetName(), *GetFullDisplayString());
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

这里以三角洲为例子，IDA中伪代码如下：

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

## GetWorldFromContextObject一箭双雕

```c++
// 1. 这个函数返回值就是GWorld指针
// 2. 同时注意，这个GetWorldFromContextObject是属于UEngine的一个成员方法，那么rcx寄存器就是GEngine的指针
UWorld* UEngine::GetWorldFromContextObject(const UObject* Object, EGetWorldErrorMode ErrorMode) const
{
	if (Object == nullptr)
	{
		switch (ErrorMode)
		{
		case EGetWorldErrorMode::Assert:
			check(Object);
			break;
		case EGetWorldErrorMode::LogAndReturnNull:
			FFrame::KismetExecutionMessage(TEXT("A null object was passed as a world context object to UEngine::GetWorldFromContextObject()."), ELogVerbosity::Warning);
			//UE_LOG(LogEngine, Warning, TEXT("UEngine::GetWorldFromContextObject() passed a nullptr"));
			break;
		case EGetWorldErrorMode::ReturnNull:
			break;
		}
		return nullptr;
	}

	bool bSupported = true;
	UWorld* World = (ErrorMode == EGetWorldErrorMode::Assert) ? Object->GetWorldChecked(/*out*/ bSupported) : Object->GetWorld();
	if (bSupported && (World == nullptr) && (ErrorMode == EGetWorldErrorMode::LogAndReturnNull))
	{
		FFrame::KismetExecutionMessage(*FString::Printf(TEXT("No world was found for object (%s) passed in to UEngine::GetWorldFromContextObject()."), *GetPathNameSafe(Object)), ELogVerbosity::Warning);
	}
	return (bSupported ? World : GWorld);
}
```



## 可得特征码字符串

```c++
// IDA直接搜索string(Unicode)
"No world was found for object (%s) passed in to UEngine::GetWorldFromContextObject()."
"A null object was passed as a world context object to UEngine::GetWorldFromContextObject()."
```



## 定位GWorld方法2

在IDA搜索字符串，得到`UWorld* FSeamlessTravelHandler::Tick()`

```c++
"SeamlessTravel FlushLevelStreaming";
"SeamlessTravel finished in %.2f seconds";
```

```c++
UWorld* FSeamlessTravelHandler::Tick()
{
    // .....
    
    // ----------------------------------------------------------------------特征，这里会将GWorld置0-------------------
    GWorld = nullptr;

    // mark everything else contained in the world to be deleted
    for (auto LevelIt(CurrentWorld->GetLevelIterator()); LevelIt; ++LevelIt)
    {
        if (const ULevel* Level = *LevelIt)
        {
            UWorld* World = CastChecked<UWorld>(Level->GetOuter());
            if (!World->HasMarkedObjectsPendingKill())
            {
                World->MarkObjectsPendingKill();
            }
        }
    }

    for (ULevelStreaming* LevelStreaming : CurrentWorld->GetStreamingLevels())
    {
        // If an unloaded levelstreaming still has a loaded level we need to mark its objects to be deleted as well
        if (LevelStreaming->GetLoadedLevel())
        {
            UWorld* World = CastChecked<UWorld>(LevelStreaming->GetLoadedLevel()->GetOuter());
            if (!World->HasMarkedObjectsPendingKill())
            {
                World->MarkObjectsPendingKill();
            }
        }
    }

    CurrentWorld = nullptr;

    // collect garbage to delete the old world
    // because we marked everything in it pending kill, references will be NULL'ed so we shouldn't end up with any dangling pointers
    CollectGarbage( GARBAGE_COLLECTION_KEEPFLAGS, true );

    if (GIsEditor)
    {
        CollectGarbage( GARBAGE_COLLECTION_KEEPFLAGS, true );
    }

    appDefragmentTexturePool();
    appDumpTextureMemoryStats(TEXT(""));

    #if !(UE_BUILD_SHIPPING || UE_BUILD_TEST)
    // verify that we successfully cleaned up the old world
    GEngine->VerifyLoadMapWorldCleanup();
    #endif
    // Clean out NetDriver's Packagemaps, since they may have a lot of NULL object ptrs rotting in the lookup maps.
    if (NetDriver)
    {
        NetDriver->PostSeamlessTravelGarbageCollect();
    }

    // set GWorld to the new world and initialize it
    GWorld = LoadedWorld;
    if (!LoadedWorld->bIsWorldInitialized)
    {
        LoadedWorld->InitWorld();
    }
    bWorldChanged = true;
    // Track session change on seamless travel.
    NETWORK_PROFILER(GNetworkProfiler.TrackSessionChange(true, LoadedWorld->URL));


    checkSlow((LoadedWorld->GetNetMode() == NM_Client) == bIsClient);

    if (bCreateNewGameMode)
    {
        LoadedWorld->SetGameMode(PendingTravelURL);
    }

    // if we've already switched to entry before and this is the transition to the new map, re-create the gameinfo
    if (bSwitchedToDefaultMap && !bIsClient)
    {
        if (FAudioDevice* AudioDevice = LoadedWorld->GetAudioDeviceRaw())
        {
            AudioDevice->SetDefaultBaseSoundMix(LoadedWorld->GetWorldSettings()->DefaultBaseSoundMix);
        }

        // Copy cheat flags if the game info is present
        // @todo UE4 FIXMELH - see if this exists, it should not since it's created in GameMode or it's garbage info
        if (LoadedWorld->NetworkManager != nullptr)
        {
            LoadedWorld->NetworkManager->bHasStandbyCheatTriggered = bHasStandbyCheatTriggered;
        }
    }

    // Make sure "always loaded" sub-levels are fully loaded
    {
        SCOPE_LOG_TIME_IN_SECONDS(TEXT("    SeamlessTravel FlushLevelStreaming "), nullptr)
            LoadedWorld->FlushLevelStreaming(EFlushLevelStreamingType::Visibility);	
    }   
    
    
    // .....
}
```



## 定位GWorld方法3

UE引擎中存在方法，如下所示，有调用`GetWorldFromContextObject`方法

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

这里可得字符串特征，直接定位到IDA

```c++
"Unable to access world with owner: %s";
```
