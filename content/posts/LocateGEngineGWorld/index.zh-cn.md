---
title: "IDA分析引擎(2)：定位GEngine、GWorld"
date: 2023-05-16T12:00:00+08:00
lastmod: 2023-05-16T12:00:00+08:00
draft: false
author: "Shinn"
images: []
tags: ["虚幻引擎", "逆向工程"]
categories: ["游戏引擎逆向、游戏安全分析"]

twemoji: false
lightgallery: true
---

<!--more-->

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
