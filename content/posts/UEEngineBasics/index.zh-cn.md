---
title: "UE虚幻引擎结构分析(1)：UE基础类"
date: 2023-03-06T12:00:00+08:00
lastmod: 2023-03-06T12:00:00+08:00
draft: false
author: "Shinn"
images: []
tags: ["虚幻引擎", "逆向工程"]
categories: ["游戏引擎逆向、游戏安全分析"]

twemoji: false
lightgallery: true
---

<!--more-->

## UE核心数据结构

1. UE的主要逻辑代码，位于如下路径

```
UnrealEngine-4.27.2-release\Engine\Source\Runtime\CoreUObject
```



### TArray

1. 这是一个UE中通用的队列类，可以灵活的存储不同类型的数据

```c++
// @Array.h
template<typename T>
class TArray
{
public:
    T* Data;
    ULONG ItemNum;
    ULONG Max;
}
```



### FString类

1. FString可以认为是继承了TArray
2. 一个FString大小为16字节

```c++
// @UnrealString.h
class FString : public TArray<wchar_t*>
{
public:
}
```



### UObjectBase

```c++
// @UObjectBase.h
class UObjectBase 
{
public:
	PVOID VMethodTable;		
	
    /** Flags used to track and report various object states. This needs to be 8 byte aligned on 32-bit
    platforms to reduce memory waste */
	EObjectFlags					ObjectFlags;

	/** Index into GObjectArray...very private. */
	int32							InternalIndex;

	/** Class the object belongs to. */
	UClass*							ClassPrivate;

	/** Name of this object */
	FName							NamePrivate;		// 0x18偏移

	/** Object this object resides in. */
	UObject*						OuterPrivate;
}
```



### FName

```c++
// @NameTypes.h

/** Externally, the instance number to represent no instance number is NAME_NO_NUMBER, 
    but internally, we add 1 to indices, so we use this #define internally for 
	zero'd memory initialization will still make NAME_None as expected */
#define NAME_NO_NUMBER_INTERNAL	0
```


```c++
// @UnrealNames.h
class FName
{
public:
     /**
	 * Returns the name of this object (with no path information)
	 * 
	 * @return Name of the object.
	 */
	FORCEINLINE FString GetName() const
	{
		return GetFName().ToString();
	}
    
    const FNameEntry* FName::GetDisplayNameEntry() const
    {
        // 这里终于出现NamePool了，同时注意这里的取GName的指针
        return &GetNamePool().Resolve(GetDisplayIndex());
    }
    
   	 /**
	 * Converts an FName to a readable format
	 *
	 * @return String representation of the name
	 */
    FString FName::ToString() const
	{
        if (GetNumber() == NAME_NO_NUMBER_INTERNAL)
        {
            // Avoids some extra allocations in non-number case
            return GetDisplayNameEntry()->GetPlainNameString();
        }
	
        FString Out;	
        ToString(Out);
        return Out;
	}
    
}
```



### NamePoolData

```c++
// @ UnrealNames.cpp

// 虚幻引擎中，GName其实就是NamePoolData，是一个静态的全局变量，通过GetNamePool返回其指针
static bool bNamePoolInitialized;
alignas(FNamePool) static uint8 NamePoolData[sizeof(FNamePool)];

// Only call this once per public FName function called
//
// Not using magic statics to run as little code as possible
static FNamePool& GetNamePool()
{
	if (bNamePoolInitialized)
	{
		return *(FNamePool*)NamePoolData;
	}

	FNamePool* Singleton = new (NamePoolData) FNamePool;
	bNamePoolInitialized = true;
	return *Singleton;
}
```



### FNamePool

```c++
// 这个就是所谓的GName，管理着所有的命名对象

// @UnrealNames.cpp
class FNamePool
{
public:
    // 构造方法
    FNamePool::FNamePool()
    {
        for (FNamePoolShardBase& Shard : ComparisonShards)
        {
            Shard.Initialize(Entries);
        }

    #if WITH_CASE_PRESERVING_NAME
        for (FNamePoolShardBase& Shard : DisplayShards)
        {
            Shard.Initialize(Entries);
        }
    #endif

        // Register all hardcoded names
    #define REGISTER_NAME(num, name) ENameToEntry[num] = Store(FNameStringView(#name, FCStringAnsi::Strlen(#name)));
    #include "UObject/UnrealNames.inl"
    #undef REGISTER_NAME

        // Make reverse mapping
        LargestEnameUnstableId = 0;
        for (uint32 ENameIndex = 0; ENameIndex < NAME_MaxHardcodedNameIndex; ++ENameIndex)
        {
            if (ENameIndex == NAME_None || ENameToEntry[ENameIndex])
            {
                EntryToEName.Add(ENameToEntry[ENameIndex], (EName)ENameIndex);
                LargestEnameUnstableId = FMath::Max(LargestEnameUnstableId, ENameToEntry[ENameIndex].ToUnstableInt());
            }
        }

        // Verify all ENames are unique
        if (NumAnsiEntries() != EntryToEName.Num())
        {
            // we can't print out here because there may be no log yet if this happens before main starts
            if (FPlatformMisc::IsDebuggerPresent())
            {
                UE_DEBUG_BREAK();
            }
            else
            {
                FPlatformMisc::PromptForRemoteDebugging(false);
                FMessageDialog::Open(EAppMsgType::Ok, NSLOCTEXT("UnrealEd", "DuplicatedHardcodedName", "Duplicate hardcoded name"));
                FPlatformMisc::RequestExit(false);
            }
        }
    }
}
```



### UObject/UnrealNames.inl

```c++
// Special zero value, meaning no name.
REGISTER_NAME(0,None)

// Class property types (name indices are significant for serialization).
REGISTER_NAME(1,ByteProperty)		// 这就是为什么IDA搜索ByteProperty可以快速定位GName
REGISTER_NAME(2,IntProperty)
REGISTER_NAME(3,BoolProperty)
REGISTER_NAME(4,FloatProperty)
...
```
