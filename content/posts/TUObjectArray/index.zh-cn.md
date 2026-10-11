---
title: "UE虚幻引擎结构分析(3)：TUObjectArray"
date: 2023-03-15T12:00:00+08:00
lastmod: 2023-03-15T12:00:00+08:00
draft: false
author: "Shinn"
images: []
tags: ["虚幻引擎", "逆向工程"]
categories: ["游戏引擎逆向、游戏安全分析"]

twemoji: false
lightgallery: true
---

<!--more-->

## TUObjectArray

1. 这个TUObjectArray，其实就是常说的GObject对象
2. 这个对象（队列），存储着当前UE程序内所有的UObject对象



### FUObjectArray

```c++
/***
*
* FUObjectArray replaces the functionality of GObjObjects and UObject::Index
*
* Note the layout of this data structure is mostly to emulate the old behavior and minimize code rework during code restructure.
* Better data structures could be used in the future, for example maybe all that is needed is a TSet<UObject *>
* One has to be a little careful with this, especially with the GC optimization. I have seen spots that assume
* that non-GC objects come before GC ones during iteration.
*
**/
class COREUOBJECT_API FUObjectArray
{
public:
    
private:
	// note these variables are left with the Obj prefix so they can be related to the historical GObj versions

	/** First index into objects array taken into account for GC.							*/
	int32 ObjFirstGCIndex;
	/** Index pointing to last object created in range disregarded for GC.					*/
	int32 ObjLastNonGCIndex;
	/** Maximum number of objects in the disregard for GC Pool */
	int32 MaxObjectsNotConsideredByGC;

	/** If true this is the intial load and we should load objects int the disregarded for GC range.	*/
	bool OpenForDisregardForGC;
    
    // 类型重命名
    typedef FChunkedFixedUObjectArray TUObjectArray;
    
    /** Array of all live objects. 所有存活的对象 */
	TUObjectArray ObjObjects;		// Offset:0x10(内存对齐)
    
    // 忽略部分成员...
}
```



### TUObjectArray（FChunkedFixedUObjectArray重命名）

```c++
/**
* Simple array type that can be expanded without invalidating existing entries.
* This is critical to thread safe FNames.
* @param ElementType Type of the pointer we are storing in the array
* @param MaxTotalElements absolute maximum number of elements this array can ever hold
* @param ElementsPerChunk how many elements to allocate in a chunk
**/
class TUObjectArray
{
    enum
	{
		NumElementsPerChunk = 64 * 1024,
	};

	/** Master table to chunks of pointers UObject指针 Offset:0x0 **/
    /** 可以粗浅理解为一个二维数组FUObjectItem Objects[MaxChunks][MaxElements] **/
	FUObjectItem** Objects;
	/** If requested, a contiguous memory where all objects are allocated 一个指针，一般为NULL Offset:0x8 **/
	FUObjectItem* PreAllocatedObjects;
	/** Maximum number of elements 最大元素数量 Offset:0x10 **/
	int32 MaxElements;
	/** Number of elements we currently have 当前元素数量 Offset:0x14 **/
	int32 NumElements;
	/** Maximum number of chunks 最大的块数 Offset:0x18 **/
	int32 MaxChunks;
	/** Number of chunks we currently have 当前块数 Offset:0x1C  **/
	int32 NumChunks;
    
public:
    /**
	* Expands the array so that Element[Index] is allocated. New pointers are all zero.
	* @param Index The Index of an element we want to be sure is allocated
	**/
	void PreAllocate(int32 InMaxElements, bool bPreAllocateChunks) TSAN_SAFE
	{
		check(!Objects);
		MaxChunks = InMaxElements / NumElementsPerChunk + 1;
		MaxElements = MaxChunks * NumElementsPerChunk;
		Objects = new FUObjectItem*[MaxChunks];			// 这里分配"一维"数组
		FMemory::Memzero(Objects, sizeof(FUObjectItem*) * MaxChunks);
		if (bPreAllocateChunks)
		{
			// Fully allocate all chunks as contiguous memory
			PreAllocatedObjects = new FUObjectItem[MaxElements];	// 这里一口气分配超级大的内存，后面再分块
			for (int32 ChunkIndex = 0; ChunkIndex < MaxChunks; ++ChunkIndex)
			{
                 // 将一个个"块"挂载 
			    Objects[ChunkIndex] = PreAllocatedObjects + ChunkIndex * NumElementsPerChunk;
			}
			NumChunks = MaxChunks;
		}
	}
    
}
```



### FUObjectItem

```c++
/**
* Single item in the UObject array. 大小0x18(24字节)
*/
struct FUObjectItem
{
	// Pointer to the allocated object
	class UObjectBase* Object;
	// Internal flags
	int32 Flags;
	// UObject Owner Cluster Index
	int32 ClusterRootIndex;	
	// Weak Object Pointer Serial number associated with the object
	int32 SerialNumber;
}
```

```c++
// CE中内存查看器就是这样
000001DD3F978800 0000000040000000 0000000000000000
000001DD3B3E1A80 0000000042000000 00000000000003EA`
```



### FUObjectArray中ObjObjects的初始化

1. 在Visual Studio中查找引用，会得到以下结果（忽略其他无关项，这个就是分配内存的地方）

```c++
// @ UObjectArray.cpp调用
已确认引用	ObjObjects.PreAllocate(InMaxUObjects, bPreAllocateObjectArray);
```

2. 跳转到函数调用过去看看

```c++
//
// 这是一个类方法，所以第一个参数为FUObjectArray的指针
// 所以找到FUObjectArray的基址后，还需要偏移0x10才能得到真正的TUObjectArray指针（FUObjectArray->TUObjectArray->FUObjectItem->UObjectBase）
//
void FUObjectArray::AllocateObjectPool(int32 InMaxUObjects, int32 InMaxObjectsNotConsideredByGC, bool bPreAllocateObjectArray)
{
	check(IsInGameThread());

	MaxObjectsNotConsideredByGC = InMaxObjectsNotConsideredByGC;

	// GObjFirstGCIndex is the index at which the garbage collector will start for the mark phase.
	// If disregard for GC is enabled this will be set to an invalid value so that later we
	// know if disregard for GC pool has already been closed (at least once)
	ObjFirstGCIndex = DisregardForGCEnabled() ? -1 : 0;

	// Pre-size array.
	check(ObjObjects.Num() == 0);
	UE_CLOG(InMaxUObjects <= 0, LogUObjectArray, Fatal, TEXT("Max UObject count is invalid. It must be a number that is greater than 0."));
    // 这里分配内存
	ObjObjects.PreAllocate(InMaxUObjects, bPreAllocateObjectArray);

	if (MaxObjectsNotConsideredByGC > 0)
	{
		ObjObjects.AddRange(MaxObjectsNotConsideredByGC);
	}
}


```

3. 可得特征码字符串

```c++
"Max UObject count is invalid. It must be a number that is greater than 0."
```

4. 继续跟，看看哪里调用了FUObjectArray::AllocateObjectPool方法，会很容易得到以下函数

```c++
/**
 * Final phase of UObject initialization. all auto register objects are added to the main data structures.
 */
void UObjectBaseInit()
{
	SCOPED_BOOT_TIMING("UObjectBaseInit");

	// Zero initialize and later on get value from .ini so it is overridable per game/ platform...
	int32 MaxObjectsNotConsideredByGC = 0;
	int32 SizeOfPermanentObjectPool = 0;
	int32 MaxUObjects = 2 * 1024 * 1024; // Default to ~2M UObjects
	bool bPreAllocateUObjectArray = false;	

	// To properly set MaxObjectsNotConsideredByGC look for "Log: XXX objects as part of root set at end of initial load."
	// in your log file. This is being logged from LaunchEnglineLoop after objects have been added to the root set. 

	// Disregard for GC relies on seekfree loading for interaction with linkers. We also don't want to use it in the Editor, for which
	// FPlatformProperties::RequiresCookedData() will be false. Please note that GIsEditor and FApp::IsGame() are not valid at this point.
	if (FPlatformProperties::RequiresCookedData())
	{
		FString Value;
		bool bIsCookOnTheFly = FParse::Value(FCommandLine::Get(), TEXT("-filehostip="), Value);
		if (bIsCookOnTheFly)
		{
			GCreateGCClusters = false;
		}
		else
		{
			GConfig->GetInt(TEXT("/Script/Engine.GarbageCollectionSettings"), TEXT("gc.MaxObjectsNotConsideredByGC"), MaxObjectsNotConsideredByGC, GEngineIni);

			// Not used on PC as in-place creation inside bigger pool interacts with the exit purge and deleting UObject directly.
			GConfig->GetInt(TEXT("/Script/Engine.GarbageCollectionSettings"), TEXT("gc.SizeOfPermanentObjectPool"), SizeOfPermanentObjectPool, GEngineIni);
		}

		// Maximum number of UObjects in cooked game
		GConfig->GetInt(TEXT("/Script/Engine.GarbageCollectionSettings"), TEXT("gc.MaxObjectsInGame"), MaxUObjects, GEngineIni);

		// If true, the UObjectArray will pre-allocate all entries for UObject pointers
		GConfig->GetBool(TEXT("/Script/Engine.GarbageCollectionSettings"), TEXT("gc.PreAllocateUObjectArray"), bPreAllocateUObjectArray, GEngineIni);
	}
	else
	{
#if IS_PROGRAM
		// Maximum number of UObjects for programs can be low
		MaxUObjects = 100000; // Default to 100K for programs
		GConfig->GetInt(TEXT("/Script/Engine.GarbageCollectionSettings"), TEXT("gc.MaxObjectsInProgram"), MaxUObjects, GEngineIni);
#else
		// Maximum number of UObjects in the editor
		GConfig->GetInt(TEXT("/Script/Engine.GarbageCollectionSettings"), TEXT("gc.MaxObjectsInEditor"), MaxUObjects, GEngineIni);
#endif
	}

	if (MaxObjectsNotConsideredByGC <= 0 && SizeOfPermanentObjectPool > 0)
	{
		// If permanent object pool is enabled but disregard for GC is disabled, GC will mark permanent object pool objects
		// as unreachable and may destroy them so disable permanent object pool too.
		// An alternative would be to make GC not mark permanent object pool objects as unreachable but then they would have to
		// be considered as root set objects because they could be referencing objects from outside of permanent object pool.
		// This would be inconsistent and confusing and also counter productive (the more root set objects the more expensive MarkAsUnreachable phase is).
		SizeOfPermanentObjectPool = 0;
		UE_LOG(LogInit, Warning, TEXT("Disabling permanent object pool because disregard for GC is disabled (gc.MaxObjectsNotConsideredByGC=%d)."), MaxObjectsNotConsideredByGC);
	}

	// Log what we're doing to track down what really happens as log in LaunchEngineLoop doesn't report those settings in pristine form.
	UE_LOG(LogInit, Log, TEXT("%s for max %d objects, including %i objects not considered by GC, pre-allocating %i bytes for permanent pool."), 
		bPreAllocateUObjectArray ? TEXT("Pre-allocating") : TEXT("Presizing"),
		MaxUObjects, MaxObjectsNotConsideredByGC, SizeOfPermanentObjectPool);

	GUObjectAllocator.AllocatePermanentObjectPool(SizeOfPermanentObjectPool);
    // 这里面分配内存
	GUObjectArray.AllocateObjectPool(MaxUObjects, MaxObjectsNotConsideredByGC, bPreAllocateUObjectArray);

	void InitAsyncThread();
	InitAsyncThread();

	// Note initialized.
	Internal::GetUObjectSubsystemInitialised() = true;

	UObjectProcessRegistrants();
}
```

5. 可得特征码字符串

```c++
// 这个函数头部有一个特征字符串
"UObjectBaseInit"
```



### 全局变量

1. UE引擎中存在一个静态的全局变量

```c++
// Global UObject array instance
FUObjectArray GUObjectArray;
```

```c++
// 很明显这个全局变量的是FUObjectArray类型的
```
