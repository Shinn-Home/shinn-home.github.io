---
title: "UE虚幻引擎结构分析(2)：UObject"
date: 2023-03-11T12:00:00+08:00
lastmod: 2023-03-11T12:00:00+08:00
draft: false
author: "Shinn"
images: []
tags: ["虚幻引擎", "逆向工程"]
categories: ["游戏引擎逆向、游戏安全分析"]

twemoji: false
lightgallery: true
---

<!--more-->

## 万物基于UObject

### UObject

```c++
// @UObject.h

/** 
 * The base class of all UE4 objects. The type of an object is defined by its UClass.
 * This provides support functions for creating and using objects, and virtual functions that should be overridden in child classes.
 * 
 * @see https://docs.unrealengine.com/en-us/Programming/UnrealArchitecture/Objects
 */
class COREUOBJECT_API UObject : public UObjectBaseUtility
{
public:
    
}
```



### UObjectBaseUtility

```c++
// @UObjectBaseUtility.h

/**
 * Provides utility functions for UObject, this class should not be used directly
 */
class COREUOBJECT_API UObjectBaseUtility : public UObjectBase
{
public:
    
}
```



### UObjectBase（UE万物之源）

```c++
// @UObjectBaseUtility.h

/** 
 * Low level implementation of UObject, should not be used directly in game code 
 */
class COREUOBJECT_API UObjectBase
{
public:
    /** 
	 * Returns the unique ID of the object...these are reused so it is only unique while the object is alive.
	 * Useful as a tag.
	**/
	FORCEINLINE uint32 GetUniqueID() const
	{
		return (uint32)InternalIndex;
	}

	/** Returns the UClass that defines the fields of this object */
	FORCEINLINE UClass* GetClass() const
	{
		return ClassPrivate;
	}
	
	/** Returns the UObject this object resides in */
	FORCEINLINE UObject* GetOuter() const
	{
		return OuterPrivate;
	}

	/** Returns the logical name of this object */
	FORCEINLINE FName GetFName() const
	{
		return NamePrivate;
	}
    
private:
    /** Flags used to track and report various object states. This needs to be 8 byte aligned on 32-bit
	    platforms to reduce memory waste */
	EObjectFlags					ObjectFlags;	

	/** Index into GObjectArray...very private. */
	int32							InternalIndex;

	/** Class the object belongs to. */
	UClass*							ClassPrivate;

	/** Name of this object */
	FName							NamePrivate;	

	/** Object this object resides in. */
	UObject*						OuterPrivate;	
    
}
```

```c++
// @UObjectBaseUtility.h

/** 
 * Low level implementation of UObject, should not be used directly in game code 
 * UObject的低级实现，不应该直接用于游戏代码中
 */
class COREUOBJECT_API UObjectBase
{
private:
    /** Flags used to track and report various object states. This needs to be 8 byte aligned on 32-bit
	    platforms to reduce memory waste 
	    存储对象的各种标识，是否为临时对象、是否回收
	*/
	EObjectFlags					ObjectFlags;		// 8Byte(s)

	/** Index into GObjectArray...very private. 当前对象在GObjectArray中的序号 */
	int32							InternalIndex;		// 4Byte(s)

	/** Class the object belongs to. 指向一个UClass对象 */
	UClass*							ClassPrivate;		// 8Byte(s)		Offset:0x10

	/** Name of this object 当前对象的FName对象，这个对象由8字节组成，前4字节为ObjectId */
	FName							NamePrivate;		// 8Byte(s)		Offset:0x18(内存对齐)

	/** Object this object resides in. 指向这个class的父类！ */
	UObject*						OuterPrivate;		// 8Byte(s)		Offset:0x20
}
```
