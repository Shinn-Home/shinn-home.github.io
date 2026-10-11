---
title: "UE虚幻引擎结构分析(4)：UEnum"
date: 2023-03-21T12:00:00+08:00
lastmod: 2023-03-21T12:00:00+08:00
draft: false
author: "Shinn"
images: []
tags: ["虚幻引擎", "逆向工程"]
categories: ["游戏引擎逆向、游戏安全分析"]

twemoji: false
lightgallery: true
---

<!--more-->

## UEnum

```c++
//
// Reflection data for an enumeration.
//
class COREUOBJECT_API UEnum : public UField
{
	// ... (base class and other declarations remain)

protected:
	/** List of pairs of all enum names and values. Offset:0x40 */
	TArray<TPair<FName, int64>> Names;

	/** How the enum was originally defined. */
	ECppForm CppForm;

	/** Enum flags. */
	EEnumFlags EnumFlags;

	/** pointer to function used to look up the enum's display name. Currently only assigned for UEnums generated for nativized blueprints */
	FEnumDisplayNameFn EnumDisplayNameFn;

	/** global list of all value names used by all enums in memory, used for property text import */
	static TMap<FName, UEnum*> AllEnumNames;

private:
	FString CppType;
}
```



## UField

```c++
class COREUOBJECT_API UField : public UObject
{
	DECLARE_CASTED_CLASS_INTRINSIC(UField, UObject, CLASS_Abstract, TEXT("/Script/CoreUObject"), CASTCLASS_UField)

	typedef UField BaseFieldClass;
	typedef UClass FieldTypeClass;

	/** Next Field in the linked list Offset:0x28 */
	UField* Next;
}
```
