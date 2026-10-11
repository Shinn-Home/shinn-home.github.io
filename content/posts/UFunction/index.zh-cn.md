---
title: "UE虚幻引擎结构分析(5)：UFunction"
date: 2023-03-28T12:00:00+08:00
lastmod: 2023-03-28T12:00:00+08:00
draft: false
author: "Shinn"
images: []
tags: ["虚幻引擎", "逆向工程"]
categories: ["游戏引擎逆向、游戏安全分析"]

twemoji: false
lightgallery: true
---

<!--more-->

## UFunction

```c++
//
// Reflection data for a replicated or Kismet callable function.
//
class COREUOBJECT_API UFunction : public UStruct
{
	// ... (base class and other declarations remain)

public:
	/** EFunctionFlags set defined for this function */
	EFunctionFlags FunctionFlags;

	/** Number of parameters total */
	uint8 NumParms;
	
	/** Total size of parameters in memory */
	uint16 ParmsSize;
	
	/** Memory offset of return value property */
	uint16 ReturnValueOffset;
	
	/** Id of this RPC function call (must be FUNC_Net & (FUNC_NetService|FUNC_NetResponse)) */
	uint16 RPCId;
	
	/** Id of the corresponding response call (must be FUNC_Net & FUNC_NetService) */
	uint16 RPCResponseId;

	/** pointer to first local struct property in this UFunction that contains defaults */
	FProperty* FirstPropertyToInit;

#if UE_BLUEPRINT_EVENTGRAPH_FASTCALLS
	/** The event graph this function calls in to (persistent) */
	UFunction* EventGraphFunction;

	/** The state offset inside of the event graph (persistent) */
	int32 EventGraphCallOffset;
#endif

private:
	/** C++ function this is bound to 绑定到exe主模块的一个函数体(CE中静态、绿色的函数) */
	FNativeFuncPtr Func;		// 0xD8
}
```



## UStruct

```c++
/**
 * Base class for all UObject types that contain fields.
*/
class COREUOBJECT_API UStruct : public UField
#if USTRUCT_FAST_ISCHILDOF_IMPL == USTRUCT_ISCHILDOF_STRUCTARRAY
	, private FStructBaseChain
#endif
{
protected:
	friend struct Z_Construct_UClass_UStruct_Statics;
private:
	/** Struct this inherits from, may be null 继承的结构Offset:0x40 */
	UStruct* SuperStruct;		// 找法：在CoreUObject.Struct下,指向应为CoreUObject.Field的地址
	
public:
	/** Pointer to start of linked list of child fields */
	UField* Children;
	
	/** Pointer to start of linked list of child fields */
	FField* ChildProperties;

	/** Total size of all UProperties, the allocated structure may be larger due to alignment */
	int32 PropertiesSize;
	
	/** Alignment of structure in memory, structure will be at least this large */
	int32 MinAlignment;
	
	/** Script bytecode associated with this object */
	TArray<uint8> Script;

	/** In memory only: Linked list of properties from most-derived to base */
	FProperty* PropertyLink;
	
	/** In memory only: Linked list of object reference properties from most-derived to base */
	FProperty* RefLink;
	
	/** In memory only: Linked list of properties requiring destruction */
	FProperty* DestructorLink;
	
	/** In memory only: Linked list of properties requiring post constructor initialization */
	FProperty* PostConstructLink;

	/** Array of object references embedded in script code and referenced by FProperties */
	TArray<UObject*> ScriptAndPropertyObjectReferences;

	/** Contains a list of script properties that couldn't be resolved at load time */
	FUnresolvedScriptPropertiesArray* UnresolvedScriptProperties;

#if WITH_EDITORONLY_DATA
	/** List of wrapper UObjects for FProperties */
	TArray<UPropertyWrapper*> PropertyWrappers;
	
	/** Unique id incremented each time this class properties get destroyed */
	int32 FieldPathSerialNumber;
#endif

	/** Cached schema for optimized unversioned property serialization */
	mutable const struct FUnversionedStructSchema* UnversionedSchema;
}
```
