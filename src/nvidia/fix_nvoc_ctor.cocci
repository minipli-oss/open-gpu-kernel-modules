// Coccinelle script to fix 'objCreatefn' function pointer casts to use proper
// types to prevent runtime CFI violations, e.g. under RAP.
//
// As for fix_nvoc_dtor.cocci, we need to create a thunk.
//
// typedef NV_STATUS (*NVOC_DYNAMIC_OBJ_CREATE)(Dynamic**, Dynamic *pParent, NvU32 createFlags, va_list);
//
// (c) 2025,2026 Open Source Security, Inc. All Rights Reserved.

// replace function casts to (NVOC_DYNAMIC_OBJ_CREATE) with its thunk
@ctor_cast@
identifier fn;
fresh identifier fnthunk = fn ## "_THUNK";
@@
- (NVOC_DYNAMIC_OBJ_CREATE) &fn
+ &fnthunk

// add decl for the thunk
// XXX: little hacky, as the decl is in the .h file, thereby we cannot match on
// XXX: @ctor_cast@ and need to use heuristics based on the function name.
@thunk_decl@
identifier fn =~ "^__nvoc_objCreateDynamic_";
fresh identifier fnthunk = fn ## "_THUNK";
typedef NV_STATUS, Dynamic, NvU32, va_list;
type T1, T2, T3, T4, R;
@@
// XXX: matching function decls is only poorly supported, so we need this hack
-R fn(T1, T2, T3, T4)
+R fn(T1, T2, T3, T4);
+NV_STATUS fnthunk(Dynamic **, Dynamic *, NvU32, va_list)
;

// add thunk function
@thunk_def@
identifier ctor_cast.fn, ctor_cast.fnthunk, a1, a2, a3, a4;
typedef NV_STATUS, Dynamic, NvU32, va_list;
type T1, T2, T3, T4, R;
@@
R fn(T1 a1, T2 a2, T3 a3, T4 a4) { ... }
+
+NV_STATUS fnthunk(Dynamic **a1, Dynamic *a2, NvU32 a3, va_list a4) {
+  return fn((T1)a1, (T2)a2, a3, a4);
+}
