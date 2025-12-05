// Coccinelle script to fix 'pFunc' function pointer casts to use proper
// types to prevent runtime CFI violations, e.g. under RAP.
//
// fix_nvoc_pfunc_addr.cocci already replaced the function pointer with a
// thunk. What's left is to actually generate the thunk declarations and
// definitions.
//
//   NV_STATUS (*pFunc)(void *, void *);
//
// This script depends on fix_nvoc_pfunc_addr.cocci to generate a file
// 'pfunc.list' with all the functions that have been replaced (see
// cocci.sh:pfunc_list_filter()).
//
// Implementations aren't limited to generated/ but live also in src/kernel/
// or even arch/nvalloc/. Therefore scan all source files:
//
// options: --dir . --allow-inconsistent-paths
//
// The --allow-inconsistent-paths is to work around bogus(?) warnings.
//
// (c) 2025,2026 Open Source Security, Inc. All Rights Reserved.

@initialize:python@
@@
with open('pfunc.list', 'r') as file:
	pfuncs = file.read().splitlines()

// search for potential pFunc decls, filtered by @pfunc_decl_filter@
@pfunc_decl@
identifier fn;
identifier a1, a2;
type T1, T2, R;
@@
(
R fn(T1 a1);
|
R fn(T1 a1, T2 a2);
)

@script:python pfunc_decl_filter@
func << pfunc_decl.fn;
@@
if func not in pfuncs:
	cocci.include_match(False)
#else:
#	print(f">>> {func} included")

// Add thunk decls right next to the original function's decl to make sure
// it'll be declared when its address is taken.
@pfunc_thunk_decl depends on pfunc_decl_filter@
identifier pfunc_decl.fn;
type pfunc_decl.R;
parameter list P;
fresh identifier thunk = fn ## "_THUNK";
typedef NV_STATUS;
@@
// XXX: matching function decls is only poorly supported, so we need this hack
-R fn(P)
+R fn(P);
+NV_STATUS thunk(void *obj, void *arg)
;

// search for potential pFunc definitions, filtered by @pfunc_def_filter@
//
// TODO: Try to merge with pfunc_decl*
@pfunc_def@
identifier fn;
identifier a1, a2;
type T1, T2, R;
@@
(
R fn(T1 a1) { ... }
|
R fn(T1 a1, T2 a2) { ... }
)

@script:python pfunc_def_filter@
func << pfunc_def.fn;
@@
if func not in pfuncs:
	cocci.include_match(False)
#else:
#	print(f">>> {func} included")

// Add thunk definitions
//
// TODO: merge all of these
@pfunc_thunk_def_two_args_inline depends on pfunc_def_filter@
identifier pfunc_def.fn;
identifier pfunc_def.a1, pfunc_def.a2;
type pfunc_def.T1, pfunc_def.T2, pfunc_def.R;
fresh identifier thunk = fn ## "_THUNK";
typedef NV_STATUS;
@@
 static inline R fn(T1 a1, T2 a2) { ... }
+static inline NV_STATUS thunk(void *obj, void *arg)
+{
+	return fn((T1)obj, (T2)arg);
+}

@pfunc_thunk_def_two_args depends on pfunc_def_filter && !pfunc_thunk_def_two_args_inline@
identifier pfunc_def.fn;
identifier pfunc_def.a1, pfunc_def.a2;
type pfunc_def.T1, pfunc_def.T2, pfunc_def.R;
fresh identifier thunk = fn ## "_THUNK";
typedef NV_STATUS;
@@
 R fn(T1 a1, T2 a2) { ... }
+NV_STATUS thunk(void *obj, void *arg)
+{
+	return fn((T1)obj, (T2)arg);
+}

@pfunc_thunk_def_one_arg_inline depends on pfunc_def_filter@
identifier pfunc_def.fn;
identifier pfunc_def.a1;
type pfunc_def.T1, pfunc_def.R;
fresh identifier thunk = fn ## "_THUNK";
typedef NV_STATUS;
@@
 static inline R fn(T1 a1) { ... }
+static inline NV_STATUS thunk(void *obj, void *arg)
+{
+	return fn((T1)obj);
+}

@pfunc_thunk_def_one_arg depends on pfunc_def_filter && !pfunc_thunk_def_one_arg_inline@
identifier pfunc_def.fn;
identifier pfunc_def.a1;
type pfunc_def.T1, pfunc_def.R;
fresh identifier thunk = fn ## "_THUNK";
typedef NV_STATUS;
@@
 R fn(T1 a1) { ... }
+NV_STATUS thunk(void *obj, void *arg)
+{
+	return fn((T1)obj);
+}
