// Coccinelle script to fix 'pFunc' function pointer casts to use proper
// types to prevent runtime CFI violations, e.g. under RAP.
//
// As for fix_nvoc_dtor.cocci, we need to create a thunk. The thunk takes two
// arguments, even if the implementation takes only one. That'll get handled
// when adding a thunk definition.
//
//   NV_STATUS (*pFunc)(void *, void *);
//
// As coccinelle cannot handle the preprocessor branches for the 'pFunc'
// assignment correctly, we need a workaround that simplifies the code so
// coccinelle can understand it (see cocci.sh:pfunc_filter()).
//
// This script handles the part of replacing taking the address of the real
// function. It uses heuristics based on the function name to avoid false
// positives. Post-processing in cocci.sh creates a file pfunc.list that'll
// get used by fix_nvoc_pfunc_thunk.cocci to create the thunks.
//
// (c) 2025,2026 Open Source Security, Inc. All Rights Reserved.

@initialize:python@
@@
import re

# cocci's regex support is too limiting, use python for the filtering
type_match = re.compile(r"void *\( *\* *\) *\( *void *\)")	# cocci adds spaces
func_match = re.compile(r"_(IMPL|DISPATCH|KERNEL|[0-9a-f]{6})$")

// search for (function) pointer casts (filtered in @pfunc_cast_filter@)
@pfunc_cast disable drop_cast@
identifier fn;
type T;
@@
 (T) &fn

@script:python pfunc_cast_filter@
t << pfunc_cast.T;
f << pfunc_cast.fn;
@@
if not type_match.search(t) or not func_match.search(f):
#	print(f">>> '({t}) {f}' didn't match")
	cocci.include_match(False)

// drop cast and replace function with a thunk
@remove_cast depends on pfunc_cast_filter@
identifier pfunc_cast.fn;
type pfunc_cast.T;
fresh identifier fnthunk = fn ## "_THUNK";
@@
- (T) &fn
+ &fnthunk
