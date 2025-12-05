#!/bin/sh
#
# Helper to invoke spatch with optional pre- and post-processing filters and
# optional additional arguments..
#
# Not meant to be used directly but invoked via Kbuild!
#
# (c) 2025,2026 Open Source Security, Inc. All Rights Reserved.

pfunc_filter() {
	# What a hack!
	#
	# coccinelle doesn't evaluate both sides of a #if ...  #else ... #endif
	# block and even worse, it doesn't even implement enough preprocessor
	# logic to actually understand the #if expression and always only
	# handles the #if branch for non-trivial expressions.
	# Work around that by modifying the expression to '#if 0' and use
	# --noif0-passing to get the #else branch. *sigh!*
	#
	# Hack #2:
	# On top of that we need yet another hack to get thunk definitions as
	# blindly adding thunks for all ever possible functions doesn't work
	# (there are multiple decls that'd lead to multiple static inline thunk
	# definitions). So we record which functions we want a thunk for via
	# pfunc_list_filter() and use that to actually generate thunks only for
	# these. Gross!
	case "$1" in
		pre)	sed 's|\(#if\) \(NVOC_EXPORTED_METHOD_DISABLED_BY_FLAG\)|\1 0//\2|' -i generated/*.[ch]; ;;
		diff)	sed 's|\(#if\) 0//\(NVOC_EXPORTED_METHOD_DISABLED_BY_FLAG\)|\1 \2|'; ;;
		post)	sed 's|\(#if\) 0//\(NVOC_EXPORTED_METHOD_DISABLED_BY_FLAG\)|\1 \2|' -i generated/*.[ch]; ;;
	esac
}

pfunc_list_filter() {
	case "$1" in
		# To create thunks for all replaced pFunc replacements, we create a
		# file 'pfunc.list' with all their names. That'll get used by
		# fix_nvoc_pfunc_thunk.cocci to create thunks for each of these -- and
		# only these.
		#
		# Don't look too close at how we do that -- yet another hack ;P
		diff)
			fifo=$(mktemp -u)
			mkfifo "$fifo"

			sed -n 's|^-.*pFunc=.*&\(.*\),|\1|p' <"$fifo" >pfunc.list &
			sed_pid=$!

			# copy the diff to the 'pfunc.list' creation process
			pfunc_filter "$@" | tee "$fifo"

			wait $sed_pid
			rm "$fifo"
			;;

		*)	pfunc_filter "$@";;
	esac
}

pfunc_sli_filter() {
	# Oh well, another hack.
	#
	# coccinelle cannot cope with the SLI_LOOP_START / SLI_LOOP_END macros,
	# leading to parse errors and, in turn, missing thunk generation.
	# Work around that by simplify the macros, similar to what we already
	# do for NVOC_EXPORTED_METHOD_DISABLED_BY_FLAG in pfunc_filter().
	#
	# Fortunately, only this one file needs it:
	SLI_FILES="
		arch/nvalloc/unix/src/unix_console.c
		"

	case "$1" in
		pre)	sed 's|\(SLI_LOOP_START\)|do { //\1|;s|\(SLI_LOOP_END\)|} while(0);//\1|' -i $SLI_FILES
			pfunc_filter "$@"
			;;
		diff)	sed 's|do { //\(SLI_LOOP_START\)|\1|;s|} while(0);//\(SLI_LOOP_END\)|\1|' | \
			pfunc_filter "$@"
			;;
		post)	sed 's|do { //\(SLI_LOOP_START\)|\1|;s|} while(0);//\(SLI_LOOP_END\)|\1|' -i $SLI_FILES
			pfunc_filter "$@"
			;;
	esac
}

null_filter() {
	case "$1" in
		pre)	;;
		diff)	cat; ;;
		post)	;;
	esac
}

filter() {
	${1:-null}_filter "$2"
}

check_prog() {
	BIN="$1"
	PKG="$2"

	if [ -z "$(command -v $BIN 2>/dev/null)" ]; then
		echo >&2 "error: $BIN not found, please install $PKG!"
		return 1
	fi

	return 0
}

if [ $# -lt 2 ]; then
	echo >&2 "error: spatch file and program missing!"
	exit 1
fi

SCRIPT=$1; shift
SPATCH=$1; shift

if ! check_prog "$SPATCH" coccinelle; then
	echo >&2 "error: missing required programs!"
	exit 2
fi

FILTER=$(echo "$SCRIPT" | sed -n 's|.*:||p')
SCRIPT=${SCRIPT%:*}
EXTRA_ARGS=$(sed -n 's|// options: ||p' $SCRIPT)

filter "$FILTER" pre
$SPATCH --sp-file "$SCRIPT" "$@" $EXTRA_ARGS | filter "$FILTER" diff
filter "$FILTER" post
