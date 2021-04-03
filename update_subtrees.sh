#!/usr/bin/env sh
update_subtree() {
    # set single parameters
    REMOTE="$1"
    LOCAL_SUBDIR="$2"
    REMOTE_SUBDIR="$3"

    # get content from repository
    git fetch "$REMOTE"
    FETCH_HEAD="$(git describe --always FETCH_HEAD)"
    SOURCE_HEAD="$FETCH_HEAD"

    # if a remote subdir is set, split the content to only have that subdir
    if test "x$REMOTE_SUBDIR" != "x"
    then
        touch "$REMOTE_SUBDIR" # this hack lets git-subtree split a non-worktree branch
        SOURCE_HEAD="$(git subtree split --prefix "$REMOTE_SUBDIR" "$FETCH_HEAD")"
    fi

    MESSAGE="Merge subtree $LOCAL_SUBDIR from $REMOTE $REMOTE_SUBDIR $FETCH_HEAD"

    # merge or add the subtree into the worktree
    git subtree merge --squash --prefix src/"$LOCAL_SUBDIR" "$SOURCE_HEAD" --message "$MESSAGE" ||
        git subtree add --squash --prefix src/"$LOCAL_SUBDIR" "$SOURCE_HEAD" --message "$MESSAGE" ||
        continue

    # if header names are provided, mutate them to be like libbtc, and copy them in
    shift 3
    for HEADER in "$@"
    do
        HEADERNAME=$(basename "$HEADER")
        sed \
            -e 's/^\(#ifndef _\)_*\([^_]*.*[^_]\)_*_$/\1_LIBBTC_\2__/' \
            -e 's/^\(#define _\)_*\([^_]*.*[^_]\)_*_\(\s.*$\|$\)/\1_LIBBTC_\2__\n\n#include "btc.h"\n\nLIBBTC_BEGIN_DECL/' \
            -e 's/^\(int\|void\|char\)/LIBBTC_API \1/' \
            -e '$ s/^\(#endif\)$/LIBBTC_END_DECL\n\n\1/' \
            < src/"$LOCAL_SUBDIR"/"$HEADER" \
            > include/btc/"$HEADERNAME" &&
        git add include/btc/"$HEADERNAME" &&
        git commit -m "Update include/btc/$HEADERNAME from src/$LOCAL_SUBDIR/$HEADER"
    done
}

# subtrees
update_subtree https://github.com/bitcoin-core/secp256k1 secp256k1 ''
update_subtree https://github.com/trezor/trezor-firmware trezor-crypto crypto hmac.h sha2.h segwit_addr.h
