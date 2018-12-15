#!/bin/sh
# Prepare sqleet.c sqleet.h amalgamation for a release.

set -e

die() {
    rm -f tmp-rekeyvacuum.c tmp-sqleet.c
    [ "$#" -ne 0 ] && echo "[-] Error:" "$@" >&2
    exit 1
}

cd "$(git rev-parse --show-toplevel)"
[ "$(git symbolic-ref --short -q HEAD)" = "master" ] || die "checkout master first"
git status --short | grep -vq '^[!?]' && die "dirty working tree (commit or stash your changes)"

VERSION="$(sed -nr 's/^#define SQLITE_VERSION[^"]*"([0-9]+\.[0-9]+\.[0-9]+)"$/\1/p' sqlite3.h)"
[ -z "$VERSION" ] && die "cannot find SQLite3 version"

echo "[+] SQLite version $VERSION" >&2

echo "[+] Generating rekeyvacuum.c" >&2
./script/rekeyvacuum.sh sqlite3.c >>tmp-rekeyvacuum.c || die

echo "[+] Generating sqleet.c amalgamation" >&2
while IFS='' read -r ln; do
    if echo "$ln" | grep -q '^#include "[^"]\+"$'; then
        cat "$(printf "%s\n" "$ln" | sed 's/^#include "\([^"]\+\)"/\1/')"
    else
        printf "%s\n" "$ln"
    fi
done <sqleet.c >tmp-sqleet.c || die "sqleet amalgamation failed"

echo '[+] Updating shell.c #include "sqlite3.h" -> "sqleet.h"' >&2
sed -i 's/^#include "sqlite3.h"$/#include "sqleet.h"/' shell.c
grep -Fq '#include "sqleet.h"' shell.c || die "failed to update shell.c include"

echo "[+] Moving files around a bit" >&2
mv tmp-sqleet.c sqleet.c
mv tmp-rekeyvacuum.c rekeyvacuum.c
git add sqleet.c shell.c
git mv sqlite3.h sqleet.h
git ls-files | grep ".c$" | grep -v "sqleet.c\|shell.c" | xargs git rm -fq
git rm -fqr script/

sync
SQLEET_VERSION="$(echo "$VERSION" | sed 's/^3/0/')"
echo "[+] Success!" >&2
echo "git checkout -b v$SQLEET_VERSION"
echo "git commit -m \"Release v$SQLEET_VERSION\""
echo "git push -u origin v$SQLEET_VERSION"
