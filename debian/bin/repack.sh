#!/bin/bash
# Borrowed from Raphael Geissert's Debian PHP repack script.

set -e

if [ ! -f "$3" ] && [ ! -f "$1" ]; then
    echo "This script must be run via uscan or by manually specifying the tarball" >&2
    exit 1
fi

tarball=

[ -f "$3" ] && tarball="$3"
[ -z "$tarball" -a -f "$1" ] && tarball="$1"

tarball="$(readlink -f "$tarball")"

tdir="$(mktemp -d)"
trap '[ ! -d "$tdir" ] || rm -r "$tdir"' EXIT

tar -xzf $tarball -C $tdir
cp -a "$tarball" "$tarball.orig"
distdir="$(basename $(ls -d $tdir/*))"
srcdir="$tdir/$distdir"

#echo "Adjusting $srcdir/configure"
sed -i 's/perlmods\/Makefile\ //' $srcdir/configure
sed -i '/perlmods\/Makefile/d' $srcdir/configure
#echo "Adjusting $srcdir/Makefile*"
sed -i 's/perlmods\ //' $srcdir/Makefile*
#echo "Removing $srcdir/perlmods/
rm -rf $srcdir/perlmods/

#tarball=$(echo $tarball|sed 's/\.orig\.tar\.gz/+dfsg.orig.tar.gz/')
tar -cof "${tarball/.gz}" -C $tdir/ $distdir
gzip -f9 "${tarball/.gz}"
