#!/bin/bash

if [ ! -f yubiauth/__init__.py ]; then
	echo "$0: Must be executed from top yubiauth dir."
	exit 1
fi

do_test="true"

if [ "x$1" == "x--no-test" ]; then
	do_test="false"
	shift
fi

keyid="$1"

if [ "x$keyid" = "x" ]; then
	echo "Syntax: $0 [--no-test] <KEYID>"
	exit 1
fi

set -e

version=$(grep "version=" setup.py | sed "s/^.\{1,\}version='\(.\{1,\}\)'.\{1,\}$/\1/")

tagname="yubiauth-$version"

if ! head -1 NEWS | grep -q "Version $version (released $(date -I))"; then
	echo "You need to update date/version in NEWS"
	exit 1
fi

if git tag | grep -q "^$tagname\$"; then
	echo "Tag $tagname already exists!"
	echo "Did you remember to update the version in setup.py?"
	exit 1
fi

git2cl > ChangeLog

if [ "x$do_test" != "xfalse" ]; then
	python setup.py check nosetests
fi

python setup.py sdist upload --sign --identity $keyid

gpg --output dist/$tagname.tar.gz.sig --dearmor dist/$tagname.tar.gz.asc
gpg --verify dist/$tagname.tar.gz.sig

git tag -u $keyid -m $tagname $tagname

#Publish release
if test ! -d "$YUBICO_GITHUB_REPO"; then
	echo "warn: YUBICO_GITHUB_REPO not set or invalid!"
	echo "      This release will not be published!"
else
	$YUBICO_GITHUB_REPO/publish yubiauth $version dist/$tagname.tar.gz*
fi

echo "Done! Don't forget to git push && git push --tags"
