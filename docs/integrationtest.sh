#!/bin/bash
# vim: set ts=8 sw=4 sts=4 et ai tw=71:
FAILFAST=   # set to non-empty to exit immediately
SKIPLARGE=1 # set to non-empty to skip largefile tests

# If you want to run the server yourself, specify the store-url on the
# command line.
if test -n "$1"; then
    URL="$1"
else
    URL=
fi

# Fetch paths
self="$0"
[ "${self:0:1}" != '/' ] && self="`pwd`/$self"
rootdir="`dirname "$self"`/.."

# Mangle the root dir by replacing /home/USER with ~ if applicable.
# This tests that the ssh key file argument understands the tilde.
if echo "$HOME" | grep -q '^[^#]\+$'; then
    joefile="`echo $rootdir |
             sed -e "s#^$HOME#~#"`/docs/examples/joe_at_example_com"
else
    joefile="$rootdir/docs/examples/joe_at_example_com"
fi

# Check for unused ports (not really multiuser safe, but will work in
# most cases.
get_unused_port() {
    used_ports=`netstat -nlt | sed -e '{
        s/^\([^[:blank:]]*[[:blank:]]*\)\{3\}[0-9.:]*:\([0-9]*\).*/\2/
        /^[0-9]/!d
    }'`
    port=8000
    while test $port -lt 65535; do
        if ! echo "$used_ports" | grep "$port" -q; then
            echo $port
            break
        fi
        port=$((port+1))
    done
}

# Create a binary blob / large file that we can use to test.
get_large_binary() {
    file=`mktemp`
    echo "(temp+ $file)" >&2
    dd if=/dev/urandom of="$file" bs=4k count=1000 2>/dev/null
    file2=`mktemp`
    # Make it about 40MB, but not an exact number (by adding this file
    # in the mix).
    echo "(temp+ $file2)" >&2
    cat "$file" "$file" "$file" "$file" "$file" "$0" \
        "$file" "$file" "$file" "$file" "$file" > "$file2"
    echo "(temp- $file)" >&2
    rm "$file"
    echo "$file2"
}

# Prepare environment
export PYTHONPATH="$rootdir"  # ./bin/pstore needs access to pstorelib
export PSTORE_NOINPUT=y  # no password asking
unset HOME  # to ensure that .pstorerc isn't read

if test -z "$URL"; then
    PORT=`get_unused_port`
    [ -z "$PORT" ] && echo 'No port?' >&2 && exit 1
    URL="http://127.0.0.1:$PORT/"
    kill_children() { res=$?; pkill -u`whoami` -xf \
                      '.*/python.*pstore.*:'$PORT; exit $res; }
else
    PORT=
    kill_children() { res=$?; exit $res; }
fi

# Ensure that daemon children get killed when we end, and make sure we end.
trap kill_children INT TERM EXIT

# joe is the only one using sshrsa so he gets the ssh-rsa private key
# setting.
pstore="$rootdir/bin/pstore --store-url=$URL \
        --private-key=$joefile"

# Test "framework"
begintest() {
    printf '\x1b[1m* %s:\x1b[0m ' "$1"
}
endtest() {
    printf '\x1b[32;1mOK\x1b[0m\n'
}
failtest() {
    printf '\n\x1b[31;1m  FAIL: %s\n\x1b[33;1m' "$*"
    # (cat -v and head to trim output if we're dumping a file)
    echo Whatever | $call 2>&1 | sed -e 's/^/  > /' | cat -v |
        head -n30
    printf '\x1b[0m\n'
    fails=$((fails+1))
    [ -n "$FAILFAST" ] && exit 1
}

#
# NOTE: alex and walter should be able to see all.. the others
# shouldn't,
# NOTE: harm is not staff and not admin, but still has view_all_objects
# powers
# NOTE: ingmar shouldn't be able to do anything, he is inactive
#

if test -n "$PORT"; then
    # Start backend
    ( $rootdir/manage runserver 127.0.0.1:$PORT >/dev/null 2>&1 ) &
    # Wait while starting server
    echo "Starting daemon on port $PORT:"
    n=0; until nc 127.0.0.1 $PORT -zw1; do
        printf .; n=$((n+1)); sleep 1
        if test $n -gt 5; then echo 'too slow, no virtualenv?'; exit 1; fi
    done; echo running
fi

# Run the tests
fails=0


#######################################################################
## BASIC USAGE TESTS
#######################################################################


begintest 'Basic run test with failover' ------------------------------
#
call="$rootdir/bin/pstore --store-url=http://does-not-exist \
      --store-url=$URL -ualex"
if ! $call >/dev/null; then
    failtest 'expected success on 2nd host'
else
    endtest
fi


begintest 'Testing failed store url' ----------------------------------
#
# (not using $pstore because of the store-url)
call="$rootdir/bin/pstore --store-url=http://does-not-exist \
      --store-url=http://does-not-either"
if test "`$call 2>&1 | sed -e 's/^.* \([^ ]*\)$/\1/'`" != \
        'http://does-not-exist'; then
    failtest 'expected first url in error message'
else
    endtest
fi


begintest 'Running consistency check' ---------------------------------
#
call="$pstore --consistency-check"
if ! $call >/dev/null; then
    failtest 'expected silence'
else
    endtest
fi


begintest 'Fail doing anything with non-existent user' ----------------
#
call="$pstore -udoesnotexist"
if $call 2>/dev/null; then
    failtest 'expected failure (doesnotexist should not exist)'
else
    endtest
fi


begintest 'Fail doing anything with bad key user' ---------------------
#
call="$pstore -uharm"
if $call 2>/dev/null; then
    failtest 'expected failure (harm does not have a valid key)'
else
    endtest
fi


begintest 'Fail doing anything with inactive user' --------------------
#
call="$pstore -uingmar"
if $call 2>/dev/null; then
    failtest 'expected failure (ingmar is set to inactive)'
else
    endtest
fi


#######################################################################
## READ ONLY TESTS
#######################################################################


begintest 'Get owned object property' ---------------------------------
#
call="$pstore -uwalter walter.example.com -pg description"
if test "`$call`" != "Description"; then
    failtest 'expected Description'
else
    endtest
fi


begintest 'Get not-owned object property as SU' -----------------------
#
call="$pstore -ualex walter.example.com -pg description"
if test "`$call`" != "Description"; then
    failtest 'expected Description'
else
    endtest
fi


begintest 'Fail getting not-owned object property as non-SU' ----------
#
call="$pstore -ujoe walter.example.com -pg description"
if $call 2>/dev/null; then
    failtest 'expected failure'
else
    endtest
fi


begintest 'Listing owned objects' -------------------------------------
#
call="$pstore -uwalter"
if test "`$call | sed -e 1,2d | wc -l`" != 1; then
    failtest 'expected one machine'
else
    endtest
fi


begintest 'Listing all objects as SU' ---------------------------------
#
call="$pstore -ualex -a"
if test "`$call | sed -e 1,2d | wc -l`" != 3; then
    failtest 'expected three machines'
else
    endtest
fi


begintest 'Fail listing all objects as non-SU' ------------------------
#
call="$pstore -ujoe -a"
if $call 2>/dev/null; then
    failtest 'expected failure'
else
    endtest
fi


begintest 'Listing machines subset' -----------------------------------
#
call="$pstore -a erver.exa -ualex"
if test "`$call | sed -e1,2d | wc -l`" != 1; then
    failtest 'expected one machine (server.example.com)'
else
    endtest
fi


begintest 'Reading password' ------------------------------------------
#
call="$pstore server.example.com -ujoe"
if test "`$call | sed -ne 's/^password = \(.*\)/\1/p'`" != 'sErVeR!'; then
    failtest 'expected password sErVeR!'
else
    endtest
fi


begintest 'Listing owned properties' ----------------------------------
#
call="$pstore server.example.com -ujoe -pl"
if test "`$call | grep '^[^ ]\+$' | wc -l`" != 2; then
    failtest 'expected two properties'
else
    endtest
fi


begintest 'Listing not-owned properties as SU' ------------------------
#
# (observe the -a to list all properties)
call="$pstore walter.example.com -ualex -pl -a"
if test "`$call | grep '^[^ ]\+$' | wc -l`" != 2; then
    failtest 'expected two properties'
else
    endtest
fi


begintest 'Fail listing not-owned properties as non-SU' ---------------
#
call="$pstore walter.example.com -ujoe -pl"
if $call 2>/dev/null; then
    failtest 'expected failure'
else
    endtest
fi


#######################################################################
## MUTATING OBJECTS TESTS
#######################################################################


begintest 'Adding public property' ------------------------------------
#
call="$pstore server.example.com -ualex -ps location"
if ! printf 'Behind the scenes' | $call; then
    failtest 'could not add public property'
else
    endtest
fi


begintest 'Adding private property' -----------------------------------
#
call="$pstore server.example.com -ualex -ps secret-location"
if ! printf 'Secret scenes' | $call; then
    failtest 'could not add public property'
else
    endtest
fi


begintest 'Listing the new properties' --------------------------------
#
call="$pstore server.example.com -ujoe -pl"
if test "`$call | grep '^[^ ]\+$' | wc -l`" != 4; then
    failtest 'expected four properties'
else
    endtest
fi


begintest 'Getting the new public property' ---------------------------
#
call="$pstore server.example.com -ujoe -pg location"
if test "`$call`" != 'Behind the scenes'; then
    failtest 'expected "Behind the scenes"'
else
    endtest
fi

    
begintest 'Getting the new shared property' ---------------------------
#
call="$pstore server.example.com -ujoe -pg secret-location"
if test "`$call`" != 'Secret scenes'; then
    failtest 'expected "Secret scenes"'
else
    endtest
fi

    
begintest 'Fail adding new machine with same name' --------------------
#
call="$pstore server.example.com -ualex -c"
if $call 2>/dev/null; then
    failtest 'overwrote existing server?'
else
    endtest
fi


begintest 'Fail adding public property as disallowed user' ------------
#
call="$pstore server.example.com -uwalter -ps location2"
if printf 'Behind the scenes' | $call 2>/dev/null; then
    failtest 'got to write to disallowed item?'
else
    endtest
fi


begintest 'Fail adding shared property as disallowed user' -----------
#
call="$pstore walter.example.com -ualex -pe secret-location"
if printf 'Secret scenes' | $call 2>/dev/null; then
    failtest 'got to write disallowed item?'
else
    endtest
fi


#######################################################################
## NEW MACHINES TESTS
#######################################################################


begintest 'Creating new machine (test.example.com)' -------------------
#
# password will be "example-password" because of PSTORE_NOINPUT
call="$pstore test.example.com -ualex -c +joe"
if ! $call; then
    failtest 'failed to create new machine'
else
    endtest
fi


begintest 'Looking for/at new machine by alex' ------------------------
call="$pstore test.example.co -ualex"
if test "`$call | sed -e1,2d | wc -l`" != 1; then
    failtest 'new machine not listed for alex?'
else
    endtest
fi


begintest 'Looking for/at new machine by joe' -------------------------
call="$pstore test.example.co -ujoe"
if test "`$call | sed -e1,2d | wc -l`" != 1; then
    failtest 'new machine not listed for joe?'
else
    endtest
fi


begintest 'Looking for/at new machine password by alex' ---------------
call="$pstore test.example.com -ualex"
if test "`$call`" != "password = example-password"; then
    failtest 'cannot view correct password?'
else
    endtest
fi


begintest 'Looking for/at new machine password by joe' ----------------
call="$pstore test.example.com -ujoe"
if test "`$call`" != "password = example-password"; then
    failtest 'cannot view correct password?'
else
    endtest
fi


begintest 'Fail looking for/at new machine password by walter' --------
call="$pstore test.example.com -uwalter"
if $call 2>/dev/null; then
    failtest 'got to view password?'
else
    endtest
fi


#######################################################################
## PERMISSION ALTERATION TESTS
#######################################################################


begintest 'Adding/revoking access from/to user' -----------------------
#
call="$pstore test.example.com -ujoe ^alex +walter"
if ! $call; then
    failtest 'did not succeed'
else
    endtest
fi


begintest 'Fail adding unknown user' ----------------------------------
#
call="$pstore test.example.com -ujoe +walter2"
if $call 2>/dev/null; then
    failtest 'succeeded, should not'
else
    endtest
fi


begintest 'Fail removing unknown user' --------------------------------
#
call="$pstore test.example.com -ujoe ^walter2"
if $call 2>/dev/null; then
    failtest 'succeeded, should not'
else
    endtest
fi


begintest 'Fail checking password as disallowed user' -----------------
#
call="$pstore test.example.com -ualex"
if $call 2>/dev/null; then
    failtest 'succeeded, should not'
else
    endtest
fi


begintest 'Adding machine name with slash in it' ----------------------
#
call="$pstore -c abc/def=123 -ualex"
if ! printf 'With a slash' | $call; then
    failtest 'could not add public property'
else
    endtest
fi


begintest 'Adding property with slash in it' --------------------------
#
call="$pstore test.example.com -ujoe -ps abc/def=123"
if ! printf 'With a slash' | $call; then
    failtest 'could not add public property'
else
    endtest
fi


begintest 'Checking password as allowed user' -------------------------
#
call="$pstore test.example.com -ujoe -pg password"
if test "`$call`" != "example-password"; then
    failtest "expected example-password"
else
    endtest
fi


begintest 'Checking password as allowed user (2)' ---------------------
#
call="$pstore test.example.com -uwalter -pg password"
if test "`$call`" != "example-password"; then
    failtest "expected example-password"
else
    endtest
fi


#######################################################################
## LARGE FILE SUPPORT
#######################################################################


begintest 'Large file support (setup, dropping sshrsa)' ---------------
#
call="$pstore test.example.com -uwalter ^joe"
if ! $call; then
    failtest "could not revoke joe"
else
    endtest
fi


if test -z "$SKIPLARGE"; then


    largefile="`get_large_binary`"
    largedest="`mktemp`"
    echo "(temp+ $largedest)"


    begintest 'Large file support (adding large public file)' ---------
    #
    call="$pstore test.example.com -uwalter -ps blob.bin"
    if ! cat "$largefile" | $call; then
        failtest "could not write large unencrypted file"
    else
        endtest
    fi


    begintest 'Large file support (adding large shared file)' ---------
    #
    call="$pstore test.example.com -uwalter -pe blob2.bin"
    if ! cat "$largefile" | $call; then
        failtest "could not write large encrypted file"
    else
        endtest
    fi


    begintest 'Large file support (adding user alex)' -----------------
    #
    call="$pstore test.example.com -uwalter +alex"
    if ! $call; then
        failtest 'did not succeed'
    else
        endtest
    fi


    begintest 'Large file support (reading public file)' --------------
    #
    call="$pstore test.example.com -ualex -pg blob.bin"
    if ! $call > "$largedest"; then
        failtest "could not read large unencrypted file"
    elif ! cmp --quiet "$largefile" "$largedest"; then
        failtest "large file comparison failed!"
    else
        endtest
    fi


    begintest 'Large file support (reading shared file)' --------------
    #
    call="$pstore test.example.com -ualex -pg blob2.bin"
    if ! $call > "$largedest"; then
        failtest "could not read large encrypted file"
    elif ! cmp --quiet "$largefile" "$largedest"; then
        failtest "large file comparison failed!"
    else
        endtest
    fi


    echo "(temp- $largefile)"
    echo "(temp- $largedest)"
    rm "$largefile" "$largedest"


else # SKIPLARGE


    begintest 'Large file setup (adding user alex)' -------------------
    #
    call="$pstore test.example.com -uwalter +alex"
    if ! $call; then
        failtest 'did not succeed'
    else
        endtest
    fi

    echo "(skipped large file tests, see docs/integrationtest.sh)" >&2


fi


begintest 'Large file support (cleanup, 1)' -----------------------
#
call="$pstore test.example.com -ualex -ps blob.bin"
if ! printf ABC | $call; then
    failtest "could not clean up unencrypted file"
else
    endtest
fi


begintest 'Large file support (cleanup, 2)' -----------------------
#
call="$pstore test.example.com -ualex -pe blob2.bin"
if ! printf ABC | $call; then
    failtest "could not clean up encrypted file"
else
    endtest
fi


#######################################################################
## REGRESSION TESTS
#######################################################################


begintest 'Quick password lookup-fallback' ----------------------------
#
# (fetching a password is done through the get_object method, which
# gets lots of properties at once. if it is too large (e.g. 8k) we need
# a second query, make sure that gets called. note: do not use
# /dev/zero as it will be compacted by the encryption.)
dd if=/dev/urandom bs=1k count=8 2>/dev/null |
    $pstore test.example.com -uwalter -pe password || exit 2
call="$pstore test.example.com -uwalter"
if test "`$call | wc --bytes`" -lt 8192; then
    failtest "fetching large password failed"
else
    endtest
fi


#######################################################################
## TAIL
#######################################################################


begintest 'Running consistency check (2)' -----------------------------
#
call="$pstore --consistency-check"
if ! $call >/dev/null 2>&1; then
    failtest 'expected silence'
else
    endtest
fi


begintest '0 failures in total' --------------------------------------
#
call=true
if test $fails -gt 0; then
    failtest "got $fails error(s)"
else
    endtest
fi

if test $fails -gt 0; then
    exit 1
fi
