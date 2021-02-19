#!/bin/sh
#
# Create/import a set of sample GPG keys to test the application.
#
# Creating keys can take time. You may see several of these:
# > Not enough random bytes available.  Please do some other work to give
# > the OS a chance to collect more entropy! (Need 131 more bytes)
# Probably one for every 1024 bits in the keylen.
# 
# If you want to know what gpg(1) is doing, use strace(1):
# # strace -eread -p`pidof gpg`
# and/or look at the current entropy:
# # cat /proc/sys/kernel/random/entropy_avail
#

keylen=1024 # should be 2048+ for live
comment=TEST
set -e # abort on error

for name in 'Alex B' 'Harm G' 'Walter D' 'Joe J' 'Ingmar I'; do
	lowsurname=`echo $name | awk '{print tolower($1)}'`
	email=$lowsurname@example.com
	password=${lowsurname}2

	filename=`echo $email | sed -e 's/@/_at_/g;s/\./_/g'`

	# Make sure appropriate keys exist
	if test '!' -f "$filename.key" -o '!' -f "$filename.pub"; then
		echo "Generating key for $name"
		gpg --gen-key --batch << __EOF__
Key-Type: RSA
Key-Length: $keylen
Subkey-Type: RSA
Subkey-Length: $keylen
Name-Real: $name
Name-Comment: $comment
Name-Email: $email
Passphrase: $password
__EOF__
		echo "Exporting key for future use"
		gpg --export-secret-key --armor "$email" > "$filename.key"
		gpg --export --armor "$email" > "$filename.pub"
	fi

	# Import the keys if not done already
	echo "Importing key for $name"
	gpg --import < "$filename.key" || true
	# (no need to import .pub, it's in the key file)
done
