#!/bin/sh
#
# package reqs: od, getcapability, nv_readvalue, dd
#
# Author: Kent Yoder <key@linux.vnet.ibm.com>
#
CRYPTSETUP=/sbin/cryptsetup
MOUNT=/bin/mount
UMOUNT=/bin/umount
TPM_NVREAD=/usr/bin/nv_readvalue
GETCAP=/usr/bin/getcapability
AWK=/bin/awk
DEVICE=${1}
NAME=${2}

#set -x

VIABLE_INDEXES=""

#
# An index is viable if its composite hash matches current PCR state, or if
# it doesn't require PCR state at all
#
ALL_INDEXES=$($GETCAP -cap 0xd | ${AWK} -F "= " '$1 ~ /Index/ {print $2 }' | ${AWK} -F "." '{ print $1 }')
for i in $ALL_INDEXES; do
	MATCH1=$($GETCAP -cap 0x11 -scap $i | ${AWK} -F ": " '$1 ~ /Matches/ { print $2 }')
	MATCH2=$($GETCAP -cap 0x11 -scap $i | ${AWK} -F= '$1 ~ /dataSize/ { print $2 }')
	if test -n "${MATCH1}" && test "${MATCH1}" = "Yes"; then
		# Add this index at the beginning, since its especially likely to be
		# the index we're looking for
		VIABLE_INDEXES="$i $VIABLE_INDEXES"
		echo "PCR composite matches for index: $i"
		continue
	elif test -n "${MATCH2}" && test ${MATCH2} -eq 33; then
		# Add this index at the end of the list
		VIABLE_INDEXES="$VIABLE_INDEXES $i"
	else
		echo "Ignoring TPM NVRAM index: $i"
		continue
	fi
	echo "Viable index: $i"
done

TMPFS_MNT=/tmp/cryptroot-mnt
if [ ! -d ${TMPFS_MNT} ]; then
	mkdir ${TMPFS_MNT} || exit -1
fi

$MOUNT -t tmpfs -o size=16K tmpfs ${TMPFS_MNT}
if [ $? -ne 0 ]; then
	echo "Unable to mount tmpfs area to securely use TPM NVRAM data."
	exit 255
fi

# plymouth feeds in this password for us
if [ ! -n "${NVPASS}" ]; then
       read NVPASS
fi

TMPFILE=${TMPFS_MNT}/data.tmp
KEYFILE=${TMPFS_MNT}/key
SUCCESS=0

for NVINDEX in ${VIABLE_INDEXES}; do
	$TPM_NVREAD -ix ${NVINDEX} -sz 33 -pwdd ${NVPASS} \
		-of ${TMPFILE} >/dev/null 2>&1
	RC=$?
	if [ ${RC} -eq 1 ]; then
		#/bin/plymouth --text="TPM NV index ${NVINDEX}: Bad password."
		echo "TPM NV index ${NVINDEX}: Bad password."
		continue
	elif [ ${RC} -eq 24 ]; then
		#/bin/plymouth --text="TPM NV index ${NVINDEX}: PCR mismatch."
		echo "TPM NV index ${NVINDEX}: PCR mismatch."
		continue
	elif [ ${RC} -eq 2 ]; then
		#/bin/plymouth --text="TPM NV index ${NVINDEX}: Invalid NVRAM Index."
		echo "TPM NV index ${NVINDEX}: Invalid NVRAM Index."
		continue
	elif [ ${RC} -ne 0 ]; then
		echo "TPM NV index ${NVINDEX}: Unknown error (${RC})"
		continue
	fi

	# version check
	/usr/bin/od -A n -N 1 -t x1 ${TMPFILE} | grep -q 00
	RC=$?
	if [ ${RC} -ne 0 ]; then
		# Zeroize keyfile
		dd if=/dev/zero of=${TMPFILE} bs=1c count=32 >/dev/null 2>&1
		echo "TPM NV index ${NVINDEX}: wrong version (${RC})"
		continue
	fi

	echo "Using data read from NV index $NVINDEX"
	# copy out all but the version byte, zeroize tmp file, delete it
	dd if=${TMPFILE} of=${KEYFILE} bs=1c skip=1 count=32 >/dev/null 2>&1
	dd if=/dev/zero of=${TMPFILE} bs=1c count=33 >/dev/null 2>&1
	rm -f ${TMPFILE}

	$CRYPTSETUP luksOpen ${DEVICE} ${NAME} --key-file ${KEYFILE} --keyfile-size 32
	RC=$?
	# Zeroize keyfile regardless of success/fail
	dd if=/dev/zero of=${KEYFILE} bs=1c count=32 >/dev/null 2>&1
	if [ ${RC} -ne 0 ]; then
		continue
	fi
	${UMOUNT} ${TMPFS_MNT}

	SUCCESS=1
	break
done

# NVRAM cannot be accessed. Fall back to LUKS passphrase
if [ ${SUCCESS} -eq 0 ]; then
	echo "Unable to unlock an NVRAM area."
	${UMOUNT} ${TMPFS_MNT}
	exit 255
fi

exit 0
