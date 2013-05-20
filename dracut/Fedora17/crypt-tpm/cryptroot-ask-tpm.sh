#!/bin/sh
#
# package reqs: od, getcapability, nv_readvalue, dd
#
# Author: Kent Yoder <shpedoikal@gmail.com>
#
CRYPTSETUP=/sbin/cryptsetup
MOUNT=/bin/mount
UMOUNT=/bin/umount
TPM_NVREAD=/usr/bin/nv_readvalue
GETCAP=/usr/bin/getcapability
AWK=/bin/awk
DEVICE=${1}
NAME=${2}
TPM_LUKS_MAX_NV_INDEX=128

set -x

VIABLE_INDEXES=""

#
# An index is viable if its composite hash matches current PCR state, or if
# it doesn't require PCR state at all
#
ALL_INDEXES=$($GETCAP -cap 0xd | ${AWK} -F: '$1 ~ /Index/ {print $2 }' | ${AWK} -F= '{ print $1 }')
for i in $ALL_INDEXES; do
	MATCH1=$($GETCAP -cap 0x11 -scap $i | ${AWK} -F ": " '$1 ~ /Matches/ { print $2 }')
	SIZE=$($GETCAP -cap 0x11 -scap $i | ${AWK} -F= '$1 ~ /dataSize/ { print $2 }')
	if [ -n "${MATCH1}" -a "${MATCH1}" = "Yes" ]; then
		# Add this index at the beginning, since its especially likely to be
		# the index we're looking for
		VIABLE_INDEXES="$i $VIABLE_INDEXES"
		echo "PCR composite matches for index: $i"
		continue
	elif [ $i -gt ${TPM_LUKS_MAX_NV_INDEX} ]; then
		continue
	fi

	# Add this index at the end of the list
	VIABLE_INDEXES="$VIABLE_INDEXES $i"
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

KEYFILE=${TMPFS_MNT}/key

for NVINDEX in $VIABLE_INDEXES; do
	NVSIZE=$($GETCAP -cap 0x11 -scap ${NVINDEX} | ${AWK} -F= '$1 ~ /dataSize/ { print $2 }')

	$TPM_NVREAD -ix ${NVINDEX} -pwdd ${NVPASS} \
		-sz ${NVSIZE} -of ${KEYFILE} >/dev/null 2>&1
	RC=$?
	if [ ${RC} -eq 1 ]; then
		echo "TPM NV index ${NVINDEX}: Bad password."
		continue
	elif [ ${RC} -eq 24 ]; then
		echo "TPM NV index ${NVINDEX}: PCR mismatch."
		continue
	elif [ ${RC} -eq 2 ]; then
		echo "TPM NV index ${NVINDEX}: Invalid NVRAM Index."
		continue
	elif [ ${RC} -ne 0 ]; then
		echo "TPM NV index ${NVINDEX}: Unknown error (${RC})"
		continue
	fi

	echo "Trying data read from NV index $NVINDEX"
	$CRYPTSETUP luksOpen ${DEVICE} ${NAME} --key-file ${KEYFILE} --keyfile-size ${NVSIZE}
	RC=$?
	# Zeroize keyfile regardless of success/fail
	dd if=/dev/zero of=${KEYFILE} bs=1c count=${NVSIZE} >/dev/null 2>&1
	if [ ${RC} -ne 0 ]; then
		echo "Cryptsetup failed, trying next index..."
		continue
	fi
	echo "Success."
	${UMOUNT} ${TMPFS_MNT}

	exit 0
done

# NVRAM cannot be accessed. Fall back to LUKS passphrase
echo "Unable to unlock an NVRAM area."
${UMOUNT} ${TMPFS_MNT}
exit 255
