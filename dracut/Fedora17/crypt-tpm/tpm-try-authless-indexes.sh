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
TPM_LUKS_MAX_NV_INDEX=128
TPM_NV_PER_AUTHREAD=0x00040000
TPM_NV_PER_OWNERREAD=0x00020000
NOAUTH_INDEXES=""

#set -x

#
# An index is viable if its composite hash matches current PCR state, or if
# it doesn't require PCR state at all
#
#ALL_INDEXES=$($GETCAP -cap 0xd | ${AWK} -F "= " '$1 ~ /Index/ {print $2 }' | ${AWK} -F "." '{ print $1 }')
ALL_INDEXES=$($GETCAP -cap 0xd | ${AWK} -F: '$1 ~ /Index/ {print $2 }' | ${AWK} -F= '{ print $1 }')
for i in $ALL_INDEXES; do
	MATCH1=$($GETCAP -cap 0x11 -scap $i | ${AWK} -F ": " '$1 ~ /Matches/ { print $2 }')
	SIZE=$($GETCAP -cap 0x11 -scap $i | ${AWK} -F= '$1 ~ /dataSize/ { print $2 }')
	AUTH_BITS=0x$($GETCAP -cap 0x11 -scap $i | ${AWK} '$1 ~ /Result/ { print $11 }')
	if [ $i -gt ${TPM_LUKS_MAX_NV_INDEX} ]; then
		continue
	else
		AUTHREAD=$(( ${AUTH_BITS} & ${TPM_NV_PER_AUTHREAD} ))
		OWNERREAD=$(( ${AUTH_BITS} & ${TPM_NV_PER_OWNERREAD} ))

		if [ ${AUTHREAD} -eq 0 -a ${OWNERREAD} -eq 0 ];then
			NOAUTH_INDEXES="$i $NOAUTH_INDEXES"
			echo "No auth index: $i"
			continue
		fi
	fi
done

if [ -z "${NOAUTH_INDEXES}" ]; then
	echo "No TPM authless indexes found"
	exit 255
fi

TMPFS_MNT=/tmp/cryptroot-mnt
if [ ! -d ${TMPFS_MNT} ]; then
	mkdir ${TMPFS_MNT} || exit -1
fi

$MOUNT -t tmpfs -o size=16K tmpfs ${TMPFS_MNT}
if [ $? -ne 0 ]; then
	echo "Unable to mount tmpfs area to securely use TPM NVRAM data."
	exit 255
fi

KEYFILE=${TMPFS_MNT}/key

for NVINDEX in $NOAUTH_INDEXES; do
	NVSIZE=$($GETCAP -cap 0x11 -scap ${NVINDEX} | ${AWK} -F= '$1 ~ /dataSize/ { print $2 }')

	$TPM_NVREAD -ix ${NVINDEX} -sz ${NVSIZE} -of ${KEYFILE} >/dev/null 2>&1
	RC=$?
	if [ ${RC} -ne 0 ]; then
		echo "No auth TPM NV index ${NVINDEX}: error (${RC})"
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

