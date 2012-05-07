#!/bin/sh
#
# package reqs: od, getcapability, nv_readvalue
#
# Author: Kent Yoder <yoder1@us.ibm.com>
#
CRYPTSETUP=/sbin/cryptsetup
MOUNT=/bin/mount
UMOUNT=/bin/umount
TPM_NVREAD=/usr/bin/nv_readvalue
GETCAP=/usr/bin/getcapability
AWK=/usr/bin/awk
DEVICE=${1}
NAME=${2}

#set -x

VIABLE_INDEXES=""

#
# An index is viable if its composite hash matches current PCR state, or if
# it doesn't require PCR state at all
#
ALL_INDEXES=$($GETCAP -cap 0xd | $AWK -F "= " '$1 ~ /Index/ {print $2 }' | $AWK -F "." '{ print $1 }')
for i in $ALL_INDEXES; do
	MATCH=$($GETCAP -cap 0x11 -scap $i | $AWK -F ": " '$1 ~ /Matches/ { print $2 }')
	if test -n "$MATCH" && test "$MATCH" = "No"; then
		continue
	fi

	VIABLE_INDEXES="$VIABLE_INDEXES $i"
done

# plymouth feeds in this password for us
if [ ! -n "${NVPASS}" ]; then
	read -p "Enter your TPM NVRAM password: " NVPASS
	echo
fi

TMPFS_MNT=/tmp/cryptroot-mnt
if [ ! -d ${TMPFS_MNT} ]; then
	mkdir ${TMPFS_MNT} || exit -1
fi

$MOUNT -t tmpfs -o size=16K tmpfs ${TMPFS_MNT}
if [ $? -ne 0 ]; then
	echo "Unable to mount tmpfs area to securely save TPM NVRAM data."
	#/bin/plymouth --text "Unable to mount tmpfs area to securely save TPM NVRAM data."
	#/bin/plymouth ask-for-password \
	#	--prompt "Password for ${DEVICE} (${NAME}):" \
	#        --command="$CRYPTSETUP luksOpen -T1 ${DEVICE} ${NAME}"
	exit -1
fi

TMPFILE=${TMPFS_MNT}/data.tmp
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
		#/bin/plymouth --text="TPM NV index ${NVINDEX}: wrong version"
		echo "TPM NV index ${NVINDEX}: wrong version (${RC})"
		continue
	fi

	SUCCESS=1
	break
done

# NVRAM cannot be accessed. Fall back to LUKS passphrase
if [ ${SUCCESS} -eq 0 ]; then
	echo "Unable to unlock an NVRAM area."
	#/bin/plymouth --text "Unable to unlock an NVRAM area."
	#/bin/plymouth ask-for-password \
	#	--prompt "Password for ${DEVICE} (${NAME}):" \
	#        --command="$CRYPTSETUP luksOpen -T1 ${DEVICE} ${NAME}"
	${UMOUNT} ${TMPFS_MNT}
	exit -1
fi

echo "Using data read from NV index $NVINDEX"
# copy out all but the version byte, zeroize, delete
dd if=${TMPFS_MNT}/data.tmp of=${TMPFS_MNT}/data bs=1c skip=1 count=32 >/dev/null 2>&1
dd if=/dev/zero of=${TMPFS_MNT}/data.tmp bs=33 count=1 >/dev/null 2>&1
rm -f ${TMPFS_MNT}/data.tmp

$CRYPTSETUP luksOpen ${DEVICE} ${NAME} --key-file ${TMPFS_MNT}/data --keyfile-size 32
dd if=/dev/zero of=${TMPFS_MNT}/data bs=33 count=1 >/dev/null 2>&1
${UMOUNT} ${TMPFS_MNT}

exit 0


