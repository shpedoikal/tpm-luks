#!/bin/sh
#
# package reqs: tpm-tools, trousers
#
# Author: Kent Yoder <yoder1@us.ibm.com>
#
CRYPTSETUP=/sbin/cryptsetup
MOUNT=/bin/mount
TPM_NVREAD=/usr/bin/nv_readvalue
NV_INDEX_LIMIT=8
PCRS=8
DEVICE=${1}
NAME=${2}

#set -x

# plymouth feeds in this password for us
if [ ! -n "${NVPASS}" ]; then
	read -p "Enter your TPM NVRAM password: " NVPASS
	echo
fi

NVINDEX=1

TMPFS_MNT=/tmp/cryptroot-mnt
if [ ! -d ${TMPFS_MNT} ]; then
	mkdir ${TMPFS_MNT} || exit -1
fi

$MOUNT -t tmpfs -o size=16K tmpfs ${TMPFS_MNT}
if [ $? -ne 0 ]; then
	/bin/plymouth --text "Unable to mount tmpfs area to securely save TPM NVRAM data."
	/bin/plymouth ask-for-password \
		--prompt "Password for ${DEVICE} (${NAME}):" \
	        --command="$CRYPTSETUP luksOpen -T1 ${DEVICE} ${NAME}"
fi

while [ ${NVINDEX} -lt ${NV_INDEX_LIMIT} ]; do
	$TPM_NVREAD -ix ${NVINDEX} -sz 33 -pwdd ${NVPASS} \
		-of ${TMPFS_MNT}/data.tmp >/dev/null 2>&1
	RC=$?
	if [ ${RC} -eq 1 ]; then
		/bin/plymouth --text="TPM NV index ${NVINDEX}: Bad password."
		NVINDEX=$(( $NVINDEX + 1 ))
		continue
	elif [ ${RC} -eq 24 ]; then
		/bin/plymouth --text="TPM NV index ${NVINDEX}: PCR mismatch."
		NVINDEX=$(( $NVINDEX + 1 ))
		continue
	elif [ ${RC} -eq 2 ]; then
		/bin/plymouth --text="TPM NV index ${NVINDEX}: Invalid NVRAM Index."
		NVINDEX=$(( $NVINDEX + 1 ))
		continue
	fi

	# version check
	/usr/bin/od -A n -N 1 -t x1 ${TMPFS_MNT}/data.tmp|grep -q 00
	RC=$?
	if [ ${RC} -ne 0 ]; then
		/bin/plymouth --text="TPM NV index ${NVINDEX}: wrong version"
		NVINDEX=$(( $NVINDEX + 1 ))
		continue
	fi

	break
done

# NVRAM cannot be accessed. Fall back to LUKS passphrase
if [ ${NVINDEX} -eq ${NV_INDEX_LIMIT} ]; then
	/bin/plymouth --text "Unable to unlock an NVRAM area."
	/bin/plymouth ask-for-password \
		--prompt "Password for ${DEVICE} (${NAME}):" \
	        --command="$CRYPTSETUP luksOpen -T1 ${DEVICE} ${NAME}"
	exit $?
fi

# copy out all but the version byte, zeroize, delete
dd if=${TMPFS_MNT}/data.tmp of=${TMPFS_MNT}/data bs=1c skip=1 count=32 >/dev/null 2>&1
dd if=/dev/zero of=${TMPFS_MNT}/data.tmp bs=33 count=1 >/dev/null 2>&1
rm -f ${TMPFS_MNT}/data.tmp

$CRYPTSETUP luksOpen ${DEVICE} ${NAME} --key-file ${TMPFS_MNT}/data --keyfile-size 32
dd if=/dev/zero of=${TMPFS_MNT}/data bs=33 count=1 >/dev/null 2>&1
umount ${TMPFS_MNT}

exit 0


