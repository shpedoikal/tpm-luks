#
# package reqs: tpm-tools, trousers
#
# Author: Kent Yoder <yoder1@us.ibm.com>
#
CRYPTSETUP=/sbin/cryptsetup
MOUNT=/bin/mount
TPM_NVREAD=tpm_nvread
NV_INDEX_LIMIT=64
PCRS=8
DEVICE=${1}
NAME=${2}

if [ ! -n "${NVPASS}" ]; then
	read -p "Enter your TPM NVRAM password: " NVPASS
	echo
fi

NVINDEX=1

TMPFS_MNT=$(mktemp -d /tmp/${0##*/}-XXXXXX)
$MOUNT -t tmpfs -o size=16K tmpfs ${TMPFS_MNT}
if [ $? -ne 0 ]; then
	echo "Unable to mount tmpfs area"
	exit -1
fi

while [ ${NVINDEX} -lt ${NV_INDEX_LIMIT} ]; do
	$TPM_NVREAD -i ${NVINDEX} -s 33 --password=${NVPASS} \
	-f ${TMPFS_MNT}/data.tmp >/dev/null 2>&1
	RC=$?
	if [ ${RC} -ne 0 ]; then
		NVINDEX=$(( $NVINDEX + 1 ))
		echo "rc for tpm_nvread is ${RC}. Trying NV index ${NVINDEX}"
		continue
	fi

	# version check
	od -A n -N 1 -t x1 ${TMPFS_MNT}/data.tmp|grep -q 00
	RC=$?
	if [ ${RC} -ne 0 ]; then
		echo "ignoring NV index ${NVINDEX} (wrong version)"
		NVINDEX=$(( $NVINDEX + 1 ))
		continue
	fi

	break
done

if [ ${NVINDEX} -eq ${NV_INDEX_LIMIT} ]; then
	echo "Coulfn't find a TPM NVRAM index containing a usable key, falling back"
	echo "to password-based LUKS device opening."
	$CRYPTSETUP luksOpen -T1 ${DEVICE} ${NAME}
fi

# debug
#echo "DBG: data.tmp:"
#od -t x1 ${TMPFS_MNT}/data.tmp

# copy out all but the version byte
dd if=${TMPFS_MNT}/data.tmp of=${TMPFS_MNT}/data bs=1c skip=1 count=32 >/dev/null 2>&1
rm -f ${TMPFS_MNT}/data.tmp

# debug
#echo "DBG: data:"
#od -t x1 ${TMPFS_MNT}/data

$CRYPTSETUP luksOpen ${DEVICE} ${NAME} --key-file ${TMPFS_MNT}/data --keyfile-size 32 --readonly
dd if=/dev/zero of=${TMPFS_MNT}/data bs=33 count=1 >/dev/null 2>&1
umount ${TMPFS_MNT}

exit 0


