SUBDIRS = swtpm-utils dracut

plymouthdir=/usr/share/dracut/modules.d/50plymouth-tpm
dist_plymouth_SCRIPTS=plymouth-tpm/install \
		      plymouth-tpm/check \
		      plymouth-tpm/plymouth-newroot.sh \
		      plymouth-tpm/cryptroot-ask.sh \
		      plymouth-tpm/installkernel \
		      plymouth-tpm/plymouth-populate-initrd \
		      plymouth-tpm/cryptroot-ask-tpm.sh \
		      plymouth-tpm/plymouth-emergency.sh \
		      plymouth-tpm/plymouth-pretrigger.sh

sbin_SCRIPTS=tpm-luks/chain_hashes \
	     tpm-luks/tpm_luks \
	     tpm-luks/gen_pcr_values \
	     tpm-luks/tpm-luks-update \
	     tpm-luks/tpm-luks-init
