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

yumpluginconfdir=/etc/yum/pluginconf.d
dist_yumpluginconf_SCRIPTS=yum/post-transaction-actions.conf

yumpluginsdir=/usr/lib/yum-plugins
dist_yumplugins_SCRIPTS=yum/post-transaction-actions.py

yumpostactionsdir=/etc/yum/post-actions
dist_yumpostactions_SCRIPTS=yum/tpm-luks.action

CLEANFILES = yum/tpm-luks.action

yum/tpm-luks.action: yum/tpm-luks.action.in
	@SED@ -e s!\@sbindir\@!"@sbindir@"!g < $< > $@-t
	mv $@-t $@
