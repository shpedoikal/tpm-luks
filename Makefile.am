SUBDIRS = swtpm-utils dracut .

if FEDORA17
plymouthdir=/usr/lib/dracut/modules.d/90crypt-tpm
dist_plymouth_SCRIPTS=dracut/Fedora17/crypt-tpm/cryptroot-ask.sh \
		      dracut/Fedora17/crypt-tpm/cryptroot-ask-tpm.sh \
		      dracut/Fedora17/crypt-tpm/crypt-cleanup.sh \
		      dracut/Fedora17/crypt-tpm/crypt-lib.sh \
		      dracut/Fedora17/crypt-tpm/module-setup.sh \
		      dracut/Fedora17/crypt-tpm/parse-crypt.sh \
		      dracut/Fedora17/crypt-tpm/parse-keydev.sh \
		      dracut/Fedora17/crypt-tpm/probe-keydev.sh
endif

if RHEL6
plymouthdir=/usr/share/dracut/modules.d/50plymouth-tpm
dist_plymouth_SCRIPTS=dracut/RHEL6/plymouth-tpm/install \
		      dracut/RHEL6/plymouth-tpm/check \
		      dracut/RHEL6/plymouth-tpm/plymouth-newroot.sh \
		      dracut/RHEL6/plymouth-tpm/cryptroot-ask.sh \
		      dracut/RHEL6/plymouth-tpm/installkernel \
		      dracut/RHEL6/plymouth-tpm/plymouth-populate-initrd \
		      dracut/RHEL6/plymouth-tpm/cryptroot-ask-tpm.sh \
		      dracut/RHEL6/plymouth-tpm/plymouth-emergency.sh \
		      dracut/RHEL6/plymouth-tpm/plymouth-pretrigger.sh
endif

dist_sbin_SCRIPTS=tpm-luks/tpm-luks-chain-hashes \
	     tpm-luks/tpm-luks \
	     tpm-luks/tpm-luks-gen-tgrub-pcr-values \
	     tpm-luks/tpm-luks-update \
	     tpm-luks/tpm-luks-init

yumpluginconfdir=/etc/yum/pluginconf.d
dist_yumpluginconf_SCRIPTS=yum/post-transaction-actions.conf

yumpluginsdir=/usr/lib/yum-plugins
dist_yumplugins_SCRIPTS=yum/post-transaction-actions.py

yumpostactionsdir=/etc/yum/post-actions
dist_yumpostactions_SCRIPTS=yum/tpm-luks.action

confdir=/etc
conf_SCRIPTS=tpm-luks.conf

CLEANFILES = yum/tpm-luks.action tpm-luks.conf

yum/tpm-luks.action: yum/tpm-luks.action.in
	@SED@ -e s!\@sbindir\@!"@sbindir@"!g < $< > $@-t
	mv $@-t $@

EXTRA_DIST = tpm-luks.conf.in yum/tpm-luks.action.in

tpm-luks.conf: tpm-luks.conf.in
	@SED@ -e s!\@sbindir\@!"@sbindir@"!g < $< > $@-t
	mv $@-t $@

install-exec-hook:
	if test ! -e ${DESTDIR}/etc/tpm-luks.conf; then cp tpm-luks.conf ${DESTDIR}/etc; fi

