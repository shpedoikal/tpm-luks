#################################################################################
#										#
# Makefile for libtpm/utils							#
#										#
# $Id: Makefile.am 4073 2010-04-30 14:44:14Z kgoldman $				#
#										#
# (c) Copyright IBM Corporation 2006, 2010.					#
# 										#
# All rights reserved.								#
# 										#
# Redistribution and use in source and binary forms, with or without		#
# modification, are permitted provided that the following conditions are	#
# met:										#
# 										#
# Redistributions of source code must retain the above copyright notice,	#
# this list of conditions and the following disclaimer.				#
# 										#
# Redistributions in binary form must reproduce the above copyright		#
# notice, this list of conditions and the following disclaimer in the		#
# documentation and/or other materials provided with the distribution.		#
# 										#
# Neither the names of the IBM Corporation nor the names of its			#
# contributors may be used to endorse or promote products derived from		#
# this software without specific prior written permission.			#
# 										#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		#
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		#
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR		#
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		#
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	#
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		#
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,		#
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY		#
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		#
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE		#
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		#
#										#
#################################################################################

#AM_CFLAGS = -I/usr/linux/include -Wall -ggdb -Wmissing-declarations -Wmissing-prototypes -Wnested-externs @STATIC_LINKING_FLAG@ -W -Werror
AM_CFLAGS = -I/usr/linux/include -Wall -Wmissing-declarations -Wmissing-prototypes -Wnested-externs @STATIC_LINKING_FLAG@ -W
INCLUDES =  -I../lib
#LDADD = $(top_builddir)/lib/.libs/libtpm.a -lcrypto @UDXTK_LD_PATHS@ @UDXTK_LD_LIBS@
#LDADD = $(top_builddir)/lib/.libs/libtpm.a /usr/local/ssl/lib/libcrypto.a @UDXTK_LD_PATHS@ @UDXTK_LD_LIBS@
LDADD = $(top_builddir)/lib/.libs/libtpm.a /usr/local/ssl/lib/libcrypto.a /usr/lib/i386-linux-gnu/libc.a /usr/lib/i386-linux-gnu/libdl.a

AM_CONDITIONAL = TPM_VTPM
AM_LDFLAGS = -all-static
bin_PROGRAMS = getcapability resetlockvalue nv_readvalue
#bin_PROGRAMS = takeown clearown createkey tpmreset evictkey  \
#               signfile verifyfile sealfile unsealfile loadkey \
#               listkeys quote dumpkey bindfile unbindfile getpubek \
#               disablepubek chgauth chgtpmauth tpm_demo \
#		createek tpmbios setownerinstall takeowntpmdiag \
#		nv nv_definespace nv_readvalue nv_writevalue certifyselftest \
#		counter_create counter_increment counter_read counter_release \
#		sha identity createrevek revtrust extend getticks \
#		tickstampblob migrate forceclear resetestbit counter_calc_incr \
#		physicaldisable physicalenable physicalsetdeactivated \
#		ownersetdisable setoperatorauth \
#		settempdeactivated disableownerclear disableforceclear \
#		ownerreadinternalpub selftest savecontext loadcontext \
#		loadmigrationblob enableaudit getauditdigest counter_calc_incr\
#		getauditdigestsigned flushspecific migratekey \
#		pcrread calcfuturepcr pcrreset sealfile2 sealxfile \
#		cmk_migrate cmk_setrestrictions cmk_createkey \
#		cmk_approvema cmk_loadmigrationblob cmk_createticket \
#		signmsg quote2 keycontrol savekeycontext saveauthcontext \
#		loadkeycontext loadauthcontext \
#		certifykey dirwrite dirread getcapability setcapability \
#		savestate tpminit killmaintenancefeature loadmanumaintpub \
#		readmanumaintpub delegatemanage delegatereadtable \
#		createownerdelegation loadownerdelegation unsealxfile \
#		createkeydelegation updateverification verifydelegation \
#		random resetlockvalue setownerpointer session transport_test \
#		getcontextcount physicalpresence \
#		libtpm-config

getcapability_SOURCES = getcapability.c
nv_readvalue_SOURCES = nv_readvalue.c
resetlockvalue_SOURCES = resetlockvalue.c
#takeown_SOURCES = takeown.c
#clearown_SOURCES = clearown.c
#createkey_SOURCES = createkey.c
#evictkey_SOURCES = evictkey.c
#listkeys_SOURCES = listkeys.c
#loadkey_SOURCES = loadkey.c
#signfile_SOURCES = signfile.c
#signmsg_SOURCES = signmsg.c
#verifyfile_SOURCES = verifyfile.c
#quote_SOURCES = quote.c
#quote2_SOURCES = quote2.c
#dumpkey_SOURCES = dumpkey.c
#sealfile_SOURCES = sealfile.c
#sealxfile_SOURCES = sealxfile.c
#sealfile2_SOURCES = sealfile2.c
#unsealfile_SOURCES = unsealfile.c
#unsealxfile_SOURCES = unsealxfile.c
#tpmreset_SOURCES = tpmreset.c
#bindfile_SOURCES = bindfile.c
#unbindfile_SOURCES = unbindfile.c
#getpubek_SOURCES = getpubek.c
#disablepubek_SOURCES = disablepubek.c
#chgauth_SOURCES = chgauth.c
#chgtpmauth_SOURCES = chgtpmauth.c
#tpm_demo_SOURCES = tpm_demo.c
#createek_SOURCES = createek.c
#createrevek_SOURCES = createrevek.c
#revtrust_SOURCES = revtrust.c
#tpmbios_SOURCES = tpmbios.c
#setownerinstall_SOURCES = setownerinstall.c
#takeowntpmdiag_SOURCES = takeowntpmdiag.c
#nv_definespace_SOURCES = nv_definespace.c
#nv_writevalue_SOURCES = nv_writevalue.c
#nv_SOURCES = nv.c
#counter_create_SOURCES = counter_create.c
#counter_increment_SOURCES = counter_increment.c
#counter_read_SOURCES = counter_read.c
#counter_release_SOURCES = counter_release.c
#sha_SOURCES = sha.c
#identity_SOURCES = identity.c
#extend_SOURCES = extend.c
#getticks_SOURCES = getticks.c
#tickstampblob_SOURCSE = tickstampblob.c
#migrate_SOURCES = migrate.c
#forceclear_SOURCES = forceclear.c
#resetestbit_SOURCES = resetestbit.c
#physicaldisable_SOURCES = physicaldisable.c
#physicalenable_SOURCES = physicalenable.c
#physicalsetdeactivated_SOURCES = physicalsetdeactivated.c
#ownersetdisable_SOURCES = ownersetdisable.c
#setoperatorauth_SOURCES = setoperatorauth.c
#settempdeactivated_SOURCES = settempdeactivated.c
#disableownerclear_SOURCES = disableownerclear.c
#disableforceclear_SOURCES = disableforceclear.c
#ownerreadinternalpub_SOURCES = ownerreadinternalpub.c
#selftest_SOURCES = selftest.c
#savecontext_SOURCES = savecontext.c
#loadcontext_SOURCES = loadcontext.c
#loadmigrationblob_SOURCES = loadmigrationblob.c
#flushspecific_SOURCES = flushspecific.c
#migratekey_SOURCES = migratekey.c
#pcrread_SOURCES = pcrread.c
#calcfuturepcr_SOURCES = calcfuturepcr.c
#pcrreset_SOURCES = pcrreset.c
#cmk_migrate_SOURCES = cmk_migrate.c
#cmk_setrestrictions_SOURCES = cmk_setrestrictions.c
#cmk_createkey_SOURCES = cmk_createkey.c
#cmk_approvema_SOURCES = cmk_approvema.c
#cmk_loadmigrationblob_SOURCES = cmk_loadmigrationblob.c
#cmk_createticket_SOURCES = cmk_createticket.c
#keycontrol_SOURCES = keycontrol.c
#savekeycontext_SOURCES = savekeycontext.c
#saveauthcontext_SOURCES = saveauthcontext.c
#loadkeycontext_SOURCES = loadkeycontext.c
#loadauthcontext_SOURCES = loadauthcontext.c
#certifykey_SOURCES = certifykey.c
#dirwrite_SOURCES = dirwrite.c
#dirread_SOURCES = dirread.c
#setcapability_SOURCES = setcapability.c
#savestate_SOURCES = savestate.c
#tpminit_SOURCES = tpminit.c
#killmaintenancefeature_SOURCES = killmaintenancefeature.c
#loadmanumaintpub_SOURCES = loadmanumaintpub.c
#readmanumaintpub_SOURCES = readmanumaintpub.c
#delegatemanage_SOURCES = delegatemanage.c
#delegatereadtable_SOURCES = delegatereadtable.c
#physicalpresence_SOURCES = physicalpresence.c
