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
SUBDIRS = lib .

AM_CFLAGS = -I/usr/linux/include -Wmissing-declarations -Wmissing-prototypes -Wnested-externs -static -W -Wuninitialized -DTPM_POSIX -DTPM_V12 -DTPM_NV_DISK -DTPM_AES -DTPM_USE_TAG_IN_STRUCTURE=1 -DTPM_USE_CHARDEV

INCLUDES =  -Ilib
#LDADD = lib/.libs/libtpm.a /usr/local/ssl/lib/libcrypto.a
LDADD = lib/.libs/libtpm.a

AM_CONDITIONAL = TPM_VTPM
#AM_LDFLAGS = -all-static
AM_LDFLAGS = -lc -ldl -lcrypto
# These must go into /usr/bin because they'll be gathered up by dracut's
# scripts as part of bnuilding the initramfs. The 'inst_binary' script
# only looks in a few places, and /usr/local/bin isn't one of them
bindir=/usr/bin
bin_PROGRAMS = getcapability nv_readvalue

getcapability_SOURCES = getcapability.c
nv_readvalue_SOURCES = nv_readvalue.c
