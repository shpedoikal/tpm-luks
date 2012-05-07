/********************************************************************************/
/*										*/
/*			     	TPM Utilities					*/
/*			     Written by J. Kravitz     				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tpm.h 4073 2010-04-30 14:44:14Z kgoldman $			*/
/*										*/
/* (c) Copyright IBM Corporation 2006, 2010.					*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

#ifndef TPM_H
#define TPM_H

#include <string.h>
#include <stdint.h>
#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif

#define ERR_MASK             0x80000000 /* mask to define error state */
/* keep 0x8001000 unassigned since the bash only sees the lowest byte! */ 
#define ERR_DUMMY            0x80001000
#define ERR_HMAC_FAIL        0x80001001 /* HMAC authorization verification failed */
#define ERR_NULL_ARG         0x80001002 /* An argument was NULL that shouldn't be */
#define ERR_BAD_ARG          0x80001003 /* An argument had an invalid value */
#define ERR_CRYPT_ERR        0x80001004 /* An error occurred in an OpenSSL library call */
#define ERR_IO               0x80001005 /* An I/O Error occured */
#define ERR_MEM_ERR          0x80001006 /* A memory allocation error occurred */
#define ERR_BAD_FILE         0x80001007 /* File error occurred */
#define ERR_BAD_DATA         0x80001008 /* data read from a stream were bad */
#define ERR_BAD_SIZE         0x80001009 /* the size of the data to send to the TPM is too large */
#define ERR_BUFFER           0x8000100a /* the size of the buffer is too small */
#define ERR_STRUCTURE        0x8000100b /* this is not the stream for the structure to be parsed */
#define ERR_NOT_FOUND        0x8000100c /* searched item could not be found  */
#define ERR_ENV_VARIABLE     0x8000100d /* environment varaible is not set */
#define ERR_NO_TRANSPORT     0x8000100e /* no transport allowed for this ordinal */
#define ERR_BADRESPONSETAG   0x8000100f /* bad response tag in message */
#define ERR_SIGNATURE        0x80001010 /* bad signature */
#define ERR_PCR_LIST_NOT_IMA 0x80001011 /* PCR values do not correspond to that in IMA */
#define ERR_CHECKSUM         0x80001012 /* Checksum not correct */
#define ERR_BAD_RESP         0x80001013 /* response from TPM not formatted correctly */
#define ERR_BAD_SESSION_TYPE 0x80001014 /* session type choice is not good */

#define ERR_LAST             0x80001015 /* keep this as the last error code !!!! */

#define TPM_MAX_BUFF_SIZE              4096
#define TPM_HASH_SIZE                  20
#define TPM_NONCE_SIZE                 20

#define TPM_U16_SIZE                   2
#define TPM_U32_SIZE                   4

#define TPM_PARAMSIZE_OFFSET           TPM_U16_SIZE
#define TPM_RETURN_OFFSET              ( TPM_U16_SIZE + TPM_U32_SIZE )
#define TPM_DATA_OFFSET                ( TPM_RETURN_OFFSET + TPM_U32_SIZE )

#define STORE32(buffer,offset,value)  { *(uint32_t *)&buffer[offset] = htonl(value); }
#define STORE16(buffer,offset,value)  { *(uint16_t *)&buffer[offset] = htons(value); }
#define STORE32N(buffer,offset,value) { *(uint32_t *)&buffer[offset] = value; }
#define STORE16N(buffer,offset,value) { *(uint16_t *)&buffer[offset] = value; }
#define LOAD32(buffer,offset)         ( ntohl(*(uint32_t *)&buffer[offset]) )
#define LOAD16(buffer,offset)         ( ntohs(*(uint16_t *)&buffer[offset]) )
#define LOAD32N(buffer,offset)        ( *(uint32_t *)&buffer[offset] )
#define LOAD16N(buffer,offset)        ( *(uint16_t *)&buffer[offset] )

#define TPM_CURRENT_TICKS_SIZE  (sizeof(TPM_STRUCTURE_TAG)+2*TPM_U32_SIZE+TPM_U16_SIZE+TPM_NONCE_SIZE)

struct tpm_buffer
{
	uint32_t size;
	uint32_t used;
	uint32_t flags;
	unsigned char buffer[TPM_MAX_BUFF_SIZE];
};

enum {
	BUFFER_FLAG_ON_STACK = 1,
};

#define STACK_TPM_BUFFER(X)                    \
	struct tpm_buffer X = {                \
		.size = sizeof( X.buffer ),    \
		.used = 0,                     \
		.flags = BUFFER_FLAG_ON_STACK, \
		.buffer = ""};
#define RESET_TPM_BUFFER(X) \
	(X)->used = 0
#define ALLOC_TPM_BUFFER(X,S) \
	struct tpm_buffer *X = TSS_AllocTPMBuffer(S);
#define FREE_TPM_BUFFER(X) \
	TSS_FreeTPMBuffer(X)
#define SET_TPM_BUFFER(X, src, len) 					\
	do {								\
		uint32_t to_copy = (X)->size > len ? len : (X)->size; 	\
		memcpy((X)->buffer, src, to_copy);			\
		(X)->used = to_copy;					\
	} while (0);
#define IS_TPM_BUFFER_EMPTY(X) \
	((X)->used == 0)

struct tpm_buffer *TSS_AllocTPMBuffer(int len);

static inline struct tpm_buffer *clone_tpm_buffer(struct tpm_buffer *orig) {
	struct tpm_buffer * buf = TSS_AllocTPMBuffer(orig->used + 20);
	if (buf) {
		SET_TPM_BUFFER(buf, orig->buffer, orig->used);
	}
	return buf;
}

#if defined (__x86_64__)
#define OUT_FORMAT(a,b) b
#else
#define OUT_FORMAT(a,b) a
#endif

#endif
