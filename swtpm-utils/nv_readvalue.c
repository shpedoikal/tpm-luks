/********************************************************************************/
/*										*/
/*			    TCPA Read Value from NV Storage			*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: nv_readvalue.c 4073 2010-04-30 14:44:14Z kgoldman $		*/
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif

#include "tpm.h"
#include "tpmutil.h"
#include "tpmfunc.h"
#include "tpm_constants.h"
#include "tpm_structures.h"


/* local functions */

static void usage()
{
    printf("Usage: nv_readvalue -ix index -sz size [-off offset] \n"
	   "\t[-pwdo <owner password>] [-pwdd <area password>] [-of <data file name>]\n"
	   "\n"
	   " -pwdo pwd    : The TPM owner password.\n"
	   " -ix index    : The index of the memory to use in hex.\n"
	   " -sz size      : The number of bytes to read.\n"
	   " -off offset    : The offset in memory where to start reading from (default 0)\n"
	   " -pwdd password  : The password for the memory area.\n"
	   " -of file      : File to store the read bytes.\n"
	   " -ee num      : Expected error number.\n"
	   "\n"
           "With -pwdo, does TPM_ReadValue\n"
           "With -pwdd, does TPM_ReadValueAuth\n"
           "With neither, does TPM_ReadValue with no authorization\n"
	   "\n"
	   "Examples:\n"
	   "nv_readvalue -pwdo ooo -ix 2 -sz  2 -off 0\n"
	   "nv_readvalue -pwdd aaa -ix 2 -sz 10 -off 5 \n");
    exit(-1);
}


int main(int argc, char * argv[]) {
	char * ownerpass = NULL;
	char * areapass = NULL;
	unsigned char * passptr1 = NULL;
	unsigned char * passptr2 = NULL;
	unsigned char passhash1[20];
	unsigned char passhash2[20];	
	uint32_t ret = 0;
	unsigned long lrc;
	int irc;
	uint32_t size = 0xffffffff; 
	uint32_t offset = 0;
	int i =	0;
	TPM_NV_INDEX index = 0xffffffff;
	unsigned char * readbuffer = NULL;
	uint32_t readbufferlen = -1;
	uint32_t expectederror = 0;
	const char *datafilename = NULL;
	FILE *datafile = NULL;
	int verbose = FALSE;
	
	i = 1;
	
	TPM_setlog(0);
	
	while (i < argc) {
		if (!strcmp("-pwdo",argv[i])) {
			i++;
			if (i < argc) {
				ownerpass = argv[i];
			} else {
				printf("Missing mandatory parameter for -pwdo (owner password).\n");
				usage();
			}
		} else
		if (!strcmp("-sz",argv[i])) {
			i++;
			if (i < argc) {
				size = atoi(argv[i]);
				if ((int)size < 0) {
					printf("Size must not be negative!\n");
					exit(-1);
				}
			} else {
				printf("Missing mandatory parameter for -sz (size).\n");
				usage();
			}
		} else
		if (!strcmp("-ix",argv[i])) {
			i++;
			if (i < argc) {
			    if (1 != sscanf(argv[i], "%x", &index)) {
				printf("Could not parse index '%s'.\n", argv[i]);
				exit(-1);
			    }
			} else {
				printf("Missing mandatory parameter for -ix (NV space index).\n");
				usage();
			}
		} else
		if (!strcmp("-off",argv[i])) {
			i++;
			if (i < argc) {
				offset = atoi(argv[i]);
			} else {
				printf("Missing mandatory parameter for -off (offest).\n");
				usage();
			}
		} else
		if (!strcmp("-pwdd",argv[i])) {
			i++;
			if (i < argc) {
				areapass = argv[i];
			} else {
				printf("Missing parameter for -pwdd (NV space password).\n");
				usage();
			}
		} else
		if (!strcmp("-ee",argv[i])) {
			i++;
			if (i < argc) {
				expectederror = atoi(argv[i]);
			} else {
				printf("Missing parameter for -ee (expected error).\n");
				usage();
			}
		} else
		if (!strcmp("-of",argv[i])) {
			i++;
			if (i < argc) {
			        datafilename = argv[i];
			} else {
			        printf("Missing mandatory parameter for -of (data file name).\n");
			        usage();
			}
		} else
		if (!strcmp("-v",argv[i])) {
			verbose = TRUE;
			TPM_setlog(1);
		} else
		if (!strcmp("-h",argv[i])) {
			usage();
		} else {
			printf("\n%s is not a valid option\n", argv[i]);
			usage();
		}
		i++;
	}

	if (index == 0xffffffff || size == 0xffffffff) {
		printf("Input parameters (index or size) wrong or missing!\n");
		usage();
	}
	
	if (TRUE == verbose) {
		printf("Using ownerpass : %s\n",ownerpass);
		printf("Using areapass: %s\n",areapass);
	}
	

	if (NULL != ownerpass) {
		TSS_sha1(ownerpass,strlen(ownerpass),passhash1);
		passptr1 = passhash1;
	} else {
		passptr1 = NULL;
	}

	if (NULL != areapass) {
		TSS_sha1(areapass,strlen(areapass),passhash2);
		passptr2 = passhash2;
	} else {
		passptr2 = NULL;
	}


        /* if no area password specified, do owner read (either auth-1 or no auth) */
	if (NULL == areapass) {
		readbufferlen = size + 1;
		readbuffer = (unsigned char *)malloc(readbufferlen);
		
		ret = TPM_NV_ReadValue(index,
		                       offset,
		                       size,
		                       readbuffer,&readbufferlen,
		                       passptr1);
		if (0 != ret) {
			if (ret == expectederror) {
				printf("Success.\n");
			} else {
				printf("Error %s from NV_ReadValue\n",
				       TPM_GetErrMsg(ret));
			}
		}
	}
        /* if area password specified, and no owner password */
        else if (NULL == ownerpass) {
		readbufferlen = size + 1;
		readbuffer = (unsigned char *)malloc(readbufferlen);
		
		ret = TPM_NV_ReadValueAuth(index,
		                           offset,
		                           size,
		                           readbuffer,&readbufferlen,
		                           passptr2);
		if (0 != ret) {	
			if (ret == expectederror) {
				printf("Success.\n");
			} else {
				printf("Error %s from NV_ReadValueAuth\n",
				       TPM_GetErrMsg(ret));
			}
		}
	}
        /* if both area and owner password specified */
        else {
            printf("Owner and area password cannot both be specified\n");
            usage();
        }
	if (0 == ret) {
		uint32_t i = 0;
		int is_ascii = TRUE;
		printf("Received %d bytes: ",readbufferlen);
		while (i < readbufferlen) {
			printf("%02x ",readbuffer[i]);
			if (readbuffer[i] < ' ' || readbuffer[i] >= 128) {
				is_ascii = FALSE;
			}
			i++;
		}
		printf("\n");
		if (TRUE == is_ascii) {
			readbuffer[readbufferlen] = 0;
			printf("Text: %s\n",readbuffer);
		}
	}
	/* optionally write the data to a file */
	if ((0 == ret) && (datafilename != NULL)) {
	    datafile = fopen(datafilename, "wb");
	    if (datafile == NULL) {
		printf("Error, opening %s for write from NV_ReadValue, %s\n",
		       datafilename, strerror(errno));
		ret = -1;
	    }
	}
	if ((0 == ret) && (datafilename != NULL)) {
	    lrc = fwrite(readbuffer, 1, readbufferlen, datafile);
	    if (lrc != readbufferlen) {
		printf("Error, could not write %u bytes from NV_ReadValue\n", readbufferlen);
		ret = -1;
	    }
	}
	if ((0 == ret) && (datafilename != NULL)) {
	    if (datafile != NULL) {
		irc = fclose(datafile);
		if (irc != 0) {
		    printf("Error closing output file %s from NV_ReadValue\n", datafilename);
		    ret = -1;
		}
	    }
	}
	free(readbuffer);

	exit(ret);
}
