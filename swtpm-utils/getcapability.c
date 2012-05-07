/********************************************************************************/
/*										*/
/*			     	TPM Get a TPM capability			*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: getcapability.c 4073 2010-04-30 14:44:14Z kgoldman $		*/
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
#include <string.h>
#include <ctype.h>

#include <unistd.h>
#include "tpmfunc.h"
#include "tpm.h"
#include "tpm_constants.h"
#include "tpm_structures.h"

#include <openssl/pem.h>
#include <openssl/rsa.h>


struct matrix 
{
	uint32_t cap;
	uint32_t subcap_size;
	uint32_t result_size;
};

#define TYPE_BOOL          (1 << 0)
#define TYPE_STRUCTURE     (1 << 1)
#define TYPE_UINT32        (1 << 2)
#define TYPE_UINT32_ARRAY  (1 << 3)
#define TYPE_VARIOUS       (1 << 4)

static const struct matrix matrx[] = 
{
	{TPM_CAP_ORD              , 4, TYPE_BOOL},
	{TPM_CAP_ALG              , 4, TYPE_BOOL},
	{TPM_CAP_PID              , 2, TYPE_BOOL},
	{TPM_CAP_FLAG             , 4, TYPE_STRUCTURE},
	{TPM_CAP_PROPERTY         , 4, TYPE_VARIOUS},
	{TPM_CAP_VERSION          , 0, TYPE_UINT32},
	{TPM_CAP_KEY_HANDLE       , 0, TYPE_STRUCTURE},
	{TPM_CAP_CHECK_LOADED     , 4, TYPE_BOOL},
	{TPM_CAP_KEY_STATUS       , 4, TYPE_BOOL},
	{TPM_CAP_NV_LIST          , 0, TYPE_UINT32_ARRAY},
	{TPM_CAP_MFR              , 4, TYPE_VARIOUS},
	{TPM_CAP_NV_INDEX         , 4, TYPE_STRUCTURE},
	{TPM_CAP_TRANS_ALG        , 4, TYPE_BOOL},
//	{TPM_CAP_GPIO_CHANNEL     , 2, TYPE_BOOL},
	{TPM_CAP_HANDLE           , 4, TYPE_STRUCTURE},
	{TPM_CAP_TRANS_ES         , 2, TYPE_BOOL},
//	{TPM_CAP_MANUFACTURER_VER , 0, TYPE_STRUCTURE},
	{TPM_CAP_AUTH_ENCRYPT     , 4, TYPE_BOOL},
	{TPM_CAP_SELECT_SIZE      , 4, TYPE_BOOL},
	{TPM_CAP_VERSION_VAL      , 0, TYPE_STRUCTURE},
	{TPM_CAP_FLAG_PERMANENT   , 0, TYPE_STRUCTURE},
	{TPM_CAP_FLAG_VOLATILE    , 0, TYPE_STRUCTURE},
	{TPM_CAP_DA_LOGIC         , 2, TYPE_STRUCTURE},
	{-1,-1,-1}
};


static const struct matrix mfr_matrix[] = {
	{TPM_CAP_PROCESS_ID	  , 0, TYPE_UINT32},
	{-1,-1,-1}
};

static void ParseArgs(int argc, char *argv[]);

static uint32_t sikeyhandle = 0;
static char * sikeypass = NULL;
static uint32_t cap;
static uint32_t scap = -1;
#if 0
static uint32_t sscap = -1;
#endif

static void showPermanentFlags(TPM_PERMANENT_FLAGS *pf, uint32_t size)
{
	printf("Permanent flags:\n");
	/* rev 62 + */
	printf("Disabled: %s\n",(0 == pf->disable) ? "FALSE" : "TRUE");
	printf("Ownership: %s\n",(0 == pf->ownership) ? "FALSE" : "TRUE");
	printf("Deactivated: %s\n",(0 == pf->deactivated) ? "FALSE" : "TRUE");
	printf("Read Pubek: %s\n",(0 == pf->readPubek) ? "FALSE" : "TRUE");
	printf("Disable Owner Clear: %s\n", (0 == pf->disableOwnerClear) ? "FALSE" : "TRUE");
	printf("Allow Maintenance: %s\n",(0 == pf->allowMaintenance) ? "FALSE" : "TRUE");
	printf("Physical Presence Lifetime Lock: %s\n",(0 == pf->physicalPresenceLifetimeLock) ? "FALSE" : "TRUE");
	printf("Physical Presence HW Enable: %s\n",(0 == pf->physicalPresenceHWEnable) ? "FALSE" : "TRUE");
	printf("Physical Presence CMD Enable: %s\n", (0 == pf->physicalPresenceCMDEnable) ? "FALSE" : "TRUE");
	printf("CEKPUsed: %s\n", (0 == pf->CEKPUsed) ? "FALSE" : "TRUE");
	printf("TPMpost: %s\n",(0 == pf->TPMpost) ? "FALSE" : "TRUE");
	printf("TPMpost Lock: %s\n", (0 == pf->TPMpostLock) ? "FALSE" : "TRUE");
	printf("FIPS: %s\n",(0 == pf->FIPS) ? "FALSE" : "TRUE");
	printf("Operator: %s\n", (0 == pf->tpmOperator) ? "FALSE" : "TRUE");
	printf("Enable Revoke EK: %s\n", (0 == pf->enableRevokeEK) ? "FALSE" : "TRUE");
	/* Atmel rev 85 only returns 18 BOOLs */
	if (size > 19) {
	    printf("NV Locked: %s\n",( 0 == pf->nvLocked) ? "FALSE" : "TRUE");
	    printf("Read SRK pub: %s\n",(0 == pf->readSRKPub) ? "FALSE" : "TRUE");
	    printf("TPM established: %s\n",(0 == pf->tpmEstablished) ? "FALSE" : "TRUE");
	}
	/* rev 85 + */
	if (size > 20) {
	    printf("Maintenance done: %s\n",(0 == pf->maintenanceDone) ? "FALSE" : "TRUE");
	}	    
	/* rev 103 */
	if (size > 21) {
		printf("Disable full DA logic info: %s\n",(0 == pf->disableFullDALogicInfo) ? "FALSE" : "TRUE");
	}
}

static void showVolatileFlags(TPM_STCLEAR_FLAGS *sf)
{
	printf("Volatile flags:\n");
	printf("Deactivated: %s\n",(0 == sf->deactivated) ? "FALSE" : "TRUE");
	printf("Disable ForceClear: %s\n",(0 == sf->disableForceClear) ? "FALSE" : "TRUE");
	printf("Physical Presence: %s\n",(0 == sf->physicalPresence) ? "FALSE" : "TRUE");
	printf("Physical Presence Lock: %s\n",(0 == sf->physicalPresenceLock) ? "FALSE" : "TRUE");
	printf("bGlobal Lock: %s\n",(0 == sf->bGlobalLock) ? "FALSE" : "TRUE");
}

static void printUsage() {
	printf("Usage: getcapability [options] -cap <capability (hex)>\n"
	       "[-scap <sub cap (hex)>] [-scapd <sub cap (dec)>]\n"
	       "[-hk signing key handle] [-pwdk signing key password]\n"
	       "\n"
	       "Possible options are:\n"
	       "  -hk :   handle of a signing key if a signed response is requested\n"
	       "  -pwdk : password of that signing key (if it needs one)\n"
	       "\n");
	exit(-1);
}

static int prepare_subcap(uint32_t cap,
                          struct tpm_buffer *subcap,
                          uint32_t scap)
{
	int handled = 0;
	uint32_t ret;
	if (TPM_CAP_CHECK_LOADED == cap) {
		struct keydata k;
		memset(&k, 0, sizeof(k));
		handled = 1;
		k.keyFlags = 0;
		k.keyUsage = TPM_KEY_LEGACY;
		k.pub.algorithmParms.algorithmID = scap;
		k.pub.algorithmParms.encScheme = TPM_ES_NONE;
		k.pub.algorithmParms.sigScheme = TPM_SS_RSASSAPKCS1v15_INFO;
		k.pub.algorithmParms.u.rsaKeyParms.keyLength = 2048   ;      /* RSA modulus size 2048 bits */
		k.pub.algorithmParms.u.rsaKeyParms.numPrimes = 2;            /* required */
		k.pub.algorithmParms.u.rsaKeyParms.exponentSize   = 0;       /* RSA exponent - default 0x010001 */
		k.pub.pubKey.keyLength = 0;       /* key not specified here */
		k.pub.pcrInfo.size = 0;           /* no PCR's used at this time */
		ret = TPM_WriteKeyInfo(subcap, &k);
	}
	return handled;
}

int main(int argc, char *argv[])
{
    uint32_t ret;
    STACK_TPM_BUFFER(resp);
    int index = 0;
    STACK_TPM_BUFFER( subcap );;
	
    TPM_setlog(0);		/* turn off verbose output */

    ParseArgs(argc, argv);

    while ((int)matrx[index].cap != -1) {
	if (cap == matrx[index].cap) {
	    break;
	}
	index++;
    }
    if (-1 == (int)matrx[index].cap) {
	printf("Unknown or unsupported capability!\n");
	exit(-1);
    }
	
    subcap.used = 0;
    if (matrx[index].subcap_size > 0) {
	if ((int)scap == -1) {
	    printf("Need subcap parameter for this capability!\n");
	    exit(-1);
	}
	if (0 == prepare_subcap(cap, &subcap, scap)) {
	    if (2 == matrx[index].subcap_size) {
		STORE16(subcap.buffer,0,scap);
		subcap.used = 2;
	    } else
		if (matrx[index].subcap_size >= 4) {
		    STORE32(subcap.buffer,0,scap);
		    subcap.used  = 4;
		}
	}
    }
	
#if 0
    /* This was for VTPM extensions and needs retest */
    if (cap == TPM_CAP_MFR) {
	int idx2 = 0;
	while ((int)mfr_matrix[idx2].cap != -1) {
	    if (mfr_matrix[idx2].cap == scap) {
		break;
	    }
	    idx2++;
	}
	if (mfr_matrix[idx2].subcap_size > 0) {
	    uint32_t used = subcap.used +
			    mfr_matrix[idx2].subcap_size;
	    while (subcap.used < used) {
		if (argc <= nxtarg) {
		    printf("Need one more parameter for this "
			   "capability!\n");
		    exit(-1);
		}
		if (!strncmp("0x",argv[nxtarg],2)) {
		    sscanf(argv[nxtarg],"%x",&sscap);
		} else {
		    sscanf(argv[nxtarg],"%d",&sscap);
		}
		nxtarg++;
		if (2 == matrx[index].subcap_size) {
		    STORE16(subcap.buffer,
			    subcap.used,sscap);
		    subcap.used += 2;
		} else
		    if (matrx[index].subcap_size >= 4) {
			STORE32(subcap.buffer,
				subcap.used,sscap);
			subcap.used += 4;
		    }
	    }
	}
    }


#endif
    if (0 == sikeyhandle) {
	ret = TPM_GetCapability(cap,
				&subcap,
				&resp);

	if (0 != ret) {
	    printf("TPM_GetCapability returned %s.\n",
		   TPM_GetErrMsg(ret));
	    exit(ret);
	}
    } else {
	unsigned char antiReplay[TPM_HASH_SIZE];
	unsigned char signature[2048];
	uint32_t signaturelen = sizeof(signature);
	pubkeydata pubkey;
	RSA * rsa;
	unsigned char sighash[TPM_HASH_SIZE];
	unsigned char * buffer = NULL;
	unsigned char * sigkeyhashptr = NULL;
	unsigned char sigkeypasshash[TPM_HASH_SIZE];

	if (NULL != sikeypass) {
	    TSS_sha1(sikeypass,strlen(sikeypass),sigkeypasshash);
	    sigkeyhashptr = sigkeypasshash;
	}

	TSS_gennonce(antiReplay);
		
	ret = TPM_GetPubKey(sikeyhandle,
			    sigkeyhashptr,
			    &pubkey);

	if (0 != ret) {
	    printf("Error while trying to access the signing key's public key.\n");
	    exit(-1);
	}
		
	rsa = TSS_convpubkey(&pubkey);
		
	ret = TPM_GetCapabilitySigned(sikeyhandle,
				      sigkeyhashptr,
				      antiReplay,
				      cap,
				      &subcap,
				      &resp,
				      signature, &signaturelen);

	if (0 != ret) {
	    printf("TPM_GetCapabilitySigned returned %s.\n",
		   TPM_GetErrMsg(ret));
	    exit(ret);
	}

	buffer = malloc(resp.used+TPM_NONCE_SIZE);
	if (NULL == buffer) {
	    printf("Could not allocate buffer.\n");
	    exit(-1);
	}
	memcpy(&buffer[0], resp.buffer, resp.used);
	memcpy(&buffer[resp.used], antiReplay, TPM_NONCE_SIZE);

	TSS_sha1(buffer,
		 resp.used+TPM_NONCE_SIZE,
		 sighash);
	free(buffer);

	ret = RSA_verify(NID_sha1,
			 sighash,TPM_HASH_SIZE,
			 signature,signaturelen,
			 rsa);
	if (1 != ret) {
	    printf("Error: Signature verification failed.\n");
	    exit(-1);
	}
    }

    if (0 == resp.used) {
	printf("Empty response.\n");
    } else {

	if (-1 == (int)scap) {
	    printf("Result for capability 0x%x is : ",cap);
	} else {
	    printf("Result for capability 0x%x, subcapability 0x%x is : ",cap,scap);
	}
	if (TYPE_BOOL == matrx[index].result_size) {
	    if (resp.buffer[0] == 0) {
		printf("FALSE\n");
	    } else {
		printf("TRUE\n");
	    }
	} else
	    if (TYPE_UINT32 == matrx[index].result_size) {
		uint32_t rsp;
		rsp = LOAD32(resp.buffer,0);
		printf("0x%08X  = %d\n",rsp,rsp);
	    } else
		if (TYPE_UINT32_ARRAY == matrx[index].result_size) {
		    int i = 0;
		    printf("\n");
		    while (i+3 < (int)resp.used) {
			uint32_t rsp = LOAD32(resp.buffer,i);
			i+=4;
			if (TPM_CAP_NV_LIST == cap) {
			    /* don't zero extend, grep needs the exact value for test suite */
			    printf("%d. Index : %d = 0x%x.\n",
				   i/4,
				   rsp,
				   rsp);
			} else
			    if (TPM_CAP_KEY_HANDLE == cap) {
				printf("%d. keyhandle : %d.\n",
				       i/4,
				       rsp);
				} else {
				    printf("%d. item : %d.\n",
					   i/4,
					   rsp);
				}
		    }
		} else
		    if (TYPE_STRUCTURE == matrx[index].result_size) {
			switch(cap) {
			  case TPM_CAP_FLAG:
			      {
				  if (scap == TPM_CAP_FLAG_PERMANENT) {
				      TPM_PERMANENT_FLAGS pf;
				      STACK_TPM_BUFFER(tb)
					  TSS_SetTPMBuffer(&tb, resp.buffer, resp.used);
				      ret = TPM_ReadPermanentFlags(&tb, 0, &pf, resp.used);
				      if ( ( ret & ERR_MASK ) != 0 || ret > resp.used) {
					  printf("ret=%x, responselen=%d\n",ret,resp.used);
					  printf("Error parsing response!\n");
					  exit(-1);
				      }
						
				      printf("\n");
				      showPermanentFlags(&pf, resp.used);
				  } else 
				      if (scap == TPM_CAP_FLAG_VOLATILE) {
					  TPM_STCLEAR_FLAGS sf;
					  STACK_TPM_BUFFER(tb);
					  TSS_SetTPMBuffer(&tb, resp.buffer, resp.used);
					  ret = TPM_ReadSTClearFlags(&tb, 0, &sf);
					  if ( ( ret & ERR_MASK ) != 0 || ret > resp.used) {
					      printf("ret=%x, responselen=%d\n",ret,resp.used);
					      printf("Error parsing response!\n");
					      exit(-1);
					  }
						
					  printf("\n");
					  showVolatileFlags(&sf);
						
				      }
			      }
			      break;
				
			  case TPM_CAP_KEY_HANDLE:
			      {
				  uint16_t num = LOAD16(resp.buffer, 0);
				  uint32_t i = 0;
				  uint32_t handle;
				  printf("\n");
				  while (i < num) {
				      handle = LOAD32(resp.buffer,2+i*4);
				      printf("%d. handle: 0x%08X\n",
					     i,
					     handle);
				      i++;
				  }
			      }
			      break;
			  case TPM_CAP_NV_INDEX:
			      {
				  TPM_NV_DATA_PUBLIC ndp;
				  uint32_t i, c;
				  STACK_TPM_BUFFER(tb)
				      TSS_SetTPMBuffer(&tb, resp.buffer, resp.used);
				  ret = TPM_ReadNVDataPublic(&tb,
							     0,
							     &ndp);
				  if ( ( ret & ERR_MASK) != 0) {
				      printf("Could not deserialize the TPM_NV_DATA_PUBLIC structure.\n");
				      exit(-1);
				  }
				  printf("permission.attributes : %08X\n",(unsigned int)ndp.permission.attributes);
				  printf("ReadSTClear           : %02X\n",ndp.bReadSTClear);
				  printf("WriteSTClear          : %02X\n",ndp.bWriteSTClear);
				  printf("WriteDefine           : %02X\n",ndp.bWriteDefine);
				  printf("dataSize              : %08X = %d",(unsigned int)ndp.dataSize,
					 (unsigned int)ndp.dataSize);

				  c = 0;
				  for (i = 0; i < ndp.pcrInfoRead.pcrSelection.sizeOfSelect*8; i++) {
				      if (ndp.pcrInfoRead.pcrSelection.pcrSelect[(i / 8)] & (1 << (i & 0x7))) {
					      if (!c)
						  printf("\nRead PCRs selected: ");
					      else
						  printf(", ");
					      printf("%d", i);
					      c++;

				      }
				  }

				  if (c) {
				      printf("\nRead PCR Composite: ");
				      for (i = 0; i < 20; i++)
					  printf("%02x", ndp.pcrInfoRead.digestAtRelease[i] & 0xff);
				      printf("\n");
				  }


				  c = 0;
				  for (i = 0; i < ndp.pcrInfoWrite.pcrSelection.sizeOfSelect*8; i++) {
				      if (ndp.pcrInfoWrite.pcrSelection.pcrSelect[(i / 8)] & (1 << (i & 0x7))) {
					      if (!c)
						  printf("\nWrite PCRs selected: ");
					      else
						  printf(", ");
					      printf("%d", i);
					      c++;

				      }
				  }

				  if (c) {
				      printf("\nWrite PCR Composite: ");
				      for (i = 0; i < 20; i++)
					  printf("%02x", ndp.pcrInfoWrite.digestAtRelease[i] & 0xff);
				      printf("\n");
				  }
			      }
			      break;
			  case TPM_CAP_HANDLE:
			      {
				  uint16_t num = LOAD16(resp.buffer, 0);
				  uint16_t x = 0;
				  while (x < num) {
				      uint32_t handle = LOAD32(resp.buffer,
							       sizeof(num)+4*x);
				      printf("%02d. 0x%08X\n",x,handle);
				      x++;
				  }
			      }
			      break;
			  case TPM_CAP_VERSION_VAL:
			      {
				  int i = 0;
				  TPM_CAP_VERSION_INFO cvi;
				  STACK_TPM_BUFFER(tb)
				      TSS_SetTPMBuffer(&tb, resp.buffer, resp.used);
				  ret = TPM_ReadCapVersionInfo(&tb,
							       0,
							       &cvi);
				  if ( ( ret & ERR_MASK) != 0) {
				      printf("Could not read the version info structure.\n");
				      exit(-1);
				  }
					
				  printf("\n");
				  printf("major      : 0x%02X\n",cvi.version.major);
				  printf("minor      : 0x%02X\n",cvi.version.minor);
				  printf("revMajor   : 0x%02X\n",cvi.version.revMajor);
				  printf("revMinor   : 0x%02X\n",cvi.version.revMinor);
				  printf("specLevel  : 0x%04X\n",cvi.specLevel);
				  printf("errataRev  : 0x%02X\n",cvi.errataRev);
	
				  printf("VendorID   : ");
				  while (i < 4) {
				      printf("%02X ",cvi.tpmVendorID[i]);
				      i++;
				  }
				  printf("\n");
				  /* Print vendor ID in text if printable */
				  for (i=0 ; i<4 ; i++) {
				      if (isprint(cvi.tpmVendorID[i])) {
					  if (i == 0) {
					      printf("VendorID   : ");
					  }
					  printf("%c", cvi.tpmVendorID[i]);
				      }
				      else {
					  break;
				      }
				  }	    
				  printf("\n");

				  printf("[not displaying vendor specific information]\n");
			      }
			      break;
#if 0	/* kgold: I don't think these are valid cap values */
			  case TPM_CAP_FLAG_PERMANENT:
			      {
				  TPM_PERMANENT_FLAGS pf;
				  STACK_TPM_BUFFER(tb)
				      TSS_SetTPMBuffer(&tb, resp.buffer, resp.used);

				  if (resp.used == 21) {
				      ret = TPM_ReadPermanentFlagsPre103(&tb, 0, &pf);
				  } else {
				      ret = TPM_ReadPermanentFlags(&tb, 0, &pf);
				  }
				  if ( ( ret & ERR_MASK ) != 0 || ret > resp.used) {
				      printf("ret=%x, responselen=%d\n",ret,resp.used);
				      printf("Error parsing response!\n");
				      exit(-1);
				  }
						
				  printf("\n");
				  showPermanentFlags(&pf, resp.used);
			      }
			      break;
				
			  case TPM_CAP_FLAG_VOLATILE:
			      {
				  TPM_STCLEAR_FLAGS sf;
				  STACK_TPM_BUFFER(tb);
				  TSS_SetTPMBuffer(&tb, resp.buffer, resp.used);
				  ret = TPM_ReadSTClearFlags(&tb, 0, &sf);
				  if ( ( ret & ERR_MASK ) != 0 || ret > resp.used) {
				      printf("ret=%x, responselen=%d\n",ret,resp.used);
				      printf("Error parsing response!\n");
				      exit(-1);
				  }
						
				  printf("\n");
				  showVolatileFlags(&sf);
			      }
			      break;
#endif
			  case TPM_CAP_DA_LOGIC:
			      {
				  uint32_t ctr;
				  TPM_BOOL lim = FALSE;
				  TPM_DA_INFO dainfo;
				  TPM_DA_INFO_LIMITED dainfo_lim;
				  STACK_TPM_BUFFER(tb);
				  TSS_SetTPMBuffer(&tb, resp.buffer, resp.used);
				  ret = TPM_ReadDAInfo(&tb, 0, &dainfo);
				  if ( ( ret & ERR_MASK) != 0 || ret > resp.used) {
				      ret = TPM_ReadDAInfoLimited(&tb, 0, &dainfo_lim);
				      if ( (ret & ERR_MASK ) != 0 || ret > resp.used) {
					  printf("ret=%x, responselen=%d\n",ret,resp.used);
					  printf("Error parsing response!\n");
					  exit(-1);
				      } else {
					  lim = TRUE;
				      }
				  }
					
				  printf("\n");
				  if (lim) {
				      printf("State      : %d\n",dainfo_lim.state);
				      printf("Actions    : 0x%08x\n",dainfo_lim.actionAtThreshold.actions);
						
				      ctr = 0;
				      while (ctr < dainfo_lim.vendorData.size) {
					  printf("%02x ",(unsigned char)dainfo_lim.vendorData.buffer[ctr]);
					  ctr++;
				      }
				  } else {
				      printf("State              : %d\n",dainfo.state);
				      printf("currentCount       : %d\n",dainfo.currentCount);
				      printf("thresholdCount     : %d\n",dainfo.thresholdCount);
				      printf("Actions            : 0x%08x\n",dainfo.actionAtThreshold.actions);
				      printf("actionDependValue  : %d\n",dainfo.actionDependValue);
						
#if 0
				      ctr = 0;
				      while (ctr < dainfo_lim.vendorData.size) {
					  printf("%02x ",(unsigned char)dainfo_lim.vendorData.buffer[ctr]);
					  ctr++;
				      }
#endif
				  }
			      }
			      break;
			}
		    } else
			if (TYPE_VARIOUS == matrx[index].result_size) {
			    switch(cap) {
			
			      case TPM_CAP_MFR:
				switch (scap) {
				  case TPM_CAP_PROCESS_ID:
				      {
					  uint32_t rsp;
					  rsp = LOAD32(resp.buffer,0);
					  printf("%d\n",rsp);
				      }
				      break;
				}
				break; /* TPM_CAP_MFR */
			
			      default:
				/* Show booleans */
				if (scap == TPM_CAP_PROP_OWNER ||
				    scap == TPM_CAP_PROP_DAA_INTERRUPT
				    ) {
				    if (0 == resp.buffer[0]) {
					printf("FALSE\n");
				    } else {
					printf("TRUE\n");
				    }
				} else /* check for array of 4 UINTs */
				    if (scap == TPM_CAP_PROP_TIS_TIMEOUT /* ||
									    scap == TPM_CAP_PROP_TIMEOUTS      */) {
					int i = 0;
					while (i < 4) {
					    uint32_t val = LOAD32(resp.buffer,i * 4);
					    printf("%d ",
						   val);
					    i++;
					}
					printf("\n");
				    } else /* check for TPM_STARTUP_EFFECTS */
					if (scap == TPM_CAP_PROP_STARTUP_EFFECT) {
					    TPM_STARTUP_EFFECTS se = 0;
					    ret = TPM_ReadStartupEffects(resp.buffer, 
									 &se);
					    if ( ( ret & ERR_MASK ) != 0 ) {
						printf("Could not read startup effects structure.\n");
						exit(-1);
					    }
					    printf("0x%08X=%d\n",
						   (unsigned int)se,
						   (unsigned int)se);
					    printf("\n");
					    printf("Startup effects:\n");
					    printf("Effect on audit digest: %s\n", (se & (1 << 7)) 
						   ? "none"
						   : "active");
					    printf("Audit Digest on TPM_Startup(ST_CLEAR): %s\n", ( se & (1 << 6)) 
						   ? "set to NULL" 
						   : "not set to NULL" );
		
					    printf("Audit Digest on TPM_Startup(any)     : %s\n", ( se & (1 << 5))
						   ? "set to NULL"
						   : "not set to NULL" );
					    printf("TPM_RT_KEY resource initialized on TPM_Startup(ST_ANY)     : %s\n", (se & ( 1 << 4))
						   ? "yes"
						   : "no");
					    printf("TPM_RT_AUTH resource initialized on TPM_Startup(ST_STATE)  : %s\n", (se & ( 1 << 3))
						   ? "yes"
						   : "no");
					    printf("TPM_RT_HASH resource initialized on TPM_Startup(ST_STATE)  : %s\n", (se & ( 1 << 2))
						   ? "yes"
						   : "no");
					    printf("TPM_RT_TRANS resource initialized on TPM_Startup(ST_STATE) : %s\n", (se & ( 1 << 1))
						   ? "yes"
						   : "no");
					    printf("TPM_RT_CONTEXT session initialized on TPM_Startup(ST_STATE): %s\n", (se & ( 1 << 0))
						   ? "yes"
						   : "no");
					} else /* check for  array of 3 UINTs */
					    if (scap == TPM_CAP_PROP_DURATION) {
						int i = 0;
						while (i < 4*3) {
						    uint32_t val = LOAD32(resp.buffer,i);
						    printf("%d ",
							   val);
						    i+= 4;
						}
						printf("\n");
					    } else /* check for TPM_COUNT_ID */
						if (scap == TPM_CAP_PROP_ACTIVE_COUNTER) {
						    uint32_t val = LOAD32(resp.buffer,0);
						    printf("0x%08X=%d",val,val);
						    if (0xffffffff == val) {
							printf(" (no counter is active)");
						    }
						    printf("\n");
						} else { /* just a single UINT32 */
						    printf("%ld=0x%08lX.\n",
							   (long)LOAD32(resp.buffer, 0),
							   (long)LOAD32(resp.buffer, 0));
						}
			    }
			}
    }		
	
    printf("\n");
    exit(0);
}


/**************************************************************************/
/*                                                                        */
/*  Parse Arguments                                                       */
/*                                                                        */
/**************************************************************************/
static void ParseArgs(int argc, char *argv[])
{
    int i;
    
    for (i=1 ; i<argc ; i++) {
	if (!strcmp(argv[i], "-pwdk")) {
	    i++;
	    if (i < argc) {
		sikeypass = argv[i];
	    }
	    else {
		printf("Missing parameter to -pwdk\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-hk") == 0) {
	    i++;
	    if (i < argc) {
		/* convert key handle from hex */
		if (1 != sscanf(argv[i], "%x", &sikeyhandle)) {
		    printf("Invalid -hk argument '%s'\n",argv[i]);
		    exit(2);
		}
	    }
	    else {
		printf("-hk option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-cap") == 0) {
	    i++;
	    if (i < argc) {
		/* convert key handle from hex */
		if (1 != sscanf(argv[i], "%x", &cap)) {
		    printf("Invalid -cap argument '%s'\n",argv[i]);
		    exit(2);
		}
	    }
	    else {
		printf("-cap option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-scap") == 0) {
	    i++;
	    if (i < argc) {
		/* convert key handle from hex */
		if (1 != sscanf(argv[i], "%x", &scap)) {
		    printf("Invalid -scap argument '%s'\n",argv[i]);
		    exit(2);
		}
	    }
	    else {
		printf("-scap option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-scapd") == 0) {
	    i++;
	    if (i < argc) {
		/* convert key handle from hex */
		if (1 != sscanf(argv[i], "%d", &scap)) {
		    printf("Invalid -scapd argument '%s'\n",argv[i]);
		    exit(2);
		}
	    }
	    else {
		printf("-scapd option needs a value\n");
		printUsage();
	    }
	}
	else if (!strcmp(argv[i], "-h")) {
	    printUsage();
	}
	else if (!strcmp(argv[i], "-v")) {
	    TPM_setlog(1);
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    printUsage();
	}
    }
    return;
}
