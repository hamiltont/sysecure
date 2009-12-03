#ifndef SESSION_KEYS_C
#define SESSION_KEYS_C

// General Includes
#include <string.h>

// NSS includes
#include "nss.h"
#include "pk11pub.h"
#include "pk11func.h"

// libpurple includes
#include "debug.h"

// SySecure includes
#include "globals.h"

#include "session_keys.h"

PK11SymKey *
generate_symmetric_key()
{
  // We want AES encryption
  // AES is a block cipher, so if the input is not a multiple of the block size
  // then someone has to pad the input with some extra data. We add _PAD to 
  // inform NSS that it should handle this padding for us, we don't want to 
  // manage it ourself
  CK_MECHANISM_TYPE keygenMech = CKM_AES_CBC_PAD;
  
  PK11SymKey* sym_key = PK11_KeyGen(PK11_GetInternalKeySlot(),
                                    keygenMech, 
                                    NULL, 
                                    128/8, 
                                    NULL);

  return sym_key;
}

void
debug_symmetric_key(PK11SymKey * key)
{
  purple_debug_info(PLUGIN_ID,
                    "Debugging session key\n");
  
  purple_debug_info(PLUGIN_ID,
                    "Type: 0x%x\n",
                    PK11_GetMechanism(key));
                    
  purple_debug_info(PLUGIN_ID,
                    "Key-Length: %i\n",
                    PK11_GetKeyLength(key));
  
}

void 
encrypt(PK11SymKey *key, unsigned char * plain)
{
  
  SECItem ivItem;
  
  unsigned char data[1024];
  unsigned char gIV[] = {0xe4, 0xbb, 0x3b, 0xd3, 0xc3, 0x71, 0x2e, 0x58};
  
  ivItem.type = siBuffer;
  ivItem.data = gIV;
  ivItem.len = sizeof(gIV);
  SECItem *param = PK11_ParamFromIV(PK11_GetMechanism(key), &ivItem);
  
   if (param == NULL)
  {
    fprintf(stderr, "Failure to set up PKCS11 param (err %d)\n",
            PR_GetError());
  }
  
  strcpy(data, "Encrypt me!");
  fprintf(stderr, "Clear Data: %s\n", data);
  
  PK11Context* EncContext = PK11_CreateContextBySymKey(PK11_GetMechanism(key), 
                                                       CKA_ENCRYPT, 
                                                       key, 
                                                       param);
  
  //purple_debug_info(PLUGIN_ID,"Encrypting %s",plain);
  
  // Allocate and zero our output buffer
  int out_buf_size = (strlen(plain) * sizeof(char))
                   + PK11_GetBlockSize(PK11_GetMechanism(key),param);           
  unsigned char outbuf[1024];
                                         
  //memset(&outbuf,0,out_buf_size);
  
  int outlen = 0;
  int outlen2 = 0;
    
  SECStatus s = PK11_CipherOp(EncContext,
                              outbuf, 
                              &outlen, 
                              sizeof(outbuf), 
                              plain,
                              strlen(plain) + 1);
  
  PK11_DigestFinal(EncContext,
                   outbuf+outlen, 
                   &outlen2, 
                   sizeof(outbuf) - outlen);
  
  
  PK11_DestroyContext(EncContext, PR_TRUE);
  
  fprintf(stderr, "Encrypted Data: \n");
  int result_len = outlen + outlen2;
  fprintf(stderr, "Data length %i \n",result_len);
  int i;
  
  for (i=0; i<result_len; i++)
    fprintf(stderr, "%02x ", outbuf[i]);
  fprintf(stderr, "\n");
  
  unsigned char dec_buf[1024];
  outlen = outlen2 = 0;
  
  EncContext = PK11_CreateContextBySymKey(PK11_GetMechanism(key), 
                                                       CKA_DECRYPT, 
                                                       key, 
                                                       param);
  
  PK11_CipherOp(EncContext,
                dec_buf, 
                &outlen, 
                sizeof(dec_buf), 
                outbuf,
                result_len);
  
  PK11_DigestFinal(EncContext,
                   dec_buf+outlen, 
                   &outlen2, 
                   result_len - outlen);
  
  
  PK11_DestroyContext(EncContext, PR_TRUE);
  
  result_len = outlen + outlen2;
  
  fprintf(stderr, "Decrypted Data: %s\n", dec_buf);
  
}

#endif
