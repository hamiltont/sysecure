/**
 * @file
 * @brief Allows symmetric encryption, decryption, and key generation 
 * 
 * Currently has methods to perform encryption, decryption, symmetric key 
 * generation. Also has some helper methods to use static data, which can
 * be useful for debugging. 
 *
 * @TODO - This file does not encrypt/decrypt properly with some input. Debug..
 * TODO 
 */
 
#ifndef SESSION_KEYS_C
#define SESSION_KEYS_C

// General Includes
#include <string.h>
#include <stdlib.h>

// NSS includes
#include "nss.h"
#include "nspr.h"      // PR_GetError
#include "pk11pub.h"
#include "pk11func.h"

// libpurple includes
#include "debug.h"

// SySecure includes
#include "globals.h"

#include "session_keys.h"

// Random IV for now. IV matters because we are using CBC mode of encryption
static unsigned char gIV[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// Unchanging SymKey. Useful for debugging changes to the file
// Note that this key is 16 bytes AKA 128 bits 
// Should be used for 128 bit AES
static unsigned char gKey[] = {0xe8, 0xa7, 0x7c, 0xe2, 0x05, 0x63, 0x6a, 0x31,
                               0xe8, 0xa7, 0x7c, 0xe2, 0x05, 0x63, 0x6a, 0x31};

PK11SymKey *
generate_symmetric_key()
{
  // We want AES encryption
  // AES is a block cipher, so if the input is not a multiple of the block size
  // then someone has to pad the input with some extra data. We add _PAD to 
  // inform NSS that it should handle this padding for us, we don't want to 
  // manage it ourself
  CK_MECHANISM_TYPE keygenMech = CKM_DES_CBC_PAD;
  
  PK11SymKey* sym_key = PK11_KeyGen(PK11_GetBestSlot(keygenMech, NULL),
                                    keygenMech, 
                                    NULL, 
                                    128/8, 
                                    NULL);

  return sym_key;
}

/**
 * Used to generate a static key. Will always return the exact same key, should
 * only be used for debugging purposes
 */
PK11SymKey*  
get_static_key()
{
  SECItem keyItem;
  PK11SlotInfo* slot = NULL;
  CK_MECHANISM_TYPE  cipherMech;
  PK11SymKey* SymKey;
  
  // NSS passes blobs around as SECItems. These contain a pointer to 
  // data and a length. Turn the raw key into a SECItem. 
  keyItem.type = siBuffer;
  keyItem.data = gKey;
  keyItem.len = sizeof(gKey);
  
  cipherMech = CKM_AES_CBC_PAD;
  slot = PK11_GetBestSlot(cipherMech, NULL);

  if (slot == NULL)
  {
    fprintf(stderr, "Unable to find security device (err %d)\n",
            PR_GetError());
    return NULL;
  }
  
  // Turn the raw key into a key object. We use PK11_OriginUnwrap 
  // to indicate the key was unwrapped - which is what should be done 
  // normally anyway - using raw keys isn't a good idea 
  SymKey = PK11_ImportSymKey(slot,
                             cipherMech,
                             PK11_OriginUnwrap,
                             CKA_ENCRYPT,
                             &keyItem,
                             NULL);
  if (SymKey == NULL)
  {
    PRErrorCode code = PR_GetError();
    purple_debug_error(PLUGIN_ID,
                       "Failure to generate static symmetric key (err %d)\n",
                       code);
    
    purple_debug_error(PLUGIN_ID,
                       "Is the key the correct size? Check the key size needed for your encryption method\n");
    
    purple_debug_error(PLUGIN_ID,
                       "Error Name - (%s)\n",
                       PR_ErrorToName(code));
    
    purple_debug_error(PLUGIN_ID,
                       "Error Message - (%s)\n",
                       PR_ErrorToString(code, PR_LANGUAGE_EN));
    return NULL;
  }
  
  return SymKey;
}

void
debug_symmetric_key(PK11SymKey * key)
{
  purple_debug_info(PLUGIN_ID,
                    "Debugging session key\n");
  
  purple_debug_info(PLUGIN_ID,
                    "Mecahanism: 0x%x\n",
                    (unsigned int) PK11_GetMechanism(key)); // cast to remove
                                                            // compiler warning
                    
  purple_debug_info(PLUGIN_ID,
                    "Key-Length: %i\n",
                    PK11_GetKeyLength(key));
  
}

/**
 * This method encrypts some arbitrary data, using the method specified in the 
 * PK11SymKey. 
 *
 * @param key Symmetric key. Method of encryption should _always_ have a suffix
 *            of _PAD, which indicates that NSS handles any padding necessary
 *            when performing block cipher operations. This method does not 
 *            handle padding at all, it assumes NSS is on top of it. 
 * @param plain The initial raw data. 
 * @param result_length An output variable. Pass in any random integer, and upon
 *                      return it will be set to the length of the output 
 * 
 * @return A newly allocated array, which contains the encrypted data. Length
 *         of encrypted data is stored to result_length                      
 */
// TODO - add better names to some of the internal methods 
unsigned char * 
encrypt(PK11SymKey *key, unsigned char * plain, unsigned int * result_length)
{
  // Turn our static IV into a SECItem
  SECItem ivItem;
  ivItem.type = siBuffer;
  ivItem.data = gIV;
  ivItem.len = sizeof(gIV);
  
  purple_debug_info(PLUGIN_ID,
                    "Encrypting '%s' with length %i\n",
                    plain,
                    strlen((char*)plain)+1);
  
  // Get the parameters needed to start performing the specificed type of 
  // encryption, using our IV as the seed if a seed is needed for this enc.
  // type. 
  // For us, this is AES_CBC mode. Because CBC mode of encryption needs a
  // seed IV, this param will be populated with the IV data needed to start 
  // CBC encryption
  SECItem *param = PK11_ParamFromIV(PK11_GetMechanism(key), &ivItem);
  
  if (param == NULL)
  {
    purple_debug_error(PLUGIN_ID,
                       "Error when attempting to encrypt message\n");
                     
    purple_debug_error(PLUGIN_ID,
                       "Failure to set up PKCS11 param (err %d)\n",
                       PR_GetError());
    
    purple_debug_error(PLUGIN_ID,
                       "For SySecure, this likely indicates that no IV was provided\n");
                       
    return NULL;
  }
  
  // The context simply wraps our operation into a data structure. This is 
  // useful if you need to perform multiple operations consecutively on the
  // same data (like encrypt, then hash)
  PK11Context* EncContext = PK11_CreateContextBySymKey(PK11_GetMechanism(key), 
                                                       CKA_ENCRYPT, 
                                                       key, 
                                                       param);
  
  // We are using a block cipher, so our output buffer needs to be
  // (1) at least as big as the input text
  int out_buf_size = strlen((char *)plain) * sizeof(char); // cast to remove 
                                                           // compiler warning 
  // (2) plus one extra block, in case the input had to be padded to complete
  //     filling the last block
  out_buf_size = out_buf_size + PK11_GetBlockSize(PK11_GetMechanism(key),param);
  
  // Alloc and clear our output buffer
  unsigned char *outbuf = g_malloc(out_buf_size);
  memset(outbuf, 0, out_buf_size);
  purple_debug_misc(PLUGIN_ID, 
                    "%d bytes allocated at %p for encryption\n",
                    out_buf_size,
                    outbuf);
  
  if (outbuf == NULL)
  {
    purple_debug_error(PLUGIN_ID,
                       "Unable to allocate memory to store the encrypted message!\n");
    return NULL;
  }
                                         
  // Used to store the size that encrypted output takes up. If too much buffer
  // was allocated, it may not all be used. This param tells you exactly how
  // much was used
  int outlen = 0;
  
  fprintf(stderr, "Input data length: %i\n", strlen((char*)plain) + 1);
    
  // Perform the encryption 
  SECStatus cipher_status = PK11_CipherOp(EncContext,         // Context, useful for chaining operations
                              outbuf,             // Buf to store result     
                              &outlen,            // Out param - turns into the length of the result
                              out_buf_size,       // The max size the output 
                              plain,              // Input data
                              strlen((char *)plain) + 1); // Input data length (amount to encrypt)
  
  
  // check that the cipher succeeded
  if (cipher_status != SECSuccess)
  {
    purple_debug_error(PLUGIN_ID,
                       "Error when attempting to encrypt message\n");
    
    PRErrorCode code = PR_GetError();
    purple_debug_error(PLUGIN_ID,
                       "Failure to perform cipher operation (err %d)\n",
                       code);
    
    purple_debug_error(PLUGIN_ID,
                       "Error Name - (%s)\n",
                       PR_ErrorToName(code));
    
    purple_debug_error(PLUGIN_ID,
                       "Error Message - (%s)\n",
                       PR_ErrorToString(code, PR_LANGUAGE_EN));
        
    purple_debug_info(PLUGIN_ID,
                      "Freeing pointer at %p",
                      outbuf);
    g_free(outbuf);
    
    return NULL;
  }
  
  fprintf(stderr, "Encrypted Data: \n");
  fprintf(stderr, "Data length %i \n",outlen);
  int i;
  for (i=0; i < out_buf_size; i++)
    fprintf(stderr, "%02x ", outbuf[i]);
  fprintf(stderr, "\n");
  
  unsigned int outlen2 = 0;
  
  // Digest is another term for hash. This method performs any final operations
  // on the data, as specified by the EncContext. While it could add a MAC, a 
  // hash, or a digital signature, in our case (AES CBC) it likely performs no
  // function. However, we leave this call in, in case one of the future
  // encryption methods needs this call!
  SECStatus digest_status = 
    PK11_DigestFinal(EncContext,    // Context, lets this method know if it
                                    // needs to do anything
                     outbuf+outlen, // Digest should go immediately after 
                                      // encrypted data 
                     &outlen2,        // The length of the digest generated
                     out_buf_size - outlen);   // Max room available is the 
                                               // amount originally there minus
                                               // what was used
  
  // Check that the digest succeed  
  if (digest_status != SECSuccess)
  {
    purple_debug_error(PLUGIN_ID,
                       "Error when attempting to encrypt message\n");
                  
    PRErrorCode code = PR_GetError();   
    purple_debug_error(PLUGIN_ID,
                       "Failure to perform digest(hash) operation (err %d)\n",
                       code);
    
    purple_debug_error(PLUGIN_ID,
                       "Error Name - (%s)\n",
                       PR_ErrorToName(code));
    
    purple_debug_error(PLUGIN_ID,
                       "Error Message - (%s)\n",
                       PR_ErrorToString(code, PR_LANGUAGE_EN));
    
    fprintf(stderr, "Error when adding message digest\n");
    
    purple_debug_misc(PLUGIN_ID,
                      "Freeing pointer at %p\n",
                      outbuf);
    g_free(outbuf);
    
    return NULL;
  }  
  
  fprintf(stderr, "Encrypted plus digest : \n");
  fprintf(stderr, "Digest length %i \n",outlen2);
  for (i=0; i<out_buf_size; i++)
    fprintf(stderr, "%02x ", outbuf[i]);
  fprintf(stderr, "\n");
  
  // Release the memory for the context
  PK11_DestroyContext(EncContext, PR_TRUE);
  
  // Calculate the final size of the memory used
  // This is encrypted_message_size plus digest_size
  int result_len = outlen + outlen2;
  
  *result_length = result_len;
  
  //fprintf(stderr, "Encrypted Data: \n");
  //fprintf(stderr, "Data length %i \n",result_len);
  //int i;
  //for (i=0; i<result_len; i++)
  //  fprintf(stderr, "%02x ", outbuf[i]);
  //fprintf(stderr, "\n");

  return outbuf;
}

/**
 * This method decrypts some arbitrary data, using the method specified in the 
 * PK11SymKey. 
 *
 * @param key Symmetric key. Method of encryption should _always_ have a suffix
 *            of _PAD, which indicates that NSS handles any padding necessary
 *            when performing block cipher operations. This method does not 
 *            handle padding at all, it assumes NSS is on top of it. 
 * @param cipher The initial cipher data.
 * @param cipher_length The length of the input cipher buffer 
 * @param result_length An output variable. Pass in any random integer, and upon
 *                      return it will be set to the length of the plain text
 *                      output. You could _likely_ call strlen() on the returned
 *                      char *, but this is more convenient, and safer (in case
 *                      the plain text is not a valid string) 
 * 
 * @return A newly allocated array, which contains the plaintext data. Length
 *         of encrypted data is stored to result_length                      
 */
unsigned char *
decrypt(PK11SymKey *key, unsigned char * cipher, unsigned int cipher_length, 
        unsigned int * result_length)
{

  // Turn our static IV into a SECItem
  SECItem ivItem;
  ivItem.type = siBuffer;
  ivItem.data = gIV;
  ivItem.len = sizeof(gIV);

  unsigned char *dec_buf = g_malloc(1024);
  
  if (dec_buf == NULL)
  {
    purple_debug_error(PLUGIN_ID,
                       "Unable to allocate memory to store the decrypted message!");
    return NULL;
  }
  
  memset(dec_buf,0,1024);
  
  int outlen = 0;
  unsigned int outlen2 = 0;
  
  
  // Get the parameters needed to start performing the specificed type of 
  // decryption, using our IV as the seed if a seed is needed for this decrypt
  // type. 
  // For us, this is AES_CBC mode. Because CBC mode of decryption needs a
  // seed IV, this param will be populated with the IV data needed to start 
  // CBC decryption
  SECItem *param = PK11_ParamFromIV(PK11_GetMechanism(key), &ivItem);
  
  
  if (param == NULL)
  {
    purple_debug_error(PLUGIN_ID,
                       "Error when attempting to decrypt message\n");
                     
    purple_debug_error(PLUGIN_ID,
                       "Failure to set up PKCS11 param (err %d)\n",
                       PR_GetError());
    
    purple_debug_error(PLUGIN_ID,
                       "For SySecure, this likely indicates that no IV was provided\n");
                       
    return NULL;
  }
  
  // The context simply wraps our operation into a data structure. This is 
  // useful if you need to perform multiple operations consecutively on the
  // same data (like decrypt, then hash to check the integrity)
  PK11Context* EncContext = PK11_CreateContextBySymKey(PK11_GetMechanism(key), 
                                                       CKA_DECRYPT, 
                                                       key, 
                                                       param);
  
  // Perform the decryption
  SECStatus cipher_status = 
    PK11_CipherOp(EncContext,
                  dec_buf,          // buffer to store the decrypted text
                  &outlen,          // output var that tells us the decrypted
                                    //   text's length
                  1024,  // The size of the buffer
                  cipher,           // Input cipher text
                  cipher_length);   // Amount of cipher text to process
                
  // check that the decryption succeeded
  if (cipher_status != SECSuccess)
  {
    purple_debug_error(PLUGIN_ID,
                       "Error when attempting to decrypt message\n");
    
    PRErrorCode code = PR_GetError();
    purple_debug_error(PLUGIN_ID,
                       "Failure to perform cipher operation (err %d)\n",
                       code);
    
    purple_debug_error(PLUGIN_ID,
                       "Error Name - (%s)\n",
                       PR_ErrorToName(code));
    
    purple_debug_error(PLUGIN_ID,
                       "Error Message - (%s)\n",
                       PR_ErrorToString(code, PR_LANGUAGE_EN));
        
    return NULL;
  }
  
  // Digest is another term for hash. This method performs any final operations
  // on the data, as specified by the EncContext. While it could add a MAC, a 
  // hash, or a digital signature, in our case (AES CBC) it likely performs no
  // function. However, we leave this call in, in case one of the future
  // encryption methods needs this call!
  SECStatus digest_status = 
    PK11_DigestFinal(EncContext,
                     dec_buf+outlen, 
                     &outlen2, 
                     cipher_length - outlen);
  
  
  // Check that the digest succeed  
  if (digest_status != SECSuccess)
  {
    fprintf(stderr, "Decrypted Data: %s\n", dec_buf);
  purple_debug_info(PLUGIN_ID,
                    "Decrypted data: %s\n",dec_buf);
    purple_debug_error(PLUGIN_ID,
                       "Error when attempting to decrypt message\n");
                     
    purple_debug_error(PLUGIN_ID,
                       "Failure to perform digest(hash) operation (err %d)\n",
                       PR_GetError());
    
    return NULL;
  }
  
  
  PK11_DestroyContext(EncContext, PR_TRUE);
  
  int result_len = outlen + outlen2;
  
  fprintf(stderr, "Decrypted Data: %s\n", dec_buf);
  purple_debug_info(PLUGIN_ID,
                    "Decrypted data: %s\n",dec_buf);
  return dec_buf;
}
#endif
