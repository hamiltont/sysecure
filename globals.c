/**
 * @file
 * @brief Holds all of the globals needed by many core files in SySecure 
 * 
 * Currently holds the EncryptionInfo structure, and some #defines for PLUGIN
 * information
 */

#include "globals.h"

/**
 * Allocates and initializes a default EncryptionInfo object
 */
EncryptionInfo *
init_encryption_info() {
  // Get some memory
  EncryptionInfo *enc = g_malloc(sizeof(EncryptionInfo));
  
  // Default all variables
  enc->is_encrypted = FALSE;
  
  return enc;
}

/**
 * Cleans up previously allocated EncryptionInfo
 */
void 
uninit_encryption_info(EncryptionInfo * e_info) {
  g_free(e_info);
}
