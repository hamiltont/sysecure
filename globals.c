
#include "globals.h"


EncryptionInfo *
init_encryption_info() {
  // Get some memory
  EncryptionInfo *enc = g_malloc(sizeof(EncryptionInfo));
  
  // Default all variables
  enc->is_encrypted = FALSE;
  
  return enc;
}

void 
uninit_encryption_info() {
  // TODO  -free memort
}
