#ifndef SESSION_KEYS_C
#define SESSION_KEYS_C

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
  CK_MECHANISM_TYPE keygenMech = CKM_AES_KEY_GEN;
  
  
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
                    "Type: %i\n",
                    PK11_GetMechanism(key));
                    
  purple_debug_info(PLUGIN_ID,
                    "Key-Length: %i\n",
                    PK11_GetKeyLength(key));
  
}


#endif
